#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

use base64::{engine::general_purpose, Engine as _};
#[cfg(target_arch = "wasm32")]
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(target_arch = "wasm32")]
use std::collections::HashMap;

const TAPE_API_PREFIX: &str = "/api/play/tape";
const SOURCE_AUDIO_API_PREFIX: &str = "/api/bitneedle-source-audio";
const CACHE_API_JSON_CONTENT_TYPE: &str = "application/json";
const CACHE_API_HASH_LENGTH: usize = 64;
const TAPE_API_DEFAULT_VERSION: &str = "v1";
const TAPE_API_MAX_VERSION_LENGTH: usize = 32;
const CACHE_API_R2_BINDING: &str = "CACHE_BUCKET";

const CACHE_API_BATCH_FORMAT: &str = "bitneedle-player-cache-batch-v1";
const CACHE_API_BATCH_STREAM_CONTENT_TYPE: &str =
    "application/vnd.bitneedle.player-cache-stream+binary";
// The stored content object is the full BCE1 encrypted envelope, not a bare
// Opus packet stream — the inner codec identity travels in the envelope's
// AAD-bound cache-encryption context, not in this content type.
const CACHE_API_OPUS_CONTENT_TYPE: &str = "application/vnd.bitneedle.bce1+binary";
// Two-tier addressing for the encrypted opus-chunks store: the caller's `key`
// (a pre-decode, record-scoped lookup key — see playerEcdcOpusChunkCacheKey in
// bitneedle-decoded-ecdc-opus-cache.js) is never itself the storage path.
// Instead it resolves through a small pointer object to the actual content
// blob, which is addressed by sha256 of the BCE1 envelope bytes. This keeps
// the client-visible protocol unchanged (still asks/writes by lookup key)
// while making the persisted object genuinely content-addressed: a
// deterministic nonce (see derive_cache_nonce in record-descriptor) means the
// same (record, plaintext, context) always produces the same envelope bytes,
// so the content object's write-once skip-if-exists check is actually safe.
// Reads only return small JSON (contentHash + a signed R2 URL), so a much
// larger batch is cheap. Writes carry the full chunk payload bytes in the
// request body, so that cap stays conservative.
const CACHE_API_MAX_READ_BATCH_ENTRIES: usize = 256;
const CACHE_API_MAX_WRITE_BATCH_ENTRIES: usize = 32;
const CACHE_API_BATCH_JSON_FORMAT: &str = "vin-yl-tape-batch-v2";
const CACHE_API_PRESIGN_EXPIRES_SECONDS: u32 = 300;
// Per-chunk limits: 2s × 128kbps stereo with 4× headroom.
const CACHE_API_MAX_OPUS_PAYLOAD_BYTES: usize = 131_072; // 128 KB
const CACHE_API_MAX_BCE1_ENVELOPE_BYTES: usize =
    record_descriptor::CacheEncryptionEnvelope::HEADER_LENGTH
        + CACHE_API_MAX_OPUS_PAYLOAD_BYTES
        + record_descriptor::CACHE_ENCRYPTION_TAG_LENGTH;
const SOURCE_AUDIO_UPLOAD_STATE_MAX_BYTES: usize = 256 * 1024;
const SOURCE_AUDIO_UPLOAD_CHUNK_MAX_BYTES: usize = 2 * 1024 * 1024;
const SOURCE_AUDIO_OBJECT_NAMESPACE: &str = "source-audio/v1/objects";

#[derive(Debug, Deserialize)]
struct BatchReadRequest {
    #[serde(default)]
    keys: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BatchReadKeyResult {
    key: String,
    hit: bool,
    content_hash: Option<String>,
    direct_get_url: Option<String>,
    direct_get_expires_at: Option<String>,
}

#[derive(Debug, Serialize)]
struct BatchReadResponse {
    format: String,
    results: Vec<BatchReadKeyResult>,
}

#[derive(Debug, Deserialize)]
struct BatchWriteRequest {
    #[serde(default)]
    writes: Vec<BatchWriteEntry>,
}

#[derive(Debug, Deserialize)]
struct BatchWriteEntry {
    key: String,
    #[serde(rename = "payloadBase64")]
    payload_base64: String,
    proof: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct BatchWriteResult {
    stored: bool,
}

#[derive(Debug, Serialize)]
struct BatchWriteResponse {
    format: String,
    results: Vec<BatchWriteResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SourceAudioChunkManifest {
    index: usize,
    byte_length: usize,
    sha256: String,
    object_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SourceAudioUploadState {
    object_id: String,
    object_hash: String,
    sealed: bool,
    metadata: serde_json::Value,
    chunks: Vec<SourceAudioChunkManifest>,
}

#[cfg(target_arch = "wasm32")]
use worker::*;

#[cfg(target_arch = "wasm32")]
#[event(fetch)]
pub async fn main(request: Request, env: Env, _ctx: worker::Context) -> worker::Result<Response> {
    console_error_panic_hook::set_once();

    let url = request.url()?;
    if !is_cache_api_path(url.path()) && !is_source_audio_api_path(url.path()) {
        return Response::ok("Not found\n").map(|response| response.with_status(404));
    }

    let origin = request.headers().get("Origin").ok().flatten();

    let result = if is_source_audio_api_path(url.path()) {
        handle_source_audio_api_request(request, url, env, origin.as_deref()).await
    } else {
        handle_cache_api_request(request, url, env, origin.as_deref()).await
    };

    match result {
        Ok(response) => Ok(response),
        Err(error) => {
            console_warn!("[play-cache] request failed: {}", error);
            cache_api_json(
                &serde_json::json!({ "error": "Cache API request failed" }),
                500,
                origin.as_deref(),
            )
        }
    }
}

fn is_cache_api_path(pathname: &str) -> bool {
    pathname == TAPE_API_PREFIX || pathname.starts_with(&format!("{TAPE_API_PREFIX}/"))
}

fn is_source_audio_api_path(pathname: &str) -> bool {
    pathname == SOURCE_AUDIO_API_PREFIX
        || pathname.starts_with(&format!("{SOURCE_AUDIO_API_PREFIX}/"))
}

fn cache_api_relative_path(pathname: &str) -> Option<&str> {
    pathname.strip_prefix(TAPE_API_PREFIX)
}

fn source_audio_api_relative_path(pathname: &str) -> Option<&str> {
    pathname.strip_prefix(SOURCE_AUDIO_API_PREFIX)
}

fn normalize_tape_version(version: &str) -> Option<String> {
    let normalized = version.trim().to_ascii_lowercase();
    if normalized.is_empty() || normalized.len() > TAPE_API_MAX_VERSION_LENGTH {
        return None;
    }
    if normalized
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.'))
    {
        Some(normalized)
    } else {
        None
    }
}

#[cfg(target_arch = "wasm32")]
async fn handle_cache_api_request(
    request: Request,
    url: url::Url,
    env: Env,
    origin: Option<&str>,
) -> worker::Result<Response> {
    if request.method() == Method::Options {
        return with_cache_api_headers(Response::empty()?.with_status(204), origin);
    }

    let relative_path = cache_api_relative_path(url.path())
        .unwrap_or("")
        .trim_start_matches('/');

    if relative_path == "batch" {
        if request.method() != Method::Post {
            return cache_api_json(
                &serde_json::json!({ "error": "Method not allowed" }),
                405,
                origin,
            );
        }
        return handle_batch_request(request, &env, origin).await;
    }

    cache_api_json(&serde_json::json!({ "error": "Not found" }), 404, origin)
}

#[cfg(target_arch = "wasm32")]
async fn handle_source_audio_api_request(
    mut request: Request,
    url: url::Url,
    env: Env,
    origin: Option<&str>,
) -> worker::Result<Response> {
    if request.method() == Method::Options {
        return with_cache_api_headers(Response::empty()?.with_status(204), origin);
    }

    let relative_path = source_audio_api_relative_path(url.path())
        .unwrap_or("")
        .trim_start_matches('/');
    let Some((object_id, action)) = parse_source_audio_object_action(relative_path) else {
        return cache_api_json(&serde_json::json!({ "error": "Not found" }), 404, origin);
    };

    match (request.method(), action.as_str()) {
        (Method::Post, "uploads") => {
            source_audio_create_upload(&mut request, &env, &object_id, origin).await
        }
        (Method::Post, "chunks") => {
            source_audio_append_chunk(&mut request, &env, &object_id, origin).await
        }
        (Method::Post, "seal") => source_audio_seal_upload(&env, &object_id, origin).await,
        (Method::Get, "manifest") => source_audio_read_manifest(&env, &object_id, origin).await,
        _ => cache_api_json(
            &serde_json::json!({ "error": "Method not allowed" }),
            405,
            origin,
        ),
    }
}

fn parse_source_audio_object_action(relative_path: &str) -> Option<(String, String)> {
    let parts = relative_path.split('/').collect::<Vec<_>>();
    if parts.len() != 3 || parts[0] != "objects" || parts[1].is_empty() || parts[2].is_empty() {
        return None;
    }
    let object_id = urlencoding::decode(parts[1]).ok()?.into_owned();
    if !is_valid_source_audio_object_id(&object_id) {
        return None;
    }
    Some((object_id, parts[2].to_ascii_lowercase()))
}

fn is_valid_source_audio_object_id(object_id: &str) -> bool {
    !object_id.is_empty()
        && object_id.len() <= 128
        && object_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
}

fn source_audio_object_hash(object_id: &str) -> String {
    sha256_hex(object_id.as_bytes())
}

fn source_audio_state_key(object_hash: &str) -> String {
    format!("{SOURCE_AUDIO_OBJECT_NAMESPACE}/{object_hash}/upload-state.json")
}

fn source_audio_manifest_key(object_hash: &str) -> String {
    format!("{SOURCE_AUDIO_OBJECT_NAMESPACE}/{object_hash}/manifest.json")
}

fn source_audio_chunk_key(object_hash: &str, index: usize, chunk_hash: &str) -> String {
    format!("{SOURCE_AUDIO_OBJECT_NAMESPACE}/{object_hash}/chunks/{index:06}-{chunk_hash}.bce1")
}

#[cfg(target_arch = "wasm32")]
async fn source_audio_read_state(
    env: &Env,
    object_hash: &str,
) -> worker::Result<Option<SourceAudioUploadState>> {
    let bucket = env.bucket(CACHE_API_R2_BINDING)?;
    let Some(object) = bucket
        .get(&source_audio_state_key(object_hash))
        .execute()
        .await?
    else {
        return Ok(None);
    };
    let Some(body) = object.body() else {
        return Ok(None);
    };
    let bytes = body.bytes().await?;
    if bytes.len() > SOURCE_AUDIO_UPLOAD_STATE_MAX_BYTES {
        return Ok(None);
    }
    Ok(serde_json::from_slice(&bytes).ok())
}

#[cfg(target_arch = "wasm32")]
async fn source_audio_write_state(env: &Env, state: &SourceAudioUploadState) -> worker::Result<()> {
    let bucket = env.bucket(CACHE_API_R2_BINDING)?;
    let bytes = serde_json::to_vec(state)?;
    if bytes.len() > SOURCE_AUDIO_UPLOAD_STATE_MAX_BYTES {
        return Err(worker::Error::RustError(
            "source-audio upload state is too large".to_string(),
        ));
    }
    let mut http_metadata = HttpMetadata::default();
    http_metadata.content_type = Some(CACHE_API_JSON_CONTENT_TYPE.to_string());
    bucket
        .put(&source_audio_state_key(&state.object_hash), bytes)
        .http_metadata(http_metadata)
        .execute()
        .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn source_audio_create_upload(
    request: &mut Request,
    env: &Env,
    object_id: &str,
    origin: Option<&str>,
) -> worker::Result<Response> {
    let bytes = request.bytes().await?;
    if bytes.len() > SOURCE_AUDIO_UPLOAD_STATE_MAX_BYTES {
        return cache_api_json(
            &serde_json::json!({ "error": "Upload metadata is too large" }),
            413,
            origin,
        );
    }
    let metadata = if bytes.is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_slice(&bytes).unwrap_or_else(|_| serde_json::json!({}))
    };
    let object_hash = source_audio_object_hash(object_id);
    let state = SourceAudioUploadState {
        object_id: object_id.to_string(),
        object_hash: object_hash.clone(),
        sealed: false,
        metadata,
        chunks: Vec::new(),
    };
    source_audio_write_state(env, &state).await?;
    cache_api_json(
        &serde_json::json!({
            "ok": true,
            "objectId": object_id,
            "objectHash": object_hash,
            "chunkCount": 0
        }),
        201,
        origin,
    )
}

#[cfg(target_arch = "wasm32")]
async fn source_audio_append_chunk(
    request: &mut Request,
    env: &Env,
    object_id: &str,
    origin: Option<&str>,
) -> worker::Result<Response> {
    let object_hash = source_audio_object_hash(object_id);
    let Some(mut state) = source_audio_read_state(env, &object_hash).await? else {
        return cache_api_json(
            &serde_json::json!({ "error": "Upload has not been created" }),
            404,
            origin,
        );
    };
    if state.sealed {
        return cache_api_json(
            &serde_json::json!({ "error": "Upload is already sealed" }),
            409,
            origin,
        );
    }
    let bytes = request.bytes().await?;
    if bytes.is_empty() || bytes.len() > SOURCE_AUDIO_UPLOAD_CHUNK_MAX_BYTES {
        return cache_api_json(
            &serde_json::json!({ "error": "Invalid source-audio chunk size" }),
            400,
            origin,
        );
    }
    let chunk_hash = sha256_hex(&bytes);
    let index = state.chunks.len();
    let object_key = source_audio_chunk_key(&object_hash, index, &chunk_hash);
    let bucket = env.bucket(CACHE_API_R2_BINDING)?;
    let mut metadata = HashMap::new();
    metadata.insert("objectHash".to_string(), object_hash.clone());
    metadata.insert("chunkIndex".to_string(), index.to_string());
    metadata.insert("sha256".to_string(), chunk_hash.clone());
    let mut http_metadata = HttpMetadata::default();
    http_metadata.content_type = Some(CACHE_API_OPUS_CONTENT_TYPE.to_string());
    bucket
        .put(&object_key, bytes.clone())
        .custom_metadata(metadata)
        .http_metadata(http_metadata)
        .execute()
        .await?;
    let chunk = SourceAudioChunkManifest {
        index,
        byte_length: bytes.len(),
        sha256: chunk_hash,
        object_key,
    };
    state.chunks.push(chunk.clone());
    source_audio_write_state(env, &state).await?;
    cache_api_json(
        &serde_json::json!({
            "ok": true,
            "objectId": object_id,
            "objectHash": object_hash,
            "chunk": chunk
        }),
        201,
        origin,
    )
}

#[cfg(target_arch = "wasm32")]
async fn source_audio_seal_upload(
    env: &Env,
    object_id: &str,
    origin: Option<&str>,
) -> worker::Result<Response> {
    let object_hash = source_audio_object_hash(object_id);
    let Some(mut state) = source_audio_read_state(env, &object_hash).await? else {
        return cache_api_json(
            &serde_json::json!({ "error": "Upload has not been created" }),
            404,
            origin,
        );
    };
    if state.chunks.is_empty() {
        return cache_api_json(
            &serde_json::json!({ "error": "Upload has no chunks" }),
            400,
            origin,
        );
    }
    state.sealed = true;
    source_audio_write_state(env, &state).await?;
    let manifest = serde_json::json!({
        "ok": true,
        "format": "bitneedle-source-audio-object-v1",
        "objectId": state.object_id,
        "objectHash": state.object_hash,
        "sealed": true,
        "metadata": state.metadata,
        "chunkCount": state.chunks.len(),
        "byteLength": state.chunks.iter().map(|chunk| chunk.byte_length).sum::<usize>(),
        "chunks": state.chunks,
    });
    let bucket = env.bucket(CACHE_API_R2_BINDING)?;
    let bytes = serde_json::to_vec(&manifest)?;
    let mut http_metadata = HttpMetadata::default();
    http_metadata.content_type = Some(CACHE_API_JSON_CONTENT_TYPE.to_string());
    bucket
        .put(&source_audio_manifest_key(&object_hash), bytes)
        .http_metadata(http_metadata)
        .execute()
        .await?;
    cache_api_json(&manifest, 200, origin)
}

#[cfg(target_arch = "wasm32")]
async fn source_audio_read_manifest(
    env: &Env,
    object_id: &str,
    origin: Option<&str>,
) -> worker::Result<Response> {
    let object_hash = source_audio_object_hash(object_id);
    let bucket = env.bucket(CACHE_API_R2_BINDING)?;
    let Some(object) = bucket
        .get(&source_audio_manifest_key(&object_hash))
        .execute()
        .await?
    else {
        return cache_api_json(&serde_json::json!({ "error": "Not found" }), 404, origin);
    };
    let Some(body) = object.body() else {
        return cache_api_json(
            &serde_json::json!({ "error": "Manifest body unavailable" }),
            500,
            origin,
        );
    };
    let headers = Headers::new();
    headers.set("Content-Type", CACHE_API_JSON_CONTENT_TYPE)?;
    headers.set("Cache-Control", "no-store")?;
    with_cache_api_headers(
        Response::from_bytes(body.bytes().await?)?
            .with_status(200)
            .with_headers(headers),
        origin,
    )
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == CACHE_API_HASH_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_opus_proof(proof: &serde_json::Value, payload: &[u8]) -> Result<(), &'static str> {
    // recordHeader must be present and decode to plausible bytes.
    let record_header = proof
        .get("recordHeader")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or("proof.recordHeader is missing")?;

    let encoded = record_header
        .strip_prefix("ecdc-v2:")
        .ok_or("proof.recordHeader must use the ecdc-v2 prefix")?;

    let header_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .or_else(|_| general_purpose::URL_SAFE.decode(encoded))
        .or_else(|_| general_purpose::STANDARD.decode(encoded))
        .map_err(|_| "proof.recordHeader base64 is invalid")?;

    if header_bytes.len() < 8 {
        return Err("proof.recordHeader is too small to be a valid header");
    }

    // chunkByteLength must be a positive integer.
    let chunk_byte_length = proof
        .get("chunkByteLength")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if chunk_byte_length == 0 {
        return Err("proof.chunkByteLength is missing or zero");
    }

    // bodyByteLength must exactly match the payload we actually received.
    // This ties the proof to this specific upload and catches truncation/inflation.
    let declared_body_len = proof
        .get("bodyByteLength")
        .and_then(|v| v.as_u64())
        .ok_or("proof.bodyByteLength is missing")?;
    if declared_body_len as usize != payload.len() {
        return Err("proof.bodyByteLength does not match payload");
    }

    Ok(())
}

fn is_bce1_envelope(payload: &[u8]) -> bool {
    payload.len()
        >= record_descriptor::CacheEncryptionEnvelope::HEADER_LENGTH
            + record_descriptor::CACHE_ENCRYPTION_TAG_LENGTH
        && payload.get(0..4) == Some(record_descriptor::CACHE_ENCRYPTION_ENVELOPE_MAGIC.as_slice())
}

fn validate_bce1_envelope(payload: &[u8]) -> Result<(), &'static str> {
    if payload.len() > CACHE_API_MAX_BCE1_ENVELOPE_BYTES {
        return Err("BCE1 envelope is too large");
    }

    let envelope = record_descriptor::CacheEncryptionEnvelope::parse(payload)
        .map_err(|_| "BCE1 envelope is invalid")?;

    if envelope.plaintext_length as usize > CACHE_API_MAX_OPUS_PAYLOAD_BYTES {
        return Err("BCE1 envelope declares an oversized plaintext");
    }

    if envelope.ciphertext.len()
        > CACHE_API_MAX_OPUS_PAYLOAD_BYTES + record_descriptor::CACHE_ENCRYPTION_TAG_LENGTH
    {
        return Err("BCE1 envelope ciphertext is too large");
    }

    Ok(())
}

const CACHE_API_KEY_PREFIX_MAX_LENGTH: usize = 32;

// Keys look like `<prefix>/<16-or-64-hex>[:version]`, e.g.
// `ecdc-opus/ab12...:v1`. The prefix names the object type (today only
// `ecdc-opus` is produced) and is carried straight through into the R2
// object path so objects stay listable/debuggable per type, rather than
// being folded invisibly into the hash.
fn parse_batch_cache_key(key: &str) -> Option<(String, String, String)> {
    let trimmed = key.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return None;
    }
    let (prefix, rest) = trimmed.split_once('/')?;
    if prefix.is_empty()
        || prefix.len() > CACHE_API_KEY_PREFIX_MAX_LENGTH
        || !prefix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return None;
    }
    let (lookup_key, version_part) = match rest.split_once(':') {
        Some((lookup_key, version)) => (lookup_key, version),
        None => (rest, TAPE_API_DEFAULT_VERSION),
    };
    if !((lookup_key.len() == 16 || lookup_key.len() == 64)
        && lookup_key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    {
        return None;
    }
    let version = normalize_tape_version(version_part)?;
    Some((prefix.to_string(), lookup_key.to_string(), version))
}

fn opus_pointer_object_key(prefix: &str, lookup_key: &str, version: &str) -> String {
    format!(
        "{version}/lookup/{prefix}/{}/{}/{}",
        &lookup_key[0..2],
        &lookup_key[2..4],
        lookup_key
    )
}

fn opus_content_object_key(prefix: &str, content_hash_hex: &str, version: &str) -> String {
    format!(
        "{version}/sha256/{prefix}/{}/{}/{}",
        &content_hash_hex[0..2],
        &content_hash_hex[2..4],
        content_hash_hex
    )
}

#[cfg(target_arch = "wasm32")]
struct CacheApiPresignConfig {
    account_id: String,
    bucket_name: String,
    access_key_id: String,
    secret_access_key: String,
    expires_seconds: u32,
}

#[cfg(target_arch = "wasm32")]
struct PresignedGetUrl {
    url: String,
    expires_at: String,
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(sha256_bytes(bytes))
}

#[cfg(target_arch = "wasm32")]
fn hmac_sha256(key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).map_err(|_| "Invalid HMAC key".to_string())?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().to_vec())
}

#[cfg(target_arch = "wasm32")]
fn cache_api_presign_config(env: &Env) -> Result<CacheApiPresignConfig, worker::Error> {
    let account_id = env.var("R2_PRESIGN_ACCOUNT_ID")?.to_string();
    let bucket_name = env.var("R2_PRESIGN_BUCKET_NAME")?.to_string();
    let access_key_id = env.var("R2_PRESIGN_ACCESS_KEY_ID")?.to_string();
    let secret_access_key = env.var("R2_PRESIGN_SECRET_ACCESS_KEY")?.to_string();
    let expires_seconds = env
        .var("R2_PRESIGN_EXPIRES_SECONDS")
        .ok()
        .and_then(|value| value.to_string().parse::<u32>().ok())
        .filter(|value| (1..=604_800).contains(value))
        .unwrap_or(CACHE_API_PRESIGN_EXPIRES_SECONDS);
    Ok(CacheApiPresignConfig {
        account_id,
        bucket_name,
        access_key_id,
        secret_access_key,
        expires_seconds,
    })
}

#[cfg(target_arch = "wasm32")]
fn iso8601_basic_utc_now() -> (String, String, f64) {
    let date = js_sys::Date::new_0();
    let year = date.get_utc_full_year();
    let month = date.get_utc_month() + 1;
    let day = date.get_utc_date();
    let hours = date.get_utc_hours();
    let minutes = date.get_utc_minutes();
    let seconds = date.get_utc_seconds();
    let date_stamp = format!("{year:04}{month:02}{day:02}");
    let timestamp = format!("{date_stamp}T{hours:02}{minutes:02}{seconds:02}Z");
    (date_stamp, timestamp, date.get_time())
}

#[cfg(target_arch = "wasm32")]
fn uri_encode_path(path: &str) -> String {
    path.split('/')
        .map(urlencoding::encode)
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(target_arch = "wasm32")]
fn presign_r2_get_url(
    config: &CacheApiPresignConfig,
    object_key: &str,
) -> Result<PresignedGetUrl, String> {
    let (date_stamp, timestamp, now_ms) = iso8601_basic_utc_now();
    let host = format!(
        "{}.{}.r2.cloudflarestorage.com",
        config.bucket_name, config.account_id
    );
    let canonical_uri = format!("/{}", uri_encode_path(object_key));
    let credential_scope = format!("{date_stamp}/auto/s3/aws4_request");
    let credential = format!("{}/{}", config.access_key_id, credential_scope);
    let canonical_query = format!(
        "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential={}&X-Amz-Date={}&X-Amz-Expires={}&X-Amz-SignedHeaders=host&x-id=GetObject",
        urlencoding::encode(&credential),
        timestamp,
        config.expires_seconds,
    );
    let canonical_headers = format!("host:{host}\n");
    let canonical_request = format!(
        "GET\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\nhost\nUNSIGNED-PAYLOAD"
    );
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{timestamp}\n{credential_scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let k_date = hmac_sha256(
        format!("AWS4{}", config.secret_access_key).as_bytes(),
        date_stamp.as_bytes(),
    )?;
    let k_region = hmac_sha256(&k_date, b"auto")?;
    let k_service = hmac_sha256(&k_region, b"s3")?;
    let k_signing = hmac_sha256(&k_service, b"aws4_request")?;
    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes())?);
    let expires_at = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(
        now_ms + (config.expires_seconds as f64 * 1000.0),
    ))
    .to_iso_string()
    .as_string()
    .unwrap_or_default();
    Ok(PresignedGetUrl {
        url: format!("https://{host}{canonical_uri}?{canonical_query}&X-Amz-Signature={signature}"),
        expires_at,
    })
}

#[cfg(target_arch = "wasm32")]
async fn handle_batch_request(
    mut request: Request,
    env: &Env,
    origin: Option<&str>,
) -> worker::Result<Response> {
    let accept_header = request
        .headers()
        .get("Accept")
        .ok()
        .flatten()
        .unwrap_or_default();
    let prefer_stream_response = accept_header
        .split(',')
        .map(|part| part.trim())
        .any(|part| part == CACHE_API_BATCH_STREAM_CONTENT_TYPE || part == "*/*");
    let body_bytes = request.bytes().await?;
    let raw: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => {
            return cache_api_json(
                &serde_json::json!({ "error": "Invalid JSON body" }),
                400,
                origin,
            );
        }
    };

    if raw.get("writes").is_some() {
        let req: BatchWriteRequest = match serde_json::from_value(raw) {
            Ok(v) => v,
            Err(_) => {
                return cache_api_json(
                    &serde_json::json!({ "error": "Invalid batch write request" }),
                    400,
                    origin,
                );
            }
        };
        handle_batch_write(req, env, origin).await
    } else {
        let req: BatchReadRequest = match serde_json::from_value(raw) {
            Ok(v) => v,
            Err(_) => {
                return cache_api_json(
                    &serde_json::json!({ "error": "Invalid batch read request" }),
                    400,
                    origin,
                );
            }
        };
        handle_batch_read(req, env, origin, prefer_stream_response).await
    }
}

#[cfg(target_arch = "wasm32")]
async fn handle_batch_read(
    req: BatchReadRequest,
    env: &Env,
    origin: Option<&str>,
    prefer_stream_response: bool,
) -> worker::Result<Response> {
    let bucket = env.bucket(CACHE_API_R2_BINDING)?;
    let presign_config = cache_api_presign_config(env).ok();
    let mut frame_buf: Vec<u8> = Vec::new();
    let mut keys: Vec<BatchReadKeyResult> = Vec::new();

    {
        for raw_key in req.keys.iter().take(CACHE_API_MAX_READ_BATCH_ENTRIES) {
            let Some((prefix, lookup_key, version)) = parse_batch_cache_key(raw_key) else {
                keys.push(BatchReadKeyResult {
                    key: raw_key.trim().to_ascii_lowercase(),
                    hit: false,
                    content_hash: None,
                    direct_get_url: None,
                    direct_get_expires_at: None,
                });
                continue;
            };
            let key = if version == TAPE_API_DEFAULT_VERSION {
                format!("{prefix}/{lookup_key}")
            } else {
                format!("{prefix}/{lookup_key}:{version}")
            };
            // Resolve the caller's pre-decode lookup key to the content hash
            // it currently points at, then fetch the actual content-addressed
            // blob. Both hops happen server-side; the client still only ever
            // deals in lookup keys.
            let pointer_key = opus_pointer_object_key(&prefix, &lookup_key, &version);
            let Some(pointer_object) = bucket.get(&pointer_key).execute().await? else {
                keys.push(BatchReadKeyResult {
                    key,
                    hit: false,
                    content_hash: None,
                    direct_get_url: None,
                    direct_get_expires_at: None,
                });
                continue;
            };
            let Some(pointer_body_handle) = pointer_object.body() else {
                keys.push(BatchReadKeyResult {
                    key,
                    hit: false,
                    content_hash: None,
                    direct_get_url: None,
                    direct_get_expires_at: None,
                });
                continue;
            };
            let pointer_bytes = pointer_body_handle.bytes().await?;
            let Ok(content_hash_hex) = String::from_utf8(pointer_bytes) else {
                keys.push(BatchReadKeyResult {
                    key,
                    hit: false,
                    content_hash: None,
                    direct_get_url: None,
                    direct_get_expires_at: None,
                });
                continue;
            };
            if !is_sha256_hex(&content_hash_hex) {
                keys.push(BatchReadKeyResult {
                    key,
                    hit: false,
                    content_hash: None,
                    direct_get_url: None,
                    direct_get_expires_at: None,
                });
                continue;
            }
            let content_key = opus_content_object_key(&prefix, &content_hash_hex, &version);
            let Some(object) = bucket.get(&content_key).execute().await? else {
                keys.push(BatchReadKeyResult {
                    key,
                    hit: false,
                    content_hash: Some(content_hash_hex),
                    direct_get_url: None,
                    direct_get_expires_at: None,
                });
                continue;
            };
            let direct_get = presign_config
                .as_ref()
                .and_then(|config| presign_r2_get_url(config, &content_key).ok());
            keys.push(BatchReadKeyResult {
                key: key.clone(),
                hit: true,
                content_hash: Some(content_hash_hex.clone()),
                direct_get_url: direct_get.as_ref().map(|value| value.url.clone()),
                direct_get_expires_at: direct_get.as_ref().map(|value| value.expires_at.clone()),
            });
            if !prefer_stream_response {
                continue;
            }
            let Some(body_handle) = object.body() else {
                continue;
            };
            let payload = body_handle.bytes().await?;
            if payload.is_empty() {
                continue;
            }
            let key_bytes = key.as_bytes();
            frame_buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            frame_buf.extend_from_slice(&(key_bytes.len() as u16).to_be_bytes());
            frame_buf.extend_from_slice(key_bytes);
            frame_buf.extend_from_slice(&payload);
        }
    }

    if !prefer_stream_response {
        return cache_api_json(
            &BatchReadResponse {
                format: CACHE_API_BATCH_JSON_FORMAT.to_string(),
                results: keys,
            },
            200,
            origin,
        );
    }

    let headers = Headers::new();
    headers.set("Content-Type", CACHE_API_BATCH_STREAM_CONTENT_TYPE)?;
    headers.set("Cache-Control", "no-store")?;
    with_cache_api_headers(
        Response::from_bytes(frame_buf)?
            .with_status(200)
            .with_headers(headers),
        origin,
    )
}

#[cfg(target_arch = "wasm32")]
async fn handle_batch_write(
    req: BatchWriteRequest,
    env: &Env,
    origin: Option<&str>,
) -> worker::Result<Response> {
    let bucket = env.bucket(CACHE_API_R2_BINDING)?;

    // Entries land concurrently: each write is up to three R2 round
    // trips, and running thirty-two of them in a line was the 20-second
    // sync timeout. Anything past the cap answers stored:false instead
    // of being silently dropped, so the client knows to resend.
    let capped = req.writes.len().min(CACHE_API_MAX_WRITE_BATCH_ENTRIES);
    let mut results = futures_util::future::join_all(
        req.writes[..capped]
            .iter()
            .map(|entry| write_batch_entry(&bucket, entry)),
    )
    .await
    .into_iter()
    .collect::<worker::Result<Vec<_>>>()?;
    results.extend(
        req.writes[capped..]
            .iter()
            .map(|_| BatchWriteResult { stored: false }),
    );

    cache_api_json(
        &BatchWriteResponse {
            format: CACHE_API_BATCH_FORMAT.to_string(),
            results,
        },
        200,
        origin,
    )
}

#[cfg(target_arch = "wasm32")]
async fn write_batch_entry(
    bucket: &worker::Bucket,
    entry: &BatchWriteEntry,
) -> worker::Result<BatchWriteResult> {
        let Some((prefix, lookup_key, version)) = parse_batch_cache_key(&entry.key) else {
            return Ok(BatchWriteResult { stored: false });
        };

        // Decode payload first so the proof's bodyByteLength can be verified against it.
        let payload = general_purpose::STANDARD
            .decode(&entry.payload_base64)
            .or_else(|_| general_purpose::URL_SAFE_NO_PAD.decode(&entry.payload_base64))
            .or_else(|_| general_purpose::URL_SAFE.decode(&entry.payload_base64));
        let payload = match payload {
            Ok(b) => b,
            Err(_) => {
                return Ok(BatchWriteResult { stored: false });
            }
        };

        let envelope_valid = is_bce1_envelope(&payload);
        let payload_valid = envelope_valid && validate_bce1_envelope(&payload).is_ok();

        if !payload_valid {
            return Ok(BatchWriteResult { stored: false });
        }

        // Full proof guard: header decode, chunkByteLength present, bodyByteLength matches.
        let proof_valid = entry
            .proof
            .as_ref()
            .is_some_and(|p| validate_opus_proof(p, &payload).is_ok());
        if !proof_valid {
            return Ok(BatchWriteResult { stored: false });
        }

        // The content object is addressed by the hash of the exact bytes
        // being stored (the full BCE1 envelope), computed here rather than
        // trusted from the client. A deterministic nonce (see
        // record_descriptor::derive_cache_nonce) means the same (record,
        // plaintext, context) always produces the same envelope bytes, so
        // this write-once skip is now actually correct: two writers racing
        // to store the same logical chunk always compute the same content
        // hash and the same bytes.
        let content_hash_hex = sha256_hex(&payload);
        let content_key = opus_content_object_key(&prefix, &content_hash_hex, &version);

        if bucket.head(&content_key).await?.is_none() {
            let mut metadata = HashMap::new();
            metadata.insert("format".to_string(), "bce1".to_string());
            metadata.insert(
                "innerFormat".to_string(),
                "soundkit-v2-opus-stream".to_string(),
            );
            metadata.insert("contentHash".to_string(), content_hash_hex.clone());
            metadata.insert("byteLength".to_string(), payload.len().to_string());

            let mut http_metadata = HttpMetadata::default();
            http_metadata.content_type = Some(CACHE_API_OPUS_CONTENT_TYPE.to_string());

            bucket
                .put(&content_key, payload)
                .custom_metadata(metadata)
                .http_metadata(http_metadata)
                .execute()
                .await?;
        }

        // The pointer is small and always safe to overwrite: even under a
        // write race for the same lookup key, both writers resolve to the
        // same content hash (deterministic nonce), so the pointer converges
        // regardless of ordering.
        let pointer_key = opus_pointer_object_key(&prefix, &lookup_key, &version);
        bucket
            .put(&pointer_key, content_hash_hex.into_bytes())
            .execute()
            .await?;

    Ok(BatchWriteResult { stored: true })
}


#[cfg(target_arch = "wasm32")]
fn cache_api_json<T: Serialize>(
    payload: &T,
    status: u16,
    origin: Option<&str>,
) -> worker::Result<Response> {
    let headers = Headers::new();
    headers.set("Content-Type", CACHE_API_JSON_CONTENT_TYPE)?;
    headers.set("Cache-Control", "no-store")?;
    let body = format!("{}\n", serde_json::to_string(payload)?);
    with_cache_api_headers(
        Response::ok(body)?
            .with_status(status)
            .with_headers(headers),
        origin,
    )
}

#[cfg(target_arch = "wasm32")]
fn with_cache_api_headers(
    mut response: Response,
    origin: Option<&str>,
) -> worker::Result<Response> {
    let headers = response.headers_mut();
    headers.set("Cross-Origin-Opener-Policy", "same-origin")?;
    headers.set("Cross-Origin-Embedder-Policy", "require-corp")?;
    headers.set("Cross-Origin-Resource-Policy", "cross-origin")?;
    headers.set("X-Content-Type-Options", "nosniff")?;
    headers.set("Referrer-Policy", "strict-origin-when-cross-origin")?;
    headers.set("Access-Control-Allow-Methods", "POST, OPTIONS")?;
    headers.set("Access-Control-Allow-Headers", "Content-Type")?;
    headers.set(
        "Access-Control-Expose-Headers",
        "Content-Length, ETag, X-Play-Cache-SHA256, X-Play-Cache-Bytes",
    )?;
    headers.set("Access-Control-Max-Age", "86400")?;

    if let Some(origin) = allowed_cache_api_origin(origin) {
        headers.set("Access-Control-Allow-Origin", origin)?;
        headers.append("Vary", "Origin")?;
    }

    Ok(response)
}

fn allowed_cache_api_origin(origin: Option<&str>) -> Option<&str> {
    let origin = origin?.trim();
    if origin.is_empty() {
        return None;
    }

    let url = url::Url::parse(origin).ok()?;
    let hostname = url.host_str()?.to_ascii_lowercase();

    if matches!(
        hostname.as_str(),
        "wavey.ai"
            | "www.wavey.ai"
            | "yl.vin"
            | "www.yl.vin"
            | "local.yl.vin"
            | "local.infidelity.io"
            | "localhost"
            | "127.0.0.1"
            | "air.local"
    ) || is_private_lan_hostname(&hostname)
    {
        Some(origin)
    } else {
        None
    }
}

fn is_private_lan_hostname(hostname: &str) -> bool {
    if hostname.starts_with("10.") || hostname.starts_with("192.168.") {
        return true;
    }

    let Some(rest) = hostname.strip_prefix("172.") else {
        return false;
    };

    let Some(second_octet) = rest
        .split('.')
        .next()
        .and_then(|part| part.parse::<u8>().ok())
    else {
        return false;
    };

    (16..=31).contains(&second_octet)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn accepts_sha256_key() {
        assert!(is_sha256_hex(TEST_HASH));
    }

    #[test]
    fn rejects_uppercase_sha256_key() {
        assert!(!is_sha256_hex(
            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
        ));
    }

    #[test]
    fn content_hash_is_stable() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn derives_sharded_pointer_key() {
        let lookup_key = "0123456789abcdef";
        assert_eq!(
            opus_pointer_object_key("ecdc-opus", lookup_key, "v1"),
            format!("v1/lookup/ecdc-opus/01/23/{lookup_key}")
        );
    }

    #[test]
    fn derives_sharded_content_key() {
        assert_eq!(
            opus_content_object_key("ecdc-opus", TEST_HASH, "v1"),
            format!("v1/sha256/ecdc-opus/01/23/{TEST_HASH}")
        );
    }

    #[test]
    fn parses_prefixed_versioned_batch_key() {
        assert_eq!(
            parse_batch_cache_key("ecdc-opus/0123456789abcdef:v1"),
            Some((
                "ecdc-opus".to_string(),
                "0123456789abcdef".to_string(),
                "v1".to_string()
            ))
        );
        assert_eq!(parse_batch_cache_key("0123456789abcdef"), None);
        assert_eq!(parse_batch_cache_key("bad/prefix!!/0123456789abcdef"), None);
    }
}
