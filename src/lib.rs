#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

use base64::{engine::general_purpose, Engine as _};
#[cfg(target_arch = "wasm32")]
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(target_arch = "wasm32")]
use std::collections::HashMap;

/// The product owns the path. Everything the store answers is under it.
const TAPE_PREFIX: &str = "/tape";
const CACHE_API_JSON_CONTENT_TYPE: &str = "application/json";
const TAPE_API_DEFAULT_VERSION: &str = "v1";
const TAPE_API_MAX_VERSION_LENGTH: usize = 32;
const CACHE_API_R2_BINDING: &str = "CACHE_BUCKET";

/// The protocol, in three strings.
///
/// A lookup is answered without reading R2 at all: the envelope lives under a
/// key the caller can derive for itself, so every answer is a signature over
/// a string. The client fetches the object from storage and reads a 404 as
/// the miss. That is the whole read path — there is no pointer to resolve, no
/// second object to confirm, and nothing for the Worker to stream.
const CACHE_API_LOOKUP_FORMAT: &str = "vin-yl-tape-lookup-v3";
const CACHE_API_WRITE_FORMAT: &str = "vin-yl-tape-write-v3";
/// A store request asks for signed uploads instead of signed reads. It only
/// answers for the content-addressed namespace: a `blob` key *is* the SHA-256
/// of the bytes, so the worst a bad upload can do is occupy a name nothing
/// will ever ask for. Chunk-cache writes keep the proxied path, where the
/// record-header proof is worth the round trip.
const CACHE_API_STORE_FORMAT: &str = "vin-yl-tape-store-v3";
/// The content-addressed namespace. Every version of a recording lives here —
/// the master, the lossless copy, the Opus, the stems — addressed only by
/// what it contains. Who owns what is a question for a layer above this one.
const CACHE_API_BLOB_PREFIX: &str = "blob";
const CACHE_API_RESPONSE_FORMAT: &str = "vin-yl-tape-batch-v3";
// The stored object is the full BCE1 encrypted envelope, not a bare Opus
// packet stream — the inner codec identity travels in the envelope's
// AAD-bound cache-encryption context, not in this content type.
const CACHE_API_OPUS_CONTENT_TYPE: &str = "application/vnd.bitneedle.bce1+binary";
// Reads carry a signed URL per key and cost no I/O, so the batch can be
// large. Writes carry the chunk payloads themselves, so that cap stays
// conservative.
const CACHE_API_MAX_READ_BATCH_ENTRIES: usize = 256;
const CACHE_API_MAX_WRITE_BATCH_ENTRIES: usize = 32;
const CACHE_API_PRESIGN_EXPIRES_SECONDS: u32 = 300;
// Per-chunk limits: 2s × 128kbps stereo with 4× headroom.
const CACHE_API_MAX_OPUS_PAYLOAD_BYTES: usize = 131_072; // 128 KB
const CACHE_API_MAX_BCE1_ENVELOPE_BYTES: usize =
    record_descriptor::CacheEncryptionEnvelope::HEADER_LENGTH
        + CACHE_API_MAX_OPUS_PAYLOAD_BYTES
        + record_descriptor::CACHE_ENCRYPTION_TAG_LENGTH;

#[derive(Debug, Deserialize)]
struct BatchReadRequest {
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    keys: Vec<String>,
}

/// What a signed request answers with: one URL per key, for the action that
/// was asked for. There is no `hit` — the Worker did not look, and saying so
/// would be a guess. A key it cannot sign comes back without a URL, which is
/// the only miss this response can state honestly.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PresignedReadKeyResult {
    key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
}

#[derive(Debug, Serialize)]
struct PresignedReadResponse {
    format: String,
    results: Vec<PresignedReadKeyResult>,
}

#[derive(Debug, Deserialize)]
struct BatchWriteRequest {
    #[serde(default)]
    format: Option<String>,
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

#[cfg(target_arch = "wasm32")]
use worker::*;

#[cfg(target_arch = "wasm32")]
#[event(fetch)]
pub async fn main(request: Request, env: Env, _ctx: worker::Context) -> worker::Result<Response> {
    console_error_panic_hook::set_once();

    let url = request.url()?;
    if !is_tape_path(url.path()) {
        return Response::ok("Not found\n").map(|response| response.with_status(404));
    }

    let origin = request.headers().get("Origin").ok().flatten();
    let result = handle_cache_api_request(request, url, env, origin.as_deref()).await;

    match result {
        Ok(response) => Ok(response),
        Err(error) => {
            console_warn!("[tape] request failed: {}", error);
            cache_api_json(
                &serde_json::json!({ "error": "Cache API request failed" }),
                500,
                origin.as_deref(),
            )
        }
    }
}

fn is_tape_path(pathname: &str) -> bool {
    pathname == TAPE_PREFIX || pathname.starts_with(&format!("{TAPE_PREFIX}/"))
}

fn cache_api_relative_path(pathname: &str) -> Option<&str> {
    pathname.strip_prefix(TAPE_PREFIX)
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
// `ecdc-opus/ab12...:v1` or `blob/9f3c...`. The prefix names the namespace
// and is carried straight through into the object path, so objects stay
// listable per type rather than folded invisibly into a hash.
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

/// Where an object lives. One layout for everything the store holds: the
/// namespace it was asked for, sharded by the first two byte-pairs of the
/// key. `ecdc-opus` keys are derived from a record and address a chunk of
/// decoded audio; `blob` keys are the SHA-256 of the bytes themselves, which
/// is how every other version of a recording is addressed — masters, stems,
/// the lossless copy. Same store, one address space.
fn tape_object_key(prefix: &str, key: &str, version: &str) -> String {
    format!(
        "{version}/{prefix}/{}/{}/{}",
        &key[0..2],
        &key[2..4],
        key
    )
}

#[cfg(target_arch = "wasm32")]
fn presign_r2_get_url(
    config: &CacheApiPresignConfig,
    object_key: &str,
) -> Result<PresignedGetUrl, String> {
    presign_r2_url(config, "GET", "GetObject", object_key)
}

/// A signed upload. The caller names the object by the SHA-256 of the bytes
/// it is about to send, so bytes that do not match their name land under a
/// name nobody will ask for. Large objects never pass through the Worker.
#[cfg(target_arch = "wasm32")]
fn presign_r2_put_url(
    config: &CacheApiPresignConfig,
    object_key: &str,
) -> Result<PresignedGetUrl, String> {
    presign_r2_url(config, "PUT", "PutObject", object_key)
}

#[cfg(target_arch = "wasm32")]
fn presign_r2_url(
    config: &CacheApiPresignConfig,
    method: &str,
    action: &str,
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
        "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential={}&X-Amz-Date={}&X-Amz-Expires={}&X-Amz-SignedHeaders=host&x-id={action}",
        urlencoding::encode(&credential),
        timestamp,
        config.expires_seconds,
    );
    let canonical_headers = format!("host:{host}\n");
    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\nhost\nUNSIGNED-PAYLOAD"
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
async fn handle_batch_request(
    mut request: Request,
    env: &Env,
    origin: Option<&str>,
) -> worker::Result<Response> {
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
        handle_batch_read(&req, env, origin)
    }
}

/// The whole batch, answered without a single R2 call.
///
/// Every key becomes a signature over a derived object key, which is pure
/// computation — the reason the batch ceiling can be 256 and still finish
/// inside one round trip. It is also the only thing in this Worker that
/// spends real CPU, so it is what the 10 ms budget is actually spent on.
#[cfg(target_arch = "wasm32")]
fn handle_batch_read(
    req: &BatchReadRequest,
    env: &Env,
    origin: Option<&str>,
) -> worker::Result<Response> {
    let store = match req.format.as_deref() {
        Some(CACHE_API_LOOKUP_FORMAT) => false,
        Some(CACHE_API_STORE_FORMAT) => true,
        _ => {
            return cache_api_json(
                &serde_json::json!({ "error": "Unsupported batch lookup format" }),
                400,
                origin,
            );
        }
    };
    let Ok(presign_config) = cache_api_presign_config(env) else {
        return cache_api_json(
            &serde_json::json!({ "error": "Signed lookups are not configured" }),
            503,
            origin,
        );
    };

    let results = req
        .keys
        .iter()
        .take(CACHE_API_MAX_READ_BATCH_ENTRIES)
        .map(|raw_key| {
            let Some((prefix, lookup_key, version)) = parse_batch_cache_key(raw_key) else {
                return PresignedReadKeyResult {
                    key: raw_key.trim().to_ascii_lowercase(),
                    url: None,
                    expires_at: None,
                };
            };
            let key = if version == TAPE_API_DEFAULT_VERSION {
                format!("{prefix}/{lookup_key}")
            } else {
                format!("{prefix}/{lookup_key}:{version}")
            };
            // Uploads are signed for the content-addressed namespace only.
            if store && prefix != CACHE_API_BLOB_PREFIX {
                return PresignedReadKeyResult {
                    key,
                    url: None,
                    expires_at: None,
                };
            }
            let object_key = tape_object_key(&prefix, &lookup_key, &version);
            let signed = if store {
                presign_r2_put_url(&presign_config, &object_key)
            } else {
                presign_r2_get_url(&presign_config, &object_key)
            };
            match signed {
                Ok(signed) => PresignedReadKeyResult {
                    key,
                    url: Some(signed.url),
                    expires_at: Some(signed.expires_at),
                },
                Err(_) => PresignedReadKeyResult {
                    key,
                    url: None,
                    expires_at: None,
                },
            }
        })
        .collect::<Vec<_>>();

    cache_api_json(
        &PresignedReadResponse {
            format: CACHE_API_RESPONSE_FORMAT.to_string(),
            results,
        },
        200,
        origin,
    )
}

#[cfg(target_arch = "wasm32")]
async fn handle_batch_write(
    req: BatchWriteRequest,
    env: &Env,
    origin: Option<&str>,
) -> worker::Result<Response> {
    if req.format.as_deref() != Some(CACHE_API_WRITE_FORMAT) {
        return cache_api_json(
            &serde_json::json!({ "error": "Unsupported batch write format" }),
            400,
            origin,
        );
    }
    let bucket = env.bucket(CACHE_API_R2_BINDING)?;

    // Entries land concurrently: running thirty-two writes in a line was the
    // 20-second sync timeout. Anything past the cap answers stored:false
    // instead of being silently dropped, so the client knows to resend.
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
            format: CACHE_API_RESPONSE_FORMAT.to_string(),
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

    // One object, under the key the reader derives. Overwriting is safe: a
    // deterministic nonce (see record_descriptor::derive_cache_nonce) means
    // the same (record, plaintext, context) always encrypts to the same
    // bytes, so two writers racing on one chunk write the same thing. The
    // envelope is not hashed here — nothing addresses it by content any more,
    // and hashing a full batch was the largest CPU cost in the Worker.
    let mut metadata = HashMap::new();
    metadata.insert("format".to_string(), "bce1".to_string());
    metadata.insert(
        "innerFormat".to_string(),
        "soundkit-v2-opus-stream".to_string(),
    );
    metadata.insert("byteLength".to_string(), payload.len().to_string());

    let mut http_metadata = HttpMetadata::default();
    http_metadata.content_type = Some(CACHE_API_OPUS_CONTENT_TYPE.to_string());

    bucket
        .put(
            &tape_object_key(&prefix, &lookup_key, &version),
            payload,
        )
        .custom_metadata(metadata)
        .http_metadata(http_metadata)
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

    #[test]
    fn content_hash_is_stable() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn derives_the_sharded_object_key() {
        let lookup_key = "0123456789abcdef";
        assert_eq!(
            tape_object_key("ecdc-opus", lookup_key, "v1"),
            format!("v1/ecdc-opus/01/23/{lookup_key}")
        );
        let content_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        assert_eq!(
            tape_object_key("blob", content_hash, "v1"),
            format!("v1/blob/ab/cd/{content_hash}")
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
