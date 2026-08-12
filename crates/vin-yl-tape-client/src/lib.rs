//! Shared client for encrypted YL.VIN tape cache entries.

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use record_descriptor::{
    cache_encryption_record_binding_hash_hex, decrypt_cache_envelope, encrypt_cache_envelope,
    CacheEncryptionContext, RecordDescriptor, CACHE_ENCRYPTION_SECRET_LENGTH,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const DEFAULT_API_BASE_URL: &str = "https://yl.vin/api/play/tape";
pub const CACHE_BATCH_FORMAT: &str = "bitneedle-player-cache-batch-v1";
pub const CACHE_BATCH_JSON_FORMAT: &str = "vin-yl-tape-batch-v2";
pub const CACHE_STORE_NAME: &str = "opus-chunks";
pub const CACHE_KEY_PREFIX: &str = "ecdc-opus";
pub const CACHE_KEY_DOMAIN: &str = "bitneedle.opus-chunk-cache-key.v1";
pub const CACHE_VERSION: &str = "bitneedle-opus-chunk-cache-v3";
pub const OUTPUT_CODEC: &str = "soundkit_opus_packets";
pub const OUTPUT_BITRATE: u32 = 64_000;
pub const MAX_BATCH_WRITES: usize = 32;
pub const MAX_BATCH_READS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordHeaderProof {
    pub record_header: String,
    pub chunk_index: u64,
    pub chunk_offset: u64,
    pub chunk_byte_length: usize,
    pub body_byte_length: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedTapeWrite {
    pub key: String,
    pub payload_base64: String,
    pub proof: RecordHeaderProof,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TapeBatchWriteRequest {
    pub format: String,
    pub writes: Vec<PreparedTapeWrite>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct TapeBatchWriteResult {
    pub stored: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct TapeBatchWriteResponse {
    pub format: String,
    pub results: Vec<TapeBatchWriteResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TapeBatchReadRequest {
    pub format: String,
    pub keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TapeBatchReadResult {
    pub key: String,
    pub hit: bool,
    pub content_hash: Option<String>,
    pub direct_get_url: Option<String>,
    pub direct_get_expires_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct TapeBatchReadResponse {
    pub format: String,
    pub results: Vec<TapeBatchReadResult>,
}

#[derive(Debug, Clone, Copy)]
pub struct EcdcOpusWriteInput<'a> {
    pub record_descriptor_json: &'a str,
    pub record_header: &'a str,
    pub source_payload: &'a [u8],
    pub opus_packet_stream: &'a [u8],
    pub chunk_index: u64,
    pub chunk_offset: u64,
    pub packet_offset: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct EcdcOpusReadInput<'a> {
    pub record_descriptor_json: &'a str,
    pub source_payload: &'a [u8],
}

pub fn generate_cache_encryption_secret_base64url() -> Result<String> {
    let mut secret = [0u8; CACHE_ENCRYPTION_SECRET_LENGTH];
    getrandom::getrandom(&mut secret).map_err(|error| {
        anyhow::anyhow!("failed to generate a cache-encryption secret: {error}")
    })?;
    Ok(general_purpose::URL_SAFE_NO_PAD.encode(secret))
}

pub fn ecdc_opus_cache_key(descriptor: &RecordDescriptor, source_payload: &[u8]) -> Result<String> {
    let binding_hash = cache_encryption_record_binding_hash_hex(descriptor)
        .context("failed to bind the cache key to the record")?;
    ecdc_opus_cache_key_from_binding_hash(source_payload, &binding_hash)
}

pub fn ecdc_opus_cache_key_from_binding_hash(
    source_payload: &[u8],
    binding_hash: &str,
) -> Result<String> {
    if source_payload.is_empty() {
        bail!("the ECDC source payload is empty");
    }
    let binding_hash = binding_hash.trim().to_ascii_lowercase();
    if binding_hash.len() != 64
        || !binding_hash
            .bytes()
            .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
    {
        bail!("the record binding hash is invalid");
    }
    let source_hash = hex::encode(Sha256::digest(source_payload));
    let preimage = format!(
        "{CACHE_KEY_DOMAIN}\nsource_payload_sha256={source_hash}\nrecord_binding_sha256={binding_hash}\noutput_codec={OUTPUT_CODEC}\nbitrate={OUTPUT_BITRATE}\ncache_version={CACHE_VERSION}\n"
    );
    let hash = hex::encode(Sha256::digest(preimage.as_bytes()));
    Ok(format!("{CACHE_KEY_PREFIX}/{hash}"))
}

pub fn batch_read_request(keys: Vec<String>) -> Result<TapeBatchReadRequest> {
    if keys.is_empty() {
        bail!("the tape lookup has no keys");
    }
    if keys.len() > MAX_BATCH_READS {
        bail!("the tape lookup exceeds {MAX_BATCH_READS} keys");
    }
    Ok(TapeBatchReadRequest {
        format: CACHE_BATCH_FORMAT.to_string(),
        keys,
    })
}

pub fn decrypt_ecdc_opus_entry(
    record_descriptor_json: &str,
    source_payload: &[u8],
    envelope: &[u8],
) -> Result<Vec<u8>> {
    let descriptor: RecordDescriptor = serde_json::from_str(record_descriptor_json)
        .context("the record descriptor JSON is invalid")?;
    descriptor
        .validate_cache_encryption()
        .context("the record cache-encryption descriptor is invalid")?;
    let key = ecdc_opus_cache_key(&descriptor, source_payload)?;
    let context = CacheEncryptionContext {
        protocol_version: 1,
        cache_format_version: 1,
        cache_store_name: CACHE_STORE_NAME.to_string(),
        cache_key: key,
        chunk_index: 0,
        packet_offset: 0,
        plaintext_length: 0,
        codec_identifier: OUTPUT_CODEC.to_string(),
    };
    decrypt_cache_envelope(&descriptor, &context, envelope)
        .context("failed to decrypt the tape cache entry")
}

pub fn prepare_ecdc_opus_write(input: EcdcOpusWriteInput<'_>) -> Result<PreparedTapeWrite> {
    if input.record_header.trim().is_empty() {
        bail!("the record header proof is empty");
    }
    if input.opus_packet_stream.is_empty() {
        bail!("the SoundKit Opus packet stream is empty");
    }
    let descriptor: RecordDescriptor = serde_json::from_str(input.record_descriptor_json)
        .context("the record descriptor JSON is invalid")?;
    descriptor
        .validate_cache_encryption()
        .context("the record cache-encryption descriptor is invalid")?;
    if descriptor.cache_encryption().is_none() {
        bail!("the record descriptor has no cache-encryption descriptor");
    }
    let key = ecdc_opus_cache_key(&descriptor, input.source_payload)?;
    let context = CacheEncryptionContext {
        protocol_version: 1,
        cache_format_version: 1,
        cache_store_name: CACHE_STORE_NAME.to_string(),
        cache_key: key.clone(),
        chunk_index: input.chunk_index,
        packet_offset: input.packet_offset,
        plaintext_length: input.opus_packet_stream.len(),
        codec_identifier: OUTPUT_CODEC.to_string(),
    };
    let envelope = encrypt_cache_envelope(&descriptor, &context, input.opus_packet_stream)
        .context("failed to encrypt the tape cache entry")?;
    Ok(PreparedTapeWrite {
        key,
        payload_base64: general_purpose::STANDARD.encode(&envelope),
        proof: RecordHeaderProof {
            record_header: input.record_header.to_string(),
            chunk_index: input.chunk_index,
            chunk_offset: input.chunk_offset,
            chunk_byte_length: input.source_payload.len(),
            body_byte_length: envelope.len(),
        },
    })
}

pub fn batch_write_request(writes: Vec<PreparedTapeWrite>) -> Result<TapeBatchWriteRequest> {
    if writes.is_empty() {
        bail!("the tape batch has no writes");
    }
    if writes.len() > MAX_BATCH_WRITES {
        bail!("the tape batch exceeds {MAX_BATCH_WRITES} writes");
    }
    Ok(TapeBatchWriteRequest {
        format: CACHE_BATCH_FORMAT.to_string(),
        writes,
    })
}

#[cfg(feature = "http")]
#[derive(Debug, Clone)]
pub struct TapeClient {
    api_base_url: String,
    http: reqwest::Client,
    retry_delays_ms: Vec<u64>,
}

#[cfg(feature = "http")]
impl TapeClient {
    pub fn new(api_base_url: impl Into<String>) -> Result<Self> {
        let api_base_url = api_base_url.into().trim().trim_end_matches('/').to_string();
        if api_base_url.is_empty() {
            bail!("the tape API URL is empty");
        }
        Ok(Self {
            api_base_url,
            http: reqwest::Client::builder()
                .build()
                .context("failed to create the tape HTTP client")?,
            retry_delays_ms: vec![180, 600],
        })
    }

    pub fn yl_vin() -> Result<Self> {
        Self::new(DEFAULT_API_BASE_URL)
    }

    pub fn with_retry_delays_ms(mut self, retry_delays_ms: Vec<u64>) -> Self {
        self.retry_delays_ms = retry_delays_ms;
        self
    }

    pub async fn upload_writes(&self, writes: Vec<PreparedTapeWrite>) -> Result<usize> {
        let mut stored = 0usize;
        for batch in writes.chunks(MAX_BATCH_WRITES) {
            stored += self.upload_batch(batch.to_vec()).await?;
        }
        Ok(stored)
    }

    pub async fn read_ecdc_opus(&self, input: EcdcOpusReadInput<'_>) -> Result<Option<Vec<u8>>> {
        let descriptor: RecordDescriptor = serde_json::from_str(input.record_descriptor_json)
            .context("the record descriptor JSON is invalid")?;
        descriptor
            .validate_cache_encryption()
            .context("the record cache-encryption descriptor is invalid")?;
        let key = ecdc_opus_cache_key(&descriptor, input.source_payload)?;
        let request = batch_read_request(vec![key.clone()])?;
        let url = format!("{}/batch", self.api_base_url);
        let response = self
            .http
            .post(&url)
            .header("Accept", "application/json")
            .json(&request)
            .send()
            .await
            .context("the tape lookup failed")?;
        if !response.status().is_success() {
            bail!("the tape lookup failed with status {}", response.status());
        }
        let response: TapeBatchReadResponse = response
            .json()
            .await
            .context("the tape lookup response is invalid")?;
        if response.format != CACHE_BATCH_JSON_FORMAT || response.results.len() != 1 {
            bail!("the tape lookup response format is invalid");
        }
        let result = &response.results[0];
        if result.key != key {
            bail!("the tape lookup returned the wrong key");
        }
        if !result.hit {
            return Ok(None);
        }
        let direct_get_url = result
            .direct_get_url
            .as_deref()
            .context("the tape lookup did not return a direct read URL")?;
        let envelope = self
            .http
            .get(direct_get_url)
            .send()
            .await
            .context("the tape object download failed")?;
        if !envelope.status().is_success() {
            bail!(
                "the tape object download failed with status {}",
                envelope.status()
            );
        }
        let envelope = envelope
            .bytes()
            .await
            .context("the tape object body is invalid")?;
        decrypt_ecdc_opus_entry(
            input.record_descriptor_json,
            input.source_payload,
            &envelope,
        )
        .map(Some)
    }

    async fn upload_batch(&self, writes: Vec<PreparedTapeWrite>) -> Result<usize> {
        let expected = writes.len();
        let request = batch_write_request(writes)?;
        let url = format!("{}/batch", self.api_base_url);
        let mut last_error = None;

        for attempt in 0..=self.retry_delays_ms.len() {
            match self
                .http
                .post(&url)
                .header("Accept", "application/json")
                .json(&request)
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => {
                    let response: TapeBatchWriteResponse = response
                        .json()
                        .await
                        .context("the tape batch response is invalid")?;
                    if response.format != CACHE_BATCH_FORMAT {
                        bail!("the tape batch response format is invalid");
                    }
                    if response.results.len() != expected {
                        bail!("the tape batch response count is invalid");
                    }
                    let accepted = response.results.iter().filter(|item| item.stored).count();
                    if accepted != expected {
                        bail!("the tape store rejected one or more cache entries");
                    }
                    return Ok(accepted);
                }
                Ok(response) if !response.status().is_server_error() => {
                    bail!(
                        "the tape store rejected the batch with status {}",
                        response.status()
                    );
                }
                Ok(response) => {
                    last_error = Some(format!("HTTP {}", response.status()));
                }
                Err(error) => {
                    last_error = Some(error.to_string());
                }
            }

            if let Some(delay) = self.retry_delays_ms.get(attempt) {
                futures_timer::Delay::new(std::time::Duration::from_millis(*delay)).await;
            }
        }

        bail!(
            "the tape upload failed after retries: {}",
            last_error.unwrap_or_else(|| "unknown transport error".to_string())
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use record_descriptor::{
        CacheEncryptionAlgorithm, CacheEncryptionDescriptor, CacheKeyDerivation,
        CACHE_ENCRYPTION_DESCRIPTOR_VERSION, PAYLOAD_ENCODING_RGB, RECORD_DESCRIPTOR_VERSION,
        RECORD_PROFILE_SINGLE45,
    };

    fn descriptor() -> RecordDescriptor {
        RecordDescriptor {
            version: RECORD_DESCRIPTOR_VERSION,
            checksum_protected: true,
            b_value_bits: 1.0f64.to_bits(),
            record_profile: RECORD_PROFILE_SINGLE45.to_string(),
            stream_byte_length: 4096,
            payload_encoding: PAYLOAD_ENCODING_RGB.to_string(),
            title: Some("Test".to_string()),
            artist: Some("Artist".to_string()),
            release_id: Some([0x11; 16]),
            catalog_number: None,
            label: None,
            artwork_credit: None,
            canonical_url: None,
            created_at: None,
            copyright_year: None,
            copyright_holder: None,
            signed_release_reference: None,
            bsc_pointer: None,
            tone_spans: Vec::new(),
            cache_encryption: Some(CacheEncryptionDescriptor {
                version: CACHE_ENCRYPTION_DESCRIPTOR_VERSION,
                algorithm: CacheEncryptionAlgorithm::XChaCha20Poly1305,
                key_derivation: CacheKeyDerivation::HkdfSha256,
                secret: vec![7; CACHE_ENCRYPTION_SECRET_LENGTH],
            }),
        }
    }

    #[test]
    fn generated_secret_has_the_required_length() {
        let secret = generate_cache_encryption_secret_base64url().expect("secret");
        let decoded = general_purpose::URL_SAFE_NO_PAD
            .decode(secret)
            .expect("base64url");
        assert_eq!(decoded.len(), CACHE_ENCRYPTION_SECRET_LENGTH);
    }

    #[test]
    fn cache_key_is_record_scoped_and_prefixed() {
        let first = ecdc_opus_cache_key(&descriptor(), b"first").expect("first key");
        let second = ecdc_opus_cache_key(&descriptor(), b"second").expect("second key");
        assert!(first.starts_with("ecdc-opus/"));
        assert_eq!(first.len(), "ecdc-opus/".len() + 64);
        assert_ne!(first, second);
    }

    #[test]
    fn cache_key_from_binding_matches_descriptor_key() {
        let descriptor = descriptor();
        let binding = cache_encryption_record_binding_hash_hex(&descriptor).expect("binding");
        assert_eq!(
            ecdc_opus_cache_key(&descriptor, b"source").expect("descriptor key"),
            ecdc_opus_cache_key_from_binding_hash(b"source", &binding).expect("binding key")
        );
    }

    #[test]
    fn prepared_write_contains_an_encrypted_bce1_envelope() {
        let descriptor_json = serde_json::to_string(&descriptor()).expect("descriptor JSON");
        let write = prepare_ecdc_opus_write(EcdcOpusWriteInput {
            record_descriptor_json: &descriptor_json,
            record_header: "ecdc-v2:RUNEQw",
            source_payload: b"ecdc chunk",
            opus_packet_stream: b"soundkit opus packets",
            chunk_index: 3,
            chunk_offset: 99,
            packet_offset: 194_880,
        })
        .expect("prepared write");
        let envelope = general_purpose::STANDARD
            .decode(write.payload_base64)
            .expect("envelope base64");
        assert_eq!(&envelope[..4], b"BCE1");
        assert_eq!(write.proof.body_byte_length, envelope.len());
        assert_eq!(write.proof.chunk_byte_length, b"ecdc chunk".len());
        let decrypted = decrypt_ecdc_opus_entry(&descriptor_json, b"ecdc chunk", &envelope)
            .expect("decrypted entry");
        assert_eq!(decrypted, b"soundkit opus packets");
    }
}
