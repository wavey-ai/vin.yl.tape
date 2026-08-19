//! Recordings in the tape store, in the shape they are played back from.
//!
//! Everything a recording exists as — the master, the FLAC preservation copy,
//! the SoundKit Opus, a stem — is stored the same way: as a SoundKit v2
//! stream cut into segments on frame boundaries, each segment sealed on its
//! own and addressed by what it contains. Nothing is stored as one opaque
//! file, because one opaque file cannot be played from the middle: a listener
//! who wants the last chorus would have to pull the whole master to hear it.
//!
//! A segment is a whole number of SoundKit v2 frames, so every segment starts
//! at a decodable boundary and carries its own timing (`FrameHeaderV2` holds
//! the codec, rate, channel count, sample count and PTS). The manifest lists
//! them in order with their PTS and sample counts, which makes it the seek
//! index: to play from a point in the track, take the segment whose span
//! covers it and start there. FLAC is not a special case — it is framed by
//! the same container and cut by the same rule.
//!
//! ## Sealing, and why the store still dedupes
//!
//! Each segment is encrypted before it is stored, with a key derived from the
//! segment's own plaintext hash (HKDF-SHA256) and a nonce derived the same
//! way. That is deliberate: identical audio always produces identical
//! ciphertext, so the object address — the SHA-256 of the *stored* bytes — is
//! stable, an upload is idempotent, and the same take stored twice occupies
//! one object. The manifest carries each segment's plaintext hash, which is
//! the capability: holding the manifest is holding the audio, and holding
//! neither leaves the store with bytes it cannot read.
//!
//! The trade is the one convergent encryption always makes: someone who
//! already holds a candidate file can confirm the store has it. Mixing a
//! per-vault secret into `derive_blob_keys` removes that and costs the
//! cross-account dedupe; the format carries a version byte so that change is
//! a new envelope version rather than a migration.

use anyhow::{bail, ensure, Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use frame_header::{EncodingFlag, FrameHeaderV2};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The content-addressed namespace in the tape store.
pub const BLOB_PREFIX: &str = "blob";
pub const BLOB_ENVELOPE_MAGIC: &[u8; 4] = b"TSB1";
pub const BLOB_ENVELOPE_VERSION: u8 = 1;
pub const BLOB_ENVELOPE_ALGORITHM_XCHACHA20POLY1305: u8 = 1;
pub const BLOB_ENVELOPE_HEADER_LENGTH: usize = 8;
pub const BLOB_KEY_INFO: &[u8] = b"vin.yl.tape.blob-key.v1";
pub const BLOB_NONCE_INFO: &[u8] = b"vin.yl.tape.blob-nonce.v1";
pub const BLOB_AAD_DOMAIN: &[u8] = b"vin.yl.tape.blob-aad.v1";
const BLOB_NONCE_LENGTH: usize = 24;

pub const STREAM_MANIFEST_FORMAT: &str = "vin-yl-tape-stream-v1";

/// A segment is cut when either ceiling is reached, whichever comes first.
///
/// The byte ceiling is what a phone can hold and decrypt in one piece; the
/// duration ceiling is what keeps a seek from pulling more audio than it
/// needs. They differ wildly by codec — eight seconds of 192 kbps Opus is a
/// couple of hundred kilobytes, eight seconds of 24-bit FLAC is megabytes —
/// which is exactly why both exist.
pub const SEGMENT_TARGET_BYTES: usize = 2 * 1024 * 1024;
pub const SEGMENT_TARGET_SECONDS: u64 = 8;

/// One segment of a stored stream: where it lives, what unlocks it, and the
/// span of the recording it covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TapeStreamSegment {
    /// The tape key, `blob/{sha256-of-the-stored-bytes}`.
    pub key: String,
    /// SHA-256 of the segment's plaintext. The key material, and the reason
    /// this manifest is the capability.
    pub plaintext_sha256: String,
    pub byte_length: usize,
    /// Presentation timestamp of the segment's first frame, when the encoder
    /// wrote one.
    pub first_pts: Option<u64>,
    /// Samples per channel in this segment — the seek index.
    pub sample_count: u64,
    pub frame_count: u32,
}

/// What a stored recording is: the stream's shape, and its segments in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TapeStreamManifest {
    pub format: String,
    pub codec: String,
    pub sample_rate: u32,
    pub channels: u8,
    pub bits_per_sample: u8,
    pub sample_count: u64,
    pub segments: Vec<TapeStreamSegment>,
}

impl TapeStreamManifest {
    /// Seconds of audio, from the sample count the frames declare.
    pub fn duration_seconds(&self) -> f64 {
        if self.sample_rate == 0 {
            return 0.0;
        }
        self.sample_count as f64 / f64::from(self.sample_rate)
    }

    /// The segment covering a point in the recording, for a seek.
    pub fn segment_at_sample(&self, sample: u64) -> Option<&TapeStreamSegment> {
        let mut cursor = 0u64;
        for segment in &self.segments {
            let end = cursor + segment.sample_count;
            if sample < end {
                return Some(segment);
            }
            cursor = end;
        }
        None
    }
}

/// A segment ready to be stored: the address, the bytes, and the hash that
/// opens them again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedBlob {
    pub key: String,
    pub plaintext_sha256: String,
    pub bytes: Vec<u8>,
}

/// A whole recording, ready to be stored. The manifest travels as a blob of
/// its own, so a caller only has to remember two strings to come back to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedStream {
    pub manifest: TapeStreamManifest,
    pub manifest_blob: SealedBlob,
    pub segments: Vec<SealedBlob>,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn derive_blob_keys(plaintext_sha256: &str) -> Result<([u8; 32], [u8; BLOB_NONCE_LENGTH])> {
    let ikm = hex::decode(plaintext_sha256).context("the plaintext hash is not hex")?;
    ensure!(ikm.len() == 32, "the plaintext hash is not a SHA-256");
    let hkdf = Hkdf::<Sha256>::new(Some(BLOB_AAD_DOMAIN), &ikm);
    let mut key = [0u8; 32];
    let mut nonce = [0u8; BLOB_NONCE_LENGTH];
    hkdf.expand(BLOB_KEY_INFO, &mut key)
        .map_err(|_| anyhow::anyhow!("the blob key could not be derived"))?;
    hkdf.expand(BLOB_NONCE_INFO, &mut nonce)
        .map_err(|_| anyhow::anyhow!("the blob nonce could not be derived"))?;
    Ok((key, nonce))
}

fn blob_envelope_header() -> [u8; BLOB_ENVELOPE_HEADER_LENGTH] {
    let mut header = [0u8; BLOB_ENVELOPE_HEADER_LENGTH];
    header[0..4].copy_from_slice(BLOB_ENVELOPE_MAGIC);
    header[4] = BLOB_ENVELOPE_VERSION;
    header[5] = BLOB_ENVELOPE_ALGORITHM_XCHACHA20POLY1305;
    header
}

fn blob_aad(plaintext_sha256: &str, plaintext_length: usize) -> Vec<u8> {
    let mut aad = Vec::with_capacity(BLOB_AAD_DOMAIN.len() + 96);
    aad.extend_from_slice(BLOB_AAD_DOMAIN);
    aad.push(BLOB_ENVELOPE_VERSION);
    aad.extend_from_slice(plaintext_sha256.as_bytes());
    aad.extend_from_slice(&(plaintext_length as u64).to_be_bytes());
    aad
}

/// Seals one blob. Deterministic: the same bytes always produce the same
/// envelope, and therefore the same address.
pub fn seal_blob(plaintext: &[u8]) -> Result<SealedBlob> {
    ensure!(!plaintext.is_empty(), "an empty blob cannot be stored");
    let plaintext_sha256 = sha256_hex(plaintext);
    let (key, nonce) = derive_blob_keys(&plaintext_sha256)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| anyhow::anyhow!("the blob cipher could not be created"))?;
    let aad = blob_aad(&plaintext_sha256, plaintext.len());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("the blob could not be sealed"))?;

    let mut bytes = Vec::with_capacity(BLOB_ENVELOPE_HEADER_LENGTH + ciphertext.len());
    bytes.extend_from_slice(&blob_envelope_header());
    bytes.extend_from_slice(&ciphertext);

    Ok(SealedBlob {
        key: format!("{BLOB_PREFIX}/{}", sha256_hex(&bytes)),
        plaintext_sha256,
        bytes,
    })
}

/// Opens a blob with the plaintext hash the manifest carries. The hash is
/// checked against what came back, so a substituted object fails here rather
/// than downstream.
pub fn open_blob(plaintext_sha256: &str, envelope: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        envelope.len() > BLOB_ENVELOPE_HEADER_LENGTH,
        "the blob envelope is truncated"
    );
    ensure!(
        &envelope[0..4] == BLOB_ENVELOPE_MAGIC,
        "the blob envelope is not a tape blob"
    );
    ensure!(
        envelope[4] == BLOB_ENVELOPE_VERSION,
        "the blob envelope version is unsupported"
    );
    ensure!(
        envelope[5] == BLOB_ENVELOPE_ALGORITHM_XCHACHA20POLY1305,
        "the blob envelope algorithm is unsupported"
    );

    let (key, nonce) = derive_blob_keys(plaintext_sha256)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| anyhow::anyhow!("the blob cipher could not be created"))?;
    let ciphertext = &envelope[BLOB_ENVELOPE_HEADER_LENGTH..];
    let plaintext_length = ciphertext
        .len()
        .checked_sub(16)
        .context("the blob envelope is truncated")?;
    let aad = blob_aad(plaintext_sha256, plaintext_length);
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("the blob could not be opened"))?;
    ensure!(
        sha256_hex(&plaintext) == plaintext_sha256.to_ascii_lowercase(),
        "the blob does not match the hash it was opened with"
    );
    Ok(plaintext)
}

/// One frame's place in a SoundKit v2 stream.
struct FrameSpan {
    start: usize,
    end: usize,
    sample_count: u64,
    pts: Option<u64>,
}

struct StreamShape {
    codec: String,
    sample_rate: u32,
    channels: u8,
    bits_per_sample: u8,
}

fn codec_name(encoding: &EncodingFlag) -> &'static str {
    match encoding {
        EncodingFlag::PCMSigned => "pcm-signed",
        EncodingFlag::PCMFloat => "pcm-float",
        EncodingFlag::Opus => "opus",
        EncodingFlag::FLAC => "flac",
        EncodingFlag::AAC => "aac",
        EncodingFlag::H264 => "h264",
    }
}

/// Walks the stream and records where every frame sits. A stream that does
/// not decode as SoundKit v2 is refused here rather than stored and found
/// unplayable later.
fn walk_frames(stream: &[u8]) -> Result<(StreamShape, Vec<FrameSpan>)> {
    let mut cursor = 0usize;
    let mut spans = Vec::new();
    let mut shape: Option<StreamShape> = None;

    while cursor < stream.len() {
        let remaining = &stream[cursor..];
        ensure!(
            remaining.len() >= FrameHeaderV2::BASE_SIZE,
            "the stream ends inside a frame header"
        );
        let mut reader = remaining;
        let header = FrameHeaderV2::decode(&mut reader)
            .map_err(|error| anyhow::anyhow!("the stream is not SoundKit v2: {error}"))?;
        let header_size = header.size();
        let payload_size = header.payload_size() as usize;
        let end = cursor
            .checked_add(header_size + payload_size)
            .filter(|end| *end <= stream.len())
            .context("a frame runs past the end of the stream")?;

        if shape.is_none() {
            shape = Some(StreamShape {
                codec: codec_name(header.encoding()).to_owned(),
                sample_rate: header.sample_rate(),
                channels: header.channels(),
                bits_per_sample: header.bits_per_sample(),
            });
        }

        spans.push(FrameSpan {
            start: cursor,
            end,
            sample_count: u64::from(header.frame_count()),
            pts: header.pts(),
        });
        cursor = end;
    }

    let shape = shape.context("the stream has no frames")?;
    ensure!(!spans.is_empty(), "the stream has no frames");
    Ok((shape, spans))
}

/// Cuts a SoundKit v2 stream into sealed segments and the manifest that puts
/// them back together. Pure: nothing here talks to the store.
pub fn seal_stream(stream: &[u8]) -> Result<SealedStream> {
    let (shape, frames) = walk_frames(stream)?;
    let sample_ceiling = u64::from(shape.sample_rate) * SEGMENT_TARGET_SECONDS;

    let mut segments = Vec::new();
    let mut sealed = Vec::new();
    let mut total_samples = 0u64;

    let mut start = frames[0].start;
    let mut first_pts = frames[0].pts;
    let mut samples = 0u64;
    let mut frame_count = 0u32;

    for (index, frame) in frames.iter().enumerate() {
        samples += frame.sample_count;
        frame_count += 1;
        let bytes = frame.end - start;
        let last = index + 1 == frames.len();
        let full = bytes >= SEGMENT_TARGET_BYTES
            || (sample_ceiling > 0 && samples >= sample_ceiling);
        if !last && !full {
            continue;
        }

        let blob = seal_blob(&stream[start..frame.end])?;
        segments.push(TapeStreamSegment {
            key: blob.key.clone(),
            plaintext_sha256: blob.plaintext_sha256.clone(),
            byte_length: blob.bytes.len(),
            first_pts,
            sample_count: samples,
            frame_count,
        });
        sealed.push(blob);
        total_samples += samples;

        if !last {
            start = frames[index + 1].start;
            first_pts = frames[index + 1].pts;
            samples = 0;
            frame_count = 0;
        }
    }

    let manifest = TapeStreamManifest {
        format: STREAM_MANIFEST_FORMAT.to_owned(),
        codec: shape.codec,
        sample_rate: shape.sample_rate,
        channels: shape.channels,
        bits_per_sample: shape.bits_per_sample,
        sample_count: total_samples,
        segments,
    };
    let manifest_json = serde_json::to_vec(&manifest).context("the manifest could not be encoded")?;
    let manifest_blob = seal_blob(&manifest_json)?;

    Ok(SealedStream {
        manifest,
        manifest_blob,
        segments: sealed,
    })
}

/// Stores something that is not a SoundKit v2 stream — an imported master in
/// whatever format it arrived as, an ECDC payload — as fixed-size segments
/// under the same manifest shape.
///
/// There are no frame boundaries to respect here, so the cut is arithmetic and
/// the manifest carries no timing: it is a byte index, not a seek index. Audio
/// that *can* be framed should go through `seal_stream` instead, because only
/// that one can be played from the middle.
pub fn seal_opaque_stream(bytes: &[u8], codec: &str) -> Result<SealedStream> {
    ensure!(!bytes.is_empty(), "an empty stream cannot be stored");
    let mut segments = Vec::new();
    let mut sealed = Vec::new();

    for slice in bytes.chunks(SEGMENT_TARGET_BYTES) {
        let blob = seal_blob(slice)?;
        segments.push(TapeStreamSegment {
            key: blob.key.clone(),
            plaintext_sha256: blob.plaintext_sha256.clone(),
            byte_length: blob.bytes.len(),
            first_pts: None,
            sample_count: 0,
            frame_count: 0,
        });
        sealed.push(blob);
    }

    let manifest = TapeStreamManifest {
        format: STREAM_MANIFEST_FORMAT.to_owned(),
        codec: codec.to_owned(),
        sample_rate: 0,
        channels: 0,
        bits_per_sample: 0,
        sample_count: 0,
        segments,
    };
    let manifest_json = serde_json::to_vec(&manifest).context("the manifest could not be encoded")?;
    let manifest_blob = seal_blob(&manifest_json)?;

    Ok(SealedStream {
        manifest,
        manifest_blob,
        segments: sealed,
    })
}

/// Reads a manifest back out of the blob it was stored as.
pub fn open_manifest(plaintext_sha256: &str, envelope: &[u8]) -> Result<TapeStreamManifest> {
    let bytes = open_blob(plaintext_sha256, envelope)?;
    let manifest: TapeStreamManifest =
        serde_json::from_slice(&bytes).context("the manifest is not valid JSON")?;
    if manifest.format != STREAM_MANIFEST_FORMAT {
        bail!("the manifest format is unsupported");
    }
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use frame_header::Endianness;
    use std::io::Cursor;

    /// A SoundKit v2 stream with `frames` frames of `payload` bytes each, the
    /// way an encoder writes one.
    fn soundkit_stream(encoding: EncodingFlag, frames: usize, payload: usize) -> Vec<u8> {
        let mut stream = Vec::new();
        for index in 0..frames {
            let header = FrameHeaderV2::new(
                encoding.clone(),
                payload as u32,
                960,
                48_000,
                2,
                16,
                Endianness::LittleEndian,
                Some(index as u64),
                Some(index as u64 * 960),
                None,
            )
            .expect("frame header");
            let mut encoded = Cursor::new(Vec::new());
            header.encode(&mut encoded).expect("encoded header");
            stream.extend_from_slice(&encoded.into_inner());
            stream.extend(std::iter::repeat(index as u8).take(payload));
        }
        stream
    }

    #[test]
    fn a_sealed_blob_opens_again() {
        let blob = seal_blob(b"a segment of audio").expect("sealed");
        assert!(blob.key.starts_with("blob/"));
        assert_eq!(blob.key.len(), "blob/".len() + 64);
        let opened = open_blob(&blob.plaintext_sha256, &blob.bytes).expect("opened");
        assert_eq!(opened, b"a segment of audio");
    }

    #[test]
    fn the_same_audio_seals_to_the_same_address() {
        let first = seal_blob(b"one take").expect("first");
        let second = seal_blob(b"one take").expect("second");
        assert_eq!(first.key, second.key);
        assert_eq!(first.bytes, second.bytes);
        let other = seal_blob(b"another take").expect("other");
        assert_ne!(first.key, other.key);
    }

    #[test]
    fn a_blob_will_not_open_with_the_wrong_hash() {
        let blob = seal_blob(b"a segment of audio").expect("sealed");
        let wrong = sha256_hex(b"something else");
        assert!(open_blob(&wrong, &blob.bytes).is_err());
    }

    #[test]
    fn a_stream_is_cut_on_frame_boundaries_and_reassembles() {
        let stream = soundkit_stream(EncodingFlag::Opus, 2_400, 512);
        let sealed = seal_stream(&stream).expect("sealed stream");

        assert_eq!(sealed.manifest.codec, "opus");
        assert_eq!(sealed.manifest.sample_rate, 48_000);
        assert_eq!(sealed.manifest.channels, 2);
        assert!(sealed.segments.len() > 1, "the stream should be cut up");
        assert_eq!(sealed.manifest.segments.len(), sealed.segments.len());
        assert_eq!(sealed.manifest.sample_count, 2_400 * 960);

        let mut rebuilt = Vec::new();
        for (segment, blob) in sealed.manifest.segments.iter().zip(&sealed.segments) {
            let bytes = open_blob(&segment.plaintext_sha256, &blob.bytes).expect("opened segment");
            rebuilt.extend_from_slice(&bytes);
        }
        assert_eq!(rebuilt, stream, "the segments must rebuild the stream");
    }

    #[test]
    fn flac_is_cut_by_the_same_rule() {
        let stream = soundkit_stream(EncodingFlag::FLAC, 600, 4_096);
        let sealed = seal_stream(&stream).expect("sealed stream");
        assert_eq!(sealed.manifest.codec, "flac");
        assert!(sealed.segments.len() > 1);

        let mut rebuilt = Vec::new();
        for (segment, blob) in sealed.manifest.segments.iter().zip(&sealed.segments) {
            rebuilt.extend_from_slice(
                &open_blob(&segment.plaintext_sha256, &blob.bytes).expect("opened segment"),
            );
        }
        assert_eq!(rebuilt, stream);
    }

    #[test]
    fn the_manifest_is_a_seek_index() {
        let stream = soundkit_stream(EncodingFlag::Opus, 2_400, 512);
        let sealed = seal_stream(&stream).expect("sealed stream");
        let manifest = &sealed.manifest;

        assert!((manifest.duration_seconds() - 48.0).abs() < 0.001);
        let first = manifest.segment_at_sample(0).expect("first segment");
        assert_eq!(Some(first), manifest.segments.first());
        let late = manifest
            .segment_at_sample(manifest.sample_count - 1)
            .expect("last segment");
        assert_eq!(Some(late), manifest.segments.last());
        assert!(manifest.segment_at_sample(manifest.sample_count).is_none());
    }

    #[test]
    fn a_manifest_round_trips_through_its_own_blob() {
        let stream = soundkit_stream(EncodingFlag::Opus, 120, 512);
        let sealed = seal_stream(&stream).expect("sealed stream");
        let manifest = open_manifest(
            &sealed.manifest_blob.plaintext_sha256,
            &sealed.manifest_blob.bytes,
        )
        .expect("manifest");
        assert_eq!(manifest, sealed.manifest);
    }

    #[test]
    fn a_stream_that_is_not_soundkit_is_refused() {
        assert!(seal_stream(b"not a stream at all, just bytes").is_err());
    }

    #[test]
    fn an_opaque_stream_is_cut_by_size_and_reassembles() {
        let bytes = (0..(SEGMENT_TARGET_BYTES * 2 + 1024))
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let sealed = seal_opaque_stream(&bytes, "wav").expect("sealed");
        assert_eq!(sealed.manifest.codec, "wav");
        assert_eq!(sealed.segments.len(), 3);
        assert_eq!(sealed.manifest.sample_count, 0, "no timing is claimed");

        let mut rebuilt = Vec::new();
        for (segment, blob) in sealed.manifest.segments.iter().zip(&sealed.segments) {
            rebuilt.extend_from_slice(
                &open_blob(&segment.plaintext_sha256, &blob.bytes).expect("opened"),
            );
        }
        assert_eq!(rebuilt, bytes);
    }
}
