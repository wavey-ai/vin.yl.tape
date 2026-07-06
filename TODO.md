# Bitneedle R2 Chunk Cache TODO

## Goal

Replace the current Cache API and D1 implementation with an immutable, content-addressed R2 cache that stores one serialized `BCS2` chunk per object.

The cache must support:

- recovery and resume one revolution at a time
- direct retrieval by SHA-256
- client-side cache population after a miss
- generic `BCS2` validation rather than ECDC-only validation
- future payload containers through `payloadDescriptors`
- safe immutable object semantics

## Priority 0 — Make the Worker Compile

### Replace the existing worker implementation

- Replace `workers/cache/src/lib.rs` with the R2-only implementation.
- Remove all D1 code.
- Remove all Cloudflare Cache API code.
- Remove batch read and batch write routes.
- Remove the old 16-character hexadecimal cache-key format.
- Remove the `opus-chunks` and `codec-chunks` store split unless another caller still depends on it.

Expected public route:

```text
/api/play/tape/brs1-chunks/{sha256}
```

### Add R2 binding

Add to Wrangler configuration:

```toml
[[r2_buckets]]
binding = "CACHE_BUCKET"
bucket_name = "vinyl-play-cache"
preview_bucket_name = "vinyl-play-cache-preview"
```

Create both buckets.

### Update dependencies

Add or verify:

```toml
base64 = "0.22"
hex = "0.4"
record-core = { path = "..." }
sha2 = "0.10"
worker = "..."
```

Remove D1-only dependencies when no longer used.

### Resolve Worker crate API differences

The provided implementation has not been compiled in the repository.

Verify the exact signatures for:

- `env.bucket`
- `bucket.get`
- `bucket.head`
- `bucket.put`
- `custom_metadata`
- `sha256`
- R2 object `size`
- R2 object `body`
- streaming versus buffered response bodies

Adjust the implementation to the actual `worker` crate version in the workspace.

### Run host tests

```sh
cargo test
```

or the correct package name.

### Build the WASM worker

```sh
npx wrangler deploy --dry-run
```

or the project’s existing build command.

## Priority 1 — Confirm the Cache Object Boundary

### Confirm one R2 object equals one complete serialized BCS2 chunk

The stored bytes should begin at:

```text
chunk index
```

and end at the end of that chunk payload.

They should not include:

- `BCS2` stream magic
- stream metadata length
- stream metadata JSON
- another chunk
- unrelated ECDC framing outside the BCS2 chunk payload

### Confirm revolution-to-chunk mapping

Verify whether one revolution always maps to exactly one BCS2 chunk.

If not, decide whether the cache unit is:

- one revolution
- one BCS2 chunk
- one revolution fragment

**Business decision required:** No, unless product behaviour requires revolution-level recovery even when the BCS2 chunking model differs.

### Confirm hash definition

Use:

```text
SHA-256(exact serialized BCS2 chunk bytes)
```

Do not hash only the inner payload.

Do not include the BCS2 stream header in the chunk content hash.

## Priority 2 — Reuse Canonical Record-Core Validation

### Avoid duplicating BCS2 parsing

Use `record-core` for:

- `stream_header_end`
- `payload_descriptor_count_from_metadata`
- `chunk_nonce_length_from_metadata`
- `read_chunk_header_with_nonce_length`
- `validate_payload_descriptor_index`
- `crc32_ieee`

Add a canonical helper to `record-core` if the Worker currently needs to compose several low-level calls.

Suggested API:

```rust
pub struct StandaloneChunkValidation {
    pub index: u16,
    pub chunk_count: u16,
    pub payload_descriptor_index: u8,
    pub payload_len: usize,
    pub crc32: u32,
}

pub fn validate_standalone_chunk(
    stream_header: &[u8],
    chunk_bytes: &[u8],
) -> Result<StandaloneChunkValidation>;
```

This should become the single validation implementation used by:

- the Worker
- browser/WASM code
- native encoders
- tests

### Add a canonical stream-header encoder

Add or expose a helper for creating the exact proof bytes:

```rust
pub fn chunk_stream_header_bytes(
    metadata_bytes: &[u8],
) -> Result<Vec<u8>>;
```

The client should not independently rebuild BCS2 framing in JavaScript when canonical Rust/WASM code is available.

## Priority 3 — Update the Player Read Path

### Replace batch reads

Remove player assumptions that cache hits arrive from:

```text
POST /batch
```

Replace with one `GET` per expected chunk hash.

### Add bounded prefetch

Maintain a small moving window, for example:

```text
current revolution
next 2–4 revolutions cached locally
next 1–2 requests in flight
```

Do not request the entire record at once.

### Use individual cache URLs

```text
GET /api/play/tape/brs1-chunks/{sha256}
```

### Verify every downloaded object

The player must calculate:

```text
SHA-256(downloaded bytes)
```

and compare it with the requested hash before accepting the chunk.

### Validate BCS2 locally

After hash verification, validate the serialized chunk against the record’s trusted BCS2 stream metadata.

Do not trust server validation as a replacement for player verification.

### Cache locally

Store valid chunks in IndexedDB using the full SHA-256 as the key.

Suggested key:

```text
bitneedle:bcs2-chunk:sha256:{hash}
```

## Priority 4 — Update the Player Write-Back Path

### Populate R2 after an initial miss

On cache miss:

1. recover or generate the serialized BCS2 chunk
2. validate it locally
3. calculate SHA-256
4. ensure it matches the expected record chunk hash
5. upload it to the Worker
6. continue playback without waiting for the upload when safe

### Send the BCS2 stream-header proof

Request headers:

```http
Content-Type: application/vnd.bitneedle.bcs2-chunk+binary
X-Play-Cache-Body-Bytes: {body length}
X-Play-BCS2-Header: bcs2-v2:{base64url header}
```

### Make write-back non-fatal

A cache upload failure must not fail playback.

Treat write-back as opportunistic:

```text
playback success
cache upload failure logged separately
```

### Deduplicate concurrent writes

Prevent multiple tabs or decode workers from uploading the same hash simultaneously.

Use an in-memory map keyed by hash:

```text
hash -> in-flight upload promise
```

### Add retry limits

Retry only transient failures:

- network failure
- `429`
- `500`
- `502`
- `503`
- `504`

Do not retry:

- `400`
- `409` hash mismatch
- `413`
- `415`

## Priority 5 — Strengthen Write Authorization

Format validation alone does not prevent storage abuse.

### Add rate limiting

Apply limits by:

- IP
- anonymous session ID
- authenticated account ID when available

Suggested initial controls:

- maximum body size: 1.9 MB
- maximum requests per minute
- maximum bytes per hour
- maximum concurrent uploads per client

**Business decision required:** Yes. Choose acceptable anonymous write limits and expected monthly storage exposure.

### Add short-lived cache-fill grants

Preferred design:

```text
type
version
chunkSha256
streamMetadataSha256
chunkIndex
chunkCount
expiresAt
nonce
issuerKeyId
signature
```

The player receives a grant only after a legitimate cache miss or trusted record verification.

The Worker verifies:

- grant signature
- expiry
- chunk hash
- stream metadata hash
- chunk index
- chunk count

**Business decision required:** Yes. Decide whether anonymous players may receive grants and which service issues them.

### Consider trusted manifest membership

Require proof that the requested chunk hash appears in an accepted record manifest.

Possible mechanisms:

- signed short-lived grant
- signed manifest supplied with the request
- platform lookup
- Merkle proof against a signed root

Do not add a database lookup unless necessary.

## Priority 6 — Signature Verification

### Decide whether cache writes must verify BCS2 chunk signatures

Current structural validation checks:

- framing
- metadata
- descriptor index
- nonce layout
- CRC
- content hash

It does not establish who created the chunk.

Possible policies:

1. Accept any structurally valid BCS2 chunk with a valid cache-fill grant.
2. Verify each chunk signature against a public key bound to the record.
3. Verify manifest membership only and leave chunk signature verification to players.

**Business decision required:** Yes.

Recommended first implementation:

```text
valid grant + structural validation + content hash
```

Keep player-side signature verification mandatory.

## Priority 7 — HTTP and R2 Behaviour

### Stream GET responses

Avoid reading the complete R2 object into a Worker `Vec<u8>` if the Rust Worker API supports passing through the R2 body stream.

The player already verifies SHA-256, so server-side rehashing on every GET may be unnecessary.

Recommended behaviour:

- verify on PUT
- trust immutable R2 object identity on GET
- return the R2 stream directly
- let the player verify the hash

### Preserve immutable caching headers

Return:

```http
Cache-Control: public, max-age=31536000, immutable
ETag: "sha256-{hash}"
```

### Consider a public custom domain

Potential route:

```text
https://cache.bitneedle.com/v1/brs1-chunks/sha256/ab/cd/{hash}
```

Uploads should remain Worker-controlled.

Reads may use:

- Worker endpoint
- public R2 custom domain
- CDN-cached route

**Business decision required:** Yes. Decide whether cached chunks are public by hash.

### Review CORS

Confirm required production origins.

Avoid allowing arbitrary private-LAN origins in production unless needed.

## Priority 8 — Resume and Recovery State

### Persist encoding progress locally

For each record job, store:

```text
stream metadata SHA-256
expected chunk count
completed chunk indexes
chunk SHA-256 values
upload status
```

### Resume without rebuilding completed chunks

On restart:

1. load local job state
2. verify locally stored chunks
3. `HEAD` or `GET` missing local chunks from R2
4. regenerate only actual misses
5. upload regenerated chunks

### Do not rely on R2 listing

Resume should use known expected hashes.

Do not list the bucket to discover progress.

## Priority 9 — Migration

### Identify current callers

Search for:

```text
/api/play/tape/batch
opus-chunks
codec-chunks
X-Bitneedle-Record-Header
X-Bitneedle-Cache-Chunk-Index
X-Bitneedle-Cache-Chunk-Offset
X-Bitneedle-Cache-Chunk-Bytes
16-character cache key
```

### Remove old client code

Delete:

- batch request builders
- framed batch response parsers
- D1 cache-hit response handling
- old store-name switching
- old u64 cache-key generation

### Decide whether old cache data is retained

The old keys are not cryptographic full-content addresses.

Migration options:

1. discard the old cache
2. read old entries and rewrite them under SHA-256 keys
3. temporarily support old reads only

**Business decision required:** Yes. Determine whether existing cache contents have enough value to migrate.

Recommended default:

```text
discard old cache and start clean
```

unless production cache population is expensive.

## Priority 10 — Tests

### Pure validation tests

Add tests for:

- valid unencrypted chunk
- valid encrypted chunk
- invalid stream magic
- malformed metadata length
- invalid metadata JSON
- missing payload descriptors
- invalid track listing
- invalid descriptor index
- zero chunk count
- index equal to chunk count
- truncated fixed header
- truncated nonce
- truncated payload
- trailing bytes
- CRC mismatch
- payload at maximum size
- payload above maximum size
- SHA-256 mismatch
- uppercase hash rejection

### Worker integration tests

Test:

- `PUT` new object returns `201`
- repeated `PUT` returns `200 exists`
- `GET` returns exact bytes
- `HEAD` returns metadata only
- missing object returns `404`
- wrong content type returns `415`
- wrong declared length returns `400`
- oversized upload returns `413`
- malformed proof returns `400`
- disallowed origin receives no CORS allow-origin header

### Resume integration test

Simulate:

1. generate several chunks
2. upload only some
3. restart the client
4. retrieve existing chunks
5. regenerate misses
6. upload misses
7. reconstruct the complete ordered stream

## Priority 11 — Observability

Add structured logs for:

```text
method
status
hash prefix
body length
chunk index
chunk count
validation failure category
R2 result
origin
```

Do not log:

- complete payloads
- complete signatures
- complete record metadata
- user-identifying account data

Add metrics for:

- GET hit rate
- PUT stored count
- PUT exists count
- validation rejection count
- bytes read
- bytes written
- R2 latency
- write-back failure rate
- recovery success rate

## Priority 12 — Lifecycle and Cost Controls

### Define retention

Content-addressed chunks are immutable, but not necessarily permanently valuable.

Possible retention policies:

- retain indefinitely
- delete chunks not referenced by a published record
- move cold chunks to a cheaper storage class
- delete abandoned anonymous uploads after a fixed period

**Business decision required:** Yes.

### Track references before garbage collection

Do not delete solely based on last access unless record manifests can confirm that no published record references the hash.

### Estimate storage growth

Model:

```text
average chunk bytes
× average chunks per record
× records created per month
× deduplication ratio
```

Add expected anonymous-abuse headroom.

## Definition of Done

The refactor is complete when:

- the Worker uses only R2 for payload persistence
- every object is addressed by full SHA-256
- one object stores exactly one serialized BCS2 chunk
- the Worker validates generic BCS2 framing
- the Worker does not assume ECDC
- the player reads chunks individually
- the player writes back valid chunks after misses
- write-back failures do not interrupt playback
- the player verifies downloaded hashes
- old D1 and Cache API paths are removed
- tests cover malformed and valid chunks
- deployment configuration includes the R2 bucket
- abuse controls have at least an initial rate limit
