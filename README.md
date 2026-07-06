# vin.yl.tape

Standalone Cloudflare Worker repo for the play tape API.

This Worker provides an immutable, content-addressed tape store for individual `BRS1` chunks and record manifests.

The canonical public route in this repo is:

```text
/api/play/tape
```

The underlying cache payload formats and media types are intentionally kept compatible with the existing player clients.

Each completed chunk is stored as a separate Cloudflare R2 object using a `hash:version` identifier where `hash` is the SHA-256 digest of the exact serialized chunk bytes. The same Worker also stores a record-level manifest under the same version namespace.

## Architecture

The Worker uses:

- Cloudflare Workers for validation and HTTP routing
- Cloudflare R2 for durable binary object storage
- `record-core` for canonical `BCS2` parsing and validation
- SHA-256 content addresses for immutable object identity

It does not use:

- D1
- the Cloudflare Cache API
- a database index
- application-level batch retrieval
- ECDC-specific payload validation

The stored object is one serialized `BCS2` chunk, not an entire `BCS2` stream and not an entire song.

## Why the Validation Is BCS2-Level

A `BCS2` stream can contain payloads described by different payload descriptors. ECDC is one possible inner payload format, but it is not the cache protocol.

The Worker therefore validates the generic `BCS2` envelope:

- stream metadata header
- payload descriptor index
- chunk index and count
- optional nonce layout
- declared payload length
- CRC32
- exact serialized chunk boundary
- SHA-256 content address

It does not require the payload bytes to be ECDC.

This allows the same cache to hold chunks for ECDC and future payload containers without changing the storage protocol.

## Routes

All routes are below:

```text
/api/play/tape
```

### Read a chunk

```http
GET /api/play/tape/brs1-chunks/{sha256}
```

Returns the exact serialized `BCS2` chunk bytes.

### Check whether a chunk exists

```http
HEAD /api/play/tape/brs1-chunks/{sha256}
```

Returns `200` when the object exists and `404` otherwise.

### Store a chunk

```http
PUT /api/play/tape/brs1-chunks/{sha256}
```

Stores one validated serialized `BCS2` chunk.

### CORS preflight

```http
OPTIONS /api/play/tape/brs1-chunks/{sha256}
```

## Content Address

The `{sha256}` path component is the lowercase hexadecimal SHA-256 digest of the complete request body.

It must contain exactly 64 lowercase hexadecimal characters.

Example:

```text
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

The Worker recalculates the digest from the uploaded bytes and rejects the request when it differs from the URL.

The hash is calculated over the complete serialized chunk:

```text
chunk index
chunk count
payload descriptor index
payload length
CRC32
signature
optional nonce
payload
```

The inner payload alone is not the content-addressed object.

## R2 Object Layout

Objects are stored under:

```text
v1/brs1-chunks/sha256/{first-two-hex}/{next-two-hex}/{full-sha256}
```

Example:

```text
v1/brs1-chunks/sha256/ba/78/ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

The prefix sharding is not required by R2, but makes the namespace easier to inspect and keeps the layout explicit.

## PUT Request

A write request must use:

```http
Content-Type: application/vnd.bitneedle.bcs2-chunk+binary
X-Play-Cache-Body-Bytes: {decimal byte length}
X-Play-BCS2-Header: bcs2-v2:{base64url encoded BCS2 header}
```

The request body is the exact serialized chunk.

### BCS2 header proof

`X-Play-BCS2-Header` contains the stream header and metadata only:

```text
BCS2
u32 big-endian metadata length
metadata JSON
```

It must not contain any chunk bytes.

The recommended encoding is unpadded base64url:

```text
bcs2-v2:{base64url-no-padding}
```

Standard base64 and padded base64url are also accepted.

The header proof is necessary because an isolated serialized chunk does not carry the stream metadata needed to determine:

- the number of payload descriptors
- whether the stream is encrypted
- the per-chunk nonce length
- whether the chunk payload descriptor index is valid

## Upload Validation

The Worker rejects an upload unless all of the following are true:

1. The URL hash is a valid lowercase SHA-256 digest.
2. The content type is correct.
3. The body is non-empty.
4. The body is no larger than `1,900,000` bytes.
5. The declared body length matches the actual body length.
6. The supplied stream proof starts with `BCS2`.
7. The stream metadata length is valid.
8. The stream metadata is valid JSON.
9. The metadata satisfies the current `record-core` payload descriptor rules.
10. The chunk framing is valid under the metadata encryption settings.
11. The chunk contains no trailing bytes.
12. `chunkCount` is non-zero.
13. `chunkIndex` is smaller than `chunkCount`.
14. The payload descriptor index exists.
15. The payload CRC32 matches.
16. The SHA-256 of the complete serialized chunk matches the URL.

The Worker validates syntax and content identity. It does not currently verify the chunk signature against a trusted signer.

## Write Semantics

Objects are immutable by content address.

When the object does not exist:

```text
PUT
  -> validate
  -> calculate SHA-256
  -> write to R2
  -> return 201 stored
```

When the object already exists:

```text
PUT
  -> validate submitted body
  -> confirm the existing object length
  -> return 200 exists
```

A valid object is never intentionally replaced with different bytes because different bytes must have a different SHA-256 address.

Example successful response:

```json
{
  "hash": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  "status": "stored",
  "byteLength": 180234,
  "chunkIndex": 12,
  "chunkCount": 94,
  "payloadDescriptorIndex": 0,
  "payloadByteLength": 180157
}
```

An existing object returns the same shape with:

```json
{
  "status": "exists"
}
```

## Read Semantics

A successful `GET` returns:

```http
200 OK
Content-Type: application/vnd.bitneedle.bcs2-chunk+binary
Cache-Control: public, max-age=31536000, immutable
ETag: "sha256-{hash}"
X-Play-Cache-SHA256: {hash}
X-Play-Cache-Bytes: {byte length}
```

The Worker currently reads the R2 body, verifies the SHA-256 digest, and then returns it.

A missing object returns:

```http
404 Not Found
```

A successful `HEAD` returns the same metadata headers without the body.

## Player Recovery Flow

A player or encoder can save and recover one revolution at a time.

For each expected chunk:

```text
1. Obtain the expected serialized chunk SHA-256 from the record or local work state.
2. Send HEAD or GET for that hash.
3. On a hit, use the cached serialized chunk.
4. On a miss, generate or recover the chunk locally.
5. Calculate SHA-256 over the complete serialized chunk.
6. PUT the chunk with its BCS2 header proof.
7. Continue with the next revolution.
```

A player may skip `HEAD` and issue `GET` directly. A `404` is then the cache-miss signal.

For playback, use several independent `GET` requests over HTTP/2 or HTTP/3 and maintain a small prefetch window. R2 does not provide a native multi-object read operation.

## JavaScript Upload Example

```js
const bytes = serializedChunk;
const hash = await sha256Hex(bytes);
const header = toBase64Url(bcs2HeaderBytes);

const response = await fetch(
  `/api/play/tape/brs1-chunks/${hash}`,
  {
    method: "PUT",
    headers: {
      "Content-Type": "application/vnd.bitneedle.bcs2-chunk+binary",
      "X-Play-Cache-Body-Bytes": String(bytes.byteLength),
      "X-Play-BCS2-Header": `bcs2-v2:${header}`
    },
    body: bytes
  }
);

if (!response.ok) {
  throw new Error(await response.text());
}
```

## JavaScript Read Example

```js
const response = await fetch(
  `/api/play/tape/brs1-chunks/${hash}`
);

if (response.status === 404) {
  return null;
}

if (!response.ok) {
  throw new Error(await response.text());
}

const bytes = new Uint8Array(await response.arrayBuffer());
const actualHash = await sha256Hex(bytes);

if (actualHash !== hash) {
  throw new Error("Cached chunk hash mismatch");
}

return bytes;
```

Clients should still verify the returned SHA-256 digest even though the Worker performs server-side verification.

## Configuration

### R2 binding

Add this to the Worker's Wrangler configuration:

```toml
[[r2_buckets]]
binding = "CACHE_BUCKET"
bucket_name = "vinyl-play-cache"
preview_bucket_name = "vinyl-play-cache-preview"
```

Create the buckets before deployment if they do not already exist.

Example:

```sh
npx wrangler r2 bucket create vinyl-play-cache
npx wrangler r2 bucket create vinyl-play-cache-preview
```

If you want batch lookups to return direct R2 `GET` URLs, set these Worker secrets before deploying:

```sh
npx wrangler secret put R2_PRESIGN_ACCOUNT_ID
npx wrangler secret put R2_PRESIGN_BUCKET_NAME
npx wrangler secret put R2_PRESIGN_ACCESS_KEY_ID
npx wrangler secret put R2_PRESIGN_SECRET_ACCESS_KEY
```

Optional:

```sh
npx wrangler secret put R2_PRESIGN_EXPIRES_SECONDS
```

This repo also supports a local `.secrets` file for deployment. `make deploy` will:

1. Read `CLOUDFLARE_EMAIL` and `CLOUDFLARE_API_KEY` from `.secrets`
2. Push the `R2_PRESIGN_*` Worker secrets
3. Deploy the Worker with Wrangler

The checked-in `.secrets` template reads the existing Cloudflare API token from `../.cloudflare-token`, but you still need to fill in real R2 S3 API credentials for:

```sh
R2_PRESIGN_ACCESS_KEY_ID
R2_PRESIGN_SECRET_ACCESS_KEY
```

The presigned URLs target `*.r2.cloudflarestorage.com` directly, so bucket CORS must also allow your player origin such as `http://localhost:5193`.

### Rust dependencies

The Worker requires:

```toml
[dependencies]
base64 = "0.22"
console_error_panic_hook = "0.1"
hex = "0.4"
record-core = { path = "../../../bitneedle/record-core" }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha2 = "0.10"
url = "2"
urlencoding = "2"
worker = "0.8.5"
```

Adjust the `record-core` relative path to match the workspace.

## Local Development

Run the Worker with the project’s normal Wrangler command.

For example:

```sh
npx wrangler dev
```

The configured local origins include:

```text
localhost
127.0.0.1
air.local
local.infidelity.io
private 10.x.x.x addresses
private 172.16.x.x through 172.31.x.x addresses
private 192.168.x.x addresses
```

Production origins include:

```text
yl.vin
www.yl.vin
wavey.ai
www.wavey.ai
```

## Testing

The included tests cover:

- SHA-256 key validation
- uppercase hash rejection
- deterministic R2 key generation
- generic BCS2 chunk validation
- CRC mismatch rejection
- trailing-byte rejection
- stable SHA-256 calculation

Run:

```sh
cargo test
```

Because the Cloudflare Worker APIs are compiled only for `wasm32`, the pure validation helpers and tests remain available for normal host-target test runs.

## Security Model

The content-addressed design prevents a caller from writing arbitrary bytes under the hash of different bytes.

The BCS2 validator also prevents completely unstructured uploads.

It does not prevent an attacker from generating many syntactically valid BCS2 chunks and uploading each under its correct hash.

Format validation is therefore not a complete abuse-control system.

Recommended additional controls include:

- per-IP rate limits
- per-session write quotas
- maximum writes per time window
- short-lived upload grants
- requiring the chunk hash to appear in an authorised record manifest
- verifying BCS2 chunk signatures against a trusted record key
- Cloudflare WAF or rate-limiting rules
- R2 lifecycle rules for unreferenced objects

A useful future upload grant can bind:

```text
chunk SHA-256
stream metadata SHA-256
chunk index
chunk count
expiry
issuer signature
```

The Worker can then validate both the BCS2 structure and the right to populate that specific cache entry.

## Trust Boundary

Successful cache validation means:

- the object is a structurally valid serialized BCS2 chunk
- the object is internally CRC-consistent
- the URL is its actual SHA-256 content address
- the descriptor index is valid for the supplied metadata
- the chunk layout matches the supplied encryption metadata

It does not by itself mean:

- the artist authorised the chunk
- the payload is safe to decode
- the signature is trusted
- the supplied stream metadata belongs to an official release
- the object is referenced by a published record

Those checks belong to the player’s record verification and signing architecture, or to a future authenticated cache-write grant.

## Files

The implementation is expected at:

```text
workers/cache/src/lib.rs
```

The R2 binding is named:

```text
CACHE_BUCKET
```

The public object route is:

```text
/api/play/tape/brs1-chunks/{sha256}
```
# vin.yl.tape
