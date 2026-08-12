# vin.yl.tape

This repository owns the YL.VIN encrypted playback cache.

It contains:

- the Rust client in `crates/vin-yl-tape-client`;
- the Rust Cloudflare Worker;
- the R2 object layout;
- the `/api/play/tape/` protocol.

The cache stores per-chunk SoundKit Opus streams. Clients encrypt each stream
before upload. The Worker only receives a `BCE1` encrypted envelope.

## Security model

A picture record contains the cache-encryption secret. The secret is a bearer
capability for its cached audio.

The Rust client derives a record-scoped lookup key from:

- the exact ECDC source chunk;
- the canonical record binding hash;
- the output codec and bitrate;
- the cache protocol version.

The client uses XChaCha20-Poly1305 to encrypt the Opus stream. The authenticated
context binds the envelope to its lookup key and codec.

The Worker does not receive the secret or plaintext audio.

## Tape API

The public base path is:

```text
https://yl.vin/api/play/tape
```

All reads and writes use:

```http
POST /api/play/tape/batch
```

A write request contains up to 32 encrypted entries. A read request contains up
to 256 record-scoped lookup keys.

The Worker returns a short-lived direct R2 URL for each read hit. The client
downloads the encrypted object and decrypts it locally with the picture record.

The API supports browser CORS requests. It does not require account credentials.

## R2 layout

The Worker stores two object types:

```text
v1/sha256/{prefix}/{first-two}/{next-two}/{sha256-of-bce1}
v1/lookup/{prefix}/{first-two}/{next-two}/{record-scoped-lookup-key}
```

The content object is immutable and content-addressed. The pointer maps the
record-scoped lookup key to the encrypted content hash.

## Client ownership

Applications must use `vin-yl-tape-client` for:

- cache-key derivation;
- `BCE1` encryption and decryption;
- batch request and response validation;
- upload acknowledgement;
- direct object retrieval.

Add the client with an HTTPS Cargo dependency:

```toml
vin-yl-tape-client = { git = "https://github.com/wavey-ai/vin.yl.tape.git", branch = "main" }
```

## Cloudflare configuration

The Worker uses the `CACHE_BUCKET` R2 binding. The deployed bucket is
`vin-yl-bucket-tape`.

The Worker has a 10 ms CPU limit for Cloudflare's free plan. Clients perform
codec and cryptographic work outside the Worker.

The Worker also retains `/api/bitneedle-source-audio` for resumable encrypted
source-audio storage. This API is separate from the playback cache.

## Validation

Run all Rust tests:

```sh
cargo test --workspace
```

Build the Worker:

```sh
npx wrangler deploy --dry-run
```
