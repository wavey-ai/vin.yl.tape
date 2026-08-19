# vin.yl.tape

This repository owns the YL.VIN encrypted store: every version of a
recording — the master, the lossless copy, the Opus, the stems — and the
decoded-chunk playback cache, in one content-addressed bucket.

It contains:

- the Rust client in `crates/vin-yl-tape-client`;
- the Rust Cloudflare Worker;
- the R2 object layout;
- the `/tape/` protocol.

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
https://yl.vin/tape
```

All reads and writes use:

```http
POST /tape/batch
```

A read is a *signed lookup*. The Worker does not touch R2: the envelope for a
lookup key is stored under that key, so the answer is a signed URL per key and
nothing else. The client fetches each object from storage itself and reads a
404 as the miss. A 256-key lookup is one round trip.

```json
{ "format": "vin-yl-tape-lookup-v3", "keys": ["ecdc-opus/…"] }
```

```json
{ "format": "vin-yl-tape-batch-v3",
  "results": [{ "key": "ecdc-opus/…", "directGetUrl": "…", "directGetExpiresAt": "…" }] }
```

There is no `hit` field, because the Worker did not look.

A store request asks for signed uploads instead:

```json
{ "format": "vin-yl-tape-store-v3", "keys": ["blob/{sha256-of-the-bytes}"] }
```

It answers in the same shape, with `PUT` URLs. Large objects never pass
through the Worker. Uploads are signed for the content-addressed `blob`
namespace only: a blob key *is* the SHA-256 of its bytes, so an upload that
does not match its name lands under a name nothing will ever ask for.

A write carries up to 32 encrypted entries, each with the record-header proof
the Worker validates before storing:

```json
{ "format": "vin-yl-tape-write-v3",
  "writes": [{ "key": "ecdc-opus/…", "payloadBase64": "…", "proof": { … } }] }
```

Requests in any other format are rejected. The API supports browser CORS
requests and requires no account credentials.

## R2 layout

One layout for everything, sharded by the first two byte-pairs of the key:

```text
{version}/{namespace}/{first-two}/{next-two}/{key}
```

Two namespaces:

- `ecdc-opus` — the playback cache. The key is derived from the record and
  the source chunk, because a reader has to address the object *before* it
  has the audio that would hash to it.
- `blob` — everything else a recording exists as: masters, stems, the FLAC
  preservation copy, the Opus. The key is the SHA-256 of the stored bytes.
  Whoever holds the hash holds the capability; which account owns which blob
  is a question for a layer above this one, and this Worker never asks it.

Nothing is addressed by content hash: a lookup key is already record-scoped,
so the same chunk under two records is two different ciphertexts and there was
never anything to share. Overwriting is safe because the encryption is
deterministic — the same (record, plaintext, context) always produces the same
envelope bytes.

## Streamable recordings

Nothing is stored as one opaque file. A recording — master, stem, FLAC
preservation copy, SoundKit Opus — is a SoundKit v2 stream cut into segments
on frame boundaries, each sealed and stored as its own `blob`. A manifest
lists them in order with their PTS and sample counts, which makes it the seek
index: playback pulls the segments covering the part being played and no more.
FLAC is not a special case; it is framed by the same container and cut by the
same rule.

Segments are cut at 2 MiB or 8 seconds, whichever comes first — the byte
ceiling is what a phone can decrypt in one piece, the duration ceiling is what
keeps a seek from pulling more audio than it needs.

Each segment is sealed with a key derived from its own plaintext hash, so the
same audio always produces the same ciphertext and therefore the same address:
uploads are idempotent and one take occupies one object. The manifest carries
those plaintext hashes and is itself stored as a blob, so a recording is
reached by two strings — the manifest's key, and the hash that opens it.
Holding them is holding the audio; the store holds bytes it cannot read.

The trade is the one convergent encryption always makes: someone already
holding a candidate file can confirm the store has it. Mixing a per-vault
secret into the key derivation removes that and costs the dedupe — the
envelope carries a version byte so that is a new version, not a migration.

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

## Validation

Run all Rust tests:

```sh
cargo test --workspace
```

Build the Worker:

```sh
npx wrangler deploy --dry-run
```
