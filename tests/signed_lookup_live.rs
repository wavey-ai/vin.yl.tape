//! What a full signed lookup costs the Worker, asked of a deployed one.
//!
//! The Worker runs under a 10 ms CPU budget (`limits.cpu_ms` in
//! wrangler.toml) and the signed lookup is the only thing in it that spends
//! real CPU: a 256-key batch is 256 SigV4 signatures and no I/O at all. There
//! is no way to read the CPU meter from inside — `Date.now()` does not
//! advance during computation in Workers — so the budget is tested the way it
//! actually fails: a Worker that runs over is killed, and the request comes
//! back as an error instead of a batch. A clean 200 carrying a signed URL for
//! every one of the 256 keys *is* the assertion that the signing fits.
//!
//! Ignored by default. Point it at a deployment and run it:
//!
//! ```sh
//! BITNEEDLE_CACHE_API_BASE=https://yl.vin/tape \
//!   cargo test --test signed_lookup_live -- --ignored --nocapture
//! ```

use std::env;
use std::io::Read;
use std::time::Instant;

const DEFAULT_API_BASE: &str = "https://yl.vin/tape";
const LOOKUP_FORMAT_V3: &str = "vin-yl-tape-lookup-v3";
const BATCH_JSON_FORMAT_V3: &str = "vin-yl-tape-batch-v3";
/// The read ceiling the Worker enforces, which is also the worst case for the
/// CPU budget: nothing asks it to sign more than this in one request.
const MAX_READ_BATCH_ENTRIES: usize = 256;
/// Generous, because it is measuring a network round trip and not the signing.
/// The point is to catch a lookup that has gone back to touching storage.
const LOOKUP_BUDGET_MS: u128 = 3_000;

#[test]
#[ignore = "requires a deployed Cloudflare tape endpoint"]
fn a_full_signed_lookup_fits_inside_the_worker_cpu_budget() {
    let api_base = env::var("BITNEEDLE_CACHE_API_BASE")
        .unwrap_or_else(|_| DEFAULT_API_BASE.to_owned());
    let url = format!("{}/batch", api_base.trim_end_matches('/'));

    // Keys nothing has ever been written under: the signing work is identical
    // either way, since the Worker does not look.
    let keys = (0..MAX_READ_BATCH_ENTRIES)
        .map(|index| format!("ecdc-opus/{:064x}", index + 1))
        .collect::<Vec<_>>();

    let started = Instant::now();
    let response = ureq::post(&url)
        .set("Accept", "application/json")
        .send_json(ureq::json!({ "format": LOOKUP_FORMAT_V3, "keys": keys }));
    let elapsed = started.elapsed().as_millis();

    let response = match response {
        Ok(response) => response,
        Err(ureq::Error::Status(status, response)) => {
            let mut body = String::new();
            let _ = response.into_reader().read_to_string(&mut body);
            panic!(
                "a {MAX_READ_BATCH_ENTRIES}-key signed lookup failed with status {status} \
                 after {elapsed} ms — a Worker killed for exceeding its CPU budget \
                 arrives exactly like this. Body: {body}"
            );
        }
        Err(error) => panic!("the signed lookup could not be sent: {error}"),
    };

    assert_eq!(response.status(), 200, "the signed lookup was not answered");
    let payload: serde_json::Value = response
        .into_json()
        .expect("the signed lookup response is not JSON");
    assert_eq!(
        payload["format"].as_str(),
        Some(BATCH_JSON_FORMAT_V3),
        "the endpoint answered in another protocol — it may predate signed lookups"
    );

    let results = payload["results"]
        .as_array()
        .expect("the signed lookup returned no results array");
    assert_eq!(
        results.len(),
        MAX_READ_BATCH_ENTRIES,
        "the Worker answered {} of {MAX_READ_BATCH_ENTRIES} keys — a truncated batch is \
         how a CPU overrun would show up if it were caught rather than killed",
        results.len()
    );
    let signed = results
        .iter()
        .filter(|result| result["url"].as_str().is_some_and(|url| !url.is_empty()))
        .count();
    assert_eq!(
        signed, MAX_READ_BATCH_ENTRIES,
        "only {signed} of {MAX_READ_BATCH_ENTRIES} keys came back signed"
    );

    assert!(
        elapsed <= LOOKUP_BUDGET_MS,
        "a signed lookup took {elapsed} ms; it does no I/O and should cost one round trip"
    );

    println!("signed {MAX_READ_BATCH_ENTRIES} keys in {elapsed} ms");
}

/// A signed URL has to be honoured by R2 itself — and a key with nothing
/// behind it has to answer 404, because that 404 is what the client reads as
/// a cache miss. A 403 here means the signature is wrong and every lookup is
/// silently a miss.
#[test]
#[ignore = "requires a deployed Cloudflare tape endpoint"]
fn a_signed_url_for_an_empty_key_answers_not_found() {
    let api_base = env::var("BITNEEDLE_CACHE_API_BASE")
        .unwrap_or_else(|_| DEFAULT_API_BASE.to_owned());
    let url = format!("{}/batch", api_base.trim_end_matches('/'));
    let key = "ecdc-opus/00000000000000000000000000000000000000000000000000000000000000ff";

    let payload: serde_json::Value = ureq::post(&url)
        .set("Accept", "application/json")
        .send_json(ureq::json!({ "format": LOOKUP_FORMAT_V3, "keys": [key] }))
        .expect("the signed lookup failed")
        .into_json()
        .expect("the signed lookup response is not JSON");

    let signed_url = payload["results"][0]["url"]
        .as_str()
        .expect("the key came back unsigned")
        .to_owned();

    match ureq::get(&signed_url).call() {
        Ok(response) => panic!(
            "an empty key answered {} — something is stored under it",
            response.status()
        ),
        Err(ureq::Error::Status(404, _)) => {}
        Err(ureq::Error::Status(403, response)) => {
            let mut body = String::new();
            let _ = response.into_reader().read_to_string(&mut body);
            panic!("R2 rejected the signature, so every lookup is a miss: {body}");
        }
        Err(ureq::Error::Status(status, _)) => {
            panic!("the signed URL answered {status}, not 404")
        }
        Err(error) => panic!("the signed URL could not be fetched: {error}"),
    }
}
