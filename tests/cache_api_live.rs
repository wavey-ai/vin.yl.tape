use std::env;
use std::io::Read;

const DEFAULT_API_BASE: &str = "https://yl.vin/api/play/tape";
const DEFAULT_STORE_NAME: &str = "opus-chunks";
const DEFAULT_CACHE_KEY: &str = "0123456789abcdef";
const CACHE_BATCH_FORMAT: &str = "bitneedle-player-cache-batch-v1";
const CACHE_CONTENT_TYPE: &str = "application/vnd.bitneedle.player-cache+binary";
const CACHE_STREAM_CONTENT_TYPE: &str = "application/vnd.bitneedle.player-cache-stream+binary";

struct HttpResponse {
    status: u16,
    content_type: String,
    body: Vec<u8>,
}

#[test]
#[ignore = "requires deployed Cloudflare cache endpoint and a seeded cache key"]
fn direct_get_returns_same_payload_as_batch_stream() {
    let api_base = env_string("BITNEEDLE_CACHE_API_BASE", DEFAULT_API_BASE);
    let store_name = env_string("BITNEEDLE_CACHE_STORE", DEFAULT_STORE_NAME);
    let cache_key = env_string("BITNEEDLE_CACHE_KEY", DEFAULT_CACHE_KEY);

    assert!(
        is_cache_api_key(&cache_key),
        "BITNEEDLE_CACHE_KEY must be a 16-character hex u64 cache key"
    );

    let batch_stream = read_batch_stream_payload(&api_base, &store_name, &cache_key);
    assert_soundkit_v2_packet_stream(&batch_stream);

    let direct_url = format!(
        "{}/{}/{}",
        api_base.trim_end_matches('/'),
        store_name,
        cache_key
    );
    let head = http_call(ureq::head(&direct_url).set("Accept", CACHE_CONTENT_TYPE));
    assert_eq!(
        head.status, 200,
        "direct HEAD should find the cached object"
    );
    assert_eq!(
        content_type_base(&head.content_type),
        CACHE_CONTENT_TYPE,
        "direct HEAD content type"
    );

    let get = http_call(ureq::get(&direct_url).set("Accept", CACHE_CONTENT_TYPE));
    assert_eq!(
        get.status, 200,
        "direct GET should return the cached object"
    );
    assert_eq!(
        content_type_base(&get.content_type),
        CACHE_CONTENT_TYPE,
        "direct GET content type"
    );
    assert_eq!(
        get.body, batch_stream,
        "direct GET payload should match the batch stream payload"
    );
}

fn read_batch_stream_payload(api_base: &str, store_name: &str, cache_key: &str) -> Vec<u8> {
    let batch_url = format!("{}/batch", api_base.trim_end_matches('/'));
    let body = serde_json::json!({
        "format": CACHE_BATCH_FORMAT,
        "requests": [{
            "storeName": store_name,
            "keys": [cache_key],
        }],
    })
    .to_string();
    let response = http_send_string(
        ureq::post(&batch_url)
            .set("Accept", CACHE_STREAM_CONTENT_TYPE)
            .set("Content-Type", "application/json"),
        &body,
    );
    assert_eq!(response.status, 200, "batch stream status");
    assert_eq!(
        content_type_base(&response.content_type),
        CACHE_STREAM_CONTENT_TYPE,
        "batch stream content type"
    );
    stream_payload_for_key(&response.body, cache_key)
}

fn stream_payload_for_key(stream: &[u8], cache_key: &str) -> Vec<u8> {
    let mut offset = 0usize;
    while offset + 6 <= stream.len() {
        let payload_len = u32::from_be_bytes(
            stream[offset..offset + 4]
                .try_into()
                .expect("stream frame length bytes"),
        ) as usize;
        let key_len = u16::from_be_bytes(
            stream[offset + 4..offset + 6]
                .try_into()
                .expect("stream frame key length bytes"),
        ) as usize;
        let key_start = offset + 6;
        let payload_start = key_start
            .checked_add(key_len)
            .expect("stream key length overflow");
        let payload_end = payload_start
            .checked_add(payload_len)
            .expect("stream payload length overflow");
        assert!(
            payload_end <= stream.len(),
            "cache stream payload frame is truncated"
        );
        let frame_key = std::str::from_utf8(&stream[key_start..payload_start])
            .expect("stream frame key should be UTF-8");
        if frame_key == cache_key {
            return stream[payload_start..payload_end].to_vec();
        }
        offset = payload_end;
    }
    panic!("cache stream did not include key {cache_key}");
}

fn assert_soundkit_v2_packet_stream(body: &[u8]) {
    assert!(!body.is_empty(), "cached body should be raw packet bytes");
    let mut offset = 0usize;
    let mut packets = 0usize;
    while offset < body.len() {
        assert!(offset + 8 <= body.len(), "SoundKit v2 packet is truncated");
        let header =
            u32::from_be_bytes(body[offset..offset + 4].try_into().expect("packet header"));
        assert_eq!(
            header >> 26,
            0x2b,
            "cached Opus packet should use SoundKit v2"
        );
        assert_eq!((header >> 24) & 0x3, 2, "SoundKit packet version");
        assert_eq!(
            (header >> 12) & 0xf,
            2,
            "SoundKit packet encoding should be Opus"
        );
        let flags = ((header >> 16) & 0xff) as u8;
        let size_word =
            u32::from_be_bytes(body[offset + 4..offset + 8].try_into().expect("size word"));
        let mut header_size = 8usize;
        let payload_size = if flags & 0x20 != 0 {
            assert_eq!(size_word, 0xffff_ffff, "extended size sentinel");
            assert!(
                offset + 16 <= body.len(),
                "extended size packet is truncated"
            );
            header_size = 16;
            u32::from_be_bytes(
                body[offset + 8..offset + 12]
                    .try_into()
                    .expect("payload size"),
            ) as usize
        } else {
            (size_word >> 16) as usize
        };
        if flags & 0x01 != 0 {
            header_size += if flags & 0x02 != 0 { 8 } else { 4 };
        }
        if flags & 0x04 != 0 {
            header_size += 8;
        }
        if flags & 0x08 != 0 {
            header_size += 4;
        }
        let packet_end = offset + header_size + payload_size;
        assert!(
            packet_end <= body.len(),
            "SoundKit v2 packet payload is truncated"
        );
        offset = packet_end;
        packets += 1;
    }
    assert!(
        packets > 0,
        "cached body should include at least one packet"
    );
}

fn http_call(request: ureq::Request) -> HttpResponse {
    response_from_result(request.call())
}

fn http_send_string(request: ureq::Request, body: &str) -> HttpResponse {
    response_from_result(request.send_string(body))
}

fn response_from_result(result: Result<ureq::Response, ureq::Error>) -> HttpResponse {
    let response = match result {
        Ok(response) => response,
        Err(ureq::Error::Status(_, response)) => response,
        Err(error) => panic!("HTTP request failed: {error}"),
    };
    let status = response.status();
    let content_type = response.header("Content-Type").unwrap_or("").to_string();
    let mut body = Vec::new();
    response
        .into_reader()
        .read_to_end(&mut body)
        .expect("read HTTP response body");
    HttpResponse {
        status,
        content_type,
        body,
    }
}

fn env_string(name: &str, fallback: &str) -> String {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

fn content_type_base(content_type: &str) -> &str {
    content_type.split(';').next().unwrap_or("").trim()
}

fn is_cache_api_key(value: &str) -> bool {
    value.len() == 16 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
