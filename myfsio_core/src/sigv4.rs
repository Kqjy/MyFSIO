use hmac::{Hmac, Mac};
use lru::LruCache;
use parking_lot::Mutex;
use pyo3::prelude::*;
use sha2::{Digest, Sha256};
use std::num::NonZeroUsize;
use std::sync::LazyLock;
use std::time::Instant;

type HmacSha256 = Hmac<Sha256>;

struct CacheEntry {
    key: Vec<u8>,
    created: Instant,
}

static SIGNING_KEY_CACHE: LazyLock<Mutex<LruCache<(String, String, String, String), CacheEntry>>> =
    LazyLock::new(|| Mutex::new(LruCache::new(NonZeroUsize::new(256).unwrap())));

const CACHE_TTL_SECS: u64 = 60;

fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key length is always valid");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

#[pyfunction]
pub fn derive_signing_key(
    secret_key: &str,
    date_stamp: &str,
    region: &str,
    service: &str,
) -> Vec<u8> {
    let cache_key = (
        secret_key.to_owned(),
        date_stamp.to_owned(),
        region.to_owned(),
        service.to_owned(),
    );

    {
        let mut cache = SIGNING_KEY_CACHE.lock();
        if let Some(entry) = cache.get(&cache_key) {
            if entry.created.elapsed().as_secs() < CACHE_TTL_SECS {
                return entry.key.clone();
            }
            cache.pop(&cache_key);
        }
    }

    let k_date = hmac_sha256(format!("AWS4{}", secret_key).as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"aws4_request");

    {
        let mut cache = SIGNING_KEY_CACHE.lock();
        cache.put(
            cache_key,
            CacheEntry {
                key: k_signing.clone(),
                created: Instant::now(),
            },
        );
    }

    k_signing
}

#[pyfunction]
pub fn compute_signature(signing_key: &[u8], string_to_sign: &str) -> String {
    let sig = hmac_sha256(signing_key, string_to_sign.as_bytes());
    hex::encode(sig)
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[pyfunction]
pub fn build_string_to_sign(
    amz_date: &str,
    credential_scope: &str,
    canonical_request: &str,
) -> String {
    let cr_hash = sha256_hex(canonical_request.as_bytes());
    format!("AWS4-HMAC-SHA256\n{}\n{}\n{}", amz_date, credential_scope, cr_hash)
}

#[pyfunction]
pub fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result: u8 = 0;
    for (x, y) in a.bytes().zip(b.bytes()) {
        result |= x ^ y;
    }
    result == 0
}

#[pyfunction]
pub fn clear_signing_key_cache() {
    SIGNING_KEY_CACHE.lock().clear();
}
