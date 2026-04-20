use hmac::{Hmac, Mac};
use lru::LruCache;
use parking_lot::Mutex;
use percent_encoding::{percent_encode, AsciiSet, NON_ALPHANUMERIC};
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

const AWS_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key length is always valid");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn aws_uri_encode(input: &str) -> String {
    percent_encode(input.as_bytes(), AWS_ENCODE_SET).to_string()
}

pub fn derive_signing_key_cached(
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

    let k_date = hmac_sha256(
        format!("AWS4{}", secret_key).as_bytes(),
        date_stamp.as_bytes(),
    );
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

fn constant_time_compare_inner(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

pub fn verify_sigv4_signature(
    method: &str,
    canonical_uri: &str,
    query_params: &[(String, String)],
    signed_headers_str: &str,
    header_values: &[(String, String)],
    payload_hash: &str,
    amz_date: &str,
    date_stamp: &str,
    region: &str,
    service: &str,
    secret_key: &str,
    provided_signature: &str,
) -> bool {
    let mut sorted_params = query_params.to_vec();
    sorted_params.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    let canonical_query_string = sorted_params
        .iter()
        .map(|(k, v)| format!("{}={}", aws_uri_encode(k), aws_uri_encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    let mut canonical_headers = String::new();
    for (name, value) in header_values {
        let lower_name = name.to_lowercase();
        let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
        let final_value = if lower_name == "expect" && normalized.is_empty() {
            "100-continue"
        } else {
            &normalized
        };
        canonical_headers.push_str(&lower_name);
        canonical_headers.push(':');
        canonical_headers.push_str(final_value);
        canonical_headers.push('\n');
    }

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method,
        canonical_uri,
        canonical_query_string,
        canonical_headers,
        signed_headers_str,
        payload_hash
    );

    let credential_scope = format!("{}/{}/{}/aws4_request", date_stamp, region, service);
    let cr_hash = sha256_hex(canonical_request.as_bytes());
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date, credential_scope, cr_hash
    );

    let signing_key = derive_signing_key_cached(secret_key, date_stamp, region, service);
    let calculated = hmac_sha256(&signing_key, string_to_sign.as_bytes());
    let calculated_hex = hex::encode(&calculated);

    constant_time_compare_inner(calculated_hex.as_bytes(), provided_signature.as_bytes())
}

pub fn derive_signing_key(
    secret_key: &str,
    date_stamp: &str,
    region: &str,
    service: &str,
) -> Vec<u8> {
    derive_signing_key_cached(secret_key, date_stamp, region, service)
}

pub fn compute_signature(signing_key: &[u8], string_to_sign: &str) -> String {
    let sig = hmac_sha256(signing_key, string_to_sign.as_bytes());
    hex::encode(sig)
}

pub fn compute_post_policy_signature(signing_key: &[u8], policy_b64: &str) -> String {
    let sig = hmac_sha256(signing_key, policy_b64.as_bytes());
    hex::encode(sig)
}

pub fn build_string_to_sign(
    amz_date: &str,
    credential_scope: &str,
    canonical_request: &str,
) -> String {
    let cr_hash = sha256_hex(canonical_request.as_bytes());
    format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date, credential_scope, cr_hash
    )
}

pub fn constant_time_compare(a: &str, b: &str) -> bool {
    constant_time_compare_inner(a.as_bytes(), b.as_bytes())
}

pub fn clear_signing_key_cache() {
    SIGNING_KEY_CACHE.lock().clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_signing_key() {
        let key = derive_signing_key(
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "20130524",
            "us-east-1",
            "s3",
        );
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_signing_key_cached() {
        let key1 = derive_signing_key("secret", "20240101", "us-east-1", "s3");
        let key2 = derive_signing_key("secret", "20240101", "us-east-1", "s3");
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare("abc", "abc"));
        assert!(!constant_time_compare("abc", "abd"));
        assert!(!constant_time_compare("abc", "abcd"));
    }

    #[test]
    fn test_build_string_to_sign() {
        let result = build_string_to_sign(
            "20130524T000000Z",
            "20130524/us-east-1/s3/aws4_request",
            "GET\n/\n\nhost:example.com\n\nhost\nUNSIGNED-PAYLOAD",
        );
        assert!(result.starts_with("AWS4-HMAC-SHA256\n"));
        assert!(result.contains("20130524T000000Z"));
    }

    #[test]
    fn test_aws_uri_encode() {
        assert_eq!(aws_uri_encode("hello world"), "hello%20world");
        assert_eq!(aws_uri_encode("test-file_name.txt"), "test-file_name.txt");
        assert_eq!(aws_uri_encode("a/b"), "a%2Fb");
    }

    #[test]
    fn test_verify_sigv4_roundtrip() {
        let secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let date_stamp = "20130524";
        let region = "us-east-1";
        let service = "s3";
        let amz_date = "20130524T000000Z";

        let signing_key = derive_signing_key(secret, date_stamp, region, service);

        let canonical_request =
            "GET\n/\n\nhost:examplebucket.s3.amazonaws.com\n\nhost\nUNSIGNED-PAYLOAD";
        let string_to_sign = build_string_to_sign(
            amz_date,
            &format!("{}/{}/{}/aws4_request", date_stamp, region, service),
            canonical_request,
        );

        let signature = compute_signature(&signing_key, &string_to_sign);

        let result = verify_sigv4_signature(
            "GET",
            "/",
            &[],
            "host",
            &[(
                "host".to_string(),
                "examplebucket.s3.amazonaws.com".to_string(),
            )],
            "UNSIGNED-PAYLOAD",
            amz_date,
            date_stamp,
            region,
            service,
            secret,
            &signature,
        );
        assert!(result);
    }
}
