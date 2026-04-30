use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub fn cluster_attest(psk: &str, amz_date: &str, origin_site_id: &str, idempotency_key: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(psk.as_bytes()).expect("HMAC accepts any key length");
    mac.update(amz_date.as_bytes());
    mac.update(b"|");
    mac.update(origin_site_id.as_bytes());
    mac.update(b"|");
    mac.update(idempotency_key.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[allow(clippy::too_many_arguments)]
pub fn admin_attest(
    psk: &str,
    amz_date: &str,
    admin_user_id: &str,
    method: &str,
    canonical_path: &str,
    body_sha256_hex: &str,
    idempotency_key: &str,
) -> String {
    let mut mac = HmacSha256::new_from_slice(psk.as_bytes()).expect("HMAC accepts any key length");
    mac.update(amz_date.as_bytes());
    mac.update(b"|");
    mac.update(admin_user_id.as_bytes());
    mac.update(b"|");
    mac.update(method.as_bytes());
    mac.update(b"|");
    mac.update(canonical_path.as_bytes());
    mac.update(b"|");
    mac.update(body_sha256_hex.as_bytes());
    mac.update(b"|");
    mac.update(idempotency_key.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn verify_cluster_attest(
    psk: &str,
    amz_date: &str,
    origin_site_id: &str,
    idempotency_key: &str,
    provided: &str,
) -> bool {
    let expected = cluster_attest(psk, amz_date, origin_site_id, idempotency_key);
    constant_time_eq(expected.as_bytes(), provided.as_bytes())
}

#[allow(clippy::too_many_arguments)]
pub fn verify_admin_attest(
    psk: &str,
    amz_date: &str,
    admin_user_id: &str,
    method: &str,
    canonical_path: &str,
    body_sha256_hex: &str,
    idempotency_key: &str,
    provided: &str,
) -> bool {
    let expected = admin_attest(
        psk,
        amz_date,
        admin_user_id,
        method,
        canonical_path,
        body_sha256_hex,
        idempotency_key,
    );
    constant_time_eq(expected.as_bytes(), provided.as_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_attest_changes_when_method_changes() {
        let a = admin_attest("psk", "20260101T000000Z", "u-1", "GET", "/admin/peer/iam", "abc", "k1");
        let b = admin_attest("psk", "20260101T000000Z", "u-1", "POST", "/admin/peer/iam", "abc", "k1");
        assert_ne!(a, b);
    }

    #[test]
    fn admin_attest_changes_when_path_changes() {
        let a = admin_attest("psk", "20260101T000000Z", "u-1", "GET", "/admin/peer/iam", "abc", "k1");
        let b = admin_attest("psk", "20260101T000000Z", "u-1", "GET", "/admin/peer/sites", "abc", "k1");
        assert_ne!(a, b);
    }

    #[test]
    fn admin_attest_changes_when_body_changes() {
        let a = admin_attest("psk", "20260101T000000Z", "u-1", "POST", "/p", "aaa", "k1");
        let b = admin_attest("psk", "20260101T000000Z", "u-1", "POST", "/p", "bbb", "k1");
        assert_ne!(a, b);
    }

    #[test]
    fn admin_attest_changes_when_idempotency_changes() {
        let a = admin_attest("psk", "20260101T000000Z", "u-1", "POST", "/p", "h", "k1");
        let b = admin_attest("psk", "20260101T000000Z", "u-1", "POST", "/p", "h", "k2");
        assert_ne!(a, b);
    }

    #[test]
    fn verify_admin_attest_round_trips() {
        let token = admin_attest("psk", "20260101T000000Z", "u-1", "GET", "/p", "h", "k1");
        assert!(verify_admin_attest(
            "psk",
            "20260101T000000Z",
            "u-1",
            "GET",
            "/p",
            "h",
            "k1",
            &token
        ));
        assert!(!verify_admin_attest(
            "psk",
            "20260101T000000Z",
            "u-1",
            "GET",
            "/p",
            "h",
            "k2",
            &token
        ));
    }
}
