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

pub fn admin_attest(psk: &str, amz_date: &str, admin_user_id: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(psk.as_bytes()).expect("HMAC accepts any key length");
    mac.update(amz_date.as_bytes());
    mac.update(b"|");
    mac.update(admin_user_id.as_bytes());
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

pub fn verify_admin_attest(
    psk: &str,
    amz_date: &str,
    admin_user_id: &str,
    provided: &str,
) -> bool {
    let expected = admin_attest(psk, amz_date, admin_user_id);
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
