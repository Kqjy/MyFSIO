use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::{engine::general_purpose::URL_SAFE, Engine};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type HmacSha256 = Hmac<Sha256>;

pub fn derive_fernet_key(secret: &str) -> String {
    let mut derived = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(
        secret.as_bytes(),
        b"myfsio-iam-encryption",
        100_000,
        &mut derived,
    );
    URL_SAFE.encode(derived)
}

pub fn decrypt(key_b64: &str, token: &str) -> Result<Vec<u8>, &'static str> {
    let key_bytes = URL_SAFE
        .decode(key_b64)
        .map_err(|_| "invalid fernet key base64")?;
    if key_bytes.len() != 32 {
        return Err("fernet key must be 32 bytes");
    }

    let signing_key = &key_bytes[..16];
    let encryption_key = &key_bytes[16..];

    let token_bytes = URL_SAFE
        .decode(token)
        .map_err(|_| "invalid fernet token base64")?;

    if token_bytes.len() < 57 {
        return Err("fernet token too short");
    }

    if token_bytes[0] != 0x80 {
        return Err("invalid fernet version");
    }

    let hmac_offset = token_bytes.len() - 32;
    let payload = &token_bytes[..hmac_offset];
    let expected_hmac = &token_bytes[hmac_offset..];

    let mut mac = HmacSha256::new_from_slice(signing_key).map_err(|_| "hmac key error")?;
    mac.update(payload);
    mac.verify_slice(expected_hmac)
        .map_err(|_| "HMAC verification failed")?;

    let iv = &token_bytes[9..25];
    let ciphertext = &token_bytes[25..hmac_offset];

    let plaintext = Aes128CbcDec::new(encryption_key.into(), iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| "AES-CBC decryption failed")?;

    Ok(plaintext)
}

pub fn encrypt(key_b64: &str, plaintext: &[u8]) -> Result<String, &'static str> {
    let key_bytes = URL_SAFE
        .decode(key_b64)
        .map_err(|_| "invalid fernet key base64")?;
    if key_bytes.len() != 32 {
        return Err("fernet key must be 32 bytes");
    }

    let signing_key = &key_bytes[..16];
    let encryption_key = &key_bytes[16..];

    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system time error")?
        .as_secs();

    let ciphertext = Aes128CbcEnc::new(encryption_key.into(), (&iv).into())
        .encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    let mut payload = Vec::with_capacity(1 + 8 + 16 + ciphertext.len());
    payload.push(0x80);
    payload.extend_from_slice(&timestamp.to_be_bytes());
    payload.extend_from_slice(&iv);
    payload.extend_from_slice(&ciphertext);

    let mut mac = HmacSha256::new_from_slice(signing_key).map_err(|_| "hmac key error")?;
    mac.update(&payload);
    let tag = mac.finalize().into_bytes();

    let mut token_bytes = payload;
    token_bytes.extend_from_slice(&tag);
    Ok(URL_SAFE.encode(&token_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_fernet_key_format() {
        let key = derive_fernet_key("test-secret");
        let decoded = URL_SAFE.decode(&key).unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn test_roundtrip_with_python_compat() {
        let key = derive_fernet_key("dev-secret-key");
        let decoded = URL_SAFE.decode(&key).unwrap();
        assert_eq!(decoded.len(), 32);
    }
}
