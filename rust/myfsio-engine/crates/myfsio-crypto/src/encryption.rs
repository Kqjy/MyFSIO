use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::RngCore;
use std::collections::HashMap;
use std::path::Path;

use crate::aes_gcm::{
    encrypt_stream_chunked, decrypt_stream_chunked, CryptoError,
};
use crate::kms::KmsService;

#[derive(Debug, Clone, PartialEq)]
pub enum SseAlgorithm {
    Aes256,
    AwsKms,
    CustomerProvided,
}

impl SseAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            SseAlgorithm::Aes256 => "AES256",
            SseAlgorithm::AwsKms => "aws:kms",
            SseAlgorithm::CustomerProvided => "AES256",
        }
    }
}

#[derive(Debug, Clone)]
pub struct EncryptionContext {
    pub algorithm: SseAlgorithm,
    pub kms_key_id: Option<String>,
    pub customer_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct EncryptionMetadata {
    pub algorithm: String,
    pub nonce: String,
    pub encrypted_data_key: Option<String>,
    pub kms_key_id: Option<String>,
}

impl EncryptionMetadata {
    pub fn to_metadata_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert(
            "x-amz-server-side-encryption".to_string(),
            self.algorithm.clone(),
        );
        map.insert("x-amz-encryption-nonce".to_string(), self.nonce.clone());
        if let Some(ref dk) = self.encrypted_data_key {
            map.insert("x-amz-encrypted-data-key".to_string(), dk.clone());
        }
        if let Some(ref kid) = self.kms_key_id {
            map.insert("x-amz-encryption-key-id".to_string(), kid.clone());
        }
        map
    }

    pub fn from_metadata(meta: &HashMap<String, String>) -> Option<Self> {
        let algorithm = meta.get("x-amz-server-side-encryption")?;
        let nonce = meta.get("x-amz-encryption-nonce")?;
        Some(Self {
            algorithm: algorithm.clone(),
            nonce: nonce.clone(),
            encrypted_data_key: meta.get("x-amz-encrypted-data-key").cloned(),
            kms_key_id: meta.get("x-amz-encryption-key-id").cloned(),
        })
    }

    pub fn is_encrypted(meta: &HashMap<String, String>) -> bool {
        meta.contains_key("x-amz-server-side-encryption")
    }

    pub fn clean_metadata(meta: &mut HashMap<String, String>) {
        meta.remove("x-amz-server-side-encryption");
        meta.remove("x-amz-encryption-nonce");
        meta.remove("x-amz-encrypted-data-key");
        meta.remove("x-amz-encryption-key-id");
    }
}

pub struct EncryptionService {
    master_key: [u8; 32],
    kms: Option<std::sync::Arc<KmsService>>,
}

impl EncryptionService {
    pub fn new(master_key: [u8; 32], kms: Option<std::sync::Arc<KmsService>>) -> Self {
        Self { master_key, kms }
    }

    pub fn generate_data_key(&self) -> ([u8; 32], [u8; 12]) {
        let mut data_key = [0u8; 32];
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut data_key);
        rand::thread_rng().fill_bytes(&mut nonce);
        (data_key, nonce)
    }

    pub fn wrap_data_key(&self, data_key: &[u8; 32]) -> Result<String, CryptoError> {
        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

        let cipher = Aes256Gcm::new((&self.master_key).into());
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted = cipher
            .encrypt(nonce, data_key.as_slice())
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        let mut combined = Vec::with_capacity(12 + encrypted.len());
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&encrypted);
        Ok(B64.encode(&combined))
    }

    pub fn unwrap_data_key(&self, wrapped_b64: &str) -> Result<[u8; 32], CryptoError> {
        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

        let combined = B64.decode(wrapped_b64).map_err(|e| {
            CryptoError::EncryptionFailed(format!("Bad wrapped key encoding: {}", e))
        })?;
        if combined.len() < 12 {
            return Err(CryptoError::EncryptionFailed(
                "Wrapped key too short".to_string(),
            ));
        }

        let (nonce_bytes, ciphertext) = combined.split_at(12);
        let cipher = Aes256Gcm::new((&self.master_key).into());
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed(0))?;

        if plaintext.len() != 32 {
            return Err(CryptoError::InvalidKeySize(plaintext.len()));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&plaintext);
        Ok(key)
    }

    pub async fn encrypt_object(
        &self,
        input_path: &Path,
        output_path: &Path,
        ctx: &EncryptionContext,
    ) -> Result<EncryptionMetadata, CryptoError> {
        let (data_key, nonce) = self.generate_data_key();

        let (encrypted_data_key, kms_key_id) = match ctx.algorithm {
            SseAlgorithm::Aes256 => {
                let wrapped = self.wrap_data_key(&data_key)?;
                (Some(wrapped), None)
            }
            SseAlgorithm::AwsKms => {
                let kms = self
                    .kms
                    .as_ref()
                    .ok_or_else(|| CryptoError::EncryptionFailed("KMS not available".into()))?;
                let kid = ctx
                    .kms_key_id
                    .as_ref()
                    .ok_or_else(|| CryptoError::EncryptionFailed("No KMS key ID".into()))?;
                let ciphertext = kms.encrypt_data(kid, &data_key).await?;
                (Some(B64.encode(&ciphertext)), Some(kid.clone()))
            }
            SseAlgorithm::CustomerProvided => {
                (None, None)
            }
        };

        let actual_key = if ctx.algorithm == SseAlgorithm::CustomerProvided {
            let ck = ctx.customer_key.as_ref().ok_or_else(|| {
                CryptoError::EncryptionFailed("No customer key provided".into())
            })?;
            if ck.len() != 32 {
                return Err(CryptoError::InvalidKeySize(ck.len()));
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(ck);
            k
        } else {
            data_key
        };

        let ip = input_path.to_owned();
        let op = output_path.to_owned();
        let ak = actual_key;
        let n = nonce;
        tokio::task::spawn_blocking(move || {
            encrypt_stream_chunked(&ip, &op, &ak, &n, None)
        })
        .await
        .map_err(|e| CryptoError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))??;

        Ok(EncryptionMetadata {
            algorithm: ctx.algorithm.as_str().to_string(),
            nonce: B64.encode(nonce),
            encrypted_data_key,
            kms_key_id,
        })
    }

    pub async fn decrypt_object(
        &self,
        input_path: &Path,
        output_path: &Path,
        enc_meta: &EncryptionMetadata,
        customer_key: Option<&[u8]>,
    ) -> Result<(), CryptoError> {
        let nonce_bytes = B64.decode(&enc_meta.nonce).map_err(|e| {
            CryptoError::EncryptionFailed(format!("Bad nonce encoding: {}", e))
        })?;
        if nonce_bytes.len() != 12 {
            return Err(CryptoError::InvalidNonceSize(nonce_bytes.len()));
        }

        let data_key: [u8; 32] = if let Some(ck) = customer_key {
            if ck.len() != 32 {
                return Err(CryptoError::InvalidKeySize(ck.len()));
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(ck);
            k
        } else if enc_meta.algorithm == "aws:kms" {
            let kms = self
                .kms
                .as_ref()
                .ok_or_else(|| CryptoError::EncryptionFailed("KMS not available".into()))?;
            let kid = enc_meta
                .kms_key_id
                .as_ref()
                .ok_or_else(|| CryptoError::EncryptionFailed("No KMS key ID in metadata".into()))?;
            let encrypted_dk = enc_meta.encrypted_data_key.as_ref().ok_or_else(|| {
                CryptoError::EncryptionFailed("No encrypted data key in metadata".into())
            })?;
            let ct = B64.decode(encrypted_dk).map_err(|e| {
                CryptoError::EncryptionFailed(format!("Bad data key encoding: {}", e))
            })?;
            let dk = kms.decrypt_data(kid, &ct).await?;
            if dk.len() != 32 {
                return Err(CryptoError::InvalidKeySize(dk.len()));
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(&dk);
            k
        } else {
            let wrapped = enc_meta.encrypted_data_key.as_ref().ok_or_else(|| {
                CryptoError::EncryptionFailed("No encrypted data key in metadata".into())
            })?;
            self.unwrap_data_key(wrapped)?
        };

        let ip = input_path.to_owned();
        let op = output_path.to_owned();
        let nb: [u8; 12] = nonce_bytes.try_into().unwrap();
        tokio::task::spawn_blocking(move || {
            decrypt_stream_chunked(&ip, &op, &data_key, &nb)
        })
        .await
        .map_err(|e| CryptoError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))??;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn test_master_key() -> [u8; 32] {
        [0x42u8; 32]
    }

    #[test]
    fn test_wrap_unwrap_data_key() {
        let svc = EncryptionService::new(test_master_key(), None);
        let dk = [0xAAu8; 32];
        let wrapped = svc.wrap_data_key(&dk).unwrap();
        let unwrapped = svc.unwrap_data_key(&wrapped).unwrap();
        assert_eq!(dk, unwrapped);
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_object_sse_s3() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("plain.bin");
        let encrypted = dir.path().join("enc.bin");
        let decrypted = dir.path().join("dec.bin");

        let data = b"SSE-S3 encrypted content for testing!";
        std::fs::File::create(&input).unwrap().write_all(data).unwrap();

        let svc = EncryptionService::new(test_master_key(), None);

        let ctx = EncryptionContext {
            algorithm: SseAlgorithm::Aes256,
            kms_key_id: None,
            customer_key: None,
        };

        let meta = svc.encrypt_object(&input, &encrypted, &ctx).await.unwrap();
        assert_eq!(meta.algorithm, "AES256");
        assert!(meta.encrypted_data_key.is_some());

        svc.decrypt_object(&encrypted, &decrypted, &meta, None)
            .await
            .unwrap();

        let result = std::fs::read(&decrypted).unwrap();
        assert_eq!(result, data);
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_object_sse_c() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("plain.bin");
        let encrypted = dir.path().join("enc.bin");
        let decrypted = dir.path().join("dec.bin");

        let data = b"SSE-C encrypted content!";
        std::fs::File::create(&input).unwrap().write_all(data).unwrap();

        let customer_key = [0xBBu8; 32];
        let svc = EncryptionService::new(test_master_key(), None);

        let ctx = EncryptionContext {
            algorithm: SseAlgorithm::CustomerProvided,
            kms_key_id: None,
            customer_key: Some(customer_key.to_vec()),
        };

        let meta = svc.encrypt_object(&input, &encrypted, &ctx).await.unwrap();
        assert!(meta.encrypted_data_key.is_none());

        svc.decrypt_object(&encrypted, &decrypted, &meta, Some(&customer_key))
            .await
            .unwrap();

        let result = std::fs::read(&decrypted).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_encryption_metadata_roundtrip() {
        let meta = EncryptionMetadata {
            algorithm: "AES256".to_string(),
            nonce: "dGVzdG5vbmNlMTI=".to_string(),
            encrypted_data_key: Some("c29tZWtleQ==".to_string()),
            kms_key_id: None,
        };
        let map = meta.to_metadata_map();
        let restored = EncryptionMetadata::from_metadata(&map).unwrap();
        assert_eq!(restored.algorithm, "AES256");
        assert_eq!(restored.nonce, meta.nonce);
        assert_eq!(restored.encrypted_data_key, meta.encrypted_data_key);
    }

    #[test]
    fn test_is_encrypted() {
        let mut meta = HashMap::new();
        assert!(!EncryptionMetadata::is_encrypted(&meta));
        meta.insert("x-amz-server-side-encryption".to_string(), "AES256".to_string());
        assert!(EncryptionMetadata::is_encrypted(&meta));
    }
}
