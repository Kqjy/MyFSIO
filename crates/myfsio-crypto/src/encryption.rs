use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::RngCore;
use std::collections::HashMap;
use std::path::Path;

use crate::aes_gcm::{
    decrypt_stream_chunked, decrypt_stream_chunked_range, encrypt_stream_chunked, CryptoError,
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
    pub chunk_size: Option<usize>,
    pub plaintext_size: Option<u64>,
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
        if let Some(cs) = self.chunk_size {
            map.insert("x-amz-encryption-chunk-size".to_string(), cs.to_string());
        }
        if let Some(ps) = self.plaintext_size {
            map.insert(
                "x-amz-encryption-plaintext-size".to_string(),
                ps.to_string(),
            );
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
            chunk_size: meta
                .get("x-amz-encryption-chunk-size")
                .and_then(|s| s.parse().ok()),
            plaintext_size: meta
                .get("x-amz-encryption-plaintext-size")
                .and_then(|s| s.parse().ok()),
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
        meta.remove("x-amz-encryption-chunk-size");
        meta.remove("x-amz-encryption-plaintext-size");
    }
}

pub struct EncryptionService {
    master_key: [u8; 32],
    kms: Option<std::sync::Arc<KmsService>>,
    config: EncryptionConfig,
}

#[derive(Debug, Clone, Copy)]
pub struct EncryptionConfig {
    pub chunk_size: usize,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self { chunk_size: 65_536 }
    }
}

impl EncryptionService {
    pub fn new(master_key: [u8; 32], kms: Option<std::sync::Arc<KmsService>>) -> Self {
        Self::with_config(master_key, kms, EncryptionConfig::default())
    }

    pub fn with_config(
        master_key: [u8; 32],
        kms: Option<std::sync::Arc<KmsService>>,
        config: EncryptionConfig,
    ) -> Self {
        Self {
            master_key,
            kms,
            config,
        }
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
            SseAlgorithm::CustomerProvided => (None, None),
        };

        let actual_key = if ctx.algorithm == SseAlgorithm::CustomerProvided {
            let ck = ctx
                .customer_key
                .as_ref()
                .ok_or_else(|| CryptoError::EncryptionFailed("No customer key provided".into()))?;
            if ck.len() != 32 {
                return Err(CryptoError::InvalidKeySize(ck.len()));
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(ck);
            k
        } else {
            data_key
        };

        let plaintext_size = tokio::fs::metadata(input_path)
            .await
            .map_err(CryptoError::Io)?
            .len();

        let ip = input_path.to_owned();
        let op = output_path.to_owned();
        let ak = actual_key;
        let n = nonce;
        let chunk_size = self.config.chunk_size;
        tokio::task::spawn_blocking(move || {
            encrypt_stream_chunked(&ip, &op, &ak, &n, Some(chunk_size))
        })
        .await
        .map_err(|e| CryptoError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))??;

        Ok(EncryptionMetadata {
            algorithm: ctx.algorithm.as_str().to_string(),
            nonce: B64.encode(nonce),
            encrypted_data_key,
            kms_key_id,
            chunk_size: Some(chunk_size),
            plaintext_size: Some(plaintext_size),
        })
    }

    async fn resolve_data_key(
        &self,
        enc_meta: &EncryptionMetadata,
        customer_key: Option<&[u8]>,
    ) -> Result<([u8; 32], [u8; 12]), CryptoError> {
        let nonce_bytes = B64
            .decode(&enc_meta.nonce)
            .map_err(|e| CryptoError::EncryptionFailed(format!("Bad nonce encoding: {}", e)))?;
        if nonce_bytes.len() != 12 {
            return Err(CryptoError::InvalidNonceSize(nonce_bytes.len()));
        }
        let nonce: [u8; 12] = nonce_bytes.try_into().unwrap();

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

        Ok((data_key, nonce))
    }

    pub async fn decrypt_object(
        &self,
        input_path: &Path,
        output_path: &Path,
        enc_meta: &EncryptionMetadata,
        customer_key: Option<&[u8]>,
    ) -> Result<(), CryptoError> {
        let (data_key, nonce) = self.resolve_data_key(enc_meta, customer_key).await?;

        let ip = input_path.to_owned();
        let op = output_path.to_owned();
        tokio::task::spawn_blocking(move || decrypt_stream_chunked(&ip, &op, &data_key, &nonce))
            .await
            .map_err(|e| CryptoError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))??;

        Ok(())
    }

    pub async fn decrypt_object_range(
        &self,
        input_path: &Path,
        output_path: &Path,
        enc_meta: &EncryptionMetadata,
        customer_key: Option<&[u8]>,
        plain_start: u64,
        plain_end_inclusive: u64,
    ) -> Result<u64, CryptoError> {
        let chunk_size = enc_meta.chunk_size.ok_or_else(|| {
            CryptoError::EncryptionFailed("chunk_size missing from encryption metadata".into())
        })?;
        let plaintext_size = enc_meta.plaintext_size.ok_or_else(|| {
            CryptoError::EncryptionFailed("plaintext_size missing from encryption metadata".into())
        })?;

        let (data_key, nonce) = self.resolve_data_key(enc_meta, customer_key).await?;

        let ip = input_path.to_owned();
        let op = output_path.to_owned();
        tokio::task::spawn_blocking(move || {
            decrypt_stream_chunked_range(
                &ip,
                &op,
                &data_key,
                &nonce,
                chunk_size,
                plaintext_size,
                plain_start,
                plain_end_inclusive,
            )
        })
        .await
        .map_err(|e| CryptoError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?
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
        std::fs::File::create(&input)
            .unwrap()
            .write_all(data)
            .unwrap();

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
        std::fs::File::create(&input)
            .unwrap()
            .write_all(data)
            .unwrap();

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
            chunk_size: Some(65_536),
            plaintext_size: Some(1_234_567),
        };
        let map = meta.to_metadata_map();
        let restored = EncryptionMetadata::from_metadata(&map).unwrap();
        assert_eq!(restored.algorithm, "AES256");
        assert_eq!(restored.nonce, meta.nonce);
        assert_eq!(restored.encrypted_data_key, meta.encrypted_data_key);
        assert_eq!(restored.chunk_size, Some(65_536));
        assert_eq!(restored.plaintext_size, Some(1_234_567));
    }

    #[test]
    fn test_encryption_metadata_legacy_missing_sizes() {
        let mut map = HashMap::new();
        map.insert("x-amz-server-side-encryption".to_string(), "AES256".into());
        map.insert("x-amz-encryption-nonce".to_string(), "aGVsbG8=".into());
        let restored = EncryptionMetadata::from_metadata(&map).unwrap();
        assert_eq!(restored.chunk_size, None);
        assert_eq!(restored.plaintext_size, None);
    }

    #[test]
    fn test_is_encrypted() {
        let mut meta = HashMap::new();
        assert!(!EncryptionMetadata::is_encrypted(&meta));
        meta.insert(
            "x-amz-server-side-encryption".to_string(),
            "AES256".to_string(),
        );
        assert!(EncryptionMetadata::is_encrypted(&meta));
    }
}
