use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::aes_gcm::CryptoError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmsKey {
    #[serde(rename = "KeyId")]
    pub key_id: String,
    #[serde(rename = "Arn")]
    pub arn: String,
    #[serde(rename = "Description")]
    pub description: String,
    #[serde(rename = "CreationDate")]
    pub creation_date: DateTime<Utc>,
    #[serde(rename = "Enabled")]
    pub enabled: bool,
    #[serde(rename = "KeyState")]
    pub key_state: String,
    #[serde(rename = "KeyUsage")]
    pub key_usage: String,
    #[serde(rename = "KeySpec")]
    pub key_spec: String,
    #[serde(rename = "EncryptedKeyMaterial")]
    pub encrypted_key_material: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KmsStore {
    keys: Vec<KmsKey>,
}

pub struct KmsService {
    keys_path: PathBuf,
    master_key: Arc<RwLock<[u8; 32]>>,
    keys: Arc<RwLock<Vec<KmsKey>>>,
}

impl KmsService {
    pub async fn new(keys_dir: &Path) -> Result<Self, CryptoError> {
        std::fs::create_dir_all(keys_dir).map_err(CryptoError::Io)?;

        let keys_path = keys_dir.join("kms_keys.json");

        let master_key = Self::load_or_create_master_key(&keys_dir.join("kms_master.key"))?;

        let keys = if keys_path.exists() {
            let data = std::fs::read_to_string(&keys_path).map_err(CryptoError::Io)?;
            let store: KmsStore = serde_json::from_str(&data)
                .map_err(|e| CryptoError::EncryptionFailed(format!("Bad KMS store: {}", e)))?;
            store.keys
        } else {
            Vec::new()
        };

        Ok(Self {
            keys_path,
            master_key: Arc::new(RwLock::new(master_key)),
            keys: Arc::new(RwLock::new(keys)),
        })
    }

    fn load_or_create_master_key(path: &Path) -> Result<[u8; 32], CryptoError> {
        if path.exists() {
            let encoded = std::fs::read_to_string(path).map_err(CryptoError::Io)?;
            let decoded = B64.decode(encoded.trim()).map_err(|e| {
                CryptoError::EncryptionFailed(format!("Bad master key encoding: {}", e))
            })?;
            if decoded.len() != 32 {
                return Err(CryptoError::InvalidKeySize(decoded.len()));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&decoded);
            Ok(key)
        } else {
            let mut key = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            let encoded = B64.encode(key);
            std::fs::write(path, &encoded).map_err(CryptoError::Io)?;
            Ok(key)
        }
    }

    fn encrypt_key_material(
        master_key: &[u8; 32],
        plaintext_key: &[u8],
    ) -> Result<String, CryptoError> {
        let cipher = Aes256Gcm::new(master_key.into());
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext_key)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        let mut combined = Vec::with_capacity(12 + ciphertext.len());
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);
        Ok(B64.encode(&combined))
    }

    fn decrypt_key_material(
        master_key: &[u8; 32],
        encrypted_b64: &str,
    ) -> Result<Vec<u8>, CryptoError> {
        let combined = B64.decode(encrypted_b64).map_err(|e| {
            CryptoError::EncryptionFailed(format!("Bad key material encoding: {}", e))
        })?;
        if combined.len() < 12 {
            return Err(CryptoError::EncryptionFailed(
                "Encrypted key material too short".to_string(),
            ));
        }

        let (nonce_bytes, ciphertext) = combined.split_at(12);
        let cipher = Aes256Gcm::new(master_key.into());
        let nonce = Nonce::from_slice(nonce_bytes);

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed(0))
    }

    async fn save(&self) -> Result<(), CryptoError> {
        let keys = self.keys.read().await;
        let store = KmsStore { keys: keys.clone() };
        let json = serde_json::to_string_pretty(&store)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
        std::fs::write(&self.keys_path, json).map_err(CryptoError::Io)?;
        Ok(())
    }

    pub async fn create_key(&self, description: &str) -> Result<KmsKey, CryptoError> {
        let key_id = uuid::Uuid::new_v4().to_string();
        let arn = format!("arn:aws:kms:local:000000000000:key/{}", key_id);

        let mut plaintext_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut plaintext_key);

        let master = self.master_key.read().await;
        let encrypted = Self::encrypt_key_material(&master, &plaintext_key)?;

        let kms_key = KmsKey {
            key_id: key_id.clone(),
            arn,
            description: description.to_string(),
            creation_date: Utc::now(),
            enabled: true,
            key_state: "Enabled".to_string(),
            key_usage: "ENCRYPT_DECRYPT".to_string(),
            key_spec: "SYMMETRIC_DEFAULT".to_string(),
            encrypted_key_material: encrypted,
        };

        self.keys.write().await.push(kms_key.clone());
        self.save().await?;
        Ok(kms_key)
    }

    pub async fn list_keys(&self) -> Vec<KmsKey> {
        self.keys.read().await.clone()
    }

    pub async fn get_key(&self, key_id: &str) -> Option<KmsKey> {
        let keys = self.keys.read().await;
        keys.iter()
            .find(|k| k.key_id == key_id || k.arn == key_id)
            .cloned()
    }

    pub async fn delete_key(&self, key_id: &str) -> Result<bool, CryptoError> {
        let mut keys = self.keys.write().await;
        let len_before = keys.len();
        keys.retain(|k| k.key_id != key_id && k.arn != key_id);
        let removed = keys.len() < len_before;
        drop(keys);
        if removed {
            self.save().await?;
        }
        Ok(removed)
    }

    pub async fn enable_key(&self, key_id: &str) -> Result<bool, CryptoError> {
        let mut keys = self.keys.write().await;
        if let Some(key) = keys.iter_mut().find(|k| k.key_id == key_id) {
            key.enabled = true;
            key.key_state = "Enabled".to_string();
            drop(keys);
            self.save().await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub async fn disable_key(&self, key_id: &str) -> Result<bool, CryptoError> {
        let mut keys = self.keys.write().await;
        if let Some(key) = keys.iter_mut().find(|k| k.key_id == key_id) {
            key.enabled = false;
            key.key_state = "Disabled".to_string();
            drop(keys);
            self.save().await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub async fn decrypt_data_key(&self, key_id: &str) -> Result<Vec<u8>, CryptoError> {
        let keys = self.keys.read().await;
        let key = keys
            .iter()
            .find(|k| k.key_id == key_id || k.arn == key_id)
            .ok_or_else(|| CryptoError::EncryptionFailed("KMS key not found".to_string()))?;

        if !key.enabled {
            return Err(CryptoError::EncryptionFailed(
                "KMS key is disabled".to_string(),
            ));
        }

        let master = self.master_key.read().await;
        Self::decrypt_key_material(&master, &key.encrypted_key_material)
    }

    pub async fn encrypt_data(
        &self,
        key_id: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let data_key = self.decrypt_data_key(key_id).await?;
        if data_key.len() != 32 {
            return Err(CryptoError::InvalidKeySize(data_key.len()));
        }

        let key_arr: [u8; 32] = data_key.try_into().unwrap();
        let cipher = Aes256Gcm::new(&key_arr.into());
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    pub async fn decrypt_data(
        &self,
        key_id: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() < 12 {
            return Err(CryptoError::EncryptionFailed(
                "Ciphertext too short".to_string(),
            ));
        }

        let data_key = self.decrypt_data_key(key_id).await?;
        if data_key.len() != 32 {
            return Err(CryptoError::InvalidKeySize(data_key.len()));
        }

        let key_arr: [u8; 32] = data_key.try_into().unwrap();
        let (nonce_bytes, ct) = ciphertext.split_at(12);
        let cipher = Aes256Gcm::new(&key_arr.into());
        let nonce = Nonce::from_slice(nonce_bytes);

        cipher
            .decrypt(nonce, ct)
            .map_err(|_| CryptoError::DecryptionFailed(0))
    }

    pub async fn generate_data_key(
        &self,
        key_id: &str,
        num_bytes: usize,
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let kms_key = self.decrypt_data_key(key_id).await?;
        if kms_key.len() != 32 {
            return Err(CryptoError::InvalidKeySize(kms_key.len()));
        }

        let mut plaintext_key = vec![0u8; num_bytes];
        rand::thread_rng().fill_bytes(&mut plaintext_key);

        let key_arr: [u8; 32] = kms_key.try_into().unwrap();
        let cipher = Aes256Gcm::new(&key_arr.into());
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted = cipher
            .encrypt(nonce, plaintext_key.as_slice())
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        let mut wrapped = Vec::with_capacity(12 + encrypted.len());
        wrapped.extend_from_slice(&nonce_bytes);
        wrapped.extend_from_slice(&encrypted);

        Ok((plaintext_key, wrapped))
    }
}

pub async fn load_or_create_master_key(keys_dir: &Path) -> Result<[u8; 32], CryptoError> {
    std::fs::create_dir_all(keys_dir).map_err(CryptoError::Io)?;
    let path = keys_dir.join("master.key");

    if path.exists() {
        let encoded = std::fs::read_to_string(&path).map_err(CryptoError::Io)?;
        let decoded = B64.decode(encoded.trim()).map_err(|e| {
            CryptoError::EncryptionFailed(format!("Bad master key encoding: {}", e))
        })?;
        if decoded.len() != 32 {
            return Err(CryptoError::InvalidKeySize(decoded.len()));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&decoded);
        Ok(key)
    } else {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        let encoded = B64.encode(key);
        std::fs::write(&path, &encoded).map_err(CryptoError::Io)?;
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_and_list_keys() {
        let dir = tempfile::tempdir().unwrap();
        let kms = KmsService::new(dir.path()).await.unwrap();

        let key = kms.create_key("test key").await.unwrap();
        assert!(key.enabled);
        assert_eq!(key.description, "test key");
        assert!(key.key_id.len() > 0);

        let keys = kms.list_keys().await;
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_id, key.key_id);
    }

    #[tokio::test]
    async fn test_enable_disable_key() {
        let dir = tempfile::tempdir().unwrap();
        let kms = KmsService::new(dir.path()).await.unwrap();

        let key = kms.create_key("toggle").await.unwrap();
        assert!(key.enabled);

        kms.disable_key(&key.key_id).await.unwrap();
        let k = kms.get_key(&key.key_id).await.unwrap();
        assert!(!k.enabled);

        kms.enable_key(&key.key_id).await.unwrap();
        let k = kms.get_key(&key.key_id).await.unwrap();
        assert!(k.enabled);
    }

    #[tokio::test]
    async fn test_delete_key() {
        let dir = tempfile::tempdir().unwrap();
        let kms = KmsService::new(dir.path()).await.unwrap();

        let key = kms.create_key("doomed").await.unwrap();
        assert!(kms.delete_key(&key.key_id).await.unwrap());
        assert!(kms.get_key(&key.key_id).await.is_none());
        assert_eq!(kms.list_keys().await.len(), 0);
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_data() {
        let dir = tempfile::tempdir().unwrap();
        let kms = KmsService::new(dir.path()).await.unwrap();

        let key = kms.create_key("enc-key").await.unwrap();
        let plaintext = b"Hello, KMS!";

        let ciphertext = kms.encrypt_data(&key.key_id, plaintext).await.unwrap();
        assert_ne!(&ciphertext, plaintext);

        let decrypted = kms.decrypt_data(&key.key_id, &ciphertext).await.unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_generate_data_key() {
        let dir = tempfile::tempdir().unwrap();
        let kms = KmsService::new(dir.path()).await.unwrap();

        let key = kms.create_key("data-key-gen").await.unwrap();
        let (plaintext, wrapped) = kms.generate_data_key(&key.key_id, 32).await.unwrap();

        assert_eq!(plaintext.len(), 32);
        assert!(wrapped.len() > 32);
    }

    #[tokio::test]
    async fn test_disabled_key_cannot_encrypt() {
        let dir = tempfile::tempdir().unwrap();
        let kms = KmsService::new(dir.path()).await.unwrap();

        let key = kms.create_key("disabled").await.unwrap();
        kms.disable_key(&key.key_id).await.unwrap();

        let result = kms.encrypt_data(&key.key_id, b"test").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_persistence_across_reload() {
        let dir = tempfile::tempdir().unwrap();

        let key_id = {
            let kms = KmsService::new(dir.path()).await.unwrap();
            let key = kms.create_key("persistent").await.unwrap();
            key.key_id
        };

        let kms2 = KmsService::new(dir.path()).await.unwrap();
        let key = kms2.get_key(&key_id).await;
        assert!(key.is_some());
        assert_eq!(key.unwrap().description, "persistent");
    }

    #[tokio::test]
    async fn test_master_key_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let key1 = load_or_create_master_key(dir.path()).await.unwrap();
        let key2 = load_or_create_master_key(dir.path()).await.unwrap();
        assert_eq!(key1, key2);
    }
}
