use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE;
use base64::Engine;
use parking_lot::RwLock;
use rand::RngCore;
use serde::{Deserialize, Serialize};

const ENCRYPTED_PREFIX: &str = "enc:";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteConnection {
    pub id: String,
    pub name: String,
    pub endpoint_url: String,
    pub access_key: String,
    pub secret_key: String,
    #[serde(default = "default_region")]
    pub region: String,
}

fn default_region() -> String {
    "us-east-1".to_string()
}

pub struct ConnectionStore {
    path: PathBuf,
    encryption_key: String,
    inner: Arc<RwLock<Vec<RemoteConnection>>>,
}

impl ConnectionStore {
    pub fn new(storage_root: &Path) -> Self {
        let path = storage_root
            .join(".myfsio.sys")
            .join("config")
            .join("connections.json");
        let encryption_key = load_or_create_key(storage_root);
        let inner = Arc::new(RwLock::new(load_from_disk(&path, &encryption_key)));
        Self {
            path,
            encryption_key,
            inner,
        }
    }

    pub fn reload(&self) {
        let loaded = load_from_disk(&self.path, &self.encryption_key);
        *self.inner.write() = loaded;
    }

    pub fn list(&self) -> Vec<RemoteConnection> {
        self.inner.read().clone()
    }

    pub fn get(&self, id: &str) -> Option<RemoteConnection> {
        self.inner.read().iter().find(|c| c.id == id).cloned()
    }

    pub fn add(&self, connection: RemoteConnection) -> std::io::Result<()> {
        {
            let mut guard = self.inner.write();
            if let Some(existing) = guard.iter_mut().find(|c| c.id == connection.id) {
                *existing = connection;
            } else {
                guard.push(connection);
            }
        }
        self.save()
    }

    pub fn delete(&self, id: &str) -> std::io::Result<bool> {
        let removed = {
            let mut guard = self.inner.write();
            let before = guard.len();
            guard.retain(|c| c.id != id);
            guard.len() != before
        };
        if removed {
            self.save()?;
        }
        Ok(removed)
    }

    fn save(&self) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut snapshot = self.inner.read().clone();
        for conn in &mut snapshot {
            if !conn.secret_key.starts_with(ENCRYPTED_PREFIX) {
                if let Ok(token) =
                    myfsio_auth::fernet::encrypt(&self.encryption_key, conn.secret_key.as_bytes())
                {
                    conn.secret_key = format!("{}{}", ENCRYPTED_PREFIX, token);
                }
            }
        }
        let bytes = serde_json::to_vec_pretty(&snapshot)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, &self.path)
    }
}

fn load_or_create_key(storage_root: &Path) -> String {
    let key_path = storage_root
        .join(".myfsio.sys")
        .join("config")
        .join(".connections_key");
    if let Ok(text) = std::fs::read_to_string(&key_path) {
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            if let Ok(decoded) = URL_SAFE.decode(trimmed) {
                if decoded.len() == 32 {
                    return trimmed.to_string();
                }
            }
        }
    }
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    let encoded = URL_SAFE.encode(key);
    if let Some(parent) = key_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&key_path, &encoded);
    encoded
}

fn load_from_disk(path: &Path, encryption_key: &str) -> Vec<RemoteConnection> {
    if !path.exists() {
        return Vec::new();
    }
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(_) => return Vec::new(),
    };
    let mut connections: Vec<RemoteConnection> =
        serde_json::from_str(&text).unwrap_or_default();
    for conn in &mut connections {
        if let Some(token) = conn.secret_key.strip_prefix(ENCRYPTED_PREFIX) {
            match myfsio_auth::fernet::decrypt(encryption_key, token) {
                Ok(plaintext) => {
                    if let Ok(s) = String::from_utf8(plaintext) {
                        conn.secret_key = s;
                    }
                }
                Err(err) => {
                    tracing::error!(
                        "Failed to decrypt peer secret_key for connection {}: {}",
                        conn.id,
                        err
                    );
                }
            }
        }
    }
    connections
}
