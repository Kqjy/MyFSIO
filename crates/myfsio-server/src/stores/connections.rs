use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

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
    inner: Arc<RwLock<Vec<RemoteConnection>>>,
}

impl ConnectionStore {
    pub fn new(storage_root: &Path) -> Self {
        let path = storage_root
            .join(".myfsio.sys")
            .join("config")
            .join("connections.json");
        let inner = Arc::new(RwLock::new(load_from_disk(&path)));
        Self { path, inner }
    }

    pub fn reload(&self) {
        let loaded = load_from_disk(&self.path);
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
        let snapshot = self.inner.read().clone();
        let bytes = serde_json::to_vec_pretty(&snapshot)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&self.path, bytes)
    }
}

fn load_from_disk(path: &Path) -> Vec<RemoteConnection> {
    if !path.exists() {
        return Vec::new();
    }
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}
