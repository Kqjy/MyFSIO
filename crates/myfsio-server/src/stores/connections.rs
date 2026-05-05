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
    #[serde(default)]
    pub tuning: Option<TransferTuning>,
}

impl RemoteConnection {
    pub fn resolved_tuning(&self) -> ResolvedTuning {
        self.tuning
            .as_ref()
            .map(|t| t.resolve())
            .unwrap_or_else(ResolvedTuning::legacy_default)
    }
}

fn default_region() -> String {
    "us-east-1".to_string()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransferTuning {
    #[serde(default)]
    pub profile: Option<TuningProfile>,
    #[serde(default)]
    pub part_size_bytes: Option<u64>,
    #[serde(default)]
    pub multipart_concurrency: Option<usize>,
    #[serde(default)]
    pub part_buffer_bytes: Option<usize>,
    #[serde(default)]
    pub mpu_in_place_retries: Option<u32>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TuningProfile {
    SsdLan,
    SsdWan,
    HddLan,
    HddWan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedTuning {
    pub part_size_bytes: u64,
    pub multipart_concurrency: usize,
    pub part_buffer_bytes: usize,
    pub mpu_in_place_retries: u32,
}

const S3_MIN_PART_BYTES: u64 = 5 * 1024 * 1024;
const TUNING_MAX_PART_BYTES: u64 = 5 * 1024 * 1024 * 1024;
const TUNING_MAX_CONCURRENCY: usize = 64;
const TUNING_MAX_BUFFER_BYTES: usize = 16 * 1024 * 1024;
const TUNING_MAX_IN_PLACE_RETRIES: u32 = 10;

impl ResolvedTuning {
    pub const fn legacy_default() -> Self {
        Self {
            part_size_bytes: 8 * 1024 * 1024,
            multipart_concurrency: 4,
            part_buffer_bytes: 1024 * 1024,
            mpu_in_place_retries: 3,
        }
    }

    fn clamp(self) -> Self {
        Self {
            part_size_bytes: self
                .part_size_bytes
                .clamp(S3_MIN_PART_BYTES, TUNING_MAX_PART_BYTES),
            multipart_concurrency: self.multipart_concurrency.clamp(1, TUNING_MAX_CONCURRENCY),
            part_buffer_bytes: self.part_buffer_bytes.clamp(64 * 1024, TUNING_MAX_BUFFER_BYTES),
            mpu_in_place_retries: self.mpu_in_place_retries.min(TUNING_MAX_IN_PLACE_RETRIES),
        }
    }
}

impl TuningProfile {
    pub fn defaults(self) -> ResolvedTuning {
        match self {
            Self::SsdLan => ResolvedTuning {
                part_size_bytes: 8 * 1024 * 1024,
                multipart_concurrency: 4,
                part_buffer_bytes: 1024 * 1024,
                mpu_in_place_retries: 3,
            },
            Self::SsdWan => ResolvedTuning {
                part_size_bytes: 32 * 1024 * 1024,
                multipart_concurrency: 12,
                part_buffer_bytes: 2 * 1024 * 1024,
                mpu_in_place_retries: 5,
            },
            Self::HddLan => ResolvedTuning {
                part_size_bytes: 32 * 1024 * 1024,
                multipart_concurrency: 2,
                part_buffer_bytes: 4 * 1024 * 1024,
                mpu_in_place_retries: 3,
            },
            Self::HddWan => ResolvedTuning {
                part_size_bytes: 64 * 1024 * 1024,
                multipart_concurrency: 2,
                part_buffer_bytes: 4 * 1024 * 1024,
                mpu_in_place_retries: 5,
            },
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::SsdLan => "ssd_lan",
            Self::SsdWan => "ssd_wan",
            Self::HddLan => "hdd_lan",
            Self::HddWan => "hdd_wan",
        }
    }

    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "ssd_lan" => Some(Self::SsdLan),
            "ssd_wan" => Some(Self::SsdWan),
            "hdd_lan" => Some(Self::HddLan),
            "hdd_wan" => Some(Self::HddWan),
            _ => None,
        }
    }
}

impl TransferTuning {
    pub fn resolve(&self) -> ResolvedTuning {
        let base = self
            .profile
            .map(|p| p.defaults())
            .unwrap_or_else(ResolvedTuning::legacy_default);
        ResolvedTuning {
            part_size_bytes: self.part_size_bytes.unwrap_or(base.part_size_bytes),
            multipart_concurrency: self
                .multipart_concurrency
                .unwrap_or(base.multipart_concurrency),
            part_buffer_bytes: self.part_buffer_bytes.unwrap_or(base.part_buffer_bytes),
            mpu_in_place_retries: self
                .mpu_in_place_retries
                .unwrap_or(base.mpu_in_place_retries),
        }
        .clamp()
    }

    pub fn is_empty(&self) -> bool {
        self.profile.is_none()
            && self.part_size_bytes.is_none()
            && self.multipart_concurrency.is_none()
            && self.part_buffer_bytes.is_none()
            && self.mpu_in_place_retries.is_none()
    }
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
    let raw: Vec<RemoteConnection> = serde_json::from_str(&text).unwrap_or_default();
    let mut connections = Vec::with_capacity(raw.len());
    for mut conn in raw {
        if let Some(token) = conn.secret_key.strip_prefix(ENCRYPTED_PREFIX) {
            match myfsio_auth::fernet::decrypt(encryption_key, token) {
                Ok(plaintext) => match String::from_utf8(plaintext) {
                    Ok(s) => conn.secret_key = s,
                    Err(_) => {
                        tracing::error!(
                            "Connection '{}' (id={}) decrypted to non-UTF-8 secret; skipping. Recreate the connection to restore replication.",
                            conn.name,
                            conn.id
                        );
                        continue;
                    }
                },
                Err(err) => {
                    tracing::error!(
                        "Connection '{}' (id={}) has an undecryptable secret_key ({}). Skipping. Common cause: .myfsio.sys/config/.connections_key was rotated/lost. Recreate the connection.",
                        conn.name,
                        conn.id,
                        err
                    );
                    continue;
                }
            }
        }
        connections.push(conn);
    }
    connections
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_default_uses_documented_values() {
        let r = ResolvedTuning::legacy_default();
        assert_eq!(r.part_size_bytes, 8 * 1024 * 1024);
        assert_eq!(r.multipart_concurrency, 4);
        assert_eq!(r.part_buffer_bytes, 1024 * 1024);
        assert_eq!(r.mpu_in_place_retries, 3);
    }

    #[test]
    fn empty_tuning_resolves_to_legacy_default() {
        let t = TransferTuning::default();
        assert_eq!(t.resolve(), ResolvedTuning::legacy_default());
    }

    #[test]
    fn ssd_wan_profile_defaults() {
        let r = TuningProfile::SsdWan.defaults();
        assert_eq!(r.part_size_bytes, 32 * 1024 * 1024);
        assert_eq!(r.multipart_concurrency, 12);
        assert_eq!(r.part_buffer_bytes, 2 * 1024 * 1024);
        assert_eq!(r.mpu_in_place_retries, 5);
    }

    #[test]
    fn hdd_wan_profile_defaults() {
        let r = TuningProfile::HddWan.defaults();
        assert_eq!(r.part_size_bytes, 64 * 1024 * 1024);
        assert_eq!(r.multipart_concurrency, 2);
        assert_eq!(r.part_buffer_bytes, 4 * 1024 * 1024);
        assert_eq!(r.mpu_in_place_retries, 5);
    }

    #[test]
    fn explicit_overrides_beat_profile() {
        let t = TransferTuning {
            profile: Some(TuningProfile::SsdWan),
            multipart_concurrency: Some(20),
            part_size_bytes: None,
            part_buffer_bytes: None,
            mpu_in_place_retries: None,
        };
        let r = t.resolve();
        assert_eq!(r.multipart_concurrency, 20);
        assert_eq!(r.part_size_bytes, 32 * 1024 * 1024);
    }

    #[test]
    fn override_alone_falls_back_to_legacy_for_unset() {
        let t = TransferTuning {
            profile: None,
            multipart_concurrency: Some(8),
            part_size_bytes: None,
            part_buffer_bytes: None,
            mpu_in_place_retries: None,
        };
        let r = t.resolve();
        assert_eq!(r.multipart_concurrency, 8);
        assert_eq!(r.part_size_bytes, 8 * 1024 * 1024);
        assert_eq!(r.mpu_in_place_retries, 3);
    }

    #[test]
    fn part_size_clamped_to_s3_minimum() {
        let t = TransferTuning {
            part_size_bytes: Some(1024),
            ..TransferTuning::default()
        };
        assert_eq!(t.resolve().part_size_bytes, S3_MIN_PART_BYTES);
    }

    #[test]
    fn concurrency_clamped_to_at_least_one() {
        let t = TransferTuning {
            multipart_concurrency: Some(0),
            ..TransferTuning::default()
        };
        assert_eq!(t.resolve().multipart_concurrency, 1);
    }

    #[test]
    fn concurrency_clamped_to_max() {
        let t = TransferTuning {
            multipart_concurrency: Some(99999),
            ..TransferTuning::default()
        };
        assert_eq!(t.resolve().multipart_concurrency, TUNING_MAX_CONCURRENCY);
    }

    #[test]
    fn buffer_clamped_to_max() {
        let t = TransferTuning {
            part_buffer_bytes: Some(usize::MAX),
            ..TransferTuning::default()
        };
        assert_eq!(t.resolve().part_buffer_bytes, TUNING_MAX_BUFFER_BYTES);
    }

    #[test]
    fn legacy_json_round_trips_with_no_tuning_field() {
        let json = r#"{"id":"x","name":"n","endpoint_url":"http://a","access_key":"k","secret_key":"s"}"#;
        let conn: RemoteConnection = serde_json::from_str(json).unwrap();
        assert!(conn.tuning.is_none());
        assert_eq!(conn.region, "us-east-1");
        assert_eq!(conn.resolved_tuning(), ResolvedTuning::legacy_default());
    }

    #[test]
    fn profile_serializes_snake_case() {
        let json = serde_json::to_string(&TuningProfile::SsdWan).unwrap();
        assert_eq!(json, "\"ssd_wan\"");
        let parsed: TuningProfile = serde_json::from_str("\"hdd_wan\"").unwrap();
        assert_eq!(parsed, TuningProfile::HddWan);
    }

    #[test]
    fn is_empty_detects_blank_tuning() {
        assert!(TransferTuning::default().is_empty());
        let t = TransferTuning {
            profile: Some(TuningProfile::SsdLan),
            ..TransferTuning::default()
        };
        assert!(!t.is_empty());
    }
}
