use chrono::Utc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteInfo {
    pub site_id: String,
    pub endpoint: String,
    #[serde(default = "default_region")]
    pub region: String,
    #[serde(default = "default_priority")]
    pub priority: i32,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub created_at: Option<String>,
}

fn default_region() -> String {
    "us-east-1".to_string()
}
fn default_priority() -> i32 {
    100
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerSite {
    pub site_id: String,
    pub endpoint: String,
    #[serde(default = "default_region")]
    pub region: String,
    #[serde(default = "default_priority")]
    pub priority: i32,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub connection_id: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub is_healthy: bool,
    #[serde(default)]
    pub last_health_check: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct RegistryData {
    #[serde(default)]
    local: Option<SiteInfo>,
    #[serde(default)]
    peers: Vec<PeerSite>,
}

pub struct SiteRegistry {
    path: PathBuf,
    data: Arc<RwLock<RegistryData>>,
}

impl SiteRegistry {
    pub fn new(storage_root: &std::path::Path) -> Self {
        let path = storage_root
            .join(".myfsio.sys")
            .join("config")
            .join("site_registry.json");
        let data = if path.exists() {
            std::fs::read_to_string(&path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default()
        } else {
            RegistryData::default()
        };
        Self {
            path,
            data: Arc::new(RwLock::new(data)),
        }
    }

    fn save(&self) {
        let data = self.data.read();
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(&*data) {
            let _ = std::fs::write(&self.path, json);
        }
    }

    pub fn get_local_site(&self) -> Option<SiteInfo> {
        self.data.read().local.clone()
    }

    pub fn set_local_site(&self, site: SiteInfo) {
        self.data.write().local = Some(site);
        self.save();
    }

    pub fn list_peers(&self) -> Vec<PeerSite> {
        self.data.read().peers.clone()
    }

    pub fn get_peer(&self, site_id: &str) -> Option<PeerSite> {
        self.data.read().peers.iter().find(|p| p.site_id == site_id).cloned()
    }

    pub fn add_peer(&self, peer: PeerSite) {
        self.data.write().peers.push(peer);
        self.save();
    }

    pub fn update_peer(&self, peer: PeerSite) {
        let mut data = self.data.write();
        if let Some(existing) = data.peers.iter_mut().find(|p| p.site_id == peer.site_id) {
            *existing = peer;
        }
        drop(data);
        self.save();
    }

    pub fn delete_peer(&self, site_id: &str) -> bool {
        let mut data = self.data.write();
        let len_before = data.peers.len();
        data.peers.retain(|p| p.site_id != site_id);
        let removed = data.peers.len() < len_before;
        drop(data);
        if removed {
            self.save();
        }
        removed
    }

    pub fn update_health(&self, site_id: &str, is_healthy: bool) {
        let mut data = self.data.write();
        if let Some(peer) = data.peers.iter_mut().find(|p| p.site_id == site_id) {
            peer.is_healthy = is_healthy;
            peer.last_health_check = Some(Utc::now().to_rfc3339());
        }
        drop(data);
        self.save();
    }
}
