use chrono::Utc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

pub fn derive_local_endpoint(bind: &SocketAddr) -> String {
    let host = match bind.ip() {
        IpAddr::V4(v4) if v4.is_unspecified() => "127.0.0.1".to_string(),
        IpAddr::V6(v6) if v6.is_unspecified() => "[::1]".to_string(),
        IpAddr::V6(v6) => format!("[{}]", v6),
        IpAddr::V4(v4) => v4.to_string(),
    };
    format!("http://{}:{}", host, bind.port())
}

pub fn endpoint_port(endpoint: &str) -> Option<u16> {
    let trimmed = endpoint.trim_end_matches('/');
    let after_scheme = trimmed.split_once("://").map(|(_, r)| r).unwrap_or(trimmed);
    let host_port = after_scheme.split_once('/').map(|(h, _)| h).unwrap_or(after_scheme);
    if let Some(rest) = host_port.strip_prefix('[') {
        let (_v6, tail) = rest.split_once(']')?;
        tail.strip_prefix(':')?.parse().ok()
    } else {
        host_port.rsplit_once(':')?.1.parse().ok()
    }
}

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
    pub peer_inbound_access_key: Option<String>,
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
        self.data
            .read()
            .peers
            .iter()
            .find(|p| p.site_id == site_id)
            .cloned()
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

    pub fn is_peer_inbound_access_key(&self, access_key: &str) -> bool {
        if access_key.is_empty() {
            return false;
        }
        self.data
            .read()
            .peers
            .iter()
            .any(|p| p.peer_inbound_access_key.as_deref() == Some(access_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_local_endpoint_substitutes_loopback_for_unspecified_v4() {
        let bind: SocketAddr = "0.0.0.0:5050".parse().unwrap();
        assert_eq!(derive_local_endpoint(&bind), "http://127.0.0.1:5050");
    }

    #[test]
    fn derive_local_endpoint_keeps_concrete_v4() {
        let bind: SocketAddr = "127.0.0.1:5050".parse().unwrap();
        assert_eq!(derive_local_endpoint(&bind), "http://127.0.0.1:5050");
    }

    #[test]
    fn derive_local_endpoint_brackets_v6_and_substitutes_loopback() {
        let bind: SocketAddr = "[::]:5050".parse().unwrap();
        assert_eq!(derive_local_endpoint(&bind), "http://[::1]:5050");
        let bind2: SocketAddr = "[2001:db8::1]:9000".parse().unwrap();
        assert_eq!(derive_local_endpoint(&bind2), "http://[2001:db8::1]:9000");
    }

    #[test]
    fn endpoint_port_parses_v4_v6_and_paths() {
        assert_eq!(endpoint_port("http://127.0.0.1:5050"), Some(5050));
        assert_eq!(endpoint_port("https://example.com:8443/"), Some(8443));
        assert_eq!(endpoint_port("http://[::1]:5050"), Some(5050));
        assert_eq!(endpoint_port("http://[2001:db8::1]:9000/path"), Some(9000));
        assert_eq!(endpoint_port("http://example.com"), None);
    }
}
