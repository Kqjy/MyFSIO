use chrono::Utc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
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
    let host_port = after_scheme
        .split_once('/')
        .map(|(h, _)| h)
        .unwrap_or(after_scheme);
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

fn registry_path(storage_root: &Path) -> PathBuf {
    storage_root
        .join(".myfsio.sys")
        .join("config")
        .join("site_registry.json")
}

fn read_registry(path: &Path) -> std::io::Result<RegistryData> {
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text).map_err(std::io::Error::other),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(RegistryData::default()),
        Err(err) => Err(err),
    }
}

fn write_registry(path: &Path, data: &RegistryData) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut bytes = serde_json::to_vec_pretty(data).map_err(std::io::Error::other)?;
    bytes.push(b'\n');
    myfsio_common::fs_util::atomic_write_secret_file(path, &bytes)
}

fn write_registry_or_rollback(
    path: &Path,
    data: &mut RegistryData,
    previous: RegistryData,
) -> std::io::Result<()> {
    match write_registry(path, data) {
        Ok(()) => Ok(()),
        Err(err) => {
            *data = previous;
            Err(err)
        }
    }
}

fn preserve_unreadable_registry(path: &Path, reason: &str) {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("site_registry.json");
    let preserved = path.with_file_name(format!("{name}.corrupt-{}", Utc::now().timestamp()));
    match std::fs::rename(path, &preserved) {
        Ok(()) => tracing::error!(
            path = %path.display(),
            preserved_path = %preserved.display(),
            reason,
            "Site registry is unreadable; preserved it and continued with an empty registry. Local site identity and every peer need re-registering."
        ),
        Err(rename_error) => tracing::error!(
            path = %path.display(),
            reason,
            rename_error = %rename_error,
            "Site registry is unreadable and could not be preserved; continued with an empty registry"
        ),
    }
}

pub struct SiteRegistry {
    path: PathBuf,
    data: Arc<RwLock<RegistryData>>,
}

impl SiteRegistry {
    pub fn new(storage_root: &Path) -> Self {
        let path = registry_path(storage_root);
        let data = match read_registry(&path) {
            Ok(data) => data,
            Err(err) => {
                preserve_unreadable_registry(&path, &err.to_string());
                RegistryData::default()
            }
        };
        Self {
            path,
            data: Arc::new(RwLock::new(data)),
        }
    }

    pub fn open(storage_root: &Path) -> std::io::Result<Self> {
        let path = registry_path(storage_root);
        let data = read_registry(&path)?;
        Ok(Self {
            path,
            data: Arc::new(RwLock::new(data)),
        })
    }

    fn report_write_failure(&self, change: &str, error: &std::io::Error) {
        tracing::error!(
            path = %self.path.display(),
            error = %error,
            "Failed to persist site registry {}; rolled the in-memory change back so memory matches disk",
            change
        );
    }

    pub fn get_local_site(&self) -> Option<SiteInfo> {
        self.data.read().local.clone()
    }

    pub fn set_local_site(&self, site: SiteInfo) {
        if let Err(err) = self.try_set_local_site(site) {
            self.report_write_failure("local site", &err);
        }
    }

    pub fn try_set_local_site(&self, site: SiteInfo) -> std::io::Result<()> {
        let mut data = self.data.write();
        let previous = data.clone();
        data.local = Some(site);
        write_registry_or_rollback(&self.path, &mut data, previous)
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
        if let Err(err) = self.try_add_peer(peer) {
            self.report_write_failure("peer addition", &err);
        }
    }

    pub fn try_add_peer(&self, peer: PeerSite) -> std::io::Result<()> {
        let mut data = self.data.write();
        let previous = data.clone();
        data.peers.push(peer);
        write_registry_or_rollback(&self.path, &mut data, previous)
    }

    pub fn update_peer(&self, peer: PeerSite) {
        if let Err(err) = self.try_update_peer(peer) {
            self.report_write_failure("peer update", &err);
        }
    }

    pub fn try_update_peer(&self, peer: PeerSite) -> std::io::Result<()> {
        let mut data = self.data.write();
        let previous = data.clone();
        if let Some(existing) = data.peers.iter_mut().find(|p| p.site_id == peer.site_id) {
            *existing = peer;
        }
        write_registry_or_rollback(&self.path, &mut data, previous)
    }

    pub fn delete_peer(&self, site_id: &str) -> bool {
        match self.try_delete_peer(site_id) {
            Ok(removed) => removed,
            Err(err) => {
                self.report_write_failure("peer removal", &err);
                false
            }
        }
    }

    pub fn try_delete_peer(&self, site_id: &str) -> std::io::Result<bool> {
        let mut data = self.data.write();
        let previous = data.clone();
        let len_before = data.peers.len();
        data.peers.retain(|p| p.site_id != site_id);
        if data.peers.len() == len_before {
            return Ok(false);
        }
        write_registry_or_rollback(&self.path, &mut data, previous)?;
        Ok(true)
    }

    pub fn update_health(&self, site_id: &str, is_healthy: bool) {
        if let Err(err) = self.try_update_health(site_id, is_healthy) {
            self.report_write_failure("peer health", &err);
        }
    }

    pub fn try_update_health(&self, site_id: &str, is_healthy: bool) -> std::io::Result<()> {
        let mut data = self.data.write();
        let previous = data.clone();
        if let Some(peer) = data.peers.iter_mut().find(|p| p.site_id == site_id) {
            peer.is_healthy = is_healthy;
            peer.last_health_check = Some(Utc::now().to_rfc3339());
        }
        write_registry_or_rollback(&self.path, &mut data, previous)
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

    pub fn find_peer_by_connection_id(&self, connection_id: &str) -> Option<PeerSite> {
        if connection_id.is_empty() {
            return None;
        }
        self.data
            .read()
            .peers
            .iter()
            .find(|p| p.connection_id.as_deref() == Some(connection_id))
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_peer(site_id: &str) -> PeerSite {
        PeerSite {
            site_id: site_id.to_string(),
            endpoint: format!("http://{}.invalid:5050", site_id),
            region: default_region(),
            priority: default_priority(),
            display_name: site_id.to_string(),
            connection_id: Some(format!("conn-{}", site_id)),
            peer_inbound_access_key: Some(format!("AK{}", site_id)),
            created_at: None,
            is_healthy: false,
            last_health_check: None,
        }
    }

    fn config_dir(root: &Path) -> PathBuf {
        root.join(".myfsio.sys").join("config")
    }

    fn file_names(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .expect("read config dir")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .collect()
    }

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

    #[test]
    fn absent_registry_file_loads_empty_without_failing() {
        let tmp = tempfile::tempdir().expect("tempdir");

        let registry = SiteRegistry::new(tmp.path());
        assert!(registry.get_local_site().is_none());
        assert!(registry.list_peers().is_empty());

        let opened = SiteRegistry::open(tmp.path()).expect("absent registry opens clean");
        assert!(opened.list_peers().is_empty());
        assert!(!config_dir(tmp.path()).exists());
    }

    #[test]
    fn damaged_registry_file_is_preserved_instead_of_silently_emptied() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(config_dir(tmp.path())).expect("create config dir");
        let path = config_dir(tmp.path()).join("site_registry.json");
        std::fs::write(&path, "{not json").expect("write config");

        assert!(SiteRegistry::open(tmp.path()).is_err());

        let registry = SiteRegistry::new(tmp.path());
        assert!(registry.list_peers().is_empty());
        assert!(!path.exists());
        assert!(file_names(&config_dir(tmp.path()))
            .iter()
            .any(|name| name.starts_with("site_registry.json.corrupt-")));
    }

    #[test]
    fn saved_registry_round_trips_and_leaves_no_temp_residue() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let registry = SiteRegistry::new(tmp.path());

        registry
            .try_add_peer(sample_peer("peer-a"))
            .expect("add peer");
        registry
            .try_set_local_site(SiteInfo {
                site_id: "local".to_string(),
                endpoint: "http://127.0.0.1:5050".to_string(),
                region: default_region(),
                priority: default_priority(),
                display_name: "local".to_string(),
                created_at: None,
            })
            .expect("set local site");

        let reopened = SiteRegistry::open(tmp.path()).expect("reopen registry");
        assert_eq!(reopened.list_peers().len(), 1);
        assert_eq!(
            reopened.get_peer("peer-a").expect("peer").endpoint,
            "http://peer-a.invalid:5050"
        );
        assert_eq!(
            reopened.get_local_site().expect("local site").site_id,
            "local"
        );

        assert!(!file_names(&config_dir(tmp.path()))
            .iter()
            .any(|name| name.contains(".tmp-")));
    }

    #[test]
    fn deleting_a_peer_persists_and_reports_whether_it_existed() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let registry = SiteRegistry::new(tmp.path());
        registry
            .try_add_peer(sample_peer("peer-a"))
            .expect("add peer");

        assert!(!registry.try_delete_peer("absent").expect("delete absent"));
        assert!(registry.try_delete_peer("peer-a").expect("delete peer"));

        let reopened = SiteRegistry::open(tmp.path()).expect("reopen registry");
        assert!(reopened.list_peers().is_empty());
    }
}
