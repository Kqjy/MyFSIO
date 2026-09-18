use chrono::Utc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct DomainData {
    #[serde(default)]
    mappings: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum DomainDataFile {
    Wrapped(DomainData),
    Flat(HashMap<String, String>),
}

impl DomainDataFile {
    fn into_domain_data(self) -> DomainData {
        match self {
            Self::Wrapped(data) => data,
            Self::Flat(mappings) => DomainData {
                mappings: mappings
                    .into_iter()
                    .map(|(domain, bucket)| (normalize_domain(&domain), bucket))
                    .collect(),
            },
        }
    }
}

fn domains_path(storage_root: &Path) -> PathBuf {
    storage_root
        .join(".myfsio.sys")
        .join("config")
        .join("website_domains.json")
}

fn read_domains(path: &Path) -> std::io::Result<DomainData> {
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str::<DomainDataFile>(&text)
            .map(DomainDataFile::into_domain_data)
            .map_err(std::io::Error::other),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(DomainData::default()),
        Err(err) => Err(err),
    }
}

fn write_domains(path: &Path, data: &DomainData) -> std::io::Result<()> {
    let mut bytes = serde_json::to_vec_pretty(&data.mappings).map_err(std::io::Error::other)?;
    bytes.push(b'\n');
    myfsio_common::fs_util::atomic_write_file(path, &bytes)
}

fn write_domains_or_rollback(
    path: &Path,
    data: &mut DomainData,
    previous: DomainData,
) -> std::io::Result<()> {
    match write_domains(path, data) {
        Ok(()) => Ok(()),
        Err(err) => {
            *data = previous;
            Err(err)
        }
    }
}

fn preserve_unreadable_domains(path: &Path, reason: &str) {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("website_domains.json");
    let preserved = path.with_file_name(format!("{name}.corrupt-{}", Utc::now().timestamp()));
    match std::fs::rename(path, &preserved) {
        Ok(()) => tracing::error!(
            path = %path.display(),
            preserved_path = %preserved.display(),
            reason,
            "Website domain mappings are unreadable; preserved the file and continued with no mappings. Every virtual-host route stays unmapped until it is restored."
        ),
        Err(rename_error) => tracing::error!(
            path = %path.display(),
            reason,
            rename_error = %rename_error,
            "Website domain mappings are unreadable and could not be preserved; continued with no mappings"
        ),
    }
}

pub struct WebsiteDomainStore {
    path: PathBuf,
    data: Arc<RwLock<DomainData>>,
}

impl WebsiteDomainStore {
    pub fn new(storage_root: &Path) -> Self {
        let path = domains_path(storage_root);
        let data = match read_domains(&path) {
            Ok(data) => data,
            Err(err) => {
                preserve_unreadable_domains(&path, &err.to_string());
                DomainData::default()
            }
        };
        Self {
            path,
            data: Arc::new(RwLock::new(data)),
        }
    }

    pub fn open(storage_root: &Path) -> std::io::Result<Self> {
        let path = domains_path(storage_root);
        let data = read_domains(&path)?;
        Ok(Self {
            path,
            data: Arc::new(RwLock::new(data)),
        })
    }

    fn report_write_failure(&self, change: &str, error: &std::io::Error) {
        tracing::error!(
            path = %self.path.display(),
            error = %error,
            "Failed to persist website domain {}; rolled the in-memory change back so memory matches disk",
            change
        );
    }

    pub fn list_all(&self) -> Vec<serde_json::Value> {
        self.data
            .read()
            .mappings
            .iter()
            .map(|(domain, bucket)| {
                serde_json::json!({
                    "domain": domain,
                    "bucket": bucket,
                })
            })
            .collect()
    }

    pub fn get_bucket(&self, domain: &str) -> Option<String> {
        let domain = normalize_domain(domain);
        self.data.read().mappings.get(&domain).cloned()
    }

    pub fn set_mapping(&self, domain: &str, bucket: &str) {
        if let Err(err) = self.try_set_mapping(domain, bucket) {
            self.report_write_failure("mapping", &err);
        }
    }

    pub fn try_set_mapping(&self, domain: &str, bucket: &str) -> std::io::Result<()> {
        let domain = normalize_domain(domain);
        let mut data = self.data.write();
        let previous = data.clone();
        data.mappings.insert(domain, bucket.to_string());
        write_domains_or_rollback(&self.path, &mut data, previous)
    }

    pub fn delete_mapping(&self, domain: &str) -> bool {
        match self.try_delete_mapping(domain) {
            Ok(removed) => removed,
            Err(err) => {
                self.report_write_failure("mapping removal", &err);
                false
            }
        }
    }

    pub fn try_delete_mapping(&self, domain: &str) -> std::io::Result<bool> {
        let domain = normalize_domain(domain);
        let mut data = self.data.write();
        let previous = data.clone();
        if data.mappings.remove(&domain).is_none() {
            return Ok(false);
        }
        write_domains_or_rollback(&self.path, &mut data, previous)?;
        Ok(true)
    }
}

pub fn normalize_domain(domain: &str) -> String {
    domain.trim().to_ascii_lowercase()
}

pub fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::WebsiteDomainStore;
    use serde_json::json;
    use std::path::{Path, PathBuf};
    use tempfile::tempdir;

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
    fn loads_legacy_flat_mapping_file() {
        let tmp = tempdir().expect("tempdir");
        let config_dir = tmp.path().join(".myfsio.sys").join("config");
        std::fs::create_dir_all(&config_dir).expect("create config dir");
        std::fs::write(
            config_dir.join("website_domains.json"),
            r#"{"Example.COM":"site-bucket"}"#,
        )
        .expect("write config");

        let store = WebsiteDomainStore::new(tmp.path());

        assert_eq!(
            store.get_bucket("example.com"),
            Some("site-bucket".to_string())
        );
    }

    #[test]
    fn loads_wrapped_mapping_file() {
        let tmp = tempdir().expect("tempdir");
        let config_dir = tmp.path().join(".myfsio.sys").join("config");
        std::fs::create_dir_all(&config_dir).expect("create config dir");
        std::fs::write(
            config_dir.join("website_domains.json"),
            r#"{"mappings":{"example.com":"site-bucket"}}"#,
        )
        .expect("write config");

        let store = WebsiteDomainStore::new(tmp.path());

        assert_eq!(
            store.get_bucket("example.com"),
            Some("site-bucket".to_string())
        );
    }

    #[test]
    fn saves_in_shared_plain_mapping_format() {
        let tmp = tempdir().expect("tempdir");
        let store = WebsiteDomainStore::new(tmp.path());

        store.set_mapping("Example.COM", "site-bucket");

        let saved = std::fs::read_to_string(
            tmp.path()
                .join(".myfsio.sys")
                .join("config")
                .join("website_domains.json"),
        )
        .expect("read config");
        let json: serde_json::Value = serde_json::from_str(&saved).expect("parse config");

        assert_eq!(json, json!({"example.com": "site-bucket"}));
    }

    #[test]
    fn absent_mapping_file_loads_empty_without_failing() {
        let tmp = tempdir().expect("tempdir");

        let store = WebsiteDomainStore::new(tmp.path());
        assert!(store.list_all().is_empty());

        let opened = WebsiteDomainStore::open(tmp.path()).expect("absent file opens clean");
        assert!(opened.list_all().is_empty());
        assert!(!config_dir(tmp.path()).exists());
    }

    #[test]
    fn damaged_mapping_file_is_preserved_instead_of_silently_emptied() {
        let tmp = tempdir().expect("tempdir");
        std::fs::create_dir_all(config_dir(tmp.path())).expect("create config dir");
        let path = config_dir(tmp.path()).join("website_domains.json");
        std::fs::write(&path, "{not json").expect("write config");

        assert!(WebsiteDomainStore::open(tmp.path()).is_err());

        let store = WebsiteDomainStore::new(tmp.path());
        assert!(store.list_all().is_empty());
        assert!(!path.exists());
        assert!(file_names(&config_dir(tmp.path()))
            .iter()
            .any(|name| name.starts_with("website_domains.json.corrupt-")));
    }

    #[test]
    fn saved_mappings_round_trip_and_leave_no_temp_residue() {
        let tmp = tempdir().expect("tempdir");
        let store = WebsiteDomainStore::new(tmp.path());

        store
            .try_set_mapping("Example.COM", "site-bucket")
            .expect("set mapping");
        store
            .try_set_mapping("other.example.com", "other-bucket")
            .expect("set mapping");
        assert!(store
            .try_delete_mapping("other.example.com")
            .expect("delete mapping"));
        assert!(!store
            .try_delete_mapping("absent.test")
            .expect("delete absent"));

        let reopened = WebsiteDomainStore::open(tmp.path()).expect("reopen store");
        assert_eq!(
            reopened.get_bucket("example.com"),
            Some("site-bucket".to_string())
        );
        assert_eq!(reopened.get_bucket("other.example.com"), None);

        assert!(!file_names(&config_dir(tmp.path()))
            .iter()
            .any(|name| name.contains(".tmp-")));
    }
}
