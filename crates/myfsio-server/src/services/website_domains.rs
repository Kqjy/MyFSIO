use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
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

pub struct WebsiteDomainStore {
    path: PathBuf,
    data: Arc<RwLock<DomainData>>,
}

impl WebsiteDomainStore {
    pub fn new(storage_root: &std::path::Path) -> Self {
        let path = storage_root
            .join(".myfsio.sys")
            .join("config")
            .join("website_domains.json");
        let data = if path.exists() {
            std::fs::read_to_string(&path)
                .ok()
                .and_then(|s| serde_json::from_str::<DomainDataFile>(&s).ok())
                .map(DomainDataFile::into_domain_data)
                .unwrap_or_default()
        } else {
            DomainData::default()
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
        if let Ok(json) = serde_json::to_string_pretty(&data.mappings) {
            let _ = std::fs::write(&self.path, json);
        }
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
        let domain = normalize_domain(domain);
        self.data
            .write()
            .mappings
            .insert(domain, bucket.to_string());
        self.save();
    }

    pub fn delete_mapping(&self, domain: &str) -> bool {
        let domain = normalize_domain(domain);
        let removed = self.data.write().mappings.remove(&domain).is_some();
        if removed {
            self.save();
        }
        removed
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
    use tempfile::tempdir;

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
}
