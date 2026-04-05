use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct DomainData {
    #[serde(default)]
    mappings: HashMap<String, String>,
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
                .and_then(|s| serde_json::from_str(&s).ok())
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
        if let Ok(json) = serde_json::to_string_pretty(&*data) {
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
        self.data.read().mappings.get(domain).cloned()
    }

    pub fn set_mapping(&self, domain: &str, bucket: &str) {
        self.data.write().mappings.insert(domain.to_string(), bucket.to_string());
        self.save();
    }

    pub fn delete_mapping(&self, domain: &str) -> bool {
        let removed = self.data.write().mappings.remove(domain).is_some();
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
