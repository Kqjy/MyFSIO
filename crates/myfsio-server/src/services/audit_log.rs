use std::path::PathBuf;
use std::sync::Arc;

use chrono::Utc;
use parking_lot::Mutex;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub ts: String,
    pub correlation_id: String,
    pub origin_site_id: Option<String>,
    pub admin_user_id: Option<String>,
    pub action: String,
    pub method: String,
    pub path: String,
    pub target: AuditTarget,
    pub result: String,
    pub status_code: u16,
    pub peer_ip: Option<String>,
    pub idempotency_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribution: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditTarget {
    Local,
    Outbound,
}

pub const ATTRIBUTION_VERIFIED: &str = "verified";
pub const ATTRIBUTION_CLAIMED_BY_ORIGIN: &str = "claimed_by_origin";
pub const ATTRIBUTION_REJECTED: &str = "rejected_relay";

pub struct AuditLog {
    base_dir: PathBuf,
    enabled: bool,
    write_lock: Arc<Mutex<()>>,
}

impl AuditLog {
    pub fn new(storage_root: &std::path::Path, enabled: bool) -> Self {
        let base_dir = storage_root.join(".myfsio.sys").join("audit");
        Self {
            base_dir,
            enabled,
            write_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn record(&self, entry: AuditEntry) {
        if !self.enabled {
            return;
        }
        let date = Utc::now().format("%Y%m%d").to_string();
        let path = self.base_dir.join(format!("{}.jsonl", date));
        let line = match serde_json::to_string(&entry) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("audit log serialize failed: {}", e);
                return;
            }
        };
        let _guard = self.write_lock.lock();
        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                tracing::error!("audit log mkdir failed: {}", e);
                return;
            }
        }
        let mut content = line;
        content.push('\n');
        if let Err(e) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .and_then(|mut f| std::io::Write::write_all(&mut f, content.as_bytes()))
        {
            tracing::error!("audit log write failed: {}", e);
        }
    }

    pub fn read_recent(&self, limit: usize) -> Vec<serde_json::Value> {
        if !self.enabled {
            return Vec::new();
        }
        let mut entries: Vec<serde_json::Value> = Vec::new();
        let entries_iter = match std::fs::read_dir(&self.base_dir) {
            Ok(it) => it,
            Err(_) => return entries,
        };
        let mut files: Vec<PathBuf> = entries_iter
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("jsonl"))
            .collect();
        files.sort();
        for path in files.iter().rev() {
            let content = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            for line in content.lines().rev() {
                if entries.len() >= limit {
                    return entries;
                }
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
                    entries.push(value);
                }
            }
        }
        entries
    }
}
