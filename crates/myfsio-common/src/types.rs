use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectMeta {
    pub key: String,
    pub size: u64,
    pub last_modified: DateTime<Utc>,
    pub etag: Option<String>,
    pub content_type: Option<String>,
    pub storage_class: Option<String>,
    pub metadata: HashMap<String, String>,
    #[serde(default)]
    pub version_id: Option<String>,
    #[serde(default)]
    pub is_delete_marker: bool,
}

impl ObjectMeta {
    pub fn new(key: String, size: u64, last_modified: DateTime<Utc>) -> Self {
        Self {
            key,
            size,
            last_modified,
            etag: None,
            content_type: None,
            storage_class: Some("STANDARD".to_string()),
            metadata: HashMap::new(),
            version_id: None,
            is_delete_marker: false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DeleteOutcome {
    pub version_id: Option<String>,
    pub is_delete_marker: bool,
    pub existed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketMeta {
    pub name: String,
    pub creation_date: DateTime<Utc>,
}

#[derive(Debug, Clone, Default)]
pub struct BucketStats {
    pub objects: u64,
    pub bytes: u64,
    pub version_count: u64,
    pub version_bytes: u64,
}

impl BucketStats {
    pub fn total_objects(&self) -> u64 {
        self.objects + self.version_count
    }

    pub fn total_bytes(&self) -> u64 {
        self.bytes + self.version_bytes
    }
}

#[derive(Debug, Clone)]
pub struct ListObjectsResult {
    pub objects: Vec<ObjectMeta>,
    pub is_truncated: bool,
    pub next_continuation_token: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ShallowListResult {
    pub objects: Vec<ObjectMeta>,
    pub common_prefixes: Vec<String>,
    pub is_truncated: bool,
    pub next_continuation_token: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ListParams {
    pub max_keys: usize,
    pub continuation_token: Option<String>,
    pub prefix: Option<String>,
    pub start_after: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ShallowListParams {
    pub prefix: String,
    pub delimiter: String,
    pub max_keys: usize,
    pub continuation_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartMeta {
    pub part_number: u32,
    pub etag: String,
    pub size: u64,
    pub last_modified: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct PartInfo {
    pub part_number: u32,
    pub etag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultipartUploadInfo {
    pub upload_id: String,
    pub key: String,
    pub initiated: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    pub version_id: String,
    pub key: String,
    pub size: u64,
    pub last_modified: DateTime<Utc>,
    pub etag: Option<String>,
    pub is_latest: bool,
    #[serde(default)]
    pub is_delete_marker: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tag {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum VersioningStatus {
    #[default]
    Disabled,
    Enabled,
    Suspended,
}

impl VersioningStatus {
    pub fn is_enabled(self) -> bool {
        matches!(self, VersioningStatus::Enabled)
    }

    pub fn is_active(self) -> bool {
        matches!(self, VersioningStatus::Enabled | VersioningStatus::Suspended)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BucketConfig {
    #[serde(default)]
    pub versioning_enabled: bool,
    #[serde(default)]
    pub versioning_suspended: bool,
    #[serde(default)]
    pub tags: Vec<Tag>,
    #[serde(default)]
    pub cors: Option<serde_json::Value>,
    #[serde(default)]
    pub encryption: Option<serde_json::Value>,
    #[serde(default)]
    pub lifecycle: Option<serde_json::Value>,
    #[serde(default)]
    pub website: Option<serde_json::Value>,
    #[serde(default)]
    pub quota: Option<QuotaConfig>,
    #[serde(default)]
    pub acl: Option<serde_json::Value>,
    #[serde(default)]
    pub notification: Option<serde_json::Value>,
    #[serde(default)]
    pub logging: Option<serde_json::Value>,
    #[serde(default)]
    pub object_lock: Option<serde_json::Value>,
    #[serde(default)]
    pub policy: Option<serde_json::Value>,
    #[serde(default)]
    pub replication: Option<serde_json::Value>,
}

impl BucketConfig {
    pub fn versioning_status(&self) -> VersioningStatus {
        if self.versioning_enabled {
            VersioningStatus::Enabled
        } else if self.versioning_suspended {
            VersioningStatus::Suspended
        } else {
            VersioningStatus::Disabled
        }
    }

    pub fn set_versioning_status(&mut self, status: VersioningStatus) {
        match status {
            VersioningStatus::Enabled => {
                self.versioning_enabled = true;
                self.versioning_suspended = false;
            }
            VersioningStatus::Suspended => {
                self.versioning_enabled = false;
                self.versioning_suspended = true;
            }
            VersioningStatus::Disabled => {
                self.versioning_enabled = false;
                self.versioning_suspended = false;
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaConfig {
    pub max_bytes: Option<u64>,
    pub max_objects: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct Principal {
    pub access_key: String,
    pub user_id: String,
    pub display_name: String,
    pub is_admin: bool,
}

impl Principal {
    pub fn new(access_key: String, user_id: String, display_name: String, is_admin: bool) -> Self {
        Self {
            access_key,
            user_id,
            display_name,
            is_admin,
        }
    }
}
