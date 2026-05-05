use chrono::{DateTime, Utc};
use myfsio_common::types::{Principal, PrincipalKind};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Instant, SystemTime};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerMigrationOutcome {
    Migrated,
    AlreadyPeer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IamConfig {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub users: Vec<IamUser>,
}

fn default_version() -> u32 {
    2
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IamUser {
    pub user_id: String,
    pub display_name: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub access_keys: Vec<AccessKey>,
    #[serde(default)]
    pub policies: Vec<IamPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_site_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawIamConfig {
    #[serde(default)]
    pub users: Vec<RawIamUser>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawIamUser {
    pub user_id: Option<String>,
    pub display_name: Option<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub expires_at: Option<String>,
    pub access_key: Option<String>,
    pub secret_key: Option<String>,
    #[serde(default)]
    pub access_keys: Vec<AccessKey>,
    #[serde(default)]
    pub policies: Vec<IamPolicy>,
    #[serde(default)]
    pub peer_site_id: Option<String>,
}

impl RawIamUser {
    fn normalize(self) -> IamUser {
        let mut access_keys = self.access_keys;
        if access_keys.is_empty() {
            if let (Some(ak), Some(sk)) = (self.access_key, self.secret_key) {
                access_keys.push(AccessKey {
                    access_key: ak,
                    secret_key: sk,
                    status: "active".to_string(),
                    created_at: None,
                });
            }
        }
        let display_name = self.display_name.unwrap_or_else(|| {
            access_keys
                .first()
                .map(|k| k.access_key.clone())
                .unwrap_or_else(|| "unknown".to_string())
        });
        let user_id = self.user_id.unwrap_or_else(|| {
            format!("u-{}", display_name.to_ascii_lowercase().replace(' ', "-"))
        });
        let policies = self
            .policies
            .into_iter()
            .map(normalize_legacy_full_access)
            .collect();
        IamUser {
            user_id,
            display_name,
            enabled: self.enabled,
            expires_at: self.expires_at,
            access_keys,
            policies,
            peer_site_id: self.peer_site_id,
        }
    }
}

const LEGACY_FULL_ACCESS_ACTIONS: &[&str] = &[
    "list",
    "read",
    "write",
    "delete",
    "share",
    "policy",
    "create_bucket",
    "delete_bucket",
    "replication",
    "lifecycle",
    "cors",
    "versioning",
    "tagging",
    "encryption",
    "quota",
    "object_lock",
    "notification",
    "logging",
    "website",
];

fn normalize_legacy_full_access(policy: IamPolicy) -> IamPolicy {
    if policy.bucket != "*"
        || policy.prefix != "*"
        || policy.actions.iter().any(|a| a == "*")
    {
        return policy;
    }
    if !policy.actions.iter().any(|a| a == "iam:*") {
        return policy;
    }
    for required in LEGACY_FULL_ACCESS_ACTIONS {
        if !policy.actions.iter().any(|a| a == *required) {
            return policy;
        }
    }
    IamPolicy {
        bucket: policy.bucket,
        prefix: policy.prefix,
        actions: vec!["*".to_string()],
    }
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessKey {
    pub access_key: String,
    pub secret_key: String,
    #[serde(default = "default_status")]
    pub status: String,
    #[serde(default)]
    pub created_at: Option<String>,
}

fn default_status() -> String {
    "active".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IamPolicy {
    pub bucket: String,
    pub actions: Vec<String>,
    #[serde(default = "default_prefix")]
    pub prefix: String,
}

fn default_prefix() -> String {
    "*".to_string()
}

struct IamState {
    key_secrets: HashMap<String, String>,
    key_index: HashMap<String, String>,
    key_status: HashMap<String, String>,
    user_records: HashMap<String, IamUser>,
    file_mtime: Option<SystemTime>,
    last_check: Instant,
}

pub struct IamService {
    config_path: PathBuf,
    state: Arc<RwLock<IamState>>,
    check_interval: std::time::Duration,
    fernet_key: Option<String>,
}

impl IamService {
    pub fn new(config_path: PathBuf) -> Self {
        Self::new_with_secret(config_path, None)
    }

    pub fn new_with_secret(config_path: PathBuf, secret_key: Option<String>) -> Self {
        let fernet_key = secret_key.map(|s| crate::fernet::derive_fernet_key(&s));
        let service = Self {
            config_path,
            state: Arc::new(RwLock::new(IamState {
                key_secrets: HashMap::new(),
                key_index: HashMap::new(),
                key_status: HashMap::new(),
                user_records: HashMap::new(),
                file_mtime: None,
                last_check: Instant::now(),
            })),
            check_interval: std::time::Duration::from_secs(2),
            fernet_key,
        };
        service.reload();
        service
    }

    fn reload_if_needed(&self) {
        {
            let state = self.state.read();
            if state.last_check.elapsed() < self.check_interval {
                return;
            }
        }

        let current_mtime = std::fs::metadata(&self.config_path)
            .and_then(|m| m.modified())
            .ok();

        let needs_reload = {
            let state = self.state.read();
            match (&state.file_mtime, &current_mtime) {
                (None, Some(_)) => true,
                (Some(old), Some(new)) => old != new,
                (Some(_), None) => true,
                (None, None) => false,
            }
        };

        if needs_reload {
            self.reload();
        }

        self.state.write().last_check = Instant::now();
    }

    fn reload(&self) {
        let content = match std::fs::read_to_string(&self.config_path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    "Failed to read IAM config {}: {}",
                    self.config_path.display(),
                    e
                );
                return;
            }
        };

        let raw = if let Some(encrypted_token) = content.strip_prefix("MYFSIO_IAM_ENC:") {
            match &self.fernet_key {
                Some(key) => match crate::fernet::decrypt(key, encrypted_token.trim()) {
                    Ok(plaintext) => match String::from_utf8(plaintext) {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::error!("Decrypted IAM config is not valid UTF-8: {}", e);
                            return;
                        }
                    },
                    Err(e) => {
                        tracing::error!(
                            "Failed to decrypt IAM config: {}. SECRET_KEY may have changed.",
                            e
                        );
                        return;
                    }
                },
                None => {
                    tracing::error!("IAM config is encrypted but no SECRET_KEY configured");
                    return;
                }
            }
        } else {
            content
        };

        let raw_config: RawIamConfig = match serde_json::from_str(&raw) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to parse IAM config: {}", e);
                return;
            }
        };

        let users: Vec<IamUser> = raw_config
            .users
            .into_iter()
            .map(|u| u.normalize())
            .collect();

        let mut key_secrets = HashMap::new();
        let mut key_index = HashMap::new();
        let mut key_status = HashMap::new();
        let mut user_records = HashMap::new();

        for user in &users {
            user_records.insert(user.user_id.clone(), user.clone());
            for ak in &user.access_keys {
                key_secrets.insert(ak.access_key.clone(), ak.secret_key.clone());
                key_index.insert(ak.access_key.clone(), user.user_id.clone());
                key_status.insert(ak.access_key.clone(), ak.status.clone());
            }
        }

        let file_mtime = std::fs::metadata(&self.config_path)
            .and_then(|m| m.modified())
            .ok();

        let mut state = self.state.write();
        state.key_secrets = key_secrets;
        state.key_index = key_index;
        state.key_status = key_status;
        state.user_records = user_records;
        state.file_mtime = file_mtime;
        state.last_check = Instant::now();

        tracing::info!(
            "IAM config reloaded: {} users, {} keys",
            users.len(),
            state.key_secrets.len()
        );
    }

    pub fn get_secret_key(&self, access_key: &str) -> Option<String> {
        self.reload_if_needed();
        let state = self.state.read();

        let status = state.key_status.get(access_key)?;
        if status != "active" {
            return None;
        }

        let user_id = state.key_index.get(access_key)?;
        let user = state.user_records.get(user_id)?;
        if !user.enabled {
            return None;
        }

        if let Some(ref expires_at) = user.expires_at {
            if let Ok(exp) = expires_at.parse::<DateTime<Utc>>() {
                if Utc::now() > exp {
                    return None;
                }
            }
        }

        state.key_secrets.get(access_key).cloned()
    }

    pub fn get_principal(&self, access_key: &str) -> Option<Principal> {
        self.reload_if_needed();
        let state = self.state.read();

        let status = state.key_status.get(access_key)?;
        if status != "active" {
            return None;
        }

        let user_id = state.key_index.get(access_key)?;
        let user = state.user_records.get(user_id)?;
        if !user.enabled {
            return None;
        }

        if let Some(ref expires_at) = user.expires_at {
            if let Ok(exp) = expires_at.parse::<DateTime<Utc>>() {
                if Utc::now() > exp {
                    return None;
                }
            }
        }

        if let Some(site_id) = user.peer_site_id.as_deref() {
            return Some(Principal::peer(
                access_key.to_string(),
                user.user_id.clone(),
                user.display_name.clone(),
                site_id.to_string(),
            ));
        }

        let is_admin = user
            .policies
            .iter()
            .any(|p| p.bucket == "*" && p.actions.iter().any(|a| a == "*"));

        Some(Principal {
            access_key: access_key.to_string(),
            user_id: user.user_id.clone(),
            display_name: user.display_name.clone(),
            is_admin,
            kind: PrincipalKind::User,
        })
    }

    pub fn is_peer_credential(&self, access_key: &str) -> bool {
        self.reload_if_needed();
        let state = self.state.read();
        state
            .key_index
            .get(access_key)
            .and_then(|uid| state.user_records.get(uid))
            .and_then(|user| user.peer_site_id.as_deref())
            .is_some()
    }

    pub fn create_peer_credential(
        &self,
        site_id: &str,
        display_name: Option<&str>,
    ) -> Result<serde_json::Value, String> {
        let mut config = self.load_config()?;
        let new_ak = format!("PEERAK{}", uuid::Uuid::new_v4().simple());
        let new_sk = format!("PEERSK{}", uuid::Uuid::new_v4().simple());
        let user_id = format!("peer-{}", uuid::Uuid::new_v4().simple());
        let display = display_name
            .map(str::to_string)
            .unwrap_or_else(|| format!("peer:{}", site_id));

        let user = IamUser {
            user_id: user_id.clone(),
            display_name: display,
            enabled: true,
            expires_at: None,
            access_keys: vec![AccessKey {
                access_key: new_ak.clone(),
                secret_key: new_sk.clone(),
                status: "active".to_string(),
                created_at: Some(chrono::Utc::now().to_rfc3339()),
            }],
            policies: Vec::new(),
            peer_site_id: Some(site_id.to_string()),
        };
        config.users.push(user);
        self.save_config(&config)?;
        Ok(serde_json::json!({
            "user_id": user_id,
            "access_key": new_ak,
            "secret_key": new_sk,
            "site_id": site_id,
        }))
    }

    pub fn list_peer_credentials(&self) -> Vec<serde_json::Value> {
        self.reload_if_needed();
        let state = self.state.read();
        state
            .user_records
            .values()
            .filter(|u| u.peer_site_id.is_some())
            .map(|u| {
                serde_json::json!({
                    "user_id": u.user_id,
                    "site_id": u.peer_site_id.clone(),
                    "display_name": u.display_name,
                    "enabled": u.enabled,
                    "access_keys": u.access_keys.iter().map(|k| serde_json::json!({
                        "access_key": k.access_key,
                        "status": k.status,
                        "created_at": k.created_at,
                    })).collect::<Vec<_>>(),
                })
            })
            .collect()
    }

    pub fn mark_access_key_as_peer(
        &self,
        access_key: &str,
        site_id: &str,
    ) -> Result<PeerMigrationOutcome, String> {
        let mut config = self.load_config()?;
        for user in &mut config.users {
            if user.access_keys.iter().any(|k| k.access_key == access_key) {
                if let Some(existing_site) = user.peer_site_id.as_deref() {
                    if existing_site == site_id {
                        return Ok(PeerMigrationOutcome::AlreadyPeer);
                    }
                    return Err(format!(
                        "Access key '{}' is already a peer credential for site '{}'; refusing to retag for '{}'",
                        access_key, existing_site, site_id
                    ));
                }
                if user.access_keys.len() > 1 {
                    let others: Vec<String> = user
                        .access_keys
                        .iter()
                        .map(|k| k.access_key.clone())
                        .filter(|k| k != access_key)
                        .collect();
                    return Err(format!(
                        "Access key '{}' shares user '{}' with {} other access key(s) ({}). \
                         Migrating would clear that user's policies and convert all of its keys to peer credentials. \
                         Move this access key to a dedicated user (or delete the other keys) before running --migrate-peer-creds.",
                        access_key,
                        user.user_id,
                        others.len(),
                        others.join(", ")
                    ));
                }
                user.peer_site_id = Some(site_id.to_string());
                user.policies.clear();
                self.save_config(&config)?;
                return Ok(PeerMigrationOutcome::Migrated);
            }
        }
        Err(format!(
            "Access key '{}' not found in IAM config",
            access_key
        ))
    }

    pub fn authenticate(&self, access_key: &str, secret_key: &str) -> Option<Principal> {
        let stored_secret = self.get_secret_key(access_key)?;
        if !crate::sigv4::constant_time_compare(&stored_secret, secret_key) {
            return None;
        }
        self.get_principal(access_key)
    }

    pub fn authorize(
        &self,
        principal: &Principal,
        bucket_name: Option<&str>,
        action: &str,
        object_key: Option<&str>,
    ) -> bool {
        self.reload_if_needed();

        if principal.is_admin {
            return true;
        }

        let normalized_bucket = bucket_name.unwrap_or("*").trim().to_ascii_lowercase();
        let normalized_action = action.trim().to_ascii_lowercase();

        let state = self.state.read();
        let user = match state.user_records.get(&principal.user_id) {
            Some(u) => u,
            None => return false,
        };

        if !user.enabled {
            return false;
        }

        if let Some(ref expires_at) = user.expires_at {
            if let Ok(exp) = expires_at.parse::<DateTime<Utc>>() {
                if Utc::now() > exp {
                    return false;
                }
            }
        }

        for policy in &user.policies {
            if !bucket_matches(&policy.bucket, &normalized_bucket) {
                continue;
            }
            if !action_matches(&policy.actions, &normalized_action) {
                continue;
            }
            if let Some(key) = object_key {
                if !prefix_matches(&policy.prefix, key) {
                    continue;
                }
            }
            return true;
        }

        false
    }

    pub fn export_config(&self, mask_secrets: bool) -> serde_json::Value {
        self.reload_if_needed();
        let state = self.state.read();
        let users: Vec<serde_json::Value> = state
            .user_records
            .values()
            .map(|u| {
                let access_keys: Vec<serde_json::Value> = u
                    .access_keys
                    .iter()
                    .map(|k| {
                        let secret = if mask_secrets {
                            "***".to_string()
                        } else {
                            k.secret_key.clone()
                        };
                        serde_json::json!({
                            "access_key": k.access_key,
                            "secret_key": secret,
                            "status": k.status,
                            "created_at": k.created_at,
                        })
                    })
                    .collect();
                serde_json::json!({
                    "user_id": u.user_id,
                    "display_name": u.display_name,
                    "enabled": u.enabled,
                    "expires_at": u.expires_at,
                    "access_keys": access_keys,
                    "policies": u.policies,
                })
            })
            .collect();
        serde_json::json!({
            "version": 2,
            "users": users,
        })
    }

    pub async fn list_users(&self) -> Vec<serde_json::Value> {
        self.reload_if_needed();
        let state = self.state.read();
        state
            .user_records
            .values()
            .filter(|u| u.peer_site_id.is_none())
            .map(|u| {
                serde_json::json!({
                    "user_id": u.user_id,
                    "display_name": u.display_name,
                    "enabled": u.enabled,
                    "access_keys": u.access_keys.iter().map(|k| {
                        serde_json::json!({
                            "access_key": k.access_key,
                            "status": k.status,
                            "created_at": k.created_at,
                        })
                    }).collect::<Vec<_>>(),
                    "policy_count": u.policies.len(),
                })
            })
            .collect()
    }

    pub async fn get_user(&self, identifier: &str) -> Option<serde_json::Value> {
        self.reload_if_needed();
        let state = self.state.read();

        let user = state.user_records.get(identifier).or_else(|| {
            state
                .key_index
                .get(identifier)
                .and_then(|uid| state.user_records.get(uid))
        })?;
        if user.peer_site_id.is_some() {
            return None;
        }

        Some(serde_json::json!({
            "user_id": user.user_id,
            "display_name": user.display_name,
            "enabled": user.enabled,
            "expires_at": user.expires_at,
            "access_keys": user.access_keys.iter().map(|k| {
                serde_json::json!({
                    "access_key": k.access_key,
                    "status": k.status,
                    "created_at": k.created_at,
                })
            }).collect::<Vec<_>>(),
            "policies": user.policies,
        }))
    }

    pub async fn set_user_enabled(&self, identifier: &str, enabled: bool) -> Result<(), String> {
        let content = std::fs::read_to_string(&self.config_path)
            .map_err(|e| format!("Failed to read IAM config: {}", e))?;

        let raw: RawIamConfig = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse IAM config: {}", e))?;
        let mut config = IamConfig {
            version: 2,
            users: raw.users.into_iter().map(|u| u.normalize()).collect(),
        };

        let user = config
            .users
            .iter_mut()
            .find(|u| {
                u.user_id == identifier || u.access_keys.iter().any(|k| k.access_key == identifier)
            })
            .ok_or_else(|| "User not found".to_string())?;
        if user.peer_site_id.is_some() {
            return Err("Peer credentials cannot be modified via user-management".to_string());
        }

        user.enabled = enabled;

        let json = serde_json::to_string_pretty(&config)
            .map_err(|e| format!("Failed to serialize IAM config: {}", e))?;
        std::fs::write(&self.config_path, json)
            .map_err(|e| format!("Failed to write IAM config: {}", e))?;

        self.reload();
        Ok(())
    }

    pub fn get_display_name(&self, identifier: &str) -> Option<String> {
        self.reload_if_needed();
        let state = self.state.read();
        let user = state.user_records.get(identifier).or_else(|| {
            state
                .key_index
                .get(identifier)
                .and_then(|uid| state.user_records.get(uid))
        })?;
        Some(user.display_name.clone())
    }

    pub fn get_user_policies(&self, identifier: &str) -> Option<Vec<serde_json::Value>> {
        self.reload_if_needed();
        let state = self.state.read();
        let user = state.user_records.get(identifier).or_else(|| {
            state
                .key_index
                .get(identifier)
                .and_then(|uid| state.user_records.get(uid))
        })?;
        Some(
            user.policies
                .iter()
                .map(|p| serde_json::to_value(p).unwrap_or_default())
                .collect(),
        )
    }

    pub fn create_access_key(&self, identifier: &str) -> Result<serde_json::Value, String> {
        let content = std::fs::read_to_string(&self.config_path)
            .map_err(|e| format!("Failed to read IAM config: {}", e))?;
        let raw: RawIamConfig = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse IAM config: {}", e))?;
        let mut config = IamConfig {
            version: 2,
            users: raw.users.into_iter().map(|u| u.normalize()).collect(),
        };

        let user = config
            .users
            .iter_mut()
            .find(|u| {
                u.user_id == identifier || u.access_keys.iter().any(|k| k.access_key == identifier)
            })
            .ok_or_else(|| format!("User '{}' not found", identifier))?;
        if user.peer_site_id.is_some() {
            return Err("Peer credentials cannot be modified via user-management".to_string());
        }

        let new_ak = format!("AK{}", uuid::Uuid::new_v4().simple());
        let new_sk = format!("SK{}", uuid::Uuid::new_v4().simple());

        let key = AccessKey {
            access_key: new_ak.clone(),
            secret_key: new_sk.clone(),
            status: "active".to_string(),
            created_at: Some(chrono::Utc::now().to_rfc3339()),
        };
        user.access_keys.push(key);

        let json = serde_json::to_string_pretty(&config)
            .map_err(|e| format!("Failed to serialize IAM config: {}", e))?;
        std::fs::write(&self.config_path, json)
            .map_err(|e| format!("Failed to write IAM config: {}", e))?;

        self.reload();
        Ok(serde_json::json!({
            "access_key": new_ak,
            "secret_key": new_sk,
        }))
    }

    pub fn delete_access_key(&self, access_key: &str) -> Result<(), String> {
        let content = std::fs::read_to_string(&self.config_path)
            .map_err(|e| format!("Failed to read IAM config: {}", e))?;
        let raw: RawIamConfig = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse IAM config: {}", e))?;
        let mut config = IamConfig {
            version: 2,
            users: raw.users.into_iter().map(|u| u.normalize()).collect(),
        };

        let mut found = false;
        for user in &mut config.users {
            if user.access_keys.iter().any(|k| k.access_key == access_key) {
                if user.peer_site_id.is_some() {
                    return Err(
                        "Peer credentials cannot be modified via user-management".to_string(),
                    );
                }
                if user.access_keys.len() <= 1 {
                    return Err("Cannot delete the last access key".to_string());
                }
                user.access_keys.retain(|k| k.access_key != access_key);
                found = true;
                break;
            }
        }
        if !found {
            return Err(format!("Access key '{}' not found", access_key));
        }

        let json = serde_json::to_string_pretty(&config)
            .map_err(|e| format!("Failed to serialize IAM config: {}", e))?;
        std::fs::write(&self.config_path, json)
            .map_err(|e| format!("Failed to write IAM config: {}", e))?;

        self.reload();
        Ok(())
    }

    fn load_config(&self) -> Result<IamConfig, String> {
        let content = std::fs::read_to_string(&self.config_path)
            .map_err(|e| format!("Failed to read IAM config: {}", e))?;
        let raw_text = if let Some(encrypted_token) = content.strip_prefix("MYFSIO_IAM_ENC:") {
            let key = self.fernet_key.as_ref().ok_or_else(|| {
                "IAM config is encrypted but no SECRET_KEY configured".to_string()
            })?;
            let plaintext = crate::fernet::decrypt(key, encrypted_token.trim())
                .map_err(|e| format!("Failed to decrypt IAM config: {}", e))?;
            String::from_utf8(plaintext)
                .map_err(|e| format!("Decrypted IAM config not UTF-8: {}", e))?
        } else {
            content
        };
        let raw: RawIamConfig = serde_json::from_str(&raw_text)
            .map_err(|e| format!("Failed to parse IAM config: {}", e))?;
        Ok(IamConfig {
            version: 2,
            users: raw.users.into_iter().map(|u| u.normalize()).collect(),
        })
    }

    fn save_config(&self, config: &IamConfig) -> Result<(), String> {
        let json = serde_json::to_string_pretty(config)
            .map_err(|e| format!("Failed to serialize IAM config: {}", e))?;
        let payload = if let Some(key) = &self.fernet_key {
            let token = crate::fernet::encrypt(key, json.as_bytes())
                .map_err(|e| format!("Failed to encrypt IAM config: {}", e))?;
            format!("MYFSIO_IAM_ENC:{}", token)
        } else {
            json
        };
        std::fs::write(&self.config_path, payload)
            .map_err(|e| format!("Failed to write IAM config: {}", e))?;
        self.reload();
        Ok(())
    }

    pub fn create_user(
        &self,
        display_name: &str,
        policies: Option<Vec<IamPolicy>>,
        access_key: Option<String>,
        secret_key: Option<String>,
        expires_at: Option<String>,
    ) -> Result<serde_json::Value, String> {
        let mut config = self.load_config()?;

        let new_ak = access_key
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| format!("AK{}", uuid::Uuid::new_v4().simple()));
        let new_sk = secret_key
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| format!("SK{}", uuid::Uuid::new_v4().simple()));

        if config
            .users
            .iter()
            .any(|u| u.access_keys.iter().any(|k| k.access_key == new_ak))
        {
            return Err(format!("Access key '{}' already exists", new_ak));
        }

        let user_id = format!("u-{}", uuid::Uuid::new_v4().simple());
        let resolved_policies = policies.unwrap_or_default();

        let user = IamUser {
            user_id: user_id.clone(),
            display_name: display_name.to_string(),
            enabled: true,
            expires_at,
            access_keys: vec![AccessKey {
                access_key: new_ak.clone(),
                secret_key: new_sk.clone(),
                status: "active".to_string(),
                created_at: Some(chrono::Utc::now().to_rfc3339()),
            }],
            policies: resolved_policies,
            peer_site_id: None,
        };
        config.users.push(user);

        self.save_config(&config)?;
        Ok(serde_json::json!({
            "user_id": user_id,
            "access_key": new_ak,
            "secret_key": new_sk,
            "display_name": display_name,
        }))
    }

    pub fn delete_user(&self, identifier: &str) -> Result<(), String> {
        let mut config = self.load_config()?;
        if config.users.iter().any(|u| {
            (u.user_id == identifier || u.access_keys.iter().any(|k| k.access_key == identifier))
                && u.peer_site_id.is_some()
        }) {
            return Err("Peer credentials cannot be modified via user-management".to_string());
        }
        let before = config.users.len();
        config.users.retain(|u| {
            u.user_id != identifier && !u.access_keys.iter().any(|k| k.access_key == identifier)
        });
        if config.users.len() == before {
            return Err(format!("User '{}' not found", identifier));
        }
        self.save_config(&config)
    }

    pub fn delete_peer_credential(&self, access_key: &str) -> Result<(), String> {
        let mut config = self.load_config()?;
        let before = config.users.len();
        config.users.retain(|u| {
            !(u.peer_site_id.is_some()
                && u.access_keys.iter().any(|k| k.access_key == access_key))
        });
        if config.users.len() == before {
            return Err(format!("Peer credential '{}' not found", access_key));
        }
        self.save_config(&config)
    }

    pub fn update_user(
        &self,
        identifier: &str,
        display_name: Option<String>,
        expires_at: Option<Option<String>>,
    ) -> Result<(), String> {
        let mut config = self.load_config()?;
        let user = config
            .users
            .iter_mut()
            .find(|u| {
                u.user_id == identifier || u.access_keys.iter().any(|k| k.access_key == identifier)
            })
            .ok_or_else(|| format!("User '{}' not found", identifier))?;
        if user.peer_site_id.is_some() {
            return Err("Peer credentials cannot be modified via user-management".to_string());
        }
        if let Some(name) = display_name {
            user.display_name = name;
        }
        if let Some(exp) = expires_at {
            user.expires_at = exp;
        }
        self.save_config(&config)
    }

    pub fn update_user_policies(
        &self,
        identifier: &str,
        policies: Vec<IamPolicy>,
    ) -> Result<(), String> {
        let mut config = self.load_config()?;
        let user = config
            .users
            .iter_mut()
            .find(|u| {
                u.user_id == identifier || u.access_keys.iter().any(|k| k.access_key == identifier)
            })
            .ok_or_else(|| format!("User '{}' not found", identifier))?;
        if user.peer_site_id.is_some() {
            return Err("Peer credentials cannot be modified via user-management".to_string());
        }
        user.policies = policies;
        self.save_config(&config)
    }

    pub fn rotate_secret(&self, identifier: &str) -> Result<serde_json::Value, String> {
        let mut config = self.load_config()?;
        let user = config
            .users
            .iter_mut()
            .find(|u| {
                u.user_id == identifier || u.access_keys.iter().any(|k| k.access_key == identifier)
            })
            .ok_or_else(|| format!("User '{}' not found", identifier))?;
        if user.peer_site_id.is_some() {
            return Err("Peer credentials cannot be modified via user-management".to_string());
        }
        let key = user
            .access_keys
            .first_mut()
            .ok_or_else(|| "User has no access keys".to_string())?;
        let new_sk = format!("SK{}", uuid::Uuid::new_v4().simple());
        key.secret_key = new_sk.clone();
        let ak = key.access_key.clone();
        self.save_config(&config)?;
        Ok(serde_json::json!({
            "access_key": ak,
            "secret_key": new_sk,
        }))
    }
}

fn bucket_matches(policy_bucket: &str, bucket: &str) -> bool {
    let pb = policy_bucket.trim().to_ascii_lowercase();
    pb == "*" || pb == bucket
}

fn action_matches(policy_actions: &[String], action: &str) -> bool {
    for policy_action in policy_actions {
        let pa = policy_action.trim().to_ascii_lowercase();
        if pa == "*" || pa == action {
            return true;
        }
        if pa == "iam:*" && action.starts_with("iam:") {
            return true;
        }
    }
    false
}

fn prefix_matches(policy_prefix: &str, object_key: &str) -> bool {
    let p = policy_prefix.trim();
    if p.is_empty() || p == "*" {
        return true;
    }
    let base = p.trim_end_matches('*');
    object_key.starts_with(base)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn test_iam_json() -> String {
        serde_json::json!({
            "version": 2,
            "users": [{
                "user_id": "u-test1234",
                "display_name": "admin",
                "enabled": true,
                "access_keys": [{
                    "access_key": "AKIAIOSFODNN7EXAMPLE",
                    "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    "status": "active",
                    "created_at": "2024-01-01T00:00:00Z"
                }],
                "policies": [{
                    "bucket": "*",
                    "actions": ["*"],
                    "prefix": "*"
                }]
            }]
        })
        .to_string()
    }

    #[test]
    fn test_load_and_lookup() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(test_iam_json().as_bytes()).unwrap();
        tmp.flush().unwrap();

        let svc = IamService::new(tmp.path().to_path_buf());
        let secret = svc.get_secret_key("AKIAIOSFODNN7EXAMPLE");
        assert_eq!(secret.unwrap(), "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    }

    #[test]
    fn test_get_principal() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(test_iam_json().as_bytes()).unwrap();
        tmp.flush().unwrap();

        let svc = IamService::new(tmp.path().to_path_buf());
        let principal = svc.get_principal("AKIAIOSFODNN7EXAMPLE").unwrap();
        assert_eq!(principal.display_name, "admin");
        assert_eq!(principal.user_id, "u-test1234");
        assert!(principal.is_admin);
    }

    #[test]
    fn test_authenticate_success() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(test_iam_json().as_bytes()).unwrap();
        tmp.flush().unwrap();

        let svc = IamService::new(tmp.path().to_path_buf());
        let principal = svc
            .authenticate(
                "AKIAIOSFODNN7EXAMPLE",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            )
            .unwrap();
        assert_eq!(principal.display_name, "admin");
    }

    #[test]
    fn test_authenticate_wrong_secret() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(test_iam_json().as_bytes()).unwrap();
        tmp.flush().unwrap();

        let svc = IamService::new(tmp.path().to_path_buf());
        assert!(svc
            .authenticate("AKIAIOSFODNN7EXAMPLE", "wrongsecret")
            .is_none());
    }

    #[test]
    fn test_unknown_key_returns_none() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(test_iam_json().as_bytes()).unwrap();
        tmp.flush().unwrap();

        let svc = IamService::new(tmp.path().to_path_buf());
        assert!(svc.get_secret_key("NONEXISTENTKEY").is_none());
        assert!(svc.get_principal("NONEXISTENTKEY").is_none());
    }

    #[test]
    fn test_disabled_user() {
        let json = serde_json::json!({
            "version": 2,
            "users": [{
                "user_id": "u-disabled",
                "display_name": "disabled-user",
                "enabled": false,
                "access_keys": [{
                    "access_key": "DISABLED_KEY",
                    "secret_key": "secret123",
                    "status": "active"
                }],
                "policies": []
            }]
        })
        .to_string();

        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(json.as_bytes()).unwrap();
        tmp.flush().unwrap();

        let svc = IamService::new(tmp.path().to_path_buf());
        assert!(svc.get_secret_key("DISABLED_KEY").is_none());
    }

    #[test]
    fn test_inactive_key() {
        let json = serde_json::json!({
            "version": 2,
            "users": [{
                "user_id": "u-test",
                "display_name": "test",
                "enabled": true,
                "access_keys": [{
                    "access_key": "INACTIVE_KEY",
                    "secret_key": "secret123",
                    "status": "inactive"
                }],
                "policies": []
            }]
        })
        .to_string();

        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(json.as_bytes()).unwrap();
        tmp.flush().unwrap();

        let svc = IamService::new(tmp.path().to_path_buf());
        assert!(svc.get_secret_key("INACTIVE_KEY").is_none());
    }

    #[test]
    fn test_v1_flat_format() {
        let json = serde_json::json!({
            "users": [{
                "access_key": "test",
                "secret_key": "secret",
                "display_name": "Test User",
                "policies": [{"bucket": "*", "actions": ["*"], "prefix": "*"}]
            }]
        })
        .to_string();

        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(json.as_bytes()).unwrap();
        tmp.flush().unwrap();

        let svc = IamService::new(tmp.path().to_path_buf());
        let secret = svc.get_secret_key("test");
        assert_eq!(secret.unwrap(), "secret");

        let principal = svc.get_principal("test").unwrap();
        assert_eq!(principal.display_name, "Test User");
        assert!(principal.is_admin);
    }

    #[test]
    fn test_authorize_allows_matching_policy() {
        let json = serde_json::json!({
            "version": 2,
            "users": [{
                "user_id": "u-reader",
                "display_name": "reader",
                "enabled": true,
                "access_keys": [{
                    "access_key": "READER_KEY",
                    "secret_key": "reader-secret",
                    "status": "active"
                }],
                "policies": [{
                    "bucket": "docs",
                    "actions": ["read"],
                    "prefix": "reports/"
                }]
            }]
        })
        .to_string();

        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(json.as_bytes()).unwrap();
        tmp.flush().unwrap();

        let svc = IamService::new(tmp.path().to_path_buf());
        let principal = svc.get_principal("READER_KEY").unwrap();

        assert!(svc.authorize(&principal, Some("docs"), "read", Some("reports/2026.csv"),));
        assert!(!svc.authorize(&principal, Some("docs"), "write", Some("reports/2026.csv"),));
        assert!(!svc.authorize(&principal, Some("docs"), "read", Some("private/2026.csv"),));
        assert!(!svc.authorize(&principal, Some("other"), "read", Some("reports/2026.csv"),));
    }
}
