use chrono::{DateTime, Utc};
use myfsio_common::types::Principal;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Instant, SystemTime};

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
                (None, None) => state.key_secrets.is_empty(),
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
                tracing::warn!("Failed to read IAM config {}: {}", self.config_path.display(), e);
                return;
            }
        };

        let raw = if content.starts_with("MYFSIO_IAM_ENC:") {
            let encrypted_token = &content["MYFSIO_IAM_ENC:".len()..];
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
                        tracing::error!("Failed to decrypt IAM config: {}. SECRET_KEY may have changed.", e);
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

        let config: IamConfig = match serde_json::from_str(&raw) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to parse IAM config: {}", e);
                return;
            }
        };

        let mut key_secrets = HashMap::new();
        let mut key_index = HashMap::new();
        let mut key_status = HashMap::new();
        let mut user_records = HashMap::new();

        for user in &config.users {
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

        tracing::info!("IAM config reloaded: {} users, {} keys",
            config.users.len(),
            state.key_secrets.len());
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

        let is_admin = user.policies.iter().any(|p| {
            p.bucket == "*" && p.actions.iter().any(|a| a == "*")
        });

        Some(Principal::new(
            access_key.to_string(),
            user.user_id.clone(),
            user.display_name.clone(),
            is_admin,
        ))
    }

    pub fn authenticate(&self, access_key: &str, secret_key: &str) -> Option<Principal> {
        let stored_secret = self.get_secret_key(access_key)?;
        if !crate::sigv4::constant_time_compare(&stored_secret, secret_key) {
            return None;
        }
        self.get_principal(access_key)
    }

    pub async fn list_users(&self) -> Vec<serde_json::Value> {
        self.reload_if_needed();
        let state = self.state.read();
        state
            .user_records
            .values()
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

        let user = state
            .user_records
            .get(identifier)
            .or_else(|| {
                state.key_index.get(identifier).and_then(|uid| state.user_records.get(uid))
            })?;

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

        let mut config: IamConfig = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse IAM config: {}", e))?;

        let user = config
            .users
            .iter_mut()
            .find(|u| {
                u.user_id == identifier
                    || u.access_keys.iter().any(|k| k.access_key == identifier)
            })
            .ok_or_else(|| "User not found".to_string())?;

        user.enabled = enabled;

        let json = serde_json::to_string_pretty(&config)
            .map_err(|e| format!("Failed to serialize IAM config: {}", e))?;
        std::fs::write(&self.config_path, json)
            .map_err(|e| format!("Failed to write IAM config: {}", e))?;

        self.reload();
        Ok(())
    }
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
        assert_eq!(
            secret.unwrap(),
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        );
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
        assert!(svc.authenticate("AKIAIOSFODNN7EXAMPLE", "wrongsecret").is_none());
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
}
