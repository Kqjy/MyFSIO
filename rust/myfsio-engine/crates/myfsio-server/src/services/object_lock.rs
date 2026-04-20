use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const LEGAL_HOLD_METADATA_KEY: &str = "__legal_hold__";
pub const RETENTION_METADATA_KEY: &str = "__object_retention__";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RetentionMode {
    GOVERNANCE,
    COMPLIANCE,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectLockRetention {
    pub mode: RetentionMode,
    pub retain_until_date: DateTime<Utc>,
}

impl ObjectLockRetention {
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.retain_until_date
    }
}

pub fn get_object_retention(metadata: &HashMap<String, String>) -> Option<ObjectLockRetention> {
    metadata
        .get(RETENTION_METADATA_KEY)
        .and_then(|raw| serde_json::from_str::<ObjectLockRetention>(raw).ok())
}

pub fn set_object_retention(
    metadata: &mut HashMap<String, String>,
    retention: &ObjectLockRetention,
) -> Result<(), String> {
    let encoded = serde_json::to_string(retention).map_err(|err| err.to_string())?;
    metadata.insert(RETENTION_METADATA_KEY.to_string(), encoded);
    Ok(())
}

pub fn get_legal_hold(metadata: &HashMap<String, String>) -> bool {
    metadata
        .get(LEGAL_HOLD_METADATA_KEY)
        .map(|value| value.eq_ignore_ascii_case("ON") || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

pub fn set_legal_hold(metadata: &mut HashMap<String, String>, enabled: bool) {
    metadata.insert(
        LEGAL_HOLD_METADATA_KEY.to_string(),
        if enabled { "ON" } else { "OFF" }.to_string(),
    );
}

pub fn ensure_retention_mutable(
    metadata: &HashMap<String, String>,
    bypass_governance: bool,
) -> Result<(), String> {
    let Some(existing) = get_object_retention(metadata) else {
        return Ok(());
    };
    if existing.is_expired() {
        return Ok(());
    }
    match existing.mode {
        RetentionMode::COMPLIANCE => Err(format!(
            "Cannot modify retention on object with COMPLIANCE mode until retention expires"
        )),
        RetentionMode::GOVERNANCE if !bypass_governance => Err(
            "Cannot modify GOVERNANCE retention without bypass-governance permission".to_string(),
        ),
        RetentionMode::GOVERNANCE => Ok(()),
    }
}

pub fn can_delete_object(
    metadata: &HashMap<String, String>,
    bypass_governance: bool,
) -> Result<(), String> {
    if get_legal_hold(metadata) {
        return Err("Object is under legal hold".to_string());
    }
    if let Some(retention) = get_object_retention(metadata) {
        if !retention.is_expired() {
            return match retention.mode {
                RetentionMode::COMPLIANCE => Err(format!(
                    "Object is locked in COMPLIANCE mode until {}",
                    retention.retain_until_date.to_rfc3339()
                )),
                RetentionMode::GOVERNANCE if !bypass_governance => Err(format!(
                    "Object is locked in GOVERNANCE mode until {}",
                    retention.retain_until_date.to_rfc3339()
                )),
                RetentionMode::GOVERNANCE => Ok(()),
            };
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn legal_hold_blocks_delete() {
        let mut metadata = HashMap::new();
        set_legal_hold(&mut metadata, true);
        let err = can_delete_object(&metadata, false).unwrap_err();
        assert!(err.contains("legal hold"));
    }

    #[test]
    fn governance_requires_bypass() {
        let mut metadata = HashMap::new();
        set_object_retention(
            &mut metadata,
            &ObjectLockRetention {
                mode: RetentionMode::GOVERNANCE,
                retain_until_date: Utc::now() + Duration::hours(1),
            },
        )
        .unwrap();
        assert!(can_delete_object(&metadata, false).is_err());
        assert!(can_delete_object(&metadata, true).is_ok());
    }
}
