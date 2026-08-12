use std::collections::HashMap;

use chrono::{DateTime, Duration, Months, Utc};
use myfsio_common::error::{S3Error, S3ErrorCode};
use myfsio_storage::traits::StorageEngine;

use crate::state::AppState;

pub use myfsio_common::object_lock::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultRetention {
    pub mode: RetentionMode,
    pub days: Option<u32>,
    pub years: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectLockConfiguration {
    pub enabled: bool,
    pub default_retention: Option<DefaultRetention>,
}

fn child_element<'a, 'input>(
    node: &roxmltree::Node<'a, 'input>,
    name: &str,
) -> Option<roxmltree::Node<'a, 'input>> {
    node.children()
        .find(|child| child.is_element() && child.tag_name().name() == name)
}

fn child_text(node: &roxmltree::Node<'_, '_>, name: &str) -> Option<String> {
    child_element(node, name)
        .and_then(|child| child.text())
        .map(|text| text.trim().to_string())
}

fn parse_positive_count(raw: &str, field: &str) -> Result<u32, S3Error> {
    match raw.parse::<u32>() {
        Ok(value) if value > 0 => Ok(value),
        _ => Err(S3Error::new(
            S3ErrorCode::InvalidArgument,
            format!("{} must be a positive integer", field),
        )),
    }
}

pub fn parse_object_lock_configuration(xml: &str) -> Result<ObjectLockConfiguration, S3Error> {
    let doc = roxmltree::Document::parse(xml)
        .map_err(|_| S3Error::from_code(S3ErrorCode::MalformedXML))?;
    let root = doc.root_element();
    if root.tag_name().name() != "ObjectLockConfiguration" {
        return Err(S3Error::new(
            S3ErrorCode::MalformedXML,
            "Expected an ObjectLockConfiguration document",
        ));
    }

    let Some(enabled) = child_text(&root, "ObjectLockEnabled") else {
        return Err(S3Error::new(
            S3ErrorCode::MalformedXML,
            "ObjectLockEnabled is required",
        ));
    };
    if enabled != "Enabled" {
        return Err(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "ObjectLockEnabled must be Enabled",
        ));
    }

    let Some(rule) = child_element(&root, "Rule") else {
        return Ok(ObjectLockConfiguration {
            enabled: true,
            default_retention: None,
        });
    };
    let Some(default_retention) = child_element(&rule, "DefaultRetention") else {
        return Ok(ObjectLockConfiguration {
            enabled: true,
            default_retention: None,
        });
    };

    let mode = match child_text(&default_retention, "Mode")
        .unwrap_or_default()
        .as_str()
    {
        "GOVERNANCE" => RetentionMode::GOVERNANCE,
        "COMPLIANCE" => RetentionMode::COMPLIANCE,
        other => {
            return Err(S3Error::new(
                S3ErrorCode::InvalidArgument,
                format!("Invalid default retention mode: {}", other),
            ))
        }
    };

    let days = child_text(&default_retention, "Days");
    let years = child_text(&default_retention, "Years");
    let (days, years) = match (days, years) {
        (Some(days), None) => (Some(parse_positive_count(&days, "Days")?), None),
        (None, Some(years)) => (None, Some(parse_positive_count(&years, "Years")?)),
        (Some(_), Some(_)) => {
            return Err(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "DefaultRetention accepts either Days or Years, not both",
            ))
        }
        (None, None) => {
            return Err(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "DefaultRetention requires either Days or Years",
            ))
        }
    };

    Ok(ObjectLockConfiguration {
        enabled: true,
        default_retention: Some(DefaultRetention { mode, days, years }),
    })
}

pub fn default_retain_until_date(retention: &DefaultRetention) -> Option<DateTime<Utc>> {
    let now = Utc::now();
    match (retention.days, retention.years) {
        (Some(days), None) => now.checked_add_signed(Duration::days(i64::from(days))),
        (None, Some(years)) => now.checked_add_months(Months::new(years.saturating_mul(12))),
        _ => None,
    }
}

pub async fn bucket_default_retention(
    state: &AppState,
    bucket: &str,
) -> Option<ObjectLockRetention> {
    let config = state.storage.get_bucket_config(bucket).await.ok()?;
    let raw = config.object_lock.as_ref()?;
    let xml = match raw {
        serde_json::Value::String(value) => value.clone(),
        other => other.to_string(),
    };
    let parsed = match parse_object_lock_configuration(&xml) {
        Ok(parsed) => parsed,
        Err(err) => {
            tracing::warn!(
                bucket = bucket,
                error = %err.message,
                "stored object lock configuration could not be parsed; default retention not applied"
            );
            return None;
        }
    };
    let default_retention = parsed.default_retention?;
    let retain_until_date = default_retain_until_date(&default_retention)?;
    Some(ObjectLockRetention {
        mode: default_retention.mode,
        retain_until_date,
    })
}

pub async fn apply_default_retention(
    state: &AppState,
    bucket: &str,
    metadata: &mut HashMap<String, String>,
) {
    if get_object_retention(metadata).is_some() {
        return;
    }
    let Some(retention) = bucket_default_retention(state, bucket).await else {
        return;
    };
    if let Err(err) = set_object_retention(metadata, &retention) {
        tracing::warn!(
            bucket = bucket,
            error = %err,
            "failed to apply the bucket default retention"
        );
    }
}

pub async fn apply_default_retention_to_stored(state: &AppState, bucket: &str, key: &str) {
    let Ok(metadata) = state.storage.get_object_metadata(bucket, key).await else {
        return;
    };
    if get_object_retention(&metadata).is_some() {
        return;
    }
    let Some(retention) = bucket_default_retention(state, bucket).await else {
        return;
    };
    match state
        .storage
        .update_object_retention(bucket, key, None, &retention, false)
        .await
    {
        Ok(()) | Err(myfsio_storage::error::StorageError::ObjectLocked(_)) => {}
        Err(err) => {
            tracing::warn!(
                bucket = bucket,
                key = key,
                error = %err,
                "failed to persist the bucket default retention"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_xml(inner: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <ObjectLockConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{}</ObjectLockConfiguration>",
            inner
        )
    }

    #[test]
    fn parses_enabled_configuration_without_rule() {
        let parsed = parse_object_lock_configuration(&config_xml(
            "<ObjectLockEnabled>Enabled</ObjectLockEnabled>",
        ))
        .unwrap();
        assert!(parsed.enabled);
        assert!(parsed.default_retention.is_none());
    }

    #[test]
    fn parses_default_retention_days() {
        let parsed = parse_object_lock_configuration(&config_xml(
            "<ObjectLockEnabled>Enabled</ObjectLockEnabled>\
             <Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Days>7</Days></DefaultRetention></Rule>",
        ))
        .unwrap();
        let default_retention = parsed.default_retention.unwrap();
        assert_eq!(default_retention.mode, RetentionMode::COMPLIANCE);
        assert_eq!(default_retention.days, Some(7));
        assert_eq!(default_retention.years, None);
    }

    #[test]
    fn rejects_malformed_document() {
        let err = parse_object_lock_configuration("<ObjectLockConfiguration>").unwrap_err();
        assert_eq!(err.code, S3ErrorCode::MalformedXML);
    }

    #[test]
    fn rejects_unexpected_root_element() {
        let err = parse_object_lock_configuration(
            "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
        )
        .unwrap_err();
        assert_eq!(err.code, S3ErrorCode::MalformedXML);
    }

    #[test]
    fn rejects_disabled_object_lock() {
        let err = parse_object_lock_configuration(&config_xml(
            "<ObjectLockEnabled>Disabled</ObjectLockEnabled>",
        ))
        .unwrap_err();
        assert_eq!(err.code, S3ErrorCode::InvalidArgument);
    }

    #[test]
    fn rejects_invalid_default_retention_values() {
        for inner in [
            "<ObjectLockEnabled>Enabled</ObjectLockEnabled>\
             <Rule><DefaultRetention><Mode>ARCHIVE</Mode><Days>1</Days></DefaultRetention></Rule>",
            "<ObjectLockEnabled>Enabled</ObjectLockEnabled>\
             <Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>1</Days><Years>1</Years></DefaultRetention></Rule>",
            "<ObjectLockEnabled>Enabled</ObjectLockEnabled>\
             <Rule><DefaultRetention><Mode>GOVERNANCE</Mode></DefaultRetention></Rule>",
            "<ObjectLockEnabled>Enabled</ObjectLockEnabled>\
             <Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>0</Days></DefaultRetention></Rule>",
            "<ObjectLockEnabled>Enabled</ObjectLockEnabled>\
             <Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>-1</Days></DefaultRetention></Rule>",
        ] {
            let err = parse_object_lock_configuration(&config_xml(inner)).unwrap_err();
            assert_eq!(
                err.code,
                S3ErrorCode::InvalidArgument,
                "expected InvalidArgument for {}",
                inner
            );
        }
    }

    #[test]
    fn default_retain_until_date_uses_days_and_years() {
        let days = default_retain_until_date(&DefaultRetention {
            mode: RetentionMode::GOVERNANCE,
            days: Some(1),
            years: None,
        })
        .unwrap();
        assert!(days > Utc::now() + Duration::hours(23));
        assert!(days < Utc::now() + Duration::hours(25));

        let years = default_retain_until_date(&DefaultRetention {
            mode: RetentionMode::GOVERNANCE,
            days: None,
            years: Some(1),
        })
        .unwrap();
        assert!(years > Utc::now() + Duration::days(364));
    }
}
