use axum::body::Body;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};

use myfsio_common::error::{S3Error, S3ErrorCode};
use myfsio_storage::traits::StorageEngine;

use crate::services::acl::{
    acl_from_object_metadata, acl_from_xml_strict, acl_to_xml_with_lookup, create_canned_acl,
    store_object_acl,
};
use crate::services::notifications::parse_notification_configurations;
use crate::services::object_lock::{
    ensure_retention_mutable, get_legal_hold, get_object_retention as retention_from_metadata,
    set_legal_hold, set_object_retention as store_retention, ObjectLockRetention, RetentionMode,
};
use crate::state::AppState;

fn xml_response(status: StatusCode, xml: String) -> Response {
    (status, [("content-type", "application/xml")], xml).into_response()
}

fn stored_xml(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn storage_err(err: myfsio_storage::error::StorageError) -> Response {
    let s3err = S3Error::from(err);
    let status =
        StatusCode::from_u16(s3err.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (
        status,
        [("content-type", "application/xml")],
        s3err.to_xml(),
    )
        .into_response()
}

fn json_response(status: StatusCode, value: serde_json::Value) -> Response {
    (
        status,
        [("content-type", "application/json")],
        value.to_string(),
    )
        .into_response()
}

fn custom_xml_error(status: StatusCode, code: &str, message: &str) -> Response {
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <Error><Code>{}</Code><Message>{}</Message><Resource></Resource><RequestId></RequestId></Error>",
        xml_escape(code),
        xml_escape(message),
    );
    xml_response(status, xml)
}

pub async fn get_versioning(state: &AppState, bucket: &str) -> Response {
    match state.storage.get_versioning_status(bucket).await {
        Ok(status) => {
            let body = match status {
                myfsio_common::types::VersioningStatus::Enabled => {
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                    <VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                    <Status>Enabled</Status>\
                    </VersioningConfiguration>"
                        .to_string()
                }
                myfsio_common::types::VersioningStatus::Suspended => {
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                    <VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                    <Status>Suspended</Status>\
                    </VersioningConfiguration>"
                        .to_string()
                }
                myfsio_common::types::VersioningStatus::Disabled => {
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                    <VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                    </VersioningConfiguration>"
                        .to_string()
                }
            };
            xml_response(StatusCode::OK, body)
        }
        Err(e) => storage_err(e),
    }
}

pub async fn put_versioning(state: &AppState, bucket: &str, body: Body) -> Response {
    let body_bytes = match http_body_util::BodyExt::collect(body).await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return xml_response(
                StatusCode::BAD_REQUEST,
                S3Error::from_code(S3ErrorCode::MalformedXML).to_xml(),
            );
        }
    };

    let xml_str = String::from_utf8_lossy(&body_bytes);
    let doc = match roxmltree::Document::parse(&xml_str) {
        Ok(d) => d,
        Err(_) => {
            return xml_response(
                StatusCode::BAD_REQUEST,
                S3Error::from_code(S3ErrorCode::MalformedXML).to_xml(),
            );
        }
    };
    let root = doc.root_element();
    if root.tag_name().name() != "VersioningConfiguration" {
        return xml_response(
            StatusCode::BAD_REQUEST,
            S3Error::new(
                S3ErrorCode::MalformedXML,
                "Expected <VersioningConfiguration> root element",
            )
            .to_xml(),
        );
    }
    let status_text = root
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "Status")
        .and_then(|n| n.text())
        .map(|s| s.trim().to_string());
    let status = match status_text.as_deref() {
        Some("Enabled") => myfsio_common::types::VersioningStatus::Enabled,
        Some("Suspended") => myfsio_common::types::VersioningStatus::Suspended,
        _ => {
            return xml_response(
                StatusCode::BAD_REQUEST,
                S3Error::new(
                    S3ErrorCode::MalformedXML,
                    "VersioningConfiguration Status must be Enabled or Suspended",
                )
                .to_xml(),
            );
        }
    };

    match state.storage.set_versioning_status(bucket, status).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => storage_err(e),
    }
}

pub async fn get_tagging(state: &AppState, bucket: &str) -> Response {
    match state.storage.get_bucket_config(bucket).await {
        Ok(config) => {
            let mut xml = String::from(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                <Tagging xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><TagSet>",
            );
            for tag in &config.tags {
                xml.push_str(&format!(
                    "<Tag><Key>{}</Key><Value>{}</Value></Tag>",
                    tag.key, tag.value
                ));
            }
            xml.push_str("</TagSet></Tagging>");
            xml_response(StatusCode::OK, xml)
        }
        Err(e) => storage_err(e),
    }
}

pub async fn put_tagging(state: &AppState, bucket: &str, body: Body) -> Response {
    let body_bytes = match http_body_util::BodyExt::collect(body).await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return xml_response(
                StatusCode::BAD_REQUEST,
                S3Error::from_code(S3ErrorCode::MalformedXML).to_xml(),
            );
        }
    };

    let xml_str = String::from_utf8_lossy(&body_bytes);
    let tags = parse_tagging_xml(&xml_str);

    match state.storage.get_bucket_config(bucket).await {
        Ok(mut config) => {
            config.tags = tags;
            match state.storage.set_bucket_config(bucket, &config).await {
                Ok(()) => StatusCode::OK.into_response(),
                Err(e) => storage_err(e),
            }
        }
        Err(e) => storage_err(e),
    }
}

pub async fn delete_tagging(state: &AppState, bucket: &str) -> Response {
    match state.storage.get_bucket_config(bucket).await {
        Ok(mut config) => {
            config.tags.clear();
            match state.storage.set_bucket_config(bucket, &config).await {
                Ok(()) => StatusCode::NO_CONTENT.into_response(),
                Err(e) => storage_err(e),
            }
        }
        Err(e) => storage_err(e),
    }
}

pub async fn get_cors(state: &AppState, bucket: &str) -> Response {
    match state.storage.get_bucket_config(bucket).await {
        Ok(config) => {
            if let Some(cors) = &config.cors {
                xml_response(StatusCode::OK, stored_xml(cors))
            } else {
                xml_response(
                    StatusCode::NOT_FOUND,
                    S3Error::new(
                        S3ErrorCode::NoSuchCORSConfiguration,
                        "The CORS configuration does not exist",
                    )
                    .to_xml(),
                )
            }
        }
        Err(e) => storage_err(e),
    }
}

pub async fn put_cors(state: &AppState, bucket: &str, body: Body) -> Response {
    let body_bytes = match http_body_util::BodyExt::collect(body).await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let body_str = String::from_utf8_lossy(&body_bytes);
    let value = serde_json::Value::String(body_str.to_string());

    match state.storage.get_bucket_config(bucket).await {
        Ok(mut config) => {
            config.cors = Some(value);
            match state.storage.set_bucket_config(bucket, &config).await {
                Ok(()) => StatusCode::OK.into_response(),
                Err(e) => storage_err(e),
            }
        }
        Err(e) => storage_err(e),
    }
}

pub async fn delete_cors(state: &AppState, bucket: &str) -> Response {
    match state.storage.get_bucket_config(bucket).await {
        Ok(mut config) => {
            config.cors = None;
            match state.storage.set_bucket_config(bucket, &config).await {
                Ok(()) => StatusCode::NO_CONTENT.into_response(),
                Err(e) => storage_err(e),
            }
        }
        Err(e) => storage_err(e),
    }
}

pub async fn get_location(state: &AppState, _bucket: &str) -> Response {
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
        <LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{}</LocationConstraint>",
        state.config.region
    );
    xml_response(StatusCode::OK, xml)
}

pub fn parse_encryption_config(value: &serde_json::Value) -> Option<(String, Option<String>)> {
    if let Some(obj) = value.as_object() {
        if let Some(alg) = obj
            .get("sse_algorithm")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
        {
            let kms_key = obj
                .get("kms_master_key_id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            return Some((alg, kms_key));
        }
        if let Some(default) = obj
            .get("Rules")
            .and_then(|rules| rules.as_array())
            .and_then(|rules| rules.first())
            .and_then(|rule| rule.get("ApplyServerSideEncryptionByDefault"))
            .and_then(|inner| inner.as_object())
        {
            if let Some(alg) = default
                .get("SSEAlgorithm")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
            {
                let kms_key = default
                    .get("KMSMasterKeyID")
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty());
                return Some((alg, kms_key));
            }
        }
    }
    if let Some(raw) = value.as_str() {
        return parse_encryption_xml(raw).ok();
    }
    None
}

fn parse_encryption_xml(xml: &str) -> Result<(String, Option<String>), S3Error> {
    let doc = roxmltree::Document::parse(xml).map_err(|err| {
        S3Error::new(
            S3ErrorCode::MalformedXML,
            format!("Could not parse ServerSideEncryptionConfiguration: {}", err),
        )
    })?;
    let root = doc.root_element();
    if root.tag_name().name() != "ServerSideEncryptionConfiguration" {
        return Err(S3Error::new(
            S3ErrorCode::MalformedXML,
            "Expected <ServerSideEncryptionConfiguration> root element",
        ));
    }
    let rule = root
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "Rule")
        .ok_or_else(|| {
            S3Error::new(
                S3ErrorCode::MalformedXML,
                "Missing <Rule> in ServerSideEncryptionConfiguration",
            )
        })?;
    let default = rule
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "ApplyServerSideEncryptionByDefault")
        .ok_or_else(|| {
            S3Error::new(
                S3ErrorCode::MalformedXML,
                "Missing <ApplyServerSideEncryptionByDefault> in Rule",
            )
        })?;
    let algorithm = default
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "SSEAlgorithm")
        .and_then(|n| n.text())
        .map(|s| s.trim().to_string())
        .ok_or_else(|| {
            S3Error::new(
                S3ErrorCode::MalformedXML,
                "Missing <SSEAlgorithm> in ApplyServerSideEncryptionByDefault",
            )
        })?;
    if algorithm != "AES256" && algorithm != "aws:kms" {
        return Err(S3Error::new(
            S3ErrorCode::InvalidArgument,
            format!(
                "Unsupported SSEAlgorithm '{}'; supported values are AES256 and aws:kms",
                algorithm
            ),
        ));
    }
    let kms_key_id = default
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "KMSMasterKeyID")
        .and_then(|n| n.text())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if algorithm == "AES256" && kms_key_id.is_some() {
        return Err(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "KMSMasterKeyID is only valid when SSEAlgorithm is aws:kms",
        ));
    }
    Ok((algorithm, kms_key_id))
}

fn render_encryption_xml(value: &serde_json::Value) -> String {
    let (algorithm, kms_key_id) = match parse_encryption_config(value) {
        Some(parsed) => parsed,
        None => {
            return stored_xml(value);
        }
    };
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <ServerSideEncryptionConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Rule><ApplyServerSideEncryptionByDefault>",
    );
    xml.push_str(&format!("<SSEAlgorithm>{}</SSEAlgorithm>", algorithm));
    if let Some(key) = kms_key_id {
        xml.push_str(&format!("<KMSMasterKeyID>{}</KMSMasterKeyID>", key));
    }
    xml.push_str("</ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>");
    xml
}

pub async fn get_encryption(state: &AppState, bucket: &str) -> Response {
    match state.storage.get_bucket_config(bucket).await {
        Ok(config) => {
            if let Some(enc) = &config.encryption {
                xml_response(StatusCode::OK, render_encryption_xml(enc))
            } else {
                xml_response(
                    StatusCode::NOT_FOUND,
                    S3Error::from_code(S3ErrorCode::ServerSideEncryptionConfigurationNotFoundError)
                        .to_xml(),
                )
            }
        }
        Err(e) => storage_err(e),
    }
}

pub async fn put_encryption(state: &AppState, bucket: &str, body: Body) -> Response {
    let body_bytes = match http_body_util::BodyExt::collect(body).await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return xml_response(
                StatusCode::BAD_REQUEST,
                S3Error::from_code(S3ErrorCode::MalformedXML).to_xml(),
            );
        }
    };
    let xml_str = String::from_utf8_lossy(&body_bytes);
    let (algorithm, kms_key_id) = match parse_encryption_xml(&xml_str) {
        Ok(parsed) => parsed,
        Err(err) => {
            let status =
                StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::BAD_REQUEST);
            return xml_response(status, err.to_xml());
        }
    };
    if !state.config.encryption_enabled {
        return xml_response(
            StatusCode::BAD_REQUEST,
            S3Error::new(
                S3ErrorCode::InvalidArgument,
                "Server-side encryption is not enabled on this server (set ENCRYPTION_ENABLED=true)",
            )
            .to_xml(),
        );
    }
    if algorithm == "aws:kms" && !state.config.kms_enabled {
        return xml_response(
            StatusCode::BAD_REQUEST,
            S3Error::new(
                S3ErrorCode::InvalidArgument,
                "KMS support is not enabled on this server (set KMS_ENABLED=true)",
            )
            .to_xml(),
        );
    }

    let mut stored = serde_json::Map::new();
    stored.insert(
        "sse_algorithm".to_string(),
        serde_json::Value::String(algorithm),
    );
    if let Some(key) = kms_key_id {
        stored.insert(
            "kms_master_key_id".to_string(),
            serde_json::Value::String(key),
        );
    }
    let value = serde_json::Value::Object(stored);

    match state.storage.get_bucket_config(bucket).await {
        Ok(mut config) => {
            config.encryption = Some(value);
            match state.storage.set_bucket_config(bucket, &config).await {
                Ok(()) => StatusCode::OK.into_response(),
                Err(e) => storage_err(e),
            }
        }
        Err(e) => storage_err(e),
    }
}

pub async fn delete_encryption(state: &AppState, bucket: &str) -> Response {
    match state.storage.get_bucket_config(bucket).await {
        Ok(mut config) => {
            config.encryption = None;
            match state.storage.set_bucket_config(bucket, &config).await {
                Ok(()) => StatusCode::NO_CONTENT.into_response(),
                Err(e) => storage_err(e),
            }
        }
        Err(e) => storage_err(e),
    }
}

pub async fn get_lifecycle(state: &AppState, bucket: &str) -> Response {
    match state.storage.get_bucket_config(bucket).await {
        Ok(config) => {
            if let Some(lc) = &config.lifecycle {
                xml_response(StatusCode::OK, stored_xml(lc))
            } else {
                xml_response(
                    StatusCode::NOT_FOUND,
                    S3Error::from_code(S3ErrorCode::NoSuchLifecycleConfiguration).to_xml(),
                )
            }
        }
        Err(e) => storage_err(e),
    }
}

pub async fn put_lifecycle(state: &AppState, bucket: &str, body: Body) -> Response {
    let body_bytes = match http_body_util::BodyExt::collect(body).await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let raw = String::from_utf8_lossy(&body_bytes).to_string();
    if let Err(message) = validate_lifecycle_days(&raw) {
        return xml_response(
            StatusCode::BAD_REQUEST,
            S3Error::new(S3ErrorCode::InvalidArgument, message).to_xml(),
        );
    }
    let value = serde_json::Value::String(raw);

    match state.storage.get_bucket_config(bucket).await {
        Ok(mut config) => {
            config.lifecycle = Some(value);
            match state.storage.set_bucket_config(bucket, &config).await {
                Ok(()) => StatusCode::OK.into_response(),
                Err(e) => storage_err(e),
            }
        }
        Err(e) => storage_err(e),
    }
}

fn validate_lifecycle_days(raw: &str) -> Result<(), String> {
    if let Ok(doc) = roxmltree::Document::parse(raw) {
        for node in doc.descendants().filter(|node| node.is_element()) {
            let name = node.tag_name().name();
            if name == "Days" || name == "NoncurrentDays" || name == "DaysAfterInitiation" {
                let text = node.text().unwrap_or("").trim();
                if text.is_empty() {
                    continue;
                }
                let parsed: i64 = text.parse().map_err(|_| {
                    format!("Lifecycle '{}' must be a positive integer", name)
                })?;
                if parsed < 1 {
                    return Err(format!(
                        "Lifecycle '{}' must be a positive integer (>= 1)",
                        name
                    ));
                }
            }
        }
    }
    Ok(())
}

pub async fn delete_lifecycle(state: &AppState, bucket: &str) -> Response {
    match state.storage.get_bucket_config(bucket).await {
        Ok(mut config) => {
            config.lifecycle = None;
            match state.storage.set_bucket_config(bucket, &config).await {
                Ok(()) => StatusCode::NO_CONTENT.into_response(),
                Err(e) => storage_err(e),
            }
        }
        Err(e) => storage_err(e),
    }
}

pub async fn get_quota(state: &AppState, bucket: &str) -> Response {
    match state.storage.get_bucket_config(bucket).await {
        Ok(config) => {
            if let Some(quota) = &config.quota {
                let usage = match state.storage.bucket_stats(bucket).await {
                    Ok(s) => s,
                    Err(e) => return storage_err(e),
                };
                json_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "quota": {
                            "max_size_bytes": quota.max_bytes,
                            "max_objects": quota.max_objects,
                        },
                        "usage": {
                            "bytes": usage.bytes,
                            "objects": usage.objects,
                        }
                    }),
                )
            } else {
                xml_response(
                    StatusCode::NOT_FOUND,
                    S3Error::new(S3ErrorCode::NoSuchKey, "No quota configuration found").to_xml(),
                )
            }
        }
        Err(e) => storage_err(e),
    }
}

pub async fn put_quota(state: &AppState, bucket: &str, body: Body) -> Response {
    let body_bytes = match http_body_util::BodyExt::collect(body).await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return xml_response(
                StatusCode::BAD_REQUEST,
                S3Error::new(S3ErrorCode::InvalidArgument, "Invalid quota payload").to_xml(),
            );
        }
    };

    let payload: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => {
            return xml_response(
                StatusCode::BAD_REQUEST,
                S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    "Request body must be valid JSON",
                )
                .to_xml(),
            );
        }
    };

    let max_size = payload.get("max_size_bytes").and_then(|v| v.as_u64());
    let max_objects = payload.get("max_objects").and_then(|v| v.as_u64());

    if max_size.is_none() && max_objects.is_none() {
        return xml_response(
            StatusCode::BAD_REQUEST,
            S3Error::new(
                S3ErrorCode::InvalidArgument,
                "At least one of max_size_bytes or max_objects is required",
            )
            .to_xml(),
        );
    }

    match state.storage.get_bucket_config(bucket).await {
        Ok(mut config) => {
            config.quota = Some(myfsio_common::types::QuotaConfig {
                max_bytes: max_size,
                max_objects,
            });
            match state.storage.set_bucket_config(bucket, &config).await {
                Ok(()) => StatusCode::OK.into_response(),
                Err(e) => storage_err(e),
            }
        }
        Err(e) => storage_err(e),
    }
}

pub async fn delete_quota(state: &AppState, bucket: &str) -> Response {
    match state.storage.get_bucket_config(bucket).await {
        Ok(mut config) => {
            config.quota = None;
            match state.storage.set_bucket_config(bucket, &config).await {
                Ok(()) => StatusCode::NO_CONTENT.into_response(),
                Err(e) => storage_err(e),
            }
        }
        Err(e) => storage_err(e),
    }
}

pub async fn get_policy(state: &AppState, bucket: &str) -> Response {
    match state.storage.get_bucket_config(bucket).await {
        Ok(config) => {
            if let Some(policy) = &config.policy {
                json_response(StatusCode::OK, policy.clone())
            } else {
                xml_response(
                    StatusCode::NOT_FOUND,
                    S3Error::from_code(S3ErrorCode::NoSuchBucketPolicy).to_xml(),
                )
            }
        }
        Err(e) => storage_err(e),
    }
}

pub async fn put_policy(state: &AppState, bucket: &str, body: Body) -> Response {
    let body_bytes = match http_body_util::BodyExt::collect(body).await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return xml_response(
                StatusCode::BAD_REQUEST,
                S3Error::new(S3ErrorCode::MalformedXML, "Failed to read policy body").to_xml(),
            );
        }
    };

    let policy: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => {
            return xml_response(
                StatusCode::BAD_REQUEST,
                S3Error::new(S3ErrorCode::InvalidArgument, "Policy document must be JSON").to_xml(),
            );
        }
    };

    match state.storage.get_bucket_config(bucket).await {
        Ok(mut config) => {
            config.policy = Some(policy);
            match state.storage.set_bucket_config(bucket, &config).await {
                Ok(()) => StatusCode::NO_CONTENT.into_response(),
                Err(e) => storage_err(e),
            }
        }
        Err(e) => storage_err(e),
    }
}

pub async fn delete_policy(state: &AppState, bucket: &str) -> Response {
    match state.storage.get_bucket_config(bucket).await {
        Ok(mut config) => {
            config.policy = None;
            match state.storage.set_bucket_config(bucket, &config).await {
                Ok(()) => StatusCode::NO_CONTENT.into_response(),
                Err(e) => storage_err(e),
            }
        }
        Err(e) => storage_err(e),
    }
}

pub async fn get_policy_status(state: &AppState, bucket: &str) -> Response {
    match state.storage.get_bucket_config(bucket).await {
        Ok(config) => {
            let is_public = config
                .policy
                .as_ref()
                .map(policy_is_public)
                .unwrap_or(false);
            let xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><PolicyStatus><IsPublic>{}</IsPublic></PolicyStatus>",
                if is_public { "TRUE" } else { "FALSE" }
            );
            xml_response(StatusCode::OK, xml)
        }
        Err(e) => storage_err(e),
    }
}

pub async fn get_replication(state: &AppState, bucket: &str) -> Response {
    match state.storage.get_bucket_config(bucket).await {
        Ok(config) => {
            if let Some(replication) = &config.replication {
                xml_response(StatusCode::OK, stored_xml(replication))
            } else {
                xml_response(
                    StatusCode::NOT_FOUND,
                    S3Error::new(
                        S3ErrorCode::ReplicationConfigurationNotFoundError,
                        "The replication configuration was not found",
                    )
                    .to_xml(),
                )
            }
        }
        Err(e) => storage_err(e),
    }
}

pub async fn put_replication(state: &AppState, bucket: &str, body: Body) -> Response {
    let body_bytes = match http_body_util::BodyExt::collect(body).await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return xml_response(
                StatusCode::BAD_REQUEST,
                S3Error::new(S3ErrorCode::MalformedXML, "Failed to read replication body").to_xml(),
            );
        }
    };

    if body_bytes.is_empty() {
        return xml_response(
            StatusCode::BAD_REQUEST,
            S3Error::new(S3ErrorCode::MalformedXML, "Request body is required").to_xml(),
        );
    }

    let body_str = String::from_utf8_lossy(&body_bytes).to_string();
    match state.storage.get_bucket_config(bucket).await {
        Ok(mut config) => {
            config.replication = Some(serde_json::Value::String(body_str));
            match state.storage.set_bucket_config(bucket, &config).await {
                Ok(()) => StatusCode::OK.into_response(),
                Err(e) => storage_err(e),
            }
        }
        Err(e) => storage_err(e),
    }
}

pub async fn delete_replication(state: &AppState, bucket: &str) -> Response {
    match state.storage.get_bucket_config(bucket).await {
        Ok(mut config) => {
            config.replication = None;
            match state.storage.set_bucket_config(bucket, &config).await {
                Ok(()) => StatusCode::NO_CONTENT.into_response(),
                Err(e) => storage_err(e),
            }
        }
        Err(e) => storage_err(e),
    }
}

fn policy_is_public(policy: &serde_json::Value) -> bool {
    let statements = match policy.get("Statement") {
        Some(serde_json::Value::Array(items)) => items,
        Some(item) => {
            return is_allow_public_statement(item);
        }
        None => return false,
    };

    statements.iter().any(is_allow_public_statement)
}

fn is_allow_public_statement(statement: &serde_json::Value) -> bool {
    let effect_allow = statement
        .get("Effect")
        .and_then(|v| v.as_str())
        .map(|s| s.eq_ignore_ascii_case("allow"))
        .unwrap_or(false);
    if !effect_allow {
        return false;
    }

    match statement.get("Principal") {
        Some(serde_json::Value::String(s)) => s == "*",
        Some(serde_json::Value::Object(obj)) => obj.values().any(|v| v == "*"),
        _ => false,
    }
}

pub async fn get_acl(state: &AppState, bucket: &str) -> Response {
    match state.storage.get_bucket_config(bucket).await {
        Ok(config) => {
            if let Some(acl) = &config.acl {
                xml_response(StatusCode::OK, stored_xml(acl))
            } else {
                let owner = default_owner_for(state);
                let owner_display = state
                    .iam
                    .get_display_name(&owner)
                    .unwrap_or_else(|| owner.clone());
                let xml = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                    <AccessControlPolicy xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                    <Owner><ID>{owner}</ID><DisplayName>{display}</DisplayName></Owner>\
                    <AccessControlList>\
                    <Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\">\
                    <ID>{owner}</ID><DisplayName>{display}</DisplayName></Grantee>\
                    <Permission>FULL_CONTROL</Permission></Grant>\
                    </AccessControlList></AccessControlPolicy>",
                    owner = xml_escape(&owner),
                    display = xml_escape(&owner_display),
                );
                xml_response(StatusCode::OK, xml)
            }
        }
        Err(e) => storage_err(e),
    }
}

fn default_owner_for(_state: &AppState) -> String {
    "myfsio".to_string()
}

pub async fn put_acl(state: &AppState, bucket: &str, body: Body) -> Response {
    let body_bytes = match http_body_util::BodyExt::collect(body).await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let value = serde_json::Value::String(String::from_utf8_lossy(&body_bytes).to_string());

    match state.storage.get_bucket_config(bucket).await {
        Ok(mut config) => {
            config.acl = Some(value);
            match state.storage.set_bucket_config(bucket, &config).await {
                Ok(()) => StatusCode::OK.into_response(),
                Err(e) => storage_err(e),
            }
        }
        Err(e) => storage_err(e),
    }
}

pub async fn get_website(state: &AppState, bucket: &str) -> Response {
    match state.storage.get_bucket_config(bucket).await {
        Ok(config) => {
            if let Some(ws) = &config.website {
                xml_response(StatusCode::OK, stored_xml(ws))
            } else {
                xml_response(
                    StatusCode::NOT_FOUND,
                    S3Error::new(
                        S3ErrorCode::NoSuchWebsiteConfiguration,
                        "The specified bucket does not have a website configuration",
                    )
                    .to_xml(),
                )
            }
        }
        Err(e) => storage_err(e),
    }
}

pub async fn put_website(state: &AppState, bucket: &str, body: Body) -> Response {
    let body_bytes = match http_body_util::BodyExt::collect(body).await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let value = serde_json::Value::String(String::from_utf8_lossy(&body_bytes).to_string());

    match state.storage.get_bucket_config(bucket).await {
        Ok(mut config) => {
            config.website = Some(value);
            match state.storage.set_bucket_config(bucket, &config).await {
                Ok(()) => StatusCode::OK.into_response(),
                Err(e) => storage_err(e),
            }
        }
        Err(e) => storage_err(e),
    }
}

pub async fn delete_website(state: &AppState, bucket: &str) -> Response {
    match state.storage.get_bucket_config(bucket).await {
        Ok(mut config) => {
            config.website = None;
            match state.storage.set_bucket_config(bucket, &config).await {
                Ok(()) => StatusCode::NO_CONTENT.into_response(),
                Err(e) => storage_err(e),
            }
        }
        Err(e) => storage_err(e),
    }
}

pub async fn get_object_lock(state: &AppState, bucket: &str) -> Response {
    match state.storage.get_bucket_config(bucket).await {
        Ok(config) => {
            if let Some(ol) = &config.object_lock {
                xml_response(StatusCode::OK, stored_xml(ol))
            } else {
                xml_response(
                    StatusCode::NOT_FOUND,
                    S3Error::from_code(S3ErrorCode::ObjectLockConfigurationNotFoundError).to_xml(),
                )
            }
        }
        Err(e) => storage_err(e),
    }
}

pub async fn get_notification(state: &AppState, bucket: &str) -> Response {
    match state.storage.get_bucket_config(bucket).await {
        Ok(config) => {
            if let Some(n) = &config.notification {
                xml_response(StatusCode::OK, stored_xml(n))
            } else {
                let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                    <NotificationConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                    </NotificationConfiguration>";
                xml_response(StatusCode::OK, xml.to_string())
            }
        }
        Err(e) => storage_err(e),
    }
}

pub async fn get_logging(state: &AppState, bucket: &str) -> Response {
    match state.storage.bucket_exists(bucket).await {
        Ok(true) => {}
        Ok(false) => {
            return storage_err(myfsio_storage::error::StorageError::BucketNotFound(
                bucket.to_string(),
            ))
        }
        Err(e) => return storage_err(e),
    }

    let logging_config = if let Some(cfg) = state.access_logging.get(bucket) {
        Some(cfg)
    } else {
        match state.storage.get_bucket_config(bucket).await {
            Ok(config) => {
                let legacy = legacy_logging_config(&config);
                if let Some(cfg) = legacy.as_ref() {
                    if let Err(err) = state.access_logging.set(bucket, cfg.clone()) {
                        tracing::warn!(
                            "Failed to migrate legacy bucket logging config for {}: {}",
                            bucket,
                            err
                        );
                    }
                }
                legacy
            }
            Err(e) => return storage_err(e),
        }
    };

    let body = match logging_config {
        Some(cfg) if cfg.enabled => format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <BucketLoggingStatus xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <LoggingEnabled><TargetBucket>{}</TargetBucket><TargetPrefix>{}</TargetPrefix></LoggingEnabled>\
             </BucketLoggingStatus>",
            xml_escape(&cfg.target_bucket),
            xml_escape(&cfg.target_prefix),
        ),
        _ => "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
              <BucketLoggingStatus xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"></BucketLoggingStatus>"
            .to_string(),
    };
    xml_response(StatusCode::OK, body)
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn legacy_logging_config(
    config: &myfsio_common::types::BucketConfig,
) -> Option<crate::services::access_logging::LoggingConfiguration> {
    let value = config.logging.as_ref()?;
    match value {
        serde_json::Value::String(xml) => parse_logging_config_xml(xml),
        serde_json::Value::Object(_) => parse_logging_config_value(value.clone()),
        _ => None,
    }
}

fn parse_logging_config_value(
    value: serde_json::Value,
) -> Option<crate::services::access_logging::LoggingConfiguration> {
    let logging_enabled = value.get("LoggingEnabled")?;
    let target_bucket = logging_enabled
        .get("TargetBucket")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())?
        .to_string();
    let target_prefix = logging_enabled
        .get("TargetPrefix")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_string();
    Some(crate::services::access_logging::LoggingConfiguration {
        target_bucket,
        target_prefix,
        enabled: true,
    })
}

fn parse_logging_config_xml(
    xml: &str,
) -> Option<crate::services::access_logging::LoggingConfiguration> {
    let doc = roxmltree::Document::parse(xml).ok()?;
    let root = doc.root_element();
    let logging_enabled = root
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "LoggingEnabled")?;
    let target_bucket = logging_enabled
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "TargetBucket")
        .and_then(|n| n.text())
        .map(str::trim)
        .filter(|value| !value.is_empty())?
        .to_string();
    let target_prefix = logging_enabled
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "TargetPrefix")
        .and_then(|n| n.text())
        .unwrap_or_default()
        .to_string();
    Some(crate::services::access_logging::LoggingConfiguration {
        target_bucket,
        target_prefix,
        enabled: true,
    })
}

pub async fn put_object_lock(state: &AppState, bucket: &str, body: Body) -> Response {
    let body_bytes = match http_body_util::BodyExt::collect(body).await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let value = serde_json::Value::String(String::from_utf8_lossy(&body_bytes).to_string());

    match state.storage.get_bucket_config(bucket).await {
        Ok(mut config) => {
            config.object_lock = Some(value);
            match state.storage.set_bucket_config(bucket, &config).await {
                Ok(()) => StatusCode::OK.into_response(),
                Err(e) => storage_err(e),
            }
        }
        Err(e) => storage_err(e),
    }
}

pub async fn delete_object_lock(state: &AppState, bucket: &str) -> Response {
    match state.storage.get_bucket_config(bucket).await {
        Ok(mut config) => {
            config.object_lock = None;
            match state.storage.set_bucket_config(bucket, &config).await {
                Ok(()) => StatusCode::NO_CONTENT.into_response(),
                Err(e) => storage_err(e),
            }
        }
        Err(e) => storage_err(e),
    }
}

pub async fn put_notification(state: &AppState, bucket: &str, body: Body) -> Response {
    let body_bytes = match http_body_util::BodyExt::collect(body).await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return custom_xml_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                "Unable to parse XML document",
            )
        }
    };
    let raw = String::from_utf8_lossy(&body_bytes).to_string();
    let notification = if raw.trim().is_empty() {
        None
    } else {
        match parse_notification_configurations(&raw) {
            Ok(_) => Some(serde_json::Value::String(raw)),
            Err(message) => {
                let code = if message.contains("Destination URL is required") {
                    "InvalidArgument"
                } else {
                    "MalformedXML"
                };
                return custom_xml_error(StatusCode::BAD_REQUEST, code, &message);
            }
        }
    };

    match state.storage.get_bucket_config(bucket).await {
        Ok(mut config) => {
            config.notification = notification;
            match state.storage.set_bucket_config(bucket, &config).await {
                Ok(()) => StatusCode::OK.into_response(),
                Err(e) => storage_err(e),
            }
        }
        Err(e) => storage_err(e),
    }
}

pub async fn delete_notification(state: &AppState, bucket: &str) -> Response {
    match state.storage.get_bucket_config(bucket).await {
        Ok(mut config) => {
            config.notification = None;
            match state.storage.set_bucket_config(bucket, &config).await {
                Ok(()) => StatusCode::NO_CONTENT.into_response(),
                Err(e) => storage_err(e),
            }
        }
        Err(e) => storage_err(e),
    }
}

pub async fn put_logging(state: &AppState, bucket: &str, body: Body) -> Response {
    match state.storage.bucket_exists(bucket).await {
        Ok(true) => {}
        Ok(false) => {
            return storage_err(myfsio_storage::error::StorageError::BucketNotFound(
                bucket.to_string(),
            ))
        }
        Err(e) => return storage_err(e),
    }

    let body_bytes = match http_body_util::BodyExt::collect(body).await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    if body_bytes.iter().all(u8::is_ascii_whitespace) {
        state.access_logging.delete(bucket);
        return StatusCode::OK.into_response();
    }

    let xml = match std::str::from_utf8(&body_bytes) {
        Ok(s) => s,
        Err(_) => {
            return s3_error_response(
                S3ErrorCode::MalformedXML,
                "Unable to parse XML document",
                StatusCode::BAD_REQUEST,
            )
        }
    };

    let doc = match roxmltree::Document::parse(xml) {
        Ok(d) => d,
        Err(_) => {
            return s3_error_response(
                S3ErrorCode::MalformedXML,
                "Unable to parse XML document",
                StatusCode::BAD_REQUEST,
            )
        }
    };

    let root = doc.root_element();
    let logging_enabled = root
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "LoggingEnabled");

    let Some(le) = logging_enabled else {
        state.access_logging.delete(bucket);
        return StatusCode::OK.into_response();
    };

    let target_bucket = le
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "TargetBucket")
        .and_then(|n| n.text())
        .map(str::trim)
        .unwrap_or_default();

    if target_bucket.is_empty() {
        return s3_error_response(
            S3ErrorCode::InvalidArgument,
            "TargetBucket is required",
            StatusCode::BAD_REQUEST,
        );
    }

    let cfg = crate::services::access_logging::LoggingConfiguration {
        target_bucket: target_bucket.to_string(),
        target_prefix: le
            .children()
            .find(|n| n.is_element() && n.tag_name().name() == "TargetPrefix")
            .and_then(|n| n.text())
            .unwrap_or_default()
            .to_string(),
        enabled: true,
    };

    match state.storage.bucket_exists(&cfg.target_bucket).await {
        Ok(true) => {}
        Ok(false) => {
            return s3_error_response(
                S3ErrorCode::InvalidArgument,
                "Target bucket does not exist",
                StatusCode::BAD_REQUEST,
            )
        }
        Err(e) => return storage_err(e),
    }

    if let Err(e) = state.access_logging.set(bucket, cfg) {
        tracing::error!(
            "Failed to persist bucket logging config for {}: {}",
            bucket,
            e
        );
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    StatusCode::OK.into_response()
}

pub async fn delete_logging(state: &AppState, bucket: &str) -> Response {
    match state.storage.bucket_exists(bucket).await {
        Ok(true) => {}
        Ok(false) => {
            return storage_err(myfsio_storage::error::StorageError::BucketNotFound(
                bucket.to_string(),
            ))
        }
        Err(e) => return storage_err(e),
    }
    state.access_logging.delete(bucket);
    StatusCode::NO_CONTENT.into_response()
}

fn s3_error_response(code: S3ErrorCode, message: &str, status: StatusCode) -> Response {
    let err = S3Error::new(code, message.to_string());
    let code_str = code.as_str();
    (
        status,
        [
            ("content-type", "application/xml"),
            ("x-amz-error-code", code_str),
        ],
        err.to_xml(),
    )
        .into_response()
}

pub async fn list_object_versions(
    state: &AppState,
    bucket: &str,
    prefix: Option<&str>,
    delimiter: Option<&str>,
    key_marker: Option<&str>,
    version_id_marker: Option<&str>,
    max_keys: usize,
) -> Response {
    match state.storage.bucket_exists(bucket).await {
        Ok(true) => {}
        Ok(false) => {
            return storage_err(myfsio_storage::error::StorageError::BucketNotFound(
                bucket.to_string(),
            ));
        }
        Err(e) => return storage_err(e),
    }

    let params = myfsio_common::types::ListParams {
        max_keys: usize::MAX,
        prefix: prefix.map(ToOwned::to_owned),
        ..Default::default()
    };

    let object_result = match state.storage.list_objects(bucket, &params).await {
        Ok(result) => result,
        Err(e) => return storage_err(e),
    };
    let live_objects = object_result.objects;

    let archived_versions = match state
        .storage
        .list_bucket_object_versions(bucket, prefix)
        .await
    {
        Ok(versions) => versions,
        Err(e) => return storage_err(e),
    };

    #[derive(Clone)]
    struct Entry {
        key: String,
        version_id: String,
        last_modified: chrono::DateTime<chrono::Utc>,
        etag: Option<String>,
        size: u64,
        storage_class: String,
        is_delete_marker: bool,
        is_live: bool,
    }

    let mut entries: Vec<Entry> = Vec::with_capacity(live_objects.len() + archived_versions.len());
    for obj in &live_objects {
        entries.push(Entry {
            key: obj.key.clone(),
            version_id: obj.version_id.clone().unwrap_or_else(|| "null".to_string()),
            last_modified: obj.last_modified,
            etag: obj.etag.clone(),
            size: obj.size,
            storage_class: obj
                .storage_class
                .clone()
                .unwrap_or_else(|| "STANDARD".to_string()),
            is_delete_marker: false,
            is_live: true,
        });
    }
    for version in &archived_versions {
        entries.push(Entry {
            key: version.key.clone(),
            version_id: version.version_id.clone(),
            last_modified: version.last_modified,
            etag: version.etag.clone(),
            size: version.size,
            storage_class: "STANDARD".to_string(),
            is_delete_marker: version.is_delete_marker,
            is_live: false,
        });
    }

    entries.sort_by(|a, b| {
        a.key
            .cmp(&b.key)
            .then_with(|| b.is_live.cmp(&a.is_live))
            .then_with(|| b.last_modified.cmp(&a.last_modified))
            .then_with(|| a.version_id.cmp(&b.version_id))
    });

    let mut latest_marked: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut is_latest_flags: Vec<bool> = Vec::with_capacity(entries.len());
    for entry in &entries {
        if latest_marked.insert(entry.key.clone()) {
            is_latest_flags.push(true);
        } else {
            is_latest_flags.push(false);
        }
    }

    let km = key_marker.unwrap_or("");
    let vim = version_id_marker.unwrap_or("");
    let start_index = if km.is_empty() {
        0
    } else if vim.is_empty() {
        entries
            .iter()
            .position(|e| e.key.as_str() > km)
            .unwrap_or(entries.len())
    } else if let Some(pos) = entries
        .iter()
        .position(|e| e.key == km && e.version_id == vim)
    {
        pos + 1
    } else {
        entries
            .iter()
            .position(|e| e.key.as_str() > km)
            .unwrap_or(entries.len())
    };

    let delim = delimiter.unwrap_or("");
    let prefix_str = prefix.unwrap_or("");

    let mut common_prefixes: Vec<String> = Vec::new();
    let mut seen_prefixes: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut rendered = String::new();
    let mut count = 0usize;
    let mut is_truncated = false;
    let mut next_key_marker: Option<String> = None;
    let mut next_version_id_marker: Option<String> = None;
    let mut last_emitted: Option<(String, String)> = None;

    let mut idx = start_index;
    while idx < entries.len() {
        let entry = &entries[idx];
        let is_latest = is_latest_flags[idx];

        if !delim.is_empty() {
            let rest = entry.key.strip_prefix(prefix_str).unwrap_or(&entry.key);
            if let Some(delim_pos) = rest.find(delim) {
                let grouped = entry.key[..prefix_str.len() + delim_pos + delim.len()].to_string();
                if seen_prefixes.contains(&grouped) {
                    idx += 1;
                    continue;
                }
                if count >= max_keys {
                    is_truncated = true;
                    if let Some((k, v)) = last_emitted.clone() {
                        next_key_marker = Some(k);
                        next_version_id_marker = Some(v);
                    }
                    break;
                }
                common_prefixes.push(grouped.clone());
                seen_prefixes.insert(grouped.clone());
                count += 1;

                let mut group_last = (entry.key.clone(), entry.version_id.clone());
                idx += 1;
                while idx < entries.len() && entries[idx].key.starts_with(&grouped) {
                    group_last = (entries[idx].key.clone(), entries[idx].version_id.clone());
                    idx += 1;
                }
                last_emitted = Some(group_last);
                continue;
            }
        }

        if count >= max_keys {
            is_truncated = true;
            if let Some((k, v)) = last_emitted.clone() {
                next_key_marker = Some(k);
                next_version_id_marker = Some(v);
            }
            break;
        }

        let tag = if entry.is_delete_marker {
            "DeleteMarker"
        } else {
            "Version"
        };
        rendered.push_str(&format!("<{}>", tag));
        rendered.push_str(&format!("<Key>{}</Key>", xml_escape(&entry.key)));
        rendered.push_str(&format!(
            "<VersionId>{}</VersionId>",
            xml_escape(&entry.version_id)
        ));
        rendered.push_str(&format!("<IsLatest>{}</IsLatest>", is_latest));
        rendered.push_str(&format!(
            "<LastModified>{}</LastModified>",
            myfsio_xml::response::format_s3_datetime(&entry.last_modified)
        ));
        if !entry.is_delete_marker {
            if let Some(ref etag) = entry.etag {
                rendered.push_str(&format!("<ETag>\"{}\"</ETag>", xml_escape(etag)));
            }
            rendered.push_str(&format!("<Size>{}</Size>", entry.size));
            rendered.push_str(&format!(
                "<StorageClass>{}</StorageClass>",
                xml_escape(&entry.storage_class)
            ));
        }
        rendered.push_str(&format!("</{}>", tag));

        last_emitted = Some((entry.key.clone(), entry.version_id.clone()));
        count += 1;
        idx += 1;
    }

    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
        <ListVersionsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
    );
    xml.push_str(&format!("<Name>{}</Name>", xml_escape(bucket)));
    xml.push_str(&format!("<Prefix>{}</Prefix>", xml_escape(prefix_str)));
    if !km.is_empty() {
        xml.push_str(&format!("<KeyMarker>{}</KeyMarker>", xml_escape(km)));
    } else {
        xml.push_str("<KeyMarker></KeyMarker>");
    }
    if !vim.is_empty() {
        xml.push_str(&format!(
            "<VersionIdMarker>{}</VersionIdMarker>",
            xml_escape(vim)
        ));
    } else {
        xml.push_str("<VersionIdMarker></VersionIdMarker>");
    }
    xml.push_str(&format!("<MaxKeys>{}</MaxKeys>", max_keys));
    if !delim.is_empty() {
        xml.push_str(&format!("<Delimiter>{}</Delimiter>", xml_escape(delim)));
    }
    xml.push_str(&format!("<IsTruncated>{}</IsTruncated>", is_truncated));
    if let Some(ref nk) = next_key_marker {
        xml.push_str(&format!(
            "<NextKeyMarker>{}</NextKeyMarker>",
            xml_escape(nk)
        ));
    }
    if let Some(ref nv) = next_version_id_marker {
        xml.push_str(&format!(
            "<NextVersionIdMarker>{}</NextVersionIdMarker>",
            xml_escape(nv)
        ));
    }

    xml.push_str(&rendered);
    for cp in &common_prefixes {
        xml.push_str(&format!(
            "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
            xml_escape(cp)
        ));
    }

    xml.push_str("</ListVersionsResult>");
    xml_response(StatusCode::OK, xml)
}

pub async fn get_object_tagging(
    state: &AppState,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
) -> Response {
    let lookup = match version_id {
        Some(v) => state.storage.get_object_version_tags(bucket, key, v).await,
        None => state.storage.get_object_tags(bucket, key).await,
    };
    match lookup {
        Ok(tags) => {
            let mut xml = String::from(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                <Tagging xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><TagSet>",
            );
            for tag in &tags {
                xml.push_str(&format!(
                    "<Tag><Key>{}</Key><Value>{}</Value></Tag>",
                    tag.key, tag.value
                ));
            }
            xml.push_str("</TagSet></Tagging>");
            xml_response(StatusCode::OK, xml)
        }
        Err(e) => storage_err(e),
    }
}

pub async fn put_object_tagging(state: &AppState, bucket: &str, key: &str, body: Body) -> Response {
    let body_bytes = match http_body_util::BodyExt::collect(body).await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return xml_response(
                StatusCode::BAD_REQUEST,
                S3Error::from_code(S3ErrorCode::MalformedXML).to_xml(),
            );
        }
    };

    let xml_str = String::from_utf8_lossy(&body_bytes);
    let tags = parse_tagging_xml(&xml_str);
    if tags.len() > state.config.object_tag_limit {
        return xml_response(
            StatusCode::BAD_REQUEST,
            S3Error::new(
                S3ErrorCode::InvalidTag,
                format!("Maximum {} tags allowed", state.config.object_tag_limit),
            )
            .to_xml(),
        );
    }
    for tag in &tags {
        if tag.key.is_empty() || tag.key.len() > 128 {
            return xml_response(
                StatusCode::BAD_REQUEST,
                S3Error::new(S3ErrorCode::InvalidTag, "Tag key length must be 1-128").to_xml(),
            );
        }
        if tag.value.len() > 256 {
            return xml_response(
                StatusCode::BAD_REQUEST,
                S3Error::new(S3ErrorCode::InvalidTag, "Tag value length must be 0-256").to_xml(),
            );
        }
        if tag.key.contains('=') {
            return xml_response(
                StatusCode::BAD_REQUEST,
                S3Error::new(S3ErrorCode::InvalidTag, "Tag keys must not contain '='").to_xml(),
            );
        }
    }

    match state.storage.set_object_tags(bucket, key, &tags).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => storage_err(e),
    }
}

pub async fn delete_object_tagging(state: &AppState, bucket: &str, key: &str) -> Response {
    match state.storage.delete_object_tags(bucket, key).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => storage_err(e),
    }
}

pub async fn put_object_acl(
    state: &AppState,
    bucket: &str,
    key: &str,
    headers: &HeaderMap,
    body: Body,
) -> Response {
    let body_bytes = match http_body_util::BodyExt::collect(body).await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return xml_response(
                StatusCode::BAD_REQUEST,
                S3Error::from_code(S3ErrorCode::MalformedXML).to_xml(),
            );
        }
    };
    let body_str = String::from_utf8_lossy(&body_bytes);
    let body_trimmed = body_str.trim();
    let canned_acl_header = headers
        .get("x-amz-acl")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty());

    if !body_trimmed.is_empty() && canned_acl_header.is_some() {
        return xml_response(
            StatusCode::BAD_REQUEST,
            S3Error::new(
                S3ErrorCode::InvalidRequest,
                "Specifying both Canned ACLs and Header Grants is not allowed",
            )
            .to_xml(),
        );
    }

    match state.storage.head_object(bucket, key).await {
        Ok(_) => {
            let mut metadata = match state.storage.get_object_metadata(bucket, key).await {
                Ok(metadata) => metadata,
                Err(err) => return storage_err(err),
            };
            let existing_owner = acl_from_object_metadata(&metadata)
                .map(|acl| acl.owner)
                .unwrap_or_else(|| default_owner_for(state));

            let acl = if !body_trimmed.is_empty() {
                match acl_from_xml_strict(body_trimmed) {
                    Some(parsed) => {
                        if parsed.owner != existing_owner {
                            return xml_response(
                                StatusCode::FORBIDDEN,
                                S3Error::new(
                                    S3ErrorCode::AccessDenied,
                                    "The Owner ID in the ACL does not match the existing object owner",
                                )
                                .to_xml(),
                            );
                        }
                        parsed
                    }
                    None => {
                        return xml_response(
                            StatusCode::BAD_REQUEST,
                            S3Error::from_code(S3ErrorCode::MalformedACLError).to_xml(),
                        );
                    }
                }
            } else {
                let canned = canned_acl_header.unwrap_or("private");
                create_canned_acl(canned, &existing_owner)
            };

            store_object_acl(&mut metadata, &acl);
            match state
                .storage
                .put_object_metadata(bucket, key, &metadata)
                .await
            {
                Ok(()) => StatusCode::OK.into_response(),
                Err(err) => storage_err(err),
            }
        }
        Err(e) => storage_err(e),
    }
}

pub async fn get_object_retention(
    state: &AppState,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
) -> Response {
    let head_res = match version_id {
        Some(vid) => state.storage.head_object_version(bucket, key, vid).await,
        None => state.storage.head_object(bucket, key).await,
    };
    if let Err(e) = head_res {
        return storage_err(e);
    }
    let metadata_res = match version_id {
        Some(vid) => {
            state
                .storage
                .get_object_version_metadata(bucket, key, vid)
                .await
        }
        None => state.storage.get_object_metadata(bucket, key).await,
    };
    let metadata = match metadata_res {
        Ok(m) => m,
        Err(err) => return storage_err(err),
    };
    if let Some(retention) = retention_from_metadata(&metadata) {
        let xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <Retention xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <Mode>{}</Mode><RetainUntilDate>{}</RetainUntilDate></Retention>",
            match retention.mode {
                RetentionMode::GOVERNANCE => "GOVERNANCE",
                RetentionMode::COMPLIANCE => "COMPLIANCE",
            },
            retention.retain_until_date.format("%Y-%m-%dT%H:%M:%S.000Z"),
        );
        xml_response(StatusCode::OK, xml)
    } else {
        custom_xml_error(
            StatusCode::NOT_FOUND,
            "NoSuchObjectLockConfiguration",
            "No retention policy",
        )
    }
}

pub async fn put_object_retention(
    state: &AppState,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
    headers: &HeaderMap,
    body: Body,
) -> Response {
    let head_res = match version_id {
        Some(vid) => state.storage.head_object_version(bucket, key, vid).await,
        None => state.storage.head_object(bucket, key).await,
    };
    if let Err(e) = head_res {
        return storage_err(e);
    }

    let body_bytes = match http_body_util::BodyExt::collect(body).await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return custom_xml_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                "Unable to parse XML document",
            )
        }
    };
    let body_str = String::from_utf8_lossy(&body_bytes);
    let doc = match roxmltree::Document::parse(&body_str) {
        Ok(doc) => doc,
        Err(_) => {
            return custom_xml_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                "Unable to parse XML document",
            )
        }
    };
    let mode = find_xml_text(&doc, "Mode").unwrap_or_default();
    let retain_until = find_xml_text(&doc, "RetainUntilDate").unwrap_or_default();
    if mode.is_empty() || retain_until.is_empty() {
        return custom_xml_error(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "Mode and RetainUntilDate are required",
        );
    }
    let mode = match mode.as_str() {
        "GOVERNANCE" => RetentionMode::GOVERNANCE,
        "COMPLIANCE" => RetentionMode::COMPLIANCE,
        other => {
            return custom_xml_error(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                &format!("Invalid retention mode: {}", other),
            )
        }
    };
    let retain_until_date = match DateTime::parse_from_rfc3339(&retain_until) {
        Ok(value) => value.with_timezone(&Utc),
        Err(_) => {
            return custom_xml_error(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                &format!("Invalid date format: {}", retain_until),
            )
        }
    };

    let bypass_governance = headers
        .get("x-amz-bypass-governance-retention")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let metadata_res = match version_id {
        Some(vid) => {
            state
                .storage
                .get_object_version_metadata(bucket, key, vid)
                .await
        }
        None => state.storage.get_object_metadata(bucket, key).await,
    };
    let mut metadata = match metadata_res {
        Ok(m) => m,
        Err(err) => return storage_err(err),
    };
    if let Err(message) = ensure_retention_mutable(&metadata, bypass_governance) {
        return custom_xml_error(StatusCode::FORBIDDEN, "AccessDenied", &message);
    }
    if let Err(message) = store_retention(
        &mut metadata,
        &ObjectLockRetention {
            mode,
            retain_until_date,
        },
    ) {
        return custom_xml_error(StatusCode::BAD_REQUEST, "InvalidArgument", &message);
    }
    let put_res = match version_id {
        Some(vid) => {
            state
                .storage
                .put_object_version_metadata(bucket, key, vid, &metadata)
                .await
        }
        None => {
            state
                .storage
                .put_object_metadata(bucket, key, &metadata)
                .await
        }
    };
    match put_res {
        Ok(()) => StatusCode::OK.into_response(),
        Err(err) => storage_err(err),
    }
}

pub async fn get_object_legal_hold(
    state: &AppState,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
) -> Response {
    let head_res = match version_id {
        Some(vid) => state.storage.head_object_version(bucket, key, vid).await,
        None => state.storage.head_object(bucket, key).await,
    };
    if let Err(e) = head_res {
        return storage_err(e);
    }
    let metadata_res = match version_id {
        Some(vid) => {
            state
                .storage
                .get_object_version_metadata(bucket, key, vid)
                .await
        }
        None => state.storage.get_object_metadata(bucket, key).await,
    };
    let metadata = match metadata_res {
        Ok(m) => m,
        Err(err) => return storage_err(err),
    };
    let status = if get_legal_hold(&metadata) {
        "ON"
    } else {
        "OFF"
    };
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <LegalHold xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Status>{}</Status></LegalHold>",
        status
    );
    xml_response(StatusCode::OK, xml)
}

pub async fn put_object_legal_hold(
    state: &AppState,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
    body: Body,
) -> Response {
    let head_res = match version_id {
        Some(vid) => state.storage.head_object_version(bucket, key, vid).await,
        None => state.storage.head_object(bucket, key).await,
    };
    if let Err(e) = head_res {
        return storage_err(e);
    }

    let body_bytes = match http_body_util::BodyExt::collect(body).await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return custom_xml_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                "Unable to parse XML document",
            )
        }
    };
    let body_str = String::from_utf8_lossy(&body_bytes);
    let doc = match roxmltree::Document::parse(&body_str) {
        Ok(doc) => doc,
        Err(_) => {
            return custom_xml_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                "Unable to parse XML document",
            )
        }
    };
    let status = find_xml_text(&doc, "Status").unwrap_or_default();
    let enabled = match status.as_str() {
        "ON" => true,
        "OFF" => false,
        _ => {
            return custom_xml_error(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "Status must be ON or OFF",
            )
        }
    };
    let metadata_res = match version_id {
        Some(vid) => {
            state
                .storage
                .get_object_version_metadata(bucket, key, vid)
                .await
        }
        None => state.storage.get_object_metadata(bucket, key).await,
    };
    let mut metadata = match metadata_res {
        Ok(m) => m,
        Err(err) => return storage_err(err),
    };
    set_legal_hold(&mut metadata, enabled);
    let put_res = match version_id {
        Some(vid) => {
            state
                .storage
                .put_object_version_metadata(bucket, key, vid, &metadata)
                .await
        }
        None => {
            state
                .storage
                .put_object_metadata(bucket, key, &metadata)
                .await
        }
    };
    match put_res {
        Ok(()) => StatusCode::OK.into_response(),
        Err(err) => storage_err(err),
    }
}

pub async fn get_object_acl(state: &AppState, bucket: &str, key: &str) -> Response {
    match state.storage.head_object(bucket, key).await {
        Ok(_) => {
            let metadata = match state.storage.get_object_metadata(bucket, key).await {
                Ok(metadata) => metadata,
                Err(err) => return storage_err(err),
            };
            let owner = default_owner_for(state);
            let acl = acl_from_object_metadata(&metadata)
                .unwrap_or_else(|| create_canned_acl("private", &owner));
            let lookup = |id: &str| {
                state
                    .iam
                    .get_display_name(id)
                    .unwrap_or_else(|| id.to_string())
            };
            xml_response(StatusCode::OK, acl_to_xml_with_lookup(&acl, lookup))
        }
        Err(e) => storage_err(e),
    }
}

fn find_xml_text(doc: &roxmltree::Document<'_>, name: &str) -> Option<String> {
    doc.descendants()
        .find(|node| node.is_element() && node.tag_name().name() == name)
        .and_then(|node| node.text())
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
}

#[cfg(test)]
mod tests {
    use super::{legacy_logging_config, parse_logging_config_xml};
    use myfsio_common::types::BucketConfig;

    #[test]
    fn parses_legacy_logging_xml_string() {
        let config = BucketConfig {
            logging: Some(serde_json::Value::String(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                <BucketLoggingStatus xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                <LoggingEnabled><TargetBucket>logs</TargetBucket><TargetPrefix>audit/</TargetPrefix></LoggingEnabled>\
                </BucketLoggingStatus>"
                    .to_string(),
            )),
            ..Default::default()
        };

        let parsed = legacy_logging_config(&config).expect("expected legacy logging config");
        assert_eq!(parsed.target_bucket, "logs");
        assert_eq!(parsed.target_prefix, "audit/");
        assert!(parsed.enabled);
    }

    #[test]
    fn parses_legacy_logging_json_object() {
        let config = BucketConfig {
            logging: Some(serde_json::json!({
                "LoggingEnabled": {
                    "TargetBucket": "logs",
                    "TargetPrefix": "archive/"
                }
            })),
            ..Default::default()
        };

        let parsed = legacy_logging_config(&config).expect("expected legacy logging config");
        assert_eq!(parsed.target_bucket, "logs");
        assert_eq!(parsed.target_prefix, "archive/");
        assert!(parsed.enabled);
    }

    #[test]
    fn ignores_logging_xml_without_enabled_block() {
        let parsed = parse_logging_config_xml(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
            <BucketLoggingStatus xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
            </BucketLoggingStatus>",
        );

        assert!(parsed.is_none());
    }
}

fn parse_tagging_xml(xml: &str) -> Vec<myfsio_common::types::Tag> {
    let mut tags = Vec::new();
    let mut in_tag = false;
    let mut current_key = String::new();
    let mut current_value = String::new();
    let mut current_element = String::new();

    let mut reader = quick_xml::Reader::from_str(xml);
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(quick_xml::events::Event::Start(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                current_element = name.clone();
                if name == "Tag" {
                    in_tag = true;
                    current_key.clear();
                    current_value.clear();
                }
            }
            Ok(quick_xml::events::Event::Text(ref e)) => {
                if in_tag {
                    let text = e.unescape().unwrap_or_default().to_string();
                    match current_element.as_str() {
                        "Key" => current_key.push_str(&text),
                        "Value" => current_value.push_str(&text),
                        _ => {}
                    }
                }
            }
            Ok(quick_xml::events::Event::End(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if name == "Tag" && in_tag {
                    if !current_key.is_empty() {
                        tags.push(myfsio_common::types::Tag {
                            key: current_key.clone(),
                            value: current_value.clone(),
                        });
                    }
                    in_tag = false;
                }
                current_element.clear();
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }

    tags
}

#[cfg(test)]
mod tagging_xml_tests {
    use super::parse_tagging_xml;

    #[test]
    fn parse_compact_tagging() {
        let xml = "<Tagging><TagSet><Tag><Key>env</Key><Value>prod</Value></Tag></TagSet></Tagging>";
        let tags = parse_tagging_xml(xml);
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].key, "env");
        assert_eq!(tags[0].value, "prod");
    }

    #[test]
    fn parse_pretty_printed_tagging() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <TagSet>
    <Tag>
      <Key>env</Key>
      <Value>production</Value>
    </Tag>
    <Tag>
      <Key>team</Key>
      <Value>storage</Value>
    </Tag>
  </TagSet>
</Tagging>"#;
        let tags = parse_tagging_xml(xml);
        assert_eq!(tags.len(), 2);
        assert_eq!(tags[0].key, "env");
        assert_eq!(tags[0].value, "production");
        assert_eq!(tags[1].key, "team");
        assert_eq!(tags[1].value, "storage");
    }

    #[test]
    fn parse_pretty_tagging_empty_value() {
        let xml = r#"<Tagging>
  <TagSet>
    <Tag>
      <Key>only-key</Key>
      <Value></Value>
    </Tag>
  </TagSet>
</Tagging>"#;
        let tags = parse_tagging_xml(xml);
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].key, "only-key");
        assert_eq!(tags[0].value, "");
    }

    #[test]
    fn parse_pretty_tagging_preserves_whitespace_only_value() {
        let xml = r#"<Tagging>
  <TagSet>
    <Tag>
      <Key>spaced</Key>
      <Value>   </Value>
    </Tag>
  </TagSet>
</Tagging>"#;
        let tags = parse_tagging_xml(xml);
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].key, "spaced");
        assert_eq!(tags[0].value, "   ");
    }

    #[test]
    fn parse_compact_tagging_preserves_leading_and_trailing_spaces() {
        let xml = "<Tagging><TagSet><Tag><Key>k</Key><Value>  hello  </Value></Tag></TagSet></Tagging>";
        let tags = parse_tagging_xml(xml);
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].value, "  hello  ");
    }
}

#[cfg(test)]
mod encryption_xml_tests {
    use super::{parse_encryption_config, parse_encryption_xml};

    #[test]
    fn parse_aes256_default() {
        let xml = "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault>\
                   <SSEAlgorithm>AES256</SSEAlgorithm>\
                   </ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>";
        let (algo, key) = parse_encryption_xml(xml).expect("parse");
        assert_eq!(algo, "AES256");
        assert_eq!(key, None);
    }

    #[test]
    fn parse_aws_kms_with_key() {
        let xml = "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault>\
                   <SSEAlgorithm>aws:kms</SSEAlgorithm>\
                   <KMSMasterKeyID>arn:aws:kms:us-east-1:111:key/abc</KMSMasterKeyID>\
                   </ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>";
        let (algo, key) = parse_encryption_xml(xml).expect("parse");
        assert_eq!(algo, "aws:kms");
        assert_eq!(key.as_deref(), Some("arn:aws:kms:us-east-1:111:key/abc"));
    }

    #[test]
    fn reject_unknown_algorithm() {
        let xml = "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault>\
                   <SSEAlgorithm>ROT13</SSEAlgorithm>\
                   </ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>";
        assert!(parse_encryption_xml(xml).is_err());
    }

    #[test]
    fn reject_aes256_with_kms_key() {
        let xml = "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault>\
                   <SSEAlgorithm>AES256</SSEAlgorithm>\
                   <KMSMasterKeyID>k</KMSMasterKeyID>\
                   </ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>";
        assert!(parse_encryption_xml(xml).is_err());
    }

    #[test]
    fn reject_garbage_body() {
        assert!(parse_encryption_xml("this is not XML at all").is_err());
        assert!(parse_encryption_xml("<NotTheRightRoot/>").is_err());
    }

    #[test]
    fn parse_structured_config_object() {
        let value = serde_json::json!({"sse_algorithm": "AES256"});
        let (algo, key) = parse_encryption_config(&value).expect("parse");
        assert_eq!(algo, "AES256");
        assert_eq!(key, None);
    }

    #[test]
    fn parse_structured_config_with_kms_key() {
        let value = serde_json::json!({
            "sse_algorithm": "aws:kms",
            "kms_master_key_id": "arn:aws:kms:r:111:key/abc",
        });
        let (algo, key) = parse_encryption_config(&value).expect("parse");
        assert_eq!(algo, "aws:kms");
        assert_eq!(key.as_deref(), Some("arn:aws:kms:r:111:key/abc"));
    }

    #[test]
    fn parse_legacy_string_config() {
        let value = serde_json::Value::String(
            "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault>\
             <SSEAlgorithm>AES256</SSEAlgorithm>\
             </ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>"
                .to_string(),
        );
        let (algo, _) = parse_encryption_config(&value).expect("parse legacy");
        assert_eq!(algo, "AES256");
    }

    #[test]
    fn parse_ui_aes256_shape() {
        let value = serde_json::json!({
            "Rules": [{
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "AES256"
                }
            }]
        });
        let (algo, key) = parse_encryption_config(&value).expect("parse ui shape");
        assert_eq!(algo, "AES256");
        assert_eq!(key, None);
    }

    #[test]
    fn parse_ui_aws_kms_shape_with_key() {
        let value = serde_json::json!({
            "Rules": [{
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "aws:kms",
                    "KMSMasterKeyID": "arn:aws:kms:us-east-1:111:key/abc"
                }
            }]
        });
        let (algo, key) = parse_encryption_config(&value).expect("parse ui kms shape");
        assert_eq!(algo, "aws:kms");
        assert_eq!(key.as_deref(), Some("arn:aws:kms:us-east-1:111:key/abc"));
    }

    #[test]
    fn parse_ui_shape_with_blank_kms_key_treated_as_none() {
        let value = serde_json::json!({
            "Rules": [{
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "aws:kms",
                    "KMSMasterKeyID": "  "
                }
            }]
        });
        let (algo, key) = parse_encryption_config(&value).expect("parse ui shape");
        assert_eq!(algo, "aws:kms");
        assert_eq!(key, None);
    }
}
