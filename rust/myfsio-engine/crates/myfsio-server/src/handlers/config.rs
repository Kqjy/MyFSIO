use axum::body::Body;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use myfsio_common::error::{S3Error, S3ErrorCode};
use myfsio_storage::traits::StorageEngine;

use crate::state::AppState;

fn xml_response(status: StatusCode, xml: String) -> Response {
    (status, [("content-type", "application/xml")], xml).into_response()
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

pub async fn get_versioning(state: &AppState, bucket: &str) -> Response {
    match state.storage.is_versioning_enabled(bucket).await {
        Ok(enabled) => {
            let status_str = if enabled { "Enabled" } else { "Suspended" };
            let xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                <VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                <Status>{}</Status>\
                </VersioningConfiguration>",
                status_str
            );
            xml_response(StatusCode::OK, xml)
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
    let enabled = xml_str.contains("<Status>Enabled</Status>");

    match state.storage.set_versioning(bucket, enabled).await {
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
                xml_response(StatusCode::OK, cors.to_string())
            } else {
                xml_response(
                    StatusCode::NOT_FOUND,
                    S3Error::new(
                        S3ErrorCode::NoSuchKey,
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

pub async fn get_encryption(state: &AppState, bucket: &str) -> Response {
    match state.storage.get_bucket_config(bucket).await {
        Ok(config) => {
            if let Some(enc) = &config.encryption {
                xml_response(StatusCode::OK, enc.to_string())
            } else {
                xml_response(
                    StatusCode::NOT_FOUND,
                    S3Error::new(
                        S3ErrorCode::InvalidRequest,
                        "The server side encryption configuration was not found",
                    )
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
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let value = serde_json::Value::String(String::from_utf8_lossy(&body_bytes).to_string());

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
                xml_response(StatusCode::OK, lc.to_string())
            } else {
                xml_response(
                    StatusCode::NOT_FOUND,
                    S3Error::new(
                        S3ErrorCode::NoSuchKey,
                        "The lifecycle configuration does not exist",
                    )
                    .to_xml(),
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
    let value = serde_json::Value::String(String::from_utf8_lossy(&body_bytes).to_string());

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
                    S3Error::new(S3ErrorCode::NoSuchKey, "No bucket policy attached").to_xml(),
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
                match replication {
                    serde_json::Value::String(s) => xml_response(StatusCode::OK, s.clone()),
                    other => xml_response(StatusCode::OK, other.to_string()),
                }
            } else {
                xml_response(
                    StatusCode::NOT_FOUND,
                    S3Error::new(
                        S3ErrorCode::NoSuchKey,
                        "Replication configuration not found",
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
                xml_response(StatusCode::OK, acl.to_string())
            } else {
                let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                    <AccessControlPolicy xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                    <Owner><ID>myfsio</ID><DisplayName>myfsio</DisplayName></Owner>\
                    <AccessControlList>\
                    <Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\">\
                    <ID>myfsio</ID><DisplayName>myfsio</DisplayName></Grantee>\
                    <Permission>FULL_CONTROL</Permission></Grant>\
                    </AccessControlList></AccessControlPolicy>";
                xml_response(StatusCode::OK, xml.to_string())
            }
        }
        Err(e) => storage_err(e),
    }
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
                xml_response(StatusCode::OK, ws.to_string())
            } else {
                xml_response(
                    StatusCode::NOT_FOUND,
                    S3Error::new(
                        S3ErrorCode::NoSuchKey,
                        "The website configuration does not exist",
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
                xml_response(StatusCode::OK, ol.to_string())
            } else {
                let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                    <ObjectLockConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                    <ObjectLockEnabled>Disabled</ObjectLockEnabled>\
                    </ObjectLockConfiguration>";
                xml_response(StatusCode::OK, xml.to_string())
            }
        }
        Err(e) => storage_err(e),
    }
}

pub async fn get_notification(state: &AppState, bucket: &str) -> Response {
    match state.storage.get_bucket_config(bucket).await {
        Ok(config) => {
            if let Some(n) = &config.notification {
                xml_response(StatusCode::OK, n.to_string())
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
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let value = serde_json::Value::String(String::from_utf8_lossy(&body_bytes).to_string());

    match state.storage.get_bucket_config(bucket).await {
        Ok(mut config) => {
            config.notification = Some(value);
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
    (status, [("content-type", "application/xml")], err.to_xml()).into_response()
}

pub async fn list_object_versions(state: &AppState, bucket: &str) -> Response {
    match state.storage.list_buckets().await {
        Ok(buckets) => {
            if !buckets.iter().any(|b| b.name == bucket) {
                return storage_err(myfsio_storage::error::StorageError::BucketNotFound(
                    bucket.to_string(),
                ));
            }
        }
        Err(e) => return storage_err(e),
    }

    let params = myfsio_common::types::ListParams {
        max_keys: 1000,
        ..Default::default()
    };

    let objects = match state.storage.list_objects(bucket, &params).await {
        Ok(result) => result.objects,
        Err(e) => return storage_err(e),
    };

    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
        <ListVersionsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
    );
    xml.push_str(&format!("<Name>{}</Name>", bucket));

    for obj in &objects {
        xml.push_str("<Version>");
        xml.push_str(&format!("<Key>{}</Key>", obj.key));
        xml.push_str("<VersionId>null</VersionId>");
        xml.push_str("<IsLatest>true</IsLatest>");
        xml.push_str(&format!(
            "<LastModified>{}</LastModified>",
            myfsio_xml::response::format_s3_datetime(&obj.last_modified)
        ));
        if let Some(ref etag) = obj.etag {
            xml.push_str(&format!("<ETag>\"{}\"</ETag>", etag));
        }
        xml.push_str(&format!("<Size>{}</Size>", obj.size));
        xml.push_str("<StorageClass>STANDARD</StorageClass>");
        xml.push_str("</Version>");
    }

    xml.push_str("</ListVersionsResult>");
    xml_response(StatusCode::OK, xml)
}

pub async fn get_object_tagging(state: &AppState, bucket: &str, key: &str) -> Response {
    match state.storage.get_object_tags(bucket, key).await {
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

pub async fn get_object_acl(state: &AppState, bucket: &str, key: &str) -> Response {
    match state.storage.head_object(bucket, key).await {
        Ok(_) => {
            let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                <AccessControlPolicy xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                <Owner><ID>myfsio</ID><DisplayName>myfsio</DisplayName></Owner>\
                <AccessControlList>\
                <Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\">\
                <ID>myfsio</ID><DisplayName>myfsio</DisplayName></Grantee>\
                <Permission>FULL_CONTROL</Permission></Grant>\
                </AccessControlList></AccessControlPolicy>";
            xml_response(StatusCode::OK, xml.to_string())
        }
        Err(e) => storage_err(e),
    }
}

pub async fn put_object_acl(state: &AppState, bucket: &str, key: &str, _body: Body) -> Response {
    match state.storage.head_object(bucket, key).await {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => storage_err(e),
    }
}

pub async fn get_object_retention(state: &AppState, bucket: &str, key: &str) -> Response {
    match state.storage.head_object(bucket, key).await {
        Ok(_) => xml_response(
            StatusCode::NOT_FOUND,
            S3Error::new(
                S3ErrorCode::InvalidRequest,
                "No retention policy configured",
            )
            .to_xml(),
        ),
        Err(e) => storage_err(e),
    }
}

pub async fn put_object_retention(
    state: &AppState,
    bucket: &str,
    key: &str,
    _body: Body,
) -> Response {
    match state.storage.head_object(bucket, key).await {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => storage_err(e),
    }
}

pub async fn get_object_legal_hold(state: &AppState, bucket: &str, key: &str) -> Response {
    match state.storage.head_object(bucket, key).await {
        Ok(_) => {
            let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                <LegalHold xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                <Status>OFF</Status></LegalHold>";
            xml_response(StatusCode::OK, xml.to_string())
        }
        Err(e) => storage_err(e),
    }
}

pub async fn put_object_legal_hold(
    state: &AppState,
    bucket: &str,
    key: &str,
    _body: Body,
) -> Response {
    match state.storage.head_object(bucket, key).await {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => storage_err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::{legacy_logging_config, parse_logging_config_xml};
    use myfsio_common::types::BucketConfig;

    #[test]
    fn parses_legacy_logging_xml_string() {
        let mut config = BucketConfig::default();
        config.logging = Some(serde_json::Value::String(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
            <BucketLoggingStatus xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
            <LoggingEnabled><TargetBucket>logs</TargetBucket><TargetPrefix>audit/</TargetPrefix></LoggingEnabled>\
            </BucketLoggingStatus>"
                .to_string(),
        ));

        let parsed = legacy_logging_config(&config).expect("expected legacy logging config");
        assert_eq!(parsed.target_bucket, "logs");
        assert_eq!(parsed.target_prefix, "audit/");
        assert!(parsed.enabled);
    }

    #[test]
    fn parses_legacy_logging_json_object() {
        let mut config = BucketConfig::default();
        config.logging = Some(serde_json::json!({
            "LoggingEnabled": {
                "TargetBucket": "logs",
                "TargetPrefix": "archive/"
            }
        }));

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
                        "Key" => current_key = text,
                        "Value" => current_value = text,
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
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }

    tags
}
