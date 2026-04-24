use std::collections::{BTreeMap, HashMap};
use std::io::Cursor;
use std::path::{Component, Path as FsPath, PathBuf};
use std::sync::{Mutex, OnceLock};

use axum::body::{to_bytes, Body};
use axum::extract::{Extension, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Datelike, Timelike, Utc};
use futures::TryStreamExt;
use http_body_util::BodyStream;
use myfsio_auth::sigv4;
use myfsio_common::constants::{BUCKET_VERSIONS_DIR, SYSTEM_BUCKETS_DIR, SYSTEM_ROOT};
use myfsio_common::types::{ListParams, PartInfo, Tag};
use myfsio_crypto::encryption::EncryptionMetadata;
use myfsio_storage::error::StorageError;
use myfsio_storage::traits::StorageEngine;
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use roxmltree::Document;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use sysinfo::{Disks, System};
use tokio::io::AsyncReadExt;

use crate::handlers::{self, ObjectQuery};
use crate::middleware::session::SessionHandle;
use crate::state::AppState;
use crate::stores::connections::RemoteConnection;

const UI_KEY_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~')
    .remove(b'/');

const PATH_SEGMENT_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

const AWS_QUERY_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

const UI_OBJECT_BROWSER_MAX_KEYS: usize = 5000;

fn url_templates_for(bucket: &str) -> Value {
    json!({
        "download": format!("/ui/buckets/{}/objects/KEY_PLACEHOLDER/download", bucket),
        "preview": format!("/ui/buckets/{}/objects/KEY_PLACEHOLDER/preview", bucket),
        "delete": format!("/ui/buckets/{}/objects/KEY_PLACEHOLDER/delete", bucket),
        "presign": format!("/ui/buckets/{}/objects/KEY_PLACEHOLDER/presign", bucket),
        "metadata": format!("/ui/buckets/{}/objects/KEY_PLACEHOLDER/metadata", bucket),
        "versions": format!("/ui/buckets/{}/objects/KEY_PLACEHOLDER/versions", bucket),
        "restore": format!("/ui/buckets/{}/objects/KEY_PLACEHOLDER/restore/VERSION_ID_PLACEHOLDER", bucket),
        "tags": format!("/ui/buckets/{}/objects/KEY_PLACEHOLDER/tags", bucket),
        "copy": format!("/ui/buckets/{}/objects/KEY_PLACEHOLDER/copy", bucket),
        "move": format!("/ui/buckets/{}/objects/KEY_PLACEHOLDER/move", bucket),
    })
}

fn encode_object_key(key: &str) -> String {
    utf8_percent_encode(key, UI_KEY_ENCODE_SET).to_string()
}

fn encode_path_segment(value: &str) -> String {
    utf8_percent_encode(value, PATH_SEGMENT_ENCODE_SET).to_string()
}

fn build_ui_object_url(bucket: &str, key: &str, action: &str) -> String {
    format!(
        "/ui/buckets/{}/objects/{}/{}",
        bucket,
        encode_object_key(key),
        action
    )
}

fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut size = bytes as f64;
    let mut idx = 0;
    while size >= 1024.0 && idx < UNITS.len() - 1 {
        size /= 1024.0;
        idx += 1;
    }
    if idx == 0 {
        format!("{} {}", bytes, UNITS[idx])
    } else {
        format!("{:.1} {}", size, UNITS[idx])
    }
}

fn json_error(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(json!({ "error": message.into() }))).into_response()
}

fn json_ok(value: Value) -> Response {
    Json(value).into_response()
}

fn push_issue(result: &mut Value, issue: Value) {
    if let Some(items) = result
        .get_mut("issues")
        .and_then(|value| value.as_array_mut())
    {
        items.push(issue);
    }
}

fn storage_status(err: &StorageError) -> StatusCode {
    match err {
        StorageError::BucketNotFound(_)
        | StorageError::ObjectNotFound { .. }
        | StorageError::VersionNotFound { .. }
        | StorageError::UploadNotFound(_) => StatusCode::NOT_FOUND,
        StorageError::DeleteMarker { .. } => StatusCode::NOT_FOUND,
        StorageError::MethodNotAllowed(_) => StatusCode::METHOD_NOT_ALLOWED,
        StorageError::InvalidBucketName(_)
        | StorageError::InvalidObjectKey(_)
        | StorageError::InvalidRange
        | StorageError::QuotaExceeded(_) => StatusCode::BAD_REQUEST,
        StorageError::BucketAlreadyExists(_) => StatusCode::CONFLICT,
        StorageError::BucketNotEmpty(_) => StatusCode::CONFLICT,
        StorageError::Io(_) | StorageError::Json(_) | StorageError::Internal(_) => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

fn storage_json_error(err: StorageError) -> Response {
    json_error(storage_status(&err), err.to_string())
}

fn parse_bool_flag(value: Option<&str>) -> bool {
    matches!(
        value.map(|v| v.trim().to_ascii_lowercase()),
        Some(v) if v == "1" || v == "true" || v == "on" || v == "yes"
    )
}

fn parse_form_body(bytes: &[u8]) -> HashMap<String, String> {
    String::from_utf8_lossy(bytes)
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next().unwrap_or_default();
            let value = parts.next().unwrap_or_default();
            (decode_form_value(key), decode_form_value(value))
        })
        .collect()
}

fn decode_form_value(value: &str) -> String {
    percent_encoding::percent_decode_str(&value.replace('+', " "))
        .decode_utf8_lossy()
        .into_owned()
}

fn current_access_key(session: &SessionHandle) -> Option<String> {
    session.read(|s| s.user_id.clone())
}

fn owner_id_or_default(session: &SessionHandle) -> String {
    current_access_key(session).unwrap_or_else(|| "myfsio".to_string())
}

fn safe_attachment_filename(key: &str) -> String {
    let raw = key.rsplit('/').next().unwrap_or(key);
    let sanitized = raw
        .replace('"', "'")
        .replace('\\', "_")
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .collect::<String>();
    if sanitized.trim().is_empty() {
        "download".to_string()
    } else {
        sanitized
    }
}

fn parse_api_base(state: &AppState) -> String {
    state.config.api_base_url.trim_end_matches('/').to_string()
}

fn aws_query_encode(value: &str) -> String {
    utf8_percent_encode(value, AWS_QUERY_ENCODE_SET).to_string()
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn key_relative_path(key: &str) -> Result<PathBuf, String> {
    let mut out = PathBuf::new();
    for component in FsPath::new(key).components() {
        match component {
            Component::Normal(part) => out.push(part),
            _ => return Err("Invalid object key".to_string()),
        }
    }
    if out.as_os_str().is_empty() {
        return Err("Invalid object key".to_string());
    }
    Ok(out)
}

fn object_live_path(state: &AppState, bucket: &str, key: &str) -> Result<PathBuf, String> {
    let rel = key_relative_path(key)?;
    Ok(state.config.storage_root.join(bucket).join(rel))
}

fn version_root_for_bucket(state: &AppState, bucket: &str) -> PathBuf {
    state
        .config
        .storage_root
        .join(SYSTEM_ROOT)
        .join(SYSTEM_BUCKETS_DIR)
        .join(bucket)
        .join(BUCKET_VERSIONS_DIR)
}

fn version_dir_for_object(state: &AppState, bucket: &str, key: &str) -> Result<PathBuf, String> {
    let rel = key_relative_path(key)?;
    Ok(version_root_for_bucket(state, bucket).join(rel))
}

#[derive(Debug, Clone, Default, Deserialize)]
struct VersionManifest {
    #[serde(default)]
    version_id: String,
    #[serde(default)]
    key: String,
    #[serde(default)]
    size: u64,
    #[serde(default)]
    archived_at: Option<String>,
    #[serde(default)]
    etag: Option<String>,
    #[serde(default)]
    metadata: HashMap<String, String>,
    #[serde(default)]
    reason: Option<String>,
}

fn manifest_timestamp(value: &VersionManifest) -> DateTime<Utc> {
    value
        .archived_at
        .as_deref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(Utc::now)
}

fn manifest_to_json(record: &VersionManifest) -> Value {
    let ts = manifest_timestamp(record);
    json!({
        "version_id": record.version_id,
        "key": record.key,
        "size": record.size,
        "etag": record.etag,
        "archived_at": ts.to_rfc3339(),
        "last_modified": ts.to_rfc3339(),
        "metadata": record.metadata,
        "reason": record.reason.clone().unwrap_or_else(|| "update".to_string()),
        "is_latest": false,
    })
}

fn read_version_manifests_for_object(
    state: &AppState,
    bucket: &str,
    key: &str,
) -> Result<Vec<VersionManifest>, String> {
    let version_dir = version_dir_for_object(state, bucket, key)?;
    if !version_dir.exists() {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();
    for entry in std::fs::read_dir(&version_dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if !entry.file_type().map_err(|e| e.to_string())?.is_file() {
            continue;
        }
        if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let text = std::fs::read_to_string(entry.path()).map_err(|e| e.to_string())?;
        let mut manifest: VersionManifest =
            serde_json::from_str(&text).map_err(|e| e.to_string())?;
        if manifest.version_id.is_empty() {
            manifest.version_id = entry
                .path()
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string();
        }
        if manifest.key.is_empty() {
            manifest.key = key.to_string();
        }
        entries.push(manifest);
    }

    entries.sort_by(|a, b| manifest_timestamp(b).cmp(&manifest_timestamp(a)));
    Ok(entries)
}

async fn read_object_bytes_for_zip(
    state: &AppState,
    bucket: &str,
    key: &str,
) -> Result<Vec<u8>, String> {
    let all_meta = state
        .storage
        .get_object_metadata(bucket, key)
        .await
        .map_err(|e| e.to_string())?;

    if let Some(enc_meta) = EncryptionMetadata::from_metadata(&all_meta) {
        let enc_svc = state
            .encryption
            .as_ref()
            .ok_or_else(|| "Encryption service is not available".to_string())?;
        let obj_path = state
            .storage
            .get_object_path(bucket, key)
            .await
            .map_err(|e| e.to_string())?;
        let tmp_dir = state.config.storage_root.join(SYSTEM_ROOT).join("tmp");
        let _ = tokio::fs::create_dir_all(&tmp_dir).await;
        let dec_tmp = tmp_dir.join(format!("zip-dec-{}", uuid::Uuid::new_v4()));
        enc_svc
            .decrypt_object(&obj_path, &dec_tmp, &enc_meta, None)
            .await
            .map_err(|e| e.to_string())?;
        let bytes = tokio::fs::read(&dec_tmp).await.map_err(|e| e.to_string())?;
        let _ = tokio::fs::remove_file(&dec_tmp).await;
        return Ok(bytes);
    }

    let (_meta, mut reader) = state
        .storage
        .get_object(bucket, key)
        .await
        .map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .await
        .map_err(|e| e.to_string())?;
    Ok(bytes)
}

fn value_to_string_vec(value: Option<&Value>, field_name: &str) -> Vec<String> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        Some(Value::String(s)) if !s.trim().is_empty() => vec![s.to_string()],
        Some(Value::Null) | None => Vec::new(),
        Some(_) => vec![field_name.to_string()],
    }
}

fn xml_child<'a>(node: roxmltree::Node<'a, 'a>, name: &str) -> Option<roxmltree::Node<'a, 'a>> {
    node.children()
        .find(|child| child.is_element() && child.tag_name().name() == name)
}

fn xml_child_text(node: roxmltree::Node<'_, '_>, name: &str) -> Option<String> {
    xml_child(node, name)
        .and_then(|child| child.text())
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
}

fn xml_children_texts(node: roxmltree::Node<'_, '_>, name: &str) -> Vec<String> {
    node.children()
        .filter(|child| child.is_element() && child.tag_name().name() == name)
        .filter_map(|child| child.text().map(|text| text.trim().to_string()))
        .filter(|text| !text.is_empty())
        .collect()
}

fn parse_acl_value(value: Option<&Value>, owner: &str) -> Value {
    let default_grant = json!({
        "grantee": owner,
        "permission": "FULL_CONTROL",
        "grantee_type": "CanonicalUser",
        "display_name": owner,
        "grantee_id": owner,
        "grantee_uri": Value::Null,
    });

    let Some(value) = value else {
        return json!({
            "owner": owner,
            "grants": [default_grant],
            "canned_acls": ["private", "public-read", "public-read-write", "authenticated-read"],
        });
    };

    match value {
        Value::String(xml) => {
            let doc = match Document::parse(xml) {
                Ok(doc) => doc,
                Err(_) => {
                    return json!({
                        "owner": owner,
                        "grants": [default_grant],
                        "canned_acls": ["private", "public-read", "public-read-write", "authenticated-read"],
                    });
                }
            };
            let owner_node = doc
                .descendants()
                .find(|node| node.is_element() && node.tag_name().name() == "Owner");
            let owner_id = owner_node
                .and_then(|node| xml_child_text(node, "ID"))
                .unwrap_or_else(|| owner.to_string());

            let grants = doc
                .descendants()
                .filter(|node| node.is_element() && node.tag_name().name() == "Grant")
                .map(|grant| {
                    let grantee = xml_child(grant, "Grantee");
                    let permission = xml_child_text(grant, "Permission").unwrap_or_default();
                    let grantee_id = grantee.and_then(|node| xml_child_text(node, "ID"));
                    let display_name = grantee.and_then(|node| xml_child_text(node, "DisplayName"));
                    let grantee_uri = grantee.and_then(|node| xml_child_text(node, "URI"));
                    let grantee_type = grantee
                        .and_then(|node| {
                            node.attributes()
                                .find(|attr| {
                                    attr.name() == "type" || attr.name().ends_with(":type")
                                })
                                .map(|attr| attr.value().to_string())
                        })
                        .or_else(|| {
                            if grantee_uri.is_some() {
                                Some("Group".to_string())
                            } else {
                                Some("CanonicalUser".to_string())
                            }
                        })
                        .unwrap_or_else(|| "CanonicalUser".to_string());
                    let grantee_label = display_name
                        .clone()
                        .or_else(|| grantee_id.clone())
                        .or_else(|| grantee_uri.clone())
                        .unwrap_or_else(|| "unknown".to_string());

                    json!({
                        "grantee": grantee_label,
                        "permission": permission,
                        "grantee_type": grantee_type,
                        "display_name": display_name,
                        "grantee_id": grantee_id,
                        "grantee_uri": grantee_uri,
                    })
                })
                .collect::<Vec<_>>();

            json!({
                "owner": owner_id,
                "grants": if grants.is_empty() { vec![default_grant] } else { grants },
                "canned_acls": ["private", "public-read", "public-read-write", "authenticated-read"],
            })
        }
        Value::Object(map) => {
            let grants = map
                .get("grants")
                .and_then(|value| value.as_array())
                .cloned()
                .unwrap_or_else(|| vec![default_grant]);
            json!({
                "owner": map.get("owner").and_then(|v| v.as_str()).unwrap_or(owner),
                "grants": grants,
                "canned_acls": ["private", "public-read", "public-read-write", "authenticated-read"],
            })
        }
        _ => json!({
            "owner": owner,
            "grants": [default_grant],
            "canned_acls": ["private", "public-read", "public-read-write", "authenticated-read"],
        }),
    }
}

fn parse_cors_value(value: Option<&Value>) -> Value {
    let Some(value) = value else {
        return json!({ "rules": [] });
    };

    match value {
        Value::String(xml) => {
            let doc = match Document::parse(xml) {
                Ok(doc) => doc,
                Err(_) => return json!({ "rules": [] }),
            };
            let rules = doc
                .descendants()
                .filter(|node| node.is_element() && node.tag_name().name() == "CORSRule")
                .map(|rule| {
                    let allowed_origins = xml_children_texts(rule, "AllowedOrigin");
                    let allowed_methods = xml_children_texts(rule, "AllowedMethod");
                    let allowed_headers = xml_children_texts(rule, "AllowedHeader");
                    let expose_headers = xml_children_texts(rule, "ExposeHeader");
                    let max_age_seconds =
                        xml_child_text(rule, "MaxAgeSeconds").and_then(|v| v.parse::<u64>().ok());
                    json!({
                        "AllowedOrigins": allowed_origins,
                        "AllowedMethods": allowed_methods,
                        "AllowedHeaders": allowed_headers,
                        "ExposeHeaders": expose_headers,
                        "MaxAgeSeconds": max_age_seconds,
                        "allowed_origins": allowed_origins,
                        "allowed_methods": allowed_methods,
                        "allowed_headers": allowed_headers,
                        "expose_headers": expose_headers,
                        "max_age_seconds": max_age_seconds,
                    })
                })
                .collect::<Vec<_>>();
            json!({ "rules": rules })
        }
        Value::Array(rules) => json!({ "rules": rules }),
        Value::Object(map) => {
            if let Some(rules) = map.get("rules").and_then(|value| value.as_array()) {
                json!({ "rules": rules })
            } else {
                json!({ "rules": [map] })
            }
        }
        _ => json!({ "rules": [] }),
    }
}

fn parse_lifecycle_value(value: Option<&Value>) -> Value {
    let Some(value) = value else {
        return json!({ "rules": [] });
    };

    match value {
        Value::String(xml) => {
            let doc = match Document::parse(xml) {
                Ok(doc) => doc,
                Err(_) => return json!({ "rules": [] }),
            };
            let rules = doc
                .descendants()
                .filter(|node| node.is_element() && node.tag_name().name() == "Rule")
                .map(|rule| {
                    let rule_id = xml_child_text(rule, "ID").unwrap_or_default();
                    let status = xml_child_text(rule, "Status").unwrap_or_else(|| "Enabled".to_string());
                    let prefix = xml_child(rule, "Filter")
                        .and_then(|filter| xml_child_text(filter, "Prefix"))
                        .or_else(|| xml_child_text(rule, "Prefix"))
                        .unwrap_or_default();
                    let expiration_days = xml_child(rule, "Expiration")
                        .and_then(|node| xml_child_text(node, "Days"))
                        .and_then(|v| v.parse::<u64>().ok());
                    let noncurrent_days = xml_child(rule, "NoncurrentVersionExpiration")
                        .and_then(|node| xml_child_text(node, "NoncurrentDays"))
                        .and_then(|v| v.parse::<u64>().ok());
                    let abort_days = xml_child(rule, "AbortIncompleteMultipartUpload")
                        .and_then(|node| xml_child_text(node, "DaysAfterInitiation"))
                        .and_then(|v| v.parse::<u64>().ok());

                    json!({
                        "ID": rule_id,
                        "Status": status,
                        "Filter": { "Prefix": prefix },
                        "Expiration": expiration_days.map(|days| json!({ "Days": days })),
                        "NoncurrentVersionExpiration": noncurrent_days.map(|days| json!({ "NoncurrentDays": days })),
                        "AbortIncompleteMultipartUpload": abort_days.map(|days| json!({ "DaysAfterInitiation": days })),
                        "id": rule_id,
                        "status": status,
                        "prefix": prefix,
                        "expiration_days": expiration_days,
                        "noncurrent_days": noncurrent_days,
                        "abort_mpu_days": abort_days,
                    })
                })
                .collect::<Vec<_>>();
            json!({ "rules": rules })
        }
        Value::Array(rules) => json!({ "rules": rules }),
        Value::Object(map) => {
            if let Some(rules) = map.get("rules").and_then(|value| value.as_array()) {
                json!({ "rules": rules })
            } else {
                json!({ "rules": [map] })
            }
        }
        _ => json!({ "rules": [] }),
    }
}

fn bucket_acl_xml_for_canned(owner_id: &str, canned_acl: &str) -> Result<String, String> {
    let mut grants = vec![format!(
        "<Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\"><ID>{}</ID><DisplayName>{}</DisplayName></Grantee><Permission>FULL_CONTROL</Permission></Grant>",
        xml_escape(owner_id),
        xml_escape(owner_id),
    )];

    match canned_acl {
        "private" => {}
        "public-read" => grants.push(
            "<Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group\"><URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee><Permission>READ</Permission></Grant>".to_string()
        ),
        "public-read-write" => {
            grants.push(
                "<Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group\"><URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee><Permission>READ</Permission></Grant>".to_string()
            );
            grants.push(
                "<Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group\"><URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee><Permission>WRITE</Permission></Grant>".to_string()
            );
        }
        "authenticated-read" => grants.push(
            "<Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group\"><URI>http://acs.amazonaws.com/groups/global/AuthenticatedUsers</URI></Grantee><Permission>READ</Permission></Grant>".to_string()
        ),
        _ => return Err(format!("Invalid canned ACL: {}", canned_acl)),
    }

    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><AccessControlPolicy xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Owner><ID>{}</ID><DisplayName>{}</DisplayName></Owner><AccessControlList>{}</AccessControlList></AccessControlPolicy>",
        xml_escape(owner_id),
        xml_escape(owner_id),
        grants.join("")
    ))
}

fn cors_xml_from_rules(rules: &[Value]) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><CORSConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
    );
    for rule in rules {
        xml.push_str("<CORSRule>");
        for origin in value_to_string_vec(rule.get("AllowedOrigins"), "AllowedOrigin") {
            xml.push_str(&format!(
                "<AllowedOrigin>{}</AllowedOrigin>",
                xml_escape(&origin)
            ));
        }
        for method in value_to_string_vec(rule.get("AllowedMethods"), "AllowedMethod") {
            xml.push_str(&format!(
                "<AllowedMethod>{}</AllowedMethod>",
                xml_escape(&method)
            ));
        }
        for header in value_to_string_vec(rule.get("AllowedHeaders"), "AllowedHeader") {
            xml.push_str(&format!(
                "<AllowedHeader>{}</AllowedHeader>",
                xml_escape(&header)
            ));
        }
        for header in value_to_string_vec(rule.get("ExposeHeaders"), "ExposeHeader") {
            xml.push_str(&format!(
                "<ExposeHeader>{}</ExposeHeader>",
                xml_escape(&header)
            ));
        }
        if let Some(max_age) = rule.get("MaxAgeSeconds").and_then(|v| v.as_u64()) {
            xml.push_str(&format!("<MaxAgeSeconds>{}</MaxAgeSeconds>", max_age));
        }
        xml.push_str("</CORSRule>");
    }
    xml.push_str("</CORSConfiguration>");
    xml
}

fn lifecycle_xml_from_rules(rules: &[Value]) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><LifecycleConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
    );
    for rule in rules {
        xml.push_str("<Rule>");

        let id = rule.get("ID").and_then(|v| v.as_str()).unwrap_or_default();
        if !id.is_empty() {
            xml.push_str(&format!("<ID>{}</ID>", xml_escape(id)));
        }

        let status = rule
            .get("Status")
            .and_then(|v| v.as_str())
            .unwrap_or("Enabled");
        xml.push_str(&format!("<Status>{}</Status>", xml_escape(status)));

        let prefix = rule
            .get("Filter")
            .and_then(|v| v.get("Prefix"))
            .and_then(|v| v.as_str())
            .or_else(|| rule.get("Prefix").and_then(|v| v.as_str()))
            .unwrap_or_default();
        xml.push_str("<Filter>");
        xml.push_str(&format!("<Prefix>{}</Prefix>", xml_escape(prefix)));
        xml.push_str("</Filter>");

        if let Some(days) = rule
            .get("Expiration")
            .and_then(|v| v.get("Days"))
            .and_then(|v| v.as_u64())
        {
            xml.push_str(&format!("<Expiration><Days>{}</Days></Expiration>", days));
        }

        if let Some(days) = rule
            .get("NoncurrentVersionExpiration")
            .and_then(|v| v.get("NoncurrentDays"))
            .and_then(|v| v.as_u64())
        {
            xml.push_str(&format!(
                "<NoncurrentVersionExpiration><NoncurrentDays>{}</NoncurrentDays></NoncurrentVersionExpiration>",
                days
            ));
        }

        if let Some(days) = rule
            .get("AbortIncompleteMultipartUpload")
            .and_then(|v| v.get("DaysAfterInitiation"))
            .and_then(|v| v.as_u64())
        {
            xml.push_str(&format!(
                "<AbortIncompleteMultipartUpload><DaysAfterInitiation>{}</DaysAfterInitiation></AbortIncompleteMultipartUpload>",
                days
            ));
        }

        xml.push_str("</Rule>");
    }
    xml.push_str("</LifecycleConfiguration>");
    xml
}

fn zip_dos_time(dt: DateTime<Utc>) -> (u16, u16) {
    let year = dt.year().clamp(1980, 2107) as u16;
    let month = dt.month() as u16;
    let day = dt.day() as u16;
    let hour = dt.hour() as u16;
    let minute = dt.minute() as u16;
    let second = (dt.second() / 2) as u16;
    let dos_time = (hour << 11) | (minute << 5) | second;
    let dos_date = ((year - 1980) << 9) | (month << 5) | day;
    (dos_time, dos_date)
}

fn write_u16(buf: &mut Vec<u8>, value: u16) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn write_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn build_zip_archive(entries: Vec<(String, Vec<u8>, DateTime<Utc>)>) -> Result<Vec<u8>, String> {
    #[derive(Clone)]
    struct CentralEntry {
        name: Vec<u8>,
        crc32: u32,
        size: u32,
        offset: u32,
        mod_time: u16,
        mod_date: u16,
    }

    let mut output = Vec::new();
    let mut central_entries = Vec::new();

    for (name, data, modified) in entries {
        if data.len() > u32::MAX as usize {
            return Err(format!("Object '{}' is too large for ZIP export", name));
        }
        let offset = output.len();
        if offset > u32::MAX as usize {
            return Err("ZIP archive is too large".to_string());
        }

        let name_bytes = name.into_bytes();
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&data);
        let crc32 = hasher.finalize();
        let size = data.len() as u32;
        let (mod_time, mod_date) = zip_dos_time(modified);
        let flags = 0x0800u16;

        write_u32(&mut output, 0x04034b50);
        write_u16(&mut output, 20);
        write_u16(&mut output, flags);
        write_u16(&mut output, 0);
        write_u16(&mut output, mod_time);
        write_u16(&mut output, mod_date);
        write_u32(&mut output, crc32);
        write_u32(&mut output, size);
        write_u32(&mut output, size);
        write_u16(&mut output, name_bytes.len() as u16);
        write_u16(&mut output, 0);
        output.extend_from_slice(&name_bytes);
        output.extend_from_slice(&data);

        central_entries.push(CentralEntry {
            name: name_bytes,
            crc32,
            size,
            offset: offset as u32,
            mod_time,
            mod_date,
        });
    }

    let central_start = output.len();
    for entry in &central_entries {
        write_u32(&mut output, 0x02014b50);
        write_u16(&mut output, 20);
        write_u16(&mut output, 20);
        write_u16(&mut output, 0x0800);
        write_u16(&mut output, 0);
        write_u16(&mut output, entry.mod_time);
        write_u16(&mut output, entry.mod_date);
        write_u32(&mut output, entry.crc32);
        write_u32(&mut output, entry.size);
        write_u32(&mut output, entry.size);
        write_u16(&mut output, entry.name.len() as u16);
        write_u16(&mut output, 0);
        write_u16(&mut output, 0);
        write_u16(&mut output, 0);
        write_u16(&mut output, 0);
        write_u32(&mut output, 0);
        write_u32(&mut output, entry.offset);
        output.extend_from_slice(&entry.name);
    }

    let central_size = output.len() - central_start;
    if central_entries.len() > u16::MAX as usize
        || central_start > u32::MAX as usize
        || central_size > u32::MAX as usize
    {
        return Err("ZIP archive exceeds classic ZIP limits".to_string());
    }

    write_u32(&mut output, 0x06054b50);
    write_u16(&mut output, 0);
    write_u16(&mut output, 0);
    write_u16(&mut output, central_entries.len() as u16);
    write_u16(&mut output, central_entries.len() as u16);
    write_u32(&mut output, central_size as u32);
    write_u32(&mut output, central_start as u32);
    write_u16(&mut output, 0);

    Ok(output)
}

fn dangerous_preview_content_type(content_type: Option<&str>, key: &str) -> Option<String> {
    let guessed = content_type
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_else(|| {
            mime_guess::from_path(key)
                .first_raw()
                .unwrap_or("application/octet-stream")
                .to_ascii_lowercase()
        });

    match guessed.split(';').next().unwrap_or_default().trim() {
        "text/html"
        | "text/xml"
        | "application/xml"
        | "application/xhtml+xml"
        | "image/svg+xml" => Some("text/plain; charset=utf-8".to_string()),
        _ => None,
    }
}

async fn parse_json_body<T: DeserializeOwned>(body: Body) -> Result<T, Response> {
    let bytes = to_bytes(body, usize::MAX)
        .await
        .map_err(|_| json_error(StatusCode::BAD_REQUEST, "Failed to read request body"))?;
    serde_json::from_slice::<T>(&bytes)
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, format!("Invalid JSON body: {}", e)))
}

#[derive(Deserialize, Default)]
pub struct ListObjectsQuery {
    #[serde(default)]
    pub max_keys: Option<usize>,
    #[serde(default)]
    pub continuation_token: Option<String>,
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default)]
    pub start_after: Option<String>,
    #[serde(default)]
    pub delimiter: Option<String>,
}

fn object_json(bucket_name: &str, o: &myfsio_common::types::ObjectMeta) -> Value {
    json!({
        "key": o.key,
        "size": o.size,
        "last_modified": o.last_modified.to_rfc3339(),
        "last_modified_iso": o.last_modified.to_rfc3339(),
        "last_modified_display": o.last_modified.format("%Y-%m-%d %H:%M:%S").to_string(),
        "etag": o.etag.clone().unwrap_or_default(),
        "storage_class": o.storage_class.clone().unwrap_or_else(|| "STANDARD".to_string()),
        "content_type": o.content_type.clone().unwrap_or_default(),
        "download_url": build_ui_object_url(bucket_name, &o.key, "download"),
        "preview_url": build_ui_object_url(bucket_name, &o.key, "preview"),
        "delete_endpoint": build_ui_object_url(bucket_name, &o.key, "delete"),
        "presign_endpoint": build_ui_object_url(bucket_name, &o.key, "presign"),
        "metadata_url": build_ui_object_url(bucket_name, &o.key, "metadata"),
        "versions_endpoint": build_ui_object_url(bucket_name, &o.key, "versions"),
        "restore_template": format!(
            "/ui/buckets/{}/objects/{}/restore/VERSION_ID_PLACEHOLDER",
            bucket_name,
            encode_object_key(&o.key)
        ),
        "tags_url": build_ui_object_url(bucket_name, &o.key, "tags"),
        "copy_url": build_ui_object_url(bucket_name, &o.key, "copy"),
        "move_url": build_ui_object_url(bucket_name, &o.key, "move"),
    })
}

pub async fn list_bucket_objects(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    Path(bucket_name): Path<String>,
    Query(q): Query<ListObjectsQuery>,
) -> Response {
    if !matches!(state.storage.bucket_exists(&bucket_name).await, Ok(true)) {
        return json_error(StatusCode::NOT_FOUND, "Bucket not found");
    }

    let max_keys = q.max_keys.unwrap_or(1000).min(5000);
    let versioning_enabled = state
        .storage
        .is_versioning_enabled(&bucket_name)
        .await
        .unwrap_or(false);
    let stats = state.storage.bucket_stats(&bucket_name).await.ok();
    let total_count = stats.as_ref().map(|s| s.objects).unwrap_or(0);

    let use_shallow = q.delimiter.as_deref() == Some("/");

    if use_shallow {
        let params = myfsio_common::types::ShallowListParams {
            prefix: q.prefix.clone().unwrap_or_default(),
            delimiter: "/".to_string(),
            max_keys,
            continuation_token: q.continuation_token.clone(),
        };
        return match state
            .storage
            .list_objects_shallow(&bucket_name, &params)
            .await
        {
            Ok(res) => {
                let objects: Vec<Value> = res
                    .objects
                    .iter()
                    .map(|o| object_json(&bucket_name, o))
                    .collect();
                Json(json!({
                    "versioning_enabled": versioning_enabled,
                    "total_count": total_count,
                    "is_truncated": res.is_truncated,
                    "next_continuation_token": res.next_continuation_token,
                    "url_templates": url_templates_for(&bucket_name),
                    "objects": objects,
                    "common_prefixes": res.common_prefixes,
                }))
                .into_response()
            }
            Err(e) => storage_json_error(e),
        };
    }

    let params = ListParams {
        max_keys,
        continuation_token: q.continuation_token.clone(),
        prefix: q.prefix.clone(),
        start_after: q.start_after.clone(),
    };

    match state.storage.list_objects(&bucket_name, &params).await {
        Ok(res) => {
            let objects: Vec<Value> = res
                .objects
                .iter()
                .map(|o| object_json(&bucket_name, o))
                .collect();

            Json(json!({
                "versioning_enabled": versioning_enabled,
                "total_count": total_count,
                "is_truncated": res.is_truncated,
                "next_continuation_token": res.next_continuation_token,
                "url_templates": url_templates_for(&bucket_name),
                "objects": objects,
            }))
            .into_response()
        }
        Err(e) => storage_json_error(e),
    }
}

#[derive(Deserialize, Default)]
pub struct StreamObjectsQuery {
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default)]
    pub delimiter: Option<String>,
}

pub async fn stream_bucket_objects(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    Path(bucket_name): Path<String>,
    Query(q): Query<StreamObjectsQuery>,
) -> Response {
    if !matches!(state.storage.bucket_exists(&bucket_name).await, Ok(true)) {
        return (StatusCode::NOT_FOUND, "Bucket not found").into_response();
    }

    let versioning_enabled = state
        .storage
        .is_versioning_enabled(&bucket_name)
        .await
        .unwrap_or(false);
    let stats = state.storage.bucket_stats(&bucket_name).await.ok();
    let total_count = stats.as_ref().map(|s| s.objects).unwrap_or(0);

    let use_delimiter = q.delimiter.as_deref() == Some("/");
    let prefix = q.prefix.clone().unwrap_or_default();

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(64);

    let meta_line = json!({
        "type": "meta",
        "url_templates": url_templates_for(&bucket_name),
        "versioning_enabled": versioning_enabled,
    })
    .to_string()
        + "\n";
    let count_line = json!({ "type": "count", "total_count": total_count }).to_string() + "\n";

    let storage = state.storage.clone();
    let bucket = bucket_name.clone();

    tokio::spawn(async move {
        if tx
            .send(Ok(bytes::Bytes::from(meta_line.into_bytes())))
            .await
            .is_err()
        {
            return;
        }
        if tx
            .send(Ok(bytes::Bytes::from(count_line.into_bytes())))
            .await
            .is_err()
        {
            return;
        }

        if use_delimiter {
            let mut token: Option<String> = None;
            loop {
                let params = myfsio_common::types::ShallowListParams {
                    prefix: prefix.clone(),
                    delimiter: "/".to_string(),
                    max_keys: UI_OBJECT_BROWSER_MAX_KEYS,
                    continuation_token: token.clone(),
                };
                match storage.list_objects_shallow(&bucket, &params).await {
                    Ok(res) => {
                        for p in &res.common_prefixes {
                            let line = json!({ "type": "folder", "prefix": p }).to_string() + "\n";
                            if tx
                                .send(Ok(bytes::Bytes::from(line.into_bytes())))
                                .await
                                .is_err()
                            {
                                return;
                            }
                        }
                        for o in &res.objects {
                            let line = json!({
                                "type": "object",
                                "key": o.key,
                                "size": o.size,
                                "last_modified": o.last_modified.to_rfc3339(),
                                "last_modified_iso": o.last_modified.to_rfc3339(),
                                "last_modified_display": o.last_modified.format("%Y-%m-%d %H:%M:%S").to_string(),
                                "etag": o.etag.clone().unwrap_or_default(),
                                "storage_class": o.storage_class.clone().unwrap_or_else(|| "STANDARD".to_string()),
                            })
                            .to_string()
                                + "\n";
                            if tx
                                .send(Ok(bytes::Bytes::from(line.into_bytes())))
                                .await
                                .is_err()
                            {
                                return;
                            }
                        }
                        if !res.is_truncated || res.next_continuation_token.is_none() {
                            break;
                        }
                        token = res.next_continuation_token;
                    }
                    Err(e) => {
                        let line =
                            json!({ "type": "error", "error": e.to_string() }).to_string() + "\n";
                        let _ = tx.send(Ok(bytes::Bytes::from(line.into_bytes()))).await;
                        return;
                    }
                }
            }
        } else {
            let mut token: Option<String> = None;
            loop {
                let params = ListParams {
                    max_keys: 1000,
                    continuation_token: token.clone(),
                    prefix: if prefix.is_empty() {
                        None
                    } else {
                        Some(prefix.clone())
                    },
                    start_after: None,
                };
                match storage.list_objects(&bucket, &params).await {
                    Ok(res) => {
                        for o in &res.objects {
                            let line = json!({
                                "type": "object",
                                "key": o.key,
                                "size": o.size,
                                "last_modified": o.last_modified.to_rfc3339(),
                                "last_modified_iso": o.last_modified.to_rfc3339(),
                                "last_modified_display": o.last_modified.format("%Y-%m-%d %H:%M:%S").to_string(),
                                "etag": o.etag.clone().unwrap_or_default(),
                                "storage_class": o.storage_class.clone().unwrap_or_else(|| "STANDARD".to_string()),
                            })
                            .to_string()
                                + "\n";
                            if tx
                                .send(Ok(bytes::Bytes::from(line.into_bytes())))
                                .await
                                .is_err()
                            {
                                return;
                            }
                        }
                        if !res.is_truncated || res.next_continuation_token.is_none() {
                            break;
                        }
                        token = res.next_continuation_token;
                    }
                    Err(e) => {
                        let line =
                            json!({ "type": "error", "error": e.to_string() }).to_string() + "\n";
                        let _ = tx.send(Ok(bytes::Bytes::from(line.into_bytes()))).await;
                        return;
                    }
                }
            }
        }

        let done_line = json!({ "type": "done" }).to_string() + "\n";
        let _ = tx
            .send(Ok(bytes::Bytes::from(done_line.into_bytes())))
            .await;
    });

    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let body = Body::from_stream(stream);

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "application/x-ndjson; charset=utf-8".parse().unwrap(),
    );
    headers.insert(header::CACHE_CONTROL, "no-cache".parse().unwrap());
    headers.insert("x-accel-buffering", "no".parse().unwrap());

    (StatusCode::OK, headers, body).into_response()
}

#[derive(Deserialize, Default)]
pub struct SearchObjectsQuery {
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

pub async fn search_bucket_objects(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    Path(bucket_name): Path<String>,
    Query(q): Query<SearchObjectsQuery>,
) -> Response {
    if !matches!(state.storage.bucket_exists(&bucket_name).await, Ok(true)) {
        return json_error(StatusCode::NOT_FOUND, "Bucket not found");
    }

    let term = q.q.unwrap_or_default().to_lowercase();
    let limit = q.limit.unwrap_or(500).clamp(1, 1000);
    let prefix = q.prefix.clone().unwrap_or_default();

    if term.is_empty() {
        return Json(json!({ "results": [], "truncated": false })).into_response();
    }

    let mut results: Vec<Value> = Vec::new();
    let mut truncated = false;
    let mut token: Option<String> = None;
    loop {
        let params = ListParams {
            max_keys: 1000,
            continuation_token: token.clone(),
            prefix: if prefix.is_empty() {
                None
            } else {
                Some(prefix.clone())
            },
            start_after: None,
        };
        match state.storage.list_objects(&bucket_name, &params).await {
            Ok(res) => {
                for o in &res.objects {
                    if o.key.to_lowercase().contains(&term) {
                        if results.len() >= limit {
                            truncated = true;
                            break;
                        }
                        results.push(object_json(&bucket_name, o));
                    }
                }
                if truncated || !res.is_truncated || res.next_continuation_token.is_none() {
                    if res.is_truncated && results.len() >= limit {
                        truncated = true;
                    }
                    break;
                }
                token = res.next_continuation_token;
            }
            Err(e) => return storage_json_error(e),
        }
    }

    Json(json!({
        "results": results,
        "truncated": truncated,
    }))
    .into_response()
}

pub async fn bucket_stats_json(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    Path(bucket_name): Path<String>,
) -> Response {
    if !matches!(state.storage.bucket_exists(&bucket_name).await, Ok(true)) {
        return json_error(StatusCode::NOT_FOUND, "Bucket not found");
    }
    match state.storage.bucket_stats(&bucket_name).await {
        Ok(stats) => Json(json!({
            "objects": stats.objects,
            "bytes": stats.bytes,
            "version_count": stats.version_count,
            "version_bytes": stats.version_bytes,
            "total_objects": stats.objects + stats.version_count,
            "total_bytes": stats.bytes + stats.version_bytes,
        }))
        .into_response(),
        Err(e) => storage_json_error(e),
    }
}

pub async fn list_bucket_folders(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    Path(bucket_name): Path<String>,
    Query(q): Query<StreamObjectsQuery>,
) -> Response {
    if !matches!(state.storage.bucket_exists(&bucket_name).await, Ok(true)) {
        return json_error(StatusCode::NOT_FOUND, "Bucket not found");
    }

    let prefix = q.prefix.clone().unwrap_or_default();
    let params = myfsio_common::types::ShallowListParams {
        prefix: prefix.clone(),
        delimiter: "/".to_string(),
        max_keys: UI_OBJECT_BROWSER_MAX_KEYS,
        continuation_token: None,
    };
    match state
        .storage
        .list_objects_shallow(&bucket_name, &params)
        .await
    {
        Ok(res) => Json(json!({
            "prefixes": res.common_prefixes,
            "current_prefix": prefix,
        }))
        .into_response(),
        Err(e) => storage_json_error(e),
    }
}

pub async fn list_copy_targets(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    Path(_bucket_name): Path<String>,
) -> Response {
    let buckets: Vec<String> = state
        .storage
        .list_buckets()
        .await
        .map(|list| list.into_iter().map(|b| b.name).collect())
        .unwrap_or_default();
    Json(json!({ "buckets": buckets })).into_response()
}

#[derive(Deserialize)]
pub struct ConnectionTestPayload {
    pub endpoint_url: String,
    pub access_key: String,
    pub secret_key: String,
    #[serde(default = "default_region")]
    pub region: String,
}

fn default_region() -> String {
    "us-east-1".to_string()
}

pub async fn test_connection(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    body: Body,
) -> Response {
    let payload: ConnectionTestPayload = match parse_json_body(body).await {
        Ok(payload) => payload,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": "error",
                    "message": "Invalid JSON payload",
                })),
            )
                .into_response()
        }
    };

    if payload.endpoint_url.trim().is_empty()
        || payload.access_key.trim().is_empty()
        || payload.secret_key.trim().is_empty()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status": "error",
                "message": "Missing credentials",
            })),
        )
            .into_response();
    }

    let connection = RemoteConnection {
        id: "test".to_string(),
        name: "Test".to_string(),
        endpoint_url: payload.endpoint_url.trim().to_string(),
        access_key: payload.access_key.trim().to_string(),
        secret_key: payload.secret_key.trim().to_string(),
        region: payload.region.trim().to_string(),
    };

    if state.replication.check_endpoint(&connection).await {
        Json(json!({
            "status": "ok",
            "message": "Connection successful",
        }))
        .into_response()
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status": "error",
                "message": format!("Connection failed or endpoint is unreachable: {}", connection.endpoint_url),
            })),
        )
            .into_response()
    }
}

pub async fn connection_health(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    Path(connection_id): Path<String>,
) -> Response {
    let Some(connection) = state.connections.get(&connection_id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                "healthy": false,
                "error": "Connection not found",
            })),
        )
            .into_response();
    };

    let healthy = state.replication.check_endpoint(&connection).await;
    Json(json!({
        "healthy": healthy,
        "error": if healthy {
            Value::Null
        } else {
            Value::String(format!("Cannot reach endpoint: {}", connection.endpoint_url))
        }
    }))
    .into_response()
}

async fn peer_health_payload(state: &AppState, site_id: &str) -> Result<Value, Response> {
    let Some(registry) = &state.site_registry else {
        return Err(json_error(
            StatusCode::NOT_FOUND,
            "Site registry not available",
        ));
    };
    let Some(peer) = registry.get_peer(site_id) else {
        return Err(json_error(StatusCode::NOT_FOUND, "Peer not found"));
    };

    let checked_at = chrono::Utc::now().timestamp_millis() as f64 / 1000.0;
    let mut healthy = false;
    let mut error: Option<String> = None;

    if let Some(connection_id) = peer.connection_id.as_deref() {
        if let Some(connection) = state.connections.get(connection_id) {
            healthy = state.replication.check_endpoint(&connection).await;
            if !healthy {
                error = Some(format!(
                    "Cannot reach endpoint: {}",
                    connection.endpoint_url
                ));
            }
        } else {
            error = Some(format!("Connection '{}' not found", connection_id));
        }
    } else {
        error = Some("No connection configured for this peer".to_string());
    }

    registry.update_health(site_id, healthy);
    Ok(json!({
        "site_id": site_id,
        "is_healthy": healthy,
        "checked_at": checked_at,
        "error": error,
    }))
}

pub async fn peer_health(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    Path(site_id): Path<String>,
) -> Response {
    match peer_health_payload(&state, &site_id).await {
        Ok(payload) => Json(payload).into_response(),
        Err(response) => response,
    }
}

pub async fn peer_sync_stats(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    Path(site_id): Path<String>,
) -> Response {
    let Some(registry) = &state.site_registry else {
        return json_error(StatusCode::NOT_FOUND, "Site registry not available");
    };
    let Some(peer) = registry.get_peer(&site_id) else {
        return json_error(StatusCode::NOT_FOUND, "Peer not found");
    };
    let Some(connection_id) = peer.connection_id.as_deref() else {
        return json_error(StatusCode::BAD_REQUEST, "No connection configured");
    };

    let rules = state.replication.list_rules();
    let mut buckets: Vec<Value> = Vec::new();
    let mut buckets_syncing = 0u64;
    let mut objects_synced = 0u64;
    let mut objects_pending = 0u64;
    let mut objects_failed = 0u64;
    let mut bytes_synced = 0u64;
    let mut last_sync_at: Option<f64> = None;

    for rule in rules
        .into_iter()
        .filter(|rule| rule.target_connection_id == connection_id)
    {
        buckets_syncing += 1;
        objects_synced += rule.stats.objects_synced;
        objects_pending += rule.stats.objects_pending;
        bytes_synced += rule.stats.bytes_synced;
        if let Some(sync_at) = rule.stats.last_sync_at {
            if last_sync_at
                .map(|current| sync_at > current)
                .unwrap_or(true)
            {
                last_sync_at = Some(sync_at);
            }
        }

        let failures = state.replication.get_failure_count(&rule.bucket_name) as u64;
        objects_failed += failures;
        buckets.push(json!({
            "bucket_name": rule.bucket_name,
            "target_bucket": rule.target_bucket,
            "mode": rule.mode,
            "enabled": rule.enabled,
            "last_sync_at": rule.stats.last_sync_at,
            "objects_synced": rule.stats.objects_synced,
            "objects_pending": rule.stats.objects_pending,
            "failures": failures,
        }));
    }

    Json(json!({
        "buckets_syncing": buckets_syncing,
        "objects_synced": objects_synced,
        "objects_pending": objects_pending,
        "objects_failed": objects_failed,
        "bytes_synced": bytes_synced,
        "last_sync_at": last_sync_at,
        "buckets": buckets,
    }))
    .into_response()
}

pub async fn peer_bidirectional_status(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    Path(site_id): Path<String>,
) -> Response {
    let Some(registry) = &state.site_registry else {
        return json_error(StatusCode::NOT_FOUND, "Site registry not available");
    };
    let Some(peer) = registry.get_peer(&site_id) else {
        return json_error(StatusCode::NOT_FOUND, "Peer not found");
    };

    let local_site = registry.get_local_site();
    let local_bidirectional_rules: Vec<Value> = state
        .replication
        .list_rules()
        .into_iter()
        .filter(|rule| {
            peer.connection_id
                .as_deref()
                .map(|connection_id| rule.target_connection_id == connection_id)
                .unwrap_or(false)
                && rule.mode == crate::services::replication::MODE_BIDIRECTIONAL
        })
        .map(|rule| {
            json!({
                "bucket_name": rule.bucket_name,
                "target_bucket": rule.target_bucket,
                "enabled": rule.enabled,
            })
        })
        .collect();

    let mut result = json!({
        "site_id": site_id,
        "local_site_id": local_site.as_ref().map(|site| site.site_id.clone()),
        "local_endpoint": local_site.as_ref().map(|site| site.endpoint.clone()),
        "local_bidirectional_rules": local_bidirectional_rules,
        "local_site_sync_enabled": state.config.site_sync_enabled,
        "remote_status": Value::Null,
        "issues": Vec::<Value>::new(),
        "is_fully_configured": false,
    });

    if local_site
        .as_ref()
        .map(|site| site.site_id.trim().is_empty())
        .unwrap_or(true)
    {
        push_issue(
            &mut result,
            json!({
                "code": "NO_LOCAL_SITE_ID",
                "message": "Local site identity not configured",
                "severity": "error",
            }),
        );
    }
    if local_site
        .as_ref()
        .map(|site| site.endpoint.trim().is_empty())
        .unwrap_or(true)
    {
        push_issue(
            &mut result,
            json!({
                "code": "NO_LOCAL_ENDPOINT",
                "message": "Local site endpoint not configured (remote site cannot reach back)",
                "severity": "error",
            }),
        );
    }

    let Some(connection_id) = peer.connection_id.as_deref() else {
        push_issue(
            &mut result,
            json!({
                "code": "NO_CONNECTION",
                "message": "No connection configured for this peer",
                "severity": "error",
            }),
        );
        return Json(result).into_response();
    };

    let Some(connection) = state.connections.get(connection_id) else {
        push_issue(
            &mut result,
            json!({
                "code": "CONNECTION_NOT_FOUND",
                "message": format!("Connection '{}' not found", connection_id),
                "severity": "error",
            }),
        );
        return Json(result).into_response();
    };

    if result["local_bidirectional_rules"]
        .as_array()
        .map(|rules| rules.is_empty())
        .unwrap_or(true)
    {
        push_issue(
            &mut result,
            json!({
                "code": "NO_LOCAL_BIDIRECTIONAL_RULES",
                "message": "No bidirectional replication rules configured on this site",
                "severity": "warning",
            }),
        );
    }
    if !state.config.site_sync_enabled {
        push_issue(
            &mut result,
            json!({
                "code": "SITE_SYNC_DISABLED",
                "message": "Site sync worker is disabled (SITE_SYNC_ENABLED=false). Pull operations will not work.",
                "severity": "warning",
            }),
        );
    }
    if !state.replication.check_endpoint(&connection).await {
        push_issue(
            &mut result,
            json!({
                "code": "REMOTE_UNREACHABLE",
                "message": "Remote endpoint is not reachable",
                "severity": "error",
            }),
        );
        return Json(result).into_response();
    }

    let admin_url = format!(
        "{}/admin/sites",
        connection.endpoint_url.trim_end_matches('/')
    );
    match reqwest::Client::new()
        .get(&admin_url)
        .header("accept", "application/json")
        .header("x-access-key", &connection.access_key)
        .header("x-secret-key", &connection.secret_key)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => match resp.json::<Value>().await {
            Ok(remote_data) => {
                let remote_local = remote_data.get("local").cloned().unwrap_or(Value::Null);
                let remote_peers = remote_data
                    .get("peers")
                    .and_then(|value| value.as_array())
                    .cloned()
                    .unwrap_or_default();
                let mut has_peer_for_us = false;
                let mut peer_connection_configured = false;

                for remote_peer in &remote_peers {
                    let matches_site = local_site
                        .as_ref()
                        .map(|site| {
                            remote_peer.get("site_id").and_then(|v| v.as_str())
                                == Some(site.site_id.as_str())
                                || remote_peer.get("endpoint").and_then(|v| v.as_str())
                                    == Some(site.endpoint.as_str())
                        })
                        .unwrap_or(false);
                    if matches_site {
                        has_peer_for_us = true;
                        peer_connection_configured = remote_peer
                            .get("connection_id")
                            .and_then(|v| v.as_str())
                            .map(|v| !v.trim().is_empty())
                            .unwrap_or(false);
                        break;
                    }
                }

                result["remote_status"] = json!({
                    "reachable": true,
                    "local_site": remote_local,
                    "site_sync_enabled": Value::Null,
                    "has_peer_for_us": has_peer_for_us,
                    "peer_connection_configured": peer_connection_configured,
                    "has_bidirectional_rules_for_us": Value::Null,
                });

                if !has_peer_for_us {
                    push_issue(
                        &mut result,
                        json!({
                            "code": "REMOTE_NO_PEER_FOR_US",
                            "message": "Remote site does not have this site registered as a peer",
                            "severity": "error",
                        }),
                    );
                } else if !peer_connection_configured {
                    push_issue(
                        &mut result,
                        json!({
                            "code": "REMOTE_NO_CONNECTION_FOR_US",
                            "message": "Remote site has us as peer but no connection configured (cannot push back)",
                            "severity": "error",
                        }),
                    );
                }
            }
            Err(_) => {
                result["remote_status"] = json!({
                    "reachable": true,
                    "invalid_response": true,
                });
                push_issue(
                    &mut result,
                    json!({
                        "code": "REMOTE_INVALID_RESPONSE",
                        "message": "Remote admin API returned invalid JSON",
                        "severity": "warning",
                    }),
                );
            }
        },
        Ok(resp)
            if resp.status() == StatusCode::UNAUTHORIZED
                || resp.status() == StatusCode::FORBIDDEN =>
        {
            result["remote_status"] = json!({
                "reachable": true,
                "admin_access_denied": true,
            });
            push_issue(
                &mut result,
                json!({
                    "code": "REMOTE_ADMIN_ACCESS_DENIED",
                    "message": "Cannot verify remote configuration (admin access denied)",
                    "severity": "warning",
                }),
            );
        }
        Ok(resp) => {
            result["remote_status"] = json!({
                "reachable": true,
                "admin_api_error": resp.status().as_u16(),
            });
            push_issue(
                &mut result,
                json!({
                    "code": "REMOTE_ADMIN_API_ERROR",
                    "message": format!("Remote admin API returned status {}", resp.status().as_u16()),
                    "severity": "warning",
                }),
            );
        }
        Err(_) => {
            result["remote_status"] = json!({
                "reachable": false,
                "error": "Connection failed",
            });
            push_issue(
                &mut result,
                json!({
                    "code": "REMOTE_ADMIN_UNREACHABLE",
                    "message": "Could not reach remote admin API",
                    "severity": "warning",
                }),
            );
        }
    }

    let has_errors = result["issues"]
        .as_array()
        .map(|items| {
            items.iter().any(|issue| {
                issue.get("severity").and_then(|value| value.as_str()) == Some("error")
            })
        })
        .unwrap_or(true);
    result["is_fully_configured"] = json!(
        !has_errors
            && result["local_bidirectional_rules"]
                .as_array()
                .map(|rules| !rules.is_empty())
                .unwrap_or(false)
    );

    Json(result).into_response()
}

#[derive(Clone, Copy)]
struct MetricsSettingsSnapshot {
    enabled: bool,
    retention_hours: u64,
    interval_minutes: u64,
}

static METRICS_SETTINGS: OnceLock<Mutex<MetricsSettingsSnapshot>> = OnceLock::new();

fn metrics_settings_snapshot(state: &AppState) -> MetricsSettingsSnapshot {
    *METRICS_SETTINGS
        .get_or_init(|| {
            Mutex::new(MetricsSettingsSnapshot {
                enabled: state.config.metrics_history_enabled,
                retention_hours: state.config.metrics_history_retention_hours,
                interval_minutes: state.config.metrics_history_interval_minutes,
            })
        })
        .lock()
        .unwrap()
}

pub async fn metrics_settings(State(state): State<AppState>) -> Response {
    let settings = metrics_settings_snapshot(&state);
    Json(json!({
        "enabled": settings.enabled,
        "retention_hours": settings.retention_hours,
        "interval_minutes": settings.interval_minutes,
    }))
    .into_response()
}

pub async fn update_metrics_settings(State(state): State<AppState>, body: Body) -> Response {
    let payload: Value = parse_json_body(body).await.unwrap_or_else(|_| json!({}));
    let mut settings = METRICS_SETTINGS
        .get_or_init(|| {
            Mutex::new(MetricsSettingsSnapshot {
                enabled: state.config.metrics_history_enabled,
                retention_hours: state.config.metrics_history_retention_hours,
                interval_minutes: state.config.metrics_history_interval_minutes,
            })
        })
        .lock()
        .unwrap();
    let enabled = payload
        .get("enabled")
        .and_then(|value| value.as_bool())
        .unwrap_or(settings.enabled);
    let retention_hours = payload
        .get("retention_hours")
        .and_then(|value| value.as_u64())
        .unwrap_or(settings.retention_hours)
        .max(1);
    let interval_minutes = payload
        .get("interval_minutes")
        .and_then(|value| value.as_u64())
        .unwrap_or(settings.interval_minutes)
        .max(1);
    *settings = MetricsSettingsSnapshot {
        enabled,
        retention_hours,
        interval_minutes,
    };

    Json(json!({
        "enabled": enabled,
        "retention_hours": retention_hours,
        "interval_minutes": interval_minutes,
    }))
    .into_response()
}

#[derive(Deserialize, Default)]
struct MultipartInitPayload {
    #[serde(default)]
    object_key: String,
    #[serde(default)]
    metadata: Option<HashMap<String, String>>,
}

pub async fn upload_object(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    Path(bucket_name): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let content_type = match headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    {
        Some(value)
            if value
                .to_ascii_lowercase()
                .starts_with("multipart/form-data") =>
        {
            value.to_string()
        }
        _ => return json_error(StatusCode::BAD_REQUEST, "Expected multipart form upload"),
    };

    let boundary = match multer::parse_boundary(&content_type) {
        Ok(value) => value,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "Missing multipart boundary"),
    };

    let stream = BodyStream::new(body)
        .map_ok(|frame| frame.into_data().unwrap_or_default())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e));
    let mut multipart = multer::Multipart::new(stream, boundary);

    let mut object_key: Option<String> = None;
    let mut metadata_raw: Option<String> = None;
    let mut file_name: Option<String> = None;
    let mut file_content_type: Option<String> = None;
    let mut file_bytes: Option<Vec<u8>> = None;

    while let Some(field) = match multipart.next_field().await {
        Ok(field) => field,
        Err(e) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                format!("Malformed multipart body: {}", e),
            )
        }
    } {
        let name = field.name().unwrap_or_default().to_string();
        match name.as_str() {
            "object_key" => match field.text().await {
                Ok(value) if !value.trim().is_empty() => {
                    object_key = Some(value.trim().to_string())
                }
                _ => {}
            },
            "metadata" => match field.text().await {
                Ok(value) if !value.trim().is_empty() => metadata_raw = Some(value),
                _ => {}
            },
            "object" => {
                file_name = field.file_name().map(|s| s.to_string());
                file_content_type = field.content_type().map(|mime| mime.to_string());
                match field.bytes().await {
                    Ok(bytes) => file_bytes = Some(bytes.to_vec()),
                    Err(e) => {
                        return json_error(
                            StatusCode::BAD_REQUEST,
                            format!("Failed to read upload: {}", e),
                        )
                    }
                }
            }
            _ => {
                let _ = field.bytes().await;
            }
        }
    }

    let bytes = match file_bytes {
        Some(bytes) if !bytes.is_empty() => bytes,
        _ => return json_error(StatusCode::BAD_REQUEST, "Choose a file to upload"),
    };

    let key = object_key
        .or(file_name.clone())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| json_error(StatusCode::BAD_REQUEST, "Object key is required"));
    let key = match key {
        Ok(key) => key,
        Err(response) => return response,
    };

    let metadata = if let Some(raw) = metadata_raw {
        match serde_json::from_str::<HashMap<String, Value>>(&raw) {
            Ok(map) => Some(
                map.into_iter()
                    .map(|(k, v)| (k, v.as_str().unwrap_or(&v.to_string()).to_string()))
                    .collect::<HashMap<_, _>>(),
            ),
            Err(_) => return json_error(StatusCode::BAD_REQUEST, "Metadata must be a JSON object"),
        }
    } else {
        None
    };

    let mut upload_headers = HeaderMap::new();
    if let Some(content_type) = file_content_type.as_deref() {
        if let Ok(value) = content_type.parse() {
            upload_headers.insert(header::CONTENT_TYPE, value);
        }
    }
    if let Some(metadata) = &metadata {
        for (key, value) in metadata {
            let header_name = format!("x-amz-meta-{}", key);
            if let Ok(name) = header_name.parse::<axum::http::HeaderName>() {
                if let Ok(value) = value.parse() {
                    upload_headers.insert(name, value);
                }
            }
        }
    }

    let response = handlers::put_object(
        State(state),
        Path((bucket_name.clone(), key.clone())),
        Query(ObjectQuery::default()),
        upload_headers,
        Body::from(bytes),
    )
    .await;

    if !response.status().is_success() {
        return response;
    }

    let mut message = format!("Uploaded '{}'", key);
    if metadata.is_some() {
        message.push_str(" with metadata");
    }
    json_ok(json!({
        "status": "ok",
        "message": message,
        "key": key,
    }))
}

pub async fn initiate_multipart_upload(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    Path(bucket_name): Path<String>,
    body: Body,
) -> Response {
    let payload: MultipartInitPayload = match parse_json_body(body).await {
        Ok(payload) => payload,
        Err(response) => return response,
    };

    let object_key = payload.object_key.trim();
    if object_key.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "object_key is required");
    }

    match state
        .storage
        .initiate_multipart(&bucket_name, object_key, payload.metadata)
        .await
    {
        Ok(upload_id) => json_ok(json!({ "upload_id": upload_id })),
        Err(err) => storage_json_error(err),
    }
}

#[derive(Deserialize, Default)]
pub struct MultipartPartQuery {
    #[serde(rename = "partNumber")]
    part_number: Option<u32>,
}

pub async fn upload_multipart_part(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    Path((bucket_name, upload_id)): Path<(String, String)>,
    Query(query): Query<MultipartPartQuery>,
    body: Body,
) -> Response {
    let Some(part_number) = query.part_number else {
        return json_error(StatusCode::BAD_REQUEST, "partNumber is required");
    };
    if !(1..=10_000).contains(&part_number) {
        return json_error(
            StatusCode::BAD_REQUEST,
            "partNumber must be between 1 and 10000",
        );
    }

    let bytes = match to_bytes(body, usize::MAX).await {
        Ok(bytes) if !bytes.is_empty() => bytes,
        Ok(_) => return json_error(StatusCode::BAD_REQUEST, "Empty request body"),
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "Failed to read request body"),
    };
    let reader: myfsio_storage::traits::AsyncReadStream = Box::pin(Cursor::new(bytes.to_vec()));
    match state
        .storage
        .upload_part(&bucket_name, &upload_id, part_number, reader)
        .await
    {
        Ok(etag) => json_ok(json!({ "etag": etag, "part_number": part_number })),
        Err(err) => storage_json_error(err),
    }
}

#[derive(Deserialize, Default)]
struct CompleteMultipartPayload {
    #[serde(default)]
    parts: Vec<CompleteMultipartPartPayload>,
}

#[derive(Deserialize, Default)]
struct CompleteMultipartPartPayload {
    #[serde(default, alias = "PartNumber")]
    part_number: u32,
    #[serde(default, alias = "ETag")]
    etag: String,
}

pub async fn complete_multipart_upload(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    Path((bucket_name, upload_id)): Path<(String, String)>,
    body: Body,
) -> Response {
    let payload: CompleteMultipartPayload = match parse_json_body(body).await {
        Ok(payload) => payload,
        Err(response) => return response,
    };

    if payload.parts.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "parts array required");
    }

    let parts = payload
        .parts
        .iter()
        .map(|part| PartInfo {
            part_number: part.part_number,
            etag: part.etag.trim_matches('"').to_string(),
        })
        .collect::<Vec<_>>();

    match state
        .storage
        .complete_multipart(&bucket_name, &upload_id, &parts)
        .await
    {
        Ok(meta) => {
            super::trigger_replication(&state, &bucket_name, &meta.key, "write");
            json_ok(json!({
                "key": meta.key,
                "size": meta.size,
                "etag": meta.etag.unwrap_or_default(),
                "last_modified": meta.last_modified.to_rfc3339(),
            }))
        }
        Err(err) => storage_json_error(err),
    }
}

pub async fn abort_multipart_upload(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    Path((bucket_name, upload_id)): Path<(String, String)>,
) -> Response {
    match state
        .storage
        .abort_multipart(&bucket_name, &upload_id)
        .await
    {
        Ok(()) => json_ok(json!({ "status": "aborted" })),
        Err(err) => storage_json_error(err),
    }
}

async fn get_bucket_config_json(
    state: &AppState,
    bucket: &str,
) -> Result<myfsio_common::types::BucketConfig, StorageError> {
    state.storage.get_bucket_config(bucket).await
}

pub async fn bucket_acl(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
    Path(bucket_name): Path<String>,
) -> Response {
    match get_bucket_config_json(&state, &bucket_name).await {
        Ok(config) => Json(parse_acl_value(
            config.acl.as_ref(),
            &owner_id_or_default(&session),
        ))
        .into_response(),
        Err(err) => storage_json_error(err),
    }
}

#[derive(Deserialize, Default)]
struct BucketAclPayload {
    #[serde(default)]
    canned_acl: String,
}

pub async fn update_bucket_acl(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
    Path(bucket_name): Path<String>,
    body: Body,
) -> Response {
    let payload: BucketAclPayload = match parse_json_body(body).await {
        Ok(payload) => payload,
        Err(response) => return response,
    };
    if payload.canned_acl.trim().is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "canned_acl is required");
    }

    let acl_xml = match bucket_acl_xml_for_canned(
        &owner_id_or_default(&session),
        payload.canned_acl.trim(),
    ) {
        Ok(xml) => xml,
        Err(message) => return json_error(StatusCode::BAD_REQUEST, message),
    };

    match state.storage.get_bucket_config(&bucket_name).await {
        Ok(mut config) => {
            config.acl = Some(Value::String(acl_xml));
            match state.storage.set_bucket_config(&bucket_name, &config).await {
                Ok(()) => json_ok(json!({
                    "status": "ok",
                    "message": format!("ACL set to {}", payload.canned_acl.trim()),
                })),
                Err(err) => storage_json_error(err),
            }
        }
        Err(err) => storage_json_error(err),
    }
}

pub async fn bucket_cors(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    Path(bucket_name): Path<String>,
) -> Response {
    match get_bucket_config_json(&state, &bucket_name).await {
        Ok(config) => Json(parse_cors_value(config.cors.as_ref())).into_response(),
        Err(err) => storage_json_error(err),
    }
}

#[derive(Deserialize, Default)]
struct BucketCorsPayload {
    #[serde(default)]
    rules: Vec<Value>,
}

pub async fn update_bucket_cors(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    Path(bucket_name): Path<String>,
    body: Body,
) -> Response {
    let payload: BucketCorsPayload = match parse_json_body(body).await {
        Ok(payload) => payload,
        Err(response) => return response,
    };

    match state.storage.get_bucket_config(&bucket_name).await {
        Ok(mut config) => {
            config.cors = if payload.rules.is_empty() {
                None
            } else {
                Some(Value::String(cors_xml_from_rules(&payload.rules)))
            };
            match state.storage.set_bucket_config(&bucket_name, &config).await {
                Ok(()) => json_ok(json!({
                    "status": "ok",
                    "message": "CORS configuration saved",
                    "rules": payload.rules,
                })),
                Err(err) => storage_json_error(err),
            }
        }
        Err(err) => storage_json_error(err),
    }
}

pub async fn bucket_lifecycle(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    Path(bucket_name): Path<String>,
) -> Response {
    match get_bucket_config_json(&state, &bucket_name).await {
        Ok(config) => Json(parse_lifecycle_value(config.lifecycle.as_ref())).into_response(),
        Err(err) => storage_json_error(err),
    }
}

#[derive(Deserialize, Default)]
struct BucketLifecyclePayload {
    #[serde(default)]
    rules: Vec<Value>,
}

pub async fn update_bucket_lifecycle(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    Path(bucket_name): Path<String>,
    body: Body,
) -> Response {
    let payload: BucketLifecyclePayload = match parse_json_body(body).await {
        Ok(payload) => payload,
        Err(response) => return response,
    };

    match state.storage.get_bucket_config(&bucket_name).await {
        Ok(mut config) => {
            config.lifecycle = if payload.rules.is_empty() {
                None
            } else {
                Some(Value::String(lifecycle_xml_from_rules(&payload.rules)))
            };
            match state.storage.set_bucket_config(&bucket_name, &config).await {
                Ok(()) => json_ok(json!({
                    "status": "ok",
                    "message": "Lifecycle rules saved",
                    "rules": payload.rules,
                })),
                Err(err) => storage_json_error(err),
            }
        }
        Err(err) => storage_json_error(err),
    }
}

async fn serve_object_download_or_preview(
    state: AppState,
    bucket: String,
    key: String,
    headers: HeaderMap,
    is_download: bool,
) -> Response {
    let content_type = state
        .storage
        .head_object(&bucket, &key)
        .await
        .ok()
        .and_then(|meta| meta.content_type);

    let mut query = ObjectQuery::default();
    if is_download {
        query.response_content_disposition = Some(format!(
            "attachment; filename=\"{}\"",
            safe_attachment_filename(&key)
        ));
    } else if let Some(forced) = dangerous_preview_content_type(content_type.as_deref(), &key) {
        query.response_content_type = Some(forced);
    }

    let mut response =
        handlers::get_object(State(state), Path((bucket, key)), Query(query), headers).await;
    response
        .headers_mut()
        .insert("x-content-type-options", "nosniff".parse().unwrap());
    response
}

async fn object_metadata_json(state: &AppState, bucket: &str, key: &str) -> Response {
    let head = match state.storage.head_object(bucket, key).await {
        Ok(meta) => meta,
        Err(err) => return storage_json_error(err),
    };
    let metadata = state
        .storage
        .get_object_metadata(bucket, key)
        .await
        .unwrap_or_default();

    let mut out: std::collections::HashMap<String, String> = metadata
        .iter()
        .filter(|(k, _)| !(k.starts_with("__") && k.ends_with("__")))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    if let Some(content_type) = head.content_type {
        out.insert("Content-Type".to_string(), content_type);
    }
    let display_length = metadata
        .get("__size__")
        .cloned()
        .unwrap_or_else(|| head.size.to_string());
    out.insert("Content-Length".to_string(), display_length);
    if let Some(algorithm) = metadata.get("x-amz-server-side-encryption") {
        out.insert(
            "x-amz-server-side-encryption".to_string(),
            algorithm.to_string(),
        );
    }
    Json(json!({ "metadata": out })).into_response()
}

async fn object_versions_json(state: &AppState, bucket: &str, key: &str) -> Response {
    match read_version_manifests_for_object(state, bucket, key) {
        Ok(entries) => Json(json!({
            "versions": entries.into_iter().map(|entry| manifest_to_json(&entry)).collect::<Vec<_>>(),
        }))
        .into_response(),
        Err(err) => json_error(StatusCode::BAD_REQUEST, err),
    }
}

async fn object_tags_json(state: &AppState, bucket: &str, key: &str) -> Response {
    match state.storage.get_object_tags(bucket, key).await {
        Ok(tags) => Json(json!({
            "tags": tags.into_iter().map(|tag| json!({ "Key": tag.key, "Value": tag.value })).collect::<Vec<_>>(),
        }))
        .into_response(),
        Err(err) => storage_json_error(err),
    }
}

#[derive(Deserialize, Default)]
struct PresignPayload {
    #[serde(default = "default_presign_method")]
    method: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

fn default_presign_method() -> String {
    "GET".to_string()
}

async fn object_presign_json(
    state: &AppState,
    session: &SessionHandle,
    bucket: &str,
    key: &str,
    body: Body,
) -> Response {
    let payload: PresignPayload = match parse_json_body(body).await {
        Ok(payload) => payload,
        Err(response) => return response,
    };

    let method = payload.method.trim().to_ascii_uppercase();
    if !matches!(method.as_str(), "GET" | "PUT" | "DELETE") {
        return json_error(
            StatusCode::BAD_REQUEST,
            "Method must be GET, PUT, or DELETE",
        );
    }

    let access_key = match current_access_key(session) {
        Some(key) => key,
        None => return json_error(StatusCode::FORBIDDEN, "Missing authenticated session"),
    };
    let secret_key = match state.iam.get_secret_key(&access_key) {
        Some(secret) => secret,
        None => {
            return json_error(
                StatusCode::FORBIDDEN,
                "Session credentials are no longer valid",
            )
        }
    };

    let min_expiry = state.config.presigned_url_min_expiry;
    let max_expiry = state.config.presigned_url_max_expiry;
    let expires = payload
        .expires_in
        .unwrap_or(900)
        .clamp(min_expiry, max_expiry);

    let api_base = parse_api_base(state);
    let parsed = match reqwest::Url::parse(&api_base) {
        Ok(url) => url,
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Invalid API_BASE_URL: {}", err),
            )
        }
    };
    let host = match parsed.host_str() {
        Some(host) => {
            if let Some(port) = parsed.port() {
                format!("{}:{}", host, port)
            } else {
                host.to_string()
            }
        }
        None => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to determine API host",
            )
        }
    };

    let now = Utc::now();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date_stamp = now.format("%Y%m%d").to_string();
    let region = state.config.region.as_str();
    let credential = format!("{}/{}/{}/s3/aws4_request", access_key, date_stamp, region);

    let canonical_uri = format!("/{}/{}", bucket, encode_object_key(key));
    let mut query_params = vec![
        (
            "X-Amz-Algorithm".to_string(),
            "AWS4-HMAC-SHA256".to_string(),
        ),
        ("X-Amz-Credential".to_string(), credential.clone()),
        ("X-Amz-Date".to_string(), amz_date.clone()),
        ("X-Amz-Expires".to_string(), expires.to_string()),
        ("X-Amz-SignedHeaders".to_string(), "host".to_string()),
    ];
    query_params.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    let canonical_query = query_params
        .iter()
        .map(|(name, value)| format!("{}={}", aws_query_encode(name), aws_query_encode(value)))
        .collect::<Vec<_>>()
        .join("&");
    let canonical_request = format!(
        "{}\n{}\n{}\nhost:{}\n\nhost\nUNSIGNED-PAYLOAD",
        method, canonical_uri, canonical_query, host
    );
    let scope = format!("{}/{}/s3/aws4_request", date_stamp, region);
    let string_to_sign = sigv4::build_string_to_sign(&amz_date, &scope, &canonical_request);
    let signing_key = sigv4::derive_signing_key(&secret_key, &date_stamp, region, "s3");
    let signature = sigv4::compute_signature(&signing_key, &string_to_sign);

    let final_query = format!("{}&X-Amz-Signature={}", canonical_query, signature);
    let final_url = format!("{}{}?{}", api_base, canonical_uri, final_query);

    Json(json!({
        "url": final_url,
        "method": method,
        "expires_in": expires,
    }))
    .into_response()
}

#[derive(Deserialize, Default)]
struct ObjectTagsPayload {
    #[serde(default)]
    tags: Vec<ObjectTagPayload>,
}

#[derive(Deserialize, Default)]
struct ObjectTagPayload {
    #[serde(default, alias = "Key", alias = "key")]
    key: String,
    #[serde(default, alias = "Value", alias = "value")]
    value: String,
}

async fn update_object_tags(state: &AppState, bucket: &str, key: &str, body: Body) -> Response {
    let payload: ObjectTagsPayload = match parse_json_body(body).await {
        Ok(payload) => payload,
        Err(response) => return response,
    };

    if payload.tags.len() > state.config.object_tag_limit {
        return json_error(
            StatusCode::BAD_REQUEST,
            format!("Maximum {} tags allowed", state.config.object_tag_limit),
        );
    }

    let tags = payload
        .tags
        .iter()
        .filter(|tag| !tag.key.trim().is_empty())
        .map(|tag| Tag {
            key: tag.key.trim().to_string(),
            value: tag.value.to_string(),
        })
        .collect::<Vec<_>>();

    let result = if tags.is_empty() {
        state.storage.delete_object_tags(bucket, key).await
    } else {
        state.storage.set_object_tags(bucket, key, &tags).await
    };

    match result {
        Ok(()) => Json(json!({
            "status": "ok",
            "message": "Tags saved",
            "tags": tags.into_iter().map(|tag| json!({ "Key": tag.key, "Value": tag.value })).collect::<Vec<_>>(),
        }))
        .into_response(),
        Err(err) => storage_json_error(err),
    }
}

#[derive(Deserialize, Default)]
struct CopyMovePayload {
    #[serde(default)]
    dest_bucket: String,
    #[serde(default)]
    dest_key: String,
}

async fn copy_object_json(state: &AppState, bucket: &str, key: &str, body: Body) -> Response {
    let payload: CopyMovePayload = match parse_json_body(body).await {
        Ok(payload) => payload,
        Err(response) => return response,
    };
    let dest_bucket = payload.dest_bucket.trim();
    let dest_key = payload.dest_key.trim();
    if dest_bucket.is_empty() || dest_key.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            "dest_bucket and dest_key are required",
        );
    }

    match state
        .storage
        .copy_object(bucket, key, dest_bucket, dest_key)
        .await
    {
        Ok(_) => {
            super::trigger_replication(state, dest_bucket, dest_key, "write");
            Json(json!({
                "status": "ok",
                "message": format!("Copied to {}/{}", dest_bucket, dest_key),
                "dest_bucket": dest_bucket,
                "dest_key": dest_key,
            }))
            .into_response()
        }
        Err(err) => storage_json_error(err),
    }
}

async fn move_object_json(state: &AppState, bucket: &str, key: &str, body: Body) -> Response {
    let payload: CopyMovePayload = match parse_json_body(body).await {
        Ok(payload) => payload,
        Err(response) => return response,
    };
    let dest_bucket = payload.dest_bucket.trim();
    let dest_key = payload.dest_key.trim();
    if dest_bucket.is_empty() || dest_key.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            "dest_bucket and dest_key are required",
        );
    }
    if dest_bucket == bucket && dest_key == key {
        return json_error(
            StatusCode::BAD_REQUEST,
            "Cannot move object to the same location",
        );
    }

    match state.storage.copy_object(bucket, key, dest_bucket, dest_key).await {
        Ok(_) => match state.storage.delete_object(bucket, key).await {
            Ok(_) => {
                super::trigger_replication(state, dest_bucket, dest_key, "write");
                super::trigger_replication(state, bucket, key, "delete");
                Json(json!({
                    "status": "ok",
                    "message": format!("Moved to {}/{}", dest_bucket, dest_key),
                    "dest_bucket": dest_bucket,
                    "dest_key": dest_key,
                }))
                .into_response()
            }
            Err(_) => Json(json!({
                "status": "partial",
                "message": format!("Copied to {}/{} but failed to delete source", dest_bucket, dest_key),
                "dest_bucket": dest_bucket,
                "dest_key": dest_key,
            }))
            .into_response(),
        },
        Err(err) => storage_json_error(err),
    }
}

async fn purge_object_versions_for_key(
    state: &AppState,
    bucket: &str,
    key: &str,
) -> Result<(), String> {
    if let Ok(version_dir) = version_dir_for_object(state, bucket, key) {
        if version_dir.exists() {
            std::fs::remove_dir_all(&version_dir).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

async fn delete_object_json(
    state: &AppState,
    bucket: &str,
    key: &str,
    headers: &HeaderMap,
    body: Body,
) -> Response {
    let body_bytes = match to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "Failed to read request body"),
    };

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let form = if content_type.starts_with("application/x-www-form-urlencoded") {
        parse_form_body(&body_bytes)
    } else {
        HashMap::new()
    };
    let purge_versions = parse_bool_flag(form.get("purge_versions").map(|s| s.as_str()));

    if purge_versions {
        if let Err(err) = state.storage.delete_object(bucket, key).await {
            return storage_json_error(err);
        }
        super::trigger_replication(state, bucket, key, "delete");
        if let Err(err) = purge_object_versions_for_key(state, bucket, key).await {
            return json_error(StatusCode::BAD_REQUEST, err);
        }
        return Json(json!({
            "status": "ok",
            "message": format!("Permanently deleted '{}' and all versions", key),
        }))
        .into_response();
    }

    match state.storage.delete_object(bucket, key).await {
        Ok(_) => {
            super::trigger_replication(state, bucket, key, "delete");
            Json(json!({
                "status": "ok",
                "message": format!("Deleted '{}'", key),
            }))
            .into_response()
        }
        Err(err) => storage_json_error(err),
    }
}

async fn restore_object_version_json(
    state: &AppState,
    bucket: &str,
    key: &str,
    version_id: &str,
) -> Response {
    let version_dir = match version_dir_for_object(state, bucket, key) {
        Ok(path) => path,
        Err(err) => return json_error(StatusCode::BAD_REQUEST, err),
    };
    let data_path = version_dir.join(format!("{}.bin", version_id));
    let meta_path = version_dir.join(format!("{}.json", version_id));
    if !data_path.exists() || !meta_path.exists() {
        return json_error(StatusCode::NOT_FOUND, "Version not found");
    }

    let manifest_text = match std::fs::read_to_string(&meta_path) {
        Ok(text) => text,
        Err(err) => return json_error(StatusCode::BAD_REQUEST, err.to_string()),
    };
    let manifest: VersionManifest = match serde_json::from_str(&manifest_text) {
        Ok(manifest) => manifest,
        Err(err) => return json_error(StatusCode::BAD_REQUEST, err.to_string()),
    };

    let live_exists = state.storage.head_object(bucket, key).await.is_ok();
    let versioning_enabled = state
        .storage
        .is_versioning_enabled(bucket)
        .await
        .unwrap_or(false);
    if live_exists {
        if let Err(err) = state.storage.delete_object(bucket, key).await {
            return storage_json_error(err);
        }
    }

    let destination = match object_live_path(state, bucket, key) {
        Ok(path) => path,
        Err(err) => return json_error(StatusCode::BAD_REQUEST, err),
    };
    if let Some(parent) = destination.parent() {
        if let Err(err) = tokio::fs::create_dir_all(parent).await {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
        }
    }
    if let Err(err) = tokio::fs::copy(&data_path, &destination).await {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
    }
    if let Err(err) = state
        .storage
        .put_object_metadata(bucket, key, &manifest.metadata)
        .await
    {
        return storage_json_error(err);
    }
    super::trigger_replication(state, bucket, key, "write");

    let mut message = format!("Restored '{}'", key);
    if live_exists && versioning_enabled {
        message.push_str(" (previous current version was archived)");
    }
    Json(json!({ "status": "ok", "message": message })).into_response()
}

#[derive(Debug, Clone, Copy)]
enum ObjectGetAction {
    Download,
    Preview,
    Metadata,
    Versions,
    Tags,
}

#[derive(Debug, Clone)]
enum ObjectPostAction {
    Delete,
    Presign,
    Tags,
    Copy,
    Move,
    Restore(String),
}

fn parse_object_get_action(rest: &str) -> Option<(String, ObjectGetAction)> {
    for (suffix, action) in [
        ("/download", ObjectGetAction::Download),
        ("/preview", ObjectGetAction::Preview),
        ("/metadata", ObjectGetAction::Metadata),
        ("/versions", ObjectGetAction::Versions),
        ("/tags", ObjectGetAction::Tags),
    ] {
        if let Some(key) = rest.strip_suffix(suffix) {
            return Some((key.to_string(), action));
        }
    }
    None
}

fn parse_object_post_action(rest: &str) -> Option<(String, ObjectPostAction)> {
    if let Some((key, version_id)) = rest.rsplit_once("/restore/") {
        return Some((
            key.to_string(),
            ObjectPostAction::Restore(version_id.to_string()),
        ));
    }
    if let Some(key_with_version) = rest.strip_suffix("/restore") {
        if let Some((key, version_id)) = key_with_version.rsplit_once("/versions/") {
            return Some((
                key.to_string(),
                ObjectPostAction::Restore(version_id.to_string()),
            ));
        }
    }
    for (suffix, action) in [
        ("/delete", ObjectPostAction::Delete),
        ("/presign", ObjectPostAction::Presign),
        ("/tags", ObjectPostAction::Tags),
        ("/copy", ObjectPostAction::Copy),
        ("/move", ObjectPostAction::Move),
    ] {
        if let Some(key) = rest.strip_suffix(suffix) {
            return Some((key.to_string(), action));
        }
    }
    None
}

pub async fn object_get_dispatch(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
    Path((bucket_name, rest)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let Some((key, action)) = parse_object_get_action(&rest) else {
        return json_error(StatusCode::NOT_FOUND, "Unknown object action");
    };

    match action {
        ObjectGetAction::Download => {
            serve_object_download_or_preview(state, bucket_name, key, headers, true).await
        }
        ObjectGetAction::Preview => {
            serve_object_download_or_preview(state, bucket_name, key, headers, false).await
        }
        ObjectGetAction::Metadata => object_metadata_json(&state, &bucket_name, &key).await,
        ObjectGetAction::Versions => object_versions_json(&state, &bucket_name, &key).await,
        ObjectGetAction::Tags => {
            let _ = session;
            object_tags_json(&state, &bucket_name, &key).await
        }
    }
}

pub async fn object_post_dispatch(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
    Path((bucket_name, rest)): Path<(String, String)>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some((key, action)) = parse_object_post_action(&rest) else {
        return json_error(StatusCode::NOT_FOUND, "Unknown object action");
    };

    match action {
        ObjectPostAction::Delete => {
            delete_object_json(&state, &bucket_name, &key, &headers, body).await
        }
        ObjectPostAction::Presign => {
            object_presign_json(&state, &session, &bucket_name, &key, body).await
        }
        ObjectPostAction::Tags => update_object_tags(&state, &bucket_name, &key, body).await,
        ObjectPostAction::Copy => copy_object_json(&state, &bucket_name, &key, body).await,
        ObjectPostAction::Move => move_object_json(&state, &bucket_name, &key, body).await,
        ObjectPostAction::Restore(version_id) => {
            restore_object_version_json(&state, &bucket_name, &key, &version_id).await
        }
    }
}

#[derive(Deserialize, Default)]
struct BulkKeysPayload {
    #[serde(default)]
    keys: Vec<String>,
    #[serde(default)]
    purge_versions: bool,
}

async fn expand_bulk_keys(
    state: &AppState,
    bucket: &str,
    keys: &[String],
) -> Result<Vec<String>, StorageError> {
    let mut expanded = Vec::new();
    for key in keys {
        if key.ends_with('/') {
            let params = ListParams {
                max_keys: 5000,
                continuation_token: None,
                prefix: Some(key.clone()),
                start_after: None,
            };
            let objects = state.storage.list_objects(bucket, &params).await?;
            for object in objects.objects {
                expanded.push(object.key);
            }
        } else {
            expanded.push(key.clone());
        }
    }
    let mut unique = BTreeMap::new();
    for key in expanded {
        unique.entry(key.clone()).or_insert(key);
    }
    Ok(unique.into_values().collect())
}

pub async fn bulk_delete_objects(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    Path(bucket_name): Path<String>,
    body: Body,
) -> Response {
    let payload: BulkKeysPayload = match parse_json_body(body).await {
        Ok(payload) => payload,
        Err(response) => return response,
    };

    let cleaned = payload
        .keys
        .into_iter()
        .map(|key| key.trim().to_string())
        .filter(|key| !key.is_empty())
        .collect::<Vec<_>>();
    if cleaned.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            "Select at least one object to delete",
        );
    }

    let keys = match expand_bulk_keys(&state, &bucket_name, &cleaned).await {
        Ok(keys) => keys,
        Err(err) => return storage_json_error(err),
    };
    if keys.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            "No objects found under the selected folders",
        );
    }
    if keys.len() > state.config.bulk_delete_max_keys {
        return json_error(
            StatusCode::BAD_REQUEST,
            format!(
                "Bulk delete supports at most {} keys",
                state.config.bulk_delete_max_keys
            ),
        );
    }

    let mut deleted = Vec::new();
    let mut errors = Vec::new();

    for key in keys {
        match state.storage.delete_object(&bucket_name, &key).await {
            Ok(_) => {
                super::trigger_replication(&state, &bucket_name, &key, "delete");
                if payload.purge_versions {
                    if let Err(err) =
                        purge_object_versions_for_key(&state, &bucket_name, &key).await
                    {
                        errors.push(json!({ "key": key, "error": err }));
                        continue;
                    }
                }
                deleted.push(key);
            }
            Err(err) => errors.push(json!({ "key": key, "error": err.to_string() })),
        }
    }

    if deleted.is_empty() && !errors.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status": "error",
                "message": "Unable to delete the selected objects",
                "deleted": deleted,
                "errors": errors,
            })),
        )
            .into_response();
    }

    let mut message = format!(
        "Deleted {} object{}",
        deleted.len(),
        if deleted.len() == 1 { "" } else { "s" }
    );
    if payload.purge_versions && !deleted.is_empty() {
        message.push_str(" (including archived versions)");
    }
    if !errors.is_empty() {
        message.push_str(&format!("; {} failed", errors.len()));
    }

    Json(json!({
        "status": if errors.is_empty() { "ok" } else { "partial" },
        "message": message,
        "deleted": deleted,
        "errors": errors,
    }))
    .into_response()
}

pub async fn bulk_download_objects(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    Path(bucket_name): Path<String>,
    body: Body,
) -> Response {
    let payload: BulkKeysPayload = match parse_json_body(body).await {
        Ok(payload) => payload,
        Err(response) => return response,
    };

    let cleaned = payload
        .keys
        .into_iter()
        .map(|key| key.trim().to_string())
        .filter(|key| !key.is_empty())
        .collect::<Vec<_>>();
    if cleaned.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            "Select at least one object to download",
        );
    }

    let keys = match expand_bulk_keys(&state, &bucket_name, &cleaned).await {
        Ok(keys) => keys,
        Err(err) => return storage_json_error(err),
    };
    if keys.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            "No objects found under the selected folders",
        );
    }

    let mut total_bytes = 0u64;
    let mut archive_entries = Vec::new();
    for key in keys {
        match state.storage.head_object(&bucket_name, &key).await {
            Ok(meta) => {
                total_bytes = total_bytes.saturating_add(meta.size);
                match read_object_bytes_for_zip(&state, &bucket_name, &key).await {
                    Ok(bytes) => archive_entries.push((key, bytes, meta.last_modified)),
                    Err(err) => return json_error(StatusCode::BAD_REQUEST, err),
                }
            }
            Err(err) => return storage_json_error(err),
        }
    }

    let max_total_bytes = 256 * 1024 * 1024u64;
    if total_bytes > max_total_bytes {
        return json_error(
            StatusCode::BAD_REQUEST,
            "Total download size exceeds 256 MB limit. Select fewer objects.",
        );
    }

    let zip_bytes = match build_zip_archive(archive_entries) {
        Ok(bytes) => bytes,
        Err(err) => return json_error(StatusCode::BAD_REQUEST, err),
    };

    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "application/zip".parse().unwrap());
    headers.insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{}-download.zip\"", bucket_name)
            .parse()
            .unwrap(),
    );
    (StatusCode::OK, headers, zip_bytes).into_response()
}

pub async fn archived_objects(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    Path(bucket_name): Path<String>,
) -> Response {
    let versions_root = version_root_for_bucket(&state, &bucket_name);
    if !versions_root.exists() {
        return Json(json!({ "objects": [] })).into_response();
    }

    let mut grouped: BTreeMap<String, Vec<VersionManifest>> = BTreeMap::new();
    let mut stack = vec![versions_root];

    while let Some(current) = stack.pop() {
        let read_dir = match std::fs::read_dir(&current) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in read_dir.flatten() {
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(_) => continue,
            };
            if file_type.is_dir() {
                stack.push(entry.path());
                continue;
            }
            if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let text = match std::fs::read_to_string(entry.path()) {
                Ok(text) => text,
                Err(_) => continue,
            };
            let manifest = match serde_json::from_str::<VersionManifest>(&text) {
                Ok(manifest) => manifest,
                Err(_) => continue,
            };
            if manifest.key.is_empty() {
                continue;
            }
            grouped
                .entry(manifest.key.clone())
                .or_default()
                .push(manifest);
        }
    }

    let mut objects = Vec::new();
    for (key, mut versions) in grouped {
        let live_exists = object_live_path(&state, &bucket_name, &key)
            .map(|path| path.exists())
            .unwrap_or(false);
        if live_exists {
            continue;
        }
        versions.sort_by(|a, b| manifest_timestamp(b).cmp(&manifest_timestamp(a)));
        let latest = versions.first().map(|record| manifest_to_json(record));
        objects.push(json!({
            "key": key,
            "versions": versions.len(),
            "total_size": versions.iter().map(|entry| entry.size).sum::<u64>(),
            "latest": latest,
            "restore_url": versions.first().map(|record| format!(
                "/ui/buckets/{}/archived/{}/restore/{}",
                bucket_name,
                encode_object_key(&record.key),
                encode_path_segment(&record.version_id)
            )),
            "purge_url": format!(
                "/ui/buckets/{}/archived/{}/purge",
                bucket_name,
                encode_object_key(&key)
            ),
        }));
    }

    Json(json!({ "objects": objects })).into_response()
}

pub async fn archived_post_dispatch(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    Path((bucket_name, rest)): Path<(String, String)>,
) -> Response {
    if let Some((key, version_id)) = rest.rsplit_once("/restore/") {
        return restore_object_version_json(&state, &bucket_name, key, version_id).await;
    }
    if let Some(key) = rest.strip_suffix("/purge") {
        match purge_object_versions_for_key(&state, &bucket_name, key).await {
            Ok(()) => {
                let _ = state.storage.delete_object(&bucket_name, key).await;
                super::trigger_replication(&state, &bucket_name, key, "delete");
                Json(json!({
                    "status": "ok",
                    "message": format!("Removed archived versions for '{}'", key),
                }))
                .into_response()
            }
            Err(err) => json_error(StatusCode::BAD_REQUEST, err),
        }
    } else {
        json_error(StatusCode::NOT_FOUND, "Unknown archived object action")
    }
}

pub async fn gc_status_ui(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
) -> Response {
    match &state.gc {
        Some(gc) => Json(gc.status().await).into_response(),
        None => Json(json!({
            "enabled": false,
            "message": "GC is not enabled. Set GC_ENABLED=true to enable."
        }))
        .into_response(),
    }
}

pub async fn gc_run_ui(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    body: Body,
) -> Response {
    let Some(gc) = &state.gc else {
        return json_error(StatusCode::BAD_REQUEST, "GC is not enabled");
    };
    let payload: Value = parse_json_body(body).await.unwrap_or_else(|_| json!({}));
    let dry_run = payload
        .get("dry_run")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    match gc.run_now(dry_run).await {
        Ok(result) => Json(result).into_response(),
        Err(err) => json_error(StatusCode::CONFLICT, err),
    }
}

pub async fn gc_history_ui(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let limit = params.get("limit").and_then(|v| v.parse::<usize>().ok());
    match &state.gc {
        Some(gc) => Json(apply_history_limit(gc.history().await, limit)).into_response(),
        None => Json(json!({ "executions": [] })).into_response(),
    }
}

pub async fn integrity_status_ui(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
) -> Response {
    match &state.integrity {
        Some(checker) => Json(checker.status().await).into_response(),
        None => Json(json!({
            "enabled": false,
            "message": "Integrity checker is not enabled. Set INTEGRITY_ENABLED=true to enable."
        }))
        .into_response(),
    }
}

pub async fn integrity_run_ui(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    body: Body,
) -> Response {
    let Some(checker) = &state.integrity else {
        return json_error(StatusCode::BAD_REQUEST, "Integrity checker is not enabled");
    };
    let payload: Value = parse_json_body(body).await.unwrap_or_else(|_| json!({}));
    let dry_run = payload
        .get("dry_run")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let auto_heal = payload
        .get("auto_heal")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    match checker.run_now(dry_run, auto_heal).await {
        Ok(result) => Json(result).into_response(),
        Err(err) => json_error(StatusCode::CONFLICT, err),
    }
}

pub async fn integrity_history_ui(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let limit = params.get("limit").and_then(|v| v.parse::<usize>().ok());
    match &state.integrity {
        Some(checker) => Json(apply_history_limit(checker.history().await, limit)).into_response(),
        None => Json(json!({ "executions": [] })).into_response(),
    }
}

fn apply_history_limit(mut value: Value, limit: Option<usize>) -> Value {
    if let Some(limit) = limit {
        if let Some(arr) = value.get_mut("executions").and_then(|v| v.as_array_mut()) {
            if arr.len() > limit {
                arr.truncate(limit);
            }
        }
    }
    value
}

pub async fn lifecycle_history(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    Path(bucket_name): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let limit = params
        .get("limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(50);
    let offset = params
        .get("offset")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    if !state.config.lifecycle_enabled {
        return Json(json!({
            "executions": [],
            "total": 0,
            "limit": limit,
            "offset": offset,
            "enabled": false,
        }))
        .into_response();
    }
    Json(crate::services::lifecycle::read_history(
        &state.config.storage_root,
        &bucket_name,
        limit,
        offset,
    ))
    .into_response()
}

#[derive(Deserialize, Default)]
pub struct ReplicationFailuresQuery {
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub offset: Option<usize>,
}

#[derive(Deserialize)]
pub struct ReplicationObjectKeyQuery {
    pub object_key: String,
}

pub async fn replication_status(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    Path(bucket_name): Path<String>,
) -> Response {
    let Some(rule) = state.replication.get_rule(&bucket_name) else {
        return json_error(StatusCode::NOT_FOUND, "No replication rule");
    };

    let (endpoint_healthy, endpoint_error) = match state.connections.get(&rule.target_connection_id)
    {
        Some(conn) => {
            let healthy = state.replication.check_endpoint(&conn).await;
            let error = if healthy {
                None
            } else {
                Some(format!("Cannot reach endpoint: {}", conn.endpoint_url))
            };
            (healthy, error)
        }
        None => (false, Some("Target connection not found".to_string())),
    };

    json_ok(json!({
        "enabled": rule.enabled,
        "target_bucket": rule.target_bucket,
        "target_connection_id": rule.target_connection_id,
        "mode": rule.mode,
        "objects_synced": rule.stats.objects_synced,
        "objects_pending": rule.stats.objects_pending,
        "objects_orphaned": rule.stats.objects_orphaned,
        "bytes_synced": rule.stats.bytes_synced,
        "last_sync_at": rule.stats.last_sync_at,
        "last_sync_key": rule.stats.last_sync_key,
        "endpoint_healthy": endpoint_healthy,
        "endpoint_error": endpoint_error,
    }))
}

pub async fn replication_failures(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    Path(bucket_name): Path<String>,
    Query(q): Query<ReplicationFailuresQuery>,
) -> Response {
    let limit = q.limit.unwrap_or(50).clamp(1, 500);
    let offset = q.offset.unwrap_or(0);
    let failures = state
        .replication
        .get_failed_items(&bucket_name, limit, offset);
    let total = state.replication.get_failure_count(&bucket_name);
    json_ok(json!({
        "failures": failures,
        "total": total,
        "limit": limit,
        "offset": offset,
    }))
}

pub async fn retry_replication_failure(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    Path(bucket_name): Path<String>,
    Query(q): Query<ReplicationObjectKeyQuery>,
) -> Response {
    retry_replication_failure_key(&state, &bucket_name, q.object_key.trim()).await
}

pub async fn retry_replication_failure_path(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    Path((bucket_name, rest)): Path<(String, String)>,
) -> Response {
    let Some(object_key) = rest.strip_suffix("/retry") else {
        return json_error(StatusCode::NOT_FOUND, "Unknown replication failure action");
    };
    retry_replication_failure_key(&state, &bucket_name, object_key.trim()).await
}

async fn retry_replication_failure_key(
    state: &AppState,
    bucket_name: &str,
    object_key: &str,
) -> Response {
    if object_key.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "object_key is required");
    }

    if state
        .replication
        .retry_failed(bucket_name, object_key)
        .await
    {
        json_ok(json!({
            "status": "submitted",
            "object_key": object_key,
        }))
    } else {
        json_error(StatusCode::BAD_REQUEST, "Failed to submit retry")
    }
}

pub async fn retry_all_replication_failures(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    Path(bucket_name): Path<String>,
) -> Response {
    let (submitted, skipped) = state.replication.retry_all(&bucket_name).await;
    json_ok(json!({
        "status": "submitted",
        "submitted": submitted,
        "skipped": skipped,
    }))
}

pub async fn dismiss_replication_failure(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    Path(bucket_name): Path<String>,
    Query(q): Query<ReplicationObjectKeyQuery>,
) -> Response {
    dismiss_replication_failure_key(&state, &bucket_name, q.object_key.trim())
}

pub async fn dismiss_replication_failure_path(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    Path((bucket_name, object_key)): Path<(String, String)>,
) -> Response {
    dismiss_replication_failure_key(&state, &bucket_name, object_key.trim())
}

fn dismiss_replication_failure_key(
    state: &AppState,
    bucket_name: &str,
    object_key: &str,
) -> Response {
    if object_key.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "object_key is required");
    }

    if state.replication.dismiss_failure(bucket_name, object_key) {
        json_ok(json!({
            "status": "dismissed",
            "object_key": object_key,
        }))
    } else {
        json_error(StatusCode::NOT_FOUND, "Failure not found")
    }
}

pub async fn clear_replication_failures(
    State(state): State<AppState>,
    Extension(_session): Extension<SessionHandle>,
    Path(bucket_name): Path<String>,
) -> Response {
    state.replication.clear_failures(&bucket_name);
    json_ok(json!({ "status": "cleared" }))
}

static SERVER_START_TIME: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
static SYSINFO: std::sync::OnceLock<Mutex<System>> = std::sync::OnceLock::new();

async fn sample_system() -> (f64, u64, u64) {
    let lock = SYSINFO.get_or_init(|| {
        let mut system = System::new();
        system.refresh_cpu_usage();
        system.refresh_memory();
        Mutex::new(system)
    });
    {
        let mut system = lock.lock().unwrap();
        system.refresh_cpu_usage();
    }
    tokio::time::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL).await;
    let mut system = lock.lock().unwrap();
    system.refresh_cpu_usage();
    system.refresh_memory();
    let cpu_percent = system.global_cpu_usage() as f64;
    let mem_total = system.total_memory();
    let mem_used = system.used_memory();
    (cpu_percent, mem_used, mem_total)
}

fn normalize_path_for_mount(path: &FsPath) -> String {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let raw = canonical.to_string_lossy().to_string();
    let stripped = raw.strip_prefix(r"\\?\").unwrap_or(&raw);
    stripped.to_lowercase()
}

fn sample_disk(path: &FsPath) -> (u64, u64) {
    let disks = Disks::new_with_refreshed_list();
    let path_str = normalize_path_for_mount(path);
    let mut best: Option<(usize, u64, u64)> = None;
    for disk in disks.list() {
        let mount_raw = disk.mount_point().to_string_lossy().to_string();
        let mount = mount_raw
            .strip_prefix(r"\\?\")
            .unwrap_or(&mount_raw)
            .to_lowercase();
        let total = disk.total_space();
        let free = disk.available_space();
        if path_str.starts_with(&mount) {
            let len = mount.len();
            match best {
                Some((best_len, _, _)) if len <= best_len => {}
                _ => best = Some((len, total, free)),
            }
        }
    }
    best.map(|(_, total, free)| (total, free)).unwrap_or((0, 0))
}

pub async fn collect_metrics(state: &AppState) -> Value {
    let start_time = *SERVER_START_TIME.get_or_init(std::time::Instant::now);
    let uptime_days = start_time.elapsed().as_secs_f64() / 86400.0;

    let buckets_list = state.storage.list_buckets().await.unwrap_or_default();
    let bucket_count = buckets_list.len() as u64;

    let mut total_objects: u64 = 0;
    let mut total_bytes: u64 = 0;
    let mut total_versions: u64 = 0;
    for bucket in &buckets_list {
        if let Ok(stats) = state.storage.bucket_stats(&bucket.name).await {
            total_objects += stats.objects;
            total_bytes += stats.bytes;
            total_versions += stats.version_count;
        }
    }

    let (cpu_percent, mem_used, mem_total) = sample_system().await;
    let mem_pct = if mem_total > 0 {
        (mem_used as f64 / mem_total as f64) * 100.0
    } else {
        0.0
    };

    let (disk_total, disk_free) = sample_disk(&state.config.storage_root);
    let disk_used = disk_total.saturating_sub(disk_free);
    let disk_pct = if disk_total > 0 {
        (disk_used as f64 / disk_total as f64) * 100.0
    } else {
        0.0
    };

    json!({
        "cpu_percent": cpu_percent,
        "memory": {
            "percent": mem_pct,
            "used": human_size(mem_used),
            "total": human_size(mem_total),
        },
        "disk": {
            "percent": disk_pct,
            "free": human_size(disk_free),
            "total": human_size(disk_total),
        },
        "app": {
            "storage_used": human_size(total_bytes),
            "buckets": bucket_count,
            "objects": total_objects,
            "versions": total_versions,
            "uptime_days": uptime_days.floor() as u64,
        },
    })
}

pub async fn metrics_api(State(state): State<AppState>) -> Response {
    Json(collect_metrics(&state).await).into_response()
}

#[derive(Deserialize, Default)]
pub struct HoursQuery {
    #[serde(default)]
    pub hours: Option<u64>,
}

pub async fn metrics_history(
    State(state): State<AppState>,
    Query(q): Query<HoursQuery>,
) -> Response {
    let settings = metrics_settings_snapshot(&state);
    match &state.system_metrics {
        Some(metrics) => Json(json!({
            "enabled": settings.enabled,
            "history": metrics.get_history(q.hours).await,
            "interval_minutes": settings.interval_minutes,
            "retention_hours": settings.retention_hours,
            "hours_requested": q.hours.unwrap_or(settings.retention_hours),
        }))
        .into_response(),
        None => Json(json!({
            "enabled": settings.enabled,
            "history": [],
            "interval_minutes": settings.interval_minutes,
            "retention_hours": settings.retention_hours,
            "hours_requested": q.hours.unwrap_or(settings.retention_hours),
        }))
        .into_response(),
    }
}

pub async fn metrics_operations(State(state): State<AppState>) -> Response {
    match &state.metrics {
        Some(metrics) => {
            let stats = metrics.get_current_stats();
            Json(json!({
                "enabled": true,
                "stats": stats,
            }))
            .into_response()
        }
        None => Json(json!({
            "enabled": false,
            "stats": null,
        }))
        .into_response(),
    }
}

pub async fn metrics_operations_history(
    State(state): State<AppState>,
    Query(q): Query<HoursQuery>,
) -> Response {
    match &state.metrics {
        Some(metrics) => {
            let history = metrics.get_history(q.hours.or(Some(24)));
            Json(json!({
                "enabled": true,
                "history": history,
                "interval_minutes": 5,
            }))
            .into_response()
        }
        None => Json(json!({
            "enabled": false,
            "history": [],
            "interval_minutes": 5,
        }))
        .into_response(),
    }
}
