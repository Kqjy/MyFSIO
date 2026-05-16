pub mod admin;
pub mod admin_peer;
mod chunked;
mod config;
pub mod kms;
mod select;
pub mod static_assets;
pub mod ui;
pub mod ui_api;
pub mod ui_pages;

use std::collections::HashMap;

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use base64::Engine;
use chrono::{DateTime, Utc};
use md5::Md5;
use percent_encoding::percent_decode_str;
use serde_json::json;
use sha2::{Digest, Sha256};

use myfsio_common::error::{S3Error, S3ErrorCode};
use myfsio_common::types::PartInfo;
use myfsio_storage::traits::StorageEngine;
use tokio::io::AsyncSeekExt;
use tokio_util::io::ReaderStream;

use crate::services::notifications;
use crate::services::object_lock;
use crate::state::AppState;

async fn open_self_deleting(path: std::path::PathBuf) -> std::io::Result<tokio::fs::File> {
    #[cfg(unix)]
    {
        let file = tokio::fs::File::open(&path).await?;
        let _ = tokio::fs::remove_file(&path).await;
        Ok(file)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x0400_0000;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_SHARE_WRITE: u32 = 0x0000_0002;
        const FILE_SHARE_DELETE: u32 = 0x0000_0004;
        let file = tokio::task::spawn_blocking(move || {
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(FILE_FLAG_DELETE_ON_CLOSE)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .open(&path)
        })
        .await
        .map_err(std::io::Error::other)??;
        Ok(tokio::fs::File::from_std(file))
    }
}

fn parse_max_keys(raw: &str) -> Result<usize, Response> {
    match raw.parse::<i64>() {
        Ok(v) if (0..=2_147_483_647).contains(&v) => Ok(v as usize),
        _ => Err(s3_error_response(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "Argument max-keys must be an integer between 0 and 2147483647",
        ))),
    }
}

pub(crate) fn s3_error_response(err: S3Error) -> Response {
    crate::s3_response::s3_error_response(err)
}

pub(crate) const CANONICAL_DEFAULT_OWNER_ID: &str = "myfsio";

fn canonical_default_owner(state: &AppState) -> (String, String) {
    let id = CANONICAL_DEFAULT_OWNER_ID.to_string();
    let display = state
        .iam
        .get_display_name(&id)
        .unwrap_or_else(|| id.clone());
    (id, display)
}

fn build_owner_display_map(
    state: &AppState,
    objects: &[myfsio_common::types::ObjectMeta],
) -> HashMap<String, String> {
    let mut seen: HashMap<String, String> = HashMap::new();
    for obj in objects {
        if let Some(owner) = obj.owner.as_deref() {
            if seen.contains_key(owner) {
                continue;
            }
            let display = state
                .iam
                .get_display_name(owner)
                .unwrap_or_else(|| owner.to_string());
            seen.insert(owner.to_string(), display);
        }
    }
    seen
}

fn storage_err_response(err: myfsio_storage::error::StorageError) -> Response {
    if let myfsio_storage::error::StorageError::Io(io_err) = &err {
        if let Some(message) = crate::middleware::sha_body::sha256_mismatch_message(io_err) {
            return bad_digest_response(message);
        }
        if let Some(response) = io_error_to_s3_response(io_err) {
            return response;
        }
    }
    if let myfsio_storage::error::StorageError::DeleteMarker {
        bucket,
        key,
        version_id,
    } = &err
    {
        let s3_err = S3Error::from_code(S3ErrorCode::NoSuchKey)
            .with_resource(format!("/{}/{}", bucket, key));
        let mut extra = HeaderMap::new();
        extra.insert("x-amz-delete-marker", "true".parse().unwrap());
        if let Ok(vid) = version_id.parse() {
            extra.insert("x-amz-version-id", vid);
        }
        return crate::s3_response::s3_error_response_with_headers(s3_err, extra);
    }
    s3_error_response(S3Error::from(err))
}

fn io_error_to_s3_response(err: &std::io::Error) -> Option<Response> {
    use std::io::ErrorKind;
    let message = err.to_string();
    let lower = message.to_ascii_lowercase();
    let hit_collision = matches!(
        err.kind(),
        ErrorKind::NotADirectory
            | ErrorKind::IsADirectory
            | ErrorKind::AlreadyExists
            | ErrorKind::DirectoryNotEmpty
    ) || lower.contains("not a directory")
        || lower.contains("is a directory")
        || lower.contains("file exists")
        || lower.contains("directory not empty");
    let hit_name_too_long =
        matches!(err.kind(), ErrorKind::InvalidFilename) || lower.contains("file name too long");
    if !hit_collision && !hit_name_too_long {
        return None;
    }
    let code = if hit_name_too_long {
        S3ErrorCode::InvalidKey
    } else {
        S3ErrorCode::InvalidRequest
    };
    let detail = if hit_name_too_long {
        "Object key exceeds the filesystem's per-segment length limit"
    } else {
        "Object key collides with an existing object path on the storage backend"
    };
    Some(s3_error_response(S3Error::new(code, detail)))
}

fn trigger_replication(state: &AppState, bucket: &str, key: &str, action: &str) {
    let manager = state.replication.clone();
    let bucket = bucket.to_string();
    let key = key.to_string();
    let action = action.to_string();
    tokio::spawn(async move {
        manager.trigger(bucket, key, action).await;
    });
}

fn trigger_replication_for_request(
    state: &AppState,
    peer_marker: Option<&crate::middleware::ReplicationPeerRequest>,
    bucket: &str,
    key: &str,
    action: &str,
) {
    if peer_marker.is_some() {
        return;
    }
    trigger_replication(state, bucket, key, action);
}

#[derive(Debug, Clone)]
pub struct RelayContext {
    pub origin_site_id: String,
    pub admin_user_id: String,
    pub idempotency_key: String,
    pub correlation_id: String,
}

async fn ensure_object_lock_allows_write(
    state: &AppState,
    bucket: &str,
    key: &str,
    headers: Option<&HeaderMap>,
) -> Result<(), Response> {
    let head_res = state.storage.head_object(bucket, key).await;
    let needs_lock_check = match &head_res {
        Ok(_) => true,
        Err(myfsio_storage::error::StorageError::ObjectCorrupted { .. }) => true,
        Err(myfsio_storage::error::StorageError::ObjectNotFound { .. }) => return Ok(()),
        Err(myfsio_storage::error::StorageError::DeleteMarker { .. }) => return Ok(()),
        Err(_) => false,
    };
    if !needs_lock_check {
        return Err(storage_err_response(head_res.err().unwrap()));
    }

    let metadata = match state.storage.get_object_metadata(bucket, key).await {
        Ok(metadata) => metadata,
        Err(err) => return Err(storage_err_response(err)),
    };
    let bypass_governance = headers
        .and_then(|headers| {
            headers
                .get("x-amz-bypass-governance-retention")
                .and_then(|value| value.to_str().ok())
        })
        .map(|value| value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if let Err(message) = object_lock::can_delete_object(&metadata, bypass_governance) {
        return Err(s3_error_response(S3Error::new(
            S3ErrorCode::AccessDenied,
            message,
        )));
    }
    Ok(())
}

async fn ensure_archived_null_lock_allows_overwrite(
    state: &AppState,
    bucket: &str,
    key: &str,
    headers: Option<&HeaderMap>,
) -> Result<(), Response> {
    let status = match state.storage.get_versioning_status(bucket).await {
        Ok(status) => status,
        Err(myfsio_storage::error::StorageError::BucketNotFound(_)) => return Ok(()),
        Err(err) => return Err(storage_err_response(err)),
    };
    if !matches!(status, myfsio_common::types::VersioningStatus::Suspended) {
        return Ok(());
    }
    let metadata = match state
        .storage
        .get_archived_null_version_metadata(bucket, key)
        .await
    {
        Ok(Some(metadata)) => metadata,
        Ok(None) => return Ok(()),
        Err(err) => return Err(storage_err_response(err)),
    };
    let bypass_governance = headers
        .and_then(|headers| {
            headers
                .get("x-amz-bypass-governance-retention")
                .and_then(|value| value.to_str().ok())
        })
        .map(|value| value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if let Err(message) = object_lock::can_delete_object(&metadata, bypass_governance) {
        return Err(s3_error_response(S3Error::new(
            S3ErrorCode::AccessDenied,
            message,
        )));
    }
    Ok(())
}

async fn ensure_object_version_lock_allows_delete(
    state: &AppState,
    bucket: &str,
    key: &str,
    version_id: &str,
    headers: &HeaderMap,
) -> Result<(), Response> {
    let metadata = match state
        .storage
        .get_object_version_metadata(bucket, key, version_id)
        .await
    {
        Ok(metadata) => metadata,
        Err(err) => return Err(storage_err_response(err)),
    };
    let bypass_governance = headers
        .get("x-amz-bypass-governance-retention")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if let Err(message) = object_lock::can_delete_object(&metadata, bypass_governance) {
        return Err(s3_error_response(S3Error::new(
            S3ErrorCode::AccessDenied,
            message,
        )));
    }
    Ok(())
}

pub async fn list_buckets(
    State(state): State<AppState>,
    Query(query): Query<BucketQuery>,
    headers: HeaderMap,
    request: axum::extract::Request,
) -> Response {
    if let Some(host_bucket) = virtual_host_bucket_from_headers(&state, &headers).await {
        return get_bucket(State(state), Path(host_bucket), Query(query), headers).await;
    }

    let (owner_id, owner_display) = caller_owner(&state, &request);

    match state.storage.list_buckets().await {
        Ok(buckets) => {
            let xml = myfsio_xml::response::list_buckets_xml(
                &owner_id,
                &owner_display,
                &buckets,
                &state.config.region,
            );
            (StatusCode::OK, [("content-type", "application/xml")], xml).into_response()
        }
        Err(e) => storage_err_response(e),
    }
}

fn caller_owner(_state: &AppState, request: &axum::extract::Request) -> (String, String) {
    if let Some(principal) = request
        .extensions()
        .get::<myfsio_common::types::Principal>()
    {
        return (principal.user_id.clone(), principal.display_name.clone());
    }
    ("myfsio".to_string(), "myfsio".to_string())
}

pub async fn health_check() -> Response {
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        json!({
            "status": "ok",
            "version": env!("CARGO_PKG_VERSION"),
        })
        .to_string(),
    )
        .into_response()
}

pub async fn create_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(query): Query<BucketQuery>,
    raw_query: axum::extract::RawQuery,
    peer: Option<axum::extract::Extension<crate::middleware::ReplicationPeerRequest>>,
    principal: Option<axum::extract::Extension<myfsio_common::types::Principal>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if let Some(host_bucket) = virtual_host_bucket_from_headers(&state, &headers).await {
        if host_bucket != bucket {
            return put_object(
                State(state),
                Path((host_bucket, bucket)),
                Query(ObjectQuery::default()),
                peer,
                principal,
                headers,
                body,
            )
            .await;
        }
    }

    if let Some(unsupported) = unsupported_bucket_subresource(raw_query.0.as_deref()) {
        return s3_error_response(S3Error::new(
            S3ErrorCode::NotImplemented,
            format!(
                "The bucket subresource '?{}' is not implemented by this server",
                unsupported
            ),
        ));
    }

    if query.quota.is_some() {
        return config::put_quota(&state, &bucket, body).await;
    }
    if query.versioning.is_some() {
        return config::put_versioning(&state, &bucket, body).await;
    }
    if query.tagging.is_some() {
        return config::put_tagging(&state, &bucket, body).await;
    }
    if query.cors.is_some() {
        return config::put_cors(&state, &bucket, body).await;
    }
    if query.encryption.is_some() {
        return config::put_encryption(&state, &bucket, body).await;
    }
    if query.lifecycle.is_some() {
        return config::put_lifecycle(&state, &bucket, body).await;
    }
    if query.acl.is_some() {
        return config::put_acl(&state, &bucket, body).await;
    }
    if query.policy.is_some() {
        return config::put_policy(&state, &bucket, body).await;
    }
    if query.replication.is_some() {
        return config::put_replication(&state, &bucket, body).await;
    }
    if query.website.is_some() {
        return config::put_website(&state, &bucket, body).await;
    }
    if query.object_lock.is_some() {
        return config::put_object_lock(&state, &bucket, body).await;
    }
    if query.ownership_controls.is_some() {
        return config::put_ownership_controls(&state, &bucket, body).await;
    }
    if query.public_access_block.is_some() {
        return config::put_public_access_block(&state, &bucket, body).await;
    }
    if query.notification.is_some() {
        return config::put_notification(&state, &bucket, body).await;
    }
    if query.logging.is_some() {
        return config::put_logging(&state, &bucket, body).await;
    }

    if let Err(resp) = canned_acl_value(&headers) {
        return resp;
    }

    let body_bytes = match http_body_util::BodyExt::collect(body).await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return s3_error_response(S3Error::new(
                S3ErrorCode::InvalidRequest,
                "Failed to read request body",
            ));
        }
    };

    if let Some(constraint) = parse_location_constraint(&body_bytes) {
        if let Err(resp) = validate_location_constraint(&state, &constraint) {
            return resp;
        }
    }

    match state.storage.create_bucket(&bucket).await {
        Ok(()) => (
            StatusCode::OK,
            [("location", format!("/{}", bucket).as_str())],
            "",
        )
            .into_response(),
        Err(e) => storage_err_response(e),
    }
}

fn parse_location_constraint(body: &[u8]) -> Option<String> {
    if body.is_empty() {
        return None;
    }
    let text = std::str::from_utf8(body).ok()?;
    let lower = text.to_ascii_lowercase();
    let open_idx = lower.find("<locationconstraint")?;
    let after_open = &text[open_idx..];
    let gt = after_open.find('>')?;
    let value_start = open_idx + gt + 1;
    let close_idx = lower[value_start..].find("</locationconstraint")?;
    let raw = text[value_start..value_start + close_idx].trim();
    if raw.is_empty() {
        None
    } else {
        Some(raw.to_string())
    }
}

fn validate_location_constraint(state: &AppState, constraint: &str) -> Result<(), Response> {
    if constraint.eq_ignore_ascii_case(&state.config.region) {
        return Ok(());
    }
    Err(s3_error_response(S3Error::new(
        S3ErrorCode::InvalidLocationConstraint,
        format!(
            "The specified location-constraint '{}' is not compatible with the endpoint region '{}'",
            constraint, state.config.region
        ),
    )))
}

#[derive(serde::Deserialize, Default)]
pub struct BucketQuery {
    #[serde(rename = "list-type")]
    pub list_type: Option<String>,
    pub marker: Option<String>,
    pub prefix: Option<String>,
    pub delimiter: Option<String>,
    #[serde(rename = "max-keys")]
    pub max_keys: Option<String>,
    #[serde(rename = "continuation-token")]
    pub continuation_token: Option<String>,
    #[serde(rename = "start-after")]
    pub start_after: Option<String>,
    #[serde(rename = "encoding-type")]
    pub encoding_type: Option<String>,
    #[serde(rename = "fetch-owner")]
    pub fetch_owner: Option<String>,
    pub uploads: Option<String>,
    pub delete: Option<String>,
    pub versioning: Option<String>,
    pub tagging: Option<String>,
    pub cors: Option<String>,
    pub location: Option<String>,
    pub encryption: Option<String>,
    pub lifecycle: Option<String>,
    pub acl: Option<String>,
    pub quota: Option<String>,
    pub policy: Option<String>,
    #[serde(rename = "policyStatus")]
    pub policy_status: Option<String>,
    pub replication: Option<String>,
    pub website: Option<String>,
    #[serde(rename = "object-lock")]
    pub object_lock: Option<String>,
    #[serde(rename = "ownershipControls")]
    pub ownership_controls: Option<String>,
    #[serde(rename = "publicAccessBlock")]
    pub public_access_block: Option<String>,
    pub notification: Option<String>,
    pub logging: Option<String>,
    pub versions: Option<String>,
    #[serde(rename = "key-marker")]
    pub key_marker: Option<String>,
    #[serde(rename = "version-id-marker")]
    pub version_id_marker: Option<String>,
    #[serde(rename = "upload-id-marker")]
    pub upload_id_marker: Option<String>,
    #[serde(rename = "max-uploads")]
    pub max_uploads: Option<usize>,
}

const SUPPORTED_BUCKET_SUBRESOURCES: &[&str] = &[
    "versioning",
    "tagging",
    "cors",
    "encryption",
    "lifecycle",
    "acl",
    "policy",
    "policyStatus",
    "replication",
    "website",
    "object-lock",
    "ownershipControls",
    "publicAccessBlock",
    "notification",
    "logging",
    "quota",
    "location",
    "uploads",
    "delete",
    "versions",
    "list-type",
    "marker",
    "prefix",
    "delimiter",
    "max-keys",
    "max-uploads",
    "continuation-token",
    "start-after",
    "encoding-type",
    "fetch-owner",
    "key-marker",
    "version-id-marker",
    "upload-id-marker",
];

fn unsupported_bucket_subresource(query: Option<&str>) -> Option<String> {
    let q = query?;
    if q.is_empty() {
        return None;
    }
    for part in q.split('&').filter(|p| !p.is_empty()) {
        let key = part.split('=').next().unwrap_or("");
        if key.is_empty() {
            continue;
        }
        let key_owned = key.to_string();
        let lower = key_owned.to_ascii_lowercase();
        let known = SUPPORTED_BUCKET_SUBRESOURCES
            .iter()
            .any(|known| known.eq_ignore_ascii_case(&key_owned))
            || lower.starts_with("x-amz-")
            || lower.starts_with("x-id");
        if !known {
            return Some(key_owned);
        }
    }
    None
}

async fn virtual_host_bucket_from_headers(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let host = headers
        .get("host")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(':').next())?
        .trim()
        .to_ascii_lowercase();
    let (candidate, _) = host.split_once('.')?;
    if myfsio_storage::validation::validate_bucket_name(candidate).is_some() {
        return None;
    }
    match state.storage.bucket_exists(candidate).await {
        Ok(true) => Some(candidate.to_string()),
        _ => None,
    }
}

pub async fn get_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(query): Query<BucketQuery>,
    headers: HeaderMap,
) -> Response {
    let (owner_id, owner_display) = canonical_default_owner(&state);
    let owner_id_ref = owner_id.as_str();
    let owner_display_ref = owner_display.as_str();
    if let Some(host_bucket) = virtual_host_bucket_from_headers(&state, &headers).await {
        if host_bucket != bucket {
            return get_object(
                State(state),
                Path((host_bucket, bucket)),
                Query(ObjectQuery::default()),
                headers,
            )
            .await;
        }
    }

    if !matches!(state.storage.bucket_exists(&bucket).await, Ok(true)) {
        return storage_err_response(myfsio_storage::error::StorageError::BucketNotFound(bucket));
    }

    if query.quota.is_some() {
        return config::get_quota(&state, &bucket).await;
    }
    if query.versioning.is_some() {
        return config::get_versioning(&state, &bucket).await;
    }
    if query.tagging.is_some() {
        return config::get_tagging(&state, &bucket).await;
    }
    if query.cors.is_some() {
        return config::get_cors(&state, &bucket).await;
    }
    if query.location.is_some() {
        return config::get_location(&state, &bucket).await;
    }
    if query.encryption.is_some() {
        return config::get_encryption(&state, &bucket).await;
    }
    if query.lifecycle.is_some() {
        return config::get_lifecycle(&state, &bucket).await;
    }
    if query.acl.is_some() {
        return config::get_acl(&state, &bucket).await;
    }
    if query.policy.is_some() {
        return config::get_policy(&state, &bucket).await;
    }
    if query.policy_status.is_some() {
        return config::get_policy_status(&state, &bucket).await;
    }
    if query.replication.is_some() {
        return config::get_replication(&state, &bucket).await;
    }
    if query.website.is_some() {
        return config::get_website(&state, &bucket).await;
    }
    if query.object_lock.is_some() {
        return config::get_object_lock(&state, &bucket).await;
    }
    if query.ownership_controls.is_some() {
        return config::get_ownership_controls(&state, &bucket).await;
    }
    if query.public_access_block.is_some() {
        return config::get_public_access_block(&state, &bucket).await;
    }
    if query.notification.is_some() {
        return config::get_notification(&state, &bucket).await;
    }
    if query.logging.is_some() {
        return config::get_logging(&state, &bucket).await;
    }
    let max_keys: usize = match query.max_keys.as_deref() {
        None => 1000,
        Some(raw) => match parse_max_keys(raw) {
            Ok(v) => v,
            Err(resp) => return resp,
        },
    };
    if query.versions.is_some() {
        return config::list_object_versions(
            &state,
            &bucket,
            query.prefix.as_deref(),
            query.delimiter.as_deref(),
            query.key_marker.as_deref(),
            query.version_id_marker.as_deref(),
            max_keys,
        )
        .await;
    }
    if query.uploads.is_some() {
        return list_multipart_uploads_handler(&state, &bucket, &query).await;
    }

    let prefix = query.prefix.clone().unwrap_or_default();
    let delimiter = query.delimiter.clone().unwrap_or_default();
    let marker = query.marker.clone().unwrap_or_default();
    let list_type = query.list_type.clone().unwrap_or_default();
    let is_v2 = list_type == "2";

    let effective_start = if is_v2 {
        if let Some(token) = query.continuation_token.as_deref() {
            match URL_SAFE.decode(token) {
                Ok(bytes) => match String::from_utf8(bytes) {
                    Ok(decoded) => Some(decoded),
                    Err(_) => {
                        return s3_error_response(S3Error::new(
                            S3ErrorCode::InvalidArgument,
                            "Invalid continuation token",
                        ));
                    }
                },
                Err(_) => {
                    return s3_error_response(S3Error::new(
                        S3ErrorCode::InvalidArgument,
                        "Invalid continuation token",
                    ));
                }
            }
        } else {
            query.start_after.clone()
        }
    } else if marker.is_empty() {
        None
    } else {
        Some(marker.clone())
    };

    let fetch_owner = query
        .fetch_owner
        .as_deref()
        .is_some_and(|v| v.eq_ignore_ascii_case("true"));
    let encoding_type = query.encoding_type.as_deref();
    let start_after_v2 = if is_v2 {
        query.start_after.clone()
    } else {
        None
    };

    if max_keys == 0 {
        let xml = if is_v2 {
            myfsio_xml::response::list_objects_v2_xml_with_encoding(
                &bucket,
                &prefix,
                &delimiter,
                0,
                &[],
                &[],
                false,
                query.continuation_token.as_deref(),
                None,
                0,
                encoding_type,
                fetch_owner,
                start_after_v2.as_deref(),
                Some(owner_id_ref),
                Some(owner_display_ref),
            )
        } else {
            myfsio_xml::response::list_objects_v1_xml_with_owner(
                &bucket,
                &prefix,
                &marker,
                &delimiter,
                0,
                &[],
                &[],
                false,
                None,
                None,
                Some(owner_id_ref),
                Some(owner_display_ref),
            )
        };
        return (StatusCode::OK, [("content-type", "application/xml")], xml).into_response();
    }

    if delimiter.is_empty() {
        let params = myfsio_common::types::ListParams {
            max_keys,
            continuation_token: effective_start.clone(),
            prefix: if prefix.is_empty() {
                None
            } else {
                Some(prefix.clone())
            },
            start_after: start_after_v2.clone(),
        };
        match state.storage.list_objects(&bucket, &params).await {
            Ok(result) => {
                let next_marker = if result.is_truncated {
                    result
                        .next_continuation_token
                        .clone()
                        .or_else(|| result.objects.last().map(|o| o.key.clone()))
                } else {
                    None
                };
                let owner_map = build_owner_display_map(&state, &result.objects);
                let xml = if is_v2 {
                    let next_token = next_marker
                        .as_deref()
                        .map(|s| URL_SAFE.encode(s.as_bytes()));
                    myfsio_xml::response::list_objects_v2_xml_full(
                        &bucket,
                        &prefix,
                        &delimiter,
                        max_keys,
                        &result.objects,
                        &[],
                        result.is_truncated,
                        query.continuation_token.as_deref(),
                        next_token.as_deref(),
                        result.objects.len(),
                        encoding_type,
                        fetch_owner,
                        start_after_v2.as_deref(),
                        Some(owner_id_ref),
                        Some(owner_display_ref),
                        &owner_map,
                    )
                } else {
                    myfsio_xml::response::list_objects_v1_xml_full(
                        &bucket,
                        &prefix,
                        &marker,
                        &delimiter,
                        max_keys,
                        &result.objects,
                        &[],
                        result.is_truncated,
                        next_marker.as_deref(),
                        encoding_type,
                        Some(owner_id_ref),
                        Some(owner_display_ref),
                        &owner_map,
                    )
                };
                (StatusCode::OK, [("content-type", "application/xml")], xml).into_response()
            }
            Err(e) => storage_err_response(e),
        }
    } else if delimiter == "/" {
        let params = myfsio_common::types::ShallowListParams {
            prefix,
            delimiter: delimiter.clone(),
            max_keys,
            continuation_token: effective_start,
        };
        match state.storage.list_objects_shallow(&bucket, &params).await {
            Ok(result) => {
                let owner_map = build_owner_display_map(&state, &result.objects);
                let xml = if is_v2 {
                    let next_token = result
                        .next_continuation_token
                        .as_deref()
                        .map(|s| URL_SAFE.encode(s.as_bytes()));
                    myfsio_xml::response::list_objects_v2_xml_full(
                        &bucket,
                        &params.prefix,
                        &delimiter,
                        max_keys,
                        &result.objects,
                        &result.common_prefixes,
                        result.is_truncated,
                        query.continuation_token.as_deref(),
                        next_token.as_deref(),
                        result.objects.len() + result.common_prefixes.len(),
                        encoding_type,
                        fetch_owner,
                        start_after_v2.as_deref(),
                        Some(owner_id_ref),
                        Some(owner_display_ref),
                        &owner_map,
                    )
                } else {
                    myfsio_xml::response::list_objects_v1_xml_full(
                        &bucket,
                        &params.prefix,
                        &marker,
                        &delimiter,
                        max_keys,
                        &result.objects,
                        &result.common_prefixes,
                        result.is_truncated,
                        result.next_continuation_token.as_deref(),
                        encoding_type,
                        Some(owner_id_ref),
                        Some(owner_display_ref),
                        &owner_map,
                    )
                };
                (StatusCode::OK, [("content-type", "application/xml")], xml).into_response()
            }
            Err(e) => storage_err_response(e),
        }
    } else {
        match list_with_arbitrary_delimiter(
            &state,
            &bucket,
            &prefix,
            &delimiter,
            max_keys,
            effective_start.clone(),
            start_after_v2.clone(),
        )
        .await
        {
            Ok(grouped) => {
                let owner_map = build_owner_display_map(&state, &grouped.objects);
                let xml = if is_v2 {
                    let next_token = grouped
                        .next_token
                        .as_deref()
                        .map(|s| URL_SAFE.encode(s.as_bytes()));
                    myfsio_xml::response::list_objects_v2_xml_full(
                        &bucket,
                        &prefix,
                        &delimiter,
                        max_keys,
                        &grouped.objects,
                        &grouped.common_prefixes,
                        grouped.is_truncated,
                        query.continuation_token.as_deref(),
                        next_token.as_deref(),
                        grouped.objects.len() + grouped.common_prefixes.len(),
                        encoding_type,
                        fetch_owner,
                        start_after_v2.as_deref(),
                        Some(owner_id_ref),
                        Some(owner_display_ref),
                        &owner_map,
                    )
                } else {
                    myfsio_xml::response::list_objects_v1_xml_full(
                        &bucket,
                        &prefix,
                        &marker,
                        &delimiter,
                        max_keys,
                        &grouped.objects,
                        &grouped.common_prefixes,
                        grouped.is_truncated,
                        grouped.next_token.as_deref(),
                        encoding_type,
                        Some(owner_id_ref),
                        Some(owner_display_ref),
                        &owner_map,
                    )
                };
                (StatusCode::OK, [("content-type", "application/xml")], xml).into_response()
            }
            Err(e) => storage_err_response(e),
        }
    }
}

struct GroupedListing {
    objects: Vec<myfsio_common::types::ObjectMeta>,
    common_prefixes: Vec<String>,
    is_truncated: bool,
    next_token: Option<String>,
}

async fn list_with_arbitrary_delimiter(
    state: &AppState,
    bucket: &str,
    prefix: &str,
    delimiter: &str,
    max_keys: usize,
    continuation_token: Option<String>,
    start_after: Option<String>,
) -> Result<GroupedListing, myfsio_storage::error::StorageError> {
    const SCAN_PAGE_SIZE: usize = 1000;
    let prefix_len = prefix.len();

    let initial_skip = continuation_token
        .clone()
        .or_else(|| start_after.clone());

    let mut storage_cursor: Option<String> = initial_skip.clone();
    if let Some(token) = initial_skip.as_deref() {
        if !delimiter.is_empty()
            && token.starts_with(prefix)
            && token[prefix_len..].contains(delimiter)
        {
            let after = &token[prefix_len..];
            if let Some(idx) = after.find(delimiter) {
                let cp_end = idx + delimiter.len();
                let cp = format!("{}{}", prefix, &after[..cp_end]);
                storage_cursor = Some(skip_past_common_prefix(&cp));
            }
        }
    }

    let mut storage_truncated = false;
    let mut objects: Vec<myfsio_common::types::ObjectMeta> = Vec::new();
    let mut common_prefixes: Vec<String> = Vec::new();
    let mut last_emitted_key: Option<String> = None;
    let mut last_cp: Option<String> = None;
    let mut emitted: usize = 0;

    'outer: loop {
        let params = myfsio_common::types::ListParams {
            max_keys: SCAN_PAGE_SIZE,
            continuation_token: storage_cursor.clone(),
            prefix: if prefix.is_empty() {
                None
            } else {
                Some(prefix.to_string())
            },
            start_after: None,
        };
        let page = state.storage.list_objects(bucket, &params).await?;
        let page_was_truncated = page.is_truncated;
        let page_next = page.next_continuation_token.clone();

        let mut skip_cp: Option<String> = None;
        for obj in page.objects.into_iter() {
            if !obj.key.starts_with(prefix) {
                continue;
            }
            if let Some(ref active) = skip_cp {
                if obj.key.starts_with(active.as_str()) {
                    continue;
                }
                skip_cp = None;
            }

            let after_prefix = &obj.key[prefix_len..];
            if let Some(idx) = after_prefix.find(delimiter) {
                let cp_end = idx + delimiter.len();
                let cp = format!("{}{}", prefix, &after_prefix[..cp_end]);
                if last_cp.as_deref() == Some(cp.as_str()) {
                    continue;
                }
                if emitted == max_keys {
                    storage_truncated = true;
                    break 'outer;
                }
                last_cp = Some(cp.clone());
                last_emitted_key = Some(cp.clone());
                common_prefixes.push(cp.clone());
                emitted += 1;
                skip_cp = Some(cp);
            } else {
                if emitted == max_keys {
                    storage_truncated = true;
                    break 'outer;
                }
                last_emitted_key = Some(obj.key.clone());
                objects.push(obj);
                emitted += 1;
            }
        }

        if !page_was_truncated || page_next.is_none() {
            break;
        }
        storage_cursor = page_next;
        if let Some(cp) = last_cp.clone() {
            if let Some(ref cur) = storage_cursor {
                if cur.starts_with(cp.as_str()) {
                    storage_cursor = Some(skip_past_common_prefix(&cp));
                }
            }
        }
    }

    let is_truncated = storage_truncated;
    let next_token = if is_truncated { last_emitted_key } else { None };

    Ok(GroupedListing {
        objects,
        common_prefixes,
        is_truncated,
        next_token,
    })
}

fn skip_past_common_prefix(cp: &str) -> String {
    let mut s = cp.to_string();
    s.push('\u{10FFFF}');
    s
}

pub async fn post_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(query): Query<BucketQuery>,
    peer: Option<axum::extract::Extension<crate::middleware::ReplicationPeerRequest>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let peer_marker = peer.as_ref().map(|e| &e.0);
    if let Some(host_bucket) = virtual_host_bucket_from_headers(&state, &headers).await {
        if host_bucket != bucket {
            return post_object(
                State(state),
                Path((host_bucket, bucket)),
                Query(ObjectQuery::default()),
                peer,
                headers,
                body,
            )
            .await;
        }
    }

    if query.delete.is_some() {
        return delete_objects_handler(&state, &bucket, peer_marker, body).await;
    }

    if let Some(ct) = headers.get("content-type").and_then(|v| v.to_str().ok()) {
        if ct.to_ascii_lowercase().starts_with("multipart/form-data") {
            let ct = ct.to_string();
            return post_object_form_handler(&state, &bucket, &ct, &headers, peer_marker, body)
                .await;
        }
    }

    (StatusCode::METHOD_NOT_ALLOWED).into_response()
}

pub async fn delete_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(query): Query<BucketQuery>,
    peer: Option<axum::extract::Extension<crate::middleware::ReplicationPeerRequest>>,
    headers: HeaderMap,
) -> Response {
    if let Some(host_bucket) = virtual_host_bucket_from_headers(&state, &headers).await {
        if host_bucket != bucket {
            return delete_object(
                State(state),
                Path((host_bucket, bucket)),
                Query(ObjectQuery::default()),
                peer,
                headers,
            )
            .await;
        }
    }

    if query.quota.is_some() {
        return config::delete_quota(&state, &bucket).await;
    }
    if query.tagging.is_some() {
        return config::delete_tagging(&state, &bucket).await;
    }
    if query.cors.is_some() {
        return config::delete_cors(&state, &bucket).await;
    }
    if query.encryption.is_some() {
        return config::delete_encryption(&state, &bucket).await;
    }
    if query.lifecycle.is_some() {
        return config::delete_lifecycle(&state, &bucket).await;
    }
    if query.website.is_some() {
        return config::delete_website(&state, &bucket).await;
    }
    if query.policy.is_some() {
        return config::delete_policy(&state, &bucket).await;
    }
    if query.replication.is_some() {
        return config::delete_replication(&state, &bucket).await;
    }
    if query.object_lock.is_some() {
        return config::delete_object_lock(&state, &bucket).await;
    }
    if query.ownership_controls.is_some() {
        return config::delete_ownership_controls(&state, &bucket).await;
    }
    if query.public_access_block.is_some() {
        return config::delete_public_access_block(&state, &bucket).await;
    }
    if query.notification.is_some() {
        return config::delete_notification(&state, &bucket).await;
    }
    if query.logging.is_some() {
        return config::delete_logging(&state, &bucket).await;
    }
    if query.acl.is_some()
        || query.versioning.is_some()
        || query.versions.is_some()
        || query.uploads.is_some()
        || query.delete.is_some()
        || query.location.is_some()
        || query.policy_status.is_some()
    {
        return s3_error_response(S3Error::new(
            S3ErrorCode::MethodNotAllowed,
            "DELETE is not supported on this bucket subresource",
        ));
    }

    match state.storage.delete_bucket(&bucket).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => storage_err_response(e),
    }
}

pub async fn head_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Some(host_bucket) = virtual_host_bucket_from_headers(&state, &headers).await {
        if host_bucket != bucket {
            return head_object(
                State(state),
                Path((host_bucket, bucket)),
                Query(ObjectQuery::default()),
                headers,
            )
            .await;
        }
    }

    match state.storage.bucket_exists(&bucket).await {
        Ok(true) => {
            let mut headers = HeaderMap::new();
            headers.insert("x-amz-bucket-region", state.config.region.parse().unwrap());
            headers.insert("x-amz-access-point-alias", "false".parse().unwrap());
            (StatusCode::OK, headers).into_response()
        }
        Ok(false) => {
            storage_err_response(myfsio_storage::error::StorageError::BucketNotFound(bucket))
        }
        Err(e) => storage_err_response(e),
    }
}

#[derive(serde::Deserialize, Default)]
pub struct ObjectQuery {
    pub uploads: Option<String>,
    pub attributes: Option<String>,
    pub select: Option<String>,
    #[serde(rename = "uploadId")]
    pub upload_id: Option<String>,
    #[serde(rename = "partNumber")]
    pub part_number: Option<u32>,
    #[serde(rename = "part-number-marker")]
    pub part_number_marker: Option<u32>,
    #[serde(rename = "max-parts")]
    pub max_parts: Option<usize>,
    #[serde(rename = "versionId")]
    pub version_id: Option<String>,
    pub tagging: Option<String>,
    pub acl: Option<String>,
    pub retention: Option<String>,
    #[serde(rename = "legal-hold")]
    pub legal_hold: Option<String>,
    #[serde(rename = "response-content-type")]
    pub response_content_type: Option<String>,
    #[serde(rename = "response-content-disposition")]
    pub response_content_disposition: Option<String>,
    #[serde(rename = "response-content-language")]
    pub response_content_language: Option<String>,
    #[serde(rename = "response-content-encoding")]
    pub response_content_encoding: Option<String>,
    #[serde(rename = "response-cache-control")]
    pub response_cache_control: Option<String>,
    #[serde(rename = "response-expires")]
    pub response_expires: Option<String>,
}

fn apply_response_overrides(headers: &mut HeaderMap, query: &ObjectQuery) {
    if let Some(ref v) = query.response_content_type {
        if let Ok(val) = v.parse() {
            headers.insert("content-type", val);
        }
    }
    if let Some(ref v) = query.response_content_disposition {
        if let Ok(val) = v.parse() {
            headers.insert("content-disposition", val);
        }
    }
    if let Some(ref v) = query.response_content_language {
        if let Ok(val) = v.parse() {
            headers.insert("content-language", val);
        }
    }
    if let Some(ref v) = query.response_content_encoding {
        if let Ok(val) = v.parse() {
            headers.insert("content-encoding", val);
        }
    }
    if let Some(ref v) = query.response_cache_control {
        if let Ok(val) = v.parse() {
            headers.insert("cache-control", val);
        }
    }
    if let Some(ref v) = query.response_expires {
        if let Ok(val) = v.parse() {
            headers.insert("expires", val);
        }
    }
}

fn guessed_content_type(key: &str, explicit: Option<&str>) -> String {
    explicit
        .filter(|v| !v.trim().is_empty())
        .map(|v| v.to_string())
        .unwrap_or_else(|| {
            mime_guess::from_path(key)
                .first_raw()
                .unwrap_or("application/octet-stream")
                .to_string()
        })
}

fn is_aws_chunked(headers: &HeaderMap) -> bool {
    if let Some(sha) = headers
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
    {
        if sha.to_ascii_uppercase().starts_with("STREAMING-") {
            return true;
        }
    }
    let content_encoding_says_chunked = headers
        .get("content-encoding")
        .and_then(|v| v.to_str().ok())
        .map(|enc| {
            enc.split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("aws-chunked"))
        })
        .unwrap_or(false);
    if content_encoding_says_chunked && headers.get("x-amz-decoded-content-length").is_some() {
        return true;
    }
    false
}

fn insert_content_type(headers: &mut HeaderMap, key: &str, explicit: Option<&str>) {
    let value = guessed_content_type(key, explicit);
    if let Ok(header_value) = value.parse() {
        headers.insert("content-type", header_value);
    } else {
        headers.insert("content-type", "application/octet-stream".parse().unwrap());
    }
}

fn internal_header_pairs() -> &'static [(&'static str, &'static str, &'static str)] {
    &[
        ("cache-control", "__cache_control__", "cache-control"),
        (
            "content-disposition",
            "__content_disposition__",
            "content-disposition",
        ),
        (
            "content-language",
            "__content_language__",
            "content-language",
        ),
        (
            "content-encoding",
            "__content_encoding__",
            "content-encoding",
        ),
        ("expires", "__expires__", "expires"),
        (
            "x-amz-website-redirect-location",
            "__website_redirect_location__",
            "x-amz-website-redirect-location",
        ),
    ]
}

fn decoded_content_encoding(value: &str) -> Option<String> {
    let filtered: Vec<&str> = value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty() && !part.eq_ignore_ascii_case("aws-chunked"))
        .collect();
    if filtered.is_empty() {
        None
    } else {
        Some(filtered.join(", "))
    }
}

fn insert_standard_object_metadata(
    headers: &HeaderMap,
    metadata: &mut HashMap<String, String>,
) -> Result<(), Response> {
    for (request_header, metadata_key, _) in internal_header_pairs() {
        if let Some(value) = headers.get(*request_header).and_then(|v| v.to_str().ok()) {
            if *request_header == "content-encoding" {
                if let Some(stored) = decoded_content_encoding(value) {
                    metadata.insert((*metadata_key).to_string(), stored);
                }
            } else {
                metadata.insert((*metadata_key).to_string(), value.to_string());
            }
        }
    }
    if let Some(value) = headers
        .get("x-amz-storage-class")
        .and_then(|v| v.to_str().ok())
    {
        let upper = value.to_ascii_uppercase();
        if !VALID_STORAGE_CLASSES.contains(&upper.as_str()) {
            return Err(s3_error_response(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "Invalid x-amz-storage-class",
            )));
        }
        metadata.insert("__storage_class__".to_string(), upper);
    }

    if let Some(value) = headers
        .get("x-amz-object-lock-legal-hold")
        .and_then(|v| v.to_str().ok())
    {
        object_lock::set_legal_hold(metadata, value.eq_ignore_ascii_case("ON"));
    }

    let retention_mode = headers
        .get("x-amz-object-lock-mode")
        .and_then(|v| v.to_str().ok());
    let retain_until = headers
        .get("x-amz-object-lock-retain-until-date")
        .and_then(|v| v.to_str().ok());
    if let (Some(mode), Some(retain_until)) = (retention_mode, retain_until) {
        let mode = match mode.to_ascii_uppercase().as_str() {
            "GOVERNANCE" => object_lock::RetentionMode::GOVERNANCE,
            "COMPLIANCE" => object_lock::RetentionMode::COMPLIANCE,
            _ => {
                return Err(s3_error_response(S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    "Invalid x-amz-object-lock-mode",
                )))
            }
        };
        let retain_until_date = DateTime::parse_from_rfc3339(retain_until)
            .map(|value| value.with_timezone(&Utc))
            .map_err(|_| {
                s3_error_response(S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    "Invalid x-amz-object-lock-retain-until-date",
                ))
            })?;
        object_lock::set_object_retention(
            metadata,
            &object_lock::ObjectLockRetention {
                mode,
                retain_until_date,
            },
        )
        .map_err(|message| {
            s3_error_response(S3Error::new(S3ErrorCode::InvalidArgument, message))
        })?;
    }
    Ok(())
}

const VALID_STORAGE_CLASSES: &[&str] = &[
    "STANDARD",
    "REDUCED_REDUNDANCY",
    "STANDARD_IA",
    "ONEZONE_IA",
    "INTELLIGENT_TIERING",
    "GLACIER",
    "GLACIER_IR",
    "DEEP_ARCHIVE",
    "OUTPOSTS",
    "SNOW",
    "EXPRESS_ONEZONE",
];

const CANNED_ACL_VALUES: &[&str] = &[
    "private",
    "public-read",
    "public-read-write",
    "authenticated-read",
    "bucket-owner-read",
    "bucket-owner-full-control",
    "aws-exec-read",
];

fn apply_object_acl(
    headers: &HeaderMap,
    metadata: &mut HashMap<String, String>,
    owner: &str,
) -> Result<(), Response> {
    let canned = canned_acl_value(headers)?.unwrap_or_else(|| "private".to_string());
    let acl = crate::services::acl::create_canned_acl(&canned, owner);
    crate::services::acl::store_object_acl(metadata, &acl);
    Ok(())
}

fn canned_acl_value(headers: &HeaderMap) -> Result<Option<String>, Response> {
    let Some(raw) = headers.get("x-amz-acl").and_then(|v| v.to_str().ok()) else {
        return Ok(None);
    };
    let value = raw.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if !CANNED_ACL_VALUES
        .iter()
        .any(|known| known.eq_ignore_ascii_case(value))
    {
        return Err(s3_error_response(S3Error::new(
            S3ErrorCode::InvalidArgument,
            format!("Unsupported canned ACL: {}", value),
        )));
    }
    Ok(Some(value.to_string()))
}

fn validate_sse_request(state: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    let alg = headers
        .get("x-amz-server-side-encryption")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let Some(alg) = alg else {
        return Ok(());
    };
    if alg != "AES256" && alg != "aws:kms" {
        return Err(s3_error_response(S3Error::new(
            S3ErrorCode::InvalidArgument,
            format!("Unsupported server-side encryption algorithm: {}", alg),
        )));
    }
    if alg == "aws:kms" && !state.config.kms_enabled {
        return Err(s3_error_response(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "KMS is not enabled on this server",
        )));
    }
    if alg == "aws:kms" {
        let kid = headers
            .get("x-amz-server-side-encryption-aws-kms-key-id")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty());
        if kid.is_none() {
            return Err(s3_error_response(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "x-amz-server-side-encryption-aws-kms-key-id is required when SSE algorithm is aws:kms",
            )));
        }
    }
    if state.encryption.is_none() {
        return Err(s3_error_response(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "Server-side encryption is not enabled on this server",
        )));
    }
    Ok(())
}

fn apply_stored_response_headers(headers: &mut HeaderMap, metadata: &HashMap<String, String>) {
    for (_, metadata_key, response_header) in internal_header_pairs() {
        if let Some(value) = metadata
            .get(*metadata_key)
            .and_then(|value| value.parse().ok())
        {
            headers.insert(*response_header, value);
        }
    }
    if let Some(value) = metadata
        .get("__storage_class__")
        .and_then(|value| value.parse().ok())
    {
        headers.insert("x-amz-storage-class", value);
    }
    if let Some(value) = metadata
        .get(crate::services::replication::REPLICATION_STATUS_KEY)
        .and_then(|value| value.parse().ok())
    {
        headers.insert("x-amz-replication-status", value);
    }
}

fn apply_stored_encryption_headers(
    headers: &mut HeaderMap,
    metadata: &HashMap<String, String>,
    request_headers: &HeaderMap,
) {
    if let Some(alg) = metadata
        .get("x-amz-server-side-encryption")
        .and_then(|v| v.parse().ok())
    {
        headers.insert("x-amz-server-side-encryption", alg);
    }
    if let Some(kid) = metadata
        .get("x-amz-encryption-key-id")
        .and_then(|v| v.parse().ok())
    {
        headers.insert("x-amz-server-side-encryption-aws-kms-key-id", kid);
    }
    if let Some(value) = request_headers
        .get("x-amz-server-side-encryption-customer-algorithm")
        .cloned()
    {
        headers.insert("x-amz-server-side-encryption-customer-algorithm", value);
    }
    if let Some(value) = request_headers
        .get("x-amz-server-side-encryption-customer-key-MD5")
        .cloned()
    {
        headers.insert("x-amz-server-side-encryption-customer-key-MD5", value);
    }
}

fn apply_user_metadata(headers: &mut HeaderMap, metadata: &HashMap<String, String>) {
    for (k, v) in metadata {
        if k.starts_with("__") || k.starts_with("x-amz-") {
            continue;
        }
        if let Ok(header_val) = v.parse() {
            let header_name = format!("x-amz-meta-{}", k);
            if let Ok(name) = header_name.parse::<axum::http::HeaderName>() {
                headers.insert(name, header_val);
            }
        }
    }
}

fn bad_digest_response(message: impl Into<String>) -> Response {
    s3_error_response(S3Error::new(S3ErrorCode::BadDigest, message))
}

fn invalid_digest_response(message: impl Into<String>) -> Response {
    s3_error_response(S3Error::new(S3ErrorCode::InvalidDigest, message))
}

fn base64_header_bytes(headers: &HeaderMap, name: &str) -> Result<Option<Vec<u8>>, Response> {
    let Some(value) = headers.get(name).and_then(|v| v.to_str().ok()) else {
        return Ok(None);
    };
    STANDARD
        .decode(value.trim())
        .map(Some)
        .map_err(|_| invalid_digest_response(format!("Invalid base64 value for {}", name)))
}

fn has_upload_checksum(headers: &HeaderMap) -> bool {
    headers.contains_key("content-md5")
        || headers.contains_key("x-amz-checksum-sha256")
        || headers.contains_key("x-amz-checksum-crc32")
}

fn persist_additional_checksums(headers: &HeaderMap, metadata: &mut HashMap<String, String>) {
    for algo in ["sha256", "sha1", "crc32", "crc32c", "crc64nvme"] {
        let header_name = format!("x-amz-checksum-{}", algo);
        if let Some(value) = headers.get(&header_name).and_then(|v| v.to_str().ok()) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                metadata.insert(format!("__checksum_{}__", algo), trimmed.to_string());
            }
        }
    }
    if let Some(value) = headers
        .get("x-amz-sdk-checksum-algorithm")
        .and_then(|v| v.to_str().ok())
    {
        let trimmed = value.trim().to_ascii_uppercase();
        if !trimmed.is_empty() {
            metadata.insert("__checksum_algorithm__".to_string(), trimmed);
        }
    }
}

fn apply_stored_checksum_headers(resp_headers: &mut HeaderMap, metadata: &HashMap<String, String>) {
    for algo in ["sha256", "sha1", "crc32", "crc32c", "crc64nvme"] {
        if let Some(value) = metadata.get(&format!("__checksum_{}__", algo)) {
            if let Ok(parsed) = value.parse() {
                resp_headers.insert(
                    axum::http::HeaderName::from_bytes(
                        format!("x-amz-checksum-{}", algo).as_bytes(),
                    )
                    .unwrap(),
                    parsed,
                );
            }
        }
    }
}

fn validate_upload_checksums(headers: &HeaderMap, data: &[u8]) -> Result<(), Response> {
    if let Some(expected) = base64_header_bytes(headers, "content-md5")? {
        if expected.len() != 16 {
            return Err(invalid_digest_response(
                "The Content-MD5 you specified is not a valid 16-byte MD5 digest",
            ));
        }
        if Md5::digest(data).as_slice() != expected.as_slice() {
            return Err(bad_digest_response(
                "The Content-MD5 you specified did not match what we received",
            ));
        }
    }

    if let Some(expected) = base64_header_bytes(headers, "x-amz-checksum-sha256")? {
        if Sha256::digest(data).as_slice() != expected.as_slice() {
            return Err(bad_digest_response(
                "The x-amz-checksum-sha256 you specified did not match what we received",
            ));
        }
    }

    if let Some(expected) = base64_header_bytes(headers, "x-amz-checksum-crc32")? {
        let actual = crc32fast::hash(data).to_be_bytes();
        if expected.as_slice() != actual {
            return Err(bad_digest_response(
                "The x-amz-checksum-crc32 you specified did not match what we received",
            ));
        }
    }

    Ok(())
}

async fn collect_upload_body(body: Body, aws_chunked: bool) -> Result<bytes::Bytes, Response> {
    if aws_chunked {
        let mut reader = chunked::decode_body(body);
        let mut data = Vec::new();
        reader.read_to_end(&mut data).await.map_err(|_| {
            s3_error_response(S3Error::new(
                S3ErrorCode::InvalidRequest,
                "Failed to read aws-chunked request body",
            ))
        })?;
        return Ok(bytes::Bytes::from(data));
    }

    http_body_util::BodyExt::collect(body)
        .await
        .map(|collected| collected.to_bytes())
        .map_err(|err| {
            if let Some(message) = crate::middleware::sha_body::sha256_mismatch_message(&err) {
                bad_digest_response(message)
            } else {
                s3_error_response(S3Error::new(
                    S3ErrorCode::InvalidRequest,
                    "Failed to read request body",
                ))
            }
        })
}

fn parse_tagging_header(value: &str) -> Result<Vec<myfsio_common::types::Tag>, Response> {
    let mut tags = Vec::new();
    if value.trim().is_empty() {
        return Ok(tags);
    }

    for pair in value.split('&') {
        let (raw_key, raw_value) = pair.split_once('=').ok_or_else(|| {
            s3_error_response(S3Error::new(
                S3ErrorCode::InvalidTag,
                "The x-amz-tagging header must use query-string key=value pairs",
            ))
        })?;
        let key = percent_decode_str(raw_key)
            .decode_utf8()
            .map_err(|_| {
                s3_error_response(S3Error::new(
                    S3ErrorCode::InvalidTag,
                    "Tag keys must be valid UTF-8",
                ))
            })?
            .to_string();
        let value = percent_decode_str(raw_value)
            .decode_utf8()
            .map_err(|_| {
                s3_error_response(S3Error::new(
                    S3ErrorCode::InvalidTag,
                    "Tag values must be valid UTF-8",
                ))
            })?
            .to_string();
        tags.push(myfsio_common::types::Tag { key, value });
    }

    Ok(tags)
}

fn parse_copy_source(copy_source: &str) -> Result<(String, String, Option<String>), Response> {
    let source = copy_source.strip_prefix('/').unwrap_or(copy_source);
    let (bucket_raw, key_and_query) = source.split_once('/').ok_or_else(|| {
        s3_error_response(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "Invalid x-amz-copy-source",
        ))
    })?;
    let (key_raw, query) = key_and_query
        .split_once('?')
        .map(|(key, query)| (key, Some(query)))
        .unwrap_or((key_and_query, None));

    let bucket = percent_decode_str(bucket_raw)
        .decode_utf8()
        .map_err(|_| {
            s3_error_response(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "Invalid x-amz-copy-source bucket encoding",
            ))
        })?
        .to_string();
    let key = percent_decode_str(key_raw)
        .decode_utf8()
        .map_err(|_| {
            s3_error_response(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "Invalid x-amz-copy-source key encoding",
            ))
        })?
        .to_string();

    let mut version_id = None;
    if let Some(query) = query {
        for pair in query.split('&') {
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            if name == "versionId" {
                version_id = Some(
                    percent_decode_str(value)
                        .decode_utf8()
                        .map_err(|_| {
                            s3_error_response(S3Error::new(
                                S3ErrorCode::InvalidArgument,
                                "Invalid x-amz-copy-source versionId encoding",
                            ))
                        })?
                        .to_string(),
                );
                break;
            }
        }
    }

    Ok((bucket, key, version_id))
}

pub async fn put_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(query): Query<ObjectQuery>,
    peer: Option<axum::extract::Extension<crate::middleware::ReplicationPeerRequest>>,
    principal: Option<axum::extract::Extension<myfsio_common::types::Principal>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let peer_marker = peer.as_ref().map(|e| &e.0);
    let owner_id = principal
        .as_ref()
        .map(|p| p.0.user_id.clone())
        .unwrap_or_else(|| "myfsio".to_string());
    if query.tagging.is_some() {
        if query.version_id.as_deref().is_some_and(|v| !v.is_empty()) {
            return s3_error_response(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "PUT Object Tagging with versionId is not supported on archived versions",
            ));
        }
        let resp = config::put_object_tagging(&state, &bucket, &key, body).await;
        if resp.status().is_success() {
            trigger_replication_for_request(&state, peer_marker, &bucket, &key, "write");
        }
        return resp;
    }
    if query.acl.is_some() {
        let resp = config::put_object_acl(&state, &bucket, &key, &headers, body).await;
        if resp.status().is_success() {
            trigger_replication_for_request(&state, peer_marker, &bucket, &key, "write");
        }
        return resp;
    }
    if query.retention.is_some() {
        let resp = config::put_object_retention(
            &state,
            &bucket,
            &key,
            query.version_id.as_deref(),
            &headers,
            body,
        )
        .await;
        if resp.status().is_success() {
            trigger_replication_for_request(&state, peer_marker, &bucket, &key, "write");
        }
        return resp;
    }
    if query.legal_hold.is_some() {
        let resp = config::put_object_legal_hold(
            &state,
            &bucket,
            &key,
            query.version_id.as_deref(),
            body,
        )
        .await;
        if resp.status().is_success() {
            trigger_replication_for_request(&state, peer_marker, &bucket, &key, "write");
        }
        return resp;
    }

    if let Some(ref upload_id) = query.upload_id {
        if let Some(part_number) = query.part_number {
            if let Some(copy_source) = headers
                .get("x-amz-copy-source")
                .and_then(|v| v.to_str().ok())
            {
                let range = headers
                    .get("x-amz-copy-source-range")
                    .and_then(|v| v.to_str().ok());
                return upload_part_copy_handler(
                    &state,
                    &bucket,
                    upload_id,
                    part_number,
                    copy_source,
                    range,
                    &headers,
                )
                .await;
            }
            return upload_part_handler_with_chunking(
                &state,
                &bucket,
                upload_id,
                part_number,
                body,
                is_aws_chunked(&headers),
            )
            .await;
        }
    }

    if let Some(copy_source) = headers
        .get("x-amz-copy-source")
        .and_then(|v| v.to_str().ok())
    {
        return copy_object_handler(
            &state,
            copy_source,
            &bucket,
            &key,
            peer_marker,
            &headers,
        )
        .await;
    }

    if let Err(response) =
        ensure_object_lock_allows_write(&state, &bucket, &key, Some(&headers)).await
    {
        return response;
    }
    if let Err(response) =
        ensure_archived_null_lock_allows_overwrite(&state, &bucket, &key, Some(&headers)).await
    {
        return response;
    }
    if let Some(response) = evaluate_put_preconditions(&state, &bucket, &key, &headers).await {
        return response;
    }

    let content_type = guessed_content_type(
        &key,
        headers.get("content-type").and_then(|v| v.to_str().ok()),
    );

    let mut metadata = HashMap::new();
    metadata.insert("__content_type__".to_string(), content_type);
    if let Err(response) = insert_standard_object_metadata(&headers, &mut metadata) {
        return response;
    }
    if let Err(response) = apply_object_acl(&headers, &mut metadata, &owner_id) {
        return response;
    }
    if let Err(response) = validate_sse_request(&state, &headers) {
        return response;
    }
    let resolved_enc_ctx = match resolve_encryption_context(&state, &bucket, &headers).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    for (name, value) in headers.iter() {
        let name_str = name.as_str();
        if let Some(meta_key) = name_str.strip_prefix("x-amz-meta-") {
            if let Ok(val) = value.to_str() {
                metadata.insert(meta_key.to_string(), val.to_string());
            }
        }
    }

    let tags = match headers
        .get("x-amz-tagging")
        .and_then(|value| value.to_str().ok())
        .map(parse_tagging_header)
        .transpose()
    {
        Ok(tags) => tags,
        Err(response) => return response,
    };
    if let Some(ref tags) = tags {
        if tags.len() > state.config.object_tag_limit {
            return s3_error_response(S3Error::new(
                S3ErrorCode::InvalidTag,
                format!("Maximum {} tags allowed", state.config.object_tag_limit),
            ));
        }
    }

    persist_additional_checksums(&headers, &mut metadata);

    let aws_chunked = is_aws_chunked(&headers);
    let boxed: myfsio_storage::traits::AsyncReadStream = if has_upload_checksum(&headers) {
        let data = match collect_upload_body(body, aws_chunked).await {
            Ok(data) => data,
            Err(response) => return response,
        };
        if let Err(response) = validate_upload_checksums(&headers, &data) {
            return response;
        }
        Box::pin(std::io::Cursor::new(data))
    } else if aws_chunked {
        Box::pin(chunked::decode_body(body))
    } else {
        let stream = tokio_util::io::StreamReader::new(
            body.into_data_stream()
                .map_err(std::io::Error::other),
        );
        Box::pin(stream)
    };

    match state
        .storage
        .put_object(&bucket, &key, boxed, Some(metadata))
        .await
    {
        Ok(meta) => {
            if let Some(ref tags) = tags {
                if let Err(e) = state.storage.set_object_tags(&bucket, &key, tags).await {
                    return storage_err_response(e);
                }
            }
            if let Some(enc_ctx) = resolved_enc_ctx {
                if let Some(ref enc_svc) = state.encryption {
                    let obj_path = match state.storage.get_object_path(&bucket, &key).await {
                        Ok(p) => p,
                        Err(e) => return storage_err_response(e),
                    };
                    let tmp_dir = state.config.storage_root.join(".myfsio.sys").join("tmp");
                    let _ = tokio::fs::create_dir_all(&tmp_dir).await;
                    let enc_tmp = tmp_dir.join(format!("enc-{}", uuid::Uuid::new_v4()));

                    match enc_svc.encrypt_object(&obj_path, &enc_tmp, &enc_ctx).await {
                        Ok(enc_meta) => {
                            if let Err(e) = tokio::fs::rename(&enc_tmp, &obj_path).await {
                                let _ = tokio::fs::remove_file(&enc_tmp).await;
                                return storage_err_response(
                                    myfsio_storage::error::StorageError::Io(e),
                                );
                            }
                            let enc_size = tokio::fs::metadata(&obj_path)
                                .await
                                .map(|m| m.len())
                                .unwrap_or(0);

                            let mut enc_metadata = enc_meta.to_metadata_map();
                            let all_meta: HashMap<String, String> = state
                                .storage
                                .get_object_metadata(&bucket, &key)
                                .await
                                .unwrap_or_default();
                            for (k, v) in &all_meta {
                                enc_metadata.entry(k.clone()).or_insert_with(|| v.clone());
                            }
                            enc_metadata.insert("__size__".to_string(), enc_size.to_string());
                            let _ = state
                                .storage
                                .put_object_metadata(&bucket, &key, &enc_metadata)
                                .await;

                            let mut resp_headers = HeaderMap::new();
                            if let Some(ref etag) = meta.etag {
                                resp_headers
                                    .insert("etag", format!("\"{}\"", etag).parse().unwrap());
                            }
                            if let Some(ref vid) = meta.version_id {
                                if let Ok(value) = vid.parse() {
                                    resp_headers.insert("x-amz-version-id", value);
                                }
                            }
                            resp_headers.insert(
                                "x-amz-server-side-encryption",
                                enc_ctx.algorithm.as_str().parse().unwrap(),
                            );
                            apply_stored_response_headers(&mut resp_headers, &enc_metadata);
                            apply_stored_checksum_headers(&mut resp_headers, &enc_metadata);
                            apply_stored_encryption_headers(
                                &mut resp_headers,
                                &enc_metadata,
                                &headers,
                            );
                            notifications::emit_object_created(
                                &state,
                                &bucket,
                                &key,
                                meta.size,
                                meta.etag.as_deref(),
                                "",
                                "",
                                "",
                                "Put",
                            );
                            trigger_replication_for_request(
                                &state,
                                peer_marker,
                                &bucket,
                                &key,
                                "write",
                            );
                            return (StatusCode::OK, resp_headers).into_response();
                        }
                        Err(e) => {
                            let _ = tokio::fs::remove_file(&enc_tmp).await;
                            let _ = state.storage.delete_object(&bucket, &key).await;
                            return s3_error_response(S3Error::new(
                                myfsio_common::error::S3ErrorCode::InternalError,
                                format!("Encryption failed: {}", e),
                            ));
                        }
                    }
                }
            }

            let mut resp_headers = HeaderMap::new();
            if let Some(ref etag) = meta.etag {
                resp_headers.insert("etag", format!("\"{}\"", etag).parse().unwrap());
            }
            if let Some(ref vid) = meta.version_id {
                if let Ok(value) = vid.parse() {
                    resp_headers.insert("x-amz-version-id", value);
                }
            }
            let stored = state
                .storage
                .get_object_metadata(&bucket, &key)
                .await
                .unwrap_or_default();
            apply_stored_response_headers(&mut resp_headers, &stored);
            apply_stored_checksum_headers(&mut resp_headers, &stored);
            apply_stored_encryption_headers(&mut resp_headers, &stored, &headers);
            notifications::emit_object_created(
                &state,
                &bucket,
                &key,
                meta.size,
                meta.etag.as_deref(),
                "",
                "",
                "",
                "Put",
            );
            trigger_replication_for_request(&state, peer_marker, &bucket, &key, "write");
            (StatusCode::OK, resp_headers).into_response()
        }
        Err(e) => storage_err_response(e),
    }
}

pub async fn get_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(query): Query<ObjectQuery>,
    headers: HeaderMap,
) -> Response {
    if query.tagging.is_some() {
        return config::get_object_tagging(
            &state,
            &bucket,
            &key,
            query.version_id.as_deref(),
        )
        .await;
    }
    if query.acl.is_some() {
        return config::get_object_acl(&state, &bucket, &key).await;
    }
    if query.retention.is_some() {
        return config::get_object_retention(
            &state,
            &bucket,
            &key,
            query.version_id.as_deref(),
        )
        .await;
    }
    if query.legal_hold.is_some() {
        return config::get_object_legal_hold(
            &state,
            &bucket,
            &key,
            query.version_id.as_deref(),
        )
        .await;
    }
    if query.attributes.is_some() {
        return object_attributes_handler(&state, &bucket, &key, &headers).await;
    }
    if let Some(ref upload_id) = query.upload_id {
        return list_parts_handler(&state, &bucket, &key, upload_id, &query).await;
    }

    let version_id = query.version_id.as_deref();

    let range_header = headers
        .get("range")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    if range_header.is_some() && query.part_number.is_some() {
        return s3_error_response(S3Error::new(
            S3ErrorCode::InvalidRequest,
            "Cannot specify both Range and partNumber on the same request",
        ));
    }

    if let Some(ref range_str) = range_header {
        return range_get_handler(&state, &bucket, &key, range_str, &query, &headers).await;
    }

    let stream_cap = state.config.stream_chunk_size.max(64 * 1024);

    let tmp_dir = state.config.storage_root.join(".myfsio.sys").join("tmp");
    let _ = tokio::fs::create_dir_all(&tmp_dir).await;
    let snap_link = tmp_dir.join(format!("src-{}", uuid::Uuid::new_v4()));
    let snap_res = match version_id {
        Some(v) => {
            state
                .storage
                .snapshot_object_version_to_link(&bucket, &key, v, &snap_link)
                .await
        }
        None => {
            state
                .storage
                .snapshot_object_to_link(&bucket, &key, &snap_link)
                .await
        }
    };
    let snap_meta = match snap_res {
        Ok(m) => m,
        Err(e) => return storage_err_response(e),
    };

    if let Some(part_number) = query.part_number {
        match resolve_part_view(&snap_meta, part_number) {
            Ok(view) if view.multipart => {
                if view.length == 0 {
                    if let Some(resp) = evaluate_get_preconditions(&headers, &snap_meta) {
                        let _ = tokio::fs::remove_file(&snap_link).await;
                        return resp;
                    }
                    let _ = tokio::fs::remove_file(&snap_link).await;
                    let mut h =
                        build_part_response_headers(&key, &snap_meta, &view, &query);
                    apply_user_metadata(&mut h, &snap_meta.metadata);
                    return (StatusCode::PARTIAL_CONTENT, h).into_response();
                }
                let range_str = format!("bytes={}-{}", view.start, view.start + view.length - 1);
                return serve_range_from_snapshot(
                    &state,
                    snap_link,
                    snap_meta,
                    &range_str,
                    &query,
                    &headers,
                    Some(view.parts_count),
                )
                .await;
            }
            Ok(_) => {}
            Err(resp) => {
                let _ = tokio::fs::remove_file(&snap_link).await;
                return resp;
            }
        }
    }

    if let Some(resp) = evaluate_get_preconditions(&headers, &snap_meta) {
        let _ = tokio::fs::remove_file(&snap_link).await;
        return resp;
    }

    let enc_info =
        myfsio_crypto::encryption::EncryptionMetadata::from_metadata(&snap_meta.internal_metadata);

    let (file, file_size, enc_header): (tokio::fs::File, u64, Option<&str>) =
        match (enc_info.as_ref(), state.encryption.as_ref()) {
            (Some(enc_info), Some(enc_svc)) => {
                if enc_info.algorithm == "AES256" && enc_info.encrypted_data_key.is_none() {
                    if let Err(resp) = require_sse_c_key_match(&headers, enc_info) {
                        let _ = tokio::fs::remove_file(&snap_link).await;
                        return resp;
                    }
                }
                let dec_tmp = tmp_dir.join(format!("dec-{}", uuid::Uuid::new_v4()));
                let customer_key = match extract_sse_c_key(&headers) {
                    Ok(key) => key,
                    Err(resp) => {
                        let _ = tokio::fs::remove_file(&snap_link).await;
                        return resp;
                    }
                };
                let decrypt_res = enc_svc
                    .decrypt_object(&snap_link, &dec_tmp, enc_info, customer_key.as_deref())
                    .await;
                let _ = tokio::fs::remove_file(&snap_link).await;
                if let Err(e) = decrypt_res {
                    let _ = tokio::fs::remove_file(&dec_tmp).await;
                    return s3_error_response(S3Error::new(
                        myfsio_common::error::S3ErrorCode::InternalError,
                        format!("Decryption failed: {}", e),
                    ));
                }
                let file = match open_self_deleting(dec_tmp.clone()).await {
                    Ok(f) => f,
                    Err(e) => {
                        let _ = tokio::fs::remove_file(&dec_tmp).await;
                        return storage_err_response(myfsio_storage::error::StorageError::Io(e));
                    }
                };
                let file_size = file.metadata().await.map(|m| m.len()).unwrap_or(0);
                (file, file_size, Some(enc_info.algorithm.as_str()))
            }
            (Some(_), None) => {
                let _ = tokio::fs::remove_file(&snap_link).await;
                return s3_error_response(S3Error::new(
                    myfsio_common::error::S3ErrorCode::InternalError,
                    "Object is encrypted but encryption service is disabled".to_string(),
                ));
            }
            (None, _) => {
                let file = match open_self_deleting(snap_link.clone()).await {
                    Ok(f) => f,
                    Err(e) => {
                        let _ = tokio::fs::remove_file(&snap_link).await;
                        return storage_err_response(myfsio_storage::error::StorageError::Io(e));
                    }
                };
                (file, snap_meta.size, None)
            }
        };

    let stream = ReaderStream::with_capacity(file, stream_cap);
    let body = Body::from_stream(stream);

    let meta = &snap_meta;
    let mut resp_headers = HeaderMap::new();
    resp_headers.insert("content-length", file_size.to_string().parse().unwrap());
    if let Some(ref etag) = meta.etag {
        resp_headers.insert("etag", format!("\"{}\"", etag).parse().unwrap());
    }
    insert_content_type(&mut resp_headers, &key, meta.content_type.as_deref());
    resp_headers.insert(
        "last-modified",
        meta.last_modified
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string()
            .parse()
            .unwrap(),
    );
    resp_headers.insert("accept-ranges", "bytes".parse().unwrap());
    if let Some(alg) = enc_header {
        resp_headers.insert("x-amz-server-side-encryption", alg.parse().unwrap());
    }
    apply_stored_response_headers(&mut resp_headers, &meta.internal_metadata);
    apply_stored_checksum_headers(&mut resp_headers, &meta.internal_metadata);
    if let Some(ref requested_version) = query.version_id {
        if let Ok(value) = requested_version.parse() {
            resp_headers.insert("x-amz-version-id", value);
        }
    } else if let Some(ref vid) = meta.version_id {
        if let Ok(value) = vid.parse() {
            resp_headers.insert("x-amz-version-id", value);
        }
    }
    apply_user_metadata(&mut resp_headers, &meta.metadata);
    apply_response_overrides(&mut resp_headers, &query);

    (StatusCode::OK, resp_headers, body).into_response()
}

pub async fn post_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(query): Query<ObjectQuery>,
    peer: Option<axum::extract::Extension<crate::middleware::ReplicationPeerRequest>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let peer_marker = peer.as_ref().map(|e| &e.0);
    if query.uploads.is_some() {
        return initiate_multipart_handler(&state, &bucket, &key, &headers).await;
    }

    if let Some(ref upload_id) = query.upload_id {
        return complete_multipart_handler(
            &state,
            &bucket,
            &key,
            upload_id,
            peer_marker,
            &headers,
            body,
        )
        .await;
    }

    if query.select.is_some() {
        return select::post_select_object_content(&state, &bucket, &key, &headers, body).await;
    }

    (StatusCode::METHOD_NOT_ALLOWED).into_response()
}

pub async fn delete_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(query): Query<ObjectQuery>,
    peer: Option<axum::extract::Extension<crate::middleware::ReplicationPeerRequest>>,
    headers: HeaderMap,
) -> Response {
    let peer_marker = peer.as_ref().map(|e| &e.0);
    if query.tagging.is_some() {
        if query.version_id.as_deref().is_some_and(|v| !v.is_empty()) {
            return s3_error_response(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "DELETE Object Tagging with versionId is not supported on archived versions",
            ));
        }
        let resp = config::delete_object_tagging(&state, &bucket, &key).await;
        if resp.status().is_success() {
            trigger_replication_for_request(&state, peer_marker, &bucket, &key, "write");
        }
        return resp;
    }
    if query.acl.is_some() {
        return StatusCode::NO_CONTENT.into_response();
    }

    if let Some(ref upload_id) = query.upload_id {
        return abort_multipart_handler(&state, &bucket, upload_id).await;
    }

    if let Some(version_id) = query.version_id.as_deref() {
        if let Err(response) =
            ensure_object_version_lock_allows_delete(&state, &bucket, &key, version_id, &headers)
                .await
        {
            return response;
        }
        return match state
            .storage
            .delete_object_version(&bucket, &key, version_id)
            .await
        {
            Ok(outcome) => {
                let mut resp_headers = HeaderMap::new();
                if let Some(ref vid) = outcome.version_id {
                    if let Ok(value) = vid.parse() {
                        resp_headers.insert("x-amz-version-id", value);
                    }
                }
                if outcome.is_delete_marker {
                    resp_headers.insert("x-amz-delete-marker", "true".parse().unwrap());
                }
                notifications::emit_object_removed(&state, &bucket, &key, "", "", "", "Delete");
                trigger_replication_for_request(&state, peer_marker, &bucket, &key, "delete");
                (StatusCode::NO_CONTENT, resp_headers).into_response()
            }
            Err(e) => storage_err_response(e),
        };
    }

    if let Err(response) =
        ensure_object_lock_allows_write(&state, &bucket, &key, Some(&headers)).await
    {
        return response;
    }

    match state.storage.delete_object(&bucket, &key).await {
        Ok(outcome) => {
            let mut resp_headers = HeaderMap::new();
            if let Some(ref vid) = outcome.version_id {
                if let Ok(value) = vid.parse() {
                    resp_headers.insert("x-amz-version-id", value);
                }
            }
            if outcome.is_delete_marker {
                resp_headers.insert("x-amz-delete-marker", "true".parse().unwrap());
            }
            notifications::emit_object_removed(&state, &bucket, &key, "", "", "", "Delete");
            trigger_replication_for_request(&state, peer_marker, &bucket, &key, "delete");
            (StatusCode::NO_CONTENT, resp_headers).into_response()
        }
        Err(e) => storage_err_response(e),
    }
}

pub async fn head_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(query): Query<ObjectQuery>,
    headers: HeaderMap,
) -> Response {
    let version_id = query.version_id.as_deref();
    let result = match version_id {
        Some(version_id) => {
            state
                .storage
                .head_object_version(&bucket, &key, version_id)
                .await
        }
        None => state.storage.head_object(&bucket, &key).await,
    };

    match result {
        Ok(meta) => {
            if let Some(resp) = evaluate_get_preconditions(&headers, &meta) {
                return resp;
            }

            let enc_info = myfsio_crypto::encryption::EncryptionMetadata::from_metadata(
                &meta.internal_metadata,
            );
            if let Some(ref info) = enc_info {
                if info.algorithm == "AES256" && info.encrypted_data_key.is_none() {
                    if let Err(resp) = require_sse_c_key_match(&headers, info) {
                        return resp;
                    }
                }
            }

            let part_view = match query.part_number {
                Some(n) => match resolve_part_view(&meta, n) {
                    Ok(v) => Some(v),
                    Err(resp) => return resp,
                },
                None => None,
            };

            if let Some(view) = part_view.as_ref().filter(|v| v.multipart) {
                let mut headers = build_part_response_headers(&key, &meta, view, &query);
                apply_user_metadata(&mut headers, &meta.metadata);
                return (StatusCode::PARTIAL_CONTENT, headers).into_response();
            }

            let mut headers = HeaderMap::new();
            let plaintext_size = enc_info
                .as_ref()
                .and_then(|info| info.plaintext_size)
                .unwrap_or(meta.size);
            headers.insert(
                "content-length",
                plaintext_size.to_string().parse().unwrap(),
            );
            if let Some(ref etag) = meta.etag {
                headers.insert("etag", format!("\"{}\"", etag).parse().unwrap());
            }
            insert_content_type(&mut headers, &key, meta.content_type.as_deref());
            headers.insert(
                "last-modified",
                meta.last_modified
                    .format("%a, %d %b %Y %H:%M:%S GMT")
                    .to_string()
                    .parse()
                    .unwrap(),
            );
            headers.insert("accept-ranges", "bytes".parse().unwrap());
            if let Some(ref enc_info) = enc_info {
                if let Ok(alg) = enc_info.algorithm.as_str().parse() {
                    headers.insert("x-amz-server-side-encryption", alg);
                }
            }
            apply_stored_response_headers(&mut headers, &meta.internal_metadata);
            apply_stored_checksum_headers(&mut headers, &meta.internal_metadata);
            if let Some(ref requested_version) = query.version_id {
                if let Ok(value) = requested_version.parse() {
                    headers.insert("x-amz-version-id", value);
                }
            } else if let Some(ref vid) = meta.version_id {
                if let Ok(value) = vid.parse() {
                    headers.insert("x-amz-version-id", value);
                }
            }

            apply_user_metadata(&mut headers, &meta.metadata);

            (StatusCode::OK, headers).into_response()
        }
        Err(e) => storage_err_response(e),
    }
}

struct PartView {
    start: u64,
    length: u64,
    parts_count: u32,
    multipart: bool,
}

fn build_part_response_headers(
    key: &str,
    meta: &myfsio_common::types::ObjectMeta,
    view: &PartView,
    query: &ObjectQuery,
) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("content-length", view.length.to_string().parse().unwrap());
    if view.length > 0 {
        headers.insert(
            "content-range",
            format!(
                "bytes {}-{}/{}",
                view.start,
                view.start + view.length - 1,
                meta.size
            )
            .parse()
            .unwrap(),
        );
    }
    if let Some(ref etag) = meta.etag {
        headers.insert("etag", format!("\"{}\"", etag).parse().unwrap());
    }
    insert_content_type(&mut headers, key, meta.content_type.as_deref());
    headers.insert(
        "last-modified",
        meta.last_modified
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string()
            .parse()
            .unwrap(),
    );
    headers.insert("accept-ranges", "bytes".parse().unwrap());
    if let Some(enc_info) =
        myfsio_crypto::encryption::EncryptionMetadata::from_metadata(&meta.internal_metadata)
    {
        if let Ok(alg) = enc_info.algorithm.as_str().parse() {
            headers.insert("x-amz-server-side-encryption", alg);
        }
    }
    apply_stored_response_headers(&mut headers, &meta.internal_metadata);
    if let Some(ref requested_version) = query.version_id {
        if let Ok(value) = requested_version.parse() {
            headers.insert("x-amz-version-id", value);
        }
    } else if let Some(ref vid) = meta.version_id {
        if let Ok(value) = vid.parse() {
            headers.insert("x-amz-version-id", value);
        }
    }
    headers.insert(
        "x-amz-mp-parts-count",
        view.parts_count.to_string().parse().unwrap(),
    );
    apply_response_overrides(&mut headers, query);
    headers
}

fn resolve_part_view(
    meta: &myfsio_common::types::ObjectMeta,
    part_number: u32,
) -> Result<PartView, Response> {
    if part_number < 1 {
        return Err(s3_error_response(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "partNumber must be >= 1",
        )));
    }

    let etag = meta.etag.as_deref().unwrap_or("");
    let is_multipart = myfsio_storage::fs_backend::is_multipart_etag(etag);

    if !is_multipart {
        if part_number == 1 {
            return Ok(PartView {
                start: 0,
                length: meta.size,
                parts_count: 1,
                multipart: false,
            });
        }
        return Err(s3_error_response(S3Error::new(
            S3ErrorCode::InvalidPart,
            format!(
                "partNumber {} is out of range for a non-multipart object",
                part_number
            ),
        )));
    }

    let part_sizes = match meta
        .internal_metadata
        .get(myfsio_storage::fs_backend::META_KEY_PART_SIZES)
        .and_then(|raw| myfsio_storage::fs_backend::parse_part_sizes(raw))
    {
        Some(sizes) => sizes,
        None => {
            return Err(s3_error_response(S3Error::new(
                S3ErrorCode::InvalidRequest,
                "Object is multipart but has no recorded part-size manifest; \
                 partNumber addressing is unavailable",
            )));
        }
    };

    let idx = (part_number as usize).saturating_sub(1);
    if idx >= part_sizes.len() {
        return Err(s3_error_response(S3Error::new(
            S3ErrorCode::InvalidPart,
            format!(
                "partNumber {} exceeds the {} parts in this object",
                part_number,
                part_sizes.len()
            ),
        )));
    }

    let start: u64 = part_sizes.iter().take(idx).sum();
    let length = part_sizes[idx];
    Ok(PartView {
        start,
        length,
        parts_count: part_sizes.len() as u32,
        multipart: true,
    })
}

const MULTIPART_PENDING_SSE_ALG: &str = "__pending_sse_algorithm__";
const MULTIPART_PENDING_SSE_KMS_KEY: &str = "__pending_sse_kms_key_id__";
const MULTIPART_PENDING_SSE_C_KEY: &str = "__pending_sse_c_customer_key__";

async fn initiate_multipart_handler(
    state: &AppState,
    bucket: &str,
    key: &str,
    headers: &HeaderMap,
) -> Response {
    let mut metadata: HashMap<String, String> = HashMap::new();
    if let Err(resp) = insert_standard_object_metadata(headers, &mut metadata) {
        return resp;
    }
    if let Err(resp) = validate_sse_request(state, headers) {
        return resp;
    }
    let resolved_enc_ctx = match resolve_encryption_context(state, bucket, headers).await {
        Ok(ctx) => ctx,
        Err(resp) => return resp,
    };
    if let Some(ref ctx) = resolved_enc_ctx {
        metadata.insert(
            MULTIPART_PENDING_SSE_ALG.to_string(),
            ctx.algorithm.as_str().to_string(),
        );
        if let Some(ref kid) = ctx.kms_key_id {
            metadata.insert(MULTIPART_PENDING_SSE_KMS_KEY.to_string(), kid.clone());
        }
        if let Some(ref ck) = ctx.customer_key {
            use base64::engine::general_purpose::STANDARD as B64;
            use base64::Engine;
            metadata.insert(
                MULTIPART_PENDING_SSE_C_KEY.to_string(),
                B64.encode(ck),
            );
        }
    }
    if let Some(value) = headers.get("x-amz-tagging").and_then(|v| v.to_str().ok()) {
        let tags = match parse_tagging_header(value) {
            Ok(tags) => tags,
            Err(resp) => return resp,
        };
        if tags.len() > state.config.object_tag_limit {
            return s3_error_response(S3Error::new(
                S3ErrorCode::InvalidTag,
                format!("Maximum {} tags allowed", state.config.object_tag_limit),
            ));
        }
        metadata.insert("__pending_tagging__".to_string(), value.to_string());
    }
    let initial = if metadata.is_empty() {
        None
    } else {
        Some(metadata)
    };
    match state.storage.initiate_multipart(bucket, key, initial).await {
        Ok(upload_id) => {
            let xml = myfsio_xml::response::initiate_multipart_upload_xml(bucket, key, &upload_id);
            let mut headers = HeaderMap::new();
            headers.insert("content-type", "application/xml".parse().unwrap());
            if let Some(ref ctx) = resolved_enc_ctx {
                if let Ok(alg) = ctx.algorithm.as_str().parse() {
                    headers.insert("x-amz-server-side-encryption", alg);
                }
                if let Some(ref kid) = ctx.kms_key_id {
                    if let Ok(value) = kid.parse() {
                        headers
                            .insert("x-amz-server-side-encryption-aws-kms-key-id", value);
                    }
                }
            }
            (StatusCode::OK, headers, xml).into_response()
        }
        Err(e) => storage_err_response(e),
    }
}

async fn read_pending_multipart_sse(
    state: &AppState,
    bucket: &str,
    key: &str,
) -> Option<(myfsio_crypto::encryption::EncryptionContext, HashMap<String, String>)> {
    let stored = state.storage.get_object_metadata(bucket, key).await.ok()?;
    let alg = stored.get(MULTIPART_PENDING_SSE_ALG)?.clone();
    let kms_key_id = stored.get(MULTIPART_PENDING_SSE_KMS_KEY).cloned();
    let customer_key = stored.get(MULTIPART_PENDING_SSE_C_KEY).and_then(|s| {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;
        B64.decode(s).ok()
    });
    let algorithm = match alg.as_str() {
        "AES256" if customer_key.is_some() => {
            myfsio_crypto::encryption::SseAlgorithm::CustomerProvided
        }
        "AES256" => myfsio_crypto::encryption::SseAlgorithm::Aes256,
        "aws:kms" => myfsio_crypto::encryption::SseAlgorithm::AwsKms,
        _ => return None,
    };
    Some((
        myfsio_crypto::encryption::EncryptionContext {
            algorithm,
            kms_key_id,
            customer_key,
        },
        stored,
    ))
}

async fn upload_part_handler_with_chunking(
    state: &AppState,
    bucket: &str,
    upload_id: &str,
    part_number: u32,
    body: Body,
    aws_chunked: bool,
) -> Response {
    let boxed: myfsio_storage::traits::AsyncReadStream = if aws_chunked {
        Box::pin(chunked::decode_body(body))
    } else {
        let stream = tokio_util::io::StreamReader::new(
            body.into_data_stream()
                .map_err(std::io::Error::other),
        );
        Box::pin(stream)
    };

    match state
        .storage
        .upload_part(bucket, upload_id, part_number, boxed)
        .await
    {
        Ok(etag) => {
            let mut headers = HeaderMap::new();
            headers.insert("etag", format!("\"{}\"", etag).parse().unwrap());
            (StatusCode::OK, headers).into_response()
        }
        Err(e) => storage_err_response(e),
    }
}

async fn upload_part_copy_handler(
    state: &AppState,
    dst_bucket: &str,
    upload_id: &str,
    part_number: u32,
    copy_source: &str,
    range_header: Option<&str>,
    headers: &HeaderMap,
) -> Response {
    let (src_bucket, src_key, src_version_id) = match parse_copy_source(copy_source) {
        Ok(parts) => parts,
        Err(response) => return response,
    };

    let source_meta = match src_version_id.as_deref() {
        Some(version_id) => match state
            .storage
            .head_object_version(&src_bucket, &src_key, version_id)
            .await
        {
            Ok(m) => m,
            Err(e) => return storage_err_response(e),
        },
        None => match state.storage.head_object(&src_bucket, &src_key).await {
            Ok(m) => m,
            Err(e) => return storage_err_response(e),
        },
    };
    if let Some(resp) = evaluate_copy_preconditions(headers, &source_meta) {
        return resp;
    }

    let range = match range_header {
        Some(r) => match parse_copy_source_range(r) {
            Some(parsed) => Some(parsed),
            None => {
                return s3_error_response(S3Error::new(
                    myfsio_common::error::S3ErrorCode::InvalidArgument,
                    "Invalid x-amz-copy-source-range",
                ));
            }
        },
        None => None,
    };

    match state
        .storage
        .upload_part_copy(
            dst_bucket,
            upload_id,
            part_number,
            &src_bucket,
            &src_key,
            src_version_id.as_deref(),
            range,
        )
        .await
    {
        Ok((etag, last_modified)) => {
            let lm = myfsio_xml::response::format_s3_datetime(&last_modified);
            let xml = myfsio_xml::response::copy_part_result_xml(&etag, &lm);
            (StatusCode::OK, [("content-type", "application/xml")], xml).into_response()
        }
        Err(e) => storage_err_response(e),
    }
}

fn parse_copy_source_range(value: &str) -> Option<(u64, u64)> {
    let v = value.trim();
    let v = v.strip_prefix("bytes=")?;
    let (start, end) = v.split_once('-')?;
    let start: u64 = start.trim().parse().ok()?;
    let end: u64 = end.trim().parse().ok()?;
    if start > end {
        return None;
    }
    Some((start, end))
}

async fn complete_multipart_handler(
    state: &AppState,
    bucket: &str,
    key: &str,
    upload_id: &str,
    peer_marker: Option<&crate::middleware::ReplicationPeerRequest>,
    headers: &HeaderMap,
    body: Body,
) -> Response {
    let manifest_key = match state.storage.list_multipart_uploads(bucket).await {
        Ok(uploads) => uploads
            .into_iter()
            .find(|u| u.upload_id == upload_id)
            .map(|u| u.key),
        Err(e) => return storage_err_response(e),
    };
    let manifest_key = match manifest_key {
        Some(k) => k,
        None => {
            return s3_error_response(S3Error::new(
                S3ErrorCode::NoSuchUpload,
                format!("Upload '{}' not found", upload_id),
            ));
        }
    };
    if manifest_key != key {
        return s3_error_response(S3Error::new(
            S3ErrorCode::NoSuchUpload,
            "The upload id does not belong to the requested object key",
        ));
    }

    if let Err(response) =
        ensure_archived_null_lock_allows_overwrite(state, bucket, key, Some(headers)).await
    {
        return response;
    }

    let body_bytes = match http_body_util::BodyExt::collect(body).await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return s3_error_response(S3Error::new(
                myfsio_common::error::S3ErrorCode::MalformedXML,
                "Failed to read request body",
            ));
        }
    };

    let xml_str = String::from_utf8_lossy(&body_bytes);
    let parsed = match myfsio_xml::request::parse_complete_multipart_upload(&xml_str) {
        Ok(p) => p,
        Err(e) => {
            return s3_error_response(S3Error::new(
                myfsio_common::error::S3ErrorCode::MalformedXML,
                e,
            ));
        }
    };

    if parsed.parts.is_empty() {
        return s3_error_response(S3Error::new(
            S3ErrorCode::MalformedXML,
            "CompleteMultipartUpload requires at least one part",
        ));
    }

    let mut last_part_num: u32 = 0;
    for p in &parsed.parts {
        if p.part_number == 0 {
            return s3_error_response(S3Error::new(
                S3ErrorCode::InvalidPartOrder,
                "Part numbers must be greater than zero",
            ));
        }
        if p.part_number <= last_part_num {
            return s3_error_response(S3Error::new(
                S3ErrorCode::InvalidPartOrder,
                "Parts must be specified in ascending order with no duplicates",
            ));
        }
        last_part_num = p.part_number;
    }

    let stored_parts = match state.storage.list_parts(bucket, upload_id).await {
        Ok(list) => list,
        Err(e) => return storage_err_response(e),
    };
    let stored_map: HashMap<u32, (String, u64)> = stored_parts
        .iter()
        .map(|p| (p.part_number, (p.etag.clone(), p.size)))
        .collect();
    let min_part_size: u64 = state.config.multipart_min_part_size;
    let total_parts = parsed.parts.len();
    for (idx, p) in parsed.parts.iter().enumerate() {
        let stored = match stored_map.get(&p.part_number) {
            Some(s) => s,
            None => {
                return s3_error_response(S3Error::new(
                    S3ErrorCode::InvalidPart,
                    format!("Part {} not found", p.part_number),
                ));
            }
        };
        let client_etag = p.etag.trim().trim_matches('"').to_ascii_lowercase();
        let stored_etag = stored.0.trim().trim_matches('"').to_ascii_lowercase();
        if !client_etag.is_empty() && client_etag != stored_etag {
            return s3_error_response(S3Error::new(
                S3ErrorCode::InvalidPart,
                format!("ETag mismatch for part {}", p.part_number),
            ));
        }
        let is_final = idx + 1 == total_parts;
        if !is_final && stored.1 < min_part_size {
            return s3_error_response(S3Error::new(
                S3ErrorCode::EntityTooSmall,
                format!(
                    "Part {} is smaller than the minimum allowed size of {} bytes",
                    p.part_number, min_part_size
                ),
            ));
        }
    }

    let parts: Vec<PartInfo> = parsed
        .parts
        .iter()
        .map(|p| PartInfo {
            part_number: p.part_number,
            etag: p.etag.clone(),
        })
        .collect();

    match state
        .storage
        .complete_multipart(bucket, upload_id, &parts)
        .await
    {
        Ok(meta) => {
            let Some(etag) = meta.etag.as_deref() else {
                tracing::error!(
                    bucket = bucket,
                    key = key,
                    upload_id = upload_id,
                    "complete_multipart returned meta without etag"
                );
                return s3_error_response(S3Error::from_code(S3ErrorCode::InternalError));
            };
            apply_pending_multipart_tagging(state, bucket, key).await;

            let pending_sse = read_pending_multipart_sse(state, bucket, key).await;

            let mut sse_alg_response: Option<String> = None;
            let mut sse_kms_id_response: Option<String> = None;
            if let Some((enc_ctx, _)) = pending_sse {
                let Some(enc_svc) = state.encryption.as_ref() else {
                    let _ = state.storage.delete_object(bucket, key).await;
                    return s3_error_response(S3Error::new(
                        S3ErrorCode::InternalError,
                        "Encryption requested for multipart upload but encryption service is disabled",
                    ));
                };
                let obj_path = match state.storage.get_object_path(bucket, key).await {
                    Ok(p) => p,
                    Err(e) => return storage_err_response(e),
                };
                let tmp_dir = state.config.storage_root.join(".myfsio.sys").join("tmp");
                let _ = tokio::fs::create_dir_all(&tmp_dir).await;
                let enc_tmp = tmp_dir.join(format!("mp-enc-{}", uuid::Uuid::new_v4()));
                match enc_svc.encrypt_object(&obj_path, &enc_tmp, &enc_ctx).await {
                    Ok(enc_meta) => {
                        if let Err(e) = tokio::fs::rename(&enc_tmp, &obj_path).await {
                            let _ = tokio::fs::remove_file(&enc_tmp).await;
                            let _ = state.storage.delete_object(bucket, key).await;
                            return storage_err_response(
                                myfsio_storage::error::StorageError::Io(e),
                            );
                        }
                        let enc_size = tokio::fs::metadata(&obj_path)
                            .await
                            .map(|m| m.len())
                            .unwrap_or(0);
                        let mut enc_metadata = enc_meta.to_metadata_map();
                        let all_meta = state
                            .storage
                            .get_object_metadata(bucket, key)
                            .await
                            .unwrap_or_default();
                        for (k, v) in &all_meta {
                            if k == MULTIPART_PENDING_SSE_ALG
                                || k == MULTIPART_PENDING_SSE_KMS_KEY
                                || k == MULTIPART_PENDING_SSE_C_KEY
                            {
                                continue;
                            }
                            enc_metadata.entry(k.clone()).or_insert_with(|| v.clone());
                        }
                        enc_metadata.insert("__size__".to_string(), enc_size.to_string());
                        let _ = state
                            .storage
                            .put_object_metadata(bucket, key, &enc_metadata)
                            .await;
                        sse_alg_response = Some(enc_ctx.algorithm.as_str().to_string());
                        sse_kms_id_response = enc_ctx.kms_key_id.clone();
                    }
                    Err(e) => {
                        let _ = tokio::fs::remove_file(&enc_tmp).await;
                        let _ = state.storage.delete_object(bucket, key).await;
                        return s3_error_response(S3Error::new(
                            S3ErrorCode::InternalError,
                            format!("Encryption failed during multipart complete: {}", e),
                        ));
                    }
                }
            }

            let xml = myfsio_xml::response::complete_multipart_upload_xml(
                bucket,
                key,
                etag,
                &format!("/{}/{}", bucket, key),
            );
            notifications::emit_object_created(
                state,
                bucket,
                key,
                meta.size,
                Some(etag),
                "",
                "",
                "",
                "CompleteMultipartUpload",
            );
            trigger_replication_for_request(state, peer_marker, bucket, key, "write");
            let mut resp_headers = HeaderMap::new();
            resp_headers.insert("content-type", "application/xml".parse().unwrap());
            if let Some(alg) = sse_alg_response {
                if let Ok(value) = alg.parse() {
                    resp_headers.insert("x-amz-server-side-encryption", value);
                }
            }
            if let Some(kid) = sse_kms_id_response {
                if let Ok(value) = kid.parse() {
                    resp_headers
                        .insert("x-amz-server-side-encryption-aws-kms-key-id", value);
                }
            }
            (StatusCode::OK, resp_headers, xml).into_response()
        }
        Err(e) => storage_err_response(e),
    }
}

async fn apply_pending_multipart_tagging(state: &AppState, bucket: &str, key: &str) {
    let mut stored = match state.storage.get_object_metadata(bucket, key).await {
        Ok(m) => m,
        Err(_) => return,
    };
    let raw = match stored.remove("__pending_tagging__") {
        Some(v) if !v.is_empty() => v,
        _ => return,
    };
    let tags = match parse_tagging_header(&raw) {
        Ok(tags) => tags,
        Err(_) => {
            tracing::warn!(
                bucket = bucket,
                key = key,
                "discarding malformed __pending_tagging__ value from multipart manifest"
            );
            let _ = state.storage.put_object_metadata(bucket, key, &stored).await;
            return;
        }
    };
    if tags.len() > state.config.object_tag_limit {
        tracing::warn!(
            bucket = bucket,
            key = key,
            "skipping multipart tagging: exceeds object_tag_limit"
        );
        let _ = state.storage.put_object_metadata(bucket, key, &stored).await;
        return;
    }
    if !tags.is_empty() {
        if let Err(e) = state.storage.set_object_tags(bucket, key, &tags).await {
            tracing::error!(
                bucket = bucket,
                key = key,
                error = %e,
                "failed to apply pending multipart tagging"
            );
        }
    }
    if let Err(e) = state.storage.put_object_metadata(bucket, key, &stored).await {
        tracing::error!(
            bucket = bucket,
            key = key,
            error = %e,
            "failed to clear __pending_tagging__ marker after applying tags"
        );
    }
}

async fn abort_multipart_handler(state: &AppState, bucket: &str, upload_id: &str) -> Response {
    match state.storage.abort_multipart(bucket, upload_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => storage_err_response(e),
    }
}

async fn list_multipart_uploads_handler(
    state: &AppState,
    bucket: &str,
    query: &BucketQuery,
) -> Response {
    if let Some(0) = query.max_uploads {
        return s3_error_response(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "max-uploads must be at least 1",
        ));
    }
    let max_uploads = query.max_uploads.unwrap_or(1000).clamp(1, 1000);
    let key_marker = query.key_marker.as_deref().unwrap_or("");
    let upload_id_marker_opt = query.upload_id_marker.as_deref();
    let upload_id_marker = upload_id_marker_opt.unwrap_or("");
    match state.storage.list_multipart_uploads(bucket).await {
        Ok(mut uploads) => {
            uploads.sort_by(|a, b| a.key.cmp(&b.key).then(a.upload_id.cmp(&b.upload_id)));

            let start = if key_marker.is_empty() && upload_id_marker_opt.is_none() {
                0
            } else if upload_id_marker_opt.is_some() {
                uploads
                    .iter()
                    .position(|u| {
                        u.key.as_str() > key_marker
                            || (u.key == key_marker && u.upload_id.as_str() > upload_id_marker)
                    })
                    .unwrap_or(uploads.len())
            } else {
                uploads
                    .iter()
                    .position(|u| u.key.as_str() > key_marker)
                    .unwrap_or(uploads.len())
            };
            let end = (start + max_uploads).min(uploads.len());
            let is_truncated = end < uploads.len();
            let page = &uploads[start..end];
            let (next_key, next_upload) = if is_truncated {
                page.last()
                    .map(|u| (u.key.clone(), u.upload_id.clone()))
                    .unwrap_or_default()
            } else {
                (String::new(), String::new())
            };
            let params = myfsio_xml::response::ListMultipartUploadsParams {
                bucket,
                key_marker,
                upload_id_marker,
                next_key_marker: &next_key,
                next_upload_id_marker: &next_upload,
                max_uploads,
                is_truncated,
                uploads: page,
            };
            let xml = myfsio_xml::response::list_multipart_uploads_xml_paged(&params);
            (StatusCode::OK, [("content-type", "application/xml")], xml).into_response()
        }
        Err(e) => storage_err_response(e),
    }
}

async fn list_parts_handler(
    state: &AppState,
    bucket: &str,
    key: &str,
    upload_id: &str,
    query: &ObjectQuery,
) -> Response {
    if let Some(0) = query.max_parts {
        return s3_error_response(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "max-parts must be at least 1",
        ));
    }
    let max_parts = query.max_parts.unwrap_or(1000).clamp(1, 1000);
    let part_number_marker = query.part_number_marker.unwrap_or(0);
    match state.storage.list_parts(bucket, upload_id).await {
        Ok(mut parts) => {
            parts.sort_by_key(|p| p.part_number);
            let start = parts
                .iter()
                .position(|p| p.part_number > part_number_marker)
                .unwrap_or(parts.len());
            let end = (start + max_parts).min(parts.len());
            let is_truncated = end < parts.len();
            let page = &parts[start..end];
            let next_part_number_marker = page
                .last()
                .map(|p| p.part_number)
                .unwrap_or(part_number_marker);
            let params = myfsio_xml::response::ListPartsParams {
                bucket,
                key,
                upload_id,
                part_number_marker,
                next_part_number_marker,
                max_parts,
                is_truncated,
                parts: page,
            };
            let xml = myfsio_xml::response::list_parts_xml_paged(&params);
            (StatusCode::OK, [("content-type", "application/xml")], xml).into_response()
        }
        Err(e) => storage_err_response(e),
    }
}

async fn object_attributes_handler(
    state: &AppState,
    bucket: &str,
    key: &str,
    headers: &HeaderMap,
) -> Response {
    let meta = match state.storage.head_object(bucket, key).await {
        Ok(m) => m,
        Err(e) => return storage_err_response(e),
    };

    let requested = headers
        .get("x-amz-object-attributes")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let attrs: std::collections::HashSet<String> = requested
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    let all = attrs.is_empty();

    let stored_meta = state
        .storage
        .get_object_metadata(bucket, key)
        .await
        .unwrap_or_default();

    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    xml.push_str("<GetObjectAttributesResponse xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");

    if all || attrs.contains("etag") {
        if let Some(etag) = &meta.etag {
            let trimmed = etag.trim_matches('"');
            xml.push_str(&format!("<ETag>\"{}\"</ETag>", xml_escape(trimmed)));
        }
    }
    if all || attrs.contains("storageclass") {
        let sc = meta.storage_class.as_deref().unwrap_or("STANDARD");
        xml.push_str(&format!("<StorageClass>{}</StorageClass>", xml_escape(sc)));
    }
    if all || attrs.contains("objectsize") {
        xml.push_str(&format!("<ObjectSize>{}</ObjectSize>", meta.size));
    }
    if all || attrs.contains("checksum") {
        let mut checksum_xml = String::new();
        for (algo, tag) in [
            ("sha256", "ChecksumSHA256"),
            ("sha1", "ChecksumSHA1"),
            ("crc32", "ChecksumCRC32"),
            ("crc32c", "ChecksumCRC32C"),
            ("crc64nvme", "ChecksumCRC64NVME"),
        ] {
            let key_name = format!("__checksum_{}__", algo);
            if let Some(value) = stored_meta.get(&key_name) {
                let trimmed = value.trim();
                if !trimmed.is_empty() {
                    checksum_xml.push_str(&format!(
                        "<{tag}>{}</{tag}>",
                        xml_escape(trimmed),
                        tag = tag
                    ));
                }
            }
        }
        if !checksum_xml.is_empty() {
            xml.push_str("<Checksum>");
            xml.push_str(&checksum_xml);
            xml.push_str("</Checksum>");
        }
    }
    if attrs.contains("objectparts") {
        xml.push_str("<ObjectParts></ObjectParts>");
    }

    xml.push_str("</GetObjectAttributesResponse>");
    (StatusCode::OK, [("content-type", "application/xml")], xml).into_response()
}

async fn copy_object_handler(
    state: &AppState,
    copy_source: &str,
    dst_bucket: &str,
    dst_key: &str,
    peer_marker: Option<&crate::middleware::ReplicationPeerRequest>,
    headers: &HeaderMap,
) -> Response {
    if let Err(response) =
        ensure_object_lock_allows_write(state, dst_bucket, dst_key, Some(headers)).await
    {
        return response;
    }
    if let Err(response) =
        ensure_archived_null_lock_allows_overwrite(state, dst_bucket, dst_key, Some(headers)).await
    {
        return response;
    }

    let (src_bucket, src_key, src_version_id) = match parse_copy_source(copy_source) {
        Ok(parts) => parts,
        Err(response) => return response,
    };

    let source_meta = match src_version_id.as_deref() {
        Some(version_id) => match state
            .storage
            .head_object_version(&src_bucket, &src_key, version_id)
            .await
        {
            Ok(m) => m,
            Err(e) => return storage_err_response(e),
        },
        None => match state.storage.head_object(&src_bucket, &src_key).await {
            Ok(m) => m,
            Err(e) => return storage_err_response(e),
        },
    };
    if let Some(resp) = evaluate_copy_preconditions(headers, &source_meta) {
        return resp;
    }

    let metadata_directive = headers
        .get("x-amz-metadata-directive")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_ascii_uppercase())
        .unwrap_or_else(|| "COPY".to_string());
    let tagging_directive = headers
        .get("x-amz-tagging-directive")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_ascii_uppercase())
        .unwrap_or_else(|| "COPY".to_string());
    let replace_metadata = metadata_directive == "REPLACE";
    let replace_tagging = tagging_directive == "REPLACE";

    let same_object = src_bucket == dst_bucket
        && src_key == dst_key
        && src_version_id.as_deref().unwrap_or("").is_empty();
    if same_object && !replace_metadata && !replace_tagging {
        return s3_error_response(S3Error::new(
            S3ErrorCode::InvalidRequest,
            "This copy request is illegal because it is trying to copy an object to itself without changing the object's metadata, storage class, website redirect location or encryption attributes.",
        ));
    }

    let resolved_tags: Option<Vec<myfsio_common::types::Tag>> = if replace_tagging {
        let parsed = match headers
            .get("x-amz-tagging")
            .and_then(|value| value.to_str().ok())
            .map(parse_tagging_header)
            .transpose()
        {
            Ok(tags) => tags,
            Err(response) => return response,
        };
        let tags = parsed.unwrap_or_default();
        if tags.len() > state.config.object_tag_limit {
            return s3_error_response(S3Error::new(
                S3ErrorCode::InvalidTag,
                format!("Maximum {} tags allowed", state.config.object_tag_limit),
            ));
        }
        Some(tags)
    } else {
        let lookup = match src_version_id.as_deref() {
            Some(version_id) => {
                state
                    .storage
                    .get_object_version_tags(&src_bucket, &src_key, version_id)
                    .await
            }
            None => state.storage.get_object_tags(&src_bucket, &src_key).await,
        };
        match lookup {
            Ok(tags) => Some(tags),
            Err(myfsio_storage::error::StorageError::ObjectNotFound { .. }) => None,
            Err(myfsio_storage::error::StorageError::VersionNotFound { .. }) => None,
            Err(e) => return storage_err_response(e),
        }
    };

    let mut dst_enc_ctx = match resolve_encryption_context(state, dst_bucket, headers).await {
        Ok(ctx) => ctx,
        Err(resp) => return resp,
    };

    if dst_enc_ctx.is_none() {
        let src_alg = source_meta
            .internal_metadata
            .get("x-amz-server-side-encryption")
            .map(|s| s.as_str());
        match src_alg {
            Some("AES256") => {
                let is_sse_c = !source_meta
                    .internal_metadata
                    .contains_key("x-amz-encrypted-data-key");
                if !is_sse_c && state.encryption.is_some() {
                    dst_enc_ctx = Some(myfsio_crypto::encryption::EncryptionContext {
                        algorithm: myfsio_crypto::encryption::SseAlgorithm::Aes256,
                        kms_key_id: None,
                        customer_key: None,
                    });
                }
            }
            Some("aws:kms") => {
                let kid = source_meta
                    .internal_metadata
                    .get("x-amz-encryption-key-id")
                    .cloned();
                if state.encryption.is_some() && kid.is_some() {
                    dst_enc_ctx = Some(myfsio_crypto::encryption::EncryptionContext {
                        algorithm: myfsio_crypto::encryption::SseAlgorithm::AwsKms,
                        kms_key_id: kid,
                        customer_key: None,
                    });
                }
            }
            _ => {}
        }
    }

    let tmp_dir = state.config.storage_root.join(".myfsio.sys").join("tmp");
    if let Err(e) = tokio::fs::create_dir_all(&tmp_dir).await {
        return storage_err_response(myfsio_storage::error::StorageError::Io(e));
    }

    let src_snap = tmp_dir.join(format!("copy-src-{}", uuid::Uuid::new_v4()));
    let snap_meta = match src_version_id.as_deref() {
        Some(version_id) => {
            state
                .storage
                .snapshot_object_version_to_link(&src_bucket, &src_key, version_id, &src_snap)
                .await
        }
        None => {
            state
                .storage
                .snapshot_object_to_link(&src_bucket, &src_key, &src_snap)
                .await
        }
    };
    let snap_meta = match snap_meta {
        Ok(m) => m,
        Err(e) => {
            let _ = tokio::fs::remove_file(&src_snap).await;
            return storage_err_response(e);
        }
    };

    let snap_internal = &snap_meta.internal_metadata;

    let dst_metadata = if replace_metadata {
        let mut m: HashMap<String, String> = HashMap::new();
        for (request_header, metadata_key, _) in internal_header_pairs() {
            if let Some(value) = headers.get(*request_header).and_then(|v| v.to_str().ok()) {
                if *request_header == "content-encoding" {
                    if let Some(decoded_encoding) = decoded_content_encoding(value) {
                        m.insert((*metadata_key).to_string(), decoded_encoding);
                    }
                } else {
                    m.insert((*metadata_key).to_string(), value.to_string());
                }
            }
        }
        let content_type = guessed_content_type(
            dst_key,
            headers.get("content-type").and_then(|v| v.to_str().ok()),
        );
        m.insert("__content_type__".to_string(), content_type);
        for (name, value) in headers.iter() {
            let name_str = name.as_str();
            if let Some(meta_key) = name_str.strip_prefix("x-amz-meta-") {
                if let Ok(val) = value.to_str() {
                    m.insert(meta_key.to_string(), val.to_string());
                }
            }
        }
        if let Some(value) = headers
            .get("x-amz-storage-class")
            .and_then(|v| v.to_str().ok())
        {
            let upper = value.to_ascii_uppercase();
            if !VALID_STORAGE_CLASSES.contains(&upper.as_str()) {
                let _ = tokio::fs::remove_file(&src_snap).await;
                return s3_error_response(S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    "Invalid x-amz-storage-class",
                ));
            }
            m.insert("__storage_class__".to_string(), upper);
        }
        m
    } else {
        let mut m = snap_internal.clone();
        myfsio_crypto::encryption::EncryptionMetadata::clean_metadata(&mut m);
        m
    };

    let src_enc_info =
        myfsio_crypto::encryption::EncryptionMetadata::from_metadata(snap_internal);

    let plaintext_path = if let Some(enc_info) = src_enc_info.as_ref() {
        let Some(enc_svc) = state.encryption.as_ref() else {
            let _ = tokio::fs::remove_file(&src_snap).await;
            return s3_error_response(S3Error::new(
                S3ErrorCode::InternalError,
                "Source object is encrypted but encryption service is disabled",
            ));
        };
        let customer_key = match extract_copy_source_sse_c_key(headers) {
            Ok(k) => k,
            Err(resp) => {
                let _ = tokio::fs::remove_file(&src_snap).await;
                return resp;
            }
        };
        let dec_tmp = tmp_dir.join(format!("copy-dec-{}", uuid::Uuid::new_v4()));
        if let Err(e) = enc_svc
            .decrypt_object(&src_snap, &dec_tmp, enc_info, customer_key.as_deref())
            .await
        {
            let _ = tokio::fs::remove_file(&src_snap).await;
            let _ = tokio::fs::remove_file(&dec_tmp).await;
            return s3_error_response(S3Error::new(
                S3ErrorCode::InternalError,
                format!("Source decryption failed: {}", e),
            ));
        }
        let _ = tokio::fs::remove_file(&src_snap).await;
        dec_tmp
    } else {
        src_snap
    };

    let mut dst_metadata = dst_metadata;
    strip_storage_managed_keys(&mut dst_metadata);

    let (publish_path, publish_metadata, plaintext_etag_override) =
        if let Some(enc_ctx) = dst_enc_ctx {
            let Some(enc_svc) = state.encryption.as_ref() else {
                let _ = tokio::fs::remove_file(&plaintext_path).await;
                return s3_error_response(S3Error::new(
                    S3ErrorCode::InternalError,
                    "Encryption requested but encryption service is disabled",
                ));
            };
            let plaintext_md5 = if enc_ctx.algorithm
                == myfsio_crypto::encryption::SseAlgorithm::Aes256
            {
                match compute_plaintext_md5(&plaintext_path).await {
                    Ok(md5) => Some(md5),
                    Err(e) => {
                        let _ = tokio::fs::remove_file(&plaintext_path).await;
                        return storage_err_response(myfsio_storage::error::StorageError::Io(e));
                    }
                }
            } else {
                None
            };
            let enc_tmp = tmp_dir.join(format!("copy-enc-{}", uuid::Uuid::new_v4()));
            let enc_meta = match enc_svc
                .encrypt_object(&plaintext_path, &enc_tmp, &enc_ctx)
                .await
            {
                Ok(m) => m,
                Err(e) => {
                    let _ = tokio::fs::remove_file(&plaintext_path).await;
                    let _ = tokio::fs::remove_file(&enc_tmp).await;
                    return s3_error_response(S3Error::new(
                        S3ErrorCode::InternalError,
                        format!("Destination encryption failed: {}", e),
                    ));
                }
            };
            let _ = tokio::fs::remove_file(&plaintext_path).await;
            let mut merged = dst_metadata;
            for (k, v) in enc_meta.to_metadata_map() {
                merged.insert(k, v);
            }
            (enc_tmp, merged, plaintext_md5)
        } else {
            (plaintext_path, dst_metadata, None)
        };

    let publish_file = match tokio::fs::File::open(&publish_path).await {
        Ok(f) => f,
        Err(e) => {
            let _ = tokio::fs::remove_file(&publish_path).await;
            return storage_err_response(myfsio_storage::error::StorageError::Io(e));
        }
    };
    let reader: myfsio_storage::traits::AsyncReadStream = Box::pin(publish_file);

    let copy_result = state
        .storage
        .put_object_with_etag_override(
            dst_bucket,
            dst_key,
            reader,
            Some(publish_metadata),
            plaintext_etag_override,
        )
        .await;

    let _ = tokio::fs::remove_file(&publish_path).await;

    let meta = match copy_result {
        Ok(m) => m,
        Err(e) => return storage_err_response(e),
    };

    if let Some(tags) = resolved_tags.as_deref() {
        if let Err(e) = state
            .storage
            .set_object_tags(dst_bucket, dst_key, tags)
            .await
        {
            return storage_err_response(e);
        }
    }

    let Some(etag) = meta.etag.as_deref() else {
        tracing::error!(
            src_bucket = %src_bucket,
            src_key = %src_key,
            dst_bucket = dst_bucket,
            dst_key = dst_key,
            "copy_object stored object without etag"
        );
        return s3_error_response(S3Error::from_code(S3ErrorCode::InternalError));
    };
    let last_modified = myfsio_xml::response::format_s3_datetime(&meta.last_modified);
    let xml = myfsio_xml::response::copy_object_result_xml(etag, &last_modified);
    trigger_replication_for_request(state, peer_marker, dst_bucket, dst_key, "write");

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert("content-type", "application/xml".parse().unwrap());
    if let Some(ref vid) = meta.version_id {
        if let Ok(value) = vid.parse() {
            resp_headers.insert("x-amz-version-id", value);
        }
    }
    if let Some(ref src_vid) = src_version_id {
        if let Ok(value) = src_vid.parse() {
            resp_headers.insert("x-amz-copy-source-version-id", value);
        }
    }
    let stored = state
        .storage
        .get_object_metadata(dst_bucket, dst_key)
        .await
        .unwrap_or_default();
    apply_stored_response_headers(&mut resp_headers, &stored);
    apply_stored_checksum_headers(&mut resp_headers, &stored);
    apply_stored_encryption_headers(&mut resp_headers, &stored, headers);

    (StatusCode::OK, resp_headers, xml).into_response()
}

async fn delete_objects_handler(
    state: &AppState,
    bucket: &str,
    peer_marker: Option<&crate::middleware::ReplicationPeerRequest>,
    body: Body,
) -> Response {
    let body_bytes = match http_body_util::BodyExt::collect(body).await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return s3_error_response(S3Error::new(
                myfsio_common::error::S3ErrorCode::MalformedXML,
                "Failed to read request body",
            ));
        }
    };

    let xml_str = String::from_utf8_lossy(&body_bytes);
    let parsed = match myfsio_xml::request::parse_delete_objects(&xml_str) {
        Ok(p) => p,
        Err(e) => {
            return s3_error_response(S3Error::new(
                myfsio_common::error::S3ErrorCode::MalformedXML,
                e,
            ));
        }
    };

    if parsed.objects.len() > 1000 {
        return s3_error_response(S3Error::new(
            S3ErrorCode::MalformedXML,
            "The request must not contain more than 1000 keys",
        ));
    }

    use futures::stream::{self, StreamExt};

    let results: Vec<(
        String,
        Option<String>,
        Result<myfsio_common::types::DeleteOutcome, (String, String)>,
    )> = stream::iter(parsed.objects.iter().cloned())
        .map(|obj| {
            let state = state.clone();
            let bucket = bucket.to_string();
            async move {
                let key = obj.key.clone();
                let requested_vid = obj.version_id.clone();
                let to_err = |err: myfsio_storage::error::StorageError| -> (String, String) {
                    let s3err = S3Error::from(err);
                    (s3err.code.as_str().to_string(), s3err.message)
                };
                let run_can_delete =
                    |metadata: &HashMap<String, String>| -> Result<(), (String, String)> {
                        object_lock::can_delete_object(metadata, false)
                            .map_err(|m| (S3ErrorCode::AccessDenied.as_str().to_string(), m))
                    };
                let lock_check: Result<(), (String, String)> = match obj.version_id.as_deref() {
                    Some(version_id) => {
                        match state
                            .storage
                            .get_object_version_metadata(&bucket, &obj.key, version_id)
                            .await
                        {
                            Ok(metadata) => run_can_delete(&metadata),
                            Err(myfsio_storage::error::StorageError::VersionNotFound {
                                ..
                            }) => Ok(()),
                            Err(err) => Err(to_err(err)),
                        }
                    }
                    None => match state.storage.head_object(&bucket, &obj.key).await {
                        Ok(_)
                        | Err(myfsio_storage::error::StorageError::ObjectCorrupted { .. }) => {
                            match state.storage.get_object_metadata(&bucket, &obj.key).await {
                                Ok(metadata) => run_can_delete(&metadata),
                                Err(err) => Err(to_err(err)),
                            }
                        }
                        Err(myfsio_storage::error::StorageError::ObjectNotFound { .. }) => Ok(()),
                        Err(myfsio_storage::error::StorageError::DeleteMarker { .. }) => Ok(()),
                        Err(err) => Err(to_err(err)),
                    },
                };

                let result = match lock_check {
                    Err(e) => Err(e),
                    Ok(()) => {
                        let outcome = match obj.version_id.as_deref() {
                            Some(version_id) => {
                                state
                                    .storage
                                    .delete_object_version(&bucket, &obj.key, version_id)
                                    .await
                            }
                            None => state.storage.delete_object(&bucket, &obj.key).await,
                        };
                        outcome.map_err(|e| {
                            let s3err = S3Error::from(e);
                            (s3err.code.as_str().to_string(), s3err.message)
                        })
                    }
                };
                (key, requested_vid, result)
            }
        })
        .buffer_unordered(32)
        .collect()
        .await;

    let mut deleted: Vec<myfsio_xml::response::DeletedEntry> = Vec::new();
    let mut errors: Vec<(String, String, String)> = Vec::new();
    for (key, requested_vid, result) in results {
        match result {
            Ok(outcome) => {
                notifications::emit_object_removed(state, bucket, &key, "", "", "", "Delete");
                trigger_replication_for_request(state, peer_marker, bucket, &key, "delete");
                let delete_marker_version_id = if outcome.is_delete_marker {
                    outcome.version_id.clone()
                } else {
                    None
                };
                deleted.push(myfsio_xml::response::DeletedEntry {
                    key,
                    version_id: requested_vid,
                    delete_marker: outcome.is_delete_marker,
                    delete_marker_version_id,
                });
            }
            Err((code, message)) => {
                errors.push((key, code, message));
            }
        }
    }

    let xml = myfsio_xml::response::delete_result_xml(&deleted, &errors, parsed.quiet);
    (StatusCode::OK, [("content-type", "application/xml")], xml).into_response()
}

async fn range_get_handler(
    state: &AppState,
    bucket: &str,
    key: &str,
    range_str: &str,
    query: &ObjectQuery,
    headers: &HeaderMap,
) -> Response {
    range_get_handler_inner(state, bucket, key, range_str, query, headers, None).await
}

async fn range_get_handler_inner(
    state: &AppState,
    bucket: &str,
    key: &str,
    range_str: &str,
    query: &ObjectQuery,
    headers: &HeaderMap,
    parts_count: Option<u32>,
) -> Response {
    let version_id = query.version_id.as_deref();

    let tmp_dir = state.config.storage_root.join(".myfsio.sys").join("tmp");
    let _ = tokio::fs::create_dir_all(&tmp_dir).await;
    let snap_link = tmp_dir.join(format!("rsrc-{}", uuid::Uuid::new_v4()));

    let snap_meta = match version_id {
        Some(v) => {
            state
                .storage
                .snapshot_object_version_to_link(bucket, key, v, &snap_link)
                .await
        }
        None => {
            state
                .storage
                .snapshot_object_to_link(bucket, key, &snap_link)
                .await
        }
    };
    let meta = match snap_meta {
        Ok(m) => m,
        Err(e) => return storage_err_response(e),
    };

    serve_range_from_snapshot(state, snap_link, meta, range_str, query, headers, parts_count).await
}

async fn serve_range_from_snapshot(
    state: &AppState,
    snap_link: std::path::PathBuf,
    meta: myfsio_common::types::ObjectMeta,
    range_str: &str,
    query: &ObjectQuery,
    headers: &HeaderMap,
    parts_count: Option<u32>,
) -> Response {
    let key = meta.key.as_str();
    let tmp_dir = state.config.storage_root.join(".myfsio.sys").join("tmp");

    if let Some(resp) = evaluate_get_preconditions(headers, &meta) {
        let _ = tokio::fs::remove_file(&snap_link).await;
        return resp;
    }

    let enc_info =
        myfsio_crypto::encryption::EncryptionMetadata::from_metadata(&meta.internal_metadata);

    let (body_path, plaintext_size, enc_header): (std::path::PathBuf, u64, Option<&str>) =
        match (enc_info.as_ref(), state.encryption.as_ref()) {
            (Some(enc_info), Some(enc_svc)) => {
                let customer_key = match extract_sse_c_key(headers) {
                    Ok(key) => key,
                    Err(resp) => {
                        let _ = tokio::fs::remove_file(&snap_link).await;
                        return resp;
                    }
                };
                let has_fast_path =
                    enc_info.chunk_size.is_some() && enc_info.plaintext_size.is_some();

                if has_fast_path {
                    let plaintext_size = enc_info.plaintext_size.unwrap();
                    let (start, end) = match parse_range(range_str, plaintext_size) {
                        Some(r) => r,
                        None => {
                            let _ = tokio::fs::remove_file(&snap_link).await;
                            return s3_error_response(S3Error::new(
                                myfsio_common::error::S3ErrorCode::InvalidRange,
                                format!("Range not satisfiable for size {}", plaintext_size),
                            ));
                        }
                    };

                    let dec_tmp = tmp_dir.join(format!("rdec-{}", uuid::Uuid::new_v4()));
                    let res = enc_svc
                        .decrypt_object_range(
                            &snap_link,
                            &dec_tmp,
                            enc_info,
                            customer_key.as_deref(),
                            start,
                            end,
                        )
                        .await;
                    let _ = tokio::fs::remove_file(&snap_link).await;
                    if let Err(e) = res {
                        let _ = tokio::fs::remove_file(&dec_tmp).await;
                        return s3_error_response(S3Error::new(
                            myfsio_common::error::S3ErrorCode::InternalError,
                            format!("Decryption failed: {}", e),
                        ));
                    }

                    return stream_partial_content(
                        state,
                        &dec_tmp,
                        start,
                        end,
                        plaintext_size,
                        &meta,
                        key,
                        query,
                        Some(enc_info.algorithm.as_str()),
                        true,
                        parts_count,
                    )
                    .await;
                }

                let dec_tmp = tmp_dir.join(format!("rdec-{}", uuid::Uuid::new_v4()));
                let res = enc_svc
                    .decrypt_object(&snap_link, &dec_tmp, enc_info, customer_key.as_deref())
                    .await;
                let _ = tokio::fs::remove_file(&snap_link).await;
                if let Err(e) = res {
                    let _ = tokio::fs::remove_file(&dec_tmp).await;
                    return s3_error_response(S3Error::new(
                        myfsio_common::error::S3ErrorCode::InternalError,
                        format!("Decryption failed: {}", e),
                    ));
                }
                let plaintext_size = tokio::fs::metadata(&dec_tmp)
                    .await
                    .map(|m| m.len())
                    .unwrap_or(0);
                (dec_tmp, plaintext_size, Some(enc_info.algorithm.as_str()))
            }
            (Some(_), None) => {
                let _ = tokio::fs::remove_file(&snap_link).await;
                return s3_error_response(S3Error::new(
                    myfsio_common::error::S3ErrorCode::InternalError,
                    "Object is encrypted but encryption service is disabled".to_string(),
                ));
            }
            (None, _) => (snap_link.clone(), meta.size, None),
        };

    let (start, end) = match parse_range(range_str, plaintext_size) {
        Some(r) => r,
        None => {
            let _ = tokio::fs::remove_file(&body_path).await;
            return s3_error_response(S3Error::new(
                myfsio_common::error::S3ErrorCode::InvalidRange,
                format!("Range not satisfiable for size {}", plaintext_size),
            ));
        }
    };

    stream_partial_content(
        state,
        &body_path,
        start,
        end,
        plaintext_size,
        &meta,
        key,
        query,
        enc_header,
        false,
        parts_count,
    )
    .await
}

async fn stream_partial_content(
    state: &AppState,
    body_path: &std::path::Path,
    start: u64,
    end: u64,
    plaintext_size: u64,
    meta: &myfsio_common::types::ObjectMeta,
    key: &str,
    query: &ObjectQuery,
    enc_header: Option<&str>,
    already_trimmed: bool,
    parts_count: Option<u32>,
) -> Response {
    let length = end - start + 1;

    let mut file = match open_self_deleting(body_path.to_path_buf()).await {
        Ok(f) => f,
        Err(e) => {
            let _ = tokio::fs::remove_file(body_path).await;
            return storage_err_response(myfsio_storage::error::StorageError::Io(e));
        }
    };

    if !already_trimmed {
        if let Err(e) = file.seek(std::io::SeekFrom::Start(start)).await {
            return storage_err_response(myfsio_storage::error::StorageError::Io(e));
        }
    }
    let limited = file.take(length);

    let stream_cap = state.config.stream_chunk_size.max(64 * 1024);
    let stream = ReaderStream::with_capacity(limited, stream_cap);
    let body = Body::from_stream(stream);

    let mut headers = HeaderMap::new();
    headers.insert("content-length", length.to_string().parse().unwrap());
    headers.insert(
        "content-range",
        format!("bytes {}-{}/{}", start, end, plaintext_size)
            .parse()
            .unwrap(),
    );
    if let Some(ref etag) = meta.etag {
        headers.insert("etag", format!("\"{}\"", etag).parse().unwrap());
    }
    insert_content_type(&mut headers, key, meta.content_type.as_deref());
    headers.insert(
        "last-modified",
        meta.last_modified
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string()
            .parse()
            .unwrap(),
    );
    headers.insert("accept-ranges", "bytes".parse().unwrap());
    if let Some(alg) = enc_header {
        headers.insert("x-amz-server-side-encryption", alg.parse().unwrap());
    }
    apply_stored_response_headers(&mut headers, &meta.internal_metadata);
    if start == 0 && end + 1 == plaintext_size {
        apply_stored_checksum_headers(&mut headers, &meta.internal_metadata);
    }
    if let Some(ref requested_version) = query.version_id {
        if let Ok(value) = requested_version.parse() {
            headers.insert("x-amz-version-id", value);
        }
    } else if let Some(ref vid) = meta.version_id {
        if let Ok(value) = vid.parse() {
            headers.insert("x-amz-version-id", value);
        }
    }

    apply_user_metadata(&mut headers, &meta.metadata);
    apply_response_overrides(&mut headers, query);

    if let Some(count) = parts_count {
        headers.insert("x-amz-mp-parts-count", count.to_string().parse().unwrap());
    }

    (StatusCode::PARTIAL_CONTENT, headers, body).into_response()
}

fn evaluate_get_preconditions(
    headers: &HeaderMap,
    meta: &myfsio_common::types::ObjectMeta,
) -> Option<Response> {
    let if_match = headers.get("if-match").and_then(|v| v.to_str().ok());
    let if_none_match = headers.get("if-none-match").and_then(|v| v.to_str().ok());

    if if_match.is_some() && if_none_match.is_some() {
        return Some(s3_error_response(S3Error::new(
            S3ErrorCode::InvalidRequest,
            "If-Match and If-None-Match must not both be present",
        )));
    }

    if let Some(value) = if_match {
        if !etag_condition_matches(value, meta.etag.as_deref()) {
            return Some(s3_error_response(S3Error::from_code(
                S3ErrorCode::PreconditionFailed,
            )));
        }
    } else if let Some(value) = headers
        .get("if-unmodified-since")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(t) = parse_http_date(value) {
            if meta.last_modified > t {
                return Some(s3_error_response(S3Error::from_code(
                    S3ErrorCode::PreconditionFailed,
                )));
            }
        }
    }

    if let Some(value) = if_none_match {
        if etag_condition_matches(value, meta.etag.as_deref()) {
            return Some(not_modified_response(meta));
        }
    } else if let Some(value) = headers
        .get("if-modified-since")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(t) = parse_http_date(value) {
            if meta.last_modified <= t {
                return Some(not_modified_response(meta));
            }
        }
    }

    None
}

fn not_modified_response(meta: &myfsio_common::types::ObjectMeta) -> Response {
    let mut headers = HeaderMap::new();
    if let Some(ref etag) = meta.etag {
        headers.insert("etag", format!("\"{}\"", etag).parse().unwrap());
    }
    headers.insert(
        "last-modified",
        meta.last_modified
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string()
            .parse()
            .unwrap(),
    );
    if let Some(ref vid) = meta.version_id {
        if let Ok(value) = vid.parse() {
            headers.insert("x-amz-version-id", value);
        }
    }
    apply_stored_response_headers(&mut headers, &meta.internal_metadata);
    (StatusCode::NOT_MODIFIED, headers).into_response()
}

async fn evaluate_put_preconditions(
    state: &AppState,
    bucket: &str,
    key: &str,
    headers: &HeaderMap,
) -> Option<Response> {
    let has_if_match = headers.contains_key("if-match");
    let has_if_none_match = headers.contains_key("if-none-match");
    let has_if_unmodified = headers.contains_key("if-unmodified-since");
    let has_if_modified = headers.contains_key("if-modified-since");
    if !has_if_match && !has_if_none_match && !has_if_unmodified && !has_if_modified {
        return None;
    }

    if has_if_match && has_if_none_match {
        return Some(s3_error_response(S3Error::new(
            S3ErrorCode::InvalidRequest,
            "If-Match and If-None-Match must not both be present",
        )));
    }

    match state.storage.head_object(bucket, key).await {
        Ok(meta) => {
            if let Some(value) = headers.get("if-match").and_then(|v| v.to_str().ok()) {
                if !etag_condition_matches(value, meta.etag.as_deref()) {
                    return Some(s3_error_response(S3Error::from_code(
                        S3ErrorCode::PreconditionFailed,
                    )));
                }
            } else if let Some(value) = headers
                .get("if-unmodified-since")
                .and_then(|v| v.to_str().ok())
            {
                if let Some(t) = parse_http_date(value) {
                    if meta.last_modified > t {
                        return Some(s3_error_response(S3Error::from_code(
                            S3ErrorCode::PreconditionFailed,
                        )));
                    }
                }
            }
            if let Some(value) = headers.get("if-none-match").and_then(|v| v.to_str().ok()) {
                if etag_condition_matches(value, meta.etag.as_deref()) {
                    return Some(s3_error_response(S3Error::from_code(
                        S3ErrorCode::PreconditionFailed,
                    )));
                }
            } else if let Some(value) = headers
                .get("if-modified-since")
                .and_then(|v| v.to_str().ok())
            {
                if let Some(t) = parse_http_date(value) {
                    if meta.last_modified <= t {
                        return Some(s3_error_response(S3Error::from_code(
                            S3ErrorCode::PreconditionFailed,
                        )));
                    }
                }
            }
            None
        }
        Err(myfsio_storage::error::StorageError::ObjectNotFound { .. })
        | Err(myfsio_storage::error::StorageError::DeleteMarker { .. }) => {
            if has_if_match || has_if_unmodified {
                Some(s3_error_response(S3Error::from_code(
                    S3ErrorCode::PreconditionFailed,
                )))
            } else {
                None
            }
        }
        Err(err) => Some(storage_err_response(err)),
    }
}

fn evaluate_copy_preconditions(
    headers: &HeaderMap,
    source_meta: &myfsio_common::types::ObjectMeta,
) -> Option<Response> {
    let if_match = headers
        .get("x-amz-copy-source-if-match")
        .and_then(|v| v.to_str().ok());
    let if_none_match = headers
        .get("x-amz-copy-source-if-none-match")
        .and_then(|v| v.to_str().ok());

    if let Some(value) = if_match {
        if !etag_condition_matches(value, source_meta.etag.as_deref()) {
            return Some(s3_error_response(S3Error::from_code(
                S3ErrorCode::PreconditionFailed,
            )));
        }
    } else if let Some(value) = headers
        .get("x-amz-copy-source-if-unmodified-since")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(t) = parse_http_date(value) {
            if source_meta.last_modified > t {
                return Some(s3_error_response(S3Error::from_code(
                    S3ErrorCode::PreconditionFailed,
                )));
            }
        }
    }

    if let Some(value) = if_none_match {
        if etag_condition_matches(value, source_meta.etag.as_deref()) {
            return Some(s3_error_response(S3Error::from_code(
                S3ErrorCode::PreconditionFailed,
            )));
        }
    } else if let Some(value) = headers
        .get("x-amz-copy-source-if-modified-since")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(t) = parse_http_date(value) {
            if source_meta.last_modified <= t {
                return Some(s3_error_response(S3Error::from_code(
                    S3ErrorCode::PreconditionFailed,
                )));
            }
        }
    }

    None
}

fn parse_http_date(value: &str) -> Option<DateTime<Utc>> {
    let trimmed = value.trim();
    if let Ok(dt) = DateTime::parse_from_rfc2822(trimmed) {
        return Some(dt.with_timezone(&Utc));
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
        return Some(dt.with_timezone(&Utc));
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(trimmed, "%A, %d-%b-%y %H:%M:%S GMT") {
        return Some(naive.and_utc());
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(trimmed, "%a %b %e %H:%M:%S %Y") {
        return Some(naive.and_utc());
    }
    None
}

fn etag_condition_matches(condition: &str, etag: Option<&str>) -> bool {
    let trimmed = condition.trim();
    if trimmed == "*" {
        return true;
    }

    let current = match etag {
        Some(e) => e.trim_matches('"'),
        None => return false,
    };

    trimmed
        .split(',')
        .map(|v| v.trim().trim_matches('"'))
        .any(|candidate| candidate == current || candidate == "*")
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn parse_range(range_str: &str, total_size: u64) -> Option<(u64, u64)> {
    let range_spec = range_str.strip_prefix("bytes=")?;

    if total_size == 0 {
        return None;
    }

    if let Some(suffix) = range_spec.strip_prefix('-') {
        let suffix_len: u64 = suffix.parse().ok()?;
        if suffix_len == 0 {
            return None;
        }
        let start = total_size.saturating_sub(suffix_len);
        return Some((start, total_size - 1));
    }

    let (start_str, end_str) = range_spec.split_once('-')?;
    let start: u64 = start_str.parse().ok()?;

    let end = if end_str.is_empty() {
        total_size - 1
    } else {
        let e: u64 = end_str.parse().ok()?;
        e.min(total_size - 1)
    };

    if start > end || start >= total_size {
        return None;
    }

    Some((start, end))
}

#[cfg(test)]
mod range_tests {
    use super::parse_range;

    #[test]
    fn parses_explicit_range() {
        assert_eq!(parse_range("bytes=0-3", 100), Some((0, 3)));
        assert_eq!(parse_range("bytes=10-19", 100), Some((10, 19)));
    }

    #[test]
    fn open_ended_range_clamps_to_end() {
        assert_eq!(parse_range("bytes=10-", 100), Some((10, 99)));
    }

    #[test]
    fn end_past_eof_clamps() {
        assert_eq!(parse_range("bytes=0-200", 100), Some((0, 99)));
    }

    #[test]
    fn suffix_range_returns_tail() {
        assert_eq!(parse_range("bytes=-10", 100), Some((90, 99)));
    }

    #[test]
    fn suffix_larger_than_size_returns_full_object() {
        assert_eq!(parse_range("bytes=-100", 4), Some((0, 3)));
        assert_eq!(parse_range("bytes=-1000000", 50), Some((0, 49)));
    }

    #[test]
    fn empty_object_rejects_range() {
        assert_eq!(parse_range("bytes=0-0", 0), None);
        assert_eq!(parse_range("bytes=-10", 0), None);
    }

    #[test]
    fn suffix_zero_rejected() {
        assert_eq!(parse_range("bytes=-0", 100), None);
    }

    #[test]
    fn start_past_eof_rejected() {
        assert_eq!(parse_range("bytes=200-300", 100), None);
    }

    #[test]
    fn missing_prefix_rejected() {
        assert_eq!(parse_range("0-3", 100), None);
    }
}

use futures::TryStreamExt;
use http_body_util;
use tokio::io::AsyncReadExt;

async fn resolve_encryption_context(
    state: &AppState,
    bucket: &str,
    headers: &HeaderMap,
) -> Result<Option<myfsio_crypto::encryption::EncryptionContext>, Response> {
    if let Some(alg) = headers
        .get("x-amz-server-side-encryption")
        .and_then(|v| v.to_str().ok())
    {
        let algorithm = match alg {
            "AES256" => myfsio_crypto::encryption::SseAlgorithm::Aes256,
            "aws:kms" => myfsio_crypto::encryption::SseAlgorithm::AwsKms,
            _ => {
                return Err(s3_error_response(S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    "Unsupported x-amz-server-side-encryption algorithm",
                )))
            }
        };
        if state.encryption.is_none() {
            return Err(s3_error_response(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "Server-side encryption is not enabled on this server",
            )));
        }
        let kms_key_id = headers
            .get("x-amz-server-side-encryption-aws-kms-key-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        return Ok(Some(myfsio_crypto::encryption::EncryptionContext {
            algorithm,
            kms_key_id,
            customer_key: None,
        }));
    }

    let has_any_sse_c_header = headers
        .get("x-amz-server-side-encryption-customer-algorithm")
        .is_some()
        || headers
            .get("x-amz-server-side-encryption-customer-key")
            .is_some()
        || headers
            .get("x-amz-server-side-encryption-customer-key-MD5")
            .is_some();
    if has_any_sse_c_header {
        if state.encryption.is_none() {
            return Err(s3_error_response(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "Server-side encryption is not enabled on this server",
            )));
        }
        let customer_key = extract_sse_c_key(headers)?;
        if let Some(ck) = customer_key {
            return Ok(Some(myfsio_crypto::encryption::EncryptionContext {
                algorithm: myfsio_crypto::encryption::SseAlgorithm::CustomerProvided,
                kms_key_id: None,
                customer_key: Some(ck),
            }));
        }
        return Ok(None);
    }

    if state.encryption.is_some() {
        if let Ok(config) = state.storage.get_bucket_config(bucket).await {
            if let Some(enc_val) = &config.encryption {
                if let Some((algorithm, kms_key_id)) =
                    crate::handlers::config::parse_encryption_config(enc_val)
                {
                    match algorithm.as_str() {
                        "AES256" => {
                            return Ok(Some(myfsio_crypto::encryption::EncryptionContext {
                                algorithm: myfsio_crypto::encryption::SseAlgorithm::Aes256,
                                kms_key_id: None,
                                customer_key: None,
                            }));
                        }
                        "aws:kms" => {
                            return Ok(Some(myfsio_crypto::encryption::EncryptionContext {
                                algorithm: myfsio_crypto::encryption::SseAlgorithm::AwsKms,
                                kms_key_id,
                                customer_key: None,
                            }));
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    Ok(None)
}

fn extract_sse_c_key(headers: &HeaderMap) -> Result<Option<Vec<u8>>, Response> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use md5::{Digest, Md5};

    let algo = headers
        .get("x-amz-server-side-encryption-customer-algorithm")
        .and_then(|v| v.to_str().ok());
    let key_b64 = headers
        .get("x-amz-server-side-encryption-customer-key")
        .and_then(|v| v.to_str().ok());
    let md5_header = headers
        .get("x-amz-server-side-encryption-customer-key-MD5")
        .and_then(|v| v.to_str().ok());

    match (algo, key_b64, md5_header) {
        (None, None, None) => Ok(None),
        (Some(a), Some(k), Some(m)) => {
            if !a.eq_ignore_ascii_case("AES256") {
                return Err(s3_error_response(S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    "x-amz-server-side-encryption-customer-algorithm must be AES256",
                )));
            }
            let decoded = B64.decode(k).map_err(|_| {
                s3_error_response(S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    "Invalid x-amz-server-side-encryption-customer-key",
                ))
            })?;
            if decoded.len() != 32 {
                return Err(s3_error_response(S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    "SSE-C customer key must decode to 32 bytes",
                )));
            }
            let mut hasher = Md5::new();
            hasher.update(&decoded);
            let computed_md5 = B64.encode(hasher.finalize());
            if !constant_time_eq(computed_md5.as_bytes(), m.as_bytes()) {
                return Err(s3_error_response(S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    "x-amz-server-side-encryption-customer-key-MD5 mismatch",
                )));
            }
            Ok(Some(decoded))
        }
        _ => Err(s3_error_response(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "SSE-C requires algorithm, key, and key-MD5 headers together",
        ))),
    }
}

fn require_sse_c_key_match(
    headers: &HeaderMap,
    _enc_info: &myfsio_crypto::encryption::EncryptionMetadata,
) -> Result<(), Response> {
    match extract_sse_c_key(headers) {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(s3_error_response(S3Error::new(
            S3ErrorCode::InvalidRequest,
            "Object was created with SSE-C; the SSE-C customer key headers are required",
        ))),
        Err(resp) => Err(resp),
    }
}

async fn compute_plaintext_md5(path: &std::path::Path) -> std::io::Result<String> {
    use md5::{Digest, Md5};
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || -> std::io::Result<String> {
        use std::io::Read;
        let mut file = std::fs::File::open(&path)?;
        let mut hasher = Md5::new();
        let mut buf = [0u8; 65_536];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(format!("{:x}", hasher.finalize()))
    })
    .await
    .map_err(std::io::Error::other)?
}

const STORAGE_MANAGED_METADATA_KEYS: &[&str] = &[
    "__etag__",
    "__size__",
    "__last_modified__",
    "__version_id__",
];

fn strip_storage_managed_keys(metadata: &mut HashMap<String, String>) {
    for k in STORAGE_MANAGED_METADATA_KEYS {
        metadata.remove(*k);
    }
}

fn extract_copy_source_sse_c_key(headers: &HeaderMap) -> Result<Option<Vec<u8>>, Response> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use md5::{Digest, Md5};

    let algo = headers
        .get("x-amz-copy-source-server-side-encryption-customer-algorithm")
        .and_then(|v| v.to_str().ok());
    let key_b64 = headers
        .get("x-amz-copy-source-server-side-encryption-customer-key")
        .and_then(|v| v.to_str().ok());
    let md5_header = headers
        .get("x-amz-copy-source-server-side-encryption-customer-key-MD5")
        .and_then(|v| v.to_str().ok());

    match (algo, key_b64, md5_header) {
        (None, None, None) => Ok(None),
        (Some(a), Some(k), Some(m)) => {
            if !a.eq_ignore_ascii_case("AES256") {
                return Err(s3_error_response(S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    "x-amz-copy-source-server-side-encryption-customer-algorithm must be AES256",
                )));
            }
            let decoded = B64.decode(k).map_err(|_| {
                s3_error_response(S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    "Invalid x-amz-copy-source-server-side-encryption-customer-key",
                ))
            })?;
            if decoded.len() != 32 {
                return Err(s3_error_response(S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    "Copy-source SSE-C customer key must decode to 32 bytes",
                )));
            }
            let mut hasher = Md5::new();
            hasher.update(&decoded);
            let computed_md5 = B64.encode(hasher.finalize());
            if !constant_time_eq(computed_md5.as_bytes(), m.as_bytes()) {
                return Err(s3_error_response(S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    "x-amz-copy-source-server-side-encryption-customer-key-MD5 mismatch",
                )));
            }
            Ok(Some(decoded))
        }
        _ => Err(s3_error_response(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "Copy-source SSE-C requires algorithm, key, and key-MD5 headers together",
        ))),
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

async fn post_object_form_handler(
    state: &AppState,
    bucket: &str,
    content_type: &str,
    headers: &HeaderMap,
    peer_marker: Option<&crate::middleware::ReplicationPeerRequest>,
    body: Body,
) -> Response {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use futures::TryStreamExt;

    if !state.storage.bucket_exists(bucket).await.unwrap_or(false) {
        return s3_error_response(S3Error::from_code(S3ErrorCode::NoSuchBucket));
    }

    let boundary = match multer::parse_boundary(content_type) {
        Ok(b) => b,
        Err(_) => {
            return s3_error_response(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "Missing multipart boundary",
            ));
        }
    };

    let stream = http_body_util::BodyStream::new(body)
        .map_ok(|frame| frame.into_data().unwrap_or_default())
        .map_err(std::io::Error::other);
    let mut multipart = multer::Multipart::new(stream, boundary);

    let mut fields: HashMap<String, String> = HashMap::new();
    let mut file_bytes: Option<bytes::Bytes> = None;
    let mut file_name: Option<String> = None;

    while let Some(field) = match multipart.next_field().await {
        Ok(f) => f,
        Err(e) => {
            return s3_error_response(S3Error::new(
                S3ErrorCode::MalformedXML,
                format!("Malformed multipart: {}", e),
            ));
        }
    } {
        let name = field.name().map(|s| s.to_string()).unwrap_or_default();
        if name.eq_ignore_ascii_case("file") {
            file_name = field.file_name().map(|s| s.to_string());
            match field.bytes().await {
                Ok(b) => file_bytes = Some(b),
                Err(e) => {
                    return s3_error_response(S3Error::new(
                        S3ErrorCode::InternalError,
                        format!("Failed to read file: {}", e),
                    ));
                }
            }
        } else if !name.is_empty() {
            if let Ok(t) = field.text().await {
                fields.insert(name, t);
            }
        }
    }

    let key_template = match fields.get("key").cloned() {
        Some(k) => k,
        None => {
            return s3_error_response(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "Missing key field",
            ))
        }
    };
    let policy_b64 = match fields.get("policy").cloned() {
        Some(v) => v,
        None => {
            return s3_error_response(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "Missing policy field",
            ))
        }
    };
    let signature = match fields
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-amz-signature"))
        .map(|(_, v)| v.clone())
    {
        Some(v) => v,
        None => {
            return s3_error_response(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "Missing signature",
            ))
        }
    };
    let credential = match fields
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-amz-credential"))
        .map(|(_, v)| v.clone())
    {
        Some(v) => v,
        None => {
            return s3_error_response(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "Missing credential",
            ))
        }
    };
    let algorithm = match fields
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-amz-algorithm"))
        .map(|(_, v)| v.clone())
    {
        Some(v) => v,
        None => {
            return s3_error_response(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "Missing algorithm",
            ))
        }
    };
    if algorithm != "AWS4-HMAC-SHA256" {
        return s3_error_response(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "Unsupported signing algorithm",
        ));
    }

    let policy_bytes = match B64.decode(policy_b64.as_bytes()) {
        Ok(b) => b,
        Err(e) => {
            return s3_error_response(S3Error::new(
                S3ErrorCode::InvalidPolicyDocument,
                format!("Invalid policy base64: {}", e),
            ));
        }
    };
    let policy_value: serde_json::Value = match serde_json::from_slice(&policy_bytes) {
        Ok(v) => v,
        Err(e) => {
            return s3_error_response(S3Error::new(
                S3ErrorCode::InvalidPolicyDocument,
                format!("Invalid policy JSON: {}", e),
            ));
        }
    };

    if let Some(exp) = policy_value.get("expiration").and_then(|v| v.as_str()) {
        let normalized = exp.replace('Z', "+00:00");
        match chrono::DateTime::parse_from_rfc3339(&normalized) {
            Ok(exp_time) => {
                if Utc::now() > exp_time.with_timezone(&Utc) {
                    return s3_error_response(S3Error::new(
                        S3ErrorCode::AccessDenied,
                        "Policy expired",
                    ));
                }
            }
            Err(_) => {
                return s3_error_response(S3Error::new(
                    S3ErrorCode::InvalidPolicyDocument,
                    "Invalid expiration format",
                ));
            }
        }
    }

    let content_length = file_bytes.as_ref().map(|b| b.len() as u64).unwrap_or(0);
    let object_key = if key_template.contains("${filename}") {
        let fname = file_name.clone().unwrap_or_else(|| "upload".to_string());
        key_template.replace("${filename}", &fname)
    } else {
        key_template.clone()
    };

    if let Some(conditions) = policy_value.get("conditions").and_then(|v| v.as_array()) {
        if let Err(msg) = validate_post_policy_conditions(
            bucket,
            &object_key,
            conditions,
            &fields,
            content_length,
        ) {
            return s3_error_response(S3Error::new(S3ErrorCode::AccessDenied, msg));
        }
    }

    let credential_parts: Vec<&str> = credential.split('/').collect();
    if credential_parts.len() != 5 {
        return s3_error_response(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "Invalid credential format",
        ));
    }
    let access_key = credential_parts[0];
    let date_stamp = credential_parts[1];
    let region = credential_parts[2];
    let service = credential_parts[3];

    let secret_key = match state.iam.get_secret_key(access_key) {
        Some(s) => s,
        None => {
            return s3_error_response(S3Error::new(
                S3ErrorCode::AccessDenied,
                "Invalid access key",
            ))
        }
    };
    let signing_key =
        myfsio_auth::sigv4::derive_signing_key(&secret_key, date_stamp, region, service);
    let expected = myfsio_auth::sigv4::compute_post_policy_signature(&signing_key, &policy_b64);
    if !myfsio_auth::sigv4::constant_time_compare(&expected, &signature) {
        return s3_error_response(S3Error::new(
            S3ErrorCode::SignatureDoesNotMatch,
            "Signature verification failed",
        ));
    }

    let file_data = match file_bytes {
        Some(b) => b,
        None => {
            return s3_error_response(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "Missing file field",
            ))
        }
    };

    let mut metadata = HashMap::new();
    for (k, v) in &fields {
        let lower = k.to_ascii_lowercase();
        if let Some(meta_key) = lower.strip_prefix("x-amz-meta-") {
            if !(meta_key.is_empty() || meta_key.starts_with("__") && meta_key.ends_with("__")) {
                metadata.insert(meta_key.to_string(), v.clone());
            }
        }
    }
    let content_type_value = fields
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.clone());
    metadata.insert(
        "__content_type__".to_string(),
        guessed_content_type(&object_key, content_type_value.as_deref()),
    );

    if let Err(response) =
        ensure_archived_null_lock_allows_overwrite(state, bucket, &object_key, Some(headers)).await
    {
        return response;
    }

    let cursor = std::io::Cursor::new(file_data.to_vec());
    let boxed: myfsio_storage::traits::AsyncReadStream = Box::pin(cursor);

    let meta = match state
        .storage
        .put_object(bucket, &object_key, boxed, Some(metadata))
        .await
    {
        Ok(m) => m,
        Err(e) => return storage_err_response(e),
    };

    let Some(etag) = meta.etag.as_deref() else {
        tracing::error!(
            bucket = bucket,
            key = %object_key,
            "post-form put_object stored object without etag"
        );
        return s3_error_response(S3Error::from_code(S3ErrorCode::InternalError));
    };
    trigger_replication_for_request(state, peer_marker, bucket, &object_key, "write");
    let success_status = fields
        .get("success_action_status")
        .cloned()
        .unwrap_or_else(|| "204".to_string());
    let location = format!("/{}/{}", bucket, object_key);
    let xml = myfsio_xml::response::post_object_result_xml(&location, bucket, &object_key, etag);

    let status = match success_status.as_str() {
        "200" => StatusCode::OK,
        "201" => StatusCode::CREATED,
        _ => {
            let mut hdrs = HeaderMap::new();
            hdrs.insert("etag", format!("\"{}\"", etag).parse().unwrap());
            return (StatusCode::NO_CONTENT, hdrs).into_response();
        }
    };

    let mut hdrs = HeaderMap::new();
    hdrs.insert("content-type", "application/xml".parse().unwrap());
    hdrs.insert("etag", format!("\"{}\"", etag).parse().unwrap());
    (status, hdrs, xml).into_response()
}

fn validate_post_policy_conditions(
    bucket: &str,
    object_key: &str,
    conditions: &[serde_json::Value],
    form: &HashMap<String, String>,
    content_length: u64,
) -> Result<(), String> {
    for cond in conditions {
        if let Some(obj) = cond.as_object() {
            for (k, v) in obj {
                let expected = v.as_str().unwrap_or("");
                match k.as_str() {
                    "bucket" => {
                        if bucket != expected {
                            return Err(format!("Bucket must be {}", expected));
                        }
                    }
                    "key" => {
                        if object_key != expected {
                            return Err(format!("Key must be {}", expected));
                        }
                    }
                    other => {
                        let actual = form
                            .iter()
                            .find(|(fk, _)| fk.eq_ignore_ascii_case(other))
                            .map(|(_, fv)| fv.as_str())
                            .unwrap_or("");
                        if actual != expected {
                            return Err(format!("Field {} must be {}", other, expected));
                        }
                    }
                }
            }
        } else if let Some(arr) = cond.as_array() {
            if arr.len() < 2 {
                continue;
            }
            let op = arr[0].as_str().unwrap_or("").to_ascii_lowercase();
            if op == "starts-with" && arr.len() == 3 {
                let field = arr[1].as_str().unwrap_or("").trim_start_matches('$');
                let prefix = arr[2].as_str().unwrap_or("");
                if field == "key" {
                    if !object_key.starts_with(prefix) {
                        return Err(format!("Key must start with {}", prefix));
                    }
                } else {
                    let actual = form
                        .iter()
                        .find(|(fk, _)| fk.eq_ignore_ascii_case(field))
                        .map(|(_, fv)| fv.as_str())
                        .unwrap_or("");
                    if !actual.starts_with(prefix) {
                        return Err(format!("Field {} must start with {}", field, prefix));
                    }
                }
            } else if op == "eq" && arr.len() == 3 {
                let field = arr[1].as_str().unwrap_or("").trim_start_matches('$');
                let expected = arr[2].as_str().unwrap_or("");
                if field == "key" {
                    if object_key != expected {
                        return Err(format!("Key must equal {}", expected));
                    }
                } else {
                    let actual = form
                        .iter()
                        .find(|(fk, _)| fk.eq_ignore_ascii_case(field))
                        .map(|(_, fv)| fv.as_str())
                        .unwrap_or("");
                    if actual != expected {
                        return Err(format!("Field {} must equal {}", field, expected));
                    }
                }
            } else if op == "content-length-range" && arr.len() == 3 {
                let min = arr[1].as_i64().unwrap_or(0) as u64;
                let max = arr[2].as_i64().unwrap_or(0) as u64;
                if content_length < min || content_length > max {
                    return Err(format!(
                        "Content length must be between {} and {}",
                        min, max
                    ));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;
    use crate::services::acl::{acl_to_xml, create_canned_acl};
    use http_body_util::BodyExt;
    use serde_json::Value;
    use tower::ServiceExt;

    const TEST_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
    const TEST_SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    fn test_state() -> (AppState, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let config_dir = tmp.path().join(".myfsio.sys").join("config");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("iam.json"),
            serde_json::json!({
                "version": 2,
                "users": [{
                    "user_id": "u-test1234",
                    "display_name": "admin",
                    "enabled": true,
                    "access_keys": [{
                        "access_key": TEST_ACCESS_KEY,
                        "secret_key": TEST_SECRET_KEY,
                        "status": "active"
                    }],
                    "policies": [{
                        "bucket": "*",
                        "actions": ["*"],
                        "prefix": "*"
                    }]
                }]
            })
            .to_string(),
        )
        .unwrap();

        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let config = ServerConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ui_bind_addr: "127.0.0.1:0".parse().unwrap(),
            storage_root: tmp.path().to_path_buf(),
            region: "us-east-1".to_string(),
            iam_config_path: config_dir.join("iam.json"),
            sigv4_timestamp_tolerance_secs: 900,
            presigned_url_min_expiry: 1,
            presigned_url_max_expiry: 604800,
            secret_key: None,
            encryption_enabled: false,
            kms_enabled: false,
            gc_enabled: false,
            integrity_enabled: false,
            metrics_enabled: false,
            metrics_history_enabled: false,
            metrics_interval_minutes: 5,
            metrics_retention_hours: 24,
            metrics_history_interval_minutes: 5,
            metrics_history_retention_hours: 24,
            lifecycle_enabled: false,
            website_hosting_enabled: false,
            replication_connect_timeout_secs: 1,
            replication_read_timeout_secs: 1,
            replication_max_retries: 1,
            replication_streaming_threshold_bytes: 10_485_760,
            replication_max_failures_per_bucket: 50,
            replication_healer_enabled: false,
            replication_healer_interval_secs: 60,
            replication_healer_max_attempts: 12,
            replication_part_stall_timeout_secs: 300,
            site_sync_enabled: false,
            site_sync_interval_secs: 60,
            site_sync_batch_size: 100,
            site_sync_connect_timeout_secs: 10,
            site_sync_read_timeout_secs: 120,
            site_sync_max_retries: 2,
            site_sync_clock_skew_tolerance: 1.0,
            ui_enabled: false,
            templates_dir: manifest_dir.join("templates"),
            static_dir: manifest_dir.join("static"),
            allow_legacy_header_auth: true,
            ..ServerConfig::default()
        };
        (AppState::new(config), tmp)
    }

    fn auth_request(
        method: axum::http::Method,
        uri: &str,
        body: Body,
    ) -> axum::http::Request<Body> {
        axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .header("x-access-key", TEST_ACCESS_KEY)
            .header("x-secret-key", TEST_SECRET_KEY)
            .body(body)
            .unwrap()
    }

    #[test]
    fn is_aws_chunked_detection() {
        let mut h = HeaderMap::new();
        h.insert(
            "x-amz-content-sha256",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD".parse().unwrap(),
        );
        assert!(is_aws_chunked(&h));

        let mut h = HeaderMap::new();
        h.insert("content-encoding", "aws-chunked, gzip".parse().unwrap());
        h.insert("x-amz-decoded-content-length", "100".parse().unwrap());
        assert!(is_aws_chunked(&h));

        let mut h = HeaderMap::new();
        h.insert("content-encoding", "gzip, aws-chunked".parse().unwrap());
        h.insert(
            "x-amz-content-sha256",
            "abcd".repeat(16).parse().unwrap(),
        );
        assert!(!is_aws_chunked(&h));

        let mut h = HeaderMap::new();
        h.insert("content-encoding", "gzip".parse().unwrap());
        h.insert("x-amz-content-sha256", "abcd".repeat(16).parse().unwrap());
        assert!(!is_aws_chunked(&h));
    }

    #[test]
    fn aws_chunked_wire_encoding_is_not_persisted_as_object_encoding() {
        let mut headers = HeaderMap::new();
        headers.insert("content-encoding", "aws-chunked".parse().unwrap());
        headers.insert("x-amz-decoded-content-length", "100".parse().unwrap());
        let mut metadata = HashMap::new();
        insert_standard_object_metadata(&headers, &mut metadata).unwrap();
        assert!(!metadata.contains_key("__content_encoding__"));

        headers.insert("content-encoding", "aws-chunked, gzip".parse().unwrap());
        let mut metadata = HashMap::new();
        insert_standard_object_metadata(&headers, &mut metadata).unwrap();
        assert_eq!(metadata.get("__content_encoding__").unwrap(), "gzip");
    }

    #[test]
    fn aws_chunked_is_stripped_from_stored_content_encoding_regardless_of_transport() {
        let mut headers = HeaderMap::new();
        headers.insert("content-encoding", "gzip, aws-chunked".parse().unwrap());
        headers.insert(
            "x-amz-content-sha256",
            "abcd".repeat(16).parse().unwrap(),
        );
        let mut metadata = HashMap::new();
        insert_standard_object_metadata(&headers, &mut metadata).unwrap();
        assert_eq!(
            metadata.get("__content_encoding__").map(String::as_str),
            Some("gzip")
        );
    }

    #[tokio::test]
    async fn public_bucket_acl_allows_anonymous_reads() {
        let (state, _tmp) = test_state();
        state.storage.create_bucket("public").await.unwrap();
        state
            .storage
            .put_object(
                "public",
                "hello.txt",
                Box::pin(std::io::Cursor::new(b"hello".to_vec())),
                None,
            )
            .await
            .unwrap();

        let mut config = state.storage.get_bucket_config("public").await.unwrap();
        config.acl = Some(Value::String(acl_to_xml(&create_canned_acl(
            "public-read",
            "myfsio",
        ))));
        state
            .storage
            .set_bucket_config("public", &config)
            .await
            .unwrap();

        let app = crate::create_router(state);
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::GET)
                    .uri("/public/hello.txt")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn object_retention_blocks_delete_without_bypass() {
        let (state, _tmp) = test_state();
        state.storage.create_bucket("locked").await.unwrap();
        state
            .storage
            .put_object(
                "locked",
                "obj.txt",
                Box::pin(std::io::Cursor::new(b"data".to_vec())),
                None,
            )
            .await
            .unwrap();
        let app = crate::create_router(state);

        let retention_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
            <Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
              <Mode>GOVERNANCE</Mode>
              <RetainUntilDate>2099-01-01T00:00:00Z</RetainUntilDate>
            </Retention>"#;
        let response = app
            .clone()
            .oneshot(auth_request(
                axum::http::Method::PUT,
                "/locked/obj.txt?retention",
                Body::from(retention_xml),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(auth_request(
                axum::http::Method::DELETE,
                "/locked/obj.txt",
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::DELETE)
                    .uri("/locked/obj.txt")
                    .header("x-access-key", TEST_ACCESS_KEY)
                    .header("x-secret-key", TEST_SECRET_KEY)
                    .header("x-amz-bypass-governance-retention", "true")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn object_acl_round_trip_uses_metadata() {
        let (state, _tmp) = test_state();
        state.storage.create_bucket("acl").await.unwrap();
        state
            .storage
            .put_object(
                "acl",
                "photo.jpg",
                Box::pin(std::io::Cursor::new(b"image".to_vec())),
                None,
            )
            .await
            .unwrap();
        let app = crate::create_router(state);

        let response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::PUT)
                    .uri("/acl/photo.jpg?acl")
                    .header("x-access-key", TEST_ACCESS_KEY)
                    .header("x-secret-key", TEST_SECRET_KEY)
                    .header("x-amz-acl", "public-read")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(auth_request(
                axum::http::Method::GET,
                "/acl/photo.jpg?acl",
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = String::from_utf8(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(body.contains("AllUsers"));
        assert!(body.contains("READ"));
    }

    #[tokio::test]
    async fn object_acl_xml_rejects_owner_id_mismatch() {
        let (state, _tmp) = test_state();
        state.storage.create_bucket("acl").await.unwrap();
        state
            .storage
            .put_object(
                "acl",
                "photo.jpg",
                Box::pin(std::io::Cursor::new(b"image".to_vec())),
                None,
            )
            .await
            .unwrap();
        let app = crate::create_router(state);

        let spoofed_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Owner><ID>attacker</ID></Owner>
  <AccessControlList>
    <Grant>
      <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser">
        <ID>attacker</ID>
      </Grantee>
      <Permission>FULL_CONTROL</Permission>
    </Grant>
  </AccessControlList>
</AccessControlPolicy>"#;

        let response = app
            .clone()
            .oneshot(auth_request(
                axum::http::Method::PUT,
                "/acl/photo.jpg?acl",
                Body::from(spoofed_xml),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = app
            .oneshot(auth_request(
                axum::http::Method::GET,
                "/acl/photo.jpg?acl",
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = String::from_utf8(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(!body.contains("attacker"), "owner must not be the spoofed id; got: {body}");
        assert!(body.contains("myfsio"), "owner must remain the existing one; got: {body}");
    }

    #[tokio::test]
    async fn object_acl_xml_accepts_matching_owner() {
        let (state, _tmp) = test_state();
        state.storage.create_bucket("acl").await.unwrap();
        state
            .storage
            .put_object(
                "acl",
                "photo.jpg",
                Box::pin(std::io::Cursor::new(b"image".to_vec())),
                None,
            )
            .await
            .unwrap();
        let app = crate::create_router(state);

        let matching_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Owner><ID>myfsio</ID></Owner>
  <AccessControlList>
    <Grant>
      <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group">
        <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>
      </Grantee>
      <Permission>READ</Permission>
    </Grant>
  </AccessControlList>
</AccessControlPolicy>"#;

        let response = app
            .clone()
            .oneshot(auth_request(
                axum::http::Method::PUT,
                "/acl/photo.jpg?acl",
                Body::from(matching_xml),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(auth_request(
                axum::http::Method::GET,
                "/acl/photo.jpg?acl",
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = String::from_utf8(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(body.contains("AllUsers"));
        assert!(body.contains("READ"));
        assert!(body.contains("myfsio"));
    }

    #[tokio::test]
    async fn arbitrary_delimiter_groups_keys_and_paginates() {
        let (state, _tmp) = test_state();
        state.storage.create_bucket("arb").await.unwrap();
        for key in ["foo", "bar", "baz", "cab"] {
            state
                .storage
                .put_object(
                    "arb",
                    key,
                    Box::pin(std::io::Cursor::new(b"x".to_vec())),
                    None,
                )
                .await
                .unwrap();
        }

        let page = list_with_arbitrary_delimiter(&state, "arb", "", "a", 100, None, None)
            .await
            .unwrap();
        let mut got: Vec<String> = page.objects.iter().map(|o| o.key.clone()).collect();
        got.sort();
        assert_eq!(got, vec!["foo".to_string()]);
        let mut cps = page.common_prefixes.clone();
        cps.sort();
        assert_eq!(cps, vec!["ba".to_string(), "ca".to_string()]);
        assert!(!page.is_truncated);
        assert!(page.next_token.is_none());
    }

    #[tokio::test]
    async fn arbitrary_delimiter_truncation_is_honest_under_max_keys() {
        let (state, _tmp) = test_state();
        state.storage.create_bucket("arb2").await.unwrap();
        for key in ["alpha", "ba/x", "ba/y", "beta", "gamma"] {
            state
                .storage
                .put_object(
                    "arb2",
                    key,
                    Box::pin(std::io::Cursor::new(b"x".to_vec())),
                    None,
                )
                .await
                .unwrap();
        }

        let page1 = list_with_arbitrary_delimiter(&state, "arb2", "", "/", 2, None, None)
            .await
            .unwrap();
        assert!(page1.is_truncated, "max_keys=2 against 4 distinct items must be truncated");
        let token = page1
            .next_token
            .clone()
            .expect("truncated response must include a continuation token");
        assert_eq!(
            page1.objects.iter().map(|o| o.key.clone()).collect::<Vec<_>>(),
            vec!["alpha".to_string()]
        );
        assert_eq!(page1.common_prefixes, vec!["ba/".to_string()]);
        assert_eq!(token, "ba/");

        let page2 = list_with_arbitrary_delimiter(
            &state,
            "arb2",
            "",
            "/",
            10,
            Some(token),
            None,
        )
        .await
        .unwrap();
        assert!(page2.common_prefixes.is_empty(), "ba/ must not be re-emitted on resume");
        let got: Vec<String> = page2.objects.iter().map(|o| o.key.clone()).collect();
        assert_eq!(got, vec!["beta".to_string(), "gamma".to_string()]);
        assert!(!page2.is_truncated);
        assert!(page2.next_token.is_none());
    }
}
