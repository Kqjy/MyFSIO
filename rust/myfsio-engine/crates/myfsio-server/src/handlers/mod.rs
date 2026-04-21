pub mod admin;
mod chunked;
mod config;
pub mod kms;
mod select;
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

fn s3_error_response(err: S3Error) -> Response {
    let status =
        StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let resource = if err.resource.is_empty() {
        "/".to_string()
    } else {
        err.resource.clone()
    };
    let body = err
        .with_resource(resource)
        .with_request_id(uuid::Uuid::new_v4().simple().to_string())
        .to_xml();
    (status, [("content-type", "application/xml")], body).into_response()
}

fn storage_err_response(err: myfsio_storage::error::StorageError) -> Response {
    s3_error_response(S3Error::from(err))
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

async fn ensure_object_lock_allows_write(
    state: &AppState,
    bucket: &str,
    key: &str,
    headers: Option<&HeaderMap>,
) -> Result<(), Response> {
    match state.storage.head_object(bucket, key).await {
        Ok(_) => {
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
        Err(myfsio_storage::error::StorageError::ObjectNotFound { .. }) => Ok(()),
        Err(err) => Err(storage_err_response(err)),
    }
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
) -> Response {
    if let Some(host_bucket) = virtual_host_bucket_from_headers(&state, &headers).await {
        return get_bucket(State(state), Path(host_bucket), Query(query), headers).await;
    }

    match state.storage.list_buckets().await {
        Ok(buckets) => {
            let xml = myfsio_xml::response::list_buckets_xml("myfsio", "myfsio", &buckets);
            (StatusCode::OK, [("content-type", "application/xml")], xml).into_response()
        }
        Err(e) => storage_err_response(e),
    }
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
    headers: HeaderMap,
    body: Body,
) -> Response {
    if let Some(host_bucket) = virtual_host_bucket_from_headers(&state, &headers).await {
        if host_bucket != bucket {
            return put_object(
                State(state),
                Path((host_bucket, bucket)),
                Query(ObjectQuery::default()),
                headers,
                body,
            )
            .await;
        }
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
    if query.notification.is_some() {
        return config::put_notification(&state, &bucket, body).await;
    }
    if query.logging.is_some() {
        return config::put_logging(&state, &bucket, body).await;
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

#[derive(serde::Deserialize, Default)]
pub struct BucketQuery {
    #[serde(rename = "list-type")]
    pub list_type: Option<String>,
    pub marker: Option<String>,
    pub prefix: Option<String>,
    pub delimiter: Option<String>,
    #[serde(rename = "max-keys")]
    pub max_keys: Option<usize>,
    #[serde(rename = "continuation-token")]
    pub continuation_token: Option<String>,
    #[serde(rename = "start-after")]
    pub start_after: Option<String>,
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
    pub notification: Option<String>,
    pub logging: Option<String>,
    pub versions: Option<String>,
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
    if query.notification.is_some() {
        return config::get_notification(&state, &bucket).await;
    }
    if query.logging.is_some() {
        return config::get_logging(&state, &bucket).await;
    }
    if query.versions.is_some() {
        return config::list_object_versions(
            &state,
            &bucket,
            query.prefix.as_deref(),
            query.max_keys.unwrap_or(1000),
        )
        .await;
    }
    if query.uploads.is_some() {
        return list_multipart_uploads_handler(&state, &bucket).await;
    }

    let prefix = query.prefix.clone().unwrap_or_default();
    let delimiter = query.delimiter.clone().unwrap_or_default();
    let max_keys = query.max_keys.unwrap_or(1000);
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

    if delimiter.is_empty() {
        let params = myfsio_common::types::ListParams {
            max_keys,
            continuation_token: effective_start.clone(),
            prefix: if prefix.is_empty() {
                None
            } else {
                Some(prefix.clone())
            },
            start_after: if is_v2 {
                query.start_after.clone()
            } else {
                None
            },
        };
        match state.storage.list_objects(&bucket, &params).await {
            Ok(result) => {
                let next_marker = result
                    .next_continuation_token
                    .clone()
                    .or_else(|| result.objects.last().map(|o| o.key.clone()));
                let xml = if is_v2 {
                    let next_token = next_marker
                        .as_deref()
                        .map(|s| URL_SAFE.encode(s.as_bytes()));
                    myfsio_xml::response::list_objects_v2_xml(
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
                    )
                } else {
                    myfsio_xml::response::list_objects_v1_xml(
                        &bucket,
                        &prefix,
                        &marker,
                        &delimiter,
                        max_keys,
                        &result.objects,
                        &[],
                        result.is_truncated,
                        next_marker.as_deref(),
                    )
                };
                (StatusCode::OK, [("content-type", "application/xml")], xml).into_response()
            }
            Err(e) => storage_err_response(e),
        }
    } else {
        let params = myfsio_common::types::ShallowListParams {
            prefix,
            delimiter: delimiter.clone(),
            max_keys,
            continuation_token: effective_start,
        };
        match state.storage.list_objects_shallow(&bucket, &params).await {
            Ok(result) => {
                let xml = if is_v2 {
                    let next_token = result
                        .next_continuation_token
                        .as_deref()
                        .map(|s| URL_SAFE.encode(s.as_bytes()));
                    myfsio_xml::response::list_objects_v2_xml(
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
                    )
                } else {
                    myfsio_xml::response::list_objects_v1_xml(
                        &bucket,
                        &params.prefix,
                        &marker,
                        &delimiter,
                        max_keys,
                        &result.objects,
                        &result.common_prefixes,
                        result.is_truncated,
                        result.next_continuation_token.as_deref(),
                    )
                };
                (StatusCode::OK, [("content-type", "application/xml")], xml).into_response()
            }
            Err(e) => storage_err_response(e),
        }
    }
}

pub async fn post_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(query): Query<BucketQuery>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if let Some(host_bucket) = virtual_host_bucket_from_headers(&state, &headers).await {
        if host_bucket != bucket {
            return post_object(
                State(state),
                Path((host_bucket, bucket)),
                Query(ObjectQuery::default()),
                headers,
                body,
            )
            .await;
        }
    }

    if query.delete.is_some() {
        return delete_objects_handler(&state, &bucket, body).await;
    }

    if let Some(ct) = headers.get("content-type").and_then(|v| v.to_str().ok()) {
        if ct.to_ascii_lowercase().starts_with("multipart/form-data") {
            return post_object_form_handler(&state, &bucket, ct, body).await;
        }
    }

    (StatusCode::METHOD_NOT_ALLOWED).into_response()
}

pub async fn delete_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(query): Query<BucketQuery>,
    headers: HeaderMap,
) -> Response {
    if let Some(host_bucket) = virtual_host_bucket_from_headers(&state, &headers).await {
        if host_bucket != bucket {
            return delete_object(
                State(state),
                Path((host_bucket, bucket)),
                Query(ObjectQuery::default()),
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
    if query.notification.is_some() {
        return config::delete_notification(&state, &bucket).await;
    }
    if query.logging.is_some() {
        return config::delete_logging(&state, &bucket).await;
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
    if let Some(enc) = headers
        .get("content-encoding")
        .and_then(|v| v.to_str().ok())
    {
        if enc.to_ascii_lowercase().contains("aws-chunked") {
            return true;
        }
    }
    if let Some(sha) = headers
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
    {
        let lower = sha.to_ascii_lowercase();
        if lower.starts_with("streaming-") {
            return true;
        }
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
                if let Some(decoded_encoding) = decoded_content_encoding(value) {
                    metadata.insert((*metadata_key).to_string(), decoded_encoding);
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
        metadata.insert("__storage_class__".to_string(), value.to_ascii_uppercase());
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
}

fn apply_user_metadata(headers: &mut HeaderMap, metadata: &HashMap<String, String>) {
    for (k, v) in metadata {
        if let Ok(header_val) = v.parse() {
            let header_name = format!("x-amz-meta-{}", k);
            if let Ok(name) = header_name.parse::<axum::http::HeaderName>() {
                headers.insert(name, header_val);
            }
        }
    }
}

fn is_null_version(version_id: Option<&str>) -> bool {
    version_id.is_none_or(|value| value == "null")
}

fn bad_digest_response(message: impl Into<String>) -> Response {
    s3_error_response(S3Error::new(S3ErrorCode::BadDigest, message))
}

fn base64_header_bytes(headers: &HeaderMap, name: &str) -> Result<Option<Vec<u8>>, Response> {
    let Some(value) = headers.get(name).and_then(|v| v.to_str().ok()) else {
        return Ok(None);
    };
    STANDARD
        .decode(value.trim())
        .map(Some)
        .map_err(|_| bad_digest_response(format!("Invalid base64 value for {}", name)))
}

fn has_upload_checksum(headers: &HeaderMap) -> bool {
    headers.contains_key("content-md5")
        || headers.contains_key("x-amz-checksum-sha256")
        || headers.contains_key("x-amz-checksum-crc32")
}

fn validate_upload_checksums(headers: &HeaderMap, data: &[u8]) -> Result<(), Response> {
    if let Some(expected) = base64_header_bytes(headers, "content-md5")? {
        if expected.len() != 16 || Md5::digest(data).as_slice() != expected.as_slice() {
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

async fn collect_upload_body(body: Body, aws_chunked: bool) -> Result<Vec<u8>, Response> {
    if aws_chunked {
        let mut reader = chunked::decode_body(body);
        let mut data = Vec::new();
        reader.read_to_end(&mut data).await.map_err(|_| {
            s3_error_response(S3Error::new(
                S3ErrorCode::InvalidRequest,
                "Failed to read aws-chunked request body",
            ))
        })?;
        return Ok(data);
    }

    http_body_util::BodyExt::collect(body)
        .await
        .map(|collected| collected.to_bytes().to_vec())
        .map_err(|_| {
            s3_error_response(S3Error::new(
                S3ErrorCode::InvalidRequest,
                "Failed to read request body",
            ))
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
    headers: HeaderMap,
    body: Body,
) -> Response {
    if query.tagging.is_some() {
        return config::put_object_tagging(&state, &bucket, &key, body).await;
    }
    if query.acl.is_some() {
        return config::put_object_acl(&state, &bucket, &key, &headers, body).await;
    }
    if query.retention.is_some() {
        return config::put_object_retention(&state, &bucket, &key, &headers, body).await;
    }
    if query.legal_hold.is_some() {
        return config::put_object_legal_hold(&state, &bucket, &key, body).await;
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
        return copy_object_handler(&state, copy_source, &bucket, &key, &headers).await;
    }

    if let Err(response) =
        ensure_object_lock_allows_write(&state, &bucket, &key, Some(&headers)).await
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
            http_body_util::BodyStream::new(body)
                .map_ok(|frame| frame.into_data().unwrap_or_default())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)),
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
            if let Some(enc_ctx) = resolve_encryption_context(&state, &bucket, &headers).await {
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
                            let all_meta =
                                match state.storage.get_object_metadata(&bucket, &key).await {
                                    Ok(m) => m,
                                    Err(_) => HashMap::new(),
                                };
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
                            resp_headers.insert(
                                "x-amz-server-side-encryption",
                                enc_ctx.algorithm.as_str().parse().unwrap(),
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
                            trigger_replication(&state, &bucket, &key, "write");
                            return (StatusCode::OK, resp_headers).into_response();
                        }
                        Err(e) => {
                            let _ = tokio::fs::remove_file(&enc_tmp).await;
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
            trigger_replication(&state, &bucket, &key, "write");
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
        return config::get_object_tagging(&state, &bucket, &key).await;
    }
    if query.acl.is_some() {
        return config::get_object_acl(&state, &bucket, &key).await;
    }
    if query.retention.is_some() {
        return config::get_object_retention(&state, &bucket, &key).await;
    }
    if query.legal_hold.is_some() {
        return config::get_object_legal_hold(&state, &bucket, &key).await;
    }
    if query.attributes.is_some() {
        return object_attributes_handler(&state, &bucket, &key, &headers).await;
    }
    if let Some(ref upload_id) = query.upload_id {
        return list_parts_handler(&state, &bucket, &key, upload_id).await;
    }

    let version_id = query
        .version_id
        .as_deref()
        .filter(|value| !is_null_version(Some(*value)));
    let head_meta = match version_id {
        Some(version_id) => match state
            .storage
            .head_object_version(&bucket, &key, version_id)
            .await
        {
            Ok(m) => m,
            Err(e) => return storage_err_response(e),
        },
        None => match state.storage.head_object(&bucket, &key).await {
            Ok(m) => m,
            Err(e) => return storage_err_response(e),
        },
    };
    if let Some(resp) = evaluate_get_preconditions(&headers, &head_meta) {
        return resp;
    }

    let range_header = headers
        .get("range")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    if let Some(ref range_str) = range_header {
        return range_get_handler(&state, &bucket, &key, range_str, &query).await;
    }

    let all_meta = match version_id {
        Some(version_id) => state
            .storage
            .get_object_version_metadata(&bucket, &key, version_id)
            .await
            .unwrap_or_default(),
        None => state
            .storage
            .get_object_metadata(&bucket, &key)
            .await
            .unwrap_or_default(),
    };
    let enc_meta = myfsio_crypto::encryption::EncryptionMetadata::from_metadata(&all_meta);

    if let (Some(ref enc_info), Some(ref enc_svc)) = (&enc_meta, &state.encryption) {
        let obj_path = match version_id {
            Some(version_id) => match state
                .storage
                .get_object_version_path(&bucket, &key, version_id)
                .await
            {
                Ok(p) => p,
                Err(e) => return storage_err_response(e),
            },
            None => match state.storage.get_object_path(&bucket, &key).await {
                Ok(p) => p,
                Err(e) => return storage_err_response(e),
            },
        };
        let tmp_dir = state.config.storage_root.join(".myfsio.sys").join("tmp");
        let _ = tokio::fs::create_dir_all(&tmp_dir).await;
        let dec_tmp = tmp_dir.join(format!("dec-{}", uuid::Uuid::new_v4()));

        let customer_key = extract_sse_c_key(&headers);
        let ck_ref = customer_key.as_deref();

        if let Err(e) = enc_svc
            .decrypt_object(&obj_path, &dec_tmp, enc_info, ck_ref)
            .await
        {
            let _ = tokio::fs::remove_file(&dec_tmp).await;
            return s3_error_response(S3Error::new(
                myfsio_common::error::S3ErrorCode::InternalError,
                format!("Decryption failed: {}", e),
            ));
        }

        let file = match tokio::fs::File::open(&dec_tmp).await {
            Ok(f) => f,
            Err(e) => {
                let _ = tokio::fs::remove_file(&dec_tmp).await;
                return storage_err_response(myfsio_storage::error::StorageError::Io(e));
            }
        };
        let file_size = file.metadata().await.map(|m| m.len()).unwrap_or(0);
        let stream = ReaderStream::new(file);
        let body = Body::from_stream(stream);

        let meta = head_meta.clone();

        let tmp_path = dec_tmp.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            let _ = tokio::fs::remove_file(&tmp_path).await;
        });

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
        resp_headers.insert(
            "x-amz-server-side-encryption",
            enc_info.algorithm.parse().unwrap(),
        );
        apply_stored_response_headers(&mut resp_headers, &all_meta);
        if let Some(ref requested_version) = query.version_id {
            if let Ok(value) = requested_version.parse() {
                resp_headers.insert("x-amz-version-id", value);
            }
        }

        apply_user_metadata(&mut resp_headers, &meta.metadata);

        apply_response_overrides(&mut resp_headers, &query);

        return (StatusCode::OK, resp_headers, body).into_response();
    }

    let object_result = match version_id {
        Some(version_id) => {
            state
                .storage
                .get_object_version(&bucket, &key, version_id)
                .await
        }
        None => state.storage.get_object(&bucket, &key).await,
    };

    match object_result {
        Ok((meta, reader)) => {
            let stream = ReaderStream::new(reader);
            let body = Body::from_stream(stream);

            let mut headers = HeaderMap::new();
            headers.insert("content-length", meta.size.to_string().parse().unwrap());
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
            apply_stored_response_headers(&mut headers, &all_meta);
            if let Some(ref requested_version) = query.version_id {
                if let Ok(value) = requested_version.parse() {
                    headers.insert("x-amz-version-id", value);
                }
            }

            apply_user_metadata(&mut headers, &meta.metadata);

            apply_response_overrides(&mut headers, &query);

            (StatusCode::OK, headers, body).into_response()
        }
        Err(e) => storage_err_response(e),
    }
}

pub async fn post_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(query): Query<ObjectQuery>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if query.uploads.is_some() {
        return initiate_multipart_handler(&state, &bucket, &key).await;
    }

    if let Some(ref upload_id) = query.upload_id {
        return complete_multipart_handler(&state, &bucket, &key, upload_id, body).await;
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
    headers: HeaderMap,
) -> Response {
    if query.tagging.is_some() {
        return config::delete_object_tagging(&state, &bucket, &key).await;
    }
    if query.acl.is_some() {
        return StatusCode::NO_CONTENT.into_response();
    }

    if let Some(ref upload_id) = query.upload_id {
        return abort_multipart_handler(&state, &bucket, upload_id).await;
    }

    if let Some(version_id) = query
        .version_id
        .as_deref()
        .filter(|value| !is_null_version(Some(*value)))
    {
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
            Ok(()) => {
                let mut resp_headers = HeaderMap::new();
                if let Ok(value) = version_id.parse() {
                    resp_headers.insert("x-amz-version-id", value);
                }
                notifications::emit_object_removed(&state, &bucket, &key, "", "", "", "Delete");
                trigger_replication(&state, &bucket, &key, "delete");
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
        Ok(()) => {
            notifications::emit_object_removed(&state, &bucket, &key, "", "", "", "Delete");
            trigger_replication(&state, &bucket, &key, "delete");
            StatusCode::NO_CONTENT.into_response()
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
    let version_id = query
        .version_id
        .as_deref()
        .filter(|value| !is_null_version(Some(*value)));
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
            let all_meta = match version_id {
                Some(version_id) => state
                    .storage
                    .get_object_version_metadata(&bucket, &key, version_id)
                    .await
                    .unwrap_or_default(),
                None => state
                    .storage
                    .get_object_metadata(&bucket, &key)
                    .await
                    .unwrap_or_default(),
            };
            let mut headers = HeaderMap::new();
            headers.insert("content-length", meta.size.to_string().parse().unwrap());
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
            apply_stored_response_headers(&mut headers, &all_meta);
            if let Some(ref requested_version) = query.version_id {
                if let Ok(value) = requested_version.parse() {
                    headers.insert("x-amz-version-id", value);
                }
            }

            apply_user_metadata(&mut headers, &meta.metadata);

            (StatusCode::OK, headers).into_response()
        }
        Err(e) => storage_err_response(e),
    }
}

async fn initiate_multipart_handler(state: &AppState, bucket: &str, key: &str) -> Response {
    match state.storage.initiate_multipart(bucket, key, None).await {
        Ok(upload_id) => {
            let xml = myfsio_xml::response::initiate_multipart_upload_xml(bucket, key, &upload_id);
            (StatusCode::OK, [("content-type", "application/xml")], xml).into_response()
        }
        Err(e) => storage_err_response(e),
    }
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
            http_body_util::BodyStream::new(body)
                .map_ok(|frame| frame.into_data().unwrap_or_default())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)),
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
    let source = copy_source.strip_prefix('/').unwrap_or(copy_source);
    let source = match percent_encoding::percent_decode_str(source).decode_utf8() {
        Ok(s) => s.into_owned(),
        Err(_) => {
            return s3_error_response(S3Error::new(
                myfsio_common::error::S3ErrorCode::InvalidArgument,
                "Invalid x-amz-copy-source encoding",
            ));
        }
    };
    let (src_bucket, src_key) = match source.split_once('/') {
        Some((b, k)) => (b.to_string(), k.to_string()),
        None => {
            return s3_error_response(S3Error::new(
                myfsio_common::error::S3ErrorCode::InvalidArgument,
                "Invalid x-amz-copy-source",
            ));
        }
    };

    let source_meta = match state.storage.head_object(&src_bucket, &src_key).await {
        Ok(m) => m,
        Err(e) => return storage_err_response(e),
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
    let parsed = match myfsio_xml::request::parse_complete_multipart_upload(&xml_str) {
        Ok(p) => p,
        Err(e) => {
            return s3_error_response(S3Error::new(
                myfsio_common::error::S3ErrorCode::MalformedXML,
                e,
            ));
        }
    };

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
            let etag = meta.etag.as_deref().unwrap_or("");
            let xml = myfsio_xml::response::complete_multipart_upload_xml(
                bucket,
                key,
                etag,
                &format!("/{}/{}", bucket, key),
            );
            trigger_replication(state, bucket, key, "write");
            (StatusCode::OK, [("content-type", "application/xml")], xml).into_response()
        }
        Err(e) => storage_err_response(e),
    }
}

async fn abort_multipart_handler(state: &AppState, bucket: &str, upload_id: &str) -> Response {
    match state.storage.abort_multipart(bucket, upload_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => storage_err_response(e),
    }
}

async fn list_multipart_uploads_handler(state: &AppState, bucket: &str) -> Response {
    match state.storage.list_multipart_uploads(bucket).await {
        Ok(uploads) => {
            let xml = myfsio_xml::response::list_multipart_uploads_xml(bucket, &uploads);
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
) -> Response {
    match state.storage.list_parts(bucket, upload_id).await {
        Ok(parts) => {
            let xml = myfsio_xml::response::list_parts_xml(bucket, key, upload_id, &parts);
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

    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    xml.push_str("<GetObjectAttributesResponse xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");

    if all || attrs.contains("etag") {
        if let Some(etag) = &meta.etag {
            xml.push_str(&format!("<ETag>{}</ETag>", xml_escape(etag)));
        }
    }
    if all || attrs.contains("storageclass") {
        let sc = meta.storage_class.as_deref().unwrap_or("STANDARD");
        xml.push_str(&format!("<StorageClass>{}</StorageClass>", xml_escape(sc)));
    }
    if all || attrs.contains("objectsize") {
        xml.push_str(&format!("<ObjectSize>{}</ObjectSize>", meta.size));
    }
    if attrs.contains("checksum") {
        xml.push_str("<Checksum></Checksum>");
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
    headers: &HeaderMap,
) -> Response {
    if let Err(response) =
        ensure_object_lock_allows_write(state, dst_bucket, dst_key, Some(headers)).await
    {
        return response;
    }

    let (src_bucket, src_key, src_version_id) = match parse_copy_source(copy_source) {
        Ok(parts) => parts,
        Err(response) => return response,
    };

    let source_meta = match src_version_id.as_deref() {
        Some(version_id) if version_id != "null" => match state
            .storage
            .head_object_version(&src_bucket, &src_key, version_id)
            .await
        {
            Ok(m) => m,
            Err(e) => return storage_err_response(e),
        },
        _ => match state.storage.head_object(&src_bucket, &src_key).await {
            Ok(m) => m,
            Err(e) => return storage_err_response(e),
        },
    };
    if let Some(resp) = evaluate_copy_preconditions(headers, &source_meta) {
        return resp;
    }

    let copy_result = if let Some(version_id) = src_version_id
        .as_deref()
        .filter(|value| !is_null_version(Some(*value)))
    {
        let (_meta, mut reader) = match state
            .storage
            .get_object_version(&src_bucket, &src_key, version_id)
            .await
        {
            Ok(result) => result,
            Err(e) => return storage_err_response(e),
        };
        let mut data = Vec::new();
        if let Err(e) = reader.read_to_end(&mut data).await {
            return storage_err_response(myfsio_storage::error::StorageError::Io(e));
        }
        let metadata = match state
            .storage
            .get_object_version_metadata(&src_bucket, &src_key, version_id)
            .await
        {
            Ok(metadata) => metadata,
            Err(e) => return storage_err_response(e),
        };
        state
            .storage
            .put_object(
                dst_bucket,
                dst_key,
                Box::pin(std::io::Cursor::new(data)),
                Some(metadata),
            )
            .await
    } else {
        state
            .storage
            .copy_object(&src_bucket, &src_key, dst_bucket, dst_key)
            .await
    };

    match copy_result {
        Ok(meta) => {
            let etag = meta.etag.as_deref().unwrap_or("");
            let last_modified = myfsio_xml::response::format_s3_datetime(&meta.last_modified);
            let xml = myfsio_xml::response::copy_object_result_xml(etag, &last_modified);
            trigger_replication(state, dst_bucket, dst_key, "write");
            (StatusCode::OK, [("content-type", "application/xml")], xml).into_response()
        }
        Err(e) => storage_err_response(e),
    }
}

async fn delete_objects_handler(state: &AppState, bucket: &str, body: Body) -> Response {
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

    let mut deleted = Vec::new();
    let mut errors = Vec::new();

    for obj in &parsed.objects {
        if let Err(message) = match obj.version_id.as_deref() {
            Some(version_id) if version_id != "null" => match state
                .storage
                .get_object_version_metadata(bucket, &obj.key, version_id)
                .await
            {
                Ok(metadata) => object_lock::can_delete_object(&metadata, false),
                Err(err) => Err(S3Error::from(err).message),
            },
            _ => match state.storage.head_object(bucket, &obj.key).await {
                Ok(_) => match state.storage.get_object_metadata(bucket, &obj.key).await {
                    Ok(metadata) => object_lock::can_delete_object(&metadata, false),
                    Err(err) => Err(S3Error::from(err).message),
                },
                Err(myfsio_storage::error::StorageError::ObjectNotFound { .. }) => Ok(()),
                Err(err) => Err(S3Error::from(err).message),
            },
        } {
            errors.push((
                obj.key.clone(),
                S3ErrorCode::AccessDenied.as_str().to_string(),
                message,
            ));
            continue;
        }
        let delete_result = if let Some(version_id) = obj.version_id.as_deref() {
            if version_id == "null" {
                state.storage.delete_object(bucket, &obj.key).await
            } else {
                state
                    .storage
                    .delete_object_version(bucket, &obj.key, version_id)
                    .await
            }
        } else {
            state.storage.delete_object(bucket, &obj.key).await
        };

        match delete_result {
            Ok(()) => {
                notifications::emit_object_removed(state, bucket, &obj.key, "", "", "", "Delete");
                trigger_replication(state, bucket, &obj.key, "delete");
                deleted.push((obj.key.clone(), obj.version_id.clone()))
            }
            Err(e) => {
                let s3err = S3Error::from(e);
                errors.push((
                    obj.key.clone(),
                    s3err.code.as_str().to_string(),
                    s3err.message,
                ));
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
) -> Response {
    let version_id = query
        .version_id
        .as_deref()
        .filter(|value| !is_null_version(Some(*value)));
    let meta = match version_id {
        Some(version_id) => match state
            .storage
            .head_object_version(bucket, key, version_id)
            .await
        {
            Ok(m) => m,
            Err(e) => return storage_err_response(e),
        },
        None => match state.storage.head_object(bucket, key).await {
            Ok(m) => m,
            Err(e) => return storage_err_response(e),
        },
    };

    let total_size = meta.size;
    let (start, end) = match parse_range(range_str, total_size) {
        Some(r) => r,
        None => {
            return s3_error_response(S3Error::new(
                myfsio_common::error::S3ErrorCode::InvalidRange,
                format!("Range not satisfiable for size {}", total_size),
            ));
        }
    };

    let path = match version_id {
        Some(version_id) => match state
            .storage
            .get_object_version_path(bucket, key, version_id)
            .await
        {
            Ok(p) => p,
            Err(e) => return storage_err_response(e),
        },
        None => match state.storage.get_object_path(bucket, key).await {
            Ok(p) => p,
            Err(e) => return storage_err_response(e),
        },
    };

    let mut file = match tokio::fs::File::open(&path).await {
        Ok(f) => f,
        Err(e) => return storage_err_response(myfsio_storage::error::StorageError::Io(e)),
    };

    if let Err(e) = file.seek(std::io::SeekFrom::Start(start)).await {
        return storage_err_response(myfsio_storage::error::StorageError::Io(e));
    }

    let length = end - start + 1;
    let limited = file.take(length);
    let stream = ReaderStream::new(limited);
    let body = Body::from_stream(stream);

    let mut headers = HeaderMap::new();
    headers.insert("content-length", length.to_string().parse().unwrap());
    headers.insert(
        "content-range",
        format!("bytes {}-{}/{}", start, end, total_size)
            .parse()
            .unwrap(),
    );
    if let Some(ref etag) = meta.etag {
        headers.insert("etag", format!("\"{}\"", etag).parse().unwrap());
    }
    insert_content_type(&mut headers, key, meta.content_type.as_deref());
    headers.insert("accept-ranges", "bytes".parse().unwrap());
    if let Some(ref requested_version) = query.version_id {
        if let Ok(value) = requested_version.parse() {
            headers.insert("x-amz-version-id", value);
        }
    }

    apply_response_overrides(&mut headers, query);

    (StatusCode::PARTIAL_CONTENT, headers, body).into_response()
}

fn evaluate_get_preconditions(
    headers: &HeaderMap,
    meta: &myfsio_common::types::ObjectMeta,
) -> Option<Response> {
    if let Some(value) = headers.get("if-match").and_then(|v| v.to_str().ok()) {
        if !etag_condition_matches(value, meta.etag.as_deref()) {
            return Some(s3_error_response(S3Error::from_code(
                S3ErrorCode::PreconditionFailed,
            )));
        }
    }

    if let Some(value) = headers
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
            return Some(StatusCode::NOT_MODIFIED.into_response());
        }
    }

    if let Some(value) = headers
        .get("if-modified-since")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(t) = parse_http_date(value) {
            if meta.last_modified <= t {
                return Some(StatusCode::NOT_MODIFIED.into_response());
            }
        }
    }

    None
}

async fn evaluate_put_preconditions(
    state: &AppState,
    bucket: &str,
    key: &str,
    headers: &HeaderMap,
) -> Option<Response> {
    let has_if_match = headers.contains_key("if-match");
    let has_if_none_match = headers.contains_key("if-none-match");
    if !has_if_match && !has_if_none_match {
        return None;
    }

    match state.storage.head_object(bucket, key).await {
        Ok(meta) => {
            if let Some(value) = headers.get("if-match").and_then(|v| v.to_str().ok()) {
                if !etag_condition_matches(value, meta.etag.as_deref()) {
                    return Some(s3_error_response(S3Error::from_code(
                        S3ErrorCode::PreconditionFailed,
                    )));
                }
            }
            if let Some(value) = headers.get("if-none-match").and_then(|v| v.to_str().ok()) {
                if etag_condition_matches(value, meta.etag.as_deref()) {
                    return Some(s3_error_response(S3Error::from_code(
                        S3ErrorCode::PreconditionFailed,
                    )));
                }
            }
            None
        }
        Err(myfsio_storage::error::StorageError::ObjectNotFound { .. }) => {
            if has_if_match {
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
    if let Some(value) = headers
        .get("x-amz-copy-source-if-match")
        .and_then(|v| v.to_str().ok())
    {
        if !etag_condition_matches(value, source_meta.etag.as_deref()) {
            return Some(s3_error_response(S3Error::from_code(
                S3ErrorCode::PreconditionFailed,
            )));
        }
    }

    if let Some(value) = headers
        .get("x-amz-copy-source-if-none-match")
        .and_then(|v| v.to_str().ok())
    {
        if etag_condition_matches(value, source_meta.etag.as_deref()) {
            return Some(s3_error_response(S3Error::from_code(
                S3ErrorCode::PreconditionFailed,
            )));
        }
    }

    if let Some(value) = headers
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

    if let Some(value) = headers
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

    None
}

fn parse_http_date(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc2822(value)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
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

    if let Some(suffix) = range_spec.strip_prefix('-') {
        let suffix_len: u64 = suffix.parse().ok()?;
        if suffix_len == 0 || suffix_len > total_size {
            return None;
        }
        return Some((total_size - suffix_len, total_size - 1));
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

use futures::TryStreamExt;
use http_body_util;
use tokio::io::AsyncReadExt;

async fn resolve_encryption_context(
    state: &AppState,
    bucket: &str,
    headers: &HeaderMap,
) -> Option<myfsio_crypto::encryption::EncryptionContext> {
    if let Some(alg) = headers
        .get("x-amz-server-side-encryption")
        .and_then(|v| v.to_str().ok())
    {
        let algorithm = match alg {
            "AES256" => myfsio_crypto::encryption::SseAlgorithm::Aes256,
            "aws:kms" => myfsio_crypto::encryption::SseAlgorithm::AwsKms,
            _ => return None,
        };
        let kms_key_id = headers
            .get("x-amz-server-side-encryption-aws-kms-key-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        return Some(myfsio_crypto::encryption::EncryptionContext {
            algorithm,
            kms_key_id,
            customer_key: None,
        });
    }

    if let Some(sse_c_alg) = headers
        .get("x-amz-server-side-encryption-customer-algorithm")
        .and_then(|v| v.to_str().ok())
    {
        if sse_c_alg == "AES256" {
            let customer_key = extract_sse_c_key(headers);
            if let Some(ck) = customer_key {
                return Some(myfsio_crypto::encryption::EncryptionContext {
                    algorithm: myfsio_crypto::encryption::SseAlgorithm::CustomerProvided,
                    kms_key_id: None,
                    customer_key: Some(ck),
                });
            }
        }
        return None;
    }

    if state.encryption.is_some() {
        if let Ok(config) = state.storage.get_bucket_config(bucket).await {
            if let Some(enc_val) = &config.encryption {
                let enc_str = enc_val.to_string();
                if enc_str.contains("AES256") {
                    return Some(myfsio_crypto::encryption::EncryptionContext {
                        algorithm: myfsio_crypto::encryption::SseAlgorithm::Aes256,
                        kms_key_id: None,
                        customer_key: None,
                    });
                }
                if enc_str.contains("aws:kms") {
                    return Some(myfsio_crypto::encryption::EncryptionContext {
                        algorithm: myfsio_crypto::encryption::SseAlgorithm::AwsKms,
                        kms_key_id: None,
                        customer_key: None,
                    });
                }
            }
        }
    }

    None
}

fn extract_sse_c_key(headers: &HeaderMap) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;

    let key_b64 = headers
        .get("x-amz-server-side-encryption-customer-key")
        .and_then(|v| v.to_str().ok())?;
    B64.decode(key_b64).ok()
}

async fn post_object_form_handler(
    state: &AppState,
    bucket: &str,
    content_type: &str,
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
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e));
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
            match field.text().await {
                Ok(t) => {
                    fields.insert(name, t);
                }
                Err(_) => {}
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
            if !meta_key.is_empty() && !(meta_key.starts_with("__") && meta_key.ends_with("__")) {
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

    let etag = meta.etag.as_deref().unwrap_or("");
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
    fn aws_chunked_wire_encoding_is_not_persisted_as_object_encoding() {
        let mut headers = HeaderMap::new();
        headers.insert("content-encoding", "aws-chunked".parse().unwrap());
        let mut metadata = HashMap::new();
        insert_standard_object_metadata(&headers, &mut metadata).unwrap();
        assert!(!metadata.contains_key("__content_encoding__"));

        headers.insert("content-encoding", "aws-chunked, gzip".parse().unwrap());
        let mut metadata = HashMap::new();
        insert_standard_object_metadata(&headers, &mut metadata).unwrap();
        assert_eq!(metadata.get("__content_encoding__").unwrap(), "gzip");
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
}
