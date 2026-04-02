mod config;
pub mod kms;
mod select;

use std::collections::HashMap;

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::URL_SAFE;
use base64::Engine;
use chrono::{DateTime, Utc};

use myfsio_common::error::{S3Error, S3ErrorCode};
use myfsio_common::types::PartInfo;
use myfsio_storage::traits::StorageEngine;
use tokio::io::AsyncSeekExt;
use tokio_util::io::ReaderStream;

use crate::state::AppState;

fn s3_error_response(err: S3Error) -> Response {
    let status = StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let resource = if err.resource.is_empty() {
        "/".to_string()
    } else {
        err.resource.clone()
    };
    let body = err
        .with_resource(resource)
        .with_request_id(uuid::Uuid::new_v4().simple().to_string())
        .to_xml();
    (
        status,
        [("content-type", "application/xml")],
        body,
    )
        .into_response()
}

fn storage_err_response(err: myfsio_storage::error::StorageError) -> Response {
    s3_error_response(S3Error::from(err))
}

pub async fn list_buckets(State(state): State<AppState>) -> Response {
    match state.storage.list_buckets().await {
        Ok(buckets) => {
            let xml = myfsio_xml::response::list_buckets_xml("myfsio", "myfsio", &buckets);
            (
                StatusCode::OK,
                [("content-type", "application/xml")],
                xml,
            )
                .into_response()
        }
        Err(e) => storage_err_response(e),
    }
}

pub async fn create_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(query): Query<BucketQuery>,
    body: Body,
) -> Response {
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

    match state.storage.create_bucket(&bucket).await {
        Ok(()) => {
            (
                StatusCode::OK,
                [("location", format!("/{}", bucket).as_str())],
                "",
            )
                .into_response()
        }
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

pub async fn get_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(query): Query<BucketQuery>,
) -> Response {
    if !matches!(state.storage.bucket_exists(&bucket).await, Ok(true)) {
        return storage_err_response(
            myfsio_storage::error::StorageError::BucketNotFound(bucket),
        );
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
        return config::list_object_versions(&state, &bucket).await;
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
            prefix: if prefix.is_empty() { None } else { Some(prefix.clone()) },
            start_after: if is_v2 { query.start_after.clone() } else { None },
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
    body: Body,
) -> Response {
    if query.delete.is_some() {
        return delete_objects_handler(&state, &bucket, body).await;
    }

    (StatusCode::METHOD_NOT_ALLOWED).into_response()
}

pub async fn delete_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(query): Query<BucketQuery>,
) -> Response {
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

    match state.storage.delete_bucket(&bucket).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => storage_err_response(e),
    }
}

pub async fn head_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
) -> Response {
    match state.storage.bucket_exists(&bucket).await {
        Ok(true) => {
            let mut headers = HeaderMap::new();
            headers.insert("x-amz-bucket-region", state.config.region.parse().unwrap());
            (StatusCode::OK, headers).into_response()
        }
        Ok(false) => storage_err_response(
            myfsio_storage::error::StorageError::BucketNotFound(bucket),
        ),
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
        if let Ok(val) = v.parse() { headers.insert("content-type", val); }
    }
    if let Some(ref v) = query.response_content_disposition {
        if let Ok(val) = v.parse() { headers.insert("content-disposition", val); }
    }
    if let Some(ref v) = query.response_content_language {
        if let Ok(val) = v.parse() { headers.insert("content-language", val); }
    }
    if let Some(ref v) = query.response_content_encoding {
        if let Ok(val) = v.parse() { headers.insert("content-encoding", val); }
    }
    if let Some(ref v) = query.response_cache_control {
        if let Ok(val) = v.parse() { headers.insert("cache-control", val); }
    }
    if let Some(ref v) = query.response_expires {
        if let Ok(val) = v.parse() { headers.insert("expires", val); }
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

fn insert_content_type(headers: &mut HeaderMap, key: &str, explicit: Option<&str>) {
    let value = guessed_content_type(key, explicit);
    if let Ok(header_value) = value.parse() {
        headers.insert("content-type", header_value);
    } else {
        headers.insert("content-type", "application/octet-stream".parse().unwrap());
    }
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
        return config::put_object_acl(&state, &bucket, &key, body).await;
    }
    if query.retention.is_some() {
        return config::put_object_retention(&state, &bucket, &key, body).await;
    }
    if query.legal_hold.is_some() {
        return config::put_object_legal_hold(&state, &bucket, &key, body).await;
    }

    if let Some(ref upload_id) = query.upload_id {
        if let Some(part_number) = query.part_number {
            return upload_part_handler(&state, &bucket, upload_id, part_number, body).await;
        }
    }

    if let Some(copy_source) = headers.get("x-amz-copy-source").and_then(|v| v.to_str().ok()) {
        return copy_object_handler(&state, copy_source, &bucket, &key, &headers).await;
    }

    let content_type = guessed_content_type(
        &key,
        headers
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
    );

    let mut metadata = HashMap::new();
    metadata.insert("__content_type__".to_string(), content_type);

    for (name, value) in headers.iter() {
        let name_str = name.as_str();
        if let Some(meta_key) = name_str.strip_prefix("x-amz-meta-") {
            if let Ok(val) = value.to_str() {
                metadata.insert(meta_key.to_string(), val.to_string());
            }
        }
    }

    let stream = tokio_util::io::StreamReader::new(
        http_body_util::BodyStream::new(body).map_ok(|frame| {
            frame.into_data().unwrap_or_default()
        }).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)),
    );
    let boxed: myfsio_storage::traits::AsyncReadStream = Box::pin(stream);

    match state.storage.put_object(&bucket, &key, boxed, Some(metadata)).await {
        Ok(meta) => {
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
                                return storage_err_response(myfsio_storage::error::StorageError::Io(e));
                            }
                            let enc_size = tokio::fs::metadata(&obj_path).await.map(|m| m.len()).unwrap_or(0);

                            let mut enc_metadata = enc_meta.to_metadata_map();
                            let all_meta = match state.storage.get_object_metadata(&bucket, &key).await {
                                Ok(m) => m,
                                Err(_) => HashMap::new(),
                            };
                            for (k, v) in &all_meta {
                                enc_metadata.entry(k.clone()).or_insert_with(|| v.clone());
                            }
                            enc_metadata.insert("__size__".to_string(), enc_size.to_string());
                            let _ = state.storage.put_object_metadata(&bucket, &key, &enc_metadata).await;

                            let mut resp_headers = HeaderMap::new();
                            if let Some(ref etag) = meta.etag {
                                resp_headers.insert("etag", format!("\"{}\"", etag).parse().unwrap());
                            }
                            resp_headers.insert("x-amz-server-side-encryption", enc_ctx.algorithm.as_str().parse().unwrap());
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

    let head_meta = match state.storage.head_object(&bucket, &key).await {
        Ok(m) => m,
        Err(e) => return storage_err_response(e),
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

    let all_meta = state.storage.get_object_metadata(&bucket, &key).await.unwrap_or_default();
    let enc_meta = myfsio_crypto::encryption::EncryptionMetadata::from_metadata(&all_meta);

    if let (Some(ref enc_info), Some(ref enc_svc)) = (&enc_meta, &state.encryption) {
        let obj_path = match state.storage.get_object_path(&bucket, &key).await {
            Ok(p) => p,
            Err(e) => return storage_err_response(e),
        };
        let tmp_dir = state.config.storage_root.join(".myfsio.sys").join("tmp");
        let _ = tokio::fs::create_dir_all(&tmp_dir).await;
        let dec_tmp = tmp_dir.join(format!("dec-{}", uuid::Uuid::new_v4()));

        let customer_key = extract_sse_c_key(&headers);
        let ck_ref = customer_key.as_deref();

        if let Err(e) = enc_svc.decrypt_object(&obj_path, &dec_tmp, enc_info, ck_ref).await {
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
            meta.last_modified.format("%a, %d %b %Y %H:%M:%S GMT").to_string().parse().unwrap(),
        );
        resp_headers.insert("accept-ranges", "bytes".parse().unwrap());
        resp_headers.insert("x-amz-server-side-encryption", enc_info.algorithm.parse().unwrap());

        for (k, v) in &meta.metadata {
            if let Ok(header_val) = v.parse() {
                let header_name = format!("x-amz-meta-{}", k);
                if let Ok(name) = header_name.parse::<axum::http::HeaderName>() {
                    resp_headers.insert(name, header_val);
                }
            }
        }

        apply_response_overrides(&mut resp_headers, &query);

        return (StatusCode::OK, resp_headers, body).into_response();
    }

    match state.storage.get_object(&bucket, &key).await {
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

            for (k, v) in &meta.metadata {
                if let Ok(header_val) = v.parse() {
                    let header_name = format!("x-amz-meta-{}", k);
                    if let Ok(name) = header_name.parse::<axum::http::HeaderName>() {
                        headers.insert(name, header_val);
                    }
                }
            }

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
) -> Response {
    if query.tagging.is_some() {
        return config::delete_object_tagging(&state, &bucket, &key).await;
    }

    if let Some(ref upload_id) = query.upload_id {
        return abort_multipart_handler(&state, &bucket, upload_id).await;
    }

    match state.storage.delete_object(&bucket, &key).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => storage_err_response(e),
    }
}

pub async fn head_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    match state.storage.head_object(&bucket, &key).await {
        Ok(meta) => {
            if let Some(resp) = evaluate_get_preconditions(&headers, &meta) {
                return resp;
            }
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

            for (k, v) in &meta.metadata {
                if let Ok(header_val) = v.parse() {
                    let header_name = format!("x-amz-meta-{}", k);
                    if let Ok(name) = header_name.parse::<axum::http::HeaderName>() {
                        headers.insert(name, header_val);
                    }
                }
            }

            (StatusCode::OK, headers).into_response()
        }
        Err(e) => storage_err_response(e),
    }
}

async fn initiate_multipart_handler(
    state: &AppState,
    bucket: &str,
    key: &str,
) -> Response {
    match state.storage.initiate_multipart(bucket, key, None).await {
        Ok(upload_id) => {
            let xml = myfsio_xml::response::initiate_multipart_upload_xml(bucket, key, &upload_id);
            (StatusCode::OK, [("content-type", "application/xml")], xml).into_response()
        }
        Err(e) => storage_err_response(e),
    }
}

async fn upload_part_handler(
    state: &AppState,
    bucket: &str,
    upload_id: &str,
    part_number: u32,
    body: Body,
) -> Response {
    let stream = tokio_util::io::StreamReader::new(
        http_body_util::BodyStream::new(body).map_ok(|frame| {
            frame.into_data().unwrap_or_default()
        }).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)),
    );
    let boxed: myfsio_storage::traits::AsyncReadStream = Box::pin(stream);

    match state.storage.upload_part(bucket, upload_id, part_number, boxed).await {
        Ok(etag) => {
            let mut headers = HeaderMap::new();
            headers.insert("etag", format!("\"{}\"", etag).parse().unwrap());
            (StatusCode::OK, headers).into_response()
        }
        Err(e) => storage_err_response(e),
    }
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

    match state.storage.complete_multipart(bucket, upload_id, &parts).await {
        Ok(meta) => {
            let etag = meta.etag.as_deref().unwrap_or("");
            let xml = myfsio_xml::response::complete_multipart_upload_xml(
                bucket,
                key,
                etag,
                &format!("/{}/{}", bucket, key),
            );
            (StatusCode::OK, [("content-type", "application/xml")], xml).into_response()
        }
        Err(e) => storage_err_response(e),
    }
}

async fn abort_multipart_handler(
    state: &AppState,
    bucket: &str,
    upload_id: &str,
) -> Response {
    match state.storage.abort_multipart(bucket, upload_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => storage_err_response(e),
    }
}

async fn list_multipart_uploads_handler(
    state: &AppState,
    bucket: &str,
) -> Response {
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

    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    );
    xml.push_str("<GetObjectAttributesResponse xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");

    if all || attrs.contains("etag") {
        if let Some(etag) = &meta.etag {
            xml.push_str(&format!("<ETag>{}</ETag>", xml_escape(etag)));
        }
    }
    if all || attrs.contains("storageclass") {
        let sc = meta
            .storage_class
            .as_deref()
            .unwrap_or("STANDARD");
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
    let source = copy_source.strip_prefix('/').unwrap_or(copy_source);
    let (src_bucket, src_key) = match source.split_once('/') {
        Some(parts) => parts,
        None => {
            return s3_error_response(S3Error::new(
                myfsio_common::error::S3ErrorCode::InvalidArgument,
                "Invalid x-amz-copy-source",
            ));
        }
    };

    let source_meta = match state.storage.head_object(src_bucket, src_key).await {
        Ok(m) => m,
        Err(e) => return storage_err_response(e),
    };
    if let Some(resp) = evaluate_copy_preconditions(headers, &source_meta) {
        return resp;
    }

    match state.storage.copy_object(src_bucket, src_key, dst_bucket, dst_key).await {
        Ok(meta) => {
            let etag = meta.etag.as_deref().unwrap_or("");
            let last_modified = meta.last_modified.to_rfc3339();
            let xml = myfsio_xml::response::copy_object_result_xml(etag, &last_modified);
            (StatusCode::OK, [("content-type", "application/xml")], xml).into_response()
        }
        Err(e) => storage_err_response(e),
    }
}

async fn delete_objects_handler(
    state: &AppState,
    bucket: &str,
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

    let mut deleted = Vec::new();
    let mut errors = Vec::new();

    for obj in &parsed.objects {
        match state.storage.delete_object(bucket, &obj.key).await {
            Ok(()) => deleted.push((obj.key.clone(), obj.version_id.clone())),
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
    let meta = match state.storage.head_object(bucket, key).await {
        Ok(m) => m,
        Err(e) => return storage_err_response(e),
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

    let path = match state.storage.get_object_path(bucket, key).await {
        Ok(p) => p,
        Err(e) => return storage_err_response(e),
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
        format!("bytes {}-{}/{}", start, end, total_size).parse().unwrap(),
    );
    if let Some(ref etag) = meta.etag {
        headers.insert("etag", format!("\"{}\"", etag).parse().unwrap());
    }
    insert_content_type(&mut headers, key, meta.content_type.as_deref());
    headers.insert("accept-ranges", "bytes".parse().unwrap());

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
    if let Some(alg) = headers.get("x-amz-server-side-encryption").and_then(|v| v.to_str().ok()) {
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
