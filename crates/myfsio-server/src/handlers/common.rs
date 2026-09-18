use super::*;

pub(super) async fn open_self_deleting(
    path: std::path::PathBuf,
) -> std::io::Result<tokio::fs::File> {
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

pub(super) fn parse_max_keys(raw: &str) -> Result<usize, Response> {
    match raw.parse::<i64>() {
        Ok(v) if (0..=2_147_483_647).contains(&v) => Ok(v as usize),
        _ => Err(s3_error_response(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "Argument max-keys must be an integer between 0 and 2147483647",
        ))),
    }
}

pub(super) fn validate_encoding_type(query: &BucketQuery) -> Result<(), Response> {
    match query.encoding_type.as_deref() {
        Some(value) if !value.eq_ignore_ascii_case("url") => Err(s3_error_response(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "Invalid Encoding Method specified in Request",
        ))),
        _ => Ok(()),
    }
}

pub(crate) fn s3_error_response(err: S3Error) -> Response {
    crate::s3_response::s3_error_response(err)
}

pub(crate) const CONFIG_BODY_LIMIT: usize = 1024 * 1024;

pub(crate) const BULK_XML_BODY_LIMIT: usize = 8 * 1024 * 1024;

pub(crate) const JSON_API_BODY_LIMIT: usize = 1024 * 1024;

pub(crate) const POST_FORM_FIELD_LIMIT: u64 = 1024 * 1024;

pub(crate) enum BodyLimitError {
    Unreadable,
    TooLarge(usize),
}

pub(crate) async fn collect_body_capped(
    body: Body,
    max: usize,
) -> Result<bytes::Bytes, BodyLimitError> {
    use futures::StreamExt;

    let mut frames = http_body_util::BodyStream::new(body);
    let mut buffer = bytes::BytesMut::new();
    while let Some(frame) = frames.next().await {
        let data = match frame {
            Ok(frame) => frame.into_data().unwrap_or_default(),
            Err(_) => return Err(BodyLimitError::Unreadable),
        };
        if buffer.len() + data.len() > max {
            return Err(BodyLimitError::TooLarge(max));
        }
        buffer.extend_from_slice(&data);
    }
    Ok(buffer.freeze())
}

pub(crate) async fn collect_body_limited(body: Body, max: usize) -> Result<bytes::Bytes, Response> {
    collect_body_capped(body, max)
        .await
        .map_err(|err| match err {
            BodyLimitError::Unreadable => s3_error_response(S3Error::new(
                S3ErrorCode::InvalidRequest,
                "Failed to read request body",
            )),
            BodyLimitError::TooLarge(limit) => s3_error_response(S3Error::new(
                S3ErrorCode::MaxMessageLengthExceeded,
                format!(
                    "Your request was too big; this operation accepts at most {} bytes of request body",
                    limit
                ),
            )),
        })
}

pub(crate) const CANONICAL_DEFAULT_OWNER_ID: &str = "myfsio";

pub(super) fn canonical_default_owner(state: &AppState) -> (String, String) {
    let id = CANONICAL_DEFAULT_OWNER_ID.to_string();
    let display = state
        .iam
        .get_display_name(&id)
        .unwrap_or_else(|| id.clone());
    (id, display)
}

pub(super) fn build_owner_display_map(
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

pub(super) fn storage_err_response(err: myfsio_storage::error::StorageError) -> Response {
    if let myfsio_storage::error::StorageError::Io(io_err) = &err {
        if let Some(message) = crate::middleware::sha_body::sha256_mismatch_message(io_err) {
            return bad_digest_response(message);
        }
        if let Some(mismatch) = checksum_stream::upload_checksum_mismatch(io_err) {
            if mismatch.is_content_md5() {
                return bad_digest_response(mismatch.message());
            }
            return s3_error_response(S3Error::new(
                S3ErrorCode::InvalidRequest,
                mismatch.message(),
            ));
        }
        if let Some(violation) = checksum_stream::post_content_length_violation(io_err) {
            let code = if violation.too_large {
                S3ErrorCode::EntityTooLarge
            } else {
                S3ErrorCode::EntityTooSmall
            };
            return s3_error_response(S3Error::new(code, violation.to_string()));
        }
        if let Some(chunked_error) = chunked::aws_chunked_error(io_err) {
            return aws_chunked_error_response(chunked_error);
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

pub(super) fn error_chain_has_body_timeout(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = cur {
        if e.downcast_ref::<tower_http::timeout::TimeoutError>()
            .is_some()
        {
            return true;
        }
        cur = e.source();
    }
    false
}

pub(super) fn io_error_is_body_timeout(err: &std::io::Error) -> bool {
    error_chain_has_body_timeout(err)
}

pub(super) fn request_timeout_response() -> Response {
    tracing::warn!("request body timed out while streaming; returning RequestTimeout");
    s3_error_response(S3Error::from_code(S3ErrorCode::RequestTimeout))
}

pub(super) fn io_error_to_s3_response(err: &std::io::Error) -> Option<Response> {
    use std::io::ErrorKind;
    if io_error_is_body_timeout(err) {
        return Some(request_timeout_response());
    }
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

pub(super) fn trigger_replication(
    state: &AppState,
    bucket: &str,
    key: &str,
    action: &str,
    generation: Option<&str>,
) {
    let manager = state.replication.clone();
    let bucket = bucket.to_string();
    let key = key.to_string();
    let action = action.to_string();
    let generation = generation.map(ToOwned::to_owned);
    tokio::spawn(async move {
        manager.trigger(bucket, key, action, generation).await;
    });
}

pub(super) fn trigger_replication_for_request(
    state: &AppState,
    peer_marker: Option<&crate::middleware::ReplicationPeerRequest>,
    bucket: &str,
    key: &str,
    action: &str,
    generation: Option<&str>,
) {
    if peer_marker.is_some() {
        return;
    }
    trigger_replication(state, bucket, key, action, generation);
}

#[derive(Debug, Clone)]
pub struct RelayContext {
    pub origin_site_id: String,
    pub admin_user_id: String,
    pub idempotency_key: String,
    pub correlation_id: String,
}

pub(super) async fn ensure_object_lock_allows_write(
    state: &AppState,
    bucket: &str,
    key: &str,
    bypass_governance: bool,
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
    if let Err(message) = object_lock::can_delete_object(&metadata, bypass_governance) {
        return Err(s3_error_response(S3Error::new(
            S3ErrorCode::AccessDenied,
            message,
        )));
    }
    Ok(())
}

pub(super) async fn ensure_archived_null_lock_allows_overwrite(
    state: &AppState,
    bucket: &str,
    key: &str,
    bypass_governance: bool,
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
    if let Err(message) = object_lock::can_delete_object(&metadata, bypass_governance) {
        return Err(s3_error_response(S3Error::new(
            S3ErrorCode::AccessDenied,
            message,
        )));
    }
    Ok(())
}

pub(super) async fn ensure_object_version_lock_allows_delete(
    state: &AppState,
    bucket: &str,
    key: &str,
    version_id: &str,
    bypass_governance: bool,
) -> Result<(), Response> {
    let metadata = match state
        .storage
        .get_object_version_metadata(bucket, key, version_id)
        .await
    {
        Ok(metadata) => metadata,
        Err(err) => return Err(storage_err_response(err)),
    };
    if let Err(message) = object_lock::can_delete_object(&metadata, bypass_governance) {
        return Err(s3_error_response(S3Error::new(
            S3ErrorCode::AccessDenied,
            message,
        )));
    }
    Ok(())
}
