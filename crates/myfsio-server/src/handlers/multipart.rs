use super::*;
use futures::TryStreamExt;

pub(super) fn head_mpu_sse_c(
    meta: &myfsio_common::types::ObjectMeta,
    headers: &HeaderMap,
    query: &ObjectQuery,
) -> Response {
    if let Err(resp) = require_sse_c_key_match(headers, &meta.internal_metadata) {
        return resp;
    }

    let total = meta
        .internal_metadata
        .get(MPU_PLAINTEXT_SIZE)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);

    let mut h = HeaderMap::new();
    let mut parts_count: Option<u32> = None;
    let mut content_range: Option<String> = None;
    let content_len: u64;

    if let Some(pn) = query.part_number {
        let plain_sizes = meta
            .internal_metadata
            .get(MPU_PART_PLAIN_SIZES)
            .and_then(|r| myfsio_storage::fs_backend::parse_part_sizes(r));
        let part_numbers = meta
            .internal_metadata
            .get(MPU_PART_NUMBERS)
            .and_then(|r| parse_u32_csv(r));
        let (Some(plain_sizes), Some(part_numbers)) = (plain_sizes, part_numbers) else {
            return s3_error_response(S3Error::new(
                S3ErrorCode::InternalError,
                "SSE-C multipart object metadata is incomplete or inconsistent",
            ));
        };
        if plain_sizes.len() != part_numbers.len() {
            return s3_error_response(S3Error::new(
                S3ErrorCode::InternalError,
                "SSE-C multipart object metadata is incomplete or inconsistent",
            ));
        }
        let Some(idx) = part_numbers.iter().position(|x| *x == pn) else {
            return s3_error_response(S3Error::new(
                S3ErrorCode::InvalidPart,
                format!("partNumber {} does not exist for this object", pn),
            ));
        };
        parts_count = Some(part_numbers.len() as u32);
        let start: u64 = plain_sizes.iter().take(idx).sum();
        let len = plain_sizes[idx];
        content_len = len;
        if len > 0 {
            content_range = Some(format!("bytes {}-{}/{}", start, start + len - 1, total));
        }
    } else {
        content_len = total;
    }

    h.insert("content-length", content_len.to_string().parse().unwrap());
    if let Some(cr) = content_range {
        if let Ok(value) = cr.parse() {
            h.insert("content-range", value);
        }
    }
    if let Some(ref etag) = meta.etag {
        h.insert("etag", format!("\"{}\"", etag).parse().unwrap());
    }
    insert_content_type(&mut h, &meta.key, meta.content_type.as_deref());
    h.insert(
        "last-modified",
        meta.last_modified
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string()
            .parse()
            .unwrap(),
    );
    h.insert("accept-ranges", "bytes".parse().unwrap());
    apply_sse_c_response_headers(&mut h, &meta.internal_metadata);
    apply_stored_response_headers(&mut h, &meta.internal_metadata);
    if query.part_number.is_none() && checksum_mode_enabled(headers) {
        apply_stored_checksum_headers(&mut h, &meta.internal_metadata);
    }
    if let Some(ref requested_version) = query.version_id {
        if let Ok(value) = requested_version.parse() {
            h.insert("x-amz-version-id", value);
        }
    } else if let Some(ref vid) = meta.version_id {
        if let Ok(value) = vid.parse() {
            h.insert("x-amz-version-id", value);
        }
    }
    apply_user_metadata(&mut h, &meta.metadata);
    if let Some(count) = parts_count {
        h.insert("x-amz-mp-parts-count", count.to_string().parse().unwrap());
    }

    let status = if query.part_number.is_some() {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };
    (status, h).into_response()
}

pub(super) struct PartView {
    pub(super) start: u64,
    pub(super) length: u64,
    pub(super) parts_count: u32,
    pub(super) multipart: bool,
}

pub(super) fn build_part_response_headers(
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
        if let Some(ref kid) = enc_info.kms_key_id {
            if let Ok(value) = kid.parse() {
                headers.insert("x-amz-server-side-encryption-aws-kms-key-id", value);
            }
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

pub(super) fn resolve_part_view(
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

use myfsio_common::constants::{
    MPU_SSE_C_MARKER, MULTIPART_PENDING_SSE_ALG, MULTIPART_PENDING_SSE_C_KEY,
    MULTIPART_PENDING_SSE_KMS_KEY,
};

pub(super) const MPU_WRAPPED_ODK: &str = "__mpu_wrapped_odk__";

pub(super) const MPU_CHUNK_SIZE: &str = "__mpu_chunk_size__";

pub(super) const MPU_PART_NUMBERS: &str = "__mpu_part_numbers__";

pub(super) const MPU_PART_PLAIN_SIZES: &str = "__mpu_part_plain_sizes__";

pub(super) const MPU_PLAINTEXT_SIZE: &str = "__mpu_plaintext_size__";

pub(super) const SSE_C_ALGORITHM_HEADER: &str = "x-amz-server-side-encryption-customer-algorithm";

pub(super) const SSE_C_KEY_MD5_HEADER: &str = "x-amz-server-side-encryption-customer-key-MD5";

pub(super) fn mpu_is_sse_c(metadata: &HashMap<String, String>) -> bool {
    metadata
        .get(MPU_SSE_C_MARKER)
        .map(|v| v == "true")
        .unwrap_or(false)
}

pub(super) fn parse_u32_csv(raw: &str) -> Option<Vec<u32>> {
    let mut out = Vec::new();
    for tok in raw.split(',') {
        let tok = tok.trim();
        if tok.is_empty() {
            return None;
        }
        out.push(tok.parse::<u32>().ok()?);
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

pub(super) fn apply_sse_c_response_headers(
    headers: &mut HeaderMap,
    metadata: &HashMap<String, String>,
) {
    if let Ok(value) = "AES256".parse() {
        headers.insert(SSE_C_ALGORITHM_HEADER, value);
    }
    if let Some(md5) = metadata.get(SSE_C_KEY_MD5_META) {
        if let Ok(value) = md5.parse() {
            headers.insert(SSE_C_KEY_MD5_HEADER, value);
        }
    }
}

pub(super) async fn initiate_multipart_handler(
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
    if let Err(response) = validate_kms_key_usable(state, resolved_enc_ctx.as_ref()).await {
        return response;
    }
    if let Some(ref ctx) = resolved_enc_ctx {
        if ctx.algorithm == myfsio_crypto::encryption::SseAlgorithm::CustomerProvided {
            let Some(ck) = ctx.customer_key.as_ref() else {
                return s3_error_response(S3Error::from_code(S3ErrorCode::InternalError));
            };
            let Some(enc_svc) = state.encryption.as_ref() else {
                return s3_error_response(S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    "Server-side encryption is not enabled on this server",
                ));
            };
            if ck.len() != 32 {
                return s3_error_response(S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    "SSE-C customer key must decode to 32 bytes",
                ));
            }
            let mut ck_arr = [0u8; 32];
            ck_arr.copy_from_slice(ck);
            let odk = enc_svc.generate_odk();
            let wrapped = match myfsio_crypto::encryption::wrap_key_with(&ck_arr, &odk) {
                Ok(w) => w,
                Err(_) => return s3_error_response(S3Error::from_code(S3ErrorCode::InternalError)),
            };
            metadata.insert(MPU_SSE_C_MARKER.to_string(), "true".to_string());
            metadata.insert(MPU_WRAPPED_ODK.to_string(), wrapped);
            metadata.insert(
                MPU_CHUNK_SIZE.to_string(),
                state.config.encryption_chunk_size_bytes.to_string(),
            );
            metadata.insert(SSE_C_KEY_MD5_META.to_string(), sse_c_key_md5(ck));
            metadata.insert(
                "x-amz-server-side-encryption".to_string(),
                "AES256".to_string(),
            );
        } else {
            metadata.insert(
                MULTIPART_PENDING_SSE_ALG.to_string(),
                ctx.algorithm.as_str().to_string(),
            );
            if let Some(ref kid) = ctx.kms_key_id {
                metadata.insert(MULTIPART_PENDING_SSE_KMS_KEY.to_string(), kid.clone());
            }
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
                if ctx.algorithm == myfsio_crypto::encryption::SseAlgorithm::CustomerProvided {
                    if let Ok(value) = "AES256".parse() {
                        headers.insert(SSE_C_ALGORITHM_HEADER, value);
                    }
                    if let Some(ref ck) = ctx.customer_key {
                        if let Ok(value) = sse_c_key_md5(ck).parse() {
                            headers.insert(SSE_C_KEY_MD5_HEADER, value);
                        }
                    }
                } else {
                    if let Ok(alg) = ctx.algorithm.as_str().parse() {
                        headers.insert("x-amz-server-side-encryption", alg);
                    }
                    if let Some(ref kid) = ctx.kms_key_id {
                        if let Ok(value) = kid.parse() {
                            headers.insert("x-amz-server-side-encryption-aws-kms-key-id", value);
                        }
                    }
                }
            }
            (StatusCode::OK, headers, xml).into_response()
        }
        Err(e) => storage_err_response(e),
    }
}

pub(super) fn pending_multipart_sse_context(
    metadata: &HashMap<String, String>,
) -> Option<myfsio_crypto::encryption::EncryptionContext> {
    let alg = metadata.get(MULTIPART_PENDING_SSE_ALG)?.clone();
    let kms_key_id = metadata.get(MULTIPART_PENDING_SSE_KMS_KEY).cloned();
    let customer_key = metadata.get(MULTIPART_PENDING_SSE_C_KEY).and_then(|s| {
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
    Some(myfsio_crypto::encryption::EncryptionContext {
        algorithm,
        kms_key_id,
        customer_key,
    })
}

pub(super) fn apply_pending_mpu_sse_headers(
    headers: &mut HeaderMap,
    pending: &HashMap<String, String>,
) {
    if let Some(alg) = pending.get(MULTIPART_PENDING_SSE_ALG) {
        if let Ok(value) = alg.parse() {
            headers.insert("x-amz-server-side-encryption", value);
        }
        if let Some(kid) = pending.get(MULTIPART_PENDING_SSE_KMS_KEY) {
            if let Ok(value) = kid.parse() {
                headers.insert("x-amz-server-side-encryption-aws-kms-key-id", value);
            }
        }
    }
}

pub(super) async fn upload_part_handler_with_chunking(
    state: &AppState,
    bucket: &str,
    upload_id: &str,
    part_number: u32,
    headers: &HeaderMap,
    body: Body,
    aws_chunked: bool,
    streaming_sigv4: Option<crate::middleware::StreamingSigV4Context>,
) -> Response {
    let pending = match state
        .storage
        .get_multipart_metadata(bucket, upload_id)
        .await
    {
        Ok(m) => m,
        Err(e) => return storage_err_response(e),
    };

    if mpu_is_sse_c(&pending) {
        return upload_part_sse_c(
            state,
            bucket,
            upload_id,
            part_number,
            headers,
            body,
            aws_chunked,
            &pending,
            streaming_sigv4,
        )
        .await;
    }

    let _disk_permit = match acquire_disk_write_permit(state).await {
        Ok(permit) => permit,
        Err(response) => return response,
    };
    let raw: myfsio_storage::traits::AsyncReadStream = if aws_chunked {
        match decode_aws_chunked_body(
            body,
            headers,
            streaming_sigv4,
            state.config.strict_streaming_sigv4,
        ) {
            Ok(stream) => stream,
            Err(response) => return response,
        }
    } else {
        let stream = tokio_util::io::StreamReader::new(
            body.into_data_stream().map_err(std::io::Error::other),
        );
        Box::pin(stream)
    };
    let raw = match apply_upload_checksum_verification(
        enforce_declared_length(raw, declared_body_length(headers, aws_chunked)),
        headers,
    ) {
        Ok(stream) => stream,
        Err(response) => return response,
    };
    let boxed = spool_upload_stream(
        raw,
        state.config.upload_stream_buffer_bytes,
        state.config.stream_chunk_size,
        state.disk_limiter.spool_gauge(),
    );

    match state
        .storage
        .upload_part(bucket, upload_id, part_number, boxed)
        .await
    {
        Ok(etag) => {
            let mut headers = HeaderMap::new();
            headers.insert("etag", format!("\"{}\"", etag).parse().unwrap());
            apply_pending_mpu_sse_headers(&mut headers, &pending);
            (StatusCode::OK, headers).into_response()
        }
        Err(e) => storage_err_response(e),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn upload_part_sse_c(
    state: &AppState,
    bucket: &str,
    upload_id: &str,
    part_number: u32,
    headers: &HeaderMap,
    body: Body,
    aws_chunked: bool,
    pending: &HashMap<String, String>,
    streaming_sigv4: Option<crate::middleware::StreamingSigV4Context>,
) -> Response {
    let Some(enc_svc) = state.encryption.as_ref() else {
        return s3_error_response(S3Error::new(
            S3ErrorCode::InternalError,
            "Object is encrypted but encryption service is disabled",
        ));
    };

    let customer_key = match extract_sse_c_key(headers) {
        Ok(Some(k)) => k,
        Ok(None) => {
            return s3_error_response(S3Error::new(
                S3ErrorCode::InvalidRequest,
                "This multipart upload uses SSE-C; the SSE-C customer key headers are required on each part",
            ))
        }
        Err(resp) => return resp,
    };

    if let Some(stored_md5) = pending.get(SSE_C_KEY_MD5_META) {
        if !constant_time_eq(
            sse_c_key_md5(&customer_key).as_bytes(),
            stored_md5.as_bytes(),
        ) {
            return s3_error_response(S3Error::new(
                S3ErrorCode::AccessDenied,
                "The SSE-C customer key does not match the key used to initiate this upload",
            ));
        }
    }

    let Some(wrapped_odk) = pending.get(MPU_WRAPPED_ODK) else {
        return s3_error_response(S3Error::new(
            S3ErrorCode::InternalError,
            "Multipart upload is missing its wrapped data key",
        ));
    };

    let mut ck_arr = [0u8; 32];
    ck_arr.copy_from_slice(&customer_key);
    let odk = match myfsio_crypto::encryption::unwrap_key_with(&ck_arr, wrapped_odk) {
        Ok(k) => k,
        Err(_) => {
            return s3_error_response(S3Error::new(
                S3ErrorCode::AccessDenied,
                "The SSE-C customer key does not match the key used to initiate this upload",
            ))
        }
    };

    let chunk_size = pending
        .get(MPU_CHUNK_SIZE)
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(state.config.encryption_chunk_size_bytes);

    let tmp_dir = state.config.storage_root.join(".myfsio.sys").join("tmp");
    let _ = tokio::fs::create_dir_all(&tmp_dir).await;
    let plain_tmp = tmp_dir.join(format!("mpu-plain-{}", uuid::Uuid::new_v4()));
    let block_tmp = tmp_dir.join(format!("mpu-block-{}", uuid::Uuid::new_v4()));

    let _disk_permit = match acquire_disk_write_permit(state).await {
        Ok(permit) => permit,
        Err(response) => return response,
    };
    let raw: myfsio_storage::traits::AsyncReadStream = if aws_chunked {
        match decode_aws_chunked_body(
            body,
            headers,
            streaming_sigv4,
            state.config.strict_streaming_sigv4,
        ) {
            Ok(stream) => stream,
            Err(response) => return response,
        }
    } else {
        Box::pin(tokio_util::io::StreamReader::new(
            body.into_data_stream().map_err(std::io::Error::other),
        ))
    };
    let raw = match apply_upload_checksum_verification(
        enforce_declared_length(raw, declared_body_length(headers, aws_chunked)),
        headers,
    ) {
        Ok(stream) => stream,
        Err(response) => return response,
    };
    let boxed = spool_upload_stream(
        raw,
        state.config.upload_stream_buffer_bytes,
        state.config.stream_chunk_size,
        state.disk_limiter.spool_gauge(),
    );

    if let Err(resp) = drain_stream_to_file(boxed, &plain_tmp).await {
        let _ = tokio::fs::remove_file(&plain_tmp).await;
        return resp;
    }

    if let Err(e) = enc_svc
        .encrypt_mpu_part(&plain_tmp, &block_tmp, odk, part_number, chunk_size)
        .await
    {
        let _ = tokio::fs::remove_file(&plain_tmp).await;
        let _ = tokio::fs::remove_file(&block_tmp).await;
        return s3_error_response(S3Error::new(
            S3ErrorCode::InternalError,
            format!("Failed to encrypt multipart part: {}", e),
        ));
    }
    let _ = tokio::fs::remove_file(&plain_tmp).await;

    let block_file = match tokio::fs::File::open(&block_tmp).await {
        Ok(f) => f,
        Err(e) => {
            let _ = tokio::fs::remove_file(&block_tmp).await;
            return storage_err_response(myfsio_storage::error::StorageError::Io(e));
        }
    };
    let boxed_block: myfsio_storage::traits::AsyncReadStream = Box::pin(block_file);

    let result = state
        .storage
        .upload_part(bucket, upload_id, part_number, boxed_block)
        .await;
    let _ = tokio::fs::remove_file(&block_tmp).await;

    match result {
        Ok(etag) => {
            let mut resp_headers = HeaderMap::new();
            resp_headers.insert("etag", format!("\"{}\"", etag).parse().unwrap());
            apply_sse_c_response_headers(&mut resp_headers, pending);
            (StatusCode::OK, resp_headers).into_response()
        }
        Err(e) => storage_err_response(e),
    }
}

pub(super) struct SpoolTracker {
    gauge: std::sync::Arc<std::sync::atomic::AtomicU64>,
    outstanding: std::sync::atomic::AtomicU64,
}

impl SpoolTracker {
    fn record_buffered(&self, n: u64) {
        use std::sync::atomic::Ordering;
        self.outstanding.fetch_add(n, Ordering::Relaxed);
        self.gauge.fetch_add(n, Ordering::Relaxed);
    }

    fn record_consumed(&self, n: u64) {
        use std::sync::atomic::Ordering;
        self.outstanding.fetch_sub(n, Ordering::Relaxed);
        self.gauge.fetch_sub(n, Ordering::Relaxed);
    }
}

impl Drop for SpoolTracker {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;
        let remaining = self.outstanding.load(Ordering::Relaxed);
        if remaining > 0 {
            self.gauge.fetch_sub(remaining, Ordering::Relaxed);
        }
    }
}

pub(super) fn spool_upload_stream(
    stream: myfsio_storage::traits::AsyncReadStream,
    buffer_bytes: usize,
    chunk_size: usize,
    gauge: std::sync::Arc<std::sync::atomic::AtomicU64>,
) -> myfsio_storage::traits::AsyncReadStream {
    if buffer_bytes == 0 {
        return stream;
    }
    let chunk_size = chunk_size.clamp(64 * 1024, buffer_bytes.max(64 * 1024));
    let capacity = (buffer_bytes / chunk_size).max(1);
    let (tx, rx) = tokio::sync::mpsc::channel::<std::io::Result<bytes::Bytes>>(capacity);
    let tracker = std::sync::Arc::new(SpoolTracker {
        gauge,
        outstanding: std::sync::atomic::AtomicU64::new(0),
    });
    let producer_tracker = tracker.clone();
    tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut stream = stream;
        let mut buf = vec![0u8; chunk_size];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    producer_tracker.record_buffered(n as u64);
                    if tx
                        .send(Ok(bytes::Bytes::copy_from_slice(&buf[..n])))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                    break;
                }
            }
        }
    });
    use futures::StreamExt;
    let consumer_stream = tokio_stream::wrappers::ReceiverStream::new(rx).map(
        move |item: std::io::Result<bytes::Bytes>| {
            if let Ok(ref chunk) = item {
                tracker.record_consumed(chunk.len() as u64);
            }
            item
        },
    );
    Box::pin(tokio_util::io::StreamReader::new(consumer_stream))
}

pub(super) struct PermitReader {
    inner: myfsio_storage::traits::AsyncReadStream,
    _permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl tokio::io::AsyncRead for PermitReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

pub(super) fn attach_read_permit(
    reader: myfsio_storage::traits::AsyncReadStream,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
) -> myfsio_storage::traits::AsyncReadStream {
    match permit {
        Some(_) => Box::pin(PermitReader {
            inner: reader,
            _permit: permit,
        }),
        None => reader,
    }
}

pub(super) fn slow_down_response() -> Response {
    s3_error_response(S3Error::new(
        S3ErrorCode::SlowDown,
        "Storage is busy; reduce your request rate and retry",
    ))
}

pub(super) async fn acquire_disk_read_permit(
    state: &AppState,
) -> Result<Option<tokio::sync::OwnedSemaphorePermit>, Response> {
    state
        .disk_limiter
        .acquire_read()
        .await
        .map_err(|_| slow_down_response())
}

pub(super) async fn acquire_disk_write_permit(
    state: &AppState,
) -> Result<Option<tokio::sync::OwnedSemaphorePermit>, Response> {
    state
        .disk_limiter
        .acquire_write()
        .await
        .map_err(|_| slow_down_response())
}

pub(super) async fn drain_stream_to_file(
    mut stream: myfsio_storage::traits::AsyncReadStream,
    path: &std::path::Path,
) -> Result<u64, Response> {
    let mut file = match tokio::fs::File::create(path).await {
        Ok(f) => f,
        Err(e) => {
            return Err(storage_err_response(
                myfsio_storage::error::StorageError::Io(e),
            ))
        }
    };
    let copied = tokio::io::copy(&mut stream, &mut file)
        .await
        .map_err(|e| storage_err_response(myfsio_storage::error::StorageError::Io(e)))?;
    Ok(copied)
}

pub(super) async fn upload_part_copy_handler(
    state: &AppState,
    dst_bucket: &str,
    upload_id: &str,
    part_number: u32,
    copy_source: &str,
    range_header: Option<&str>,
    headers: &HeaderMap,
) -> Response {
    let pending = match state
        .storage
        .get_multipart_metadata(dst_bucket, upload_id)
        .await
    {
        Ok(pending) => {
            if mpu_is_sse_c(&pending) {
                return s3_error_response(S3Error::new(
                    S3ErrorCode::NotImplemented,
                    "UploadPartCopy is not supported for SSE-C multipart uploads; upload the part bytes directly with UploadPart instead",
                ));
            }
            pending
        }
        Err(e) => return storage_err_response(e),
    };

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

    if myfsio_crypto::encryption::EncryptionMetadata::is_encrypted(&source_meta.internal_metadata) {
        return upload_part_copy_from_encrypted_source(
            state,
            dst_bucket,
            upload_id,
            part_number,
            &src_bucket,
            &src_key,
            src_version_id.as_deref(),
            range,
            headers,
            &pending,
        )
        .await;
    }

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
            let mut resp_headers = HeaderMap::new();
            resp_headers.insert("content-type", "application/xml".parse().unwrap());
            apply_pending_mpu_sse_headers(&mut resp_headers, &pending);
            (StatusCode::OK, resp_headers, xml).into_response()
        }
        Err(e) => storage_err_response(e),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn upload_part_copy_from_encrypted_source(
    state: &AppState,
    dst_bucket: &str,
    upload_id: &str,
    part_number: u32,
    src_bucket: &str,
    src_key: &str,
    src_version_id: Option<&str>,
    range: Option<(u64, u64)>,
    headers: &HeaderMap,
    pending: &HashMap<String, String>,
) -> Response {
    let tmp_dir = state.config.storage_root.join(".myfsio.sys").join("tmp");
    if let Err(e) = tokio::fs::create_dir_all(&tmp_dir).await {
        return storage_err_response(myfsio_storage::error::StorageError::Io(e));
    }

    let src_snap = tmp_dir.join(format!("upc-src-{}", uuid::Uuid::new_v4()));
    let snapshot = match src_version_id {
        Some(version_id) => {
            state
                .storage
                .snapshot_object_version_to_link(src_bucket, src_key, version_id, &src_snap)
                .await
        }
        None => {
            state
                .storage
                .snapshot_object_to_link(src_bucket, src_key, &src_snap)
                .await
        }
    };
    let (snap_meta, snap_source) = match snapshot {
        Ok(pair) => pair,
        Err(e) => {
            let _ = tokio::fs::remove_file(&src_snap).await;
            return storage_err_response(e);
        }
    };

    let ciphertext_path = match snap_source {
        myfsio_storage::traits::SnapshotSource::LinkedFile(_) => src_snap.clone(),
        segments => {
            let dest = tmp_dir.join(format!("upc-mat-{}", uuid::Uuid::new_v4()));
            let materialized = async {
                let mut reader = segments
                    .into_range_stream(0, None)
                    .await
                    .map_err(myfsio_storage::error::StorageError::Io)?;
                let mut out = tokio::fs::File::create(&dest)
                    .await
                    .map_err(myfsio_storage::error::StorageError::Io)?;
                tokio::io::copy(&mut reader, &mut out)
                    .await
                    .map_err(myfsio_storage::error::StorageError::Io)?;
                Ok::<(), myfsio_storage::error::StorageError>(())
            }
            .await;
            let _ = tokio::fs::remove_file(&src_snap).await;
            if let Err(e) = materialized {
                let _ = tokio::fs::remove_file(&dest).await;
                return storage_err_response(e);
            }
            dest
        }
    };

    let Some(enc_info) =
        myfsio_crypto::encryption::EncryptionMetadata::from_metadata(&snap_meta.internal_metadata)
    else {
        let _ = tokio::fs::remove_file(&ciphertext_path).await;
        return s3_error_response(S3Error::new(
            S3ErrorCode::InternalError,
            "Source object is marked encrypted but carries no encryption metadata",
        ));
    };
    let Some(enc_svc) = state.encryption.as_ref() else {
        let _ = tokio::fs::remove_file(&ciphertext_path).await;
        return s3_error_response(S3Error::new(
            S3ErrorCode::InternalError,
            "Source object is encrypted but encryption service is disabled",
        ));
    };
    let customer_key = match resolve_copy_source_sse_c_key(headers, &snap_meta.internal_metadata) {
        Ok(key) => key,
        Err(response) => {
            let _ = tokio::fs::remove_file(&ciphertext_path).await;
            return response;
        }
    };

    let plaintext_path = tmp_dir.join(format!("upc-dec-{}", uuid::Uuid::new_v4()));
    let decrypted = enc_svc
        .decrypt_object(
            &ciphertext_path,
            &plaintext_path,
            &enc_info,
            customer_key.as_deref(),
        )
        .await;
    let _ = tokio::fs::remove_file(&ciphertext_path).await;
    if let Err(e) = decrypted {
        let _ = tokio::fs::remove_file(&plaintext_path).await;
        return s3_error_response(S3Error::new(
            S3ErrorCode::InternalError,
            format!("Source decryption failed: {}", e),
        ));
    }

    let plaintext_size = match tokio::fs::metadata(&plaintext_path).await {
        Ok(m) => m.len(),
        Err(e) => {
            let _ = tokio::fs::remove_file(&plaintext_path).await;
            return storage_err_response(myfsio_storage::error::StorageError::Io(e));
        }
    };
    let (start, length) = match range {
        Some((s, e)) => {
            if s >= plaintext_size || e >= plaintext_size || s > e {
                let _ = tokio::fs::remove_file(&plaintext_path).await;
                return storage_err_response(myfsio_storage::error::StorageError::InvalidRange);
            }
            (s, e - s + 1)
        }
        None => (0, plaintext_size),
    };

    let mut file = match open_self_deleting(plaintext_path.clone()).await {
        Ok(file) => file,
        Err(e) => {
            let _ = tokio::fs::remove_file(&plaintext_path).await;
            return storage_err_response(myfsio_storage::error::StorageError::Io(e));
        }
    };
    if start > 0 {
        if let Err(e) =
            tokio::io::AsyncSeekExt::seek(&mut file, std::io::SeekFrom::Start(start)).await
        {
            return storage_err_response(myfsio_storage::error::StorageError::Io(e));
        }
    }
    let stream: myfsio_storage::traits::AsyncReadStream =
        Box::pin(tokio::io::AsyncReadExt::take(file, length));

    match state
        .storage
        .upload_part(dst_bucket, upload_id, part_number, stream)
        .await
    {
        Ok(etag) => {
            let lm = myfsio_xml::response::format_s3_datetime(&chrono::Utc::now());
            let xml = myfsio_xml::response::copy_part_result_xml(&etag, &lm);
            let mut resp_headers = HeaderMap::new();
            resp_headers.insert("content-type", "application/xml".parse().unwrap());
            apply_pending_mpu_sse_headers(&mut resp_headers, pending);
            (StatusCode::OK, resp_headers, xml).into_response()
        }
        Err(e) => storage_err_response(e),
    }
}

pub(super) fn parse_copy_source_range(value: &str) -> Option<(u64, u64)> {
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

#[cfg(feature = "failpoints")]
pub(super) fn mpu_failpoint(
    state: &AppState,
    name: &str,
) -> Result<(), myfsio_storage::error::StorageError> {
    myfsio_storage::failpoints::hit(&state.config.storage_root, name)
        .map_err(myfsio_storage::error::StorageError::Io)
}

#[cfg(not(feature = "failpoints"))]
pub(super) fn mpu_failpoint(
    _state: &AppState,
    _name: &str,
) -> Result<(), myfsio_storage::error::StorageError> {
    Ok(())
}

pub(super) async fn complete_pending_sse_multipart(
    state: &AppState,
    bucket: &str,
    upload_id: &str,
    parts: &[PartInfo],
    enc_ctx: &myfsio_crypto::encryption::EncryptionContext,
    mut options: myfsio_storage::traits::PutCommitOptions,
) -> Result<(myfsio_common::types::ObjectMeta, u64), Response> {
    let Some(enc_svc) = state.encryption.as_ref() else {
        return Err(s3_error_response(S3Error::new(
            S3ErrorCode::InternalError,
            "Encryption requested for multipart upload but encryption service is disabled",
        )));
    };
    let prepared = state
        .storage
        .prepare_multipart_for_transform(bucket, upload_id, parts)
        .await
        .map_err(storage_err_response)?;
    let plaintext_size = prepared.plaintext_size;
    if let Err(error) = mpu_failpoint(state, "mpu:before-encryption") {
        let _ = tokio::fs::remove_file(&prepared.plaintext_path).await;
        return Err(storage_err_response(error));
    }
    let ciphertext_path = match state.storage.allocate_prepared_tmp_path() {
        Ok(path) => path,
        Err(error) => {
            let _ = tokio::fs::remove_file(&prepared.plaintext_path).await;
            return Err(storage_err_response(error));
        }
    };
    if let Err(error) = tokio::fs::File::create(&ciphertext_path).await {
        let _ = tokio::fs::remove_file(&prepared.plaintext_path).await;
        return Err(storage_err_response(
            myfsio_storage::error::StorageError::Io(error),
        ));
    }
    if let Err(error) = mpu_failpoint(state, "mpu:during-encryption") {
        let _ = tokio::fs::remove_file(&prepared.plaintext_path).await;
        let _ = tokio::fs::remove_file(&ciphertext_path).await;
        return Err(storage_err_response(error));
    }
    let enc_meta = match enc_svc
        .encrypt_object(&prepared.plaintext_path, &ciphertext_path, enc_ctx)
        .await
    {
        Ok(metadata) => metadata,
        Err(error) => {
            let _ = tokio::fs::remove_file(&prepared.plaintext_path).await;
            let _ = tokio::fs::remove_file(&ciphertext_path).await;
            return Err(encryption_failure_response(error));
        }
    };
    if let Err(error) = mpu_failpoint(state, "mpu:after-encryption") {
        let _ = tokio::fs::remove_file(&prepared.plaintext_path).await;
        let _ = tokio::fs::remove_file(&ciphertext_path).await;
        return Err(storage_err_response(error));
    }
    let ciphertext_size = match tokio::fs::metadata(&ciphertext_path).await {
        Ok(metadata) => metadata.len(),
        Err(error) => {
            let _ = tokio::fs::remove_file(&prepared.plaintext_path).await;
            let _ = tokio::fs::remove_file(&ciphertext_path).await;
            return Err(storage_err_response(
                myfsio_storage::error::StorageError::Io(error),
            ));
        }
    };
    let mut final_metadata = prepared.metadata.clone();
    final_metadata.remove(MULTIPART_PENDING_SSE_ALG);
    final_metadata.remove(MULTIPART_PENDING_SSE_KMS_KEY);
    final_metadata.remove(MULTIPART_PENDING_SSE_C_KEY);
    final_metadata.remove(myfsio_storage::segments::META_KEY_SEGMENTS);
    for (key, value) in enc_meta.to_metadata_map() {
        final_metadata.insert(key, value);
    }
    if let Some(raw) = final_metadata.remove("__pending_tagging__") {
        match parse_tagging_header(&raw) {
            Ok(tags) if tags.len() <= state.config.object_tag_limit => options.tags = Some(tags),
            Ok(_) => tracing::warn!(
                bucket = bucket,
                key = prepared.object_key,
                "skipping multipart tagging: exceeds object_tag_limit"
            ),
            Err(_) => tracing::warn!(
                bucket = bucket,
                key = prepared.object_key,
                "discarding malformed __pending_tagging__ value from multipart manifest"
            ),
        }
    }
    if let Some(ref customer_key) = enc_ctx.customer_key {
        final_metadata.insert(SSE_C_KEY_MD5_META.to_string(), sse_c_key_md5(customer_key));
    }
    object_lock::apply_default_retention(state, bucket, &mut final_metadata).await;
    let commit = state
        .storage
        .commit_transformed_multipart(
            &prepared,
            &ciphertext_path,
            ciphertext_size,
            final_metadata,
            options,
        )
        .await;
    let _ = tokio::fs::remove_file(&prepared.plaintext_path).await;
    if commit.is_err() {
        let _ = tokio::fs::remove_file(&ciphertext_path).await;
    }
    commit
        .map(|metadata| (metadata, plaintext_size))
        .map_err(storage_err_response)
}

pub(super) async fn complete_multipart_handler(
    state: &AppState,
    bucket: &str,
    key: &str,
    upload_id: &str,
    peer_marker: Option<&crate::middleware::ReplicationPeerRequest>,
    principal: Option<&myfsio_common::types::Principal>,
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

    let bypass_governance =
        governance_bypass_allowed(state, principal, bucket, Some(key), headers).await;
    if let Err(response) =
        ensure_archived_null_lock_allows_overwrite(state, bucket, key, bypass_governance).await
    {
        return response;
    }

    let body_bytes = match collect_body_limited(body, BULK_XML_BODY_LIMIT).await {
        Ok(bytes) => bytes,
        Err(response) => return response,
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

    let pending_manifest = match state
        .storage
        .get_multipart_metadata(bucket, upload_id)
        .await
    {
        Ok(metadata) => metadata,
        Err(error) => return storage_err_response(error),
    };
    let sse_c_enc_svc = if mpu_is_sse_c(&pending_manifest) {
        match state.encryption.as_ref() {
            Some(svc) => Some(svc),
            None => {
                return s3_error_response(S3Error::new(
                    S3ErrorCode::InternalError,
                    "Object is encrypted but encryption service is disabled",
                ));
            }
        }
    } else {
        None
    };

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
        if !is_final {
            let effective_size = match sse_c_enc_svc {
                Some(enc_svc) => {
                    let part_path = match state
                        .storage
                        .get_multipart_part_path(bucket, upload_id, p.part_number)
                        .await
                    {
                        Ok(path) => path,
                        Err(e) => return storage_err_response(e),
                    };
                    match enc_svc.read_mpu_part_plain_sizes(&part_path, vec![0]).await {
                        Ok(sizes) => sizes.first().copied().unwrap_or(stored.1),
                        Err(e) => {
                            return s3_error_response(S3Error::new(
                                S3ErrorCode::InternalError,
                                format!("Failed to read SSE-C part size: {}", e),
                            ));
                        }
                    }
                }
                None => stored.1,
            };
            if effective_size < min_part_size {
                return s3_error_response(S3Error::new(
                    S3ErrorCode::EntityTooSmall,
                    format!(
                        "Part {} is smaller than the minimum allowed size of {} bytes",
                        p.part_number, min_part_size
                    ),
                ));
            }
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

    let _disk_permit = match acquire_disk_write_permit(state).await {
        Ok(permit) => permit,
        Err(response) => return response,
    };
    let commit_options = myfsio_storage::traits::PutCommitOptions {
        etag_override: None,
        conditions: put_conditions_from_headers(headers),
        bypass_governance,
        tags: None,
    };
    let pending_sse = pending_multipart_sse_context(&pending_manifest);
    if pending_manifest.contains_key(MULTIPART_PENDING_SSE_ALG) && pending_sse.is_none() {
        return s3_error_response(S3Error::new(
            S3ErrorCode::InternalError,
            "Multipart upload carries invalid pending encryption metadata",
        ));
    }
    let completion = match pending_sse.as_ref() {
        Some(enc_ctx) => {
            complete_pending_sse_multipart(
                state,
                bucket,
                upload_id,
                &parts,
                enc_ctx,
                commit_options,
            )
            .await
        }
        None => state
            .storage
            .complete_multipart_checked(bucket, upload_id, &parts, commit_options)
            .await
            .map(|metadata| {
                let size = metadata.size;
                (metadata, size)
            })
            .map_err(storage_err_response),
    };
    let (meta, notification_size) = match completion {
        Ok(result) => result,
        Err(response) => return response,
    };
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

    let mut sse_c_md5_response: Option<String> = None;
    if pending_sse.is_none() {
        let post_complete_meta = state
            .storage
            .get_object_metadata(bucket, key)
            .await
            .unwrap_or_default();
        if mpu_is_sse_c(&post_complete_meta) {
            match finalize_mpu_sse_c_metadata(state, bucket, key, &parts, post_complete_meta).await
            {
                Ok(md5) => sse_c_md5_response = md5,
                Err(resp) => {
                    let _ = state.storage.delete_object(bucket, key).await;
                    return resp;
                }
            }
        }
        object_lock::apply_default_retention_to_stored(state, bucket, key).await;
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
        notification_size,
        Some(etag),
        "",
        "",
        "",
        "CompleteMultipartUpload",
    );
    trigger_replication_for_request(state, peer_marker, bucket, key, "write", None);
    let mut resp_headers = HeaderMap::new();
    resp_headers.insert("content-type", "application/xml".parse().unwrap());
    if let Some(ref vid) = meta.version_id {
        if let Ok(value) = vid.parse() {
            resp_headers.insert("x-amz-version-id", value);
        }
    }
    if let Some(enc_ctx) = pending_sse {
        if let Ok(value) = enc_ctx.algorithm.as_str().parse() {
            resp_headers.insert("x-amz-server-side-encryption", value);
        }
        if let Some(kid) = enc_ctx.kms_key_id {
            if let Ok(value) = kid.parse() {
                resp_headers.insert("x-amz-server-side-encryption-aws-kms-key-id", value);
            }
        }
    }
    if let Some(md5) = sse_c_md5_response {
        if let Ok(value) = "AES256".parse() {
            resp_headers.insert(SSE_C_ALGORITHM_HEADER, value);
        }
        if let Ok(value) = md5.parse() {
            resp_headers.insert(SSE_C_KEY_MD5_HEADER, value);
        }
    }
    (StatusCode::OK, resp_headers, xml).into_response()
}

pub(super) async fn finalize_mpu_sse_c_metadata(
    state: &AppState,
    bucket: &str,
    key: &str,
    parts: &[PartInfo],
    mut all_meta: HashMap<String, String>,
) -> Result<Option<String>, Response> {
    let Some(enc_svc) = state.encryption.as_ref() else {
        return Err(s3_error_response(S3Error::new(
            S3ErrorCode::InternalError,
            "Object is encrypted but encryption service is disabled",
        )));
    };

    let part_sizes = match all_meta
        .get(myfsio_storage::fs_backend::META_KEY_PART_SIZES)
        .and_then(|raw| myfsio_storage::fs_backend::parse_part_sizes(raw))
    {
        Some(sizes) => sizes,
        None => {
            return Err(s3_error_response(S3Error::new(
                S3ErrorCode::InternalError,
                "Multipart object is missing its part-size manifest",
            )))
        }
    };
    if part_sizes.len() != parts.len() {
        return Err(s3_error_response(S3Error::new(
            S3ErrorCode::InternalError,
            "Multipart part count does not match stored block sizes",
        )));
    }

    let mut offsets = Vec::with_capacity(part_sizes.len());
    let mut acc: u64 = 0;
    for sz in &part_sizes {
        offsets.push(acc);
        acc += sz;
    }

    let obj_path = match state.storage.get_object_path(bucket, key).await {
        Ok(p) => p,
        Err(e) => return Err(storage_err_response(e)),
    };
    let plain_sizes = match enc_svc.read_mpu_part_plain_sizes(&obj_path, offsets).await {
        Ok(v) => v,
        Err(e) => {
            return Err(s3_error_response(S3Error::new(
                S3ErrorCode::InternalError,
                format!("Failed to read multipart part sizes: {}", e),
            )))
        }
    };
    let total: u64 = plain_sizes.iter().sum();

    let part_numbers = parts
        .iter()
        .map(|p| p.part_number.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let plain_sizes_csv = myfsio_storage::fs_backend::encode_part_sizes(&plain_sizes);

    all_meta.insert(MPU_PART_NUMBERS.to_string(), part_numbers);
    all_meta.insert(MPU_PART_PLAIN_SIZES.to_string(), plain_sizes_csv);
    all_meta.insert(MPU_PLAINTEXT_SIZE.to_string(), total.to_string());
    all_meta
        .entry("x-amz-server-side-encryption".to_string())
        .or_insert_with(|| "AES256".to_string());

    let md5 = all_meta.get(SSE_C_KEY_MD5_META).cloned();

    if let Err(e) = state
        .storage
        .put_object_metadata(bucket, key, &all_meta)
        .await
    {
        return Err(storage_err_response(e));
    }

    Ok(md5)
}

pub(super) async fn apply_pending_multipart_tagging(state: &AppState, bucket: &str, key: &str) {
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
            let _ = state
                .storage
                .put_object_metadata(bucket, key, &stored)
                .await;
            return;
        }
    };
    if tags.len() > state.config.object_tag_limit {
        tracing::warn!(
            bucket = bucket,
            key = key,
            "skipping multipart tagging: exceeds object_tag_limit"
        );
        let _ = state
            .storage
            .put_object_metadata(bucket, key, &stored)
            .await;
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
    if let Err(e) = state
        .storage
        .put_object_metadata(bucket, key, &stored)
        .await
    {
        tracing::error!(
            bucket = bucket,
            key = key,
            error = %e,
            "failed to clear __pending_tagging__ marker after applying tags"
        );
    }
}

pub(super) async fn abort_multipart_handler(
    state: &AppState,
    bucket: &str,
    upload_id: &str,
) -> Response {
    match state.storage.abort_multipart(bucket, upload_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => storage_err_response(e),
    }
}

pub(super) async fn list_multipart_uploads_handler(
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

pub(super) async fn list_parts_handler(
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

pub(super) async fn serve_mpu_sse_c(
    state: &AppState,
    snap_link: std::path::PathBuf,
    meta: myfsio_common::types::ObjectMeta,
    headers: &HeaderMap,
    query: &ObjectQuery,
    range_str: Option<&str>,
    part_number: Option<u32>,
) -> Response {
    let key = meta.key.as_str();

    let Some(enc_svc) = state.encryption.as_ref() else {
        let _ = tokio::fs::remove_file(&snap_link).await;
        return s3_error_response(S3Error::new(
            S3ErrorCode::InternalError,
            "Object is encrypted but encryption service is disabled",
        ));
    };

    if let Err(resp) = require_sse_c_key_match(headers, &meta.internal_metadata) {
        let _ = tokio::fs::remove_file(&snap_link).await;
        return resp;
    }
    let customer_key = match extract_sse_c_key(headers) {
        Ok(Some(k)) => k,
        Ok(None) => {
            let _ = tokio::fs::remove_file(&snap_link).await;
            return s3_error_response(S3Error::new(
                S3ErrorCode::InvalidRequest,
                "Object was created with SSE-C; the SSE-C customer key headers are required",
            ));
        }
        Err(resp) => {
            let _ = tokio::fs::remove_file(&snap_link).await;
            return resp;
        }
    };

    let Some(wrapped_odk) = meta.internal_metadata.get(MPU_WRAPPED_ODK).cloned() else {
        let _ = tokio::fs::remove_file(&snap_link).await;
        return s3_error_response(S3Error::from_code(S3ErrorCode::InternalError));
    };
    let mut ck_arr = [0u8; 32];
    ck_arr.copy_from_slice(&customer_key);
    let odk = match myfsio_crypto::encryption::unwrap_key_with(&ck_arr, &wrapped_odk) {
        Ok(k) => k,
        Err(_) => {
            let _ = tokio::fs::remove_file(&snap_link).await;
            return s3_error_response(S3Error::new(
                S3ErrorCode::AccessDenied,
                "The SSE-C customer key does not match the key used to encrypt this object",
            ));
        }
    };

    let chunk_size = meta
        .internal_metadata
        .get(MPU_CHUNK_SIZE)
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(state.config.encryption_chunk_size_bytes);

    let block_sizes = meta
        .internal_metadata
        .get(myfsio_storage::fs_backend::META_KEY_PART_SIZES)
        .and_then(|r| myfsio_storage::fs_backend::parse_part_sizes(r));
    let plain_sizes = meta
        .internal_metadata
        .get(MPU_PART_PLAIN_SIZES)
        .and_then(|r| myfsio_storage::fs_backend::parse_part_sizes(r));
    let part_numbers = meta
        .internal_metadata
        .get(MPU_PART_NUMBERS)
        .and_then(|r| parse_u32_csv(r));

    let (block_sizes, plain_sizes, part_numbers) = match (block_sizes, plain_sizes, part_numbers) {
        (Some(b), Some(p), Some(n))
            if b.len() == p.len() && p.len() == n.len() && !b.is_empty() =>
        {
            (b, p, n)
        }
        _ => {
            let _ = tokio::fs::remove_file(&snap_link).await;
            return s3_error_response(S3Error::new(
                S3ErrorCode::InternalError,
                "SSE-C multipart object metadata is incomplete or inconsistent",
            ));
        }
    };

    let n_parts = block_sizes.len();
    let mut block_offsets = Vec::with_capacity(n_parts);
    let mut plain_offsets = Vec::with_capacity(n_parts);
    let mut boff = 0u64;
    let mut poff = 0u64;
    for i in 0..n_parts {
        block_offsets.push(boff);
        plain_offsets.push(poff);
        boff += block_sizes[i];
        poff += plain_sizes[i];
    }
    let total = poff;

    let mut parts_count_header: Option<u32> = None;
    let (start, end, is_full) = if let Some(pn) = part_number {
        let Some(idx) = part_numbers.iter().position(|x| *x == pn) else {
            let _ = tokio::fs::remove_file(&snap_link).await;
            return s3_error_response(S3Error::new(
                S3ErrorCode::InvalidPart,
                format!("partNumber {} does not exist for this object", pn),
            ));
        };
        parts_count_header = Some(n_parts as u32);
        let psize = plain_sizes[idx];
        if psize == 0 {
            let _ = tokio::fs::remove_file(&snap_link).await;
            let mut h = HeaderMap::new();
            h.insert("content-length", "0".parse().unwrap());
            if let Some(ref etag) = meta.etag {
                h.insert("etag", format!("\"{}\"", etag).parse().unwrap());
            }
            insert_content_type(&mut h, key, meta.content_type.as_deref());
            h.insert(
                "last-modified",
                meta.last_modified
                    .format("%a, %d %b %Y %H:%M:%S GMT")
                    .to_string()
                    .parse()
                    .unwrap(),
            );
            h.insert("accept-ranges", "bytes".parse().unwrap());
            h.insert("x-amz-mp-parts-count", n_parts.to_string().parse().unwrap());
            apply_sse_c_response_headers(&mut h, &meta.internal_metadata);
            apply_stored_response_headers(&mut h, &meta.internal_metadata);
            apply_user_metadata(&mut h, &meta.metadata);
            apply_response_overrides(&mut h, query);
            return (StatusCode::PARTIAL_CONTENT, h).into_response();
        }
        let s = plain_offsets[idx];
        (s, s + psize - 1, false)
    } else if let Some(rs) = range_str {
        match parse_range(rs, total) {
            Some(r) => (r.0, r.1, false),
            None => {
                let _ = tokio::fs::remove_file(&snap_link).await;
                let mut extra = HeaderMap::new();
                if let Ok(v) = format!("bytes */{}", total).parse() {
                    extra.insert(axum::http::header::CONTENT_RANGE, v);
                }
                return crate::s3_response::s3_error_response_with_headers(
                    S3Error::new(
                        S3ErrorCode::InvalidRange,
                        format!("Range not satisfiable for size {}", total),
                    ),
                    extra,
                );
            }
        }
    } else if total == 0 {
        (0, 0, true)
    } else {
        (0, total - 1, true)
    };

    let mut blocks: Vec<myfsio_crypto::encryption::MpuStreamBlock> = Vec::new();
    for i in 0..n_parts {
        if plain_sizes[i] == 0 {
            continue;
        }
        let p_start = plain_offsets[i];
        let p_end = p_start + plain_sizes[i] - 1;
        if end < p_start || start > p_end {
            continue;
        }
        let ov_start = start.max(p_start);
        let ov_end = end.min(p_end);
        blocks.push(myfsio_crypto::encryption::MpuStreamBlock {
            block_offset: block_offsets[i],
            block_len: block_sizes[i],
            part_number: part_numbers[i],
            part_plaintext_size: plain_sizes[i],
            plain_start: ov_start - p_start,
            plain_end_inclusive: ov_end - p_start,
        });
    }

    let disk_permit = match acquire_disk_read_permit(state).await {
        Ok(permit) => permit,
        Err(response) => {
            let _ = tokio::fs::remove_file(&snap_link).await;
            return response;
        }
    };

    let body_len: u64 = if total == 0 { 0 } else { end - start + 1 };
    let stream = enc_svc.decrypt_mpu_blocks_stream(&snap_link, odk, chunk_size, blocks, true);
    let stream = attach_read_permit(stream, disk_permit);

    let stream_cap = state.config.stream_chunk_size.max(64 * 1024);
    let stream = ReaderStream::with_capacity(stream, stream_cap);
    let body = Body::from_stream(stream);

    let mut h = HeaderMap::new();
    h.insert("content-length", body_len.to_string().parse().unwrap());
    if !is_full {
        h.insert(
            "content-range",
            format!("bytes {}-{}/{}", start, end, total)
                .parse()
                .unwrap(),
        );
    }
    if let Some(ref etag) = meta.etag {
        h.insert("etag", format!("\"{}\"", etag).parse().unwrap());
    }
    insert_content_type(&mut h, key, meta.content_type.as_deref());
    h.insert(
        "last-modified",
        meta.last_modified
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string()
            .parse()
            .unwrap(),
    );
    h.insert("accept-ranges", "bytes".parse().unwrap());
    apply_sse_c_response_headers(&mut h, &meta.internal_metadata);
    apply_stored_response_headers(&mut h, &meta.internal_metadata);
    if is_full && checksum_mode_enabled(headers) {
        apply_stored_checksum_headers(&mut h, &meta.internal_metadata);
    }
    if let Some(ref requested_version) = query.version_id {
        if let Ok(value) = requested_version.parse() {
            h.insert("x-amz-version-id", value);
        }
    } else if let Some(ref vid) = meta.version_id {
        if let Ok(value) = vid.parse() {
            h.insert("x-amz-version-id", value);
        }
    }
    apply_user_metadata(&mut h, &meta.metadata);
    apply_response_overrides(&mut h, query);
    if let Some(count) = parts_count_header {
        h.insert("x-amz-mp-parts-count", count.to_string().parse().unwrap());
    }

    let status = if is_full {
        StatusCode::OK
    } else {
        StatusCode::PARTIAL_CONTENT
    };
    (status, h, body).into_response()
}
