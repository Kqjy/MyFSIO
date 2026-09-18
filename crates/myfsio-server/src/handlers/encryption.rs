use super::*;

pub(super) fn validate_sse_request(state: &AppState, headers: &HeaderMap) -> Result<(), Response> {
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

pub(super) fn encryption_failure_response(err: myfsio_crypto::aes_gcm::CryptoError) -> Response {
    match err {
        myfsio_crypto::aes_gcm::CryptoError::Io(io_err) => {
            storage_err_response(myfsio_storage::error::StorageError::Io(io_err))
        }
        myfsio_crypto::aes_gcm::CryptoError::KmsKeyNotFound(kid) => config::custom_xml_error(
            StatusCode::BAD_REQUEST,
            "KMS.NotFoundException",
            &format!("KMS key '{}' does not exist", kid),
        ),
        myfsio_crypto::aes_gcm::CryptoError::KmsKeyDisabled(kid) => config::custom_xml_error(
            StatusCode::BAD_REQUEST,
            "KMS.DisabledException",
            &format!("KMS key '{}' is disabled", kid),
        ),
        other => s3_error_response(S3Error::new(
            S3ErrorCode::InternalError,
            format!("Encryption failed: {}", other),
        )),
    }
}

pub(super) async fn validate_kms_key_usable(
    state: &AppState,
    ctx: Option<&myfsio_crypto::encryption::EncryptionContext>,
) -> Result<(), Response> {
    let Some(ctx) = ctx else {
        return Ok(());
    };
    if ctx.algorithm != myfsio_crypto::encryption::SseAlgorithm::AwsKms {
        return Ok(());
    }
    let Some(ref kid) = ctx.kms_key_id else {
        return Ok(());
    };
    let Some(kms) = state.kms.as_ref() else {
        return Err(config::custom_xml_error(
            StatusCode::BAD_REQUEST,
            "KMS.NotFoundException",
            "KMS is not available on this server",
        ));
    };
    match kms.get_key(kid).await {
        None => Err(config::custom_xml_error(
            StatusCode::BAD_REQUEST,
            "KMS.NotFoundException",
            &format!("KMS key '{}' does not exist", kid),
        )),
        Some(key) if !key.enabled => Err(config::custom_xml_error(
            StatusCode::BAD_REQUEST,
            "KMS.DisabledException",
            &format!("KMS key '{}' is disabled", kid),
        )),
        Some(_) => Ok(()),
    }
}

pub(super) fn apply_stored_response_headers(
    headers: &mut HeaderMap,
    metadata: &HashMap<String, String>,
) {
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

pub(super) fn apply_stored_kms_key_header(
    headers: &mut HeaderMap,
    metadata: &HashMap<String, String>,
) {
    if let Some(kid) = metadata
        .get("x-amz-encryption-key-id")
        .and_then(|v| v.parse().ok())
    {
        headers.insert("x-amz-server-side-encryption-aws-kms-key-id", kid);
    }
}

pub(super) fn apply_stored_encryption_headers(
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

pub(super) async fn resolve_encryption_context(
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

    crate::services::bucket_encryption::resolve_bucket_default_encryption(
        &*state.storage,
        state.encryption.is_some(),
        bucket,
    )
    .await
    .map_err(s3_error_response)
}

pub(super) const SSE_C_KEY_MD5_META: &str = "x-amz-server-side-encryption-customer-key-MD5";

pub(super) fn sse_c_key_md5(key: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use md5::{Digest, Md5};
    let mut hasher = Md5::new();
    hasher.update(key);
    B64.encode(hasher.finalize())
}

pub(super) fn extract_sse_c_key(headers: &HeaderMap) -> Result<Option<Vec<u8>>, Response> {
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

pub(super) fn require_sse_c_key_for_object(
    state: &AppState,
    meta: &myfsio_common::types::ObjectMeta,
    headers: &HeaderMap,
) -> Result<(), Response> {
    if state.encryption.is_some() && object_read::requires_customer_key(meta) {
        require_sse_c_key_match(headers, &meta.internal_metadata)?;
    }
    Ok(())
}

pub(super) fn require_sse_c_key_match(
    headers: &HeaderMap,
    stored_metadata: &HashMap<String, String>,
) -> Result<(), Response> {
    let provided = match extract_sse_c_key(headers) {
        Ok(Some(key)) => key,
        Ok(None) => {
            return Err(s3_error_response(S3Error::new(
                S3ErrorCode::InvalidRequest,
                "Object was created with SSE-C; the SSE-C customer key headers are required",
            )))
        }
        Err(resp) => return Err(resp),
    };
    if let Some(stored_md5) = stored_metadata.get(SSE_C_KEY_MD5_META) {
        if !constant_time_eq(sse_c_key_md5(&provided).as_bytes(), stored_md5.as_bytes()) {
            return Err(s3_error_response(S3Error::new(
                S3ErrorCode::AccessDenied,
                "The SSE-C customer key does not match the key used to encrypt this object",
            )));
        }
    }
    Ok(())
}

pub(super) async fn compute_plaintext_md5(path: &std::path::Path) -> std::io::Result<String> {
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

pub(super) const STORAGE_MANAGED_METADATA_KEYS: &[&str] = &[
    "__etag__",
    "__size__",
    "__last_modified__",
    "__version_id__",
];

pub(super) fn strip_storage_managed_keys(metadata: &mut HashMap<String, String>) {
    for k in STORAGE_MANAGED_METADATA_KEYS {
        metadata.remove(*k);
    }
}

pub(super) fn resolve_copy_source_sse_c_key(
    headers: &HeaderMap,
    stored_metadata: &HashMap<String, String>,
) -> Result<Option<Vec<u8>>, Response> {
    let provided = extract_copy_source_sse_c_key(headers)?;
    let Some(stored_md5) = stored_metadata.get(SSE_C_KEY_MD5_META) else {
        return Ok(provided);
    };
    let Some(key) = provided else {
        return Err(s3_error_response(S3Error::new(
            S3ErrorCode::InvalidRequest,
            "Copy source was created with SSE-C; the copy-source SSE-C key headers are required",
        )));
    };
    if !constant_time_eq(sse_c_key_md5(&key).as_bytes(), stored_md5.as_bytes()) {
        return Err(s3_error_response(S3Error::new(
            S3ErrorCode::AccessDenied,
            "The copy-source SSE-C customer key does not match the key used to encrypt this object",
        )));
    }
    Ok(Some(key))
}

pub(super) fn extract_copy_source_sse_c_key(
    headers: &HeaderMap,
) -> Result<Option<Vec<u8>>, Response> {
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

pub(super) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
