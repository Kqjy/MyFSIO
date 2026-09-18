use super::*;

pub(super) fn bad_digest_response(message: impl Into<String>) -> Response {
    s3_error_response(S3Error::new(S3ErrorCode::BadDigest, message))
}

pub(super) fn invalid_digest_response(message: impl Into<String>) -> Response {
    s3_error_response(S3Error::new(S3ErrorCode::InvalidDigest, message))
}

pub(super) fn base64_header_bytes(
    headers: &HeaderMap,
    name: &str,
) -> Result<Option<Vec<u8>>, Response> {
    let Some(value) = headers.get(name).and_then(|v| v.to_str().ok()) else {
        return Ok(None);
    };
    STANDARD
        .decode(value.trim())
        .map(Some)
        .map_err(|_| invalid_digest_response(format!("Invalid base64 value for {}", name)))
}

pub(super) fn validate_checksum_length(
    value: Option<Vec<u8>>,
    name: &str,
    length: usize,
) -> Result<Option<Vec<u8>>, Response> {
    match value {
        Some(value) if value.len() != length => Err(invalid_digest_response(format!(
            "The {} you specified is not a valid {}-byte value",
            name, length
        ))),
        value => Ok(value),
    }
}

pub(super) fn expected_upload_checksums(
    headers: &HeaderMap,
) -> Result<checksum_stream::ExpectedUploadChecksums, Response> {
    let mut expected = checksum_stream::ExpectedUploadChecksums::default();
    if let Some(md5) = base64_header_bytes(headers, "content-md5")? {
        if md5.len() != 16 {
            return Err(invalid_digest_response(
                "The Content-MD5 you specified is not a valid 16-byte MD5 digest",
            ));
        }
        expected.md5 = Some(md5);
    }
    expected.sha256 = validate_checksum_length(
        base64_header_bytes(headers, "x-amz-checksum-sha256")?,
        "x-amz-checksum-sha256",
        32,
    )?;
    expected.sha1 = validate_checksum_length(
        base64_header_bytes(headers, "x-amz-checksum-sha1")?,
        "x-amz-checksum-sha1",
        20,
    )?;
    if let Some(crc) = base64_header_bytes(headers, "x-amz-checksum-crc32")? {
        let crc: [u8; 4] = crc.as_slice().try_into().map_err(|_| {
            invalid_digest_response(
                "The x-amz-checksum-crc32 you specified is not a valid 4-byte CRC32 value",
            )
        })?;
        expected.crc32 = Some(crc);
    }
    if let Some(crc) = base64_header_bytes(headers, "x-amz-checksum-crc32c")? {
        let crc: [u8; 4] = crc.as_slice().try_into().map_err(|_| {
            invalid_digest_response(
                "The x-amz-checksum-crc32c you specified is not a valid 4-byte CRC32C value",
            )
        })?;
        expected.crc32c = Some(crc);
    }
    if let Some(crc) = base64_header_bytes(headers, "x-amz-checksum-crc64nvme")? {
        let crc: [u8; 8] = crc.as_slice().try_into().map_err(|_| {
            invalid_digest_response(
                "The x-amz-checksum-crc64nvme you specified is not a valid 8-byte CRC64NVME value",
            )
        })?;
        expected.crc64nvme = Some(crc);
    }
    Ok(expected)
}

pub(super) fn apply_upload_checksum_verification(
    stream: myfsio_storage::traits::AsyncReadStream,
    headers: &HeaderMap,
) -> Result<myfsio_storage::traits::AsyncReadStream, Response> {
    let expected = expected_upload_checksums(headers)?;
    if expected.is_empty() {
        Ok(stream)
    } else {
        Ok(Box::pin(checksum_stream::ChecksumVerifyReader::new(
            stream, expected,
        )))
    }
}

pub(super) fn persist_additional_checksums(
    headers: &HeaderMap,
    metadata: &mut HashMap<String, String>,
) {
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

pub(super) fn apply_stored_checksum_headers(
    resp_headers: &mut HeaderMap,
    metadata: &HashMap<String, String>,
) {
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

pub(super) fn checksum_mode_enabled(headers: &HeaderMap) -> bool {
    headers
        .get("x-amz-checksum-mode")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("ENABLED"))
}

pub(super) fn aws_chunked_error_response(error: &chunked::AwsChunkedError) -> Response {
    let code = match error.kind() {
        chunked::AwsChunkedErrorKind::IncompleteBody => S3ErrorCode::IncompleteBody,
        chunked::AwsChunkedErrorKind::InvalidRequest => S3ErrorCode::InvalidRequest,
        chunked::AwsChunkedErrorKind::SignatureDoesNotMatch => S3ErrorCode::SignatureDoesNotMatch,
    };
    s3_error_response(S3Error::new(code, error.message()))
}

pub(super) fn decode_aws_chunked_body(
    body: Body,
    headers: &HeaderMap,
    signing_context: Option<crate::middleware::StreamingSigV4Context>,
    strict_signatures: bool,
) -> Result<myfsio_storage::traits::AsyncReadStream, Response> {
    chunked::decode_body(body, headers, signing_context, strict_signatures)
        .map(|stream| Box::pin(stream) as myfsio_storage::traits::AsyncReadStream)
        .map_err(|error| aws_chunked_error_response(&error))
}
