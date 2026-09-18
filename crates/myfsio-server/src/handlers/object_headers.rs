use super::*;

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

impl ObjectQuery {
    pub fn effective_version_id(&self) -> Option<&str> {
        self.version_id.as_deref().filter(|value| !value.is_empty())
    }
}

pub(super) fn apply_response_overrides(headers: &mut HeaderMap, query: &ObjectQuery) {
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

pub(super) fn guessed_content_type(key: &str, explicit: Option<&str>) -> String {
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

pub(super) fn is_aws_chunked(headers: &HeaderMap) -> bool {
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

pub(super) fn declared_body_length(headers: &HeaderMap, aws_chunked: bool) -> Option<u64> {
    let name = if aws_chunked {
        "x-amz-decoded-content-length"
    } else {
        "content-length"
    };
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
}

pub(super) fn incomplete_body_io_error(expected: u64, received: u64) -> std::io::Error {
    let kind = if received < expected {
        std::io::ErrorKind::UnexpectedEof
    } else {
        std::io::ErrorKind::InvalidData
    };
    std::io::Error::new(
        kind,
        myfsio_common::error::IncompleteBodyError { expected, received },
    )
}

pub(super) struct DeclaredLengthReader {
    inner: myfsio_storage::traits::AsyncReadStream,
    expected: u64,
    seen: u64,
}

impl tokio::io::AsyncRead for DeclaredLengthReader {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let had_capacity = buf.remaining() > 0;
        let before = buf.filled().len();
        match this.inner.as_mut().poll_read(cx, buf) {
            std::task::Poll::Ready(Ok(())) => {
                let n = (buf.filled().len() - before) as u64;
                if n == 0 {
                    if had_capacity && this.seen != this.expected {
                        return std::task::Poll::Ready(Err(incomplete_body_io_error(
                            this.expected,
                            this.seen,
                        )));
                    }
                    return std::task::Poll::Ready(Ok(()));
                }
                this.seen += n;
                if this.seen > this.expected {
                    buf.set_filled(before);
                    return std::task::Poll::Ready(Err(incomplete_body_io_error(
                        this.expected,
                        this.seen,
                    )));
                }
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(Err(err)) => {
                let err = if this.seen != this.expected
                    && !error_chain_has_body_timeout(&err)
                    && crate::middleware::sha_body::sha256_mismatch_message(&err).is_none()
                {
                    tracing::debug!(
                        "request body ended with a transport error after {} of {} declared bytes: {}",
                        this.seen,
                        this.expected,
                        err
                    );
                    incomplete_body_io_error(this.expected, this.seen)
                } else {
                    err
                };
                std::task::Poll::Ready(Err(err))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

pub(super) fn enforce_declared_length(
    stream: myfsio_storage::traits::AsyncReadStream,
    expected: Option<u64>,
) -> myfsio_storage::traits::AsyncReadStream {
    match expected {
        Some(expected) => Box::pin(DeclaredLengthReader {
            inner: stream,
            expected,
            seen: 0,
        }),
        None => stream,
    }
}

pub(super) fn insert_content_type(headers: &mut HeaderMap, key: &str, explicit: Option<&str>) {
    let value = guessed_content_type(key, explicit);
    if let Ok(header_value) = value.parse() {
        headers.insert("content-type", header_value);
    } else {
        headers.insert("content-type", "application/octet-stream".parse().unwrap());
    }
}

pub(super) fn internal_header_pairs() -> &'static [(&'static str, &'static str, &'static str)] {
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

pub(super) fn decoded_content_encoding(value: &str) -> Option<String> {
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

pub(super) fn insert_standard_object_metadata(
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

    insert_object_lock_metadata(headers, metadata)
}

pub(super) fn insert_object_lock_metadata(
    headers: &HeaderMap,
    metadata: &mut HashMap<String, String>,
) -> Result<(), Response> {
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

pub(super) fn apply_user_metadata(headers: &mut HeaderMap, metadata: &HashMap<String, String>) {
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

pub(super) fn parse_tagging_header(
    value: &str,
) -> Result<Vec<myfsio_common::types::Tag>, Response> {
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

pub(super) fn parse_copy_source(
    copy_source: &str,
) -> Result<(String, String, Option<String>), Response> {
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

pub(super) fn normalize_object_key(key: String) -> String {
    if key.starts_with(['/', '\\']) {
        key.trim_start_matches(['/', '\\']).to_string()
    } else {
        key
    }
}
