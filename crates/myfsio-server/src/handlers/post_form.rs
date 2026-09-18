use super::*;

pub(super) fn post_form_error(err: multer::Error) -> S3Error {
    match err {
        multer::Error::FieldSizeExceeded { limit, .. } => post_form_field_limit_error(limit),
        other => S3Error::new(
            S3ErrorCode::MalformedXML,
            format!("Malformed multipart: {}", other),
        ),
    }
}

pub(super) fn post_form_field_limit_error(limit: u64) -> S3Error {
    S3Error::new(
        S3ErrorCode::MaxMessageLengthExceeded,
        format!(
            "Your request was too big; a form field other than the file may not exceed {} bytes",
            limit
        ),
    )
}

pub(super) async fn read_post_form_text(field: &mut multer::Field<'_>) -> Result<String, S3Error> {
    let mut bytes = bytes::BytesMut::new();
    loop {
        match field.chunk().await {
            Ok(Some(chunk)) => {
                if bytes.len().saturating_add(chunk.len()) > POST_FORM_FIELD_LIMIT as usize {
                    return Err(post_form_field_limit_error(POST_FORM_FIELD_LIMIT));
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(None) => return Ok(String::from_utf8_lossy(&bytes).into_owned()),
            Err(error) => return Err(post_form_error(error)),
        }
    }
}

pub(super) async fn post_object_form_handler(
    state: &AppState,
    bucket: &str,
    content_type: &str,
    headers: &HeaderMap,
    peer_marker: Option<&crate::middleware::ReplicationPeerRequest>,
    principal: Option<&myfsio_common::types::Principal>,
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
    let constraints =
        multer::Constraints::new().size_limit(multer::SizeLimit::new().per_field(u64::MAX));
    let mut multipart = multer::Multipart::with_constraints(stream, boundary, constraints);

    enum PostFormEvent {
        Text {
            name: String,
            value: String,
        },
        File {
            file_name: Option<String>,
            data: tokio::sync::mpsc::Receiver<std::io::Result<bytes::Bytes>>,
        },
    }

    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel::<Result<PostFormEvent, S3Error>>(8);
    tokio::spawn(async move {
        loop {
            let mut field = match multipart.next_field().await {
                Ok(Some(f)) => f,
                Ok(None) => return,
                Err(e) => {
                    let _ = event_tx.send(Err(post_form_error(e))).await;
                    return;
                }
            };
            let name = field.name().map(|s| s.to_string()).unwrap_or_default();
            if name.eq_ignore_ascii_case("file") {
                let file_name = field.file_name().map(|s| s.to_string());
                let (data_tx, data_rx) =
                    tokio::sync::mpsc::channel::<std::io::Result<bytes::Bytes>>(4);
                if event_tx
                    .send(Ok(PostFormEvent::File {
                        file_name,
                        data: data_rx,
                    }))
                    .await
                    .is_err()
                {
                    return;
                }
                loop {
                    match field.chunk().await {
                        Ok(Some(chunk)) => {
                            if data_tx.send(Ok(chunk)).await.is_err() {
                                return;
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            let _ = data_tx.send(Err(std::io::Error::other(e))).await;
                            return;
                        }
                    }
                }
                return;
            } else if !name.is_empty() {
                match read_post_form_text(&mut field).await {
                    Ok(value) => {
                        if event_tx
                            .send(Ok(PostFormEvent::Text { name, value }))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    Err(e) => {
                        let _ = event_tx.send(Err(e)).await;
                        return;
                    }
                }
            }
        }
    });

    let mut fields: HashMap<String, String> = HashMap::new();
    let mut file_stream: Option<tokio::sync::mpsc::Receiver<std::io::Result<bytes::Bytes>>> = None;
    let mut file_name: Option<String> = None;
    while let Some(event) = event_rx.recv().await {
        match event {
            Err(err) => {
                return s3_error_response(err);
            }
            Ok(PostFormEvent::Text { name, value }) => {
                fields.insert(name, value);
            }
            Ok(PostFormEvent::File {
                file_name: fname,
                data,
            }) => {
                file_name = fname;
                file_stream = Some(data);
                break;
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

    let object_key = if key_template.contains("${filename}") {
        let fname = file_name.clone().unwrap_or_else(|| "upload".to_string());
        key_template.replace("${filename}", &fname)
    } else {
        key_template.clone()
    };

    let mut length_range: Option<(u64, u64)> = None;
    if let Some(conditions) = policy_value.get("conditions").and_then(|v| v.as_array()) {
        match validate_post_policy_conditions(bucket, &object_key, conditions, &fields) {
            Ok(range) => length_range = range,
            Err(msg) => {
                return s3_error_response(S3Error::new(S3ErrorCode::AccessDenied, msg));
            }
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

    let file_data = match file_stream {
        Some(rx) => rx,
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
            if !myfsio_storage::validation::is_reserved_user_metadata_key(meta_key) {
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
    let mut checksum_headers = HeaderMap::new();
    for name in [
        "content-md5",
        "x-amz-checksum-sha256",
        "x-amz-checksum-sha1",
        "x-amz-checksum-crc32",
        "x-amz-checksum-crc32c",
        "x-amz-checksum-crc64nvme",
        "x-amz-sdk-checksum-algorithm",
    ] {
        if let Some(value) = fields
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value)
        {
            let Ok(value) = value.parse() else {
                return invalid_digest_response(format!("Invalid value for {}", name));
            };
            checksum_headers.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value,
            );
        }
    }
    persist_additional_checksums(&checksum_headers, &mut metadata);
    object_lock::apply_default_retention(state, bucket, &mut metadata).await;

    let bypass_governance =
        governance_bypass_allowed(state, principal, bucket, Some(&object_key), headers).await;
    if let Err(response) =
        ensure_archived_null_lock_allows_overwrite(state, bucket, &object_key, bypass_governance)
            .await
    {
        return response;
    }

    let _disk_permit = match acquire_disk_write_permit(state).await {
        Ok(permit) => permit,
        Err(response) => return response,
    };
    let raw: myfsio_storage::traits::AsyncReadStream = Box::pin(tokio_util::io::StreamReader::new(
        tokio_stream::wrappers::ReceiverStream::new(file_data),
    ));
    let raw: myfsio_storage::traits::AsyncReadStream = match length_range {
        Some((min, max)) => Box::pin(checksum_stream::LengthRangeReader::new(raw, min, max)),
        None => raw,
    };
    let raw = match apply_upload_checksum_verification(raw, &checksum_headers) {
        Ok(stream) => stream,
        Err(response) => return response,
    };
    let boxed = spool_upload_stream(
        raw,
        state.config.upload_stream_buffer_bytes,
        state.config.stream_chunk_size,
        state.disk_limiter.spool_gauge(),
    );

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
    trigger_replication_for_request(state, peer_marker, bucket, &object_key, "write", None);
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

pub(super) fn validate_post_policy_conditions(
    bucket: &str,
    object_key: &str,
    conditions: &[serde_json::Value],
    form: &HashMap<String, String>,
) -> Result<Option<(u64, u64)>, String> {
    let mut length_range: Option<(u64, u64)> = None;
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
                let min = arr[1].as_i64().unwrap_or(0).max(0) as u64;
                let max = arr[2].as_i64().unwrap_or(0).max(0) as u64;
                length_range = Some(match length_range {
                    Some((prev_min, prev_max)) => (prev_min.max(min), prev_max.min(max)),
                    None => (min, max),
                });
            }
        }
    }
    Ok(length_range)
}
