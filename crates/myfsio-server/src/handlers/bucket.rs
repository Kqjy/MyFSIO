use super::*;

pub async fn list_buckets(
    State(state): State<AppState>,
    Query(_query): Query<BucketQuery>,
    _headers: HeaderMap,
    request: axum::extract::Request,
) -> Response {
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

pub(super) fn caller_owner(
    _state: &AppState,
    request: &axum::extract::Request,
) -> (String, String) {
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
    raw_query: axum::extract::RawQuery,
    _peer: Option<axum::extract::Extension<crate::middleware::ReplicationPeerRequest>>,
    _principal: Option<axum::extract::Extension<myfsio_common::types::Principal>>,
    _streaming_sigv4: Option<axum::extract::Extension<crate::middleware::StreamingSigV4Context>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if let Some(unsupported) = unsupported_bucket_subresource(raw_query.0.as_deref()) {
        return s3_error_response(S3Error::new(
            S3ErrorCode::NotImplemented,
            format!(
                "The bucket subresource '?{}' is not implemented by this server",
                unsupported
            ),
        ));
    }

    let subresource = match parse_bucket_subresource(raw_query.0.as_deref()) {
        Ok(value) => value,
        Err(selectors) => return s3_error_response(ambiguous_subresource_error(&selectors)),
    };

    if let Some(subresource) = subresource {
        return match subresource {
            BucketSubresource::Quota => config::put_quota(&state, &bucket, body).await,
            BucketSubresource::Versioning => config::put_versioning(&state, &bucket, body).await,
            BucketSubresource::Tagging => config::put_tagging(&state, &bucket, body).await,
            BucketSubresource::Cors => config::put_cors(&state, &bucket, body).await,
            BucketSubresource::Encryption => config::put_encryption(&state, &bucket, body).await,
            BucketSubresource::Lifecycle => config::put_lifecycle(&state, &bucket, body).await,
            BucketSubresource::Acl => config::put_acl(&state, &bucket, &headers, body).await,
            BucketSubresource::Policy => config::put_policy(&state, &bucket, body).await,
            BucketSubresource::Replication => config::put_replication(&state, &bucket, body).await,
            BucketSubresource::Website => config::put_website(&state, &bucket, body).await,
            BucketSubresource::ObjectLock => config::put_object_lock(&state, &bucket, body).await,
            BucketSubresource::OwnershipControls => {
                config::put_ownership_controls(&state, &bucket, body).await
            }
            BucketSubresource::PublicAccessBlock => {
                config::put_public_access_block(&state, &bucket, body).await
            }
            BucketSubresource::Notification => {
                config::put_notification(&state, &bucket, body).await
            }
            BucketSubresource::Logging => config::put_logging(&state, &bucket, body).await,
            BucketSubresource::Location
            | BucketSubresource::PolicyStatus
            | BucketSubresource::Uploads
            | BucketSubresource::Versions
            | BucketSubresource::Delete => subresource_method_not_allowed(subresource, "PUT"),
        };
    }

    let acl_request = match header_acl_request(&headers) {
        Ok(value) => value,
        Err(resp) => return resp,
    };

    let body_bytes = match collect_body_limited(body, CONFIG_BODY_LIMIT).await {
        Ok(bytes) => bytes,
        Err(response) => return response,
    };

    if let Some(constraint) = parse_location_constraint(&body_bytes) {
        if let Err(resp) = validate_location_constraint(&state, &constraint) {
            return resp;
        }
    }

    match state.storage.create_bucket(&bucket).await {
        Ok(()) => {
            let lock_requested = headers
                .get("x-amz-bucket-object-lock-enabled")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.eq_ignore_ascii_case("true"));
            if lock_requested {
                if let Err(e) = state
                    .storage
                    .set_versioning_status(&bucket, myfsio_common::types::VersioningStatus::Enabled)
                    .await
                {
                    return storage_err_response(e);
                }
                let lock_response = config::set_object_lock_enabled_default(&state, &bucket).await;
                if !lock_response.status().is_success() {
                    return lock_response;
                }
            }
            if let Some(request) = acl_request {
                let (owner, _) = canonical_default_owner(&state);
                let acl_response =
                    config::set_bucket_acl(&state, &bucket, &request.into_acl(&owner)).await;
                if !acl_response.status().is_success() {
                    return acl_response;
                }
            }
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

pub(super) fn parse_location_constraint(body: &[u8]) -> Option<String> {
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

pub(super) fn validate_location_constraint(
    state: &AppState,
    constraint: &str,
) -> Result<(), Response> {
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

pub async fn get_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(query): Query<BucketQuery>,
    raw_query: axum::extract::RawQuery,
    _headers: HeaderMap,
) -> Response {
    let (owner_id, owner_display) = canonical_default_owner(&state);
    let owner_id_ref = owner_id.as_str();
    let owner_display_ref = owner_display.as_str();

    if let Some(unsupported) = unsupported_bucket_subresource(raw_query.0.as_deref()) {
        return s3_error_response(S3Error::new(
            S3ErrorCode::NotImplemented,
            format!(
                "The bucket subresource '?{}' is not implemented by this server",
                unsupported
            ),
        ));
    }

    if !matches!(state.storage.bucket_exists(&bucket).await, Ok(true)) {
        return storage_err_response(myfsio_storage::error::StorageError::BucketNotFound(bucket));
    }

    let subresource = match parse_bucket_subresource(raw_query.0.as_deref()) {
        Ok(value) => value,
        Err(selectors) => return s3_error_response(ambiguous_subresource_error(&selectors)),
    };

    let max_keys: usize = match query.max_keys.as_deref() {
        None => 1000,
        Some(raw) => match parse_max_keys(raw) {
            Ok(v) => v.min(1000),
            Err(resp) => return resp,
        },
    };

    if let Some(subresource) = subresource {
        return match subresource {
            BucketSubresource::Quota => config::get_quota(&state, &bucket).await,
            BucketSubresource::Versioning => config::get_versioning(&state, &bucket).await,
            BucketSubresource::Tagging => config::get_tagging(&state, &bucket).await,
            BucketSubresource::Cors => config::get_cors(&state, &bucket).await,
            BucketSubresource::Location => config::get_location(&state, &bucket).await,
            BucketSubresource::Encryption => config::get_encryption(&state, &bucket).await,
            BucketSubresource::Lifecycle => config::get_lifecycle(&state, &bucket).await,
            BucketSubresource::Acl => config::get_acl(&state, &bucket).await,
            BucketSubresource::Policy => config::get_policy(&state, &bucket).await,
            BucketSubresource::PolicyStatus => config::get_policy_status(&state, &bucket).await,
            BucketSubresource::Replication => config::get_replication(&state, &bucket).await,
            BucketSubresource::Website => config::get_website(&state, &bucket).await,
            BucketSubresource::ObjectLock => config::get_object_lock(&state, &bucket).await,
            BucketSubresource::OwnershipControls => {
                config::get_ownership_controls(&state, &bucket).await
            }
            BucketSubresource::PublicAccessBlock => {
                config::get_public_access_block(&state, &bucket).await
            }
            BucketSubresource::Notification => config::get_notification(&state, &bucket).await,
            BucketSubresource::Logging => config::get_logging(&state, &bucket).await,
            BucketSubresource::Versions => {
                if let Err(resp) = validate_encoding_type(&query) {
                    return resp;
                }
                config::list_object_versions(
                    &state,
                    &bucket,
                    query.prefix.as_deref(),
                    query.delimiter.as_deref(),
                    query.key_marker.as_deref(),
                    query.version_id_marker.as_deref(),
                    max_keys,
                )
                .await
            }
            BucketSubresource::Uploads => {
                if let Err(resp) = validate_encoding_type(&query) {
                    return resp;
                }
                list_multipart_uploads_handler(&state, &bucket, &query).await
            }
            BucketSubresource::Delete => subresource_method_not_allowed(subresource, "GET"),
        };
    }

    if let Err(resp) = validate_encoding_type(&query) {
        return resp;
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

pub(super) struct GroupedListing {
    pub(super) objects: Vec<myfsio_common::types::ObjectMeta>,
    pub(super) common_prefixes: Vec<String>,
    pub(super) is_truncated: bool,
    pub(super) next_token: Option<String>,
}

pub(super) async fn list_with_arbitrary_delimiter(
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

    let initial_skip = continuation_token.clone().or_else(|| start_after.clone());

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

pub(super) fn skip_past_common_prefix(cp: &str) -> String {
    let mut s = cp.to_string();
    s.push('\u{10FFFF}');
    s
}

pub async fn post_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    raw_query: axum::extract::RawQuery,
    peer: Option<axum::extract::Extension<crate::middleware::ReplicationPeerRequest>>,
    principal: Option<axum::extract::Extension<myfsio_common::types::Principal>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let peer_marker = peer.as_ref().map(|e| &e.0);
    let principal_ref = principal.as_ref().map(|e| &e.0);

    let subresource = match parse_bucket_subresource(raw_query.0.as_deref()) {
        Ok(value) => value,
        Err(selectors) => return s3_error_response(ambiguous_subresource_error(&selectors)),
    };

    match subresource {
        Some(BucketSubresource::Delete) => {
            return delete_objects_handler(
                &state,
                &bucket,
                peer_marker,
                principal_ref,
                bypass_governance_header(&headers),
                body,
            )
            .await;
        }
        Some(other) => return subresource_method_not_allowed(other, "POST"),
        None => {}
    }

    if let Some(ct) = headers.get("content-type").and_then(|v| v.to_str().ok()) {
        if ct.to_ascii_lowercase().starts_with("multipart/form-data") {
            let ct = ct.to_string();
            return post_object_form_handler(
                &state,
                &bucket,
                &ct,
                &headers,
                peer_marker,
                principal_ref,
                body,
            )
            .await;
        }
    }

    (StatusCode::METHOD_NOT_ALLOWED).into_response()
}

pub async fn delete_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    raw_query: axum::extract::RawQuery,
    _peer: Option<axum::extract::Extension<crate::middleware::ReplicationPeerRequest>>,
    _principal: Option<axum::extract::Extension<myfsio_common::types::Principal>>,
    _headers: HeaderMap,
) -> Response {
    if let Some(unsupported) = unsupported_bucket_subresource(raw_query.0.as_deref()) {
        return s3_error_response(S3Error::new(
            S3ErrorCode::NotImplemented,
            format!(
                "The bucket subresource '?{}' is not implemented by this server",
                unsupported
            ),
        ));
    }

    let subresource = match parse_bucket_subresource(raw_query.0.as_deref()) {
        Ok(value) => value,
        Err(selectors) => return s3_error_response(ambiguous_subresource_error(&selectors)),
    };

    if let Some(subresource) = subresource {
        return match subresource {
            BucketSubresource::Quota => config::delete_quota(&state, &bucket).await,
            BucketSubresource::Tagging => config::delete_tagging(&state, &bucket).await,
            BucketSubresource::Cors => config::delete_cors(&state, &bucket).await,
            BucketSubresource::Encryption => config::delete_encryption(&state, &bucket).await,
            BucketSubresource::Lifecycle => config::delete_lifecycle(&state, &bucket).await,
            BucketSubresource::Website => config::delete_website(&state, &bucket).await,
            BucketSubresource::Policy => config::delete_policy(&state, &bucket).await,
            BucketSubresource::Replication => config::delete_replication(&state, &bucket).await,
            BucketSubresource::ObjectLock => config::delete_object_lock(&state, &bucket).await,
            BucketSubresource::OwnershipControls => {
                config::delete_ownership_controls(&state, &bucket).await
            }
            BucketSubresource::PublicAccessBlock => {
                config::delete_public_access_block(&state, &bucket).await
            }
            BucketSubresource::Notification => config::delete_notification(&state, &bucket).await,
            BucketSubresource::Logging => config::delete_logging(&state, &bucket).await,
            BucketSubresource::Acl
            | BucketSubresource::Versioning
            | BucketSubresource::Versions
            | BucketSubresource::Uploads
            | BucketSubresource::Delete
            | BucketSubresource::Location
            | BucketSubresource::PolicyStatus => {
                subresource_method_not_allowed(subresource, "DELETE")
            }
        };
    }

    match state.storage.delete_bucket(&bucket).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => storage_err_response(e),
    }
}

pub async fn head_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    _headers: HeaderMap,
) -> Response {
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
