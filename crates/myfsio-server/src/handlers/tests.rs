use super::bucket::list_with_arbitrary_delimiter;
use super::object_headers::incomplete_body_io_error;
use super::*;
use crate::config::ServerConfig;
use crate::services::acl::{acl_to_xml, create_canned_acl};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

const TEST_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
const TEST_SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

#[test]
fn effective_version_id_agrees_with_auth_version_detection() {
    for (raw, query) in [
        (None, ""),
        (Some(""), "versionId="),
        (Some("v1"), "versionId=v1"),
    ] {
        let parsed = ObjectQuery {
            version_id: raw.map(str::to_string),
            ..Default::default()
        };
        assert_eq!(
            parsed.effective_version_id().is_some(),
            query_has_version_id(Some(query)),
            "handler and auth disagree on version scoping for '{}'",
            query
        );
    }
}

fn test_state() -> (AppState, tempfile::TempDir) {
    test_state_with_strict_streaming(true)
}

fn test_state_with_strict_streaming(strict_streaming_sigv4: bool) -> (AppState, tempfile::TempDir) {
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
        replication_full_reconcile_interval_hours: 0,
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
        strict_streaming_sigv4,
        ..ServerConfig::default()
    };
    (AppState::new(config), tmp)
}

fn auth_request(method: axum::http::Method, uri: &str, body: Body) -> axum::http::Request<Body> {
    axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("x-access-key", TEST_ACCESS_KEY)
        .header("x-secret-key", TEST_SECRET_KEY)
        .body(body)
        .unwrap()
}

fn presigned_streaming_request(uri: &str) -> axum::http::Request<Body> {
    let now = chrono::Utc::now();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date_stamp = now.format("%Y%m%d").to_string();
    let scope = format!("{}/us-east-1/s3/aws4_request", date_stamp);
    let credential = format!("{}/{}", TEST_ACCESS_KEY, scope);
    let mut params = [
        (
            "X-Amz-Algorithm".to_string(),
            "AWS4-HMAC-SHA256".to_string(),
        ),
        ("X-Amz-Credential".to_string(), credential),
        ("X-Amz-Date".to_string(), amz_date.clone()),
        ("X-Amz-Expires".to_string(), "300".to_string()),
        ("X-Amz-SignedHeaders".to_string(), "host".to_string()),
    ];
    params.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let canonical_query = params
        .iter()
        .map(|(key, value)| {
            format!(
                "{}={}",
                myfsio_auth::sigv4::aws_uri_encode(key),
                myfsio_auth::sigv4::aws_uri_encode(value)
            )
        })
        .collect::<Vec<_>>()
        .join("&");
    let canonical_request = format!(
        "PUT\n{}\n{}\nhost:localhost\n\nhost\nUNSIGNED-PAYLOAD",
        uri, canonical_query
    );
    let string_to_sign =
        myfsio_auth::sigv4::build_string_to_sign(&amz_date, &scope, &canonical_request);
    let signing_key =
        myfsio_auth::sigv4::derive_signing_key(TEST_SECRET_KEY, &date_stamp, "us-east-1", "s3");
    let signature = myfsio_auth::sigv4::compute_signature(&signing_key, &string_to_sign);
    axum::http::Request::builder()
        .method(axum::http::Method::PUT)
        .uri(format!(
            "{}?{}&X-Amz-Signature={}",
            uri, canonical_query, signature
        ))
        .header("host", "localhost")
        .header("content-encoding", "aws-chunked")
        .header("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
        .header("x-amz-decoded-content-length", "5")
        .body(Body::from("5\r\nhello\r\n0\r\n\r\n"))
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
    h.insert("x-amz-content-sha256", "abcd".repeat(16).parse().unwrap());
    assert!(!is_aws_chunked(&h));

    let mut h = HeaderMap::new();
    h.insert("content-encoding", "gzip".parse().unwrap());
    h.insert("x-amz-content-sha256", "abcd".repeat(16).parse().unwrap());
    assert!(!is_aws_chunked(&h));
}

#[test]
fn declared_body_length_picks_right_header() {
    let mut h = HeaderMap::new();
    h.insert("content-length", "10".parse().unwrap());
    h.insert("x-amz-decoded-content-length", "7".parse().unwrap());
    assert_eq!(declared_body_length(&h, false), Some(10));
    assert_eq!(declared_body_length(&h, true), Some(7));
    assert_eq!(declared_body_length(&HeaderMap::new(), false), None);
    assert_eq!(declared_body_length(&HeaderMap::new(), true), None);
}

#[tokio::test]
async fn presigned_streaming_marker_without_context_respects_strict_mode() {
    let (strict_state, _strict_tmp) = test_state_with_strict_streaming(true);
    strict_state
        .storage
        .create_bucket("strict-stream")
        .await
        .unwrap();
    let response = crate::create_router(strict_state)
        .oneshot(presigned_streaming_request("/strict-stream/object.txt"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let (compat_state, _compat_tmp) = test_state_with_strict_streaming(false);
    compat_state
        .storage
        .create_bucket("compat-stream")
        .await
        .unwrap();
    let response = crate::create_router(compat_state.clone())
        .oneshot(presigned_streaming_request("/compat-stream/object.txt"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let (_, mut body) = compat_state
        .storage
        .get_object("compat-stream", "object.txt")
        .await
        .unwrap();
    let mut bytes = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut body, &mut bytes)
        .await
        .unwrap();
    assert_eq!(bytes, b"hello");
}

fn io_error_is_incomplete_body(err: &std::io::Error) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> = err.get_ref().map(|e| e as _);
    while let Some(e) = source {
        if e.downcast_ref::<myfsio_common::error::IncompleteBodyError>()
            .is_some()
        {
            return true;
        }
        source = e.source();
    }
    false
}

#[tokio::test]
async fn enforce_declared_length_rejects_short_stream() {
    use tokio::io::AsyncReadExt;
    let stream: myfsio_storage::traits::AsyncReadStream =
        Box::pin(std::io::Cursor::new(b"abc".to_vec()));
    let mut wrapped = enforce_declared_length(stream, Some(5));
    let mut buf = Vec::new();
    let err = wrapped.read_to_end(&mut buf).await.unwrap_err();
    assert!(io_error_is_incomplete_body(&err));
}

#[tokio::test]
async fn enforce_declared_length_rejects_excess_stream() {
    use tokio::io::AsyncReadExt;
    let stream: myfsio_storage::traits::AsyncReadStream =
        Box::pin(std::io::Cursor::new(b"abcdef".to_vec()));
    let mut wrapped = enforce_declared_length(stream, Some(4));
    let mut buf = Vec::new();
    let err = wrapped.read_to_end(&mut buf).await.unwrap_err();
    assert!(io_error_is_incomplete_body(&err));
}

#[tokio::test]
async fn enforce_declared_length_maps_transport_error_to_incomplete_body() {
    use tokio::io::AsyncReadExt;
    let stream = futures::stream::iter(vec![
        Ok::<bytes::Bytes, std::io::Error>(bytes::Bytes::from_static(b"ab")),
        Err(std::io::Error::other("connection reset by peer")),
    ]);
    let reader: myfsio_storage::traits::AsyncReadStream =
        Box::pin(tokio_util::io::StreamReader::new(stream));
    let mut wrapped = enforce_declared_length(reader, Some(5));
    let mut buf = Vec::new();
    let err = wrapped.read_to_end(&mut buf).await.unwrap_err();
    assert!(io_error_is_incomplete_body(&err));
}

#[tokio::test]
async fn enforce_declared_length_accepts_exact_stream() {
    use tokio::io::AsyncReadExt;
    let stream: myfsio_storage::traits::AsyncReadStream =
        Box::pin(std::io::Cursor::new(b"abcd".to_vec()));
    let mut wrapped = enforce_declared_length(stream, Some(4));
    let mut buf = Vec::new();
    wrapped.read_to_end(&mut buf).await.unwrap();
    assert_eq!(buf, b"abcd");
}

#[tokio::test]
async fn incomplete_body_maps_to_s3_error_code() {
    let io_err = incomplete_body_io_error(5, 3);
    let s3: S3Error = myfsio_storage::error::StorageError::Io(io_err).into();
    assert_eq!(s3.code, S3ErrorCode::IncompleteBody);
    assert_eq!(s3.http_status(), 400);
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
    headers.insert("x-amz-content-sha256", "abcd".repeat(16).parse().unwrap());
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
    assert!(
        !body.contains("attacker"),
        "owner must not be the spoofed id; got: {body}"
    );
    assert!(
        body.contains("myfsio"),
        "owner must remain the existing one; got: {body}"
    );
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

fn grant_request(
    method: axum::http::Method,
    uri: &str,
    grants: &[(&str, &str)],
    body: Body,
) -> axum::http::Request<Body> {
    let mut builder = axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("x-access-key", TEST_ACCESS_KEY)
        .header("x-secret-key", TEST_SECRET_KEY);
    for (name, value) in grants {
        builder = builder.header(*name, *value);
    }
    builder.body(body).unwrap()
}

async fn response_text(response: Response) -> String {
    String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

#[tokio::test]
async fn put_object_honors_grant_headers() {
    let (state, _tmp) = test_state();
    state.storage.create_bucket("grants").await.unwrap();
    let app = crate::create_router(state);

    let response = app
        .clone()
        .oneshot(grant_request(
            axum::http::Method::PUT,
            "/grants/photo.jpg",
            &[
                ("x-amz-grant-read", "id=\"alice\", id=\"bob\""),
                (
                    "x-amz-grant-write-acp",
                    "uri=\"http://acs.amazonaws.com/groups/global/AuthenticatedUsers\"",
                ),
            ],
            Body::from("image"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .oneshot(auth_request(
            axum::http::Method::GET,
            "/grants/photo.jpg?acl",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(body.contains("<ID>alice</ID>"), "got: {body}");
    assert!(body.contains("<ID>bob</ID>"), "got: {body}");
    assert!(body.contains("AuthenticatedUsers"), "got: {body}");
    assert!(
        body.contains("<Permission>READ</Permission>"),
        "got: {body}"
    );
    assert!(
        body.contains("<Permission>WRITE_ACP</Permission>"),
        "got: {body}"
    );
}

#[tokio::test]
async fn put_object_without_grant_headers_stays_private() {
    let (state, _tmp) = test_state();
    state.storage.create_bucket("grants").await.unwrap();
    let app = crate::create_router(state);

    let response = app
        .clone()
        .oneshot(auth_request(
            axum::http::Method::PUT,
            "/grants/photo.jpg",
            Body::from("image"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .oneshot(auth_request(
            axum::http::Method::GET,
            "/grants/photo.jpg?acl",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(
        body.contains("<Permission>FULL_CONTROL</Permission>"),
        "got: {body}"
    );
    assert!(!body.contains("AllUsers"), "got: {body}");
    assert!(!body.contains("AuthenticatedUsers"), "got: {body}");
}

#[tokio::test]
async fn put_object_rejects_canned_acl_combined_with_grant_header() {
    let (state, _tmp) = test_state();
    state.storage.create_bucket("grants").await.unwrap();
    let app = crate::create_router(state);

    let response = app
        .oneshot(grant_request(
            axum::http::Method::PUT,
            "/grants/photo.jpg",
            &[
                ("x-amz-acl", "public-read"),
                ("x-amz-grant-read", "id=\"alice\""),
            ],
            Body::from("image"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("InvalidRequest"), "got: {body}");
}

#[tokio::test]
async fn put_object_rejects_invalid_grant_headers() {
    let (state, _tmp) = test_state();
    state.storage.create_bucket("grants").await.unwrap();
    let app = crate::create_router(state);

    for value in [
        "emailAddress=\"user@example.com\"",
        "id=alice",
        "team=\"alice\"",
        "uri=\"http://acs.amazonaws.com/groups/s3/LogDelivery\"",
    ] {
        let response = app
            .clone()
            .oneshot(grant_request(
                axum::http::Method::PUT,
                "/grants/photo.jpg",
                &[("x-amz-grant-read", value)],
                Body::from("image"),
            ))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "value {value:?} should be rejected"
        );
        let body = response_text(response).await;
        assert!(body.contains("InvalidArgument"), "got: {body}");
    }
}

#[tokio::test]
async fn put_object_acl_honors_grant_headers() {
    let (state, _tmp) = test_state();
    state.storage.create_bucket("grants").await.unwrap();
    state
        .storage
        .put_object(
            "grants",
            "photo.jpg",
            Box::pin(std::io::Cursor::new(b"image".to_vec())),
            None,
        )
        .await
        .unwrap();
    let app = crate::create_router(state);

    let response = app
        .clone()
        .oneshot(grant_request(
            axum::http::Method::PUT,
            "/grants/photo.jpg?acl",
            &[(
                "x-amz-grant-full-control",
                "uri=\"http://acs.amazonaws.com/groups/global/AllUsers\"",
            )],
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .oneshot(auth_request(
            axum::http::Method::GET,
            "/grants/photo.jpg?acl",
            Body::empty(),
        ))
        .await
        .unwrap();
    let body = response_text(response).await;
    assert!(body.contains("AllUsers"), "got: {body}");
    assert!(
        body.contains("<Permission>FULL_CONTROL</Permission>"),
        "got: {body}"
    );
}

#[tokio::test]
async fn put_object_acl_rejects_body_combined_with_grant_header() {
    let (state, _tmp) = test_state();
    state.storage.create_bucket("grants").await.unwrap();
    state
        .storage
        .put_object(
            "grants",
            "photo.jpg",
            Box::pin(std::io::Cursor::new(b"image".to_vec())),
            None,
        )
        .await
        .unwrap();
    let app = crate::create_router(state);

    let xml = "<AccessControlPolicy><Owner><ID>myfsio</ID></Owner>\
               <AccessControlList/></AccessControlPolicy>";
    let response = app
        .oneshot(grant_request(
            axum::http::Method::PUT,
            "/grants/photo.jpg?acl",
            &[("x-amz-grant-read", "id=\"alice\"")],
            Body::from(xml),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("InvalidRequest"), "got: {body}");
}

#[tokio::test]
async fn put_bucket_acl_honors_grant_headers() {
    let (state, _tmp) = test_state();
    state.storage.create_bucket("grants").await.unwrap();
    let app = crate::create_router(state);

    let response = app
        .clone()
        .oneshot(grant_request(
            axum::http::Method::PUT,
            "/grants?acl",
            &[(
                "x-amz-grant-read",
                "uri=\"http://acs.amazonaws.com/groups/global/AllUsers\"",
            )],
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .clone()
        .oneshot(auth_request(
            axum::http::Method::GET,
            "/grants?acl",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(body.contains("AllUsers"), "got: {body}");
    assert!(
        body.contains("<Permission>READ</Permission>"),
        "got: {body}"
    );

    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method(axum::http::Method::GET)
                .uri("/grants?list-type=2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn put_bucket_acl_rejects_body_combined_with_grant_header() {
    let (state, _tmp) = test_state();
    state.storage.create_bucket("grants").await.unwrap();
    let app = crate::create_router(state);

    let xml = "<AccessControlPolicy><Owner><ID>myfsio</ID></Owner>\
               <AccessControlList/></AccessControlPolicy>";
    let response = app
        .oneshot(grant_request(
            axum::http::Method::PUT,
            "/grants?acl",
            &[("x-amz-grant-read", "id=\"alice\"")],
            Body::from(xml),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("InvalidRequest"), "got: {body}");
}

#[tokio::test]
async fn create_bucket_honors_grant_headers() {
    let (state, _tmp) = test_state();
    let app = crate::create_router(state);

    let response = app
        .clone()
        .oneshot(grant_request(
            axum::http::Method::PUT,
            "/grants",
            &[(
                "x-amz-grant-read-acp",
                "uri=\"http://acs.amazonaws.com/groups/global/AuthenticatedUsers\"",
            )],
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .oneshot(auth_request(
            axum::http::Method::GET,
            "/grants?acl",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(body.contains("AuthenticatedUsers"), "got: {body}");
    assert!(
        body.contains("<Permission>READ_ACP</Permission>"),
        "got: {body}"
    );
}

#[tokio::test]
async fn create_bucket_rejects_invalid_grant_headers() {
    let (state, _tmp) = test_state();
    let app = crate::create_router(state);

    let response = app
        .clone()
        .oneshot(grant_request(
            axum::http::Method::PUT,
            "/grants",
            &[("x-amz-grant-write", "emailAddress=\"user@example.com\"")],
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("InvalidArgument"), "got: {body}");

    let response = app
        .oneshot(grant_request(
            axum::http::Method::PUT,
            "/grants",
            &[
                ("x-amz-acl", "private"),
                ("x-amz-grant-write", "id=\"alice\""),
            ],
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("InvalidRequest"), "got: {body}");
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
    assert!(
        page1.is_truncated,
        "max_keys=2 against 4 distinct items must be truncated"
    );
    let token = page1
        .next_token
        .clone()
        .expect("truncated response must include a continuation token");
    assert_eq!(
        page1
            .objects
            .iter()
            .map(|o| o.key.clone())
            .collect::<Vec<_>>(),
        vec!["alpha".to_string()]
    );
    assert_eq!(page1.common_prefixes, vec!["ba/".to_string()]);
    assert_eq!(token, "ba/");

    let page2 = list_with_arbitrary_delimiter(&state, "arb2", "", "/", 10, Some(token), None)
        .await
        .unwrap();
    assert!(
        page2.common_prefixes.is_empty(),
        "ba/ must not be re-emitted on resume"
    );
    let got: Vec<String> = page2.objects.iter().map(|o| o.key.clone()).collect();
    assert_eq!(got, vec!["beta".to_string(), "gamma".to_string()]);
    assert!(!page2.is_truncated);
    assert!(page2.next_token.is_none());
}
