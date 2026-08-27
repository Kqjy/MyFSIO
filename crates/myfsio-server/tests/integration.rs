use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE;
use base64::Engine;
use http_body_util::BodyExt;
use myfsio_storage::traits::{AsyncReadStream, StorageEngine};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tower::ServiceExt;

const TEST_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
const TEST_SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

fn test_app_with_iam(iam_json: serde_json::Value) -> (axum::Router, tempfile::TempDir) {
    test_app_with_iam_and(iam_json, |_| {})
}

fn test_app_with_iam_and(
    iam_json: serde_json::Value,
    adjust: impl FnOnce(&mut myfsio_server::config::ServerConfig),
) -> (axum::Router, tempfile::TempDir) {
    let tmp = tempfile::TempDir::new().unwrap();
    let iam_path = tmp.path().join(".myfsio.sys").join("config");
    std::fs::create_dir_all(&iam_path).unwrap();

    std::fs::write(iam_path.join("iam.json"), iam_json.to_string()).unwrap();

    let config = myfsio_server::config::ServerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        ui_bind_addr: "127.0.0.1:0".parse().unwrap(),
        storage_root: tmp.path().to_path_buf(),
        region: "us-east-1".to_string(),
        iam_config_path: iam_path.join("iam.json"),
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
        replication_connect_timeout_secs: 5,
        replication_read_timeout_secs: 30,
        replication_max_retries: 2,
        replication_streaming_threshold_bytes: 10_485_760,
        replication_max_failures_per_bucket: 50,
        replication_healer_enabled: false,
        replication_healer_interval_secs: 60,
        replication_healer_max_attempts: 12,
        replication_full_reconcile_interval_hours: 0,
        site_sync_enabled: false,
        site_sync_interval_secs: 60,
        site_sync_batch_size: 100,
        site_sync_connect_timeout_secs: 10,
        site_sync_read_timeout_secs: 120,
        site_sync_max_retries: 2,
        site_sync_clock_skew_tolerance: 1.0,
        ui_enabled: false,
        templates_dir: std::path::PathBuf::from("templates"),
        static_dir: std::path::PathBuf::from("static"),
        multipart_min_part_size: 1,
        allow_legacy_header_auth: true,
        ..myfsio_server::config::ServerConfig::default()
    };
    let mut config = config;
    adjust(&mut config);
    let state = myfsio_server::state::AppState::new(config);
    let app = myfsio_server::create_router(state);
    (app, tmp)
}

fn test_app_and_state() -> (
    axum::Router,
    myfsio_server::state::AppState,
    tempfile::TempDir,
) {
    let tmp = tempfile::TempDir::new().unwrap();
    let iam_path = tmp.path().join(".myfsio.sys").join("config");
    std::fs::create_dir_all(&iam_path).unwrap();

    std::fs::write(
        iam_path.join("iam.json"),
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

    let config = myfsio_server::config::ServerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        ui_bind_addr: "127.0.0.1:0".parse().unwrap(),
        storage_root: tmp.path().to_path_buf(),
        region: "us-east-1".to_string(),
        iam_config_path: iam_path.join("iam.json"),
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
        replication_connect_timeout_secs: 5,
        replication_read_timeout_secs: 30,
        replication_max_retries: 2,
        replication_streaming_threshold_bytes: 10_485_760,
        replication_max_failures_per_bucket: 50,
        replication_healer_enabled: false,
        replication_healer_interval_secs: 60,
        replication_healer_max_attempts: 12,
        replication_full_reconcile_interval_hours: 0,
        site_sync_enabled: false,
        site_sync_interval_secs: 60,
        site_sync_batch_size: 100,
        site_sync_connect_timeout_secs: 10,
        site_sync_read_timeout_secs: 120,
        site_sync_max_retries: 2,
        site_sync_clock_skew_tolerance: 1.0,
        ui_enabled: false,
        templates_dir: std::path::PathBuf::from("templates"),
        static_dir: std::path::PathBuf::from("static"),
        multipart_min_part_size: 1,
        allow_legacy_header_auth: true,
        ..myfsio_server::config::ServerConfig::default()
    };
    let state = myfsio_server::state::AppState::new(config);
    let app = myfsio_server::create_router(state.clone());
    (app, state, tmp)
}

fn test_app() -> (axum::Router, tempfile::TempDir) {
    test_app_with_iam(serde_json::json!({
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
    }))
}

fn test_app_with_rate_limits(
    default: myfsio_server::config::RateLimitSetting,
    admin: myfsio_server::config::RateLimitSetting,
) -> (axum::Router, tempfile::TempDir) {
    let tmp = tempfile::TempDir::new().unwrap();
    let iam_path = tmp.path().join(".myfsio.sys").join("config");
    std::fs::create_dir_all(&iam_path).unwrap();
    std::fs::write(
        iam_path.join("iam.json"),
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

    let config = myfsio_server::config::ServerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        ui_bind_addr: "127.0.0.1:0".parse().unwrap(),
        storage_root: tmp.path().to_path_buf(),
        iam_config_path: iam_path.join("iam.json"),
        ratelimit_default: default,
        ratelimit_list_buckets: default,
        ratelimit_bucket_ops: default,
        ratelimit_object_ops: default,
        ratelimit_head_ops: default,
        ratelimit_admin: admin,
        ui_enabled: false,
        allow_legacy_header_auth: true,
        ..myfsio_server::config::ServerConfig::default()
    };
    let state = myfsio_server::state::AppState::new(config);
    let app = myfsio_server::create_router(state);
    (app, tmp)
}

#[tokio::test]
async fn rate_limit_default_and_admin_are_independent() {
    let (app, _tmp) = test_app_with_rate_limits(
        myfsio_server::config::RateLimitSetting::new(1, 60),
        myfsio_server::config::RateLimitSetting::new(2, 60),
    );

    let first = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/myfsio/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);

    let second = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/myfsio/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(second.headers().contains_key("retry-after"));

    let admin_first = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/myfsio/admin/gc/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(admin_first.status(), StatusCode::FORBIDDEN);

    let admin_second = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/myfsio/admin/gc/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(admin_second.status(), StatusCode::FORBIDDEN);

    let admin_third = app
        .oneshot(
            Request::builder()
                .uri("/myfsio/admin/gc/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(admin_third.status(), StatusCode::SERVICE_UNAVAILABLE);
}

fn test_ui_state() -> (myfsio_server::state::AppState, tempfile::TempDir) {
    let tmp = tempfile::TempDir::new().unwrap();
    let iam_path = tmp.path().join(".myfsio.sys").join("config");
    std::fs::create_dir_all(&iam_path).unwrap();

    std::fs::write(
        iam_path.join("iam.json"),
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
    let config = myfsio_server::config::ServerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        ui_bind_addr: "127.0.0.1:0".parse().unwrap(),
        storage_root: tmp.path().to_path_buf(),
        region: "us-east-1".to_string(),
        iam_config_path: iam_path.join("iam.json"),
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
        site_sync_enabled: false,
        site_sync_interval_secs: 60,
        site_sync_batch_size: 100,
        site_sync_connect_timeout_secs: 10,
        site_sync_read_timeout_secs: 120,
        site_sync_max_retries: 2,
        site_sync_clock_skew_tolerance: 1.0,
        ui_enabled: true,
        templates_dir: manifest_dir.join("templates"),
        static_dir: manifest_dir.join("static"),
        allow_legacy_header_auth: true,
        ..myfsio_server::config::ServerConfig::default()
    };
    (myfsio_server::state::AppState::new(config), tmp)
}

fn authenticated_ui_session(state: &myfsio_server::state::AppState) -> (String, String) {
    let (session_id, mut session) = state.sessions.create();
    session.user_id = Some(TEST_ACCESS_KEY.to_string());
    session.display_name = Some("admin".to_string());
    let csrf = session.csrf_token.clone();
    state.sessions.save(&session_id, session);
    (session_id, csrf)
}

fn ui_request(method: Method, uri: &str, session_id: &str, csrf: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri).header(
        "cookie",
        format!(
            "{}={}",
            myfsio_server::session::SESSION_COOKIE_NAME,
            session_id
        ),
    );
    if let Some(token) = csrf {
        builder = builder.header(myfsio_server::session::CSRF_HEADER_NAME, token);
    }
    builder.body(Body::empty()).unwrap()
}

fn ui_form_request(
    method: Method,
    uri: &str,
    session_id: &str,
    csrf: &str,
    body: &str,
) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(
            "cookie",
            format!(
                "{}={}",
                myfsio_server::session::SESSION_COOKIE_NAME,
                session_id
            ),
        )
        .header("x-csrftoken", csrf)
        .header("x-requested-with", "XMLHttpRequest")
        .header("accept", "application/json")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn ui_json_request(
    method: Method,
    uri: &str,
    session_id: &str,
    csrf: &str,
    body: &str,
) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(
            "cookie",
            format!(
                "{}={}",
                myfsio_server::session::SESSION_COOKIE_NAME,
                session_id
            ),
        )
        .header("x-csrftoken", csrf)
        .header("x-requested-with", "XMLHttpRequest")
        .header("accept", "application/json")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn response_json(response: axum::response::Response) -> Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

fn signed_request(method: Method, uri: &str, body: Body) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("x-access-key", TEST_ACCESS_KEY)
        .header("x-secret-key", TEST_SECRET_KEY)
        .body(body)
        .unwrap()
}

fn streaming_chunk_signature(
    signing_key: &[u8],
    timestamp: &str,
    scope: &str,
    previous: &str,
    data: &[u8],
) -> String {
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256-PAYLOAD\n{}\n{}\n{}\n{}\n{}",
        timestamp,
        scope,
        previous,
        myfsio_auth::sigv4::sha256_hex(b""),
        myfsio_auth::sigv4::sha256_hex(data)
    );
    myfsio_auth::sigv4::compute_signature(signing_key, &string_to_sign)
}

fn streaming_sigv4_request(
    uri: &str,
    signed_data: &[u8],
    transmitted_data: &[u8],
    trailer: Option<(&str, &str, bool)>,
) -> Request<Body> {
    let now = chrono::Utc::now();
    let timestamp = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date_stamp = now.format("%Y%m%d").to_string();
    let scope = format!("{}/us-east-1/s3/aws4_request", date_stamp);
    let payload_type = if trailer.is_some() {
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
    } else {
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
    };
    let mut signed_headers = vec![
        ("host", "localhost".to_string()),
        ("x-amz-content-sha256", payload_type.to_string()),
        ("x-amz-date", timestamp.clone()),
        (
            "x-amz-decoded-content-length",
            signed_data.len().to_string(),
        ),
    ];
    if let Some((name, _, _)) = trailer {
        signed_headers.push(("x-amz-trailer", name.to_string()));
    }
    let signed_header_names = signed_headers
        .iter()
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join(";");
    let canonical_headers = signed_headers
        .iter()
        .map(|(name, value)| format!("{}:{}\n", name, value))
        .collect::<String>();
    let canonical_request = format!(
        "PUT\n{}\n\n{}\n{}\n{}",
        uri, canonical_headers, signed_header_names, payload_type
    );
    let signing_key =
        myfsio_auth::sigv4::derive_signing_key(TEST_SECRET_KEY, &date_stamp, "us-east-1", "s3");
    let request_string_to_sign =
        myfsio_auth::sigv4::build_string_to_sign(&timestamp, &scope, &canonical_request);
    let seed_signature =
        myfsio_auth::sigv4::compute_signature(&signing_key, &request_string_to_sign);
    let data_signature = streaming_chunk_signature(
        &signing_key,
        &timestamp,
        &scope,
        &seed_signature,
        signed_data,
    );
    let final_signature =
        streaming_chunk_signature(&signing_key, &timestamp, &scope, &data_signature, b"");
    let mut encoded = format!(
        "{:x};chunk-signature={}\r\n",
        transmitted_data.len(),
        data_signature
    )
    .into_bytes();
    encoded.extend_from_slice(transmitted_data);
    encoded.extend_from_slice(format!("\r\n0;chunk-signature={}\r\n", final_signature).as_bytes());
    if let Some((name, value, valid_signature)) = trailer {
        let canonical = format!("{}:{}\n", name, value);
        let trailer_string_to_sign = format!(
            "AWS4-HMAC-SHA256-TRAILER\n{}\n{}\n{}\n{}",
            timestamp,
            scope,
            final_signature,
            myfsio_auth::sigv4::sha256_hex(canonical.as_bytes())
        );
        let trailer_signature = if valid_signature {
            myfsio_auth::sigv4::compute_signature(&signing_key, &trailer_string_to_sign)
        } else {
            "0".repeat(64)
        };
        encoded.extend_from_slice(
            format!(
                "{}:{}\r\nx-amz-trailer-signature:{}\r\n",
                name, value, trailer_signature
            )
            .as_bytes(),
        );
    }
    encoded.extend_from_slice(b"\r\n");

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        TEST_ACCESS_KEY, scope, signed_header_names, seed_signature
    );
    let mut builder = Request::builder()
        .method(Method::PUT)
        .uri(uri)
        .header("host", "localhost")
        .header("authorization", authorization)
        .header("x-amz-date", timestamp)
        .header("x-amz-content-sha256", payload_type)
        .header("x-amz-decoded-content-length", signed_data.len())
        .header("content-encoding", "aws-chunked");
    if let Some((name, _, _)) = trailer {
        builder = builder.header("x-amz-trailer", name);
    }
    builder.body(Body::from(encoded)).unwrap()
}

const WEBSITE_INDEX_BODY: &str = "<!doctype html><h1>Home</h1>";

fn website_server_config(
    tmp: &tempfile::TempDir,
    encryption_enabled: bool,
) -> myfsio_server::config::ServerConfig {
    let iam_path = tmp.path().join(".myfsio.sys").join("config");
    std::fs::create_dir_all(&iam_path).unwrap();

    std::fs::write(
        iam_path.join("iam.json"),
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

    myfsio_server::config::ServerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        ui_bind_addr: "127.0.0.1:0".parse().unwrap(),
        storage_root: tmp.path().to_path_buf(),
        region: "us-east-1".to_string(),
        iam_config_path: iam_path.join("iam.json"),
        sigv4_timestamp_tolerance_secs: 900,
        presigned_url_min_expiry: 1,
        presigned_url_max_expiry: 604800,
        secret_key: None,
        encryption_enabled,
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
        website_hosting_enabled: true,
        replication_connect_timeout_secs: 5,
        replication_read_timeout_secs: 30,
        replication_max_retries: 2,
        replication_streaming_threshold_bytes: 10_485_760,
        replication_max_failures_per_bucket: 50,
        replication_healer_enabled: false,
        replication_healer_interval_secs: 60,
        replication_healer_max_attempts: 12,
        replication_full_reconcile_interval_hours: 0,
        site_sync_enabled: false,
        site_sync_interval_secs: 60,
        site_sync_batch_size: 100,
        site_sync_connect_timeout_secs: 10,
        site_sync_read_timeout_secs: 120,
        site_sync_max_retries: 2,
        site_sync_clock_skew_tolerance: 1.0,
        ui_enabled: false,
        templates_dir: std::path::PathBuf::from("templates"),
        static_dir: std::path::PathBuf::from("static"),
        allow_legacy_header_auth: true,
        ..myfsio_server::config::ServerConfig::default()
    }
}

fn test_website_state() -> (myfsio_server::state::AppState, tempfile::TempDir) {
    let tmp = tempfile::TempDir::new().unwrap();
    let config = website_server_config(&tmp, false);
    (myfsio_server::state::AppState::new(config), tmp)
}

async fn test_encrypted_website_app() -> (axum::Router, tempfile::TempDir) {
    let tmp = tempfile::TempDir::new().unwrap();
    let config = website_server_config(&tmp, true);
    let state = myfsio_server::state::AppState::new_with_encryption(config)
        .await
        .expect("encryption initialization should succeed");

    let bucket = "enc-site-bucket";
    state.storage.create_bucket(bucket).await.unwrap();
    let mut bucket_config = state.storage.get_bucket_config(bucket).await.unwrap();
    bucket_config.website = Some(serde_json::json!({ "index_document": "index.html" }));
    bucket_config.encryption = Some(serde_json::json!({ "sse_algorithm": "AES256" }));
    state
        .storage
        .set_bucket_config(bucket, &bucket_config)
        .await
        .unwrap();
    state
        .website_domains
        .as_ref()
        .unwrap()
        .set_mapping("site.example.com", bucket);

    (myfsio_server::create_router(state), tmp)
}

fn website_object_put_request(
    uri: &str,
    body: &str,
    sse_c_key: Option<&[u8; 32]>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(Method::PUT)
        .uri(uri)
        .header("host", "localhost")
        .header("x-access-key", TEST_ACCESS_KEY)
        .header("x-secret-key", TEST_SECRET_KEY)
        .header("content-type", "text/html");
    if let Some(key) = sse_c_key {
        let (key_b64, md5_b64) = sse_c_triplet(key);
        builder = builder
            .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
            .header("x-amz-server-side-encryption-customer-key", key_b64)
            .header("x-amz-server-side-encryption-customer-key-MD5", md5_b64);
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

async fn put_website_object(
    state: &myfsio_server::state::AppState,
    bucket: &str,
    key: &str,
    body: &str,
    content_type: &str,
) {
    let mut metadata = HashMap::new();
    metadata.insert("__content_type__".to_string(), content_type.to_string());
    let reader: AsyncReadStream = Box::pin(std::io::Cursor::new(body.as_bytes().to_vec()));
    state
        .storage
        .put_object(bucket, key, reader, Some(metadata))
        .await
        .unwrap();
}

async fn test_website_app(error_document: Option<&str>) -> (axum::Router, tempfile::TempDir) {
    let (state, tmp) = test_website_state();
    let bucket = "site-bucket";

    state.storage.create_bucket(bucket).await.unwrap();
    put_website_object(
        &state,
        bucket,
        "index.html",
        WEBSITE_INDEX_BODY,
        "text/html",
    )
    .await;
    if let Some(error_key) = error_document {
        put_website_object(
            &state,
            bucket,
            error_key,
            "<!doctype html><h1>Bucket Not Found Page</h1>",
            "text/html",
        )
        .await;
    }

    let mut config = state.storage.get_bucket_config(bucket).await.unwrap();
    config.website = Some(match error_document {
        Some(error_key) => serde_json::json!({
            "index_document": "index.html",
            "error_document": error_key,
        }),
        None => serde_json::json!({
            "index_document": "index.html",
        }),
    });
    state
        .storage
        .set_bucket_config(bucket, &config)
        .await
        .unwrap();
    state
        .website_domains
        .as_ref()
        .unwrap()
        .set_mapping("site.example.com", bucket);

    (myfsio_server::create_router(state), tmp)
}

fn website_request(method: Method, uri: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("Host", "site.example.com")
        .body(Body::empty())
        .unwrap()
}

fn website_range_request(uri: &str, range: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("Host", "site.example.com")
        .header("Range", range)
        .body(Body::empty())
        .unwrap()
}

fn parse_select_events(body: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut idx: usize = 0;

    while idx + 16 <= body.len() {
        let total_len =
            u32::from_be_bytes([body[idx], body[idx + 1], body[idx + 2], body[idx + 3]]) as usize;
        let headers_len =
            u32::from_be_bytes([body[idx + 4], body[idx + 5], body[idx + 6], body[idx + 7]])
                as usize;
        if total_len < 16 || idx + total_len > body.len() {
            break;
        }

        let headers_start = idx + 12;
        let headers_end = headers_start + headers_len;
        if headers_end > idx + total_len - 4 {
            break;
        }

        let mut event_type: Option<String> = None;
        let mut hidx = headers_start;
        while hidx < headers_end {
            let name_len = body[hidx] as usize;
            hidx += 1;
            if hidx + name_len + 3 > headers_end {
                break;
            }
            let name = String::from_utf8_lossy(&body[hidx..hidx + name_len]).to_string();
            hidx += name_len;

            let value_type = body[hidx];
            hidx += 1;
            if value_type != 7 || hidx + 2 > headers_end {
                break;
            }

            let value_len = u16::from_be_bytes([body[hidx], body[hidx + 1]]) as usize;
            hidx += 2;
            if hidx + value_len > headers_end {
                break;
            }

            let value = String::from_utf8_lossy(&body[hidx..hidx + value_len]).to_string();
            hidx += value_len;

            if name == ":event-type" {
                event_type = Some(value);
            }
        }

        let payload_start = headers_end;
        let payload_end = idx + total_len - 4;
        let payload = body[payload_start..payload_end].to_vec();

        out.push((event_type.unwrap_or_default(), payload));
        idx += total_len;
    }

    out
}

#[tokio::test]
async fn test_ui_replication_endpoints_are_wired_and_operational() {
    let (state, _tmp) = test_ui_state();
    let bucket_name = "replicated-bucket";

    state
        .replication
        .set_rule(myfsio_server::services::replication::ReplicationRule {
            bucket_name: bucket_name.to_string(),
            target_connection_id: "missing-connection".to_string(),
            target_bucket: "remote-bucket".to_string(),
            enabled: true,
            mode: myfsio_server::services::replication::MODE_NEW_ONLY.to_string(),
            created_at: Some(1_700_000_000.0),
            stats: myfsio_server::services::replication::ReplicationStats {
                objects_synced: 3,
                objects_pending: 1,
                objects_orphaned: 0,
                bytes_synced: 123,
                last_sync_at: Some(1_700_000_100.0),
                last_sync_key: Some("folder/item.txt".to_string()),
            },
            sync_deletions: true,
            last_pull_at: None,
            filter_prefix: None,
        })
        .unwrap();

    state.replication.failures.add(
        bucket_name,
        myfsio_server::services::replication::ReplicationFailure {
            object_key: "folder/item.txt".to_string(),
            error_message: "temporary failure".to_string(),
            timestamp: 1_700_000_200.0,
            failure_count: 2,
            bucket_name: bucket_name.to_string(),
            action: "put".to_string(),
            last_error_code: Some("SlowDown".to_string()),
            pending_upload_id: None,
            pending_source_size: None,
            pending_source_etag: None,
            pending_part_size: None,
            permanent: false,
        },
    );
    state.replication.failures.add(
        bucket_name,
        myfsio_server::services::replication::ReplicationFailure {
            object_key: "other.txt".to_string(),
            error_message: "another failure".to_string(),
            timestamp: 1_700_000_300.0,
            failure_count: 1,
            bucket_name: bucket_name.to_string(),
            action: "put".to_string(),
            last_error_code: None,
            pending_upload_id: None,
            pending_source_size: None,
            pending_source_etag: None,
            pending_part_size: None,
            permanent: false,
        },
    );

    let (session_id, csrf) = authenticated_ui_session(&state);
    let app = myfsio_server::create_ui_router(state.clone());

    let status_resp = app
        .clone()
        .oneshot(ui_request(
            Method::GET,
            &format!("/ui/buckets/{}/replication/status", bucket_name),
            &session_id,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(status_resp.status(), StatusCode::OK);
    let status_body: Value =
        serde_json::from_slice(&status_resp.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(status_body["objects_synced"], 3);
    assert_eq!(status_body["objects_pending"], 1);
    assert_eq!(status_body["endpoint_healthy"], false);
    assert_eq!(status_body["endpoint_error"], "Target connection not found");

    let failures_resp = app
        .clone()
        .oneshot(ui_request(
            Method::GET,
            &format!("/ui/buckets/{}/replication/failures?limit=10", bucket_name),
            &session_id,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(failures_resp.status(), StatusCode::OK);
    let failures_body: Value = serde_json::from_slice(
        &failures_resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    assert_eq!(failures_body["total"], 2);
    assert_eq!(failures_body["failures"].as_array().unwrap().len(), 2);

    let retry_resp = app
        .clone()
        .oneshot(ui_request(
            Method::POST,
            &format!(
                "/ui/buckets/{}/replication/failures/retry?object_key=folder%2Fitem.txt",
                bucket_name
            ),
            &session_id,
            Some(&csrf),
        ))
        .await
        .unwrap();
    assert_eq!(retry_resp.status(), StatusCode::BAD_REQUEST);

    let dismiss_resp = app
        .clone()
        .oneshot(ui_request(
            Method::DELETE,
            &format!(
                "/ui/buckets/{}/replication/failures/dismiss?object_key=folder%2Fitem.txt",
                bucket_name
            ),
            &session_id,
            Some(&csrf),
        ))
        .await
        .unwrap();
    assert_eq!(dismiss_resp.status(), StatusCode::OK);
    let dismiss_body: Value =
        serde_json::from_slice(&dismiss_resp.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(dismiss_body["status"], "dismissed");

    let clear_resp = app
        .clone()
        .oneshot(ui_request(
            Method::DELETE,
            &format!("/ui/buckets/{}/replication/failures/clear", bucket_name),
            &session_id,
            Some(&csrf),
        ))
        .await
        .unwrap();
    assert_eq!(clear_resp.status(), StatusCode::OK);
    let clear_body: Value =
        serde_json::from_slice(&clear_resp.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(clear_body["status"], "cleared");

    let failures_after_clear = app
        .oneshot(ui_request(
            Method::GET,
            &format!("/ui/buckets/{}/replication/failures?limit=10", bucket_name),
            &session_id,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(failures_after_clear.status(), StatusCode::OK);
    let failures_after_clear_body: Value = serde_json::from_slice(
        &failures_after_clear
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    assert_eq!(failures_after_clear_body["total"], 0);
}

#[tokio::test]
async fn test_ui_replication_configuration_actions_work() {
    let (state, _tmp) = test_ui_state();
    let bucket_name = "config-bucket";
    state.storage.create_bucket(bucket_name).await.unwrap();
    state
        .connections
        .add(myfsio_server::stores::connections::RemoteConnection {
            id: "conn-1".to_string(),
            name: "Remote".to_string(),
            endpoint_url: "http://127.0.0.1:1".to_string(),
            access_key: "remote-key".to_string(),
            secret_key: "remote-secret".to_string(),
            region: "us-east-1".to_string(),
            tuning: None,
        })
        .unwrap();

    let (session_id, csrf) = authenticated_ui_session(&state);
    let app = myfsio_server::create_ui_router(state.clone());

    let create_resp = app
        .clone()
        .oneshot(ui_form_request(
            Method::POST,
            &format!("/ui/buckets/{}/replication", bucket_name),
            &session_id,
            &csrf,
            "action=create&target_connection_id=conn-1&target_bucket=remote-bucket&replication_mode=all&csrf_token=test",
        ))
        .await
        .unwrap();
    assert_eq!(create_resp.status(), StatusCode::OK);
    let create_body: Value =
        serde_json::from_slice(&create_resp.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(create_body["action"], "create");
    assert_eq!(create_body["mode"], "all");
    assert_eq!(create_body["enabled"], true);
    let rule = state.replication.get_rule(bucket_name).unwrap();
    assert_eq!(rule.target_connection_id, "conn-1");
    assert_eq!(rule.target_bucket, "remote-bucket");
    assert!(rule.enabled);
    assert_eq!(rule.mode, "all");

    let pause_resp = app
        .clone()
        .oneshot(ui_form_request(
            Method::POST,
            &format!("/ui/buckets/{}/replication", bucket_name),
            &session_id,
            &csrf,
            "action=pause&csrf_token=test",
        ))
        .await
        .unwrap();
    assert_eq!(pause_resp.status(), StatusCode::OK);
    assert!(!state.replication.get_rule(bucket_name).unwrap().enabled);

    let resume_resp = app
        .clone()
        .oneshot(ui_form_request(
            Method::POST,
            &format!("/ui/buckets/{}/replication", bucket_name),
            &session_id,
            &csrf,
            "action=resume&csrf_token=test",
        ))
        .await
        .unwrap();
    assert_eq!(resume_resp.status(), StatusCode::OK);
    assert!(state.replication.get_rule(bucket_name).unwrap().enabled);

    let delete_resp = app
        .oneshot(ui_form_request(
            Method::POST,
            &format!("/ui/buckets/{}/replication", bucket_name),
            &session_id,
            &csrf,
            "action=delete&csrf_token=test",
        ))
        .await
        .unwrap();
    assert_eq!(delete_resp.status(), StatusCode::OK);
    assert!(state.replication.get_rule(bucket_name).is_none());
}

#[tokio::test]
async fn test_create_bidirectional_rule_requires_peer_inbound_access_key() {
    let (state, _tmp) = test_ui_state();
    let bucket_name = "bidir-bucket";
    state.storage.create_bucket(bucket_name).await.unwrap();
    state
        .connections
        .add(myfsio_server::stores::connections::RemoteConnection {
            id: "conn-bidir".to_string(),
            name: "Peer".to_string(),
            endpoint_url: "http://127.0.0.1:1".to_string(),
            access_key: "remote-key".to_string(),
            secret_key: "remote-secret".to_string(),
            region: "us-east-1".to_string(),
            tuning: None,
        })
        .unwrap();

    let registry = state.site_registry.as_ref().expect("site_registry").clone();
    registry.add_peer(myfsio_server::services::site_registry::PeerSite {
        site_id: "peer-site".to_string(),
        endpoint: "http://peer.example.com".to_string(),
        region: "us-east-1".to_string(),
        priority: 100,
        display_name: "Peer Site".to_string(),
        connection_id: Some("conn-bidir".to_string()),
        peer_inbound_access_key: None,
        created_at: None,
        is_healthy: false,
        last_health_check: None,
    });

    let (session_id, csrf) = authenticated_ui_session(&state);
    let app = myfsio_server::create_ui_router(state.clone());

    let resp = app
        .clone()
        .oneshot(ui_form_request(
            Method::POST,
            &format!("/ui/buckets/{}/replication", bucket_name),
            &session_id,
            &csrf,
            "action=create&target_connection_id=conn-bidir&target_bucket=remote-bucket&replication_mode=bidirectional&csrf_token=test",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let err = body["error"].as_str().unwrap_or_default();
    assert!(
        err.to_lowercase().contains("inbound access key") || err.to_lowercase().contains("loop"),
        "expected loop guard error, got: {}",
        err
    );
    assert!(
        state.replication.get_rule(bucket_name).is_none(),
        "rule must NOT be created when bidirectional + missing peer_inbound_access_key"
    );
}

#[tokio::test]
async fn test_create_bidirectional_rule_succeeds_when_peer_ak_set() {
    let (state, _tmp) = test_ui_state();
    let bucket_name = "bidir-bucket-ok";
    state.storage.create_bucket(bucket_name).await.unwrap();
    state
        .connections
        .add(myfsio_server::stores::connections::RemoteConnection {
            id: "conn-bidir-ok".to_string(),
            name: "Peer".to_string(),
            endpoint_url: "http://127.0.0.1:1".to_string(),
            access_key: "remote-key".to_string(),
            secret_key: "remote-secret".to_string(),
            region: "us-east-1".to_string(),
            tuning: None,
        })
        .unwrap();

    let registry = state.site_registry.as_ref().expect("site_registry").clone();
    registry.add_peer(myfsio_server::services::site_registry::PeerSite {
        site_id: "peer-site-ok".to_string(),
        endpoint: "http://peer.example.com".to_string(),
        region: "us-east-1".to_string(),
        priority: 100,
        display_name: "Peer Site".to_string(),
        connection_id: Some("conn-bidir-ok".to_string()),
        peer_inbound_access_key: Some("AKIAPEERINBOUND00000".to_string()),
        created_at: None,
        is_healthy: false,
        last_health_check: None,
    });

    let (session_id, csrf) = authenticated_ui_session(&state);
    let app = myfsio_server::create_ui_router(state.clone());

    let resp = app
        .oneshot(ui_form_request(
            Method::POST,
            &format!("/ui/buckets/{}/replication", bucket_name),
            &session_id,
            &csrf,
            "action=create&target_connection_id=conn-bidir-ok&target_bucket=remote-bucket&replication_mode=bidirectional&csrf_token=test",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["mode"], "bidirectional");
    let rule = state
        .replication
        .get_rule(bucket_name)
        .expect("rule created");
    assert_eq!(
        rule.mode,
        myfsio_server::services::replication::MODE_BIDIRECTIONAL
    );
}

#[tokio::test]
async fn test_create_unidirectional_rule_does_not_require_peer_ak() {
    let (state, _tmp) = test_ui_state();
    let bucket_name = "uni-bucket";
    state.storage.create_bucket(bucket_name).await.unwrap();
    state
        .connections
        .add(myfsio_server::stores::connections::RemoteConnection {
            id: "conn-uni".to_string(),
            name: "Peer".to_string(),
            endpoint_url: "http://127.0.0.1:1".to_string(),
            access_key: "remote-key".to_string(),
            secret_key: "remote-secret".to_string(),
            region: "us-east-1".to_string(),
            tuning: None,
        })
        .unwrap();

    let registry = state.site_registry.as_ref().expect("site_registry").clone();
    registry.add_peer(myfsio_server::services::site_registry::PeerSite {
        site_id: "peer-uni".to_string(),
        endpoint: "http://peer.example.com".to_string(),
        region: "us-east-1".to_string(),
        priority: 100,
        display_name: "Peer Site".to_string(),
        connection_id: Some("conn-uni".to_string()),
        peer_inbound_access_key: None,
        created_at: None,
        is_healthy: false,
        last_health_check: None,
    });

    let (session_id, csrf) = authenticated_ui_session(&state);
    let app = myfsio_server::create_ui_router(state.clone());

    for mode in ["new_only", "all"] {
        let resp = app
            .clone()
            .oneshot(ui_form_request(
                Method::POST,
                &format!("/ui/buckets/{}/replication", bucket_name),
                &session_id,
                &csrf,
                &format!(
                    "action=create&target_connection_id=conn-uni&target_bucket=remote-bucket&replication_mode={}&csrf_token=test",
                    mode
                ),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "mode {} should not require peer_inbound_access_key",
            mode
        );
        let rule = state.replication.get_rule(bucket_name).expect("rule");
        assert_eq!(rule.mode, mode);
    }
}

#[test]
fn test_rule_requires_inbound_ak_helper() {
    use myfsio_server::services::replication::{
        rule_requires_inbound_ak, MODE_ALL, MODE_BIDIRECTIONAL, MODE_NEW_ONLY,
    };
    assert!(rule_requires_inbound_ak(MODE_BIDIRECTIONAL));
    assert!(!rule_requires_inbound_ak(MODE_NEW_ONLY));
    assert!(!rule_requires_inbound_ak(MODE_ALL));
    assert!(!rule_requires_inbound_ak("unknown"));
}

#[test]
fn test_find_peer_by_connection_id() {
    let tmp = tempfile::TempDir::new().unwrap();
    let registry = myfsio_server::services::site_registry::SiteRegistry::new(tmp.path());
    registry.add_peer(myfsio_server::services::site_registry::PeerSite {
        site_id: "site-a".to_string(),
        endpoint: "http://a.example.com".to_string(),
        region: "us-east-1".to_string(),
        priority: 100,
        display_name: "A".to_string(),
        connection_id: Some("conn-a".to_string()),
        peer_inbound_access_key: Some("AKIAA00000000000000A".to_string()),
        created_at: None,
        is_healthy: false,
        last_health_check: None,
    });
    registry.add_peer(myfsio_server::services::site_registry::PeerSite {
        site_id: "site-b".to_string(),
        endpoint: "http://b.example.com".to_string(),
        region: "us-east-1".to_string(),
        priority: 100,
        display_name: "B".to_string(),
        connection_id: None,
        peer_inbound_access_key: None,
        created_at: None,
        is_healthy: false,
        last_health_check: None,
    });

    let found = registry.find_peer_by_connection_id("conn-a").unwrap();
    assert_eq!(found.site_id, "site-a");
    assert!(registry.find_peer_by_connection_id("missing").is_none());
    assert!(registry.find_peer_by_connection_id("").is_none());
}

#[tokio::test]
async fn test_ui_iam_user_actions_use_real_user_ids() {
    let (state, _tmp) = test_ui_state();
    let (session_id, csrf) = authenticated_ui_session(&state);
    let app = myfsio_server::create_ui_router(state.clone());

    let iam_page = app
        .clone()
        .oneshot(ui_request(Method::GET, "/ui/iam", &session_id, None))
        .await
        .unwrap();
    assert_eq!(iam_page.status(), StatusCode::OK);
    let iam_page_body = String::from_utf8(
        iam_page
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(iam_page_body.contains("/ui/iam/users/u-test1234"));
    assert!(!iam_page_body.contains("{user_id}"));

    let update_resp = app
        .clone()
        .oneshot(ui_form_request(
            Method::POST,
            "/ui/iam/users/u-test1234",
            &session_id,
            &csrf,
            "display_name=Updated+Admin&csrf_token=test",
        ))
        .await
        .unwrap();
    assert_eq!(update_resp.status(), StatusCode::OK);
    let update_body: Value =
        serde_json::from_slice(&update_resp.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(update_body["display_name"], "Updated Admin");

    let policies_json = serde_json::json!([
        {"bucket": "*", "actions": ["*"], "prefix": "*"},
        {"bucket": "reports", "actions": ["list", "read"], "prefix": "*"}
    ]);
    let policies_encoded = percent_encoding::utf8_percent_encode(
        &policies_json.to_string(),
        percent_encoding::NON_ALPHANUMERIC,
    )
    .to_string();
    let policies_resp = app
        .clone()
        .oneshot(ui_form_request(
            Method::POST,
            "/ui/iam/users/u-test1234/policies",
            &session_id,
            &csrf,
            &format!("policies={}&csrf_token=test", policies_encoded),
        ))
        .await
        .unwrap();
    assert_eq!(policies_resp.status(), StatusCode::OK);
    let policies_body: Value = serde_json::from_slice(
        &policies_resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    let bucket_set: std::collections::HashSet<String> = policies_body["policies"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|p| p["bucket"].as_str().map(|s| s.to_string()))
        .collect();
    assert!(bucket_set.contains("reports"));

    let create_resp = app
        .clone()
        .oneshot(ui_form_request(
            Method::POST,
            "/ui/iam/users",
            &session_id,
            &csrf,
            "display_name=Alice&access_key=ALICEKEY123&secret_key=alice-secret&csrf_token=test",
        ))
        .await
        .unwrap();
    assert_eq!(create_resp.status(), StatusCode::OK);
    let create_body: Value =
        serde_json::from_slice(&create_resp.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    let created_user_id = create_body["user_id"].as_str().unwrap().to_string();

    let delete_resp = app
        .oneshot(ui_form_request(
            Method::POST,
            &format!("/ui/iam/users/{}/delete", created_user_id),
            &session_id,
            &csrf,
            "csrf_token=test",
        ))
        .await
        .unwrap();
    assert_eq!(delete_resp.status(), StatusCode::OK);
    assert!(state.iam.get_user(&created_user_id).await.is_none());
}

#[tokio::test]
async fn test_ui_presign_reports_clamping_and_rejects_invalid_expiry() {
    let (state, _tmp) = test_ui_state();
    let bucket_name = "presign-ui";
    state.storage.create_bucket(bucket_name).await.unwrap();
    put_website_object(&state, bucket_name, "file.txt", "hello", "text/plain").await;
    let (session_id, csrf) = authenticated_ui_session(&state);
    let app = myfsio_server::create_ui_router(state);
    let endpoint = format!("/ui/buckets/{}/objects/file.txt/presign", bucket_name);

    let clamped_response = app
        .clone()
        .oneshot(ui_json_request(
            Method::POST,
            &endpoint,
            &session_id,
            &csrf,
            r#"{"method":"GET","expires_in":9999999}"#,
        ))
        .await
        .unwrap();
    assert_eq!(clamped_response.status(), StatusCode::OK);
    let clamped = response_json(clamped_response).await;
    assert_eq!(clamped["expires_in"], 604800);
    assert_eq!(clamped["effective_expires_in"], 604800);
    assert_eq!(clamped["clamped"], true);
    assert!(clamped["url"]
        .as_str()
        .unwrap()
        .contains("X-Amz-Expires=604800"));

    for invalid in [r#""""#, r#""not-a-number""#] {
        let response = app
            .clone()
            .oneshot(ui_json_request(
                Method::POST,
                &endpoint,
                &session_id,
                &csrf,
                &format!(r#"{{"method":"GET","expires_in":{invalid}}}"#),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response_json(response).await;
        assert_eq!(body["error"], "Expiry must be a whole number of seconds");
    }
}

#[tokio::test]
async fn test_ui_pdf_preview_rejects_mismatched_magic() {
    let (state, _tmp) = test_ui_state();
    let bucket_name = "preview-ui";
    state.storage.create_bucket(bucket_name).await.unwrap();
    put_website_object(
        &state,
        bucket_name,
        "broken.pdf",
        "this is not a PDF",
        "application/pdf",
    )
    .await;
    let (session_id, _csrf) = authenticated_ui_session(&state);
    let app = myfsio_server::create_ui_router(state);

    let response = app
        .oneshot(ui_request(
            Method::GET,
            &format!("/ui/buckets/{}/objects/broken.pdf/preview", bucket_name),
            &session_id,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert!(response
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("application/json"));
    let body = response_json(response).await;
    assert_eq!(body["preview_unavailable"], true);
    assert_eq!(body["error"], "Preview unavailable — Download to view");
}

#[tokio::test]
async fn test_ui_bucket_detail_hides_buckets_the_user_cannot_list() {
    let (state, _tmp) = test_ui_state();
    state.storage.create_bucket("visible-bucket").await.unwrap();
    state.storage.create_bucket("secret-bucket").await.unwrap();

    let created = state
        .iam
        .create_user(
            "scoped",
            Some(vec![myfsio_auth::iam::IamPolicy::allow(
                "visible-bucket",
                &["list", "read"],
            )]),
            None,
            None,
            None,
        )
        .unwrap();
    let scoped_key = created["access_key"].as_str().unwrap().to_string();

    let (session_id, mut session) = state.sessions.create();
    session.user_id = Some(scoped_key);
    session.display_name = Some("scoped".to_string());
    let csrf = session.csrf_token.clone();
    state.sessions.save(&session_id, session);

    let app = myfsio_server::create_ui_router(state.clone());

    let resp = app
        .clone()
        .oneshot(ui_request(
            Method::GET,
            "/ui/buckets/secret-bucket",
            &session_id,
            Some(&csrf),
        ))
        .await
        .unwrap();
    assert!(
        resp.status().is_redirection(),
        "a bucket the user cannot list must not render its detail page"
    );
    assert_eq!(
        resp.headers()
            .get(axum::http::header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/ui/buckets")
    );

    let resp = app
        .oneshot(ui_request(
            Method::GET,
            "/ui/buckets/visible-bucket",
            &session_id,
            Some(&csrf),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_ui_expired_session_401_shape_is_unchanged() {
    let (state, _tmp) = test_ui_state();
    let (session_id, mut session) = state.sessions.create();
    session.user_id = Some("missing-access-key".to_string());
    let csrf = session.csrf_token.clone();
    state.sessions.save(&session_id, session);
    let app = myfsio_server::create_ui_router(state);

    let response = app
        .oneshot(ui_request(
            Method::GET,
            "/ui/buckets/any-bucket/stats",
            &session_id,
            Some(&csrf),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = response_json(response).await;
    assert_eq!(
        body,
        serde_json::json!({"error": "Your session is no longer valid."})
    );
}

#[tokio::test]
async fn test_ui_bucket_panels_and_history_endpoints_round_trip() {
    let (state, _tmp) = test_ui_state();
    let bucket_name = "ui-bucket";
    state.storage.create_bucket(bucket_name).await.unwrap();

    let (session_id, csrf) = authenticated_ui_session(&state);
    let app = myfsio_server::create_ui_router(state.clone());

    let policy_json = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": ["s3:GetObject"],
            "Resource": [format!("arn:aws:s3:::{}/*", bucket_name)]
        }]
    });
    let policy_encoded = percent_encoding::utf8_percent_encode(
        &policy_json.to_string(),
        percent_encoding::NON_ALPHANUMERIC,
    )
    .to_string();
    let policy_resp = app
        .clone()
        .oneshot(ui_form_request(
            Method::POST,
            &format!("/ui/buckets/{}/policy", bucket_name),
            &session_id,
            &csrf,
            &format!(
                "mode=upsert&policy_document={}&csrf_token=test",
                policy_encoded
            ),
        ))
        .await
        .unwrap();
    assert_eq!(policy_resp.status(), StatusCode::OK);
    let policy_body: Value =
        serde_json::from_slice(&policy_resp.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(policy_body["ok"], true);
    let bucket_config = state.storage.get_bucket_config(bucket_name).await.unwrap();
    assert_eq!(bucket_config.policy.unwrap(), policy_json);

    let cors_resp = app
        .clone()
        .oneshot(ui_json_request(
            Method::POST,
            &format!("/ui/buckets/{}/cors", bucket_name),
            &session_id,
            &csrf,
            r#"{"rules":[{"AllowedOrigins":["https://example.com"],"AllowedMethods":["GET","PUT"],"AllowedHeaders":["*"],"ExposeHeaders":["ETag"],"MaxAgeSeconds":600}]}"#,
        ))
        .await
        .unwrap();
    assert_eq!(cors_resp.status(), StatusCode::OK);
    let cors_get = app
        .clone()
        .oneshot(ui_request(
            Method::GET,
            &format!("/ui/buckets/{}/cors", bucket_name),
            &session_id,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(cors_get.status(), StatusCode::OK);
    let cors_body: Value =
        serde_json::from_slice(&cors_get.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(cors_body["rules"].as_array().unwrap().len(), 1);

    let lifecycle_resp = app
        .clone()
        .oneshot(ui_json_request(
            Method::POST,
            &format!("/ui/buckets/{}/lifecycle", bucket_name),
            &session_id,
            &csrf,
            r#"{"rules":[{"ID":"expire-logs","Status":"Enabled","Filter":{"Prefix":"logs/"},"Expiration":{"Days":30}}]}"#,
        ))
        .await
        .unwrap();
    assert_eq!(lifecycle_resp.status(), StatusCode::OK);
    let lifecycle_get = app
        .clone()
        .oneshot(ui_request(
            Method::GET,
            &format!("/ui/buckets/{}/lifecycle", bucket_name),
            &session_id,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(lifecycle_get.status(), StatusCode::OK);
    let lifecycle_body: Value = serde_json::from_slice(
        &lifecycle_get
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    assert_eq!(lifecycle_body["rules"].as_array().unwrap().len(), 1);

    let gc_history = app
        .clone()
        .oneshot(ui_request(
            Method::GET,
            "/ui/system/gc/history",
            &session_id,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(gc_history.status(), StatusCode::OK);
    let gc_body: Value =
        serde_json::from_slice(&gc_history.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert!(gc_body["executions"].is_array());

    let integrity_history = app
        .oneshot(ui_request(
            Method::GET,
            "/ui/system/integrity/history",
            &session_id,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(integrity_history.status(), StatusCode::OK);
    let integrity_body: Value = serde_json::from_slice(
        &integrity_history
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    assert!(integrity_body["executions"].is_array());
}

#[tokio::test]
async fn test_ui_bucket_policy_preset_reflects_private_and_public_states() {
    let (state, _tmp) = test_ui_state();
    let bucket_name = "preset-bucket";
    state.storage.create_bucket(bucket_name).await.unwrap();

    let (session_id, _csrf) = authenticated_ui_session(&state);
    let app = myfsio_server::create_ui_router(state.clone());

    let private_resp = app
        .clone()
        .oneshot(ui_request(
            Method::GET,
            &format!("/ui/buckets/{}?tab=permissions", bucket_name),
            &session_id,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(private_resp.status(), StatusCode::OK);
    let private_html = String::from_utf8(
        private_resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(private_html.contains(
        "id=\"policyPreset\" name=\"preset\" value=\"private\" data-default=\"private\""
    ));

    let public_policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowList",
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["s3:ListBucket"],
                "Resource": [format!("arn:aws:s3:::{}", bucket_name)],
            },
            {
                "Sid": "AllowRead",
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["s3:GetObject"],
                "Resource": [format!("arn:aws:s3:::{}/*", bucket_name)],
            }
        ]
    });
    let mut config = state.storage.get_bucket_config(bucket_name).await.unwrap();
    config.policy = Some(public_policy);
    state
        .storage
        .set_bucket_config(bucket_name, &config)
        .await
        .unwrap();

    let public_resp = app
        .clone()
        .oneshot(ui_request(
            Method::GET,
            &format!("/ui/buckets/{}?tab=permissions", bucket_name),
            &session_id,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(public_resp.status(), StatusCode::OK);
    let public_html = String::from_utf8(
        public_resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(public_html
        .contains("id=\"policyPreset\" name=\"preset\" value=\"public\" data-default=\"public\""));
    assert!(public_html.contains("Public Read"));

    let overview_resp = app
        .oneshot(ui_request(Method::GET, "/ui/buckets", &session_id, None))
        .await
        .unwrap();
    assert_eq!(overview_resp.status(), StatusCode::OK);
    let overview_html = String::from_utf8(
        overview_resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(overview_html.contains("Public Read"));
}

#[tokio::test]
async fn test_ui_metrics_history_endpoint_reads_system_history() {
    let tmp = tempfile::TempDir::new().unwrap();
    let config_root = tmp.path().join(".myfsio.sys").join("config");
    std::fs::create_dir_all(&config_root).unwrap();
    std::fs::write(
        config_root.join("iam.json"),
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
    std::fs::write(
        config_root.join("metrics_history.json"),
        serde_json::json!({
            "history": [{
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "cpu_percent": 12.5,
                "memory_percent": 33.3,
                "disk_percent": 44.4,
                "storage_bytes": 1024
            }]
        })
        .to_string(),
    )
    .unwrap();

    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let config = myfsio_server::config::ServerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        ui_bind_addr: "127.0.0.1:0".parse().unwrap(),
        storage_root: tmp.path().to_path_buf(),
        region: "us-east-1".to_string(),
        iam_config_path: config_root.join("iam.json"),
        sigv4_timestamp_tolerance_secs: 900,
        presigned_url_min_expiry: 1,
        presigned_url_max_expiry: 604800,
        secret_key: None,
        encryption_enabled: false,
        kms_enabled: false,
        gc_enabled: false,
        integrity_enabled: false,
        metrics_enabled: false,
        metrics_history_enabled: true,
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
        site_sync_enabled: false,
        site_sync_interval_secs: 60,
        site_sync_batch_size: 100,
        site_sync_connect_timeout_secs: 10,
        site_sync_read_timeout_secs: 120,
        site_sync_max_retries: 2,
        site_sync_clock_skew_tolerance: 1.0,
        ui_enabled: true,
        templates_dir: manifest_dir.join("templates"),
        static_dir: manifest_dir.join("static"),
        allow_legacy_header_auth: true,
        ..myfsio_server::config::ServerConfig::default()
    };
    let state = myfsio_server::state::AppState::new(config);
    let (session_id, _csrf) = authenticated_ui_session(&state);
    let app = myfsio_server::create_ui_router(state);

    let resp = app
        .oneshot(ui_request(
            Method::GET,
            "/ui/metrics/history?hours=24",
            &session_id,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["enabled"], true);
    assert_eq!(body["history"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn test_ui_operation_metrics_error_endpoints() {
    let (mut state, _tmp) = test_ui_state();
    state.metrics = Some(Arc::new(
        myfsio_server::services::metrics::MetricsService::new(
            &state.config.storage_root,
            myfsio_server::services::metrics::MetricsConfig {
                interval_minutes: 5,
                retention_hours: 24,
            },
        ),
    ));
    let metrics = state.metrics.as_ref().unwrap().clone();
    metrics.record_request(
        "GET",
        "object",
        403,
        12.5,
        0,
        0,
        Some("AccessDenied"),
        Some("bucket-a"),
        Some("key-a"),
        Some("req-a"),
        "api",
    );

    let (session_id, _csrf) = authenticated_ui_session(&state);
    let app = myfsio_server::create_ui_router(state);

    let summary_resp = app
        .clone()
        .oneshot(ui_request(
            Method::GET,
            "/ui/metrics/operations/error-summary?hours=1",
            &session_id,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(summary_resp.status(), StatusCode::OK);
    let summary_body: Value =
        serde_json::from_slice(&summary_resp.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(summary_body["enabled"], true);
    assert_eq!(summary_body["total_errors"], 1);
    assert_eq!(summary_body["error_codes"]["AccessDenied"], 1);
    assert_eq!(summary_body["error_buckets"]["bucket-a"]["AccessDenied"], 1);

    let errors_resp = app
        .oneshot(ui_request(
            Method::GET,
            "/ui/metrics/operations/errors?limit=10&code=AccessDenied&bucket=bucket-a",
            &session_id,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(errors_resp.status(), StatusCode::OK);
    let errors_body: Value =
        serde_json::from_slice(&errors_resp.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(errors_body["enabled"], true);
    assert_eq!(errors_body["total_buffered"], 1);
    assert_eq!(errors_body["errors"].as_array().unwrap().len(), 1);
    assert_eq!(errors_body["errors"][0]["code"], "AccessDenied");
    assert_eq!(errors_body["errors"][0]["bucket"], "bucket-a");
    assert_eq!(errors_body["errors"][0]["key"], "key-a");
    assert_eq!(errors_body["errors"][0]["request_id"], "req-a");
}

#[tokio::test]
async fn test_ui_operation_metrics_error_endpoints_require_auth() {
    let (mut state, _tmp) = test_ui_state();
    state.metrics = Some(Arc::new(
        myfsio_server::services::metrics::MetricsService::new(
            &state.config.storage_root,
            myfsio_server::services::metrics::MetricsConfig {
                interval_minutes: 5,
                retention_hours: 24,
            },
        ),
    ));
    let app = myfsio_server::create_ui_router(state);

    let summary_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/ui/metrics/operations/error-summary?hours=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(summary_resp.status(), StatusCode::SEE_OTHER);

    let errors_resp = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/ui/metrics/operations/errors")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(errors_resp.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn test_unauthenticated_request_rejected() {
    let (app, _tmp) = test_app();
    let resp = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("<Code>AccessDenied</Code>"));
    assert!(body.contains("<Message>Missing credentials</Message>"));
    assert!(body.contains("<Resource>/</Resource>"));
    assert!(body.contains("<RequestId>"));
    assert!(!body.contains("<RequestId></RequestId>"));
}

#[tokio::test]
async fn test_unauthenticated_request_includes_requested_resource_path() {
    let (app, _tmp) = test_app();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/some-bucket/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("<Code>AccessDenied</Code>"));
    assert!(body.contains("<Message>Missing credentials</Message>"));
    assert!(body.contains("<Resource>/some-bucket/</Resource>"));
    assert!(body.contains("<RequestId>"));
    assert!(!body.contains("<RequestId></RequestId>"));
}

#[tokio::test]
async fn test_list_buckets_empty() {
    let (app, _tmp) = test_app();
    let resp = app
        .oneshot(signed_request(Method::GET, "/", Body::empty()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("ListAllMyBucketsResult"));
}

#[tokio::test]
async fn test_create_and_list_bucket() {
    let (app, _tmp) = test_app();

    let resp = app
        .clone()
        .oneshot(signed_request(Method::PUT, "/test-bucket", Body::empty()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .oneshot(signed_request(Method::GET, "/", Body::empty()))
        .await
        .unwrap();
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("<Name>test-bucket</Name>"));
}

#[tokio::test]
async fn test_head_bucket() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/my-bucket", Body::empty()))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(signed_request(Method::HEAD, "/my-bucket", Body::empty()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("x-amz-bucket-region").unwrap(),
        "us-east-1"
    );

    let resp = app
        .oneshot(signed_request(Method::HEAD, "/nonexistent", Body::empty()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_delete_bucket() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/del-bucket", Body::empty()))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(signed_request(Method::DELETE, "/del-bucket", Body::empty()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let resp = app
        .oneshot(signed_request(Method::HEAD, "/del-bucket", Body::empty()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_put_and_get_object() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/data-bucket", Body::empty()))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/data-bucket/hello.txt")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("content-type", "text/plain")
                .body(Body::from("Hello, World!"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get("etag").is_some());

    let resp = app
        .oneshot(signed_request(
            Method::GET,
            "/data-bucket/hello.txt",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get("content-type").unwrap(), "text/plain");
    assert_eq!(resp.headers().get("content-length").unwrap(), "13");
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"Hello, World!");
}

#[tokio::test]
async fn test_content_type_falls_back_to_extension() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/img-bucket", Body::empty()))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/img-bucket/yum.jpg")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from(vec![0_u8, 1, 2, 3, 4]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/img-bucket/yum.jpg",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get("content-type").unwrap(), "image/jpeg");

    let resp = app
        .oneshot(signed_request(
            Method::HEAD,
            "/img-bucket/yum.jpg",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get("content-type").unwrap(), "image/jpeg");
}

#[tokio::test]
async fn test_head_object() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/hd-bucket", Body::empty()))
        .await
        .unwrap();

    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/hd-bucket/file.bin")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from(vec![0u8; 256]))
                .unwrap(),
        )
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::HEAD,
            "/hd-bucket/file.bin",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get("content-length").unwrap(), "256");
    assert!(resp.headers().get("etag").is_some());
    assert!(resp.headers().get("last-modified").is_some());

    let resp = app
        .oneshot(signed_request(
            Method::HEAD,
            "/hd-bucket/nonexistent.txt",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_delete_object() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/rm-bucket", Body::empty()))
        .await
        .unwrap();

    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/rm-bucket/removeme.txt")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from("bye"))
                .unwrap(),
        )
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::DELETE,
            "/rm-bucket/removeme.txt",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let resp = app
        .oneshot(signed_request(
            Method::HEAD,
            "/rm-bucket/removeme.txt",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_list_objects_v2() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/list-bucket", Body::empty()))
        .await
        .unwrap();

    for name in ["a.txt", "b.txt", "dir/c.txt"] {
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri(format!("/list-bucket/{}", name))
                    .header("x-access-key", TEST_ACCESS_KEY)
                    .header("x-secret-key", TEST_SECRET_KEY)
                    .body(Body::from("data"))
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/list-bucket?list-type=2",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("<Key>a.txt</Key>"));
    assert!(body.contains("<Key>b.txt</Key>"));
    assert!(body.contains("<Key>dir/c.txt</Key>"));
    assert!(body.contains("<KeyCount>3</KeyCount>"));

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/list-bucket?list-type=2&delimiter=/",
            Body::empty(),
        ))
        .await
        .unwrap();
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("<Key>a.txt</Key>"));
    assert!(body.contains("<Key>b.txt</Key>"));
    assert!(body.contains("<Prefix>dir/</Prefix>"));

    let resp = app
        .oneshot(signed_request(
            Method::GET,
            "/list-bucket?list-type=2&prefix=dir/",
            Body::empty(),
        ))
        .await
        .unwrap();
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("<Key>dir/c.txt</Key>"));
    assert!(!body.contains("<Key>a.txt</Key>"));
}

#[tokio::test]
async fn test_get_bucket_unknown_subresources_return_not_implemented() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/subresource-guard",
            Body::empty(),
        ))
        .await
        .unwrap();

    for subresource in ["accelerate", "inventory", "analytics"] {
        let resp = app
            .clone()
            .oneshot(signed_request(
                Method::GET,
                &format!("/subresource-guard?{subresource}"),
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
        let body = String::from_utf8(body_bytes(resp).await).unwrap();
        assert!(body.contains("<Code>NotImplemented</Code>"));
    }
}

#[tokio::test]
async fn test_get_bucket_listing_subresources_remain_supported() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/listing-subresources",
            Body::empty(),
        ))
        .await
        .unwrap();

    for (query, expected) in [
        ("prefix=", "ListBucketResult"),
        ("list-type=2", "ListBucketResult"),
        ("versions", "ListVersionsResult"),
        ("uploads", "ListMultipartUploadsResult"),
    ] {
        let resp = app
            .clone()
            .oneshot(signed_request(
                Method::GET,
                &format!("/listing-subresources?{query}"),
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "query {query}");
        let body = String::from_utf8(body_bytes(resp).await).unwrap();
        assert!(body.contains(expected), "query {query}: {body}");
    }
}

#[tokio::test]
async fn test_delete_bucket_unknown_subresource_returns_not_implemented() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/delete-subresource-guard",
            Body::empty(),
        ))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::DELETE,
            "/delete-subresource-guard?accelerate",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);

    let resp = app
        .oneshot(signed_request(
            Method::HEAD,
            "/delete-subresource-guard",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_get_nonexistent_object_returns_404() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/err-bucket", Body::empty()))
        .await
        .unwrap();

    let resp = app
        .oneshot(signed_request(
            Method::GET,
            "/err-bucket/nope.txt",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("<Code>NoSuchKey</Code>"));
}

#[tokio::test]
async fn test_create_duplicate_bucket_returns_409() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/dup-bucket", Body::empty()))
        .await
        .unwrap();

    let resp = app
        .oneshot(signed_request(Method::PUT, "/dup-bucket", Body::empty()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_delete_nonempty_bucket_returns_409() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/full-bucket", Body::empty()))
        .await
        .unwrap();

    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/full-bucket/obj.txt")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from("data"))
                .unwrap(),
        )
        .await
        .unwrap();

    let resp = app
        .oneshot(signed_request(
            Method::DELETE,
            "/full-bucket",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_object_with_user_metadata() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/meta-bucket", Body::empty()))
        .await
        .unwrap();

    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/meta-bucket/tagged.txt")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("x-amz-meta-author", "test-user")
                .header("x-amz-meta-version", "42")
                .body(Body::from("content"))
                .unwrap(),
        )
        .await
        .unwrap();

    let resp = app
        .oneshot(signed_request(
            Method::HEAD,
            "/meta-bucket/tagged.txt",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("x-amz-meta-author").unwrap(),
        "test-user"
    );
    assert_eq!(resp.headers().get("x-amz-meta-version").unwrap(), "42");
}

#[tokio::test]
async fn test_wrong_credentials_rejected() {
    let (app, _tmp) = test_app();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/")
                .header("x-access-key", "WRONGKEY")
                .header("x-secret-key", "WRONGSECRET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_server_header_present() {
    let (app, _tmp) = test_app();
    let resp = app
        .oneshot(signed_request(Method::GET, "/", Body::empty()))
        .await
        .unwrap();
    let server = resp.headers().get("server").unwrap().to_str().unwrap();
    assert!(server.starts_with("MyFSIO-Rust/"));
}

#[tokio::test]
async fn test_range_request() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/range-bucket", Body::empty()))
        .await
        .unwrap();

    let data = "Hello, World! This is range test data.";
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/range-bucket/range.txt")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from(data))
                .unwrap(),
        )
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/range-bucket/range.txt")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("range", "bytes=0-4")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(resp.headers().get("content-length").unwrap(), "5");
    assert!(resp
        .headers()
        .get("content-range")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("bytes 0-4/"));
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"Hello");

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/range-bucket/range.txt")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("range", "bytes=-5")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"data.");
}

#[tokio::test]
async fn test_range_get_omits_whole_object_checksum() {
    use base64::engine::general_purpose::STANDARD as B64;
    use sha2::{Digest, Sha256};

    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/csum-bucket", Body::empty()))
        .await
        .unwrap();

    let data = b"Hello, World! This is range checksum data.";
    let sha = B64.encode(Sha256::digest(data));

    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/csum-bucket/obj.bin")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("x-amz-checksum-sha256", &sha)
                .body(Body::from(&data[..]))
                .unwrap(),
        )
        .await
        .unwrap();

    let full_without_mode = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/csum-bucket/obj.bin")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(full_without_mode.status(), StatusCode::OK);
    assert!(full_without_mode
        .headers()
        .get("x-amz-checksum-sha256")
        .is_none());

    let full = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/csum-bucket/obj.bin")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("x-amz-checksum-mode", "enabled")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        full.headers().get("x-amz-checksum-sha256").unwrap(),
        sha.as_str()
    );

    let head_without_mode = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::HEAD)
                .uri("/csum-bucket/obj.bin")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(head_without_mode
        .headers()
        .get("x-amz-checksum-sha256")
        .is_none());
    let head_with_mode = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::HEAD)
                .uri("/csum-bucket/obj.bin")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("x-amz-checksum-mode", "ENABLED")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        head_with_mode
            .headers()
            .get("x-amz-checksum-sha256")
            .unwrap(),
        sha.as_str()
    );

    let partial = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/csum-bucket/obj.bin")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("range", "bytes=0-4")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(partial.status(), StatusCode::PARTIAL_CONTENT);
    for algo in ["sha256", "sha1", "crc32", "crc32c", "crc64nvme"] {
        let header = format!("x-amz-checksum-{}", algo);
        assert!(
            partial.headers().get(&header).is_none(),
            "ranged GET must not include {}",
            header
        );
    }

    let body_bytes = partial.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body_bytes[..], &data[..5]);

    let full_range = format!("bytes=0-{}", data.len() - 1);
    let covering = app
        .oneshot(
            Request::builder()
                .uri("/csum-bucket/obj.bin")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("range", &full_range)
                .header("x-amz-checksum-mode", "ENABLED")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(covering.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        covering.headers().get("x-amz-checksum-sha256").unwrap(),
        sha.as_str()
    );
}

#[tokio::test]
async fn test_copy_object() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/src-bucket", Body::empty()))
        .await
        .unwrap();
    app.clone()
        .oneshot(signed_request(Method::PUT, "/dst-bucket", Body::empty()))
        .await
        .unwrap();

    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/src-bucket/original.txt")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from("copy me"))
                .unwrap(),
        )
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/dst-bucket/copied.txt")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("x-amz-copy-source", "/src-bucket/original.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("CopyObjectResult"));

    let resp = app
        .oneshot(signed_request(
            Method::GET,
            "/dst-bucket/copied.txt",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"copy me");
}

#[tokio::test]
async fn test_object_attributes_honors_version_id() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/attr-ver", Body::empty()))
        .await
        .unwrap();
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/attr-ver?versioning")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from(
                    "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let first = app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/attr-ver/obj.txt",
            Body::from("first"),
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let first_version = first
        .headers()
        .get("x-amz-version-id")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
        .expect("versioned put returns a version id");

    let second = app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/attr-ver/obj.txt",
            Body::from("second-and-longer"),
        ))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!(
                    "/attr-ver/obj.txt?attributes&versionId={}",
                    first_version
                ))
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("x-amz-object-attributes", "ObjectSize")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-amz-version-id")
            .and_then(|value| value.to_str().ok()),
        Some(first_version.as_str())
    );
    let body = String::from_utf8(body_bytes(resp).await).unwrap();
    assert!(body.contains("<ObjectSize>5</ObjectSize>"), "{body}");

    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/attr-ver/obj.txt?attributes")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("x-amz-object-attributes", "ObjectSize")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = String::from_utf8(body_bytes(resp).await).unwrap();
    assert!(body.contains("<ObjectSize>17</ObjectSize>"), "{body}");
}

#[tokio::test]
async fn test_object_attributes_reports_plaintext_size_for_encrypted_objects() {
    let (app, _tmp) = test_app_sse_c().await;
    let app = app.into_service();
    let plaintext = vec![b'z'; 4096];

    tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(Method::PUT, "/attr-enc", Body::empty()),
    )
    .await
    .unwrap();

    let put = tower::ServiceExt::oneshot(
        app.clone(),
        Request::builder()
            .method(Method::PUT)
            .uri("/attr-enc/secret.bin")
            .header("x-access-key", TEST_ACCESS_KEY)
            .header("x-secret-key", TEST_SECRET_KEY)
            .header("x-amz-server-side-encryption", "AES256")
            .body(Body::from(plaintext.clone()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(put.status(), StatusCode::OK);

    let resp = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri("/attr-enc/secret.bin?attributes")
            .header("x-access-key", TEST_ACCESS_KEY)
            .header("x-secret-key", TEST_SECRET_KEY)
            .header("x-amz-object-attributes", "ObjectSize")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(body_bytes(resp).await).unwrap();
    assert!(
        body.contains(&format!("<ObjectSize>{}</ObjectSize>", plaintext.len())),
        "{body}"
    );
}

#[tokio::test]
async fn test_complete_multipart_rejects_descending_part_order() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/mp-order", Body::empty()))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::POST,
            "/mp-order/ordered.bin?uploads",
            Body::empty(),
        ))
        .await
        .unwrap();
    let body = String::from_utf8(body_bytes(resp).await).unwrap();
    let upload_id = extract_upload_id(&body);

    let mut etags = Vec::new();
    for (part_number, byte) in [(1u32, b'A'), (2u32, b'B')] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri(format!(
                        "/mp-order/ordered.bin?uploadId={}&partNumber={}",
                        upload_id, part_number
                    ))
                    .header("x-access-key", TEST_ACCESS_KEY)
                    .header("x-secret-key", TEST_SECRET_KEY)
                    .body(Body::from(vec![byte; 1024]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        etags.push(
            resp.headers()
                .get("etag")
                .unwrap()
                .to_str()
                .unwrap()
                .trim_matches('"')
                .to_string(),
        );
    }

    let complete_xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>2</PartNumber><ETag>\"{}\"</ETag></Part><Part><PartNumber>1</PartNumber><ETag>\"{}\"</ETag></Part></CompleteMultipartUpload>",
        etags[1], etags[0]
    );
    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::POST,
            &format!("/mp-order/ordered.bin?uploadId={}", upload_id),
            Body::from(complete_xml),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = String::from_utf8(body_bytes(resp).await).unwrap();
    assert!(body.contains("<Code>InvalidPartOrder</Code>"), "{body}");

    let resp = app
        .oneshot(signed_request(
            Method::GET,
            "/mp-order/ordered.bin",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_multipart_upload_http() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/mp-bucket", Body::empty()))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::POST,
            "/mp-bucket/big-file.bin?uploads",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("InitiateMultipartUploadResult"));
    assert!(body.contains("<Key>big-file.bin</Key>"));

    let upload_id = body
        .split("<UploadId>")
        .nth(1)
        .unwrap()
        .split("</UploadId>")
        .next()
        .unwrap();

    let part1_data = vec![b'A'; 1024];
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!(
                    "/mp-bucket/big-file.bin?uploadId={}&partNumber=1",
                    upload_id
                ))
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from(part1_data))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let etag1 = resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .trim_matches('"')
        .to_string();

    let part2_data = vec![b'B'; 512];
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!(
                    "/mp-bucket/big-file.bin?uploadId={}&partNumber=2",
                    upload_id
                ))
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from(part2_data))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let etag2 = resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .trim_matches('"')
        .to_string();

    let complete_xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"{etag1}\"</ETag></Part><Part><PartNumber>2</PartNumber><ETag>\"{etag2}\"</ETag></Part></CompleteMultipartUpload>"
    );

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/mp-bucket/big-file.bin?uploadId={}", upload_id))
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from(complete_xml))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("CompleteMultipartUploadResult"));

    let resp = app
        .oneshot(signed_request(
            Method::HEAD,
            "/mp-bucket/big-file.bin",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get("content-length").unwrap(), "1536");
}

#[tokio::test]
async fn test_delete_objects_batch() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/batch-bucket", Body::empty()))
        .await
        .unwrap();

    for name in ["a.txt", "b.txt", "c.txt"] {
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri(format!("/batch-bucket/{}", name))
                    .header("x-access-key", TEST_ACCESS_KEY)
                    .header("x-secret-key", TEST_SECRET_KEY)
                    .body(Body::from("data"))
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    let delete_xml =
        r#"<Delete><Object><Key>a.txt</Key></Object><Object><Key>b.txt</Key></Object></Delete>"#;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/batch-bucket?delete")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from(delete_xml))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("DeleteResult"));
    assert!(body.contains("<Key>a.txt</Key>"));
    assert!(body.contains("<Key>b.txt</Key>"));

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::HEAD,
            "/batch-bucket/a.txt",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let resp = app
        .oneshot(signed_request(
            Method::HEAD,
            "/batch-bucket/c.txt",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_bucket_versioning() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/ver-bucket", Body::empty()))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/ver-bucket?versioning",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("VersioningConfiguration"));
    assert!(!body.contains("<Status>Enabled</Status>"));
    assert!(!body.contains("<Status>Suspended</Status>"));

    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/ver-bucket?versioning")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from(
                    "<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>",
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/ver-bucket?versioning",
            Body::empty(),
        ))
        .await
        .unwrap();
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("<Status>Suspended</Status>"));

    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/ver-bucket?versioning")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from(
                    "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let resp = app
        .oneshot(signed_request(
            Method::GET,
            "/ver-bucket?versioning",
            Body::empty(),
        ))
        .await
        .unwrap();
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("<Status>Enabled</Status>"));
}

#[tokio::test]
async fn test_versioned_object_can_be_read_and_deleted_by_version_id() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/versions-bucket",
            Body::empty(),
        ))
        .await
        .unwrap();
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/versions-bucket?versioning")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from(
                    "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/versions-bucket/doc.txt",
            Body::from("first"),
        ))
        .await
        .unwrap();
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/versions-bucket/doc.txt",
            Body::from("second"),
        ))
        .await
        .unwrap();

    let list_resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/versions-bucket?versions",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(list_resp.status(), StatusCode::OK);
    let list_body = String::from_utf8(
        list_resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    let archived_version_id = list_body
        .split("<Version>")
        .skip(1)
        .find(|block| block.contains("<IsLatest>false</IsLatest>"))
        .and_then(|block| {
            block
                .split("<VersionId>")
                .nth(1)
                .and_then(|s| s.split_once("</VersionId>").map(|(id, _)| id))
        })
        .filter(|id| *id != "null")
        .expect("archived version id")
        .to_string();

    let version_resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            &format!("/versions-bucket/doc.txt?versionId={}", archived_version_id),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(version_resp.status(), StatusCode::OK);
    assert_eq!(
        version_resp.headers()["x-amz-version-id"].to_str().unwrap(),
        archived_version_id
    );
    let version_body = version_resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&version_body[..], b"first");

    let traversal_resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            &format!(
                "/versions-bucket/doc.txt?versionId=../other/{}",
                archived_version_id
            ),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(traversal_resp.status(), StatusCode::NOT_FOUND);

    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/versions-bucket/doc.txt",
            Body::from("third"),
        ))
        .await
        .unwrap();
    let limited_resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/versions-bucket?versions&max-keys=1",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(limited_resp.status(), StatusCode::OK);
    let limited_body = String::from_utf8(
        limited_resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert_eq!(limited_body.matches("<Version>").count(), 1);
    assert!(limited_body.contains("<IsTruncated>true</IsTruncated>"));

    let delete_resp = app
        .clone()
        .oneshot(signed_request(
            Method::DELETE,
            &format!("/versions-bucket/doc.txt?versionId={}", archived_version_id),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(delete_resp.status(), StatusCode::NO_CONTENT);

    let missing_resp = app
        .oneshot(signed_request(
            Method::GET,
            &format!("/versions-bucket/doc.txt?versionId={}", archived_version_id),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(missing_resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_versioned_put_and_delete_emit_version_headers_and_delete_markers() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/compat-bucket", Body::empty()))
        .await
        .unwrap();
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/compat-bucket?versioning")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from(
                    "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let put_resp = app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/compat-bucket/doc.txt",
            Body::from("first"),
        ))
        .await
        .unwrap();
    assert_eq!(put_resp.status(), StatusCode::OK);
    let first_version = put_resp
        .headers()
        .get("x-amz-version-id")
        .expect("PUT on versioned bucket must emit x-amz-version-id")
        .to_str()
        .unwrap()
        .to_string();
    assert!(!first_version.is_empty());

    let overwrite_resp = app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/compat-bucket/doc.txt",
            Body::from("second"),
        ))
        .await
        .unwrap();
    assert_eq!(overwrite_resp.status(), StatusCode::OK);
    let second_version = overwrite_resp
        .headers()
        .get("x-amz-version-id")
        .expect("overwrite on versioned bucket must emit a new x-amz-version-id")
        .to_str()
        .unwrap()
        .to_string();
    assert_ne!(first_version, second_version);

    let delete_resp = app
        .clone()
        .oneshot(signed_request(
            Method::DELETE,
            "/compat-bucket/doc.txt",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(delete_resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        delete_resp
            .headers()
            .get("x-amz-delete-marker")
            .and_then(|v| v.to_str().ok()),
        Some("true")
    );
    assert!(delete_resp.headers().contains_key("x-amz-version-id"));

    let versions_resp = app
        .oneshot(signed_request(
            Method::GET,
            "/compat-bucket?versions",
            Body::empty(),
        ))
        .await
        .unwrap();
    let versions_body = String::from_utf8(
        versions_resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(
        versions_body.contains("<DeleteMarker>"),
        "expected DeleteMarker entry in ListObjectVersions output, got: {}",
        versions_body
    );
}

#[tokio::test]
async fn test_consecutive_slashes_in_key_round_trip() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/slashes-bucket",
            Body::empty(),
        ))
        .await
        .unwrap();

    let put_ab = app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/slashes-bucket/a/b",
            Body::from("single"),
        ))
        .await
        .unwrap();
    assert_eq!(put_ab.status(), StatusCode::OK);

    let put_double = app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/slashes-bucket/a//b",
            Body::from("double"),
        ))
        .await
        .unwrap();
    assert_eq!(put_double.status(), StatusCode::OK);

    let put_triple = app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/slashes-bucket/a///b",
            Body::from("triple"),
        ))
        .await
        .unwrap();
    assert_eq!(put_triple.status(), StatusCode::OK);

    let get_ab = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/slashes-bucket/a/b",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(get_ab.status(), StatusCode::OK);
    let body_ab = get_ab.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body_ab[..], b"single");

    let get_triple = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/slashes-bucket/a///b",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(get_triple.status(), StatusCode::OK);
    let body_triple = get_triple.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body_triple[..], b"triple");

    let list_resp = app
        .oneshot(signed_request(
            Method::GET,
            "/slashes-bucket?list-type=2",
            Body::empty(),
        ))
        .await
        .unwrap();
    let list_body = String::from_utf8(
        list_resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(
        list_body.contains("<Key>a/b</Key>"),
        "expected a/b in listing: {}",
        list_body
    );
    assert!(
        list_body.contains("<Key>a//b</Key>"),
        "expected a//b in listing: {}",
        list_body
    );
    assert!(
        list_body.contains("<Key>a///b</Key>"),
        "expected a///b in listing: {}",
        list_body
    );
}

#[tokio::test]
async fn test_delete_live_version_restores_previous_to_live_slot() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/restore-bucket",
            Body::empty(),
        ))
        .await
        .unwrap();
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/restore-bucket?versioning")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from(
                    "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let v1_resp = app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/restore-bucket/k",
            Body::from("one"),
        ))
        .await
        .unwrap();
    let v1 = v1_resp
        .headers()
        .get("x-amz-version-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let v2_resp = app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/restore-bucket/k",
            Body::from("two"),
        ))
        .await
        .unwrap();
    let v2 = v2_resp
        .headers()
        .get("x-amz-version-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_ne!(v1, v2);

    let del = app
        .clone()
        .oneshot(signed_request(
            Method::DELETE,
            &format!("/restore-bucket/k?versionId={}", v2),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(del.status(), StatusCode::NO_CONTENT);

    let get_live = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/restore-bucket/k",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(get_live.status(), StatusCode::OK);
    let body = get_live.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"one");

    let get_v1 = app
        .oneshot(signed_request(
            Method::GET,
            &format!("/restore-bucket/k?versionId={}", v1),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(get_v1.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_delete_active_delete_marker_restores_previous_to_live_slot() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/undel-bucket", Body::empty()))
        .await
        .unwrap();
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/undel-bucket?versioning")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from(
                    "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/undel-bucket/k",
            Body::from("only"),
        ))
        .await
        .unwrap();

    let del = app
        .clone()
        .oneshot(signed_request(
            Method::DELETE,
            "/undel-bucket/k",
            Body::empty(),
        ))
        .await
        .unwrap();
    let dm_version = del
        .headers()
        .get("x-amz-version-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(
        del.headers()
            .get("x-amz-delete-marker")
            .and_then(|v| v.to_str().ok()),
        Some("true")
    );

    let shadowed = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/undel-bucket/k",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(shadowed.status(), StatusCode::NOT_FOUND);

    let del_dm = app
        .clone()
        .oneshot(signed_request(
            Method::DELETE,
            &format!("/undel-bucket/k?versionId={}", dm_version),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(del_dm.status(), StatusCode::NO_CONTENT);

    let restored = app
        .oneshot(signed_request(
            Method::GET,
            "/undel-bucket/k",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(restored.status(), StatusCode::OK);
    let body = restored.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"only");
}

#[tokio::test]
async fn test_versioned_get_on_delete_marker_returns_method_not_allowed() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/dm-bucket", Body::empty()))
        .await
        .unwrap();
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/dm-bucket?versioning")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from(
                    "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/dm-bucket/k", Body::from("x")))
        .await
        .unwrap();

    let del = app
        .clone()
        .oneshot(signed_request(
            Method::DELETE,
            "/dm-bucket/k",
            Body::empty(),
        ))
        .await
        .unwrap();
    let dm_version = del
        .headers()
        .get("x-amz-version-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let versioned = app
        .oneshot(signed_request(
            Method::GET,
            &format!("/dm-bucket/k?versionId={}", dm_version),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(versioned.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn test_retention_is_enforced_when_deleting_archived_version() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/locked-versions",
            Body::empty(),
        ))
        .await
        .unwrap();
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/locked-versions?versioning")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from(
                    "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/locked-versions/doc.txt")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("x-amz-object-lock-mode", "GOVERNANCE")
                .header(
                    "x-amz-object-lock-retain-until-date",
                    "2099-01-01T00:00:00Z",
                )
                .body(Body::from("locked"))
                .unwrap(),
        )
        .await
        .unwrap();

    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/locked-versions/doc.txt")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("x-amz-bypass-governance-retention", "true")
                .body(Body::from("replacement"))
                .unwrap(),
        )
        .await
        .unwrap();

    let list_resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/locked-versions?versions",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(list_resp.status(), StatusCode::OK);
    let list_body = String::from_utf8(
        list_resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    let archived_version_id = list_body
        .split("<Version>")
        .skip(1)
        .find(|block| block.contains("<IsLatest>false</IsLatest>"))
        .and_then(|block| {
            block
                .split("<VersionId>")
                .nth(1)
                .and_then(|s| s.split_once("</VersionId>").map(|(id, _)| id))
        })
        .filter(|id| *id != "null")
        .expect("archived version id")
        .to_string();

    let denied = app
        .clone()
        .oneshot(signed_request(
            Method::DELETE,
            &format!("/locked-versions/doc.txt?versionId={}", archived_version_id),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

    let allowed = app
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!(
                    "/locked-versions/doc.txt?versionId={}",
                    archived_version_id
                ))
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("x-amz-bypass-governance-retention", "true")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(allowed.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_put_object_validates_content_md5() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/md5-bucket", Body::empty()))
        .await
        .unwrap();

    let bad_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/md5-bucket/object.txt")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("content-md5", "AAAAAAAAAAAAAAAAAAAAAA==")
                .body(Body::from("hello"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_resp.status(), StatusCode::BAD_REQUEST);
    let bad_body = String::from_utf8(
        bad_resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(bad_body.contains("<Code>BadDigest</Code>"));

    let good_resp = app
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/md5-bucket/object.txt")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("content-md5", "XUFAKrxLKna5cZ2REBfFkg==")
                .body(Body::from("hello"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(good_resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_put_object_validates_crc32c_sha1_and_crc64nvme() {
    use base64::engine::general_purpose::STANDARD as B64;
    use sha1::{Digest, Sha1};

    let (app, _tmp) = test_app();
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/algorithm-checksums",
            Body::empty(),
        ))
        .await
        .unwrap();

    let data = b"checksum payload";
    let checksums = [
        (
            "crc32c",
            B64.encode(
                (crc_fast::checksum(crc_fast::CrcAlgorithm::Crc32Iscsi, data) as u32).to_be_bytes(),
            ),
        ),
        ("sha1", B64.encode(Sha1::digest(data))),
        (
            "crc64nvme",
            B64.encode(crc_fast::checksum(crc_fast::CrcAlgorithm::Crc64Nvme, data).to_be_bytes()),
        ),
    ];

    for (algorithm, checksum) in checksums {
        let bad_checksum = match algorithm {
            "sha1" => B64.encode([0u8; 20]),
            "crc64nvme" => B64.encode([0u8; 8]),
            _ => B64.encode([0u8; 4]),
        };
        let bad = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri(format!("/algorithm-checksums/bad-{}", algorithm))
                    .header("x-access-key", TEST_ACCESS_KEY)
                    .header("x-secret-key", TEST_SECRET_KEY)
                    .header(format!("x-amz-checksum-{}", algorithm), bad_checksum)
                    .body(Body::from(&data[..]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
        let body = String::from_utf8(bad.into_body().collect().await.unwrap().to_bytes().to_vec())
            .unwrap();
        assert!(body.contains("<Code>InvalidRequest</Code>"));
        assert!(body.contains(algorithm));

        let good = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri(format!("/algorithm-checksums/good-{}", algorithm))
                    .header("x-access-key", TEST_ACCESS_KEY)
                    .header("x-secret-key", TEST_SECRET_KEY)
                    .header(format!("x-amz-checksum-{}", algorithm), checksum)
                    .body(Body::from(&data[..]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(good.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn test_upload_part_validates_crc32c_sha1_and_crc64nvme() {
    use base64::engine::general_purpose::STANDARD as B64;
    use sha1::{Digest, Sha1};

    let (app, _tmp) = test_app();
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/part-algorithm-checksums",
            Body::empty(),
        ))
        .await
        .unwrap();
    let initiated = app
        .clone()
        .oneshot(signed_request(
            Method::POST,
            "/part-algorithm-checksums/object?uploads",
            Body::empty(),
        ))
        .await
        .unwrap();
    let body = String::from_utf8(
        initiated
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    let upload_id = body
        .split("<UploadId>")
        .nth(1)
        .unwrap()
        .split("</UploadId>")
        .next()
        .unwrap()
        .to_string();

    let data = b"part checksum payload";
    let checksums = [
        (
            "crc32c",
            B64.encode(
                (crc_fast::checksum(crc_fast::CrcAlgorithm::Crc32Iscsi, data) as u32).to_be_bytes(),
            ),
        ),
        ("sha1", B64.encode(Sha1::digest(data))),
        (
            "crc64nvme",
            B64.encode(crc_fast::checksum(crc_fast::CrcAlgorithm::Crc64Nvme, data).to_be_bytes()),
        ),
    ];

    for (index, (algorithm, checksum)) in checksums.into_iter().enumerate() {
        let part_number = index + 1;
        let bad_checksum = match algorithm {
            "sha1" => B64.encode([0u8; 20]),
            "crc64nvme" => B64.encode([0u8; 8]),
            _ => B64.encode([0u8; 4]),
        };
        let uri = format!(
            "/part-algorithm-checksums/object?uploadId={}&partNumber={}",
            upload_id, part_number
        );
        let bad = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri(&uri)
                    .header("x-access-key", TEST_ACCESS_KEY)
                    .header("x-secret-key", TEST_SECRET_KEY)
                    .header(format!("x-amz-checksum-{}", algorithm), bad_checksum)
                    .body(Body::from(&data[..]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
        let body = String::from_utf8(bad.into_body().collect().await.unwrap().to_bytes().to_vec())
            .unwrap();
        assert!(body.contains("<Code>InvalidRequest</Code>"));
        assert!(body.contains(algorithm));

        let good = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri(&uri)
                    .header("x-access-key", TEST_ACCESS_KEY)
                    .header("x-secret-key", TEST_SECRET_KEY)
                    .header(format!("x-amz-checksum-{}", algorithm), checksum)
                    .body(Body::from(&data[..]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(good.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn test_streaming_sigv4_chunk_chain_accepts_valid_and_rejects_tampered_body() {
    let (app, _tmp) = test_app();
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/streaming-signatures",
            Body::empty(),
        ))
        .await
        .unwrap();

    let valid = app
        .clone()
        .oneshot(streaming_sigv4_request(
            "/streaming-signatures/valid",
            b"hello",
            b"hello",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(valid.status(), StatusCode::OK);

    let tampered = app
        .oneshot(streaming_sigv4_request(
            "/streaming-signatures/tampered",
            b"hello",
            b"jello",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(tampered.status(), StatusCode::FORBIDDEN);
    let body = String::from_utf8(
        tampered
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("<Code>SignatureDoesNotMatch</Code>"));
}

#[tokio::test]
async fn test_streaming_sigv4_signed_trailer_accepts_valid_and_rejects_invalid_signature() {
    use base64::engine::general_purpose::STANDARD as B64;

    let (app, _tmp) = test_app();
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/streaming-trailer-signatures",
            Body::empty(),
        ))
        .await
        .unwrap();
    let checksum = B64.encode(
        (crc_fast::checksum(crc_fast::CrcAlgorithm::Crc32Iscsi, b"hello") as u32).to_be_bytes(),
    );

    let valid = app
        .clone()
        .oneshot(streaming_sigv4_request(
            "/streaming-trailer-signatures/valid",
            b"hello",
            b"hello",
            Some(("x-amz-checksum-crc32c", &checksum, true)),
        ))
        .await
        .unwrap();
    assert_eq!(valid.status(), StatusCode::OK);

    let invalid = app
        .oneshot(streaming_sigv4_request(
            "/streaming-trailer-signatures/invalid",
            b"hello",
            b"hello",
            Some(("x-amz-checksum-crc32c", &checksum, false)),
        ))
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::FORBIDDEN);
    let body = String::from_utf8(
        invalid
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("<Code>SignatureDoesNotMatch</Code>"));
}

#[tokio::test]
async fn test_aws_chunked_unsigned_checksum_trailer_valid_tampered_and_truncated() {
    use base64::engine::general_purpose::STANDARD as B64;

    let (app, _tmp) = test_app();
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/unsigned-checksum-trailers",
            Body::empty(),
        ))
        .await
        .unwrap();
    let checksum = B64.encode(
        (crc_fast::checksum(crc_fast::CrcAlgorithm::Crc32Iscsi, b"hello") as u32).to_be_bytes(),
    );
    let request = |key: &str, encoded: Vec<u8>| {
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/unsigned-checksum-trailers/{}", key))
            .header("x-access-key", TEST_ACCESS_KEY)
            .header("x-secret-key", TEST_SECRET_KEY)
            .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
            .header("x-amz-decoded-content-length", "5")
            .header("content-encoding", "aws-chunked")
            .header("x-amz-trailer", "x-amz-checksum-crc32c")
            .body(Body::from(encoded))
            .unwrap()
    };

    let valid_body = format!(
        "5\r\nhello\r\n0\r\nx-amz-checksum-crc32c:{}\r\n\r\n",
        checksum
    )
    .into_bytes();
    let valid = app
        .clone()
        .oneshot(request("valid", valid_body))
        .await
        .unwrap();
    assert_eq!(valid.status(), StatusCode::OK);

    let tampered_body = b"5\r\nhello\r\n0\r\nx-amz-checksum-crc32c:AAAAAA==\r\n\r\n".to_vec();
    let tampered = app
        .clone()
        .oneshot(request("tampered", tampered_body))
        .await
        .unwrap();
    assert_eq!(tampered.status(), StatusCode::BAD_REQUEST);
    let body = String::from_utf8(
        tampered
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("<Code>InvalidRequest</Code>"));

    let truncated_body = b"5\r\nhello\r\n0\r\nx-amz-checksum-crc32c:".to_vec();
    let truncated = app
        .oneshot(request("truncated", truncated_body))
        .await
        .unwrap();
    assert_eq!(truncated.status(), StatusCode::BAD_REQUEST);
    let body = String::from_utf8(
        truncated
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("<Code>IncompleteBody</Code>"));
}

#[tokio::test]
async fn test_x_amz_content_sha256_mismatch_returns_bad_digest() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/sha256-bucket", Body::empty()))
        .await
        .unwrap();

    let bad_resp = app
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/sha256-bucket/object.txt")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header(
                    "x-amz-content-sha256",
                    "0000000000000000000000000000000000000000000000000000000000000000",
                )
                .body(Body::from("hello"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_resp.status(), StatusCode::BAD_REQUEST);
    let bad_body = String::from_utf8(
        bad_resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(bad_body.contains("<Code>BadDigest</Code>"));
    assert!(bad_body.contains("x-amz-content-sha256"));
}

#[tokio::test]
async fn test_max_keys_zero_respects_marker_and_v2_cursors() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/cursor-bucket", Body::empty()))
        .await
        .unwrap();
    for key in ["a.txt", "b.txt"] {
        app.clone()
            .oneshot(signed_request(
                Method::PUT,
                &format!("/cursor-bucket/{}", key),
                Body::from(key.to_string()),
            ))
            .await
            .unwrap();
    }

    let marker_resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/cursor-bucket?max-keys=0&marker=b.txt",
            Body::empty(),
        ))
        .await
        .unwrap();
    let marker_body = String::from_utf8(
        marker_resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(marker_body.contains("<IsTruncated>false</IsTruncated>"));

    let start_after_resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/cursor-bucket?list-type=2&max-keys=0&start-after=b.txt",
            Body::empty(),
        ))
        .await
        .unwrap();
    let start_after_body = String::from_utf8(
        start_after_resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(start_after_body.contains("<IsTruncated>false</IsTruncated>"));

    let token = URL_SAFE.encode("b.txt");
    let token_resp = app
        .oneshot(signed_request(
            Method::GET,
            &format!(
                "/cursor-bucket?list-type=2&max-keys=0&continuation-token={}",
                token
            ),
            Body::empty(),
        ))
        .await
        .unwrap();
    let token_body = String::from_utf8(
        token_resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(token_body.contains("<IsTruncated>false</IsTruncated>"));
}

#[tokio::test]
async fn test_encoding_type_rejects_unknown_values() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/encoding-bucket",
            Body::empty(),
        ))
        .await
        .unwrap();
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/encoding-bucket/a.txt",
            Body::from("a"),
        ))
        .await
        .unwrap();

    for uri in [
        "/encoding-bucket?list-type=2&encoding-type=bogus",
        "/encoding-bucket?encoding-type=bogus",
        "/encoding-bucket?versions&encoding-type=bogus",
        "/encoding-bucket?uploads&encoding-type=bogus",
    ] {
        let resp = app
            .clone()
            .oneshot(signed_request(Method::GET, uri, Body::empty()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{}", uri);
        let body = String::from_utf8(
            resp.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(
            body.contains("<Code>InvalidArgument</Code>"),
            "{}: {}",
            uri,
            body
        );
        assert!(
            body.contains("Invalid Encoding Method specified in Request"),
            "{}: {}",
            uri,
            body
        );
    }

    for uri in [
        "/encoding-bucket?list-type=2&encoding-type=URL",
        "/encoding-bucket?versions&encoding-type=url",
        "/encoding-bucket?uploads&encoding-type=url",
        "/encoding-bucket?list-type=2",
    ] {
        let resp = app
            .clone()
            .oneshot(signed_request(Method::GET, uri, Body::empty()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{}", uri);
    }
}

#[tokio::test]
async fn test_encoding_type_url_encodes_listing_keys() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/encoded-keys-bucket",
            Body::empty(),
        ))
        .await
        .unwrap();
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/encoded-keys-bucket/space%20file.txt",
            Body::from("data"),
        ))
        .await
        .unwrap();

    let plain = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/encoded-keys-bucket?list-type=2",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(plain.status(), StatusCode::OK);
    let plain_body = String::from_utf8(
        plain
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(
        plain_body.contains("<Key>space file.txt</Key>"),
        "{}",
        plain_body
    );

    let encoded = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/encoded-keys-bucket?list-type=2&encoding-type=url",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(encoded.status(), StatusCode::OK);
    let encoded_body = String::from_utf8(
        encoded
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(
        encoded_body.contains("<Key>space%20file.txt</Key>"),
        "{}",
        encoded_body
    );
    assert!(
        encoded_body.contains("<EncodingType>url</EncodingType>"),
        "{}",
        encoded_body
    );

    let encoded_v1 = app
        .oneshot(signed_request(
            Method::GET,
            "/encoded-keys-bucket?encoding-type=url",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(encoded_v1.status(), StatusCode::OK);
    let encoded_v1_body = String::from_utf8(
        encoded_v1
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(
        encoded_v1_body.contains("<Key>space%20file.txt</Key>"),
        "{}",
        encoded_v1_body
    );
}

#[tokio::test]
async fn test_max_keys_above_limit_is_clamped_to_1000() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/clamp-bucket", Body::empty()))
        .await
        .unwrap();
    for key in ["a.txt", "b.txt"] {
        app.clone()
            .oneshot(signed_request(
                Method::PUT,
                &format!("/clamp-bucket/{}", key),
                Body::from(key.to_string()),
            ))
            .await
            .unwrap();
    }

    for uri in [
        "/clamp-bucket?list-type=2&max-keys=999999999",
        "/clamp-bucket?max-keys=999999999",
        "/clamp-bucket?versions&max-keys=999999999",
    ] {
        let resp = app
            .clone()
            .oneshot(signed_request(Method::GET, uri, Body::empty()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{}", uri);
        let body = String::from_utf8(
            resp.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(
            body.contains("<MaxKeys>1000</MaxKeys>"),
            "{}: {}",
            uri,
            body
        );
        assert!(
            body.contains("<IsTruncated>false</IsTruncated>"),
            "{}: {}",
            uri,
            body
        );
        assert!(body.contains("<Key>a.txt</Key>"), "{}: {}", uri, body);
        assert!(body.contains("<Key>b.txt</Key>"), "{}: {}", uri, body);
    }

    let negative = app
        .oneshot(signed_request(
            Method::GET,
            "/clamp-bucket?list-type=2&max-keys=-1",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(negative.status(), StatusCode::BAD_REQUEST);
    let negative_body = String::from_utf8(
        negative
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(negative_body.contains("<Code>InvalidArgument</Code>"));
}

#[tokio::test]
async fn test_put_object_tagging_and_standard_headers_are_persisted() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/headers-bucket",
            Body::empty(),
        ))
        .await
        .unwrap();

    let put_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/headers-bucket/report.txt")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("x-amz-tagging", "env=prod&name=quarter%201")
                .header("cache-control", "max-age=60")
                .header("content-disposition", "attachment")
                .header("content-language", "en-US")
                .header("x-amz-storage-class", "STANDARD_IA")
                .body(Body::from("report"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_resp.status(), StatusCode::OK);

    let head_resp = app
        .clone()
        .oneshot(signed_request(
            Method::HEAD,
            "/headers-bucket/report.txt",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(head_resp.status(), StatusCode::OK);
    assert_eq!(head_resp.headers()["cache-control"], "max-age=60");
    assert_eq!(head_resp.headers()["content-disposition"], "attachment");
    assert_eq!(head_resp.headers()["content-language"], "en-US");
    assert_eq!(head_resp.headers()["x-amz-storage-class"], "STANDARD_IA");

    let tags_resp = app
        .oneshot(signed_request(
            Method::GET,
            "/headers-bucket/report.txt?tagging",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(tags_resp.status(), StatusCode::OK);
    let tags_body = String::from_utf8(
        tags_resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(tags_body.contains("<Key>env</Key>"));
    assert!(tags_body.contains("<Value>prod</Value>"));
    assert!(tags_body.contains("<Key>name</Key>"));
    assert!(tags_body.contains("<Value>quarter 1</Value>"));
}

#[tokio::test]
async fn test_virtual_host_bucket_routes_to_s3_object_handlers() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/vh-bucket", Body::empty()))
        .await
        .unwrap();

    let put_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/hello.txt")
                .header("host", "vh-bucket.localhost")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from("virtual host body"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_resp.status(), StatusCode::OK);

    let get_resp = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/hello.txt")
                .header("host", "vh-bucket.localhost")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_resp.status(), StatusCode::OK);
    let body = get_resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"virtual host body");
}

#[tokio::test]
async fn test_virtual_host_multi_segment_key_stays_in_host_bucket() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/vh-main", Body::empty()))
        .await
        .unwrap();
    app.clone()
        .oneshot(signed_request(Method::PUT, "/vh-victim", Body::empty()))
        .await
        .unwrap();

    let put_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/vh-victim/planted.txt")
                .header("host", "vh-main.localhost")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from("multi segment body"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_resp.status(), StatusCode::OK);

    let victim_list = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/vh-victim?list-type=2",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(victim_list.status(), StatusCode::OK);
    let victim_body = String::from_utf8(
        victim_list
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(
        !victim_body.contains("planted.txt"),
        "virtual-host request must never write into the path-named bucket"
    );

    let host_get = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/vh-main/vh-victim/planted.txt",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(
        host_get.status(),
        StatusCode::OK,
        "the object must land under the Host-derived bucket with the full path as key"
    );

    let self_prefix_put = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/vh-main/nested.txt")
                .header("host", "vh-main.localhost")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from("self prefix body"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(self_prefix_put.status(), StatusCode::OK);

    let self_prefix_get = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/vh-main/vh-main/nested.txt",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(self_prefix_get.status(), StatusCode::OK);
    let self_prefix_body = self_prefix_get
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(&self_prefix_body[..], b"self prefix body");

    let tag_put = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/vh-victim/planted.txt?tagging")
                .header("host", "vh-main.localhost")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from(
                    "<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        tag_put.status(),
        StatusCode::OK,
        "subresource queries must survive virtual-host dispatch"
    );

    let tag_get = app
        .oneshot(signed_request(
            Method::GET,
            "/vh-main/vh-victim/planted.txt?tagging",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(tag_get.status(), StatusCode::OK);
    let tag_body = String::from_utf8(
        tag_get
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(
        tag_body.contains("<Key>k</Key>"),
        "tagging written via virtual host must be readable path-style"
    );
}

#[tokio::test]
async fn test_bucket_tagging() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/tag-bucket", Body::empty()))
        .await
        .unwrap();

    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/tag-bucket?tagging")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from(
                    "<Tagging><TagSet><Tag><Key>env</Key><Value>prod</Value></Tag></TagSet></Tagging>",
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/tag-bucket?tagging",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("<Key>env</Key>"));
    assert!(body.contains("<Value>prod</Value>"));

    let resp = app
        .oneshot(signed_request(
            Method::DELETE,
            "/tag-bucket?tagging",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_bucket_location() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/loc-bucket", Body::empty()))
        .await
        .unwrap();

    let resp = app
        .oneshot(signed_request(
            Method::GET,
            "/loc-bucket?location",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("LocationConstraint"));
    assert!(body.contains("us-east-1"));
}

#[tokio::test]
async fn test_bucket_cors() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/cors-bucket", Body::empty()))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/cors-bucket?cors",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/cors-bucket?cors")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from("<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin></CORSRule></CORSConfiguration>"))
                .unwrap(),
        )
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/cors-bucket?cors",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .oneshot(signed_request(
            Method::DELETE,
            "/cors-bucket?cors",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_bucket_acl() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/acl-bucket", Body::empty()))
        .await
        .unwrap();

    let resp = app
        .oneshot(signed_request(
            Method::GET,
            "/acl-bucket?acl",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("AccessControlPolicy"));
    assert!(body.contains("FULL_CONTROL"));
}

#[tokio::test]
async fn test_object_tagging() {
    let (app, _tmp) = test_app();
    let app = app.into_service();

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(Method::PUT, "/tag-bucket", Body::empty()),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(
            Method::PUT,
            "/tag-bucket/myfile.txt",
            Body::from("file content"),
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(Method::GET, "/tag-bucket/myfile.txt?tagging", Body::empty()),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("<TagSet>"));
    assert!(body.contains("</TagSet>"));

    let tag_xml =
        r#"<Tagging><TagSet><Tag><Key>env</Key><Value>prod</Value></Tag></TagSet></Tagging>"#;
    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(
            Method::PUT,
            "/tag-bucket/myfile.txt?tagging",
            Body::from(tag_xml),
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(Method::GET, "/tag-bucket/myfile.txt?tagging", Body::empty()),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("<Key>env</Key>"));
    assert!(body.contains("<Value>prod</Value>"));

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(
            Method::DELETE,
            "/tag-bucket/myfile.txt?tagging",
            Body::empty(),
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(Method::GET, "/tag-bucket/myfile.txt?tagging", Body::empty()),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(!body.contains("<Key>env</Key>"));
}

#[tokio::test]
async fn test_object_acl() {
    let (app, _tmp) = test_app();
    let app = app.into_service();

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(Method::PUT, "/acl-obj-bucket", Body::empty()),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(
            Method::PUT,
            "/acl-obj-bucket/myfile.txt",
            Body::from("content"),
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(Method::GET, "/acl-obj-bucket/myfile.txt?acl", Body::empty()),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("AccessControlPolicy"));
    assert!(body.contains("FULL_CONTROL"));
}

#[tokio::test]
async fn test_object_legal_hold() {
    let (app, _tmp) = test_app();
    let app = app.into_service();

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(Method::PUT, "/lh-bucket", Body::empty()),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(Method::PUT, "/lh-bucket/obj.txt", Body::from("data")),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(Method::GET, "/lh-bucket/obj.txt?legal-hold", Body::empty()),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("<Status>OFF</Status>"));
}

#[tokio::test]
async fn test_list_objects_v1_marker_flow() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/v1-bucket", Body::empty()))
        .await
        .unwrap();

    for name in ["a.txt", "b.txt", "c.txt"] {
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri(format!("/v1-bucket/{}", name))
                    .header("x-access-key", TEST_ACCESS_KEY)
                    .header("x-secret-key", TEST_SECRET_KEY)
                    .body(Body::from("data"))
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/v1-bucket?max-keys=2",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("<Marker></Marker>"));
    assert!(
        body.contains("<IsTruncated>true</IsTruncated>")
            || body.contains("<IsTruncated>false</IsTruncated>")
    );
}

#[tokio::test]
async fn test_bucket_quota_roundtrip() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/quota-bucket", Body::empty()))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/quota-bucket?quota")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"max_size_bytes": 1024, "max_objects": 10}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/quota-bucket?quota",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["quota"]["max_size_bytes"], 1024);
    assert_eq!(body["quota"]["max_objects"], 10);

    let resp = app
        .oneshot(signed_request(
            Method::DELETE,
            "/quota-bucket?quota",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_bucket_policy_and_status_roundtrip() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/policy-bucket", Body::empty()))
        .await
        .unwrap();

    let policy = r#"{
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::policy-bucket/*"
      }]
    }"#;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/policy-bucket?policy")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("content-type", "application/json")
                .body(Body::from(policy))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/policy-bucket?policy",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(body.get("Statement").is_some());

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/policy-bucket?policyStatus",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("<IsPublic>TRUE</IsPublic>"));

    let resp = app
        .oneshot(signed_request(
            Method::DELETE,
            "/policy-bucket?policy",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_public_bucket_policy_allows_anonymous_reads() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/public-bucket", Body::empty()))
        .await
        .unwrap();

    let put_object = Request::builder()
        .method(Method::PUT)
        .uri("/public-bucket/hello.txt")
        .header("x-access-key", TEST_ACCESS_KEY)
        .header("x-secret-key", TEST_SECRET_KEY)
        .body(Body::from("hello world"))
        .unwrap();
    let put_resp = app.clone().oneshot(put_object).await.unwrap();
    assert_eq!(put_resp.status(), StatusCode::OK);

    let policy = r#"{
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Principal": "*",
          "Action": "s3:ListBucket",
          "Resource": "arn:aws:s3:::public-bucket"
        },
        {
          "Effect": "Allow",
          "Principal": "*",
          "Action": "s3:GetObject",
          "Resource": "arn:aws:s3:::public-bucket/*"
        }
      ]
    }"#;

    let policy_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/public-bucket?policy")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("content-type", "application/json")
                .body(Body::from(policy))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(policy_resp.status(), StatusCode::NO_CONTENT);

    let object_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/public-bucket/hello.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(object_resp.status(), StatusCode::OK);
    let object_body = object_resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(object_body.as_ref(), b"hello world");

    let list_resp = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/public-bucket")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_resp.status(), StatusCode::OK);
    let list_body = String::from_utf8(
        list_resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(list_body.contains("hello.txt"));
}

#[tokio::test]
async fn test_narrow_policy_action_does_not_grant_whole_class() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/narrow-bucket", Body::empty()))
        .await
        .unwrap();

    let put_object = Request::builder()
        .method(Method::PUT)
        .uri("/narrow-bucket/data.txt")
        .header("x-access-key", TEST_ACCESS_KEY)
        .header("x-secret-key", TEST_SECRET_KEY)
        .body(Body::from("tagged payload"))
        .unwrap();
    let put_resp = app.clone().oneshot(put_object).await.unwrap();
    assert_eq!(put_resp.status(), StatusCode::OK);

    let policy = r#"{
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Principal": "*",
          "Action": "s3:GetObjectTagging",
          "Resource": "arn:aws:s3:::narrow-bucket/*"
        }
      ]
    }"#;
    let policy_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/narrow-bucket?policy")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("content-type", "application/json")
                .body(Body::from(policy))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(policy_resp.status(), StatusCode::NO_CONTENT);

    let tagging_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/narrow-bucket/data.txt?tagging")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        tagging_resp.status(),
        StatusCode::OK,
        "the exact granted action must be allowed"
    );

    let object_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/narrow-bucket/data.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        object_resp.status(),
        StatusCode::FORBIDDEN,
        "a tagging-only grant must not authorize GetObject"
    );

    let acl_resp = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/narrow-bucket/data.txt?acl")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        acl_resp.status(),
        StatusCode::FORBIDDEN,
        "a tagging-only grant must not authorize other read-class subresources"
    );
}

#[tokio::test]
async fn test_iam_exact_action_reaches_middleware_without_coarse_expansion() {
    const NARROW_ACCESS_KEY: &str = "AKIANARROWACTION0000";
    const NARROW_SECRET_KEY: &str = "narrow-action-secret-key";
    let (app, _tmp) = test_app_with_iam(serde_json::json!({
        "version": 2,
        "users": [
            {
                "user_id": "u-admin",
                "display_name": "admin",
                "enabled": true,
                "access_keys": [{
                    "access_key": TEST_ACCESS_KEY,
                    "secret_key": TEST_SECRET_KEY,
                    "status": "active"
                }],
                "policies": [{"bucket": "*", "actions": ["*"], "prefix": "*"}]
            },
            {
                "user_id": "u-narrow",
                "display_name": "narrow",
                "enabled": true,
                "access_keys": [{
                    "access_key": NARROW_ACCESS_KEY,
                    "secret_key": NARROW_SECRET_KEY,
                    "status": "active"
                }],
                "policies": [{
                    "bucket": "iam-narrow",
                    "actions": ["s3:GetObjectTagging"],
                    "prefix": "*"
                }]
            }
        ]
    }));

    assert_eq!(
        app.clone()
            .oneshot(signed_request(Method::PUT, "/iam-narrow", Body::empty()))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        app.clone()
            .oneshot(signed_request(
                Method::PUT,
                "/iam-narrow/item",
                Body::from("payload")
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );

    let narrow_request = |uri: &'static str| {
        Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("x-access-key", NARROW_ACCESS_KEY)
            .header("x-secret-key", NARROW_SECRET_KEY)
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(
        app.clone()
            .oneshot(narrow_request("/iam-narrow/item?tagging"))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        app.oneshot(narrow_request("/iam-narrow/item"))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn test_multi_delete_authorizes_each_object_resource() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/multi-policy", Body::empty()))
        .await
        .unwrap();
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/multi-policy/delete-me.txt",
            Body::from("payload"),
        ))
        .await
        .unwrap();

    let policy = r#"{
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:DeleteObject",
        "Resource": "arn:aws:s3:::multi-policy/*"
      }]
    }"#;
    let policy_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/multi-policy?policy")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("content-type", "application/json")
                .body(Body::from(policy))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(policy_resp.status(), StatusCode::NO_CONTENT);

    let delete_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/multi-policy?delete")
                .header("content-type", "application/xml")
                .body(Body::from(
                    "<Delete><Object><Key>delete-me.txt</Key></Object></Delete>",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(delete_resp.status(), StatusCode::OK);
    let delete_body = String::from_utf8(
        delete_resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(delete_body.contains("<Key>delete-me.txt</Key>"));
    assert!(!delete_body.contains("<Error>"));

    let get_resp = app
        .oneshot(signed_request(
            Method::GET,
            "/multi-policy/delete-me.txt",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(get_resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_copy_source_header_does_not_bypass_subresource_auth() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/copy-auth", Body::empty()))
        .await
        .unwrap();
    let seed = Request::builder()
        .method(Method::PUT)
        .uri("/copy-auth/src.txt")
        .header("x-access-key", TEST_ACCESS_KEY)
        .header("x-secret-key", TEST_SECRET_KEY)
        .body(Body::from("source object"))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(seed).await.unwrap().status(),
        StatusCode::OK
    );

    let policy = r#"{
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Principal": "*",
          "Action": ["s3:GetObject", "s3:PutObject"],
          "Resource": "arn:aws:s3:::copy-auth/*"
        }
      ]
    }"#;
    let policy_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/copy-auth?policy")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("content-type", "application/json")
                .body(Body::from(policy))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(policy_resp.status(), StatusCode::NO_CONTENT);

    let copy_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/copy-auth/dst.txt")
                .header("x-amz-copy-source", "/copy-auth/src.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        copy_resp.status(),
        StatusCode::OK,
        "a plain CopyObject must still be authorized by the copy grant"
    );

    let retention_resp = app
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/copy-auth/src.txt?retention")
                .header("x-amz-copy-source", "/copy-auth/src.txt")
                .header("content-type", "application/xml")
                .body(Body::from(
                    "<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>2099-01-01T00:00:00Z</RetainUntilDate></Retention>",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        retention_resp.status(),
        StatusCode::FORBIDDEN,
        "a copy grant plus a bogus copy-source header must not authorize PutObjectRetention"
    );
}

#[tokio::test]
async fn test_upload_part_copy_authorizes_source_read() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/upc-src", Body::empty()))
        .await
        .unwrap();
    let seed = Request::builder()
        .method(Method::PUT)
        .uri("/upc-src/private.bin")
        .header("x-access-key", TEST_ACCESS_KEY)
        .header("x-secret-key", TEST_SECRET_KEY)
        .body(Body::from("private source data"))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(seed).await.unwrap().status(),
        StatusCode::OK
    );

    app.clone()
        .oneshot(signed_request(Method::PUT, "/upc-dst", Body::empty()))
        .await
        .unwrap();
    let policy = r#"{
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Principal": "*",
          "Action": "s3:PutObject",
          "Resource": "arn:aws:s3:::upc-dst/*"
        }
      ]
    }"#;
    let policy_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/upc-dst?policy")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("content-type", "application/json")
                .body(Body::from(policy))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(policy_resp.status(), StatusCode::NO_CONTENT);

    let init = app
        .clone()
        .oneshot(signed_request(
            Method::POST,
            "/upc-dst/target.bin?uploads",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(init.status(), StatusCode::OK);
    let init_body = String::from_utf8(
        init.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    let upload_id = init_body
        .split("<UploadId>")
        .nth(1)
        .unwrap()
        .split("</UploadId>")
        .next()
        .unwrap();

    let upc = app
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!(
                    "/upc-dst/target.bin?uploadId={}&partNumber=1",
                    upload_id
                ))
                .header("x-amz-copy-source", "/upc-src/private.bin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        upc.status(),
        StatusCode::FORBIDDEN,
        "UploadPartCopy must authorize a read of the copy source"
    );
}

#[tokio::test]
async fn test_bucket_root_with_trailing_slash_works() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/slash-bucket", Body::empty()))
        .await
        .unwrap();

    let resp = app
        .oneshot(signed_request(Method::GET, "/slash-bucket/", Body::empty()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_bucket_replication_reports_the_rule_actually_in_effect() {
    let (app, state, _tmp) = test_app_and_state();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/repl-bucket", Body::empty()))
        .await
        .unwrap();

    let repl_xml = "<ReplicationConfiguration><Role>arn:aws:iam::123456789012:role/s3-repl</Role><Rule><ID>rule-1</ID><Status>Enabled</Status><Destination><Bucket>arn:aws:s3:::mirror</Bucket></Destination></Rule></ReplicationConfiguration>";

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/repl-bucket?replication")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("content-type", "application/xml")
                .body(Body::from(repl_xml))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_IMPLEMENTED,
        "PutBucketReplication must refuse rather than store XML that enables nothing"
    );
    assert!(
        state.replication.get_rule("repl-bucket").is_none(),
        "a refused PUT must not create a replication rule"
    );

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/repl-bucket?replication",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "GetBucketReplication must report no configuration when nothing is replicating"
    );

    state
        .replication
        .set_rule(myfsio_server::services::replication::ReplicationRule {
            bucket_name: "repl-bucket".to_string(),
            target_connection_id: "conn-1".to_string(),
            target_bucket: "mirror".to_string(),
            enabled: true,
            mode: myfsio_server::services::replication::MODE_NEW_ONLY.to_string(),
            created_at: None,
            stats: Default::default(),
            sync_deletions: true,
            last_pull_at: None,
            filter_prefix: Some("logs/".to_string()),
        })
        .expect("rule persists");

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/repl-bucket?replication",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("<ReplicationConfiguration"));
    assert!(
        body.contains("arn:aws:s3:::mirror"),
        "the reported destination must be the live rule's target, got {}",
        body
    );
    assert!(body.contains("<Status>Enabled</Status>"));
    assert!(body.contains("<Prefix>logs/</Prefix>"));

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::DELETE,
            "/repl-bucket?replication",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(
        state.replication.get_rule("repl-bucket").is_none(),
        "DeleteBucketReplication must stop the replication that was actually running"
    );

    let resp = app
        .oneshot(signed_request(
            Method::GET,
            "/repl-bucket?replication",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_list_parts_via_get_upload_id() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/parts-bucket", Body::empty()))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::POST,
            "/parts-bucket/large.bin?uploads",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    let upload_id = body
        .split("<UploadId>")
        .nth(1)
        .unwrap()
        .split("</UploadId>")
        .next()
        .unwrap();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!(
                    "/parts-bucket/large.bin?uploadId={}&partNumber=1",
                    upload_id
                ))
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from(vec![1_u8, 2, 3, 4]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .oneshot(signed_request(
            Method::GET,
            &format!("/parts-bucket/large.bin?uploadId={}", upload_id),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("ListPartsResult"));
    assert!(body.contains("<PartNumber>1</PartNumber>"));
}

#[tokio::test]
async fn test_conditional_get_and_head() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/cond-bucket", Body::empty()))
        .await
        .unwrap();

    let put_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/cond-bucket/item.txt")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from("abc"))
                .unwrap(),
        )
        .await
        .unwrap();
    let etag = put_resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/cond-bucket/item.txt")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("if-none-match", etag.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/cond-bucket/item.txt")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("if-match", "\"does-not-match\"")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);

    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::HEAD)
                .uri("/cond-bucket/item.txt")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("if-none-match", etag.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
}

#[tokio::test]
async fn test_copy_source_preconditions() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/src-pre", Body::empty()))
        .await
        .unwrap();
    app.clone()
        .oneshot(signed_request(Method::PUT, "/dst-pre", Body::empty()))
        .await
        .unwrap();

    let put_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/src-pre/original.txt")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from("copy source"))
                .unwrap(),
        )
        .await
        .unwrap();
    let etag = put_resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/dst-pre/copied.txt")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("x-amz-copy-source", "/src-pre/original.txt")
                .header("x-amz-copy-source-if-match", "\"bad-etag\"")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);

    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/dst-pre/copied.txt")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("x-amz-copy-source", "/src-pre/original.txt")
                .header("x-amz-copy-source-if-match", etag.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_select_object_content_csv_to_json_events() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/sel-bucket", Body::empty()))
        .await
        .unwrap();

    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/sel-bucket/people.csv")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("content-type", "text/csv")
                .body(Body::from("name,age\nalice,30\nbob,40\n"))
                .unwrap(),
        )
        .await
        .unwrap();

    let select_xml = r#"
<SelectObjectContentRequest>
  <Expression>SELECT name, age FROM S3Object WHERE CAST(age AS INTEGER) &gt;= 35</Expression>
  <ExpressionType>SQL</ExpressionType>
  <InputSerialization>
    <CSV>
      <FileHeaderInfo>USE</FileHeaderInfo>
    </CSV>
  </InputSerialization>
  <OutputSerialization>
    <JSON>
      <RecordDelimiter>\n</RecordDelimiter>
    </JSON>
  </OutputSerialization>
</SelectObjectContentRequest>
"#;

    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/sel-bucket/people.csv?select&select-type=2")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("content-type", "application/xml")
                .body(Body::from(select_xml))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/octet-stream"
    );
    assert_eq!(
        resp.headers().get("x-amz-request-charged").unwrap(),
        "requester"
    );

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let events = parse_select_events(&body);
    assert!(events.iter().any(|(name, _)| name == "Records"));
    assert!(events.iter().any(|(name, _)| name == "Stats"));
    assert!(events.iter().any(|(name, _)| name == "End"));

    let mut records = String::new();
    for (name, payload) in events {
        if name == "Records" {
            records.push_str(&String::from_utf8_lossy(&payload));
        }
    }
    assert!(records.contains("bob"));
    assert!(!records.contains("alice"));
}

#[tokio::test]
async fn test_select_object_content_requires_expression() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/sel-missing-exp",
            Body::empty(),
        ))
        .await
        .unwrap();
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/sel-missing-exp/file.csv")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from("a,b\n1,2\n"))
                .unwrap(),
        )
        .await
        .unwrap();

    let select_xml = r#"
<SelectObjectContentRequest>
  <ExpressionType>SQL</ExpressionType>
  <InputSerialization><CSV><FileHeaderInfo>USE</FileHeaderInfo></CSV></InputSerialization>
  <OutputSerialization><CSV /></OutputSerialization>
</SelectObjectContentRequest>
"#;

    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/sel-missing-exp/file.csv?select")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("content-type", "application/xml")
                .body(Body::from(select_xml))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("Expression is required"));
}

#[tokio::test]
async fn test_select_object_content_rejects_non_xml_content_type() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/sel-ct", Body::empty()))
        .await
        .unwrap();
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/sel-ct/file.csv")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from("a,b\n1,2\n"))
                .unwrap(),
        )
        .await
        .unwrap();

    let select_xml = r#"
<SelectObjectContentRequest>
  <Expression>SELECT * FROM S3Object</Expression>
  <ExpressionType>SQL</ExpressionType>
  <InputSerialization><CSV><FileHeaderInfo>USE</FileHeaderInfo></CSV></InputSerialization>
  <OutputSerialization><CSV /></OutputSerialization>
</SelectObjectContentRequest>
"#;

    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/sel-ct/file.csv?select")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("content-type", "application/json")
                .body(Body::from(select_xml))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("Content-Type must be application/xml or text/xml"));
}

#[tokio::test]
async fn test_select_object_content_aggregates_and_real_bytes_scanned() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/sel-agg", Body::empty()))
        .await
        .unwrap();

    let csv_body = "name,age\nalice,30\nbob,40\ncarol,25\n";
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/sel-agg/people.csv")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from(csv_body))
                .unwrap(),
        )
        .await
        .unwrap();

    let select_xml = r#"
<SelectObjectContentRequest>
  <Expression>SELECT COUNT(*) AS c, SUM(age) AS total FROM S3Object</Expression>
  <ExpressionType>SQL</ExpressionType>
  <InputSerialization><CSV><FileHeaderInfo>USE</FileHeaderInfo></CSV></InputSerialization>
  <OutputSerialization><JSON /></OutputSerialization>
</SelectObjectContentRequest>
"#;

    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/sel-agg/people.csv?select&select-type=2")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("content-type", "application/xml")
                .body(Body::from(select_xml))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let events = parse_select_events(&body);

    let mut records = String::new();
    let mut stats = String::new();
    for (name, payload) in &events {
        if name == "Records" {
            records.push_str(&String::from_utf8_lossy(payload));
        } else if name == "Stats" {
            stats = String::from_utf8_lossy(payload).into_owned();
        }
    }
    let row: serde_json::Value = serde_json::from_str(records.trim()).unwrap();
    assert_eq!(row["c"], serde_json::json!(3));
    assert_eq!(row["total"], serde_json::json!(95));
    assert!(
        stats.contains(&format!("<BytesScanned>{}</BytesScanned>", csv_body.len())),
        "stats should report real bytes scanned: {}",
        stats
    );
    assert!(events.iter().any(|(name, _)| name == "End"));
}

#[tokio::test]
async fn test_select_object_content_json_lines_input_with_limit() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/sel-jsonl", Body::empty()))
        .await
        .unwrap();

    let jsonl = "{\"id\":1,\"tag\":\"keep\"}\n{\"id\":2,\"tag\":\"drop\"}\n{\"id\":3,\"tag\":\"keep\"}\n{\"id\":4,\"tag\":\"keep\"}\n";
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/sel-jsonl/rows.jsonl")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from(jsonl))
                .unwrap(),
        )
        .await
        .unwrap();

    let select_xml = r#"
<SelectObjectContentRequest>
  <Expression>SELECT id FROM S3Object WHERE tag = 'keep' LIMIT 2</Expression>
  <ExpressionType>SQL</ExpressionType>
  <InputSerialization><JSON><Type>LINES</Type></JSON></InputSerialization>
  <OutputSerialization><JSON /></OutputSerialization>
</SelectObjectContentRequest>
"#;

    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/sel-jsonl/rows.jsonl?select&select-type=2")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("content-type", "application/xml")
                .body(Body::from(select_xml))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let events = parse_select_events(&body);
    let mut records = String::new();
    for (name, payload) in &events {
        if name == "Records" {
            records.push_str(&String::from_utf8_lossy(payload));
        }
    }
    assert_eq!(records, "{\"id\":1}\n{\"id\":3}\n");
}

#[tokio::test]
async fn test_select_object_content_rejects_invalid_sql_upfront() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/sel-badsql", Body::empty()))
        .await
        .unwrap();
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/sel-badsql/file.csv")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from("a,b\n1,2\n"))
                .unwrap(),
        )
        .await
        .unwrap();

    for expression in [
        "DROP TABLE S3Object",
        "SELECT * FROM S3Object ORDER BY a",
        "SELECT a FROM S3Object GROUP BY a",
        "SELECT * FROM read_csv_auto('/etc/passwd')",
        "SELECT 1; SELECT 2",
    ] {
        let select_xml = format!(
            r#"
<SelectObjectContentRequest>
  <Expression>{}</Expression>
  <ExpressionType>SQL</ExpressionType>
  <InputSerialization><CSV><FileHeaderInfo>USE</FileHeaderInfo></CSV></InputSerialization>
  <OutputSerialization><CSV /></OutputSerialization>
</SelectObjectContentRequest>
"#,
            expression
        );
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/sel-badsql/file.csv?select")
                    .header("x-access-key", TEST_ACCESS_KEY)
                    .header("x-secret-key", TEST_SECRET_KEY)
                    .header("content-type", "application/xml")
                    .body(Body::from(select_xml))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "should reject: {}",
            expression
        );
    }
}

#[tokio::test]
async fn test_select_object_content_rejects_invalid_serialization_options() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/sel-badser", Body::empty()))
        .await
        .unwrap();
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/sel-badser/file.csv")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from("a,b\n1,2\n"))
                .unwrap(),
        )
        .await
        .unwrap();

    for (input_xml, output_xml) in [
        (
            "<CSV><FileHeaderInfo>BOGUS</FileHeaderInfo></CSV>",
            "<CSV />",
        ),
        ("<JSON><Type>XML</Type></JSON>", "<JSON />"),
        (
            "<CompressionType>GZIP</CompressionType><CSV><FileHeaderInfo>USE</FileHeaderInfo></CSV>",
            "<CSV />",
        ),
        (
            "<CSV><FileHeaderInfo>USE</FileHeaderInfo><FieldDelimiter>ab</FieldDelimiter></CSV>",
            "<CSV />",
        ),
        (
            "<CSV><FileHeaderInfo>USE</FileHeaderInfo><RecordDelimiter>;</RecordDelimiter></CSV>",
            "<CSV />",
        ),
        (
            "<CSV><FileHeaderInfo>USE</FileHeaderInfo></CSV>",
            "<CSV><QuoteFields>SOMETIMES</QuoteFields></CSV>",
        ),
        (
            "<CSV><FileHeaderInfo>USE</FileHeaderInfo><QuoteEscapeCharacter>\\</QuoteEscapeCharacter></CSV>",
            "<CSV />",
        ),
    ] {
        let select_xml = format!(
            r#"
<SelectObjectContentRequest>
  <Expression>SELECT * FROM S3Object</Expression>
  <ExpressionType>SQL</ExpressionType>
  <InputSerialization>{}</InputSerialization>
  <OutputSerialization>{}</OutputSerialization>
</SelectObjectContentRequest>
"#,
            input_xml, output_xml
        );
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/sel-badser/file.csv?select")
                    .header("x-access-key", TEST_ACCESS_KEY)
                    .header("x-secret-key", TEST_SECRET_KEY)
                    .header("content-type", "application/xml")
                    .body(Body::from(select_xml))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "should reject input={} output={}",
            input_xml,
            output_xml
        );
    }
}

#[tokio::test]
async fn test_select_object_content_csv_output_from_csv_input() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/sel-csvout", Body::empty()))
        .await
        .unwrap();
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/sel-csvout/data.csv")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from("city,pop\naustin,42\n\"a,b\",7\n"))
                .unwrap(),
        )
        .await
        .unwrap();

    let select_xml = r#"
<SelectObjectContentRequest>
  <Expression>SELECT city, pop FROM S3Object</Expression>
  <ExpressionType>SQL</ExpressionType>
  <InputSerialization><CSV><FileHeaderInfo>USE</FileHeaderInfo></CSV></InputSerialization>
  <OutputSerialization><CSV /></OutputSerialization>
</SelectObjectContentRequest>
"#;

    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/sel-csvout/data.csv?select&select-type=2")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("content-type", "application/xml")
                .body(Body::from(select_xml))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let events = parse_select_events(&body);
    let mut records = String::new();
    for (name, payload) in &events {
        if name == "Records" {
            records.push_str(&String::from_utf8_lossy(payload));
        }
    }
    assert_eq!(records, "austin,42\n\"a,b\",7\n");
}

#[tokio::test]
async fn test_static_website_serves_configured_error_document() {
    let (app, _tmp) = test_website_app(Some("404.html")).await;

    let resp = app
        .oneshot(website_request(Method::GET, "/missing.html"))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert!(resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("text/html"));
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("Bucket Not Found Page"));
}

#[tokio::test]
async fn test_static_website_default_404_returns_html_body() {
    let (app, _tmp) = test_website_app(None).await;

    let resp = app
        .clone()
        .oneshot(website_request(Method::GET, "/missing.html"))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert!(resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("text/html"));
    let content_length = resp
        .headers()
        .get("content-length")
        .unwrap()
        .to_str()
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert_eq!(body.len(), content_length);
    assert_eq!(body, "<h1>404 page not found</h1>");

    let head_resp = app
        .oneshot(website_request(Method::HEAD, "/missing.html"))
        .await
        .unwrap();
    assert_eq!(head_resp.status(), StatusCode::NOT_FOUND);
    let head_content_length = head_resp
        .headers()
        .get("content-length")
        .unwrap()
        .to_str()
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let head_body = head_resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    assert_eq!(head_content_length, content_length);
    assert!(head_body.is_empty());
}

#[tokio::test]
async fn test_static_website_serves_plaintext_object() {
    let (app, _tmp) = test_website_app(None).await;

    let resp = app
        .oneshot(website_request(Method::GET, "/"))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("text/html"));
    let content_length = resp
        .headers()
        .get("content-length")
        .unwrap()
        .to_str()
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert_eq!(body, WEBSITE_INDEX_BODY);
    assert_eq!(content_length, WEBSITE_INDEX_BODY.len());
}

#[tokio::test]
async fn test_static_website_range_request_returns_partial_slice() {
    let (app, _tmp) = test_website_app(None).await;
    let total = WEBSITE_INDEX_BODY.len();

    let resp = app
        .clone()
        .oneshot(website_range_request("/index.html", "bytes=5-9"))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        resp.headers()
            .get("content-range")
            .unwrap()
            .to_str()
            .unwrap(),
        format!("bytes 5-9/{}", total)
    );
    assert_eq!(
        resp.headers()
            .get("content-length")
            .unwrap()
            .to_str()
            .unwrap(),
        "5"
    );
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert_eq!(body, WEBSITE_INDEX_BODY[5..=9]);

    let unsatisfiable = app
        .oneshot(website_range_request("/index.html", "bytes=500-600"))
        .await
        .unwrap();
    assert_eq!(unsatisfiable.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(
        unsatisfiable
            .headers()
            .get("content-range")
            .unwrap()
            .to_str()
            .unwrap(),
        format!("bytes */{}", total)
    );
}

#[tokio::test]
async fn test_static_website_serves_decrypted_sse_s3_object() {
    let (app, _tmp) = test_encrypted_website_app().await;
    let app = app.into_service();

    let put = tower::ServiceExt::oneshot(
        app.clone(),
        website_object_put_request("/enc-site-bucket/index.html", WEBSITE_INDEX_BODY, None),
    )
    .await
    .unwrap();
    assert_eq!(put.status(), StatusCode::OK);
    assert_eq!(
        put.headers().get("x-amz-server-side-encryption").unwrap(),
        "AES256"
    );

    let resp = tower::ServiceExt::oneshot(app, website_request(Method::GET, "/index.html"))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let content_length = resp
        .headers()
        .get("content-length")
        .unwrap()
        .to_str()
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert_eq!(body, WEBSITE_INDEX_BODY);
    assert_eq!(content_length, WEBSITE_INDEX_BODY.len());
}

#[tokio::test]
async fn test_static_website_head_reports_plaintext_length_for_encrypted_object() {
    let (app, _tmp) = test_encrypted_website_app().await;
    let app = app.into_service();

    let put = tower::ServiceExt::oneshot(
        app.clone(),
        website_object_put_request("/enc-site-bucket/index.html", WEBSITE_INDEX_BODY, None),
    )
    .await
    .unwrap();
    assert_eq!(put.status(), StatusCode::OK);

    let resp = tower::ServiceExt::oneshot(app, website_request(Method::HEAD, "/index.html"))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("content-length")
            .unwrap()
            .to_str()
            .unwrap(),
        WEBSITE_INDEX_BODY.len().to_string()
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(body.is_empty());
}

#[tokio::test]
async fn test_static_website_range_on_encrypted_object_serves_plaintext_slice() {
    let (app, _tmp) = test_encrypted_website_app().await;
    let app = app.into_service();

    let put = tower::ServiceExt::oneshot(
        app.clone(),
        website_object_put_request("/enc-site-bucket/index.html", WEBSITE_INDEX_BODY, None),
    )
    .await
    .unwrap();
    assert_eq!(put.status(), StatusCode::OK);

    let resp = tower::ServiceExt::oneshot(app, website_range_request("/index.html", "bytes=5-9"))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        resp.headers()
            .get("content-range")
            .unwrap()
            .to_str()
            .unwrap(),
        format!("bytes 5-9/{}", WEBSITE_INDEX_BODY.len())
    );
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert_eq!(body, WEBSITE_INDEX_BODY[5..=9]);
}

#[tokio::test]
async fn test_static_website_rejects_sse_c_object_with_forbidden() {
    let (app, _tmp) = test_encrypted_website_app().await;
    let app = app.into_service();
    let customer_key = [0x41u8; 32];

    let put = tower::ServiceExt::oneshot(
        app.clone(),
        website_object_put_request(
            "/enc-site-bucket/index.html",
            WEBSITE_INDEX_BODY,
            Some(&customer_key),
        ),
    )
    .await
    .unwrap();
    assert_eq!(put.status(), StatusCode::OK);

    let resp = tower::ServiceExt::oneshot(app.clone(), website_request(Method::GET, "/index.html"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(!body.contains(WEBSITE_INDEX_BODY));

    let head = tower::ServiceExt::oneshot(app, website_request(Method::HEAD, "/index.html"))
        .await
        .unwrap();
    assert_eq!(head.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_non_admin_authorization_enforced() {
    let iam_json = serde_json::json!({
        "version": 2,
        "users": [{
            "user_id": "u-limited",
            "display_name": "limited",
            "enabled": true,
            "access_keys": [{
                "access_key": TEST_ACCESS_KEY,
                "secret_key": TEST_SECRET_KEY,
                "status": "active"
            }],
            "policies": [{
                "bucket": "authz-bucket",
                "actions": ["list", "read"],
                "prefix": "*"
            }]
        }]
    });

    let tmp = tempfile::TempDir::new().unwrap();
    let iam_path = tmp.path().join(".myfsio.sys").join("config");
    std::fs::create_dir_all(&iam_path).unwrap();
    std::fs::write(iam_path.join("iam.json"), iam_json.to_string()).unwrap();

    let config = myfsio_server::config::ServerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        ui_bind_addr: "127.0.0.1:0".parse().unwrap(),
        storage_root: tmp.path().to_path_buf(),
        region: "us-east-1".to_string(),
        iam_config_path: iam_path.join("iam.json"),
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
        replication_connect_timeout_secs: 5,
        replication_read_timeout_secs: 30,
        replication_max_retries: 2,
        replication_streaming_threshold_bytes: 10_485_760,
        replication_max_failures_per_bucket: 50,
        replication_healer_enabled: false,
        replication_healer_interval_secs: 60,
        replication_healer_max_attempts: 12,
        replication_full_reconcile_interval_hours: 0,
        site_sync_enabled: false,
        site_sync_interval_secs: 60,
        site_sync_batch_size: 100,
        site_sync_connect_timeout_secs: 10,
        site_sync_read_timeout_secs: 120,
        site_sync_max_retries: 2,
        site_sync_clock_skew_tolerance: 1.0,
        ui_enabled: false,
        templates_dir: std::path::PathBuf::from("templates"),
        static_dir: std::path::PathBuf::from("static"),
        allow_legacy_header_auth: true,
        ..myfsio_server::config::ServerConfig::default()
    };
    let state = myfsio_server::state::AppState::new(config);
    state.storage.create_bucket("authz-bucket").await.unwrap();
    let app = myfsio_server::create_router(state);

    let resp = app
        .clone()
        .oneshot(signed_request(Method::PUT, "/denied-bucket", Body::empty()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let resp = app
        .oneshot(signed_request(Method::GET, "/authz-bucket", Body::empty()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

async fn test_app_encrypted() -> (axum::Router, tempfile::TempDir) {
    let tmp = tempfile::TempDir::new().unwrap();
    let iam_path = tmp.path().join(".myfsio.sys").join("config");
    std::fs::create_dir_all(&iam_path).unwrap();

    let iam_json = serde_json::json!({
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
    });
    std::fs::write(iam_path.join("iam.json"), iam_json.to_string()).unwrap();

    let config = myfsio_server::config::ServerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        ui_bind_addr: "127.0.0.1:0".parse().unwrap(),
        storage_root: tmp.path().to_path_buf(),
        region: "us-east-1".to_string(),
        iam_config_path: iam_path.join("iam.json"),
        sigv4_timestamp_tolerance_secs: 900,
        presigned_url_min_expiry: 1,
        presigned_url_max_expiry: 604800,
        secret_key: None,
        encryption_enabled: true,
        kms_enabled: true,
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
        replication_connect_timeout_secs: 5,
        replication_read_timeout_secs: 30,
        replication_max_retries: 2,
        replication_streaming_threshold_bytes: 10_485_760,
        replication_max_failures_per_bucket: 50,
        replication_healer_enabled: false,
        replication_healer_interval_secs: 60,
        replication_healer_max_attempts: 12,
        replication_full_reconcile_interval_hours: 0,
        site_sync_enabled: false,
        site_sync_interval_secs: 60,
        site_sync_batch_size: 100,
        site_sync_connect_timeout_secs: 10,
        site_sync_read_timeout_secs: 120,
        site_sync_max_retries: 2,
        site_sync_clock_skew_tolerance: 1.0,
        ui_enabled: false,
        templates_dir: std::path::PathBuf::from("templates"),
        static_dir: std::path::PathBuf::from("static"),
        allow_legacy_header_auth: true,
        ..myfsio_server::config::ServerConfig::default()
    };
    let state = myfsio_server::state::AppState::new_with_encryption(config)
        .await
        .expect("encryption initialization should succeed");
    let app = myfsio_server::create_router(state);
    (app, tmp)
}

async fn test_app_encrypted_small_parts() -> (axum::Router, tempfile::TempDir) {
    let tmp = tempfile::TempDir::new().unwrap();
    let iam_path = tmp.path().join(".myfsio.sys").join("config");
    std::fs::create_dir_all(&iam_path).unwrap();
    std::fs::write(
        iam_path.join("iam.json"),
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
                "policies": [{ "bucket": "*", "actions": ["*"], "prefix": "*" }]
            }]
        })
        .to_string(),
    )
    .unwrap();

    let config = myfsio_server::config::ServerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        ui_bind_addr: "127.0.0.1:0".parse().unwrap(),
        storage_root: tmp.path().to_path_buf(),
        iam_config_path: iam_path.join("iam.json"),
        encryption_enabled: true,
        kms_enabled: true,
        ui_enabled: false,
        multipart_min_part_size: 1,
        multipart_object_layout: "segments".to_string(),
        allow_legacy_header_auth: true,
        ..myfsio_server::config::ServerConfig::default()
    };
    let state = myfsio_server::state::AppState::new_with_encryption(config)
        .await
        .expect("encryption initialization should succeed");
    let app = myfsio_server::create_router(state);
    (app, tmp)
}

#[tokio::test]
async fn test_sse_multipart_never_uses_segments_layout() {
    let (app, tmp) = test_app_encrypted_small_parts().await;

    app.clone()
        .oneshot(signed_request(Method::PUT, "/enc-mpu", Body::empty()))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/enc-mpu/big.bin?uploads")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("x-amz-server-side-encryption", "AES256")
                .header("x-amz-tagging", "team=storage")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    let upload_id = body
        .split("<UploadId>")
        .nth(1)
        .and_then(|s| s.split("</UploadId>").next())
        .expect("upload id")
        .to_string();

    let part_a = "A".repeat(4096);
    let part_b = "B".repeat(4096);
    let mut etags = Vec::new();
    for (n, data) in [(1, &part_a), (2, &part_b)] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri(format!(
                        "/enc-mpu/big.bin?partNumber={}&uploadId={}",
                        n, upload_id
                    ))
                    .header("x-access-key", TEST_ACCESS_KEY)
                    .header("x-secret-key", TEST_SECRET_KEY)
                    .body(Body::from(data.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        etags.push(
            resp.headers()
                .get("etag")
                .unwrap()
                .to_str()
                .unwrap()
                .to_string(),
        );
    }

    let complete = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part><Part><PartNumber>2</PartNumber><ETag>{}</ETag></Part></CompleteMultipartUpload>",
        etags[0], etags[1]
    );
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/enc-mpu/big.bin?uploadId={}", upload_id))
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("content-type", "application/xml")
                .body(Body::from(complete))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-amz-server-side-encryption")
            .and_then(|value| value.to_str().ok()),
        Some("AES256")
    );
    let complete_body = String::from_utf8(body_bytes(resp).await.to_vec()).unwrap();
    assert!(complete_body.contains("-2"), "{complete_body}");

    let meta_dir = tmp
        .path()
        .join(".myfsio.sys")
        .join("buckets")
        .join("enc-mpu")
        .join("meta");
    let mut committed_metadata = None;
    for entry in std::fs::read_dir(&meta_dir).unwrap().flatten() {
        if entry.path().extension().and_then(|e| e.to_str()) == Some("json") {
            let sidecar: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(entry.path()).unwrap()).unwrap();
            if sidecar
                .get("metadata")
                .and_then(|value| value.get("x-amz-encryption-nonce"))
                .is_some()
            {
                committed_metadata = sidecar.get("metadata").cloned();
            }
        }
    }
    let committed_metadata = committed_metadata.expect("encrypted object sidecar");
    assert!(committed_metadata
        .get("x-amz-encrypted-data-key")
        .and_then(serde_json::Value::as_str)
        .is_some());
    assert!(
        committed_metadata.get("__segments__").is_none(),
        "an encrypted multipart object must never use the segments layout"
    );
    assert!(committed_metadata
        .get("__pending_sse_algorithm__")
        .is_none());
    assert!(committed_metadata
        .get("__pending_sse_kms_key_id__")
        .is_none());
    assert!(committed_metadata.get("__pending_tagging__").is_none());
    let raw = std::fs::read(tmp.path().join("enc-mpu").join("big.bin")).unwrap();
    assert_ne!(raw, format!("{}{}", part_a, part_b).as_bytes());
    assert_eq!(
        committed_metadata
            .get("__size__")
            .and_then(|value| value.as_str()),
        Some(raw.len().to_string().as_str())
    );
    assert!(committed_metadata
        .get("__etag__")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|etag| etag.ends_with("-2")));

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/enc-mpu/big.bin",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.len(), 8192);
    assert_eq!(
        String::from_utf8(body.to_vec()).unwrap(),
        format!("{}{}", part_a, part_b)
    );
    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/enc-mpu/big.bin?tagging",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(body_bytes(resp).await.to_vec()).unwrap();
    assert!(body.contains("<Key>team</Key>"));
    assert!(body.contains("<Value>storage</Value>"));

    let plain_upload_id = {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/enc-mpu/plain.bin?uploads")
                    .header("x-access-key", TEST_ACCESS_KEY)
                    .header("x-secret-key", TEST_SECRET_KEY)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = String::from_utf8(
            resp.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        body.split("<UploadId>")
            .nth(1)
            .and_then(|s| s.split("</UploadId>").next())
            .expect("upload id")
            .to_string()
    };
    let mut plain_etags = Vec::new();
    for (n, data) in [(1, &part_a), (2, &part_b)] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri(format!(
                        "/enc-mpu/plain.bin?partNumber={}&uploadId={}",
                        n, plain_upload_id
                    ))
                    .header("x-access-key", TEST_ACCESS_KEY)
                    .header("x-secret-key", TEST_SECRET_KEY)
                    .body(Body::from(data.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        plain_etags.push(
            resp.headers()
                .get("etag")
                .unwrap()
                .to_str()
                .unwrap()
                .to_string(),
        );
    }
    let complete = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part><Part><PartNumber>2</PartNumber><ETag>{}</ETag></Part></CompleteMultipartUpload>",
        plain_etags[0], plain_etags[1]
    );
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/enc-mpu/plain.bin?uploadId={}", plain_upload_id))
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("content-type", "application/xml")
                .body(Body::from(complete))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let mut plain_sidecar = String::new();
    for entry in std::fs::read_dir(&meta_dir).unwrap().flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json")
            && path.to_string_lossy().contains("plain.bin")
        {
            plain_sidecar.push_str(&std::fs::read_to_string(&path).unwrap());
        }
    }
    assert!(
        plain_sidecar.contains("__segments__"),
        "control: an unencrypted multipart object of this size must use the segments \
         layout, otherwise the assertion above is vacuous: {}",
        plain_sidecar
    );
}

#[tokio::test]
async fn test_sse_kms_multipart_commits_ciphertext_and_final_metadata_once() {
    let (app, tmp) = test_app_encrypted_small_parts().await;
    app.clone()
        .oneshot(signed_request(Method::PUT, "/kms-mpu", Body::empty()))
        .await
        .unwrap();
    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::POST,
            "/myfsio/kms/keys",
            Body::from(r#"{"Description":"multipart"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let key_response: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    let key_id = key_response.get("KeyId").unwrap().as_str().unwrap();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/kms-mpu/object.bin?uploads")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("x-amz-server-side-encryption", "aws:kms")
                .header("x-amz-server-side-encryption-aws-kms-key-id", key_id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let upload_body = body_bytes(resp).await;
    let upload_id = extract_upload_id(std::str::from_utf8(&upload_body).unwrap());
    let first = b"kms-first".to_vec();
    let second = b"kms-second".to_vec();
    let mut etags = Vec::new();
    for (part_number, body) in [(1, first.clone()), (2, second.clone())] {
        let resp = app
            .clone()
            .oneshot(signed_request(
                Method::PUT,
                &format!("/kms-mpu/object.bin?partNumber={part_number}&uploadId={upload_id}"),
                Body::from(body),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        etags.push(etag_from_response(&resp));
    }
    let completion = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"{}\"</ETag></Part><Part><PartNumber>2</PartNumber><ETag>\"{}\"</ETag></Part></CompleteMultipartUpload>",
        etags[0], etags[1]
    );
    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::POST,
            &format!("/kms-mpu/object.bin?uploadId={upload_id}"),
            Body::from(completion),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-amz-server-side-encryption")
            .and_then(|value| value.to_str().ok()),
        Some("aws:kms")
    );
    assert_eq!(
        resp.headers()
            .get("x-amz-server-side-encryption-aws-kms-key-id")
            .and_then(|value| value.to_str().ok()),
        Some(key_id)
    );

    let mut plaintext = first;
    plaintext.extend_from_slice(&second);
    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/kms-mpu/object.bin",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_bytes(resp).await, plaintext);
    let raw = std::fs::read(tmp.path().join("kms-mpu").join("object.bin")).unwrap();
    assert_ne!(raw, plaintext);
    let mut final_metadata = None;
    let meta_dir = tmp
        .path()
        .join(".myfsio.sys")
        .join("buckets")
        .join("kms-mpu")
        .join("meta");
    for entry in std::fs::read_dir(meta_dir).unwrap().flatten() {
        let sidecar: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(entry.path()).unwrap()).unwrap();
        if sidecar
            .get("metadata")
            .and_then(|metadata| metadata.get("x-amz-encryption-key-id"))
            .is_some()
        {
            final_metadata = sidecar.get("metadata").cloned();
        }
    }
    let final_metadata = final_metadata.unwrap();
    assert_eq!(
        final_metadata
            .get("x-amz-encryption-key-id")
            .and_then(serde_json::Value::as_str),
        Some(key_id)
    );
    assert!(final_metadata.get("__pending_sse_algorithm__").is_none());
    assert!(final_metadata.get("__pending_sse_kms_key_id__").is_none());
    assert!(final_metadata.get("__segments__").is_none());
    assert!(final_metadata
        .get("__etag__")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|etag| etag.ends_with("-2")));
    assert_eq!(
        final_metadata
            .get("__size__")
            .and_then(serde_json::Value::as_str),
        Some(raw.len().to_string().as_str())
    );
}

#[tokio::test]
async fn test_sse_s3_encrypt_decrypt_roundtrip() {
    let (app, _tmp) = test_app_encrypted().await;
    let app = app.into_service();

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(Method::PUT, "/enc-bucket", Body::empty()),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let plaintext = "This is secret data that should be encrypted at rest!";
    let req = Request::builder()
        .method(Method::PUT)
        .uri("/enc-bucket/secret.txt")
        .header("x-access-key", TEST_ACCESS_KEY)
        .header("x-secret-key", TEST_SECRET_KEY)
        .header("x-amz-server-side-encryption", "AES256")
        .header("content-type", "text/plain")
        .body(Body::from(plaintext))
        .unwrap();

    let resp = tower::ServiceExt::oneshot(app.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("x-amz-server-side-encryption").unwrap(),
        "AES256"
    );

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(Method::GET, "/enc-bucket/secret.txt", Body::empty()),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("x-amz-server-side-encryption").unwrap(),
        "AES256"
    );
    let body = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    assert_eq!(String::from_utf8(body).unwrap(), plaintext);
}

#[tokio::test]
async fn test_kms_key_crud() {
    let (app, _tmp) = test_app_encrypted().await;
    let app = app.into_service();

    let req = Request::builder()
        .method(Method::POST)
        .uri("/myfsio/kms/keys")
        .header("x-access-key", TEST_ACCESS_KEY)
        .header("x-secret-key", TEST_SECRET_KEY)
        .header("content-type", "application/json")
        .body(Body::from(r#"{"Description": "test key"}"#))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let key_id = body["KeyId"].as_str().unwrap().to_string();
    assert!(!key_id.is_empty());

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(Method::GET, "/myfsio/kms/keys", Body::empty()),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["keys"].as_array().unwrap().len(), 1);

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(
            Method::GET,
            &format!("/myfsio/kms/keys/{}", key_id),
            Body::empty(),
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(
            Method::DELETE,
            &format!("/myfsio/kms/keys/{}", key_id),
            Body::empty(),
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_kms_encrypt_decrypt() {
    let (app, _tmp) = test_app_encrypted().await;
    let app = app.into_service();

    let req = Request::builder()
        .method(Method::POST)
        .uri("/myfsio/kms/keys")
        .header("x-access-key", TEST_ACCESS_KEY)
        .header("x-secret-key", TEST_SECRET_KEY)
        .body(Body::from(r#"{"Description": "enc key"}"#))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.clone(), req).await.unwrap();
    let body: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let key_id = body["KeyId"].as_str().unwrap().to_string();

    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;

    let plaintext = b"Hello KMS!";
    let enc_req = serde_json::json!({
        "KeyId": key_id,
        "Plaintext": B64.encode(plaintext),
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri("/myfsio/kms/encrypt")
        .header("x-access-key", TEST_ACCESS_KEY)
        .header("x-secret-key", TEST_SECRET_KEY)
        .body(Body::from(enc_req.to_string()))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let ct_b64 = body["CiphertextBlob"].as_str().unwrap().to_string();

    let dec_req = serde_json::json!({
        "KeyId": key_id,
        "CiphertextBlob": ct_b64,
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri("/myfsio/kms/decrypt")
        .header("x-access-key", TEST_ACCESS_KEY)
        .header("x-secret-key", TEST_SECRET_KEY)
        .body(Body::from(dec_req.to_string()))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let pt_b64 = body["Plaintext"].as_str().unwrap();
    let result = B64.decode(pt_b64).unwrap();
    assert_eq!(result, plaintext);
}

fn deterministic_payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| ((i * 2654435761usize) >> 16) as u8)
        .collect()
}

async fn put_sse_s3(
    app: &axum::routing::RouterIntoService<Body>,
    bucket: &str,
    key: &str,
    body: Vec<u8>,
) {
    let req = Request::builder()
        .method(Method::PUT)
        .uri(format!("/{}", bucket))
        .header("x-access-key", TEST_ACCESS_KEY)
        .header("x-secret-key", TEST_SECRET_KEY)
        .body(Body::empty())
        .unwrap();
    let _ = tower::ServiceExt::oneshot(app.clone(), req).await.unwrap();

    let req = Request::builder()
        .method(Method::PUT)
        .uri(format!("/{}/{}", bucket, key))
        .header("x-access-key", TEST_ACCESS_KEY)
        .header("x-secret-key", TEST_SECRET_KEY)
        .header("x-amz-server-side-encryption", "AES256")
        .header("content-type", "application/octet-stream")
        .body(Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

async fn range_get(
    app: &axum::routing::RouterIntoService<Body>,
    uri: &str,
    range: &str,
    extra_headers: &[(&str, &str)],
) -> axum::http::Response<Body> {
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("x-access-key", TEST_ACCESS_KEY)
        .header("x-secret-key", TEST_SECRET_KEY)
        .header("range", range);
    for (k, v) in extra_headers {
        builder = builder.header(*k, *v);
    }
    tower::ServiceExt::oneshot(app.clone(), builder.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn body_bytes(resp: axum::http::Response<Body>) -> Vec<u8> {
    resp.into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec()
}

#[tokio::test]
async fn test_sse_s3_range_get_multi_chunk() {
    let (app, _tmp) = test_app_encrypted().await;
    let app = app.into_service();
    let payload = deterministic_payload(200_000);
    put_sse_s3(&app, "rng-mc", "obj.bin", payload.clone()).await;

    let resp = range_get(&app, "/rng-mc/obj.bin", "bytes=60000-140000", &[]).await;
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(resp.headers().get("content-length").unwrap(), "80001");
    assert_eq!(
        resp.headers().get("content-range").unwrap(),
        "bytes 60000-140000/200000"
    );
    assert_eq!(
        resp.headers().get("x-amz-server-side-encryption").unwrap(),
        "AES256"
    );
    assert_eq!(body_bytes(resp).await, payload[60000..=140000]);
}

#[tokio::test]
async fn test_sse_s3_range_get_within_single_chunk() {
    let (app, _tmp) = test_app_encrypted().await;
    let app = app.into_service();
    let payload = deterministic_payload(200_000);
    put_sse_s3(&app, "rng-sc", "obj.bin", payload.clone()).await;

    let resp = range_get(&app, "/rng-sc/obj.bin", "bytes=100-4999", &[]).await;
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(resp.headers().get("content-length").unwrap(), "4900");
    assert_eq!(body_bytes(resp).await, payload[100..=4999]);
}

#[tokio::test]
async fn test_sse_s3_range_get_suffix() {
    let (app, _tmp) = test_app_encrypted().await;
    let app = app.into_service();
    let payload = deterministic_payload(200_000);
    put_sse_s3(&app, "rng-sx", "obj.bin", payload.clone()).await;

    let resp = range_get(&app, "/rng-sx/obj.bin", "bytes=-1024", &[]).await;
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(resp.headers().get("content-length").unwrap(), "1024");
    assert_eq!(
        resp.headers().get("content-range").unwrap(),
        "bytes 198976-199999/200000"
    );
    assert_eq!(body_bytes(resp).await, payload[198_976..]);
}

#[tokio::test]
async fn test_sse_s3_range_get_final_partial_chunk() {
    let (app, _tmp) = test_app_encrypted().await;
    let app = app.into_service();
    let size = 65_536 + 12_345;
    let payload = deterministic_payload(size);
    put_sse_s3(&app, "rng-fp", "obj.bin", payload.clone()).await;

    let last_start = 70_000;
    let last_end = size as u64 - 1;
    let range = format!("bytes={}-{}", last_start, last_end);
    let resp = range_get(&app, "/rng-fp/obj.bin", &range, &[]).await;
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    let expected_len = (last_end - last_start + 1).to_string();
    assert_eq!(
        resp.headers().get("content-length").unwrap(),
        &expected_len.as_str()
    );
    assert_eq!(
        body_bytes(resp).await,
        payload[last_start as usize..=last_end as usize]
    );
}

#[tokio::test]
async fn test_sse_s3_range_get_open_ended() {
    let (app, _tmp) = test_app_encrypted().await;
    let app = app.into_service();
    let payload = deterministic_payload(100_000);
    put_sse_s3(&app, "rng-oe", "obj.bin", payload.clone()).await;

    let resp = range_get(&app, "/rng-oe/obj.bin", "bytes=90000-", &[]).await;
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(resp.headers().get("content-length").unwrap(), "10000");
    assert_eq!(
        resp.headers().get("content-range").unwrap(),
        "bytes 90000-99999/100000"
    );
    assert_eq!(body_bytes(resp).await, payload[90_000..]);
}

#[tokio::test]
async fn test_sse_s3_range_unsatisfiable_for_plaintext_size() {
    let (app, _tmp) = test_app_encrypted().await;
    let app = app.into_service();
    let payload = deterministic_payload(10_000);
    put_sse_s3(&app, "rng-un", "obj.bin", payload).await;

    let resp = range_get(&app, "/rng-un/obj.bin", "bytes=20000-30000", &[]).await;
    assert!(
        resp.status() == StatusCode::RANGE_NOT_SATISFIABLE
            || resp.status() == StatusCode::BAD_REQUEST,
        "unexpected status: {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_plaintext_range_still_works() {
    let (app, _tmp) = test_app_encrypted().await;
    let app = app.into_service();
    let req = Request::builder()
        .method(Method::PUT)
        .uri("/plain-rng")
        .header("x-access-key", TEST_ACCESS_KEY)
        .header("x-secret-key", TEST_SECRET_KEY)
        .body(Body::empty())
        .unwrap();
    let _ = tower::ServiceExt::oneshot(app.clone(), req).await.unwrap();

    let payload = deterministic_payload(8_000);
    let req = Request::builder()
        .method(Method::PUT)
        .uri("/plain-rng/obj.bin")
        .header("x-access-key", TEST_ACCESS_KEY)
        .header("x-secret-key", TEST_SECRET_KEY)
        .body(Body::from(payload.clone()))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = range_get(&app, "/plain-rng/obj.bin", "bytes=100-199", &[]).await;
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert!(resp.headers().get("x-amz-server-side-encryption").is_none());
    assert_eq!(body_bytes(resp).await, payload[100..=199]);
}

async fn poison_object(state: &myfsio_server::state::AppState, bucket: &str, key: &str) {
    use myfsio_storage::fs_backend::{META_KEY_CORRUPTED, META_KEY_CORRUPTION_DETAIL};
    let mut meta = state
        .storage
        .get_object_metadata(bucket, key)
        .await
        .unwrap();
    meta.insert(META_KEY_CORRUPTED.to_string(), "true".to_string());
    meta.insert(
        META_KEY_CORRUPTION_DETAIL.to_string(),
        "test poisoned for §E recovery".to_string(),
    );
    state
        .storage
        .put_object_metadata(bucket, key, &meta)
        .await
        .unwrap();
}

async fn set_legal_hold(state: &myfsio_server::state::AppState, bucket: &str, key: &str) {
    let mut meta = state
        .storage
        .get_object_metadata(bucket, key)
        .await
        .unwrap();
    meta.insert("__legal_hold__".to_string(), "true".to_string());
    state
        .storage
        .put_object_metadata(bucket, key, &meta)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_poisoned_object_can_be_overwritten_via_put() {
    let (app, state, _tmp) = test_app_and_state();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/heal-put", Body::empty()))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/heal-put/healme",
            Body::from("v1 bytes"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    poison_object(&state, "heal-put", "healme").await;

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/heal-put/healme",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        422,
        "poisoned GET must surface 422 ObjectCorrupted"
    );

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/heal-put/healme",
            Body::from("v2 bytes"),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "PUT must overwrite a poisoned object instead of returning 422"
    );

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/heal-put/healme",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_bytes(resp).await, b"v2 bytes".to_vec());
}

#[tokio::test]
async fn test_poisoned_object_can_be_deleted() {
    let (app, state, _tmp) = test_app_and_state();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/heal-del", Body::empty()))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/heal-del/healme",
            Body::from("rotting"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    poison_object(&state, "heal-del", "healme").await;

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::DELETE,
            "/heal-del/healme",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "DELETE must succeed on a poisoned object instead of returning 422"
    );

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::HEAD,
            "/heal-del/healme",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "HEAD after DELETE must be 404, not 422 (poison flag was cleared)"
    );
}

#[tokio::test]
async fn test_poisoned_quarantined_object_can_be_deleted() {
    let (app, state, _tmp) = test_app_and_state();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/heal-q", Body::empty()))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/heal-q/healme",
            Body::from("rotting"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    poison_object(&state, "heal-q", "healme").await;

    let live_path = state
        .storage
        .get_object_path("heal-q", "healme")
        .await
        .unwrap();
    std::fs::remove_file(&live_path).unwrap();

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::DELETE,
            "/heal-q/healme",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::HEAD,
            "/heal-q/healme",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

async fn complete_two_part_upload(
    app: &axum::Router,
    bucket: &str,
    key: &str,
    part1: Vec<u8>,
    part2: Vec<u8>,
) {
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            &format!("/{}", bucket),
            Body::empty(),
        ))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::POST,
            &format!("/{}/{}?uploads", bucket, key),
            Body::empty(),
        ))
        .await
        .unwrap();
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    let upload_id = body
        .split("<UploadId>")
        .nth(1)
        .unwrap()
        .split("</UploadId>")
        .next()
        .unwrap()
        .to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!(
                    "/{}/{}?uploadId={}&partNumber=1",
                    bucket, key, upload_id
                ))
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from(part1))
                .unwrap(),
        )
        .await
        .unwrap();
    let etag1 = resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .trim_matches('"')
        .to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!(
                    "/{}/{}?uploadId={}&partNumber=2",
                    bucket, key, upload_id
                ))
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from(part2))
                .unwrap(),
        )
        .await
        .unwrap();
    let etag2 = resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .trim_matches('"')
        .to_string();

    let complete_xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"{etag1}\"</ETag></Part><Part><PartNumber>2</PartNumber><ETag>\"{etag2}\"</ETag></Part></CompleteMultipartUpload>"
    );
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/{}/{}?uploadId={}", bucket, key, upload_id))
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from(complete_xml))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_part_number_get_returns_only_that_part() {
    let (app, _tmp) = test_app();
    let part1 = vec![b'A'; 1024];
    let part2 = vec![b'B'; 512];
    complete_two_part_upload(&app, "mp-pn", "obj.bin", part1.clone(), part2.clone()).await;

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/mp-pn/obj.bin?partNumber=1",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        resp.headers().get("x-amz-mp-parts-count").unwrap(),
        "2",
        "x-amz-mp-parts-count must reflect the assembled object"
    );
    assert_eq!(
        resp.headers().get("content-range").unwrap(),
        "bytes 0-1023/1536"
    );
    assert_eq!(resp.headers().get("content-length").unwrap(), "1024");
    assert_eq!(body_bytes(resp).await, part1);

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/mp-pn/obj.bin?partNumber=2",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        resp.headers().get("content-range").unwrap(),
        "bytes 1024-1535/1536"
    );
    assert_eq!(resp.headers().get("content-length").unwrap(), "512");
    assert_eq!(body_bytes(resp).await, part2);
}

#[tokio::test]
async fn test_head_part_number_returns_part_size() {
    let (app, _tmp) = test_app();
    let part1 = vec![b'X'; 2048];
    let part2 = vec![b'Y'; 256];
    complete_two_part_upload(&app, "mp-head", "obj.bin", part1, part2).await;

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::HEAD,
            "/mp-head/obj.bin?partNumber=2",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(resp.headers().get("content-length").unwrap(), "256");
    assert_eq!(
        resp.headers().get("content-range").unwrap(),
        "bytes 2048-2303/2304"
    );
    assert_eq!(resp.headers().get("x-amz-mp-parts-count").unwrap(), "2");
}

#[tokio::test]
async fn test_part_number_out_of_range_rejected() {
    let (app, _tmp) = test_app();
    complete_two_part_upload(&app, "mp-oob", "obj.bin", vec![b'A'; 8], vec![b'B'; 8]).await;

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/mp-oob/obj.bin?partNumber=5",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        resp.headers().get("x-amz-error-code").unwrap(),
        "InvalidPart"
    );
}

#[tokio::test]
async fn test_part_number_one_on_non_multipart_returns_full_body() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/single", Body::empty()))
        .await
        .unwrap();

    let payload = b"single-shot upload".to_vec();
    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/single/obj.bin",
            Body::from(payload.clone()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/single/obj.bin?partNumber=1",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "partNumber=1 on a non-multipart object must return the whole body as 200 OK"
    );
    assert!(resp.headers().get("x-amz-mp-parts-count").is_none());
    assert_eq!(body_bytes(resp).await, payload);

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/single/obj.bin?partNumber=2",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_legal_hold_blocks_delete_even_when_poisoned() {
    let (app, state, _tmp) = test_app_and_state();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/lock-poison", Body::empty()))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/lock-poison/locked.bin",
            Body::from("v1"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    set_legal_hold(&state, "lock-poison", "locked.bin").await;
    poison_object(&state, "lock-poison", "locked.bin").await;

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::DELETE,
            "/lock-poison/locked.bin",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "legal-hold must still block DELETE on a poisoned object (poison must not bypass object lock)"
    );

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/lock-poison/locked.bin",
            Body::from("v2"),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "legal-hold must still block PUT-overwrite on a poisoned object"
    );
}

#[tokio::test]
async fn test_governance_retention_blocks_poisoned_delete_without_bypass() {
    let (app, state, _tmp) = test_app_and_state();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/gov-poison", Body::empty()))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/gov-poison/locked.bin",
            Body::from("v1"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let mut meta = state
        .storage
        .get_object_metadata("gov-poison", "locked.bin")
        .await
        .unwrap();
    let retain_until = (chrono::Utc::now() + chrono::Duration::days(1)).to_rfc3339();
    meta.insert(
        "__object_retention__".to_string(),
        format!(
            "{{\"mode\":\"GOVERNANCE\",\"retain_until_date\":\"{}\"}}",
            retain_until
        ),
    );
    state
        .storage
        .put_object_metadata("gov-poison", "locked.bin", &meta)
        .await
        .unwrap();

    poison_object(&state, "gov-poison", "locked.bin").await;

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::DELETE,
            "/gov-poison/locked.bin",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "governance retention must block DELETE without bypass header even when object is poisoned"
    );

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/gov-poison/locked.bin")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("x-amz-bypass-governance-retention", "true")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "with x-amz-bypass-governance-retention=true, poisoned governance-locked object can be deleted"
    );
}

#[tokio::test]
async fn test_part_number_uses_served_snapshot_metadata() {
    let (app, state, _tmp) = test_app_and_state();
    let part1 = vec![b'A'; 1024];
    let part2 = vec![b'B'; 512];
    complete_two_part_upload(&app, "race-pn", "obj.bin", part1.clone(), part2.clone()).await;

    let live_meta = state
        .storage
        .get_object_metadata("race-pn", "obj.bin")
        .await
        .unwrap();
    let original_part_sizes = live_meta
        .get(myfsio_storage::fs_backend::META_KEY_PART_SIZES)
        .cloned()
        .unwrap();
    assert_eq!(original_part_sizes, "1024,512");

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/race-pn/obj.bin?partNumber=2",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        resp.headers().get("content-range").unwrap(),
        "bytes 1024-1535/1536",
        "Content-Range must be derived from the snapshot's __part_sizes__"
    );
    assert_eq!(resp.headers().get("x-amz-mp-parts-count").unwrap(), "2");
    assert_eq!(body_bytes(resp).await, part2);
}

#[tokio::test]
async fn test_bulk_delete_poisoned_unlocked_object_succeeds() {
    let (app, state, _tmp) = test_app_and_state();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/bulk-poison", Body::empty()))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/bulk-poison/dead.bin",
            Body::from("rotting"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    poison_object(&state, "bulk-poison", "dead.bin").await;

    let body = "<Delete><Object><Key>dead.bin</Key></Object></Delete>";
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/bulk-poison?delete")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_str = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(
        body_str.contains("<Deleted>") && body_str.contains("<Key>dead.bin</Key>"),
        "bulk delete on poisoned-unlocked object should report success, got: {}",
        body_str
    );
    assert!(
        !body_str.contains("ObjectCorrupted"),
        "bulk delete must not surface ObjectCorrupted on a poisoned-unlocked object: {}",
        body_str
    );
}

#[tokio::test]
async fn test_bulk_delete_poisoned_locked_object_blocked_by_legal_hold() {
    let (app, state, _tmp) = test_app_and_state();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/bulk-locked", Body::empty()))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/bulk-locked/locked.bin",
            Body::from("rotting"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    set_legal_hold(&state, "bulk-locked", "locked.bin").await;
    poison_object(&state, "bulk-locked", "locked.bin").await;

    let body = "<Delete><Object><Key>locked.bin</Key></Object></Delete>";
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/bulk-locked?delete")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_str = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(
        body_str.contains("<Error>") && body_str.contains("AccessDenied"),
        "bulk delete on legal-hold-locked poisoned object must report AccessDenied, got: {}",
        body_str
    );
    assert!(
        !body_str.contains("ObjectCorrupted"),
        "bulk delete must not surface ObjectCorrupted on a poisoned-locked object: {}",
        body_str
    );

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::HEAD,
            "/bulk-locked/locked.bin",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        422,
        "object must still be poisoned after blocked bulk-delete"
    );
}

async fn upload_zero_length_final_part_object(
    app: &axum::Router,
    bucket: &str,
    key: &str,
    part1: Vec<u8>,
) {
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            &format!("/{}", bucket),
            Body::empty(),
        ))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::POST,
            &format!("/{}/{}?uploads", bucket, key),
            Body::empty(),
        ))
        .await
        .unwrap();
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    let upload_id = body
        .split("<UploadId>")
        .nth(1)
        .unwrap()
        .split("</UploadId>")
        .next()
        .unwrap()
        .to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!(
                    "/{}/{}?uploadId={}&partNumber=1",
                    bucket, key, upload_id
                ))
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from(part1))
                .unwrap(),
        )
        .await
        .unwrap();
    let etag1 = resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .trim_matches('"')
        .to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!(
                    "/{}/{}?uploadId={}&partNumber=2",
                    bucket, key, upload_id
                ))
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let etag2 = resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .trim_matches('"')
        .to_string();

    let complete_xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"{etag1}\"</ETag></Part><Part><PartNumber>2</PartNumber><ETag>\"{etag2}\"</ETag></Part></CompleteMultipartUpload>"
    );
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/{}/{}?uploadId={}", bucket, key, upload_id))
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from(complete_xml))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_zero_length_part_get_omits_content_range() {
    let (app, _tmp) = test_app();
    upload_zero_length_final_part_object(&app, "zero-pn", "obj.bin", vec![b'A'; 1024]).await;

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/zero-pn/obj.bin?partNumber=2",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(resp.headers().get("content-length").unwrap(), "0");
    assert!(
        resp.headers().get("content-range").is_none(),
        "zero-length part GET must not emit Content-Range (would be misleading)"
    );
    assert_eq!(resp.headers().get("x-amz-mp-parts-count").unwrap(), "2");
    assert_eq!(body_bytes(resp).await, Vec::<u8>::new());
}

#[tokio::test]
async fn test_zero_length_part_head_omits_content_range() {
    let (app, _tmp) = test_app();
    upload_zero_length_final_part_object(&app, "zero-pn-h", "obj.bin", vec![b'A'; 1024]).await;

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::HEAD,
            "/zero-pn-h/obj.bin?partNumber=2",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(resp.headers().get("content-length").unwrap(), "0");
    assert!(
        resp.headers().get("content-range").is_none(),
        "zero-length part HEAD must not emit Content-Range"
    );
    assert_eq!(resp.headers().get("x-amz-mp-parts-count").unwrap(), "2");
}

#[tokio::test]
async fn test_zero_length_part_get_evaluates_if_none_match() {
    let (app, _tmp) = test_app();
    upload_zero_length_final_part_object(&app, "zero-pn-cond", "obj.bin", vec![b'A'; 1024]).await;

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::HEAD,
            "/zero-pn-cond/obj.bin",
            Body::empty(),
        ))
        .await
        .unwrap();
    let etag = resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/zero-pn-cond/obj.bin?partNumber=2")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("if-none-match", etag.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_MODIFIED,
        "zero-length part GET must honor If-None-Match like any other GET"
    );
}

async fn enable_versioning(app: &axum::Router, bucket: &str) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/{}?versioning", bucket))
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from(
                    "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(resp.status().is_success());
}

async fn suspend_versioning(app: &axum::Router, bucket: &str) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/{}?versioning", bucket))
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from(
                    "<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(resp.status().is_success());
}

async fn list_versions_xml(app: &axum::Router, bucket: &str) -> String {
    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            &format!("/{}?versions", bucket),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

#[tokio::test]
async fn test_delete_pre_versioning_null_version_single_object() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/null-del-1", Body::empty()))
        .await
        .unwrap();
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-del-1/pre.txt",
            Body::from("legacy"),
        ))
        .await
        .unwrap();

    enable_versioning(&app, "null-del-1").await;

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::DELETE,
            "/null-del-1/pre.txt?versionId=null",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(
        resp.headers().get("x-amz-delete-marker").is_none(),
        "deleting an explicit null version must not produce a delete-marker"
    );

    let body = list_versions_xml(&app, "null-del-1").await;
    assert!(
        !body.contains("<Version>") && !body.contains("<DeleteMarker>"),
        "no Version or DeleteMarker entries should remain after null delete, got: {}",
        body
    );

    let resp = app
        .clone()
        .oneshot(signed_request(Method::DELETE, "/null-del-1", Body::empty()))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "DeleteBucket must succeed once the null version is gone"
    );
}

#[tokio::test]
async fn test_delete_pre_versioning_null_version_batch() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-del-batch",
            Body::empty(),
        ))
        .await
        .unwrap();
    for name in ["pre1", "pre2"] {
        app.clone()
            .oneshot(signed_request(
                Method::PUT,
                &format!("/null-del-batch/{}", name),
                Body::from("legacy"),
            ))
            .await
            .unwrap();
    }

    enable_versioning(&app, "null-del-batch").await;

    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-del-batch/post",
            Body::from("v1"),
        ))
        .await
        .unwrap();

    let list_body = list_versions_xml(&app, "null-del-batch").await;
    let post_version_id = list_body
        .split("<Version>")
        .skip(1)
        .find(|block| block.contains("<Key>post</Key>"))
        .and_then(|block| {
            block
                .split("<VersionId>")
                .nth(1)
                .and_then(|s| s.split_once("</VersionId>").map(|(id, _)| id))
        })
        .filter(|id| *id != "null")
        .expect("post object should have a real version id")
        .to_string();

    let delete_xml = format!(
        "<Delete>\
         <Object><Key>pre1</Key><VersionId>null</VersionId></Object>\
         <Object><Key>pre2</Key><VersionId>null</VersionId></Object>\
         <Object><Key>post</Key><VersionId>{}</VersionId></Object>\
         </Delete>",
        post_version_id
    );

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/null-del-batch?delete")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from(delete_xml))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();

    assert!(
        !body.contains("<DeleteMarker>true</DeleteMarker>"),
        "batch delete of explicit null versions must not produce delete-markers, got: {}",
        body
    );
    assert!(
        !body.contains("<Error>"),
        "batch delete should not have errored on null versions, got: {}",
        body
    );

    let remaining = list_versions_xml(&app, "null-del-batch").await;
    assert!(
        !remaining.contains("<Version>") && !remaining.contains("<DeleteMarker>"),
        "all entries should be gone after batch null delete, got: {}",
        remaining
    );

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::DELETE,
            "/null-del-batch",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_delete_suspended_versioning_null_version() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/null-del-susp", Body::empty()))
        .await
        .unwrap();

    enable_versioning(&app, "null-del-susp").await;

    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-del-susp/k",
            Body::from("v1"),
        ))
        .await
        .unwrap();

    suspend_versioning(&app, "null-del-susp").await;

    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-del-susp/k",
            Body::from("null-overwrite"),
        ))
        .await
        .unwrap();

    let before = list_versions_xml(&app, "null-del-susp").await;
    assert!(
        before.contains("<VersionId>null</VersionId>"),
        "expected a null-version entry while suspended, got: {}",
        before
    );

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::DELETE,
            "/null-del-susp/k?versionId=null",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(
        resp.headers().get("x-amz-delete-marker").is_none(),
        "deleting the null version must not create a delete-marker"
    );

    let after = list_versions_xml(&app, "null-del-susp").await;
    assert!(
        !after.contains("<VersionId>null</VersionId>"),
        "null version should be gone, got: {}",
        after
    );
    assert!(
        after.contains("<Version>"),
        "the prior real version should still be listed, got: {}",
        after
    );
}

#[tokio::test]
async fn test_pre_versioning_object_archived_as_null_on_overwrite() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/null-archive", Body::empty()))
        .await
        .unwrap();
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-archive/k",
            Body::from("legacy"),
        ))
        .await
        .unwrap();

    enable_versioning(&app, "null-archive").await;

    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-archive/k",
            Body::from("real-v1"),
        ))
        .await
        .unwrap();

    let body = list_versions_xml(&app, "null-archive").await;
    assert!(
        body.contains("<VersionId>null</VersionId>"),
        "pre-versioning data must be archived under VersionId=null after overwrite, got: {}",
        body
    );

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/null-archive/k?versionId=null",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the archived null version must be readable by versionId=null"
    );
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&bytes[..], b"legacy");

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::DELETE,
            "/null-archive/k?versionId=null",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(
        resp.headers().get("x-amz-delete-marker").is_none(),
        "deleting an archived null version must not produce a delete-marker"
    );

    let after = list_versions_xml(&app, "null-archive").await;
    assert!(
        !after.contains("<VersionId>null</VersionId>"),
        "null version should be gone after delete, got: {}",
        after
    );
    assert!(
        after.contains("<Version>"),
        "the real version should still be listed, got: {}",
        after
    );
}

#[tokio::test]
async fn test_pre_versioning_soft_delete_archives_under_null() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/null-soft-del", Body::empty()))
        .await
        .unwrap();
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-soft-del/k",
            Body::from("legacy"),
        ))
        .await
        .unwrap();

    enable_versioning(&app, "null-soft-del").await;

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::DELETE,
            "/null-soft-del/k",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        resp.headers()
            .get("x-amz-delete-marker")
            .and_then(|v| v.to_str().ok()),
        Some("true"),
        "soft-delete on a versioning-enabled bucket must produce a delete-marker"
    );

    let body = list_versions_xml(&app, "null-soft-del").await;
    assert!(
        body.contains("<VersionId>null</VersionId>"),
        "pre-versioning data should be archived as VersionId=null on soft-delete, got: {}",
        body
    );

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/null-soft-del/k?versionId=null",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&bytes[..], b"legacy");
}

#[tokio::test]
async fn test_delete_null_version_with_real_version_kept() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/null-del-mix", Body::empty()))
        .await
        .unwrap();

    enable_versioning(&app, "null-del-mix").await;
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-del-mix/k",
            Body::from("real-v1"),
        ))
        .await
        .unwrap();

    suspend_versioning(&app, "null-del-mix").await;
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-del-mix/k",
            Body::from("null-on-top"),
        ))
        .await
        .unwrap();

    let list_body = list_versions_xml(&app, "null-del-mix").await;
    assert!(
        list_body.contains("<VersionId>null</VersionId>"),
        "expected coexisting null + real versions, got: {}",
        list_body
    );
    let real_version_id = list_body
        .split("<Version>")
        .skip(1)
        .find(|block| {
            block.contains("<Key>k</Key>") && !block.contains("<VersionId>null</VersionId>")
        })
        .and_then(|block| {
            block
                .split("<VersionId>")
                .nth(1)
                .and_then(|s| s.split_once("</VersionId>").map(|(id, _)| id))
        })
        .expect("expected a real archived version id")
        .to_string();

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::DELETE,
            "/null-del-mix/k?versionId=null",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(
        resp.headers().get("x-amz-delete-marker").is_none(),
        "deleting the explicit null version must not produce a delete-marker"
    );

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            &format!("/null-del-mix/k?versionId={}", real_version_id),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "real version must remain after null delete"
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"real-v1");

    let after = list_versions_xml(&app, "null-del-mix").await;
    assert!(
        !after.contains("<VersionId>null</VersionId>"),
        "null version should be gone, got: {}",
        after
    );
}

#[tokio::test]
async fn test_batch_delete_null_version_respects_archived_legal_hold() {
    let (app, tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/null-locked", Body::empty()))
        .await
        .unwrap();
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-locked/k",
            Body::from("legacy"),
        ))
        .await
        .unwrap();

    enable_versioning(&app, "null-locked").await;

    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-locked/k",
            Body::from("real-v1"),
        ))
        .await
        .unwrap();

    let null_manifest = tmp
        .path()
        .join(".myfsio.sys")
        .join("buckets")
        .join("null-locked")
        .join("versions")
        .join("k")
        .join("null.json");
    assert!(
        null_manifest.is_file(),
        "expected archived null manifest at {:?}",
        null_manifest
    );
    let mut record: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&null_manifest).unwrap()).unwrap();
    record
        .get_mut("metadata")
        .and_then(|m| m.as_object_mut())
        .unwrap()
        .insert(
            "__legal_hold__".to_string(),
            serde_json::Value::String("ON".to_string()),
        );
    std::fs::write(&null_manifest, serde_json::to_string(&record).unwrap()).unwrap();

    let delete_xml = "<Delete>\
         <Object><Key>k</Key><VersionId>null</VersionId></Object>\
         </Delete>";

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/null-locked?delete")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from(delete_xml))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(
        body.contains("<Error>") && body.contains("<Code>AccessDenied</Code>"),
        "batch delete of legal-hold-protected archived null version must be denied, got: {}",
        body
    );

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/null-locked/k?versionId=null",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the protected archived null version must still exist"
    );
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&bytes[..], b"legacy");
}

async fn write_archived_null_lock(
    tmp: &tempfile::TempDir,
    bucket: &str,
    key: &str,
    lock_metadata: serde_json::Value,
) -> std::path::PathBuf {
    let null_manifest = tmp
        .path()
        .join(".myfsio.sys")
        .join("buckets")
        .join(bucket)
        .join("versions")
        .join(key)
        .join("null.json");
    let mut record: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&null_manifest).unwrap()).unwrap();
    let metadata_obj = record
        .get_mut("metadata")
        .and_then(|m| m.as_object_mut())
        .unwrap();
    if let Some(obj) = lock_metadata.as_object() {
        for (k, v) in obj {
            metadata_obj.insert(k.clone(), v.clone());
        }
    }
    std::fs::write(&null_manifest, serde_json::to_string(&record).unwrap()).unwrap();
    null_manifest
}

#[tokio::test]
async fn test_suspended_put_refuses_to_purge_legal_held_archived_null() {
    let (app, tmp) = test_app();

    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-protected",
            Body::empty(),
        ))
        .await
        .unwrap();
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-protected/k",
            Body::from("legacy"),
        ))
        .await
        .unwrap();

    enable_versioning(&app, "null-protected").await;
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-protected/k",
            Body::from("real-v1"),
        ))
        .await
        .unwrap();

    let null_manifest = write_archived_null_lock(
        &tmp,
        "null-protected",
        "k",
        serde_json::json!({ "__legal_hold__": "ON" }),
    )
    .await;

    suspend_versioning(&app, "null-protected").await;

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-protected/k",
            Body::from("would-purge-locked-null"),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "suspended PUT must be denied while a legal-held archived null version exists"
    );

    assert!(
        null_manifest.is_file(),
        "the locked archived null manifest must remain intact"
    );

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/null-protected/k?versionId=null",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&bytes[..], b"legacy");
}

#[tokio::test]
async fn test_suspended_put_governance_bypass_allows_archived_null_purge() {
    let (app, tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/null-gov", Body::empty()))
        .await
        .unwrap();
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-gov/k",
            Body::from("legacy"),
        ))
        .await
        .unwrap();

    enable_versioning(&app, "null-gov").await;
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-gov/k",
            Body::from("real-v1"),
        ))
        .await
        .unwrap();

    let retain_until = (chrono::Utc::now() + chrono::Duration::days(7)).to_rfc3339();
    let retention_json = serde_json::json!({
        "mode": "GOVERNANCE",
        "retain_until_date": retain_until,
    })
    .to_string();
    write_archived_null_lock(
        &tmp,
        "null-gov",
        "k",
        serde_json::json!({ "__object_retention__": retention_json }),
    )
    .await;

    suspend_versioning(&app, "null-gov").await;

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-gov/k",
            Body::from("blocked-without-bypass"),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "suspended PUT must be denied while GOVERNANCE retention is active without bypass"
    );

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/null-gov/k")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("x-amz-bypass-governance-retention", "true")
                .body(Body::from("allowed-with-bypass"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "suspended PUT with x-amz-bypass-governance-retention: true must succeed, got {}",
        resp.status()
    );

    let after = list_versions_xml(&app, "null-gov").await;
    assert_eq!(
        after.matches("<VersionId>null</VersionId>").count(),
        1,
        "exactly one null version must remain after governance-bypass purge, got: {}",
        after
    );

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/null-gov/k?versionId=null",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        &bytes[..],
        b"allowed-with-bypass",
        "the null version must now be the new bypass-governance write"
    );
}

#[tokio::test]
async fn test_multipart_complete_respects_archived_null_legal_hold() {
    let (app, tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/null-mp", Body::empty()))
        .await
        .unwrap();
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-mp/k",
            Body::from("legacy"),
        ))
        .await
        .unwrap();

    enable_versioning(&app, "null-mp").await;
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-mp/k",
            Body::from("real-v1"),
        ))
        .await
        .unwrap();

    let null_manifest = write_archived_null_lock(
        &tmp,
        "null-mp",
        "k",
        serde_json::json!({ "__legal_hold__": "ON" }),
    )
    .await;

    suspend_versioning(&app, "null-mp").await;

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::POST,
            "/null-mp/k?uploads",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    let upload_id = body
        .split("<UploadId>")
        .nth(1)
        .unwrap()
        .split("</UploadId>")
        .next()
        .unwrap()
        .to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/null-mp/k?uploadId={}&partNumber=1", upload_id))
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from("part1-bytes"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let etag = resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .trim_matches('"')
        .to_string();

    let complete_xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"{}\"</ETag></Part></CompleteMultipartUpload>",
        etag
    );
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/null-mp/k?uploadId={}", upload_id))
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from(complete_xml))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "CompleteMultipartUpload must be denied while a legal-held archived null version exists"
    );

    assert!(
        null_manifest.is_file(),
        "the locked archived null manifest must remain intact after the blocked complete"
    );

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/null-mp/k?versionId=null",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&bytes[..], b"legacy");
}

#[tokio::test]
async fn test_form_post_respects_archived_null_legal_hold() {
    use base64::engine::general_purpose::STANDARD as B64;

    let (app, tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/null-form", Body::empty()))
        .await
        .unwrap();
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-form/k",
            Body::from("legacy"),
        ))
        .await
        .unwrap();

    enable_versioning(&app, "null-form").await;
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-form/k",
            Body::from("real-v1"),
        ))
        .await
        .unwrap();

    let null_manifest = write_archived_null_lock(
        &tmp,
        "null-form",
        "k",
        serde_json::json!({ "__legal_hold__": "ON" }),
    )
    .await;

    suspend_versioning(&app, "null-form").await;

    let policy_json = r#"{"expiration":"2099-01-01T00:00:00Z"}"#;
    let policy_b64 = B64.encode(policy_json.as_bytes());

    let date_stamp = "20260426";
    let region = "us-east-1";
    let service = "s3";
    let credential = format!(
        "{}/{}/{}/{}/aws4_request",
        TEST_ACCESS_KEY, date_stamp, region, service
    );
    let signing_key =
        myfsio_auth::sigv4::derive_signing_key(TEST_SECRET_KEY, date_stamp, region, service);
    let signature = myfsio_auth::sigv4::compute_post_policy_signature(&signing_key, &policy_b64);

    let boundary = "----TestFormBoundary";
    let body = format!(
        "--{boundary}\r\n\
Content-Disposition: form-data; name=\"key\"\r\n\r\n\
k\r\n\
--{boundary}\r\n\
Content-Disposition: form-data; name=\"policy\"\r\n\r\n\
{policy}\r\n\
--{boundary}\r\n\
Content-Disposition: form-data; name=\"x-amz-credential\"\r\n\r\n\
{credential}\r\n\
--{boundary}\r\n\
Content-Disposition: form-data; name=\"x-amz-algorithm\"\r\n\r\n\
AWS4-HMAC-SHA256\r\n\
--{boundary}\r\n\
Content-Disposition: form-data; name=\"x-amz-date\"\r\n\r\n\
{date}T000000Z\r\n\
--{boundary}\r\n\
Content-Disposition: form-data; name=\"x-amz-signature\"\r\n\r\n\
{signature}\r\n\
--{boundary}\r\n\
Content-Disposition: form-data; name=\"file\"; filename=\"k\"\r\n\
Content-Type: application/octet-stream\r\n\r\n\
form-bypass-attempt\r\n\
--{boundary}--\r\n",
        boundary = boundary,
        policy = policy_b64,
        credential = credential,
        date = date_stamp,
        signature = signature,
    );

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/null-form")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header(
                    "content-type",
                    format!("multipart/form-data; boundary={}", boundary),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "form POST upload must be denied while a legal-held archived null version exists"
    );

    assert!(
        null_manifest.is_file(),
        "the locked archived null manifest must remain intact after the blocked form POST"
    );

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/null-form/k?versionId=null",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&bytes[..], b"legacy");
}

async fn ui_post_json(uri: &str, session_id: &str, csrf: &str, json_body: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(
            "cookie",
            format!(
                "{}={}",
                myfsio_server::session::SESSION_COOKIE_NAME,
                session_id
            ),
        )
        .header(myfsio_server::session::CSRF_HEADER_NAME, csrf)
        .header("content-type", "application/json")
        .body(Body::from(json_body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn test_ui_copy_respects_archived_null_legal_hold() {
    let (s3_app, state, tmp) = test_app_and_state();

    s3_app
        .clone()
        .oneshot(signed_request(Method::PUT, "/null-ui-cp", Body::empty()))
        .await
        .unwrap();
    s3_app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-ui-cp/dst",
            Body::from("legacy"),
        ))
        .await
        .unwrap();
    s3_app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-ui-cp/src",
            Body::from("source-bytes"),
        ))
        .await
        .unwrap();

    enable_versioning(&s3_app, "null-ui-cp").await;
    s3_app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-ui-cp/dst",
            Body::from("real-v1"),
        ))
        .await
        .unwrap();

    let null_manifest = write_archived_null_lock(
        &tmp,
        "null-ui-cp",
        "dst",
        serde_json::json!({ "__legal_hold__": "ON" }),
    )
    .await;

    suspend_versioning(&s3_app, "null-ui-cp").await;

    let (session_id, csrf) = authenticated_ui_session(&state);
    let ui_app = myfsio_server::create_ui_router(state.clone());

    let resp = ui_app
        .oneshot(
            ui_post_json(
                "/ui/buckets/null-ui-cp/objects/src/copy",
                &session_id,
                &csrf,
                r#"{"dest_bucket":"null-ui-cp","dest_key":"dst"}"#,
            )
            .await,
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "UI copy onto a key with a legal-held archived null version must be denied"
    );

    assert!(null_manifest.is_file());

    let resp = s3_app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/null-ui-cp/dst?versionId=null",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&bytes[..], b"legacy");
}

#[tokio::test]
async fn test_ui_move_respects_archived_null_legal_hold() {
    let (s3_app, state, tmp) = test_app_and_state();

    s3_app
        .clone()
        .oneshot(signed_request(Method::PUT, "/null-ui-mv", Body::empty()))
        .await
        .unwrap();
    s3_app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-ui-mv/dst",
            Body::from("legacy"),
        ))
        .await
        .unwrap();
    s3_app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-ui-mv/src",
            Body::from("source-bytes"),
        ))
        .await
        .unwrap();

    enable_versioning(&s3_app, "null-ui-mv").await;
    s3_app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-ui-mv/dst",
            Body::from("real-v1"),
        ))
        .await
        .unwrap();

    let null_manifest = write_archived_null_lock(
        &tmp,
        "null-ui-mv",
        "dst",
        serde_json::json!({ "__legal_hold__": "ON" }),
    )
    .await;

    suspend_versioning(&s3_app, "null-ui-mv").await;

    let (session_id, csrf) = authenticated_ui_session(&state);
    let ui_app = myfsio_server::create_ui_router(state.clone());

    let resp = ui_app
        .oneshot(
            ui_post_json(
                "/ui/buckets/null-ui-mv/objects/src/move",
                &session_id,
                &csrf,
                r#"{"dest_bucket":"null-ui-mv","dest_key":"dst"}"#,
            )
            .await,
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "UI move onto a key with a legal-held archived null version must be denied"
    );

    assert!(null_manifest.is_file());

    let resp = s3_app
        .clone()
        .oneshot(signed_request(
            Method::HEAD,
            "/null-ui-mv/src",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the source object must remain since move was rejected"
    );
}

#[tokio::test]
async fn test_ui_complete_multipart_respects_archived_null_legal_hold() {
    let (s3_app, state, tmp) = test_app_and_state();

    s3_app
        .clone()
        .oneshot(signed_request(Method::PUT, "/null-ui-mp", Body::empty()))
        .await
        .unwrap();
    s3_app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-ui-mp/k",
            Body::from("legacy"),
        ))
        .await
        .unwrap();

    enable_versioning(&s3_app, "null-ui-mp").await;
    s3_app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-ui-mp/k",
            Body::from("real-v1"),
        ))
        .await
        .unwrap();

    let null_manifest = write_archived_null_lock(
        &tmp,
        "null-ui-mp",
        "k",
        serde_json::json!({ "__legal_hold__": "ON" }),
    )
    .await;

    suspend_versioning(&s3_app, "null-ui-mp").await;

    let resp = s3_app
        .clone()
        .oneshot(signed_request(
            Method::POST,
            "/null-ui-mp/k?uploads",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    let upload_id = body
        .split("<UploadId>")
        .nth(1)
        .unwrap()
        .split("</UploadId>")
        .next()
        .unwrap()
        .to_string();

    let resp = s3_app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/null-ui-mp/k?uploadId={}&partNumber=1", upload_id))
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from("part1"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let etag = resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .trim_matches('"')
        .to_string();

    let (session_id, csrf) = authenticated_ui_session(&state);
    let ui_app = myfsio_server::create_ui_router(state.clone());

    let payload = format!(r#"{{"parts":[{{"part_number":1,"etag":"{}"}}]}}"#, etag);
    let resp = ui_app
        .oneshot(
            ui_post_json(
                &format!("/ui/buckets/null-ui-mp/multipart/{}/complete", upload_id),
                &session_id,
                &csrf,
                &payload,
            )
            .await,
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "UI CompleteMultipartUpload over a legal-held archived null version must be denied"
    );

    assert!(null_manifest.is_file());

    let resp = s3_app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/null-ui-mp/k?versionId=null",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&bytes[..], b"legacy");
}

#[tokio::test]
async fn test_copy_object_with_version_id_null_copies_archived_null_not_current() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/null-cp-src", Body::empty()))
        .await
        .unwrap();
    app.clone()
        .oneshot(signed_request(Method::PUT, "/null-cp-dst", Body::empty()))
        .await
        .unwrap();
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-cp-src/k",
            Body::from("legacy-null-bytes"),
        ))
        .await
        .unwrap();

    enable_versioning(&app, "null-cp-src").await;
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-cp-src/k",
            Body::from("real-v1-bytes"),
        ))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/null-cp-dst/copy-of-null")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("x-amz-copy-source", "/null-cp-src/k?versionId=null")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "copy with versionId=null must succeed against the archived null version"
    );

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/null-cp-dst/copy-of-null",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        &bytes[..],
        b"legacy-null-bytes",
        "copy must take the archived null version's bytes, not the current real version"
    );

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/null-cp-dst/copy-of-current")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("x-amz-copy-source", "/null-cp-src/k")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/null-cp-dst/copy-of-current",
            Body::empty(),
        ))
        .await
        .unwrap();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        &bytes[..],
        b"real-v1-bytes",
        "copy without versionId must take the current (real) version"
    );
}

#[tokio::test]
async fn test_copy_object_with_version_id_null_after_soft_delete() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/null-cp-dm", Body::empty()))
        .await
        .unwrap();
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-cp-dm-dst",
            Body::empty(),
        ))
        .await
        .unwrap();
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-cp-dm/k",
            Body::from("legacy-null-bytes"),
        ))
        .await
        .unwrap();

    enable_versioning(&app, "null-cp-dm").await;

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::DELETE,
            "/null-cp-dm/k",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        resp.headers()
            .get("x-amz-delete-marker")
            .and_then(|v| v.to_str().ok()),
        Some("true"),
    );

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/null-cp-dm-dst/recovered")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("x-amz-copy-source", "/null-cp-dm/k?versionId=null")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "copy of versionId=null must reach the archived null even when a delete-marker hides the current key"
    );

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/null-cp-dm-dst/recovered",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&bytes[..], b"legacy-null-bytes");
}

#[tokio::test]
async fn test_archived_null_lock_guard_fails_closed_on_unreadable_manifest() {
    let (app, tmp) = test_app();

    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-failclosed",
            Body::empty(),
        ))
        .await
        .unwrap();
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-failclosed/k",
            Body::from("legacy"),
        ))
        .await
        .unwrap();

    enable_versioning(&app, "null-failclosed").await;
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-failclosed/k",
            Body::from("real-v1"),
        ))
        .await
        .unwrap();

    let null_manifest = tmp
        .path()
        .join(".myfsio.sys")
        .join("buckets")
        .join("null-failclosed")
        .join("versions")
        .join("k")
        .join("null.json");
    assert!(null_manifest.is_file());
    std::fs::write(&null_manifest, b"{ this is not valid json").unwrap();

    let null_data = tmp
        .path()
        .join(".myfsio.sys")
        .join("buckets")
        .join("null-failclosed")
        .join("versions")
        .join("k")
        .join("null.bin");
    assert!(null_data.is_file());

    suspend_versioning(&app, "null-failclosed").await;

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-failclosed/k",
            Body::from("would-purge"),
        ))
        .await
        .unwrap();
    assert!(
        !resp.status().is_success(),
        "suspended PUT must fail closed when archived null manifest is unreadable, got {}",
        resp.status()
    );

    assert!(
        null_data.is_file(),
        "the archived null data file must remain since the lock-check failed closed"
    );
}

#[tokio::test]
async fn test_upload_part_copy_with_version_id_null() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/null-mpcp-src", Body::empty()))
        .await
        .unwrap();
    app.clone()
        .oneshot(signed_request(Method::PUT, "/null-mpcp-dst", Body::empty()))
        .await
        .unwrap();
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-mpcp-src/k",
            Body::from("legacy-null-bytes"),
        ))
        .await
        .unwrap();

    enable_versioning(&app, "null-mpcp-src").await;
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-mpcp-src/k",
            Body::from("real-v1-bytes-different"),
        ))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::POST,
            "/null-mpcp-dst/recovered?uploads",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    let upload_id = body
        .split("<UploadId>")
        .nth(1)
        .unwrap()
        .split("</UploadId>")
        .next()
        .unwrap()
        .to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!(
                    "/null-mpcp-dst/recovered?uploadId={}&partNumber=1",
                    upload_id
                ))
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("x-amz-copy-source", "/null-mpcp-src/k?versionId=null")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "UploadPartCopy with versionId=null must resolve to the archived null version"
    );

    let complete_xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"{}\"</ETag></Part></CompleteMultipartUpload>",
        list_first_part_etag(&app, "null-mpcp-dst", "recovered", &upload_id).await,
    );
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/null-mpcp-dst/recovered?uploadId={}", upload_id))
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from(complete_xml))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/null-mpcp-dst/recovered",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        &bytes[..],
        b"legacy-null-bytes",
        "multipart copy must take the archived null version's bytes, not the current real version"
    );
}

async fn list_first_part_etag(
    app: &axum::Router,
    bucket: &str,
    key: &str,
    upload_id: &str,
) -> String {
    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            &format!("/{}/{}?uploadId={}", bucket, key, upload_id),
            Body::empty(),
        ))
        .await
        .unwrap();
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    body.split("<ETag>")
        .nth(1)
        .unwrap()
        .split("</ETag>")
        .next()
        .unwrap()
        .trim_matches('"')
        .to_string()
}

#[tokio::test]
async fn test_suspended_put_compliance_retention_blocks_even_with_bypass() {
    let (app, tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/null-comp", Body::empty()))
        .await
        .unwrap();
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-comp/k",
            Body::from("legacy"),
        ))
        .await
        .unwrap();

    enable_versioning(&app, "null-comp").await;
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-comp/k",
            Body::from("real-v1"),
        ))
        .await
        .unwrap();

    let retain_until = (chrono::Utc::now() + chrono::Duration::days(7)).to_rfc3339();
    let retention_json = serde_json::json!({
        "mode": "COMPLIANCE",
        "retain_until_date": retain_until,
    })
    .to_string();
    write_archived_null_lock(
        &tmp,
        "null-comp",
        "k",
        serde_json::json!({ "__object_retention__": retention_json }),
    )
    .await;

    suspend_versioning(&app, "null-comp").await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/null-comp/k")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("x-amz-bypass-governance-retention", "true")
                .body(Body::from("still-blocked"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "COMPLIANCE retention must block suspended PUT even with bypass-governance header"
    );
}

#[tokio::test]
async fn test_suspended_put_after_soft_delete_does_not_create_duplicate_null() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/null-postdm", Body::empty()))
        .await
        .unwrap();
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-postdm/k",
            Body::from("legacy"),
        ))
        .await
        .unwrap();

    enable_versioning(&app, "null-postdm").await;
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-postdm/k",
            Body::from("real-v1"),
        ))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::DELETE,
            "/null-postdm/k",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        resp.headers()
            .get("x-amz-delete-marker")
            .and_then(|v| v.to_str().ok()),
        Some("true"),
    );

    suspend_versioning(&app, "null-postdm").await;
    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-postdm/k",
            Body::from("post-dm-null"),
        ))
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "suspended PUT after soft-delete should succeed, got {}",
        resp.status()
    );

    let after = list_versions_xml(&app, "null-postdm").await;
    assert_eq!(
        after.matches("<VersionId>null</VersionId>").count(),
        1,
        "exactly one null version must exist after suspended PUT, got: {}",
        after
    );

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/null-postdm/k?versionId=null",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        &bytes[..],
        b"post-dm-null",
        "GET ?versionId=null must resolve unambiguously to the new suspended write"
    );
}

#[tokio::test]
async fn test_suspended_put_purges_stale_archived_null_version() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/null-purge", Body::empty()))
        .await
        .unwrap();
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-purge/k",
            Body::from("legacy"),
        ))
        .await
        .unwrap();

    enable_versioning(&app, "null-purge").await;
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-purge/k",
            Body::from("real-v1"),
        ))
        .await
        .unwrap();

    let mid = list_versions_xml(&app, "null-purge").await;
    assert_eq!(
        mid.matches("<VersionId>null</VersionId>").count(),
        1,
        "after enable+overwrite, exactly one null entry should exist (archived legacy), got: {}",
        mid
    );

    suspend_versioning(&app, "null-purge").await;
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/null-purge/k",
            Body::from("suspended-null"),
        ))
        .await
        .unwrap();

    let after = list_versions_xml(&app, "null-purge").await;
    assert_eq!(
        after.matches("<VersionId>null</VersionId>").count(),
        1,
        "suspended PUT must not create a duplicate null version, got: {}",
        after
    );

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/null-purge/k?versionId=null",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        &bytes[..],
        b"suspended-null",
        "the surviving null version must be the most recent (suspended) write"
    );
}

#[tokio::test]
async fn test_cluster_overview_matches_peer_inbound_access_key_not_outbound_connection() {
    const ADMIN_AK: &str = "AKIAADMINADMINADMIN0";
    const ADMIN_SK: &str = "admin-secret-admin-secret-admin-secret00";
    const PEER_AK: &str = "AKIAPEERPEERPEERPEER";
    const PEER_SK: &str = "peer-secret-peer-secret-peer-secret-peer";
    const OUTBOUND_AK: &str = "AKIAOUTBOUNDOUTBOUND";
    const OUTBOUND_SK: &str = "outbound-secret-outbound-secret-outbound";

    let iam_json = serde_json::json!({
        "version": 2,
        "users": [
            {
                "user_id": "u-admin",
                "display_name": "admin",
                "enabled": true,
                "access_keys": [{
                    "access_key": ADMIN_AK,
                    "secret_key": ADMIN_SK,
                    "status": "active"
                }],
                "policies": [{
                    "bucket": "*",
                    "actions": ["*"],
                    "prefix": "*"
                }]
            },
            {
                "user_id": "u-peer",
                "display_name": "peer",
                "enabled": true,
                "access_keys": [{
                    "access_key": PEER_AK,
                    "secret_key": PEER_SK,
                    "status": "active"
                }],
                "policies": [{
                    "bucket": "peer-bucket",
                    "actions": ["read"],
                    "prefix": "*"
                }]
            },
            {
                "user_id": "u-outbound",
                "display_name": "outbound",
                "enabled": true,
                "access_keys": [{
                    "access_key": OUTBOUND_AK,
                    "secret_key": OUTBOUND_SK,
                    "status": "active"
                }],
                "policies": [{
                    "bucket": "outbound-bucket",
                    "actions": ["read"],
                    "prefix": "*"
                }]
            }
        ]
    });

    let tmp = tempfile::TempDir::new().unwrap();
    let iam_path = tmp.path().join(".myfsio.sys").join("config");
    std::fs::create_dir_all(&iam_path).unwrap();
    std::fs::write(iam_path.join("iam.json"), iam_json.to_string()).unwrap();

    let config = myfsio_server::config::ServerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        ui_bind_addr: "127.0.0.1:0".parse().unwrap(),
        storage_root: tmp.path().to_path_buf(),
        region: "us-east-1".to_string(),
        iam_config_path: iam_path.join("iam.json"),
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
        replication_connect_timeout_secs: 5,
        replication_read_timeout_secs: 30,
        replication_max_retries: 2,
        replication_streaming_threshold_bytes: 10_485_760,
        replication_max_failures_per_bucket: 50,
        replication_healer_enabled: false,
        replication_healer_interval_secs: 60,
        replication_healer_max_attempts: 12,
        replication_full_reconcile_interval_hours: 0,
        site_sync_enabled: false,
        site_sync_interval_secs: 60,
        site_sync_batch_size: 100,
        site_sync_connect_timeout_secs: 10,
        site_sync_read_timeout_secs: 120,
        site_sync_max_retries: 2,
        site_sync_clock_skew_tolerance: 1.0,
        ui_enabled: false,
        templates_dir: std::path::PathBuf::from("templates"),
        static_dir: std::path::PathBuf::from("static"),
        multipart_min_part_size: 1,
        allow_internal_endpoints: true,
        allow_legacy_header_auth: true,
        ..myfsio_server::config::ServerConfig::default()
    };
    let state = myfsio_server::state::AppState::new(config);

    state
        .connections
        .add(myfsio_server::stores::connections::RemoteConnection {
            id: "conn-to-peer".to_string(),
            name: "Peer".to_string(),
            endpoint_url: "http://127.0.0.1:1".to_string(),
            access_key: OUTBOUND_AK.to_string(),
            secret_key: OUTBOUND_SK.to_string(),
            region: "us-east-1".to_string(),
            tuning: None,
        })
        .unwrap();

    let app = myfsio_server::create_router(state.clone());

    let register_body = serde_json::json!({
        "site_id": "peer-site",
        "endpoint": "http://peer.example.com",
        "region": "us-east-1",
        "priority": 100,
        "display_name": "Peer Site",
        "connection_id": "conn-to-peer",
        "peer_inbound_access_key": PEER_AK,
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/myfsio/admin/sites")
                .header("x-access-key", ADMIN_AK)
                .header("x-secret-key", ADMIN_SK)
                .header("content-type", "application/json")
                .body(Body::from(register_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "admin must be able to register peer with peer_inbound_access_key"
    );
    let resp_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let registered: Value = serde_json::from_slice(&resp_bytes).unwrap();
    assert_eq!(registered["peer_inbound_access_key"], PEER_AK);
    assert_eq!(registered["connection_id"], "conn-to-peer");

    state
        .iam
        .mark_access_key_as_peer(PEER_AK, "peer-site")
        .expect("mark PEER_AK as peer credential");

    fn sigv4_get(uri: &str, ak: &str, sk: &str) -> Request<Body> {
        use myfsio_auth::sigv4::{
            build_string_to_sign, compute_signature, derive_signing_key, sha256_hex,
        };
        let now = chrono::Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();
        let region = "us-east-1";
        let service = "s3";
        let payload_hash = sha256_hex(b"");
        let host = "127.0.0.1";
        let (path, query) = match uri.split_once('?') {
            Some((p, q)) => (p, q),
            None => (uri, ""),
        };
        let canonical_headers = format!(
            "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
            host, payload_hash, amz_date
        );
        let signed_headers = "host;x-amz-content-sha256;x-amz-date";
        let canonical_request = format!(
            "GET\n{}\n{}\n{}\n{}\n{}",
            path, query, canonical_headers, signed_headers, payload_hash
        );
        let credential_scope = format!("{}/{}/{}/aws4_request", date_stamp, region, service);
        let sts = build_string_to_sign(&amz_date, &credential_scope, &canonical_request);
        let signing_key = derive_signing_key(sk, &date_stamp, region, service);
        let signature = compute_signature(&signing_key, &sts);
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{},SignedHeaders={},Signature={}",
            ak, credential_scope, signed_headers, signature
        );
        Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("host", host)
            .header("x-amz-content-sha256", payload_hash)
            .header("x-amz-date", amz_date)
            .header("authorization", authorization)
            .body(Body::empty())
            .unwrap()
    }

    let resp = app
        .clone()
        .oneshot(sigv4_get(
            "/myfsio/admin/cluster/overview",
            PEER_AK,
            PEER_SK,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "registered peer's inbound access key must be authorized for cluster overview"
    );

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/myfsio/admin/cluster/overview")
                .header("x-access-key", OUTBOUND_AK)
                .header("x-secret-key", OUTBOUND_SK)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "outbound connection access key must NOT grant cluster overview when not configured as the peer's inbound key"
    );
}

#[tokio::test]
async fn test_peer_signature_replay_is_rejected_after_app_state_restart() {
    const PEER_ACCESS_KEY: &str = "AKIADURABLEPEER00000";
    const PEER_SECRET_KEY: &str = "durable-peer-secret-key";
    let tmp = tempfile::tempdir().unwrap();
    let iam_dir = tmp.path().join(".myfsio.sys").join("config");
    std::fs::create_dir_all(&iam_dir).unwrap();
    let iam_path = iam_dir.join("iam.json");
    std::fs::write(
        &iam_path,
        serde_json::json!({
            "version": 2,
            "users": [{
                "user_id": "u-durable-peer",
                "display_name": "durable-peer",
                "enabled": true,
                "peer_site_id": "peer-site",
                "access_keys": [{
                    "access_key": PEER_ACCESS_KEY,
                    "secret_key": PEER_SECRET_KEY,
                    "status": "active"
                }],
                "policies": []
            }]
        })
        .to_string(),
    )
    .unwrap();
    let config = myfsio_server::config::ServerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        ui_bind_addr: "127.0.0.1:0".parse().unwrap(),
        storage_root: tmp.path().to_path_buf(),
        iam_config_path: iam_path,
        region: "us-east-1".to_string(),
        peer_sigv4_timestamp_tolerance_secs: 60,
        replication_healer_enabled: false,
        ui_enabled: false,
        ..myfsio_server::config::ServerConfig::default()
    };
    let request_time = chrono::Utc::now() + chrono::Duration::seconds(30);
    let amz_date = request_time.format("%Y%m%dT%H%M%SZ").to_string();
    let date_stamp = request_time.format("%Y%m%d").to_string();
    let path = "/myfsio/admin/cluster/overview";
    let payload_hash = myfsio_auth::sigv4::sha256_hex(b"");
    let canonical_headers = format!(
        "host:localhost\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
        payload_hash, amz_date
    );
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let canonical_request = format!(
        "GET\n{}\n\n{}\n{}\n{}",
        path, canonical_headers, signed_headers, payload_hash
    );
    let scope = format!("{}/us-east-1/s3/aws4_request", date_stamp);
    let string_to_sign =
        myfsio_auth::sigv4::build_string_to_sign(&amz_date, &scope, &canonical_request);
    let signing_key =
        myfsio_auth::sigv4::derive_signing_key(PEER_SECRET_KEY, &date_stamp, "us-east-1", "s3");
    let signature = myfsio_auth::sigv4::compute_signature(&signing_key, &string_to_sign);
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        PEER_ACCESS_KEY, scope, signed_headers, signature
    );
    let request = || {
        Request::builder()
            .method(Method::GET)
            .uri(path)
            .header("host", "localhost")
            .header("x-amz-content-sha256", payload_hash.clone())
            .header("x-amz-date", amz_date.clone())
            .header("authorization", authorization.clone())
            .body(Body::empty())
            .unwrap()
    };

    let first_state = myfsio_server::state::AppState::new(config.clone());
    let first = myfsio_server::create_router(first_state)
        .oneshot(request())
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);

    let restarted_state = myfsio_server::state::AppState::new(config);
    assert!(request_time >= restarted_state.boot_time_utc);
    let replay = myfsio_server::create_router(restarted_state)
        .oneshot(request())
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::FORBIDDEN);
}

async fn test_app_sse_c() -> (axum::Router, tempfile::TempDir) {
    test_app_sse_c_with_min(1).await
}

async fn test_app_sse_c_with_min(min_part_size: u64) -> (axum::Router, tempfile::TempDir) {
    let tmp = tempfile::TempDir::new().unwrap();
    let iam_path = tmp.path().join(".myfsio.sys").join("config");
    std::fs::create_dir_all(&iam_path).unwrap();

    let iam_json = serde_json::json!({
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
            "policies": [{ "bucket": "*", "actions": ["*"], "prefix": "*" }]
        }]
    });
    std::fs::write(iam_path.join("iam.json"), iam_json.to_string()).unwrap();

    let config = myfsio_server::config::ServerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        ui_bind_addr: "127.0.0.1:0".parse().unwrap(),
        storage_root: tmp.path().to_path_buf(),
        region: "us-east-1".to_string(),
        iam_config_path: iam_path.join("iam.json"),
        sigv4_timestamp_tolerance_secs: 900,
        presigned_url_min_expiry: 1,
        presigned_url_max_expiry: 604800,
        secret_key: None,
        encryption_enabled: true,
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
        replication_connect_timeout_secs: 5,
        replication_read_timeout_secs: 30,
        replication_max_retries: 2,
        replication_streaming_threshold_bytes: 10_485_760,
        replication_max_failures_per_bucket: 50,
        replication_healer_enabled: false,
        replication_healer_interval_secs: 60,
        replication_healer_max_attempts: 12,
        replication_full_reconcile_interval_hours: 0,
        site_sync_enabled: false,
        site_sync_interval_secs: 60,
        site_sync_batch_size: 100,
        site_sync_connect_timeout_secs: 10,
        site_sync_read_timeout_secs: 120,
        site_sync_max_retries: 2,
        site_sync_clock_skew_tolerance: 1.0,
        ui_enabled: false,
        templates_dir: std::path::PathBuf::from("templates"),
        static_dir: std::path::PathBuf::from("static"),
        multipart_min_part_size: min_part_size,
        encryption_chunk_size_bytes: 16384,
        allow_legacy_header_auth: true,
        ..myfsio_server::config::ServerConfig::default()
    };
    let state = myfsio_server::state::AppState::new_with_encryption(config)
        .await
        .expect("encryption initialization should succeed");
    let app = myfsio_server::create_router(state);
    (app, tmp)
}

fn sse_c_triplet(key: &[u8; 32]) -> (String, String) {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use md5::{Digest, Md5};
    let key_b64 = B64.encode(key);
    let mut hasher = Md5::new();
    hasher.update(key);
    let md5_b64 = B64.encode(hasher.finalize());
    (key_b64, md5_b64)
}

fn sse_c_request(method: Method, uri: &str, key: Option<&[u8; 32]>, body: Body) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-access-key", TEST_ACCESS_KEY)
        .header("x-secret-key", TEST_SECRET_KEY);
    if let Some(k) = key {
        let (key_b64, md5_b64) = sse_c_triplet(k);
        builder = builder
            .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
            .header("x-amz-server-side-encryption-customer-key", key_b64)
            .header("x-amz-server-side-encryption-customer-key-MD5", md5_b64);
    }
    builder.body(body).unwrap()
}

fn sse_c_range_request(uri: &str, key: Option<&[u8; 32]>, range: &str) -> Request<Body> {
    let mut request = sse_c_request(Method::GET, uri, key, Body::empty());
    request
        .headers_mut()
        .insert("range", range.parse().unwrap());
    request
}

fn extract_upload_id(body: &str) -> String {
    body.split("<UploadId>")
        .nth(1)
        .unwrap()
        .split("</UploadId>")
        .next()
        .unwrap()
        .to_string()
}

fn etag_from_response(resp: &axum::response::Response) -> String {
    resp.headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .trim_matches('"')
        .to_string()
}

fn copy_source_sse_c_request(
    method: Method,
    uri: &str,
    copy_source: &str,
    key: Option<&[u8; 32]>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-access-key", TEST_ACCESS_KEY)
        .header("x-secret-key", TEST_SECRET_KEY)
        .header("x-amz-copy-source", copy_source);
    if let Some(k) = key {
        let (key_b64, md5_b64) = sse_c_triplet(k);
        builder = builder
            .header(
                "x-amz-copy-source-server-side-encryption-customer-algorithm",
                "AES256",
            )
            .header(
                "x-amz-copy-source-server-side-encryption-customer-key",
                key_b64,
            )
            .header(
                "x-amz-copy-source-server-side-encryption-customer-key-MD5",
                md5_b64,
            );
    }
    builder.body(Body::empty()).unwrap()
}

#[tokio::test]
async fn test_copy_from_sse_c_source_requires_the_matching_customer_key() {
    let (app, _tmp) = test_app_sse_c().await;
    let app = app.into_service();

    let key = [0x61u8; 32];
    let wrong_key = [0x62u8; 32];
    let bucket = "ssec-copy-gate";
    let object = "secret.bin";
    let plaintext: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();

    tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(Method::PUT, &format!("/{bucket}"), Body::empty()),
    )
    .await
    .unwrap();
    let put = tower::ServiceExt::oneshot(
        app.clone(),
        sse_c_request(
            Method::PUT,
            &format!("/{bucket}/{object}"),
            Some(&key),
            Body::from(plaintext.clone()),
        ),
    )
    .await
    .unwrap();
    assert_eq!(put.status(), StatusCode::OK);

    let copy_source = format!("/{bucket}/{object}");
    for (customer_key, expected_status, expected_code) in [
        (None, StatusCode::BAD_REQUEST, "<Code>InvalidRequest</Code>"),
        (
            Some(&wrong_key),
            StatusCode::FORBIDDEN,
            "<Code>AccessDenied</Code>",
        ),
    ] {
        let resp = tower::ServiceExt::oneshot(
            app.clone(),
            copy_source_sse_c_request(
                Method::PUT,
                &format!("/{bucket}/copied.bin"),
                &copy_source,
                customer_key,
            ),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), expected_status);
        let body = String::from_utf8(body_bytes(resp).await).unwrap();
        assert!(body.contains(expected_code), "{body}");
    }

    let init = tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(
            Method::POST,
            &format!("/{bucket}/mpu-copied.bin?uploads"),
            Body::empty(),
        ),
    )
    .await
    .unwrap();
    assert_eq!(init.status(), StatusCode::OK);
    let upload_id = extract_upload_id(&String::from_utf8(body_bytes(init).await).unwrap());

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        copy_source_sse_c_request(
            Method::PUT,
            &format!("/{bucket}/mpu-copied.bin?partNumber=1&uploadId={upload_id}"),
            &copy_source,
            Some(&wrong_key),
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = String::from_utf8(body_bytes(resp).await).unwrap();
    assert!(body.contains("<Code>AccessDenied</Code>"), "{body}");

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        copy_source_sse_c_request(
            Method::PUT,
            &format!("/{bucket}/copied.bin"),
            &copy_source,
            Some(&key),
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let got = tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(Method::GET, &format!("/{bucket}/copied.bin"), Body::empty()),
    )
    .await
    .unwrap();
    assert_eq!(got.status(), StatusCode::OK);
    assert_eq!(body_bytes(got).await, plaintext);
}

#[tokio::test]
async fn test_sse_c_range_get_key_errors_match_whole_object_get() {
    let (app, _tmp) = test_app_sse_c().await;
    let app = app.into_service();

    let key = [0x53u8; 32];
    let wrong_key = [0x54u8; 32];
    let bucket = "ssec-range";
    let object = "secret.bin";
    let uri = format!("/{bucket}/{object}");
    let plaintext: Vec<u8> = (0..5000u32).map(|i| (i % 256) as u8).collect();

    tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(Method::PUT, &format!("/{bucket}"), Body::empty()),
    )
    .await
    .unwrap();

    let put = tower::ServiceExt::oneshot(
        app.clone(),
        sse_c_request(Method::PUT, &uri, Some(&key), Body::from(plaintext.clone())),
    )
    .await
    .unwrap();
    assert_eq!(put.status(), StatusCode::OK);

    for (customer_key, expected_status, expected_code, expected_message) in [
        (
            None,
            StatusCode::BAD_REQUEST,
            "<Code>InvalidRequest</Code>",
            "Object was created with SSE-C; the SSE-C customer key headers are required",
        ),
        (
            Some(&wrong_key),
            StatusCode::FORBIDDEN,
            "<Code>AccessDenied</Code>",
            "The SSE-C customer key does not match the key used to encrypt this object",
        ),
    ] {
        let whole = tower::ServiceExt::oneshot(
            app.clone(),
            sse_c_request(Method::GET, &uri, customer_key, Body::empty()),
        )
        .await
        .unwrap();
        let ranged = tower::ServiceExt::oneshot(
            app.clone(),
            sse_c_range_request(&uri, customer_key, "bytes=10-19"),
        )
        .await
        .unwrap();

        assert_eq!(ranged.status(), whole.status());
        assert_eq!(ranged.status(), expected_status);
        assert_eq!(
            ranged.headers().get("x-amz-error-code"),
            whole.headers().get("x-amz-error-code")
        );
        let whole_body = String::from_utf8(body_bytes(whole).await).unwrap();
        let ranged_body = String::from_utf8(body_bytes(ranged).await).unwrap();
        assert!(whole_body.contains(expected_code), "{whole_body}");
        assert!(ranged_body.contains(expected_code), "{ranged_body}");
        assert!(whole_body.contains(expected_message), "{whole_body}");
        assert!(ranged_body.contains(expected_message), "{ranged_body}");
    }

    let ranged =
        tower::ServiceExt::oneshot(app, sse_c_range_request(&uri, Some(&key), "bytes=10-19"))
            .await
            .unwrap();
    assert_eq!(ranged.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        ranged
            .headers()
            .get("content-range")
            .unwrap()
            .to_str()
            .unwrap(),
        format!("bytes 10-19/{}", plaintext.len())
    );
    assert_eq!(body_bytes(ranged).await, plaintext[10..=19].to_vec());
}

#[tokio::test]
async fn test_sse_c_multipart_roundtrip_and_security() {
    let (app, tmp) = test_app_sse_c().await;
    let app = app.into_service();

    let key = [0x37u8; 32];
    let wrong_key = [0x38u8; 32];
    let (key_b64, md5_b64) = sse_c_triplet(&key);

    let bucket = "ssec-mp";
    let object = "secret/big.bin";

    tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(Method::PUT, &format!("/{bucket}"), Body::empty()),
    )
    .await
    .unwrap();

    let part1: Vec<u8> = (0..40000u32).map(|i| (i % 256) as u8).collect();
    let part2: Vec<u8> = (0..1234u32).map(|i| ((i * 7) % 256) as u8).collect();
    let mut full = part1.clone();
    full.extend_from_slice(&part2);
    let total = full.len() as u64;

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        sse_c_request(
            Method::POST,
            &format!("/{bucket}/{object}?uploads"),
            Some(&key),
            Body::empty(),
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-amz-server-side-encryption-customer-algorithm")
            .unwrap(),
        "AES256"
    );
    assert_eq!(
        resp.headers()
            .get("x-amz-server-side-encryption-customer-key-MD5")
            .unwrap(),
        md5_b64.as_str()
    );
    let init_body = String::from_utf8(body_bytes(resp).await).unwrap();
    let upload_id = extract_upload_id(&init_body);

    let manifest_path = tmp
        .path()
        .join(".myfsio.sys")
        .join("multipart")
        .join(bucket)
        .join(&upload_id)
        .join("manifest.json");
    let manifest = std::fs::read_to_string(&manifest_path).unwrap();
    assert!(
        !manifest.contains(&key_b64),
        "manifest must never contain the raw SSE-C customer key"
    );
    assert!(manifest.contains("__mpu_sse_c__"));
    assert!(manifest.contains("__mpu_wrapped_odk__"));
    assert!(!manifest.contains("__pending_sse_c_customer_key__"));

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        sse_c_request(
            Method::PUT,
            &format!("/{bucket}/{object}?uploadId={upload_id}&partNumber=1"),
            Some(&key),
            Body::from(part1.clone()),
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let etag1 = etag_from_response(&resp);

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        sse_c_request(
            Method::PUT,
            &format!("/{bucket}/{object}?uploadId={upload_id}&partNumber=2"),
            Some(&key),
            Body::from(part2.clone()),
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let etag2 = etag_from_response(&resp);

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        sse_c_request(
            Method::PUT,
            &format!("/{bucket}/{object}?uploadId={upload_id}&partNumber=3"),
            None,
            Body::from(vec![0u8; 10]),
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "uploading a part to an SSE-C upload without the key must be rejected"
    );

    let complete_xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"{etag1}\"</ETag></Part><Part><PartNumber>2</PartNumber><ETag>\"{etag2}\"</ETag></Part></CompleteMultipartUpload>"
    );
    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        sse_c_request(
            Method::POST,
            &format!("/{bucket}/{object}?uploadId={upload_id}"),
            None,
            Body::from(complete_xml),
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let stored = std::fs::read(tmp.path().join(bucket).join("secret").join("big.bin")).unwrap();
    assert_ne!(stored, full, "object must be encrypted at rest");
    assert!(
        stored.len() as u64 > total,
        "stored ciphertext should be larger than plaintext"
    );

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        sse_c_request(
            Method::GET,
            &format!("/{bucket}/{object}"),
            Some(&key),
            Body::empty(),
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("content-length").unwrap(),
        total.to_string().as_str()
    );
    assert_eq!(body_bytes(resp).await, full);

    for (s, e) in [
        (0u64, 0u64),
        (16000, 17000),
        (39000, 40500),
        (total - 1, total - 1),
        (0, total - 1),
    ] {
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("/{bucket}/{object}"))
            .header("x-access-key", TEST_ACCESS_KEY)
            .header("x-secret-key", TEST_SECRET_KEY)
            .header("range", format!("bytes={s}-{e}"))
            .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
            .header("x-amz-server-side-encryption-customer-key", key_b64.clone())
            .header(
                "x-amz-server-side-encryption-customer-key-MD5",
                md5_b64.clone(),
            )
            .body(Body::empty())
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app.clone(), req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::PARTIAL_CONTENT,
            "range {s}-{e} should be 206"
        );
        assert_eq!(
            resp.headers().get("content-range").unwrap(),
            format!("bytes {s}-{e}/{total}").as_str()
        );
        assert_eq!(
            body_bytes(resp).await,
            full[s as usize..=e as usize].to_vec(),
            "range {s}-{e} body mismatch"
        );
    }

    for (pn, expected, range) in [
        (
            1u32,
            part1.clone(),
            format!("bytes 0-{}/{}", part1.len() - 1, total),
        ),
        (
            2u32,
            part2.clone(),
            format!("bytes {}-{}/{}", part1.len(), total - 1, total),
        ),
    ] {
        let resp = tower::ServiceExt::oneshot(
            app.clone(),
            sse_c_request(
                Method::GET,
                &format!("/{bucket}/{object}?partNumber={pn}"),
                Some(&key),
                Body::empty(),
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::PARTIAL_CONTENT,
            "partNumber {pn}"
        );
        assert_eq!(
            resp.headers().get("x-amz-mp-parts-count").unwrap(),
            "2",
            "partNumber {pn} parts-count"
        );
        assert_eq!(
            resp.headers().get("content-range").unwrap(),
            range.as_str(),
            "partNumber {pn} content-range"
        );
        assert_eq!(body_bytes(resp).await, expected, "partNumber {pn} body");
    }

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        sse_c_request(
            Method::GET,
            &format!("/{bucket}/{object}"),
            Some(&wrong_key),
            Body::empty(),
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "wrong key GET → 403");

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(Method::GET, &format!("/{bucket}/{object}"), Body::empty()),
    )
    .await
    .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "missing key GET → 400"
    );

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        sse_c_request(
            Method::HEAD,
            &format!("/{bucket}/{object}"),
            Some(&key),
            Body::empty(),
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("content-length").unwrap(),
        total.to_string().as_str()
    );

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        sse_c_request(
            Method::HEAD,
            &format!("/{bucket}/{object}"),
            Some(&wrong_key),
            Body::empty(),
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "wrong key HEAD → 403");

    let _ = app;
}

#[tokio::test]
async fn test_sse_c_multipart_part_replacement_roundtrips() {
    let (app, tmp) = test_app_sse_c().await;
    let app = app.into_service();

    let key = [0x4cu8; 32];
    let bucket = "ssec-replace";
    let object = "doc.bin";

    tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(Method::PUT, &format!("/{bucket}"), Body::empty()),
    )
    .await
    .unwrap();

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        sse_c_request(
            Method::POST,
            &format!("/{bucket}/{object}?uploads"),
            Some(&key),
            Body::empty(),
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let upload_id = extract_upload_id(&String::from_utf8(body_bytes(resp).await).unwrap());

    let part1_v1: Vec<u8> = vec![0xA1u8; 20000];
    let part1_v2: Vec<u8> = (0..20000u32).map(|i| (i % 256) as u8).collect();
    let part2: Vec<u8> = (0..1234u32).map(|i| ((i * 5) % 256) as u8).collect();

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        sse_c_request(
            Method::PUT,
            &format!("/{bucket}/{object}?uploadId={upload_id}&partNumber=1"),
            Some(&key),
            Body::from(part1_v1.clone()),
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        sse_c_request(
            Method::PUT,
            &format!("/{bucket}/{object}?uploadId={upload_id}&partNumber=1"),
            Some(&key),
            Body::from(part1_v2.clone()),
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let etag1 = etag_from_response(&resp);

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        sse_c_request(
            Method::PUT,
            &format!("/{bucket}/{object}?uploadId={upload_id}&partNumber=2"),
            Some(&key),
            Body::from(part2.clone()),
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let etag2 = etag_from_response(&resp);

    let complete_xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"{etag1}\"</ETag></Part><Part><PartNumber>2</PartNumber><ETag>\"{etag2}\"</ETag></Part></CompleteMultipartUpload>"
    );
    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        sse_c_request(
            Method::POST,
            &format!("/{bucket}/{object}?uploadId={upload_id}"),
            None,
            Body::from(complete_xml),
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let mut expected = part1_v2.clone();
    expected.extend_from_slice(&part2);

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        sse_c_request(
            Method::GET,
            &format!("/{bucket}/{object}"),
            Some(&key),
            Body::empty(),
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        body_bytes(resp).await,
        expected,
        "after replacing part 1, GET must return the replacement bytes decrypted correctly"
    );

    let _ = tmp;
}

#[tokio::test]
async fn test_sse_c_multipart_upload_part_copy_rejected() {
    let (app, _tmp) = test_app_sse_c().await;
    let app = app.into_service();

    let key = [0x5du8; 32];
    let (key_b64, md5_b64) = sse_c_triplet(&key);

    let src_bucket = "ssec-copy-src";
    let dst_bucket = "ssec-copy-dst";
    let src_key = "source.bin";
    let dst_key = "dest.bin";

    for b in [src_bucket, dst_bucket] {
        tower::ServiceExt::oneshot(
            app.clone(),
            signed_request(Method::PUT, &format!("/{b}"), Body::empty()),
        )
        .await
        .unwrap();
    }

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(
            Method::PUT,
            &format!("/{src_bucket}/{src_key}"),
            Body::from(vec![0x7eu8; 8192]),
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        sse_c_request(
            Method::POST,
            &format!("/{dst_bucket}/{dst_key}?uploads"),
            Some(&key),
            Body::empty(),
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let upload_id = extract_upload_id(&String::from_utf8(body_bytes(resp).await).unwrap());

    let req = Request::builder()
        .method(Method::PUT)
        .uri(format!(
            "/{dst_bucket}/{dst_key}?uploadId={upload_id}&partNumber=1"
        ))
        .header("x-access-key", TEST_ACCESS_KEY)
        .header("x-secret-key", TEST_SECRET_KEY)
        .header("x-amz-copy-source", format!("/{src_bucket}/{src_key}"))
        .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
        .header("x-amz-server-side-encryption-customer-key", key_b64)
        .header("x-amz-server-side-encryption-customer-key-MD5", md5_b64)
        .body(Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app.clone(), req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_IMPLEMENTED,
        "UploadPartCopy into an SSE-C multipart upload must be rejected, not stored unencrypted"
    );
    let body = String::from_utf8(body_bytes(resp).await).unwrap();
    assert!(
        body.contains("NotImplemented"),
        "expected NotImplemented error, got: {body}"
    );
}

#[tokio::test]
async fn test_sse_c_multipart_min_part_size_uses_plaintext() {
    let min_part_size: u64 = 140;
    let (app, _tmp) = test_app_sse_c_with_min(min_part_size).await;
    let app = app.into_service();

    let key = [0x6eu8; 32];
    let bucket = "ssec-minsize";
    let object = "small.bin";

    tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(Method::PUT, &format!("/{bucket}"), Body::empty()),
    )
    .await
    .unwrap();

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        sse_c_request(
            Method::POST,
            &format!("/{bucket}/{object}?uploads"),
            Some(&key),
            Body::empty(),
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let upload_id = extract_upload_id(&String::from_utf8(body_bytes(resp).await).unwrap());

    let part1 = vec![0x11u8; 100];
    let part2 = vec![0x22u8; 50];

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        sse_c_request(
            Method::PUT,
            &format!("/{bucket}/{object}?uploadId={upload_id}&partNumber=1"),
            Some(&key),
            Body::from(part1.clone()),
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "part upload succeeds; the ciphertext block exceeds the minimum even though the plaintext does not"
    );
    let etag1 = etag_from_response(&resp);

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        sse_c_request(
            Method::PUT,
            &format!("/{bucket}/{object}?uploadId={upload_id}&partNumber=2"),
            Some(&key),
            Body::from(part2.clone()),
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let etag2 = etag_from_response(&resp);

    let complete_xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"{etag1}\"</ETag></Part><Part><PartNumber>2</PartNumber><ETag>\"{etag2}\"</ETag></Part></CompleteMultipartUpload>"
    );
    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        sse_c_request(
            Method::POST,
            &format!("/{bucket}/{object}?uploadId={upload_id}"),
            None,
            Body::from(complete_xml),
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "a non-final part whose plaintext is below the minimum must be rejected even if its ciphertext is not"
    );
    let body = String::from_utf8(body_bytes(resp).await).unwrap();
    assert!(
        body.contains("EntityTooSmall"),
        "expected EntityTooSmall error, got: {body}"
    );

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        sse_c_request(
            Method::GET,
            &format!("/{bucket}/{object}"),
            Some(&key),
            Body::empty(),
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "the rejected object must not have been left behind"
    );
}

async fn drive_failed_small_sse_c_mpu(
    app: &axum::routing::RouterIntoService<Body>,
    bucket: &str,
    object: &str,
    key: &[u8; 32],
) {
    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        sse_c_request(
            Method::POST,
            &format!("/{bucket}/{object}?uploads"),
            Some(key),
            Body::empty(),
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let upload_id = extract_upload_id(&String::from_utf8(body_bytes(resp).await).unwrap());

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        sse_c_request(
            Method::PUT,
            &format!("/{bucket}/{object}?uploadId={upload_id}&partNumber=1"),
            Some(key),
            Body::from(vec![0x11u8; 100]),
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let etag1 = etag_from_response(&resp);

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        sse_c_request(
            Method::PUT,
            &format!("/{bucket}/{object}?uploadId={upload_id}&partNumber=2"),
            Some(key),
            Body::from(vec![0x22u8; 50]),
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let etag2 = etag_from_response(&resp);

    let complete_xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"{etag1}\"</ETag></Part><Part><PartNumber>2</PartNumber><ETag>\"{etag2}\"</ETag></Part></CompleteMultipartUpload>"
    );
    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        sse_c_request(
            Method::POST,
            &format!("/{bucket}/{object}?uploadId={upload_id}"),
            None,
            Body::from(complete_xml),
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "completion with an undersized plaintext part must fail before publishing"
    );
    let body = String::from_utf8(body_bytes(resp).await).unwrap();
    assert!(
        body.contains("EntityTooSmall"),
        "expected EntityTooSmall, got: {body}"
    );
}

#[tokio::test]
async fn test_sse_c_multipart_failed_completion_preserves_existing_object() {
    let (app, _tmp) = test_app_sse_c_with_min(140).await;
    let app = app.into_service();

    let key = [0x7fu8; 32];
    let bucket = "ssec-overwrite";
    let object = "important.bin";
    let original = b"ORIGINAL-DATA-MUST-SURVIVE".to_vec();

    tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(Method::PUT, &format!("/{bucket}"), Body::empty()),
    )
    .await
    .unwrap();

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(
            Method::PUT,
            &format!("/{bucket}/{object}"),
            Body::from(original.clone()),
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    drive_failed_small_sse_c_mpu(&app, bucket, object, &key).await;

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(Method::GET, &format!("/{bucket}/{object}"), Body::empty()),
    )
    .await
    .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "a failed SSE-C completion must not delete the pre-existing object"
    );
    assert_eq!(body_bytes(resp).await, original);
}

#[tokio::test]
async fn test_sse_c_multipart_failed_completion_preserves_versioned_object() {
    let (app, _tmp) = test_app_sse_c_with_min(140).await;
    let app = app.into_service();

    let key = [0x80u8; 32];
    let bucket = "ssec-overwrite-ver";
    let object = "important.bin";
    let original = b"VERSIONED-ORIGINAL-MUST-SURVIVE".to_vec();

    tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(Method::PUT, &format!("/{bucket}"), Body::empty()),
    )
    .await
    .unwrap();
    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(
            Method::PUT,
            &format!("/{bucket}?versioning"),
            Body::from(
                "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
            ),
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(
            Method::PUT,
            &format!("/{bucket}/{object}"),
            Body::from(original.clone()),
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    drive_failed_small_sse_c_mpu(&app, bucket, object, &key).await;

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(Method::GET, &format!("/{bucket}/{object}"), Body::empty()),
    )
    .await
    .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "a failed SSE-C completion must not hide the prior version behind a delete marker"
    );
    assert_eq!(body_bytes(resp).await, original);
}

const GOVERNANCE_DELETER_AK: &str = "AKIAGOVDELETERDELETE";
const GOVERNANCE_DELETER_SK: &str = "gov-deleter-secret-gov-deleter-secret-00";
const GOVERNANCE_BYPASSER_AK: &str = "AKIAGOVBYPASSBYPASS0";
const GOVERNANCE_BYPASSER_SK: &str = "gov-bypasser-secret-gov-bypasser-secret0";

fn governance_bypass_app() -> (axum::Router, tempfile::TempDir) {
    test_app_with_iam(serde_json::json!({
        "version": 2,
        "users": [
            {
                "user_id": "u-admin",
                "display_name": "admin",
                "enabled": true,
                "access_keys": [{
                    "access_key": TEST_ACCESS_KEY,
                    "secret_key": TEST_SECRET_KEY,
                    "status": "active"
                }],
                "policies": [{ "bucket": "*", "actions": ["*"], "prefix": "*" }]
            },
            {
                "user_id": "u-deleter",
                "display_name": "deleter",
                "enabled": true,
                "access_keys": [{
                    "access_key": GOVERNANCE_DELETER_AK,
                    "secret_key": GOVERNANCE_DELETER_SK,
                    "status": "active"
                }],
                "policies": [{
                    "bucket": "locked",
                    "actions": ["read", "write", "delete", "list", "object_lock"],
                    "prefix": "*"
                }]
            },
            {
                "user_id": "u-bypasser",
                "display_name": "bypasser",
                "enabled": true,
                "access_keys": [{
                    "access_key": GOVERNANCE_BYPASSER_AK,
                    "secret_key": GOVERNANCE_BYPASSER_SK,
                    "status": "active"
                }],
                "policies": [{
                    "bucket": "locked",
                    "actions": ["read", "write", "delete", "list", "object_lock", "bypass_governance"],
                    "prefix": "*"
                }]
            }
        ]
    }))
}

fn bypass_request(
    method: Method,
    uri: &str,
    access_key: &str,
    secret_key: &str,
    body: Body,
) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("x-access-key", access_key)
        .header("x-secret-key", secret_key)
        .header("x-amz-bypass-governance-retention", "true")
        .body(body)
        .unwrap()
}

async fn seed_locked_object(app: &axum::Router, key: &str, mode: &str) {
    let resp = app
        .clone()
        .oneshot(signed_request(Method::PUT, "/locked", Body::empty()))
        .await
        .unwrap();
    assert!(resp.status().is_success() || resp.status() == StatusCode::CONFLICT);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/locked/{}", key))
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("x-amz-object-lock-mode", mode)
                .header(
                    "x-amz-object-lock-retain-until-date",
                    "2099-01-01T00:00:00Z",
                )
                .body(Body::from("payload"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

async fn locked_object_exists(app: &axum::Router, key: &str) -> bool {
    app.clone()
        .oneshot(signed_request(
            Method::HEAD,
            &format!("/locked/{}", key),
            Body::empty(),
        ))
        .await
        .unwrap()
        .status()
        == StatusCode::OK
}

#[tokio::test]
async fn test_governance_bypass_header_requires_bypass_permission() {
    let (app, _tmp) = governance_bypass_app();
    seed_locked_object(&app, "obj.txt", "GOVERNANCE").await;

    let denied = app
        .clone()
        .oneshot(bypass_request(
            Method::DELETE,
            "/locked/obj.txt",
            GOVERNANCE_DELETER_AK,
            GOVERNANCE_DELETER_SK,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(
        denied.status(),
        StatusCode::FORBIDDEN,
        "a principal without bypass_governance must not strip GOVERNANCE retention"
    );
    assert!(
        locked_object_exists(&app, "obj.txt").await,
        "the governance-locked object must survive an unauthorized bypass attempt"
    );

    let allowed = app
        .clone()
        .oneshot(bypass_request(
            Method::DELETE,
            "/locked/obj.txt",
            GOVERNANCE_BYPASSER_AK,
            GOVERNANCE_BYPASSER_SK,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(
        allowed.status(),
        StatusCode::NO_CONTENT,
        "a principal granted bypass_governance must be able to delete"
    );
    assert!(!locked_object_exists(&app, "obj.txt").await);
}

#[tokio::test]
async fn test_governance_bypass_allowed_for_admin_principal() {
    let (app, _tmp) = governance_bypass_app();
    seed_locked_object(&app, "admin.txt", "GOVERNANCE").await;

    let allowed = app
        .clone()
        .oneshot(bypass_request(
            Method::DELETE,
            "/locked/admin.txt",
            TEST_ACCESS_KEY,
            TEST_SECRET_KEY,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(allowed.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_compliance_retention_ignores_authorized_bypass() {
    let (app, _tmp) = governance_bypass_app();
    seed_locked_object(&app, "compliance.txt", "COMPLIANCE").await;

    for (access_key, secret_key) in [
        (GOVERNANCE_BYPASSER_AK, GOVERNANCE_BYPASSER_SK),
        (TEST_ACCESS_KEY, TEST_SECRET_KEY),
    ] {
        let denied = app
            .clone()
            .oneshot(bypass_request(
                Method::DELETE,
                "/locked/compliance.txt",
                access_key,
                secret_key,
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(
            denied.status(),
            StatusCode::FORBIDDEN,
            "COMPLIANCE retention must hold even for a principal allowed to bypass governance"
        );
    }
    assert!(locked_object_exists(&app, "compliance.txt").await);
}

#[tokio::test]
async fn test_bulk_delete_governance_bypass_requires_permission() {
    let (app, _tmp) = governance_bypass_app();
    seed_locked_object(&app, "bulk.txt", "GOVERNANCE").await;

    let delete_xml = "<Delete><Object><Key>bulk.txt</Key></Object></Delete>";
    let resp = app
        .clone()
        .oneshot(bypass_request(
            Method::POST,
            "/locked?delete",
            GOVERNANCE_DELETER_AK,
            GOVERNANCE_DELETER_SK,
            Body::from(delete_xml),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(body_bytes(resp).await).unwrap();
    assert!(
        body.contains("<Error>") && body.contains("AccessDenied"),
        "bulk delete without bypass_governance must report AccessDenied, got: {}",
        body
    );
    assert!(locked_object_exists(&app, "bulk.txt").await);

    let resp = app
        .clone()
        .oneshot(bypass_request(
            Method::POST,
            "/locked?delete",
            GOVERNANCE_BYPASSER_AK,
            GOVERNANCE_BYPASSER_SK,
            Body::from(delete_xml),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(body_bytes(resp).await).unwrap();
    assert!(
        body.contains("<Deleted>") && !body.contains("<Error>"),
        "bulk delete with bypass_governance must succeed, got: {}",
        body
    );
    assert!(!locked_object_exists(&app, "bulk.txt").await);
}

#[tokio::test]
async fn test_put_object_retention_bypass_requires_permission() {
    let (app, _tmp) = governance_bypass_app();
    seed_locked_object(&app, "retention.txt", "GOVERNANCE").await;

    let shorten_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
        <Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
          <Mode>GOVERNANCE</Mode>
          <RetainUntilDate>2030-01-01T00:00:00Z</RetainUntilDate>
        </Retention>"#;

    let denied = app
        .clone()
        .oneshot(bypass_request(
            Method::PUT,
            "/locked/retention.txt?retention",
            GOVERNANCE_DELETER_AK,
            GOVERNANCE_DELETER_SK,
            Body::from(shorten_xml),
        ))
        .await
        .unwrap();
    assert_eq!(
        denied.status(),
        StatusCode::FORBIDDEN,
        "shortening GOVERNANCE retention requires bypass_governance"
    );

    let allowed = app
        .clone()
        .oneshot(bypass_request(
            Method::PUT,
            "/locked/retention.txt?retention",
            GOVERNANCE_BYPASSER_AK,
            GOVERNANCE_BYPASSER_SK,
            Body::from(shorten_xml),
        ))
        .await
        .unwrap();
    assert_eq!(allowed.status(), StatusCode::OK);
}

const DEFAULT_LOCK_XML: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
    <ObjectLockConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
    <ObjectLockEnabled>Enabled</ObjectLockEnabled>\
    <Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>1</Days></DefaultRetention></Rule>\
    </ObjectLockConfiguration>";

async fn put_object_lock_config(app: &axum::Router, bucket: &str, xml: &str) -> StatusCode {
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            &format!("/{}?object-lock", bucket),
            Body::from(xml.to_string()),
        ))
        .await
        .unwrap()
        .status()
}

async fn object_retention_body(
    app: &axum::Router,
    bucket: &str,
    key: &str,
) -> (StatusCode, String) {
    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            &format!("/{}/{}?retention", bucket, key),
            Body::empty(),
        ))
        .await
        .unwrap();
    let status = resp.status();
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    (status, body)
}

#[tokio::test]
async fn test_put_object_lock_requires_versioning_and_valid_xml() {
    let (app, _tmp) = test_app();
    app.clone()
        .oneshot(signed_request(Method::PUT, "/lock-cfg", Body::empty()))
        .await
        .unwrap();

    assert_eq!(
        put_object_lock_config(&app, "lock-cfg", DEFAULT_LOCK_XML).await,
        StatusCode::CONFLICT,
        "object lock must be rejected while versioning is not Enabled"
    );

    enable_versioning(&app, "lock-cfg").await;

    for xml in [
        "<ObjectLockConfiguration>",
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ObjectLockConfiguration>\
         <ObjectLockEnabled>Enabled</ObjectLockEnabled>\
         <Rule><DefaultRetention><Mode>ARCHIVE</Mode><Days>1</Days></DefaultRetention></Rule>\
         </ObjectLockConfiguration>",
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ObjectLockConfiguration>\
         <ObjectLockEnabled>Enabled</ObjectLockEnabled>\
         <Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>1</Days><Years>1</Years></DefaultRetention></Rule>\
         </ObjectLockConfiguration>",
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ObjectLockConfiguration>\
         <ObjectLockEnabled>Enabled</ObjectLockEnabled>\
         <Rule><DefaultRetention><Mode>GOVERNANCE</Mode></DefaultRetention></Rule>\
         </ObjectLockConfiguration>",
    ] {
        assert_eq!(
            put_object_lock_config(&app, "lock-cfg", xml).await,
            StatusCode::BAD_REQUEST,
            "expected rejection for {}",
            xml
        );
    }

    assert_eq!(
        put_object_lock_config(&app, "lock-cfg", DEFAULT_LOCK_XML).await,
        StatusCode::OK
    );

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/lock-cfg?object-lock",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert_eq!(body, DEFAULT_LOCK_XML);
}

#[tokio::test]
async fn test_bucket_default_retention_applies_to_plain_put() {
    let (app, _tmp) = test_app();
    app.clone()
        .oneshot(signed_request(Method::PUT, "/lock-default", Body::empty()))
        .await
        .unwrap();
    enable_versioning(&app, "lock-default").await;
    assert_eq!(
        put_object_lock_config(&app, "lock-default", DEFAULT_LOCK_XML).await,
        StatusCode::OK
    );

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/lock-default/plain.txt",
            Body::from("payload"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let version_id = resp
        .headers()
        .get("x-amz-version-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let (status, body) = object_retention_body(&app, "lock-default", "plain.txt").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("<Mode>GOVERNANCE</Mode>"),
        "expected the bucket default retention, got {}",
        body
    );
    let retain_until = body
        .split("<RetainUntilDate>")
        .nth(1)
        .unwrap()
        .split("</RetainUntilDate>")
        .next()
        .unwrap()
        .to_string();
    let retain_until = chrono::DateTime::parse_from_rfc3339(&retain_until)
        .unwrap()
        .with_timezone(&chrono::Utc);
    let delta = retain_until - chrono::Utc::now();
    assert!(
        delta > chrono::Duration::hours(23) && delta < chrono::Duration::hours(25),
        "default retention should land about a day out, got {}",
        delta
    );

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::DELETE,
            &format!("/lock-default/plain.txt?versionId={}", version_id),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "the default GOVERNANCE retention must block a version delete without bypass"
    );
}

#[tokio::test]
async fn test_explicit_lock_headers_override_bucket_default() {
    let (app, _tmp) = test_app();
    app.clone()
        .oneshot(signed_request(Method::PUT, "/lock-override", Body::empty()))
        .await
        .unwrap();
    enable_versioning(&app, "lock-override").await;
    assert_eq!(
        put_object_lock_config(&app, "lock-override", DEFAULT_LOCK_XML).await,
        StatusCode::OK
    );

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/lock-override/explicit.txt")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("x-amz-object-lock-mode", "COMPLIANCE")
                .header(
                    "x-amz-object-lock-retain-until-date",
                    "2099-01-01T00:00:00Z",
                )
                .body(Body::from("payload"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let (status, body) = object_retention_body(&app, "lock-override", "explicit.txt").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("<Mode>COMPLIANCE</Mode>") && body.contains("2099-01-01"),
        "explicit lock headers must win over the bucket default, got {}",
        body
    );
}

#[tokio::test]
async fn test_copy_object_lock_headers_override_bucket_default() {
    let (app, _tmp) = test_app();
    for bucket in ["copy-lock-source", "copy-lock-destination"] {
        app.clone()
            .oneshot(signed_request(
                Method::PUT,
                &format!("/{}", bucket),
                Body::empty(),
            ))
            .await
            .unwrap();
    }
    enable_versioning(&app, "copy-lock-destination").await;
    assert_eq!(
        put_object_lock_config(&app, "copy-lock-destination", DEFAULT_LOCK_XML).await,
        StatusCode::OK
    );
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/copy-lock-source/source.txt",
            Body::from("payload"),
        ))
        .await
        .unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/copy-lock-destination/copied.txt")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("x-amz-copy-source", "/copy-lock-source/source.txt")
                .header("x-amz-object-lock-legal-hold", "ON")
                .header("x-amz-object-lock-mode", "COMPLIANCE")
                .header(
                    "x-amz-object-lock-retain-until-date",
                    "2099-01-01T00:00:00Z",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let (status, body) = object_retention_body(&app, "copy-lock-destination", "copied.txt").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("<Mode>COMPLIANCE</Mode>") && body.contains("2099-01-01"),
        "copy request retention must win over the bucket default, got {}",
        body
    );

    let response = app
        .oneshot(signed_request(
            Method::GET,
            "/copy-lock-destination/copied.txt?legal-hold",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_string(response).await;
    assert!(
        body.contains("<Status>ON</Status>"),
        "copy request legal hold must be stored, got {}",
        body
    );
}

#[tokio::test]
async fn test_multipart_complete_inherits_bucket_default_retention() {
    let (app, _tmp) = test_app();
    app.clone()
        .oneshot(signed_request(Method::PUT, "/lock-mpu", Body::empty()))
        .await
        .unwrap();
    enable_versioning(&app, "lock-mpu").await;
    assert_eq!(
        put_object_lock_config(&app, "lock-mpu", DEFAULT_LOCK_XML).await,
        StatusCode::OK
    );

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::POST,
            "/lock-mpu/big.bin?uploads",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    let upload_id = body
        .split("<UploadId>")
        .nth(1)
        .unwrap()
        .split("</UploadId>")
        .next()
        .unwrap()
        .to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!(
                    "/lock-mpu/big.bin?uploadId={}&partNumber=1",
                    upload_id
                ))
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from("part-one-bytes"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let etag = resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .trim_matches('"')
        .to_string();

    let complete_xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part></CompleteMultipartUpload>",
        etag
    );
    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::POST,
            &format!("/lock-mpu/big.bin?uploadId={}", upload_id),
            Body::from(complete_xml),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let (status, body) = object_retention_body(&app, "lock-mpu", "big.bin").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("<Mode>GOVERNANCE</Mode>"),
        "multipart complete must inherit the bucket default retention, got {}",
        body
    );
}

fn retention_xml(mode: &str, date: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <Retention xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Mode>{}</Mode><RetainUntilDate>{}</RetainUntilDate></Retention>",
        mode, date
    )
}

#[tokio::test]
async fn test_put_object_retention_never_shortens_compliance() {
    let (app, _tmp) = test_app();
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/retention-race",
            Body::empty(),
        ))
        .await
        .unwrap();
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/retention-race/obj.txt",
            Body::from("payload"),
        ))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/retention-race/obj.txt?retention",
            Body::from(retention_xml("COMPLIANCE", "2090-01-01T00:00:00Z")),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    for (mode, date) in [
        ("COMPLIANCE", "2080-01-01T00:00:00Z"),
        ("GOVERNANCE", "2095-01-01T00:00:00Z"),
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/retention-race/obj.txt?retention")
                    .header("x-access-key", TEST_ACCESS_KEY)
                    .header("x-secret-key", TEST_SECRET_KEY)
                    .header("x-amz-bypass-governance-retention", "true")
                    .body(Body::from(retention_xml(mode, date)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "COMPLIANCE retention must not be shortened or downgraded to {} {}",
            mode,
            date
        );
    }

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/retention-race/obj.txt?retention",
            Body::from(retention_xml("COMPLIANCE", "2095-01-01T00:00:00Z")),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "extending COMPLIANCE retention must be allowed"
    );

    let (_, body) = object_retention_body(&app, "retention-race", "obj.txt").await;
    assert!(
        body.contains("2095-01-01"),
        "unexpected retention: {}",
        body
    );
}

#[tokio::test]
async fn test_put_object_version_retention_checks_current_metadata() {
    let (app, _tmp) = test_app();
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/retention-vers",
            Body::empty(),
        ))
        .await
        .unwrap();
    enable_versioning(&app, "retention-vers").await;

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/retention-vers/obj.txt",
            Body::from("v1"),
        ))
        .await
        .unwrap();
    let version_id = resp
        .headers()
        .get("x-amz-version-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/retention-vers/obj.txt",
            Body::from("v2"),
        ))
        .await
        .unwrap();

    let uri = format!("/retention-vers/obj.txt?retention&versionId={}", version_id);
    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            &uri,
            Body::from(retention_xml("COMPLIANCE", "2090-01-01T00:00:00Z")),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(&uri)
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("x-amz-bypass-governance-retention", "true")
                .body(Body::from(retention_xml(
                    "GOVERNANCE",
                    "2080-01-01T00:00:00Z",
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "an archived version under COMPLIANCE must not be downgraded"
    );
}

#[tokio::test]
async fn test_put_object_legal_hold_preserves_retention() {
    let (app, _tmp) = test_app();
    app.clone()
        .oneshot(signed_request(Method::PUT, "/lh-preserve", Body::empty()))
        .await
        .unwrap();
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/lh-preserve/obj.txt")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("x-amz-object-lock-mode", "COMPLIANCE")
                .header(
                    "x-amz-object-lock-retain-until-date",
                    "2099-01-01T00:00:00Z",
                )
                .body(Body::from("payload"))
                .unwrap(),
        )
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/lh-preserve/obj.txt?legal-hold",
            Body::from(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                 <LegalHold xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                 <Status>ON</Status></LegalHold>",
            ),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let (status, body) = object_retention_body(&app, "lh-preserve", "obj.txt").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("<Mode>COMPLIANCE</Mode>") && body.contains("2099-01-01"),
        "setting a legal hold must not clobber retention, got {}",
        body
    );
}

#[tokio::test]
async fn test_put_object_retention_extends_governance_without_bypass() {
    let (app, _tmp) = test_app();
    app.clone()
        .oneshot(signed_request(Method::PUT, "/retention-gov", Body::empty()))
        .await
        .unwrap();
    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/retention-gov/obj.txt",
            Body::from("payload"),
        ))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/retention-gov/obj.txt?retention",
            Body::from(retention_xml("GOVERNANCE", "2080-01-01T00:00:00Z")),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/retention-gov/obj.txt?retention",
            Body::from(retention_xml("GOVERNANCE", "2090-01-01T00:00:00Z")),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "extending GOVERNANCE retention must not require bypass"
    );

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/retention-gov/obj.txt?retention",
            Body::from(retention_xml("GOVERNANCE", "2085-01-01T00:00:00Z")),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "shortening GOVERNANCE retention must still require bypass"
    );

    let (_, body) = object_retention_body(&app, "retention-gov", "obj.txt").await;
    assert!(
        body.contains("2090-01-01"),
        "unexpected retention: {}",
        body
    );
}

fn ui_body_request(
    method: Method,
    uri: &str,
    session_id: &str,
    csrf: &str,
    content_type: &str,
    body: Body,
) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(
            "cookie",
            format!(
                "{}={}",
                myfsio_server::session::SESSION_COOKIE_NAME,
                session_id
            ),
        )
        .header(myfsio_server::session::CSRF_HEADER_NAME, csrf)
        .header("content-type", content_type)
        .body(body)
        .unwrap()
}

async fn body_string(resp: axum::response::Response) -> String {
    String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

#[tokio::test]
async fn test_oversized_bucket_policy_body_is_rejected() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/bigbody", Body::empty()))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/bigbody?policy",
            Body::from("x".repeat(2 * 1024 * 1024)),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_string(resp).await;
    assert!(
        body.contains("<Code>MaxMessageLengthExceeded</Code>"),
        "expected MaxMessageLengthExceeded XML, got: {}",
        body
    );
}

#[tokio::test]
async fn test_oversized_delete_objects_body_is_rejected() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/bigdelete", Body::empty()))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::POST,
            "/bigdelete?delete",
            Body::from("x".repeat(9 * 1024 * 1024)),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_string(resp).await;
    assert!(
        body.contains("<Code>MaxMessageLengthExceeded</Code>"),
        "expected MaxMessageLengthExceeded XML, got: {}",
        body
    );
}

#[tokio::test]
async fn test_ui_oversized_json_body_returns_payload_too_large() {
    let (s3_app, state, _tmp) = test_app_and_state();

    s3_app
        .clone()
        .oneshot(signed_request(Method::PUT, "/ui-big-json", Body::empty()))
        .await
        .unwrap();

    let (session_id, csrf) = authenticated_ui_session(&state);
    let payload = format!(r#"{{"object_key":"{}"}}"#, "a".repeat(3 * 1024 * 1024));

    let resp = myfsio_server::create_ui_router(state.clone())
        .oneshot(ui_body_request(
            Method::POST,
            "/ui/buckets/ui-big-json/multipart/initiate",
            &session_id,
            &csrf,
            "application/json",
            Body::from(payload),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let body = body_string(resp).await;
    let parsed: Value = serde_json::from_str(&body).expect("json_error body expected");
    assert!(
        parsed["error"]
            .as_str()
            .unwrap_or_default()
            .contains("exceeds the"),
        "expected a json_error body naming the limit, got: {}",
        body
    );
}

async fn ui_initiate_upload(
    state: &myfsio_server::state::AppState,
    bucket: &str,
    session_id: &str,
    csrf: &str,
    object_key: &str,
) -> String {
    let resp = myfsio_server::create_ui_router(state.clone())
        .oneshot(ui_body_request(
            Method::POST,
            &format!("/ui/buckets/{}/multipart/initiate", bucket),
            session_id,
            csrf,
            "application/json",
            Body::from(format!(r#"{{"object_key":"{}"}}"#, object_key)),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    serde_json::from_str::<Value>(&body).unwrap()["upload_id"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn test_ui_multipart_part_upload_streams_body() {
    let (s3_app, state, _tmp) = test_app_and_state();

    s3_app
        .clone()
        .oneshot(signed_request(Method::PUT, "/ui-stream-mp", Body::empty()))
        .await
        .unwrap();

    let (session_id, csrf) = authenticated_ui_session(&state);
    let upload_id =
        ui_initiate_upload(&state, "ui-stream-mp", &session_id, &csrf, "streamed.bin").await;

    let part_body = vec![7u8; 128 * 1024];
    let chunks: Vec<Result<bytes::Bytes, std::io::Error>> = part_body
        .chunks(8192)
        .map(|chunk| Ok(bytes::Bytes::copy_from_slice(chunk)))
        .collect();

    let resp = myfsio_server::create_ui_router(state.clone())
        .oneshot(ui_body_request(
            Method::PUT,
            &format!(
                "/ui/buckets/ui-stream-mp/multipart/{}/part?partNumber=1",
                upload_id
            ),
            &session_id,
            &csrf,
            "application/octet-stream",
            Body::from_stream(futures::stream::iter(chunks)),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    let etag = serde_json::from_str::<Value>(&body).unwrap()["etag"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = myfsio_server::create_ui_router(state.clone())
        .oneshot(ui_body_request(
            Method::POST,
            &format!("/ui/buckets/ui-stream-mp/multipart/{}/complete", upload_id),
            &session_id,
            &csrf,
            "application/json",
            Body::from(format!(
                r#"{{"parts":[{{"part_number":1,"etag":"{}"}}]}}"#,
                etag
            )),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = s3_app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/ui-stream-mp/streamed.bin",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(bytes.len(), part_body.len());
    assert!(bytes.iter().all(|byte| *byte == 7u8));
}

#[tokio::test]
async fn test_ui_multipart_part_upload_rejects_empty_body() {
    let (s3_app, state, _tmp) = test_app_and_state();

    s3_app
        .clone()
        .oneshot(signed_request(Method::PUT, "/ui-empty-mp", Body::empty()))
        .await
        .unwrap();

    let (session_id, csrf) = authenticated_ui_session(&state);
    let upload_id =
        ui_initiate_upload(&state, "ui-empty-mp", &session_id, &csrf, "empty.bin").await;

    let resp = myfsio_server::create_ui_router(state.clone())
        .oneshot(ui_body_request(
            Method::PUT,
            &format!(
                "/ui/buckets/ui-empty-mp/multipart/{}/part?partNumber=1",
                upload_id
            ),
            &session_id,
            &csrf,
            "application/octet-stream",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_anonymous_ui_request_does_not_persist_a_session() {
    let (_s3_app, state, _tmp) = test_app_and_state();
    assert!(state.sessions.is_empty());

    let resp = myfsio_server::create_ui_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/ui/buckets")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(resp.status().is_redirection());
    assert!(
        state.sessions.is_empty(),
        "an anonymous request must not insert a session into the store"
    );
    assert!(
        resp.headers().get(axum::http::header::SET_COOKIE).is_none(),
        "no session cookie should be issued for an ephemeral session"
    );
}

#[tokio::test]
async fn test_login_page_persists_its_session_and_sets_a_cookie() {
    let (_s3_app, state, _tmp) = test_app_and_state();

    let resp = myfsio_server::create_ui_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers().get(axum::http::header::SET_COOKIE).is_some(),
        "GET /login stores a CSRF token, so its session must be persisted with a cookie"
    );
    assert_eq!(
        state.sessions.len(),
        1,
        "exactly the login session should be stored"
    );
}

async fn burst_until_login_rate_limited(
    state: &myfsio_server::state::AppState,
    accept: Option<&str>,
) -> axum::response::Response {
    let ui_app = myfsio_server::create_ui_router(state.clone());
    for _ in 0..40 {
        let mut builder = Request::builder().method(Method::GET).uri("/login");
        if let Some(value) = accept {
            builder = builder.header("accept", value);
        }
        let resp = ui_app
            .clone()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            return resp;
        }
    }
    panic!("GET /login must start returning 429 within the burst");
}

#[tokio::test]
async fn test_login_is_rate_limited_per_ip() {
    let (_s3_app, state, _tmp) = test_app_and_state();
    let resp = burst_until_login_rate_limited(&state, None).await;

    assert!(
        resp.headers()
            .get(axum::http::header::RETRY_AFTER)
            .is_some(),
        "a rate-limited login response must carry Retry-After"
    );
    let content_type = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        content_type.starts_with("text/html"),
        "a browser request must get the styled HTML page, got: {}",
        content_type
    );

    let body = body_string(resp).await;
    assert!(
        body.contains("Too many login attempts"),
        "expected the rate-limit page copy, got: {}",
        body
    );
}

#[tokio::test]
async fn test_login_rate_limit_answers_json_callers_with_json() {
    let (_s3_app, state, _tmp) = test_app_and_state();
    let resp = burst_until_login_rate_limited(&state, Some("application/json")).await;

    let body = body_string(resp).await;
    let parsed: Value = serde_json::from_str(&body).expect("json body expected");
    assert!(parsed["error"]
        .as_str()
        .unwrap_or_default()
        .contains("Too many login attempts"));
}

fn post_form_auth_fields(key: &str) -> Vec<(String, String)> {
    use base64::engine::general_purpose::STANDARD as B64Std;

    let policy_b64 = B64Std.encode(r#"{"expiration":"2099-01-01T00:00:00Z"}"#.as_bytes());
    let date_stamp = "20260426";
    let region = "us-east-1";
    let service = "s3";
    let credential = format!(
        "{}/{}/{}/{}/aws4_request",
        TEST_ACCESS_KEY, date_stamp, region, service
    );
    let signing_key =
        myfsio_auth::sigv4::derive_signing_key(TEST_SECRET_KEY, date_stamp, region, service);
    let signature = myfsio_auth::sigv4::compute_post_policy_signature(&signing_key, &policy_b64);

    vec![
        ("key".to_string(), key.to_string()),
        ("policy".to_string(), policy_b64),
        ("x-amz-credential".to_string(), credential),
        (
            "x-amz-algorithm".to_string(),
            "AWS4-HMAC-SHA256".to_string(),
        ),
        ("x-amz-date".to_string(), format!("{}T000000Z", date_stamp)),
        ("x-amz-signature".to_string(), signature),
    ]
}

fn multipart_form_body(
    boundary: &str,
    fields: &[(String, String)],
    file_field: Option<(&str, &[u8])>,
) -> Vec<u8> {
    let mut body = Vec::new();
    for (name, value) in fields {
        body.extend_from_slice(
            format!(
                "--{}\r\nContent-Disposition: form-data; name=\"{}\"\r\n\r\n",
                boundary, name
            )
            .as_bytes(),
        );
        body.extend_from_slice(value.as_bytes());
        body.extend_from_slice(b"\r\n");
    }
    if let Some((name, data)) = file_field {
        body.extend_from_slice(
            format!(
                "--{}\r\nContent-Disposition: form-data; name=\"{}\"; filename=\"f\"\r\nContent-Type: application/octet-stream\r\n\r\n",
                boundary, name
            )
            .as_bytes(),
        );
        body.extend_from_slice(data);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());
    body
}

#[tokio::test]
async fn test_post_form_rejects_oversized_non_file_field() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(
            Method::PUT,
            "/form-field-cap",
            Body::empty(),
        ))
        .await
        .unwrap();

    let boundary = "----FieldCapBoundary";
    let mut fields = post_form_auth_fields("capped.bin");
    fields.push(("junk".to_string(), "x".repeat(2 * 1024 * 1024)));
    let body = multipart_form_body(boundary, &fields, Some(("file", b"payload")));

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/form-field-cap")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header(
                    "content-type",
                    format!("multipart/form-data; boundary={}", boundary),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_string(resp).await;
    assert!(
        body.contains("<Code>MaxMessageLengthExceeded</Code>"),
        "expected MaxMessageLengthExceeded XML, got: {}",
        body
    );
}

#[tokio::test]
async fn test_post_form_accepts_a_large_file_field_with_any_ascii_casing() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/form-file-ok", Body::empty()))
        .await
        .unwrap();

    let payload = vec![3u8; 3 * 1024 * 1024];
    for (field_name, key, boundary) in [
        ("file", "lowercase.bin", "----LowercaseFileBoundary"),
        ("File", "uppercase.bin", "----UppercaseFileBoundary"),
    ] {
        let fields = post_form_auth_fields(key);
        let body = multipart_form_body(boundary, &fields, Some((field_name, &payload)));

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/form-file-ok")
                    .header("x-access-key", TEST_ACCESS_KEY)
                    .header("x-secret-key", TEST_SECRET_KEY)
                    .header(
                        "content-type",
                        format!("multipart/form-data; boundary={}", boundary),
                    )
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(
            resp.status().is_success(),
            "a {} field over the text cap must upload, got {}",
            field_name,
            resp.status()
        );

        let resp = app
            .clone()
            .oneshot(signed_request(
                Method::GET,
                &format!("/form-file-ok/{}", key),
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(bytes.len(), payload.len());
    }
}

#[tokio::test]
async fn test_ui_upload_translates_s3_error_to_json() {
    let (s3_app, state, _tmp) = test_app_and_state();

    s3_app
        .clone()
        .oneshot(signed_request(Method::PUT, "/ui-quota", Body::empty()))
        .await
        .unwrap();

    let resp = s3_app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/ui-quota?quota")
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"max_size_bytes": 8}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let (session_id, csrf) = authenticated_ui_session(&state);
    let boundary = "----UiQuotaBoundary";
    let fields = vec![("object_key".to_string(), "too-big.bin".to_string())];
    let body = multipart_form_body(boundary, &fields, Some(("object", &[9u8; 4096])));

    let resp = myfsio_server::create_ui_router(state.clone())
        .oneshot(ui_body_request(
            Method::POST,
            "/ui/buckets/ui-quota/upload",
            &session_id,
            &csrf,
            &format!("multipart/form-data; boundary={}", boundary),
            Body::from(body),
        ))
        .await
        .unwrap();

    assert!(
        !resp.status().is_success(),
        "the quota must reject this upload"
    );
    let content_type = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        content_type.starts_with("application/json"),
        "an AJAX upload failure must not answer with S3 XML, got: {}",
        content_type
    );

    let body = body_string(resp).await;
    let parsed: Value = serde_json::from_str(&body).expect("json_error body expected");
    let message = parsed["error"].as_str().unwrap_or_default();
    assert!(
        message.contains("QuotaExceeded"),
        "the S3 error code and message must reach the UI caller, got: {}",
        body
    );
}

const COND_ACCESS_KEY: &str = "AKCONDUSER0000000000";
const COND_SECRET_KEY: &str = "cond-user-secret";

fn policy_test_iam() -> serde_json::Value {
    serde_json::json!({
        "version": 2,
        "users": [
            {
                "user_id": "u-admin",
                "display_name": "admin",
                "enabled": true,
                "access_keys": [{
                    "access_key": TEST_ACCESS_KEY,
                    "secret_key": TEST_SECRET_KEY,
                    "status": "active"
                }],
                "policies": [{"bucket": "*", "actions": ["*"], "prefix": "*"}]
            },
            {
                "user_id": "u-cond",
                "display_name": "cond",
                "enabled": true,
                "access_keys": [{
                    "access_key": COND_ACCESS_KEY,
                    "secret_key": COND_SECRET_KEY,
                    "status": "active"
                }],
                "policies": [
                    {"bucket": "cond-bucket", "actions": ["list", "read", "write", "delete"]},
                    {"bucket": "cond-bucket", "actions": ["delete"], "effect": "Deny", "prefix": "keep/"},
                    {"bucket": "glob-*", "actions": ["list", "read", "write"]},
                    {
                        "bucket": "ip-bucket",
                        "actions": ["read"],
                        "condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}
                    }
                ]
            }
        ]
    })
}

fn cond_request(method: Method, uri: &str, body: Body) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("x-access-key", COND_ACCESS_KEY)
        .header("x-secret-key", COND_SECRET_KEY)
        .body(body)
        .unwrap()
}

fn anon_request(method: Method, uri: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

fn anon_request_from(method: Method, uri: &str, forwarded_for: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("x-forwarded-for", forwarded_for)
        .body(Body::empty())
        .unwrap()
}

async fn put_policy_doc(
    app: &axum::Router,
    bucket: &str,
    policy: &str,
) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/{}?policy", bucket))
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .header("content-type", "application/json")
                .body(Body::from(policy.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn seed_object(app: &axum::Router, bucket: &str, key: &str) {
    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            &format!("/{}/{}", bucket, key),
            Body::from("payload"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "seed {}/{}", bucket, key);
}

#[tokio::test]
async fn test_bucket_policy_source_ip_condition_gates_anonymous_reads() {
    let (app, _tmp) = test_app_with_iam_and(policy_test_iam(), |cfg| cfg.num_trusted_proxies = 1);
    app.clone()
        .oneshot(signed_request(Method::PUT, "/ip-bucket", Body::empty()))
        .await
        .unwrap();
    seed_object(&app, "ip-bucket", "public/a.txt").await;
    seed_object(&app, "ip-bucket", "private/b.txt").await;

    let policy = r#"{
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::ip-bucket/public/*",
        "Condition": {"IpAddress": {"aws:SourceIp": ["10.0.0.0/8", "192.168.1.0/24"]}}
      }]
    }"#;
    assert_eq!(
        put_policy_doc(&app, "ip-bucket", policy).await.status(),
        StatusCode::NO_CONTENT
    );

    let inside = app
        .clone()
        .oneshot(anon_request_from(
            Method::GET,
            "/ip-bucket/public/a.txt",
            "10.20.30.40, 127.0.0.1",
        ))
        .await
        .unwrap();
    assert_eq!(inside.status(), StatusCode::OK);

    let outside = app
        .clone()
        .oneshot(anon_request_from(
            Method::GET,
            "/ip-bucket/public/a.txt",
            "203.0.113.7, 127.0.0.1",
        ))
        .await
        .unwrap();
    assert_eq!(outside.status(), StatusCode::FORBIDDEN);

    let no_ip = app
        .clone()
        .oneshot(anon_request(Method::GET, "/ip-bucket/public/a.txt"))
        .await
        .unwrap();
    assert_eq!(no_ip.status(), StatusCode::FORBIDDEN);

    let private = app
        .clone()
        .oneshot(anon_request_from(
            Method::GET,
            "/ip-bucket/private/b.txt",
            "10.20.30.40, 127.0.0.1",
        ))
        .await
        .unwrap();
    assert_eq!(private.status(), StatusCode::FORBIDDEN);

    let iam_inside = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/ip-bucket/private/b.txt")
                .header("x-access-key", COND_ACCESS_KEY)
                .header("x-secret-key", COND_SECRET_KEY)
                .header("x-forwarded-for", "10.1.1.1, 127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(iam_inside.status(), StatusCode::OK);

    let iam_outside = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/ip-bucket/private/b.txt")
                .header("x-access-key", COND_ACCESS_KEY)
                .header("x-secret-key", COND_SECRET_KEY)
                .header("x-forwarded-for", "198.51.100.9, 127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(iam_outside.status(), StatusCode::FORBIDDEN);

    let status = app
        .clone()
        .oneshot(signed_request(
            Method::GET,
            "/ip-bucket?policyStatus",
            Body::empty(),
        ))
        .await
        .unwrap();
    let body = String::from_utf8(
        status
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("<IsPublic>FALSE</IsPublic>"), "{}", body);
}

#[tokio::test]
async fn test_bucket_policy_prefix_condition_and_secure_transport() {
    let (app, _tmp) = test_app_with_iam(policy_test_iam());
    app.clone()
        .oneshot(signed_request(Method::PUT, "/prefix-bucket", Body::empty()))
        .await
        .unwrap();
    seed_object(&app, "prefix-bucket", "public/a.txt").await;

    let policy = r#"{
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "ListPublicOnly",
          "Effect": "Allow",
          "Principal": {"AWS": "*"},
          "Action": "s3:ListBucket",
          "Resource": "arn:aws:s3:::prefix-bucket",
          "Condition": {"StringLike": {"s3:prefix": "public/*"}}
        },
        {
          "Sid": "ReadRequiresTls",
          "Effect": "Allow",
          "Principal": "*",
          "Action": "s3:GetObject",
          "Resource": "arn:aws:s3:::prefix-bucket/public/*",
          "Condition": {"Bool": {"aws:SecureTransport": "true"}}
        }
      ]
    }"#;
    assert_eq!(
        put_policy_doc(&app, "prefix-bucket", policy).await.status(),
        StatusCode::NO_CONTENT
    );

    let ok = app
        .clone()
        .oneshot(anon_request(
            Method::GET,
            "/prefix-bucket?list-type=2&prefix=public/",
        ))
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK);

    let wrong_prefix = app
        .clone()
        .oneshot(anon_request(
            Method::GET,
            "/prefix-bucket?list-type=2&prefix=private/",
        ))
        .await
        .unwrap();
    assert_eq!(wrong_prefix.status(), StatusCode::FORBIDDEN);

    let no_prefix = app
        .clone()
        .oneshot(anon_request(Method::GET, "/prefix-bucket?list-type=2"))
        .await
        .unwrap();
    assert_eq!(no_prefix.status(), StatusCode::FORBIDDEN);

    let plain = app
        .clone()
        .oneshot(anon_request(Method::GET, "/prefix-bucket/public/a.txt"))
        .await
        .unwrap();
    assert_eq!(plain.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_bucket_policy_not_action_with_principal_arn() {
    let (app, _tmp) = test_app_with_iam(policy_test_iam());
    app.clone()
        .oneshot(signed_request(Method::PUT, "/cond-bucket", Body::empty()))
        .await
        .unwrap();
    seed_object(&app, "cond-bucket", "a.txt").await;

    let policy = r#"{
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Deny",
        "Principal": {"AWS": "arn:aws:iam::123456789012:user/u-cond"},
        "NotAction": ["s3:GetObject", "s3:ListBucket"],
        "Resource": ["arn:aws:s3:::cond-bucket", "arn:aws:s3:::cond-bucket/*"]
      }]
    }"#;
    assert_eq!(
        put_policy_doc(&app, "cond-bucket", policy).await.status(),
        StatusCode::NO_CONTENT
    );

    let get = app
        .clone()
        .oneshot(cond_request(
            Method::GET,
            "/cond-bucket/a.txt",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::OK);

    let list = app
        .clone()
        .oneshot(cond_request(
            Method::GET,
            "/cond-bucket?list-type=2",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::OK);

    let put = app
        .clone()
        .oneshot(cond_request(
            Method::PUT,
            "/cond-bucket/new.txt",
            Body::from("x"),
        ))
        .await
        .unwrap();
    assert_eq!(put.status(), StatusCode::FORBIDDEN);

    let admin_put = app
        .clone()
        .oneshot(signed_request(
            Method::PUT,
            "/cond-bucket/new.txt",
            Body::from("x"),
        ))
        .await
        .unwrap();
    assert_eq!(admin_put.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_iam_deny_statements_and_bucket_globs() {
    let (app, _tmp) = test_app_with_iam(policy_test_iam());
    for bucket in ["cond-bucket", "glob-2026", "other"] {
        app.clone()
            .oneshot(signed_request(
                Method::PUT,
                &format!("/{}", bucket),
                Body::empty(),
            ))
            .await
            .unwrap();
    }
    seed_object(&app, "cond-bucket", "keep/x.txt").await;
    seed_object(&app, "cond-bucket", "tmp/y.txt").await;

    let kept = app
        .clone()
        .oneshot(cond_request(
            Method::DELETE,
            "/cond-bucket/keep/x.txt",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(kept.status(), StatusCode::FORBIDDEN);

    let tmp_delete = app
        .clone()
        .oneshot(cond_request(
            Method::DELETE,
            "/cond-bucket/tmp/y.txt",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(tmp_delete.status(), StatusCode::NO_CONTENT);

    let glob_put = app
        .clone()
        .oneshot(cond_request(
            Method::PUT,
            "/glob-2026/a.txt",
            Body::from("x"),
        ))
        .await
        .unwrap();
    assert_eq!(glob_put.status(), StatusCode::OK);

    let other_put = app
        .clone()
        .oneshot(cond_request(Method::PUT, "/other/a.txt", Body::from("x")))
        .await
        .unwrap();
    assert_eq!(other_put.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_put_bucket_policy_validation() {
    let (app, _tmp) = test_app();
    app.clone()
        .oneshot(signed_request(Method::PUT, "/val-bucket", Body::empty()))
        .await
        .unwrap();

    async fn rejected(app: &axum::Router, policy: &str, needle: &str) {
        let resp = put_policy_doc(app, "val-bucket", policy).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{}", policy);
        let body = String::from_utf8(
            resp.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(body.contains("<Code>MalformedPolicy</Code>"), "{}", body);
        assert!(body.contains(needle), "expected {:?} in {}", needle, body);
    }

    rejected(
        &app,
        r#"{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::val-bucket/*","Condition":{"StringEqualz":{"s3:prefix":"x"}}}]}"#,
        "Unsupported condition operator",
    )
    .await;
    rejected(
        &app,
        r#"{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::other-bucket/*"}]}"#,
        "does not belong to bucket",
    )
    .await;
    rejected(
        &app,
        r#"{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","NotAction":"s3:PutObject","Resource":"arn:aws:s3:::val-bucket/*"}]}"#,
        "both Action and NotAction",
    )
    .await;
    rejected(
        &app,
        r#"{"Statement":[{"Effect":"Permit","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::val-bucket/*"}]}"#,
        "Effect must be Allow or Deny",
    )
    .await;
    rejected(
        &app,
        r#"{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::val-bucket/*"}]}"#,
        "missing Principal",
    )
    .await;
    rejected(
        &app,
        r#"{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::val-bucket/*","Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/33"}}}]}"#,
        "invalid IP address",
    )
    .await;

    let padding = "x".repeat(21 * 1024);
    let oversized = format!(
        r#"{{"Statement":[{{"Sid":"{}","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::val-bucket/*"}}]}}"#,
        padding
    );
    rejected(&app, &oversized, "maximum size").await;

    let accepted = r#"{
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Deny",
          "NotPrincipal": {"AWS": ["arn:aws:iam::myfsio:user/u-test1234"]},
          "Action": "s3:*",
          "NotResource": "arn:aws:s3:::val-bucket/public/*",
          "Condition": {
            "Bool": {"aws:SecureTransport": false},
            "ForAnyValue:StringEqualsIfExists": {"aws:TagKeys": ["env"]},
            "DateLessThan": {"aws:CurrentTime": "2030-01-01T00:00:00Z"},
            "NumericLessThanEquals": {"s3:max-keys": 100},
            "Null": {"s3:x-amz-server-side-encryption": "true"},
            "StringLike": {"s3:prefix": "home/${aws:username}/*"}
          }
        }
      ]
    }"#;
    assert_eq!(
        put_policy_doc(&app, "val-bucket", accepted).await.status(),
        StatusCode::NO_CONTENT
    );
}

const IAM_DELEGATE_AK: &str = "AKIAMDELEGATE0000000";
const IAM_DELEGATE_SK: &str = "iam-delegate-secret-iam-delegate-secret";
const IAM_ADMIN_SPARE_AK: &str = "AKIAMADMINSPARE00000";
const IAM_ADMIN_SPARE_SK: &str = "iam-admin-spare-secret-iam-admin-spare";

fn iam_delegation_app(delegated_actions: &[&str]) -> (axum::Router, tempfile::TempDir) {
    test_app_with_iam(serde_json::json!({
        "version": 2,
        "users": [
            {
                "user_id": "u-test1234",
                "display_name": "admin",
                "enabled": true,
                "access_keys": [
                    {
                        "access_key": TEST_ACCESS_KEY,
                        "secret_key": TEST_SECRET_KEY,
                        "status": "active"
                    },
                    {
                        "access_key": IAM_ADMIN_SPARE_AK,
                        "secret_key": IAM_ADMIN_SPARE_SK,
                        "status": "active"
                    }
                ],
                "policies": [{"bucket": "*", "actions": ["*"], "prefix": "*"}]
            },
            {
                "user_id": "u-delegate",
                "display_name": "delegate",
                "enabled": true,
                "access_keys": [{
                    "access_key": IAM_DELEGATE_AK,
                    "secret_key": IAM_DELEGATE_SK,
                    "status": "active"
                }],
                "policies": [{"bucket": "*", "actions": delegated_actions, "prefix": "*"}]
            }
        ]
    }))
}

fn delegate_request(method: Method, uri: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("x-access-key", IAM_DELEGATE_AK)
        .header("x-secret-key", IAM_DELEGATE_SK)
        .body(Body::empty())
        .unwrap()
}

fn iam_user_record(tmp: &tempfile::TempDir, user_id: &str) -> Value {
    let raw = std::fs::read_to_string(
        tmp.path()
            .join(".myfsio.sys")
            .join("config")
            .join("iam.json"),
    )
    .unwrap();
    let config: Value = serde_json::from_str(&raw).unwrap();
    config["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|user| user["user_id"] == user_id)
        .cloned()
        .unwrap()
}

fn iam_access_keys(tmp: &tempfile::TempDir, user_id: &str) -> Vec<String> {
    iam_user_record(tmp, user_id)["access_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| key["access_key"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn iam_create_key_delegate_cannot_mint_admin_credentials() {
    let (app, tmp) = iam_delegation_app(&["iam:create_key"]);

    let admin_targets = [
        "/myfsio/admin/iam/users/u-test1234/access-keys".to_string(),
        "/myfsio/admin/iam/users/u-test1234/keys".to_string(),
        format!("/myfsio/admin/iam/users/{}/access-keys", TEST_ACCESS_KEY),
    ];
    for uri in admin_targets {
        let resp = app
            .clone()
            .oneshot(delegate_request(Method::POST, &uri))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{}", uri);
        let body = response_json(resp).await;
        assert_eq!(body["error"]["code"], "AccessDenied", "{}", uri);
        assert!(body.get("secret_key").is_none(), "{}", uri);
    }

    assert_eq!(
        iam_access_keys(&tmp, "u-test1234"),
        vec![TEST_ACCESS_KEY.to_string(), IAM_ADMIN_SPARE_AK.to_string()]
    );
}

#[tokio::test]
async fn iam_create_key_delegate_can_still_create_own_key() {
    let (app, tmp) = iam_delegation_app(&["iam:create_key"]);

    let resp = app
        .oneshot(delegate_request(
            Method::POST,
            "/myfsio/admin/iam/users/u-delegate/access-keys",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = response_json(resp).await;
    let minted = body["access_key"].as_str().unwrap().to_string();
    assert!(!body["secret_key"].as_str().unwrap().is_empty());

    let keys = iam_access_keys(&tmp, "u-delegate");
    assert_eq!(keys.len(), 2);
    assert!(keys.contains(&minted));
}

#[tokio::test]
async fn iam_create_key_admin_can_target_any_user() {
    let (app, tmp) = iam_delegation_app(&["iam:create_key"]);

    let resp = app
        .clone()
        .oneshot(signed_request(
            Method::POST,
            "/myfsio/admin/iam/users/u-delegate/access-keys",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert_eq!(iam_access_keys(&tmp, "u-delegate").len(), 2);

    let resp = app
        .oneshot(signed_request(
            Method::POST,
            "/myfsio/admin/iam/users/u-test1234/access-keys",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert_eq!(iam_access_keys(&tmp, "u-test1234").len(), 3);
}

#[tokio::test]
async fn iam_delete_key_delegate_cannot_rotate_admin_keys() {
    let (app, tmp) = iam_delegation_app(&["iam:delete_key"]);

    let resp = app
        .oneshot(delegate_request(
            Method::DELETE,
            &format!(
                "/myfsio/admin/iam/users/u-test1234/access-keys/{}",
                TEST_ACCESS_KEY
            ),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = response_json(resp).await;
    assert_eq!(body["error"]["code"], "AccessDenied");

    assert!(iam_access_keys(&tmp, "u-test1234").contains(&TEST_ACCESS_KEY.to_string()));
}

#[tokio::test]
async fn iam_disable_user_delegate_cannot_lock_out_admin() {
    let (app, tmp) = iam_delegation_app(&["iam:disable_user"]);

    let resp = app
        .oneshot(delegate_request(
            Method::POST,
            "/myfsio/admin/iam/users/u-test1234/disable",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = response_json(resp).await;
    assert_eq!(body["error"]["code"], "AccessDenied");

    assert_eq!(iam_user_record(&tmp, "u-test1234")["enabled"], true);
}

#[tokio::test]
async fn iam_enable_user_delegate_cannot_unlock_admin() {
    let (app, tmp) = iam_delegation_app(&["iam:disable_user"]);

    let resp = app
        .oneshot(delegate_request(
            Method::POST,
            "/myfsio/admin/iam/users/u-test1234/enable",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = response_json(resp).await;
    assert_eq!(body["error"]["code"], "AccessDenied");

    assert_eq!(iam_user_record(&tmp, "u-test1234")["enabled"], true);
}

#[tokio::test]
async fn iam_list_users_delegate_sees_only_own_record() {
    let (app, _tmp) = iam_delegation_app(&["iam:list_users"]);

    let resp = app
        .clone()
        .oneshot(delegate_request(Method::GET, "/myfsio/admin/iam/users"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_json(resp).await;
    let users = body["users"].as_array().unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0]["user_id"], "u-delegate");

    let resp = app
        .oneshot(signed_request(
            Method::GET,
            "/myfsio/admin/iam/users",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_json(resp).await;
    assert_eq!(body["users"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn iam_get_user_delegate_cannot_read_other_records() {
    let (app, _tmp) = iam_delegation_app(&["iam:get_user"]);

    let resp = app
        .clone()
        .oneshot(delegate_request(
            Method::GET,
            "/myfsio/admin/iam/users/u-test1234",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = response_json(resp).await;
    assert_eq!(body["error"]["code"], "AccessDenied");
    assert!(body.get("access_keys").is_none());

    let resp = app
        .oneshot(delegate_request(
            Method::GET,
            "/myfsio/admin/iam/users/u-delegate",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_json(resp).await;
    assert_eq!(body["user_id"], "u-delegate");
}

#[tokio::test]
async fn iam_get_policies_delegate_cannot_read_other_policies() {
    let (app, _tmp) = iam_delegation_app(&["iam:get_policy"]);

    let resp = app
        .clone()
        .oneshot(delegate_request(
            Method::GET,
            "/myfsio/admin/iam/users/u-test1234/policies",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = response_json(resp).await;
    assert_eq!(body["error"]["code"], "AccessDenied");
    assert!(body.get("policies").is_none());

    let resp = app
        .oneshot(delegate_request(
            Method::GET,
            "/myfsio/admin/iam/users/u-delegate/policies",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_json(resp).await;
    assert!(body["policies"].as_array().unwrap().len() == 1);
}
