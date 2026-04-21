use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use myfsio_storage::traits::{AsyncReadStream, StorageEngine};
use serde_json::Value;
use std::collections::HashMap;
use tower::ServiceExt;

const TEST_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
const TEST_SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

fn test_app_with_iam(iam_json: serde_json::Value) -> (axum::Router, tempfile::TempDir) {
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
    };
    let state = myfsio_server::state::AppState::new(config);
    let app = myfsio_server::create_router(state);
    (app, tmp)
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

fn signed_request(method: Method, uri: &str, body: Body) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("x-access-key", TEST_ACCESS_KEY)
        .header("x-secret-key", TEST_SECRET_KEY)
        .body(body)
        .unwrap()
}

fn test_website_state() -> (myfsio_server::state::AppState, tempfile::TempDir) {
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
        website_hosting_enabled: true,
        replication_connect_timeout_secs: 5,
        replication_read_timeout_secs: 30,
        replication_max_retries: 2,
        replication_streaming_threshold_bytes: 10_485_760,
        replication_max_failures_per_bucket: 50,
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
    };
    (myfsio_server::state::AppState::new(config), tmp)
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
        "<!doctype html><h1>Home</h1>",
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
        });

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
    assert_eq!(policies_body["policies"][0]["bucket"], "reports");

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
                "timestamp": "2026-04-20T00:00:00Z",
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
        .oneshot(Request::builder().uri("/ui/").body(Body::empty()).unwrap())
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
    assert!(body.contains("<Resource>/ui/</Resource>"));
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
async fn test_bucket_replication_roundtrip() {
    let (app, _tmp) = test_app();

    app.clone()
        .oneshot(signed_request(Method::PUT, "/repl-bucket", Body::empty()))
        .await
        .unwrap();

    let repl_xml = "<ReplicationConfiguration><Role>arn:aws:iam::123456789012:role/s3-repl</Role><Rule><ID>rule-1</ID></Rule></ReplicationConfiguration>";

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
    assert_eq!(resp.status(), StatusCode::OK);

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
    assert!(body.contains("ReplicationConfiguration"));

    let resp = app
        .oneshot(signed_request(
            Method::DELETE,
            "/repl-bucket?replication",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
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
    assert!(body.contains("<h1>404 Not Found</h1>"));
    assert!(body.len() > 512);

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
    };
    let state = myfsio_server::state::AppState::new_with_encryption(config).await;
    let app = myfsio_server::create_router(state);
    (app, tmp)
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
        .uri("/kms/keys")
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
        signed_request(Method::GET, "/kms/keys", Body::empty()),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["keys"].as_array().unwrap().len(), 1);

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(Method::GET, &format!("/kms/keys/{}", key_id), Body::empty()),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(
            Method::DELETE,
            &format!("/kms/keys/{}", key_id),
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
        .uri("/kms/keys")
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
        .uri("/kms/encrypt")
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
        .uri("/kms/decrypt")
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
