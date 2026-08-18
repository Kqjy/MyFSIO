use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use futures::StreamExt;
use http_body_util::BodyExt;
use myfsio_server::config::{ReadVerifyMode, ServerConfig};
use myfsio_server::state::AppState;
use myfsio_storage::error::StorageError;
use myfsio_storage::traits::StorageEngine;
use tokio::io::AsyncReadExt;
use tower::ServiceExt;

const ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
const SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

fn test_state(mode: ReadVerifyMode) -> (AppState, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let iam_dir = tmp.path().join(".myfsio.sys").join("config");
    std::fs::create_dir_all(&iam_dir).unwrap();
    let iam_path = iam_dir.join("iam.json");
    std::fs::write(
        &iam_path,
        serde_json::json!({
            "version": 2,
            "users": [{
                "user_id": "u-read-verify",
                "display_name": "admin",
                "enabled": true,
                "access_keys": [{
                    "access_key": ACCESS_KEY,
                    "secret_key": SECRET_KEY,
                    "status": "active"
                }],
                "policies": [{"bucket": "*", "actions": ["*"], "prefix": "*"}]
            }]
        })
        .to_string(),
    )
    .unwrap();
    let config = ServerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        ui_bind_addr: "127.0.0.1:0".parse().unwrap(),
        storage_root: tmp.path().to_path_buf(),
        iam_config_path: iam_path,
        allow_legacy_header_auth: true,
        replication_healer_enabled: false,
        read_verify_mode: mode,
        ui_enabled: false,
        ..ServerConfig::default()
    };
    (AppState::new(config), tmp)
}

fn request(method: Method, uri: &str, body: Body) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("x-access-key", ACCESS_KEY)
        .header("x-secret-key", SECRET_KEY)
        .body(body)
        .unwrap()
}

fn range_request(uri: &str, range: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("x-access-key", ACCESS_KEY)
        .header("x-secret-key", SECRET_KEY)
        .header("range", range)
        .body(Body::empty())
        .unwrap()
}

async fn seed_object(app: &axum::Router, bytes: &[u8]) {
    let response = app
        .clone()
        .oneshot(request(Method::PUT, "/verify-bucket", Body::empty()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = app
        .clone()
        .oneshot(request(
            Method::PUT,
            "/verify-bucket/object.bin",
            Body::from(bytes.to_vec()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

async fn drain_body(response: axum::response::Response) -> (HeaderMap, Vec<u8>, Option<String>) {
    let (parts, body) = response.into_parts();
    let mut stream = body.into_data_stream();
    let mut received = Vec::new();
    let mut failure = None;
    while let Some(next) = stream.next().await {
        match next {
            Ok(chunk) => received.extend_from_slice(&chunk),
            Err(error) => {
                failure = Some(error.to_string());
                break;
            }
        }
    }
    (parts.headers, received, failure)
}

async fn wait_until_corrupted(state: &AppState) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match state
                .storage
                .get_object("verify-bucket", "object.bin")
                .await
            {
                Err(StorageError::ObjectCorrupted { .. }) => break,
                Ok(_) => tokio::task::yield_now().await,
                Err(error) => {
                    panic!("unexpected read result while waiting for quarantine: {error}")
                }
            }
        }
    })
    .await
    .expect("verify-on-read quarantine did not complete");
}

#[tokio::test]
async fn mismatch_aborts_body_and_quarantines_object() {
    let (state, tmp) = test_state(ReadVerifyMode::Abort);
    let app = myfsio_server::create_router(state.clone());
    let pristine = b"pristine object content";
    let rotten = b"rotted!! object content";
    assert_eq!(pristine.len(), rotten.len());
    seed_object(&app, pristine).await;
    std::fs::write(tmp.path().join("verify-bucket").join("object.bin"), rotten).unwrap();

    let response = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/verify-bucket/object.bin",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-length"],
        pristine.len().to_string()
    );
    let (_, received, failure) = drain_body(response).await;
    assert!(failure.is_some());
    assert!(received.len() < pristine.len());

    wait_until_corrupted(&state).await;
    let metadata = state
        .storage
        .get_object_metadata("verify-bucket", "object.bin")
        .await
        .unwrap();
    let quarantine_path = metadata.get("__quarantine_path__").unwrap();
    assert_eq!(
        std::fs::read(tmp.path().join(quarantine_path)).unwrap(),
        rotten
    );

    let response = app
        .oneshot(request(
            Method::GET,
            "/verify-bucket/object.bin",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(String::from_utf8_lossy(&body).contains("ObjectCorrupted"));
}

#[tokio::test]
async fn clean_verified_get_matches_feature_off() {
    let (state, _tmp) = test_state(ReadVerifyMode::Abort);
    let abort_app = myfsio_server::create_router(state.clone());
    let content = b"clean content for read verification";
    seed_object(&abort_app, content).await;
    let mut off_state = state;
    off_state.config.read_verify_mode = ReadVerifyMode::Off;
    let off_app = myfsio_server::create_router(off_state);

    let off_response = off_app
        .oneshot(request(
            Method::GET,
            "/verify-bucket/object.bin",
            Body::empty(),
        ))
        .await
        .unwrap();
    let off_status = off_response.status();
    let (off_headers, off_body, off_failure) = drain_body(off_response).await;
    assert!(off_failure.is_none());

    let abort_response = abort_app
        .oneshot(request(
            Method::GET,
            "/verify-bucket/object.bin",
            Body::empty(),
        ))
        .await
        .unwrap();
    let abort_status = abort_response.status();
    let (abort_headers, abort_body, abort_failure) = drain_body(abort_response).await;

    assert_eq!(abort_status, off_status);
    assert_eq!(abort_headers, off_headers);
    assert_eq!(abort_body, off_body);
    assert_eq!(abort_body, content);
    assert!(abort_failure.is_none());
}

#[tokio::test]
async fn corrupt_range_get_remains_unverified() {
    let (state, tmp) = test_state(ReadVerifyMode::Abort);
    let app = myfsio_server::create_router(state.clone());
    let pristine = b"pristine object content";
    let rotten = b"rotted!! object content";
    seed_object(&app, pristine).await;
    std::fs::write(tmp.path().join("verify-bucket").join("object.bin"), rotten).unwrap();

    let response = app
        .oneshot(range_request("/verify-bucket/object.bin", "bytes=2-8"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], &rotten[2..=8]);

    let (_, mut stream) = state
        .storage
        .get_object("verify-bucket", "object.bin")
        .await
        .unwrap();
    let mut stored = Vec::new();
    stream.read_to_end(&mut stored).await.unwrap();
    assert_eq!(stored, rotten);
}

#[tokio::test]
async fn default_off_serves_corrupt_object_to_completion() {
    let (state, tmp) = test_state(ReadVerifyMode::Off);
    assert_eq!(state.config.read_verify_mode, ReadVerifyMode::Off);
    let app = myfsio_server::create_router(state.clone());
    let pristine = b"pristine object content";
    let rotten = b"rotted!! object content";
    seed_object(&app, pristine).await;
    std::fs::write(tmp.path().join("verify-bucket").join("object.bin"), rotten).unwrap();

    let response = app
        .oneshot(request(
            Method::GET,
            "/verify-bucket/object.bin",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let (_, body, failure) = drain_body(response).await;
    assert!(failure.is_none());
    assert_eq!(body, rotten);

    let (_, mut stream) = state
        .storage
        .get_object("verify-bucket", "object.bin")
        .await
        .unwrap();
    let mut stored = Vec::new();
    stream.read_to_end(&mut stored).await.unwrap();
    assert_eq!(stored, rotten);
}
