use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use tower::ServiceExt;

const TEST_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
const TEST_SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

fn app() -> (axum::Router, tempfile::TempDir) {
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
        ui_enabled: false,
        allow_legacy_header_auth: true,
        multipart_min_part_size: 1,
        ..myfsio_server::config::ServerConfig::default()
    };
    let state = myfsio_server::state::AppState::new(config);
    (myfsio_server::create_router(state), tmp)
}

fn req(method: Method, uri: &str, body: Body) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("x-access-key", TEST_ACCESS_KEY)
        .header("x-secret-key", TEST_SECRET_KEY)
        .body(body)
        .unwrap()
}

// Mirrors hoodik's wire shape: a client prefix like `/hoodik/` joined onto the
// bucket path produces `//hoodik/...`, which axum's `{*key}` catch-all captures
// WITH a leading slash. rust-s3's `is_not_found` only recognizes 404/NoSuchKey,
// so a 400 on a missing key surfaces as "unexpected status 400".
#[tokio::test]
async fn leading_slash_key_behaves_like_clean_key() {
    let (app, _tmp) = app();

    let r = app
        .clone()
        .oneshot(req(Method::PUT, "/vault", Body::empty()))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "create bucket");

    let r = app
        .clone()
        .oneshot(req(
            Method::HEAD,
            "/vault//hoodik/missing.part.4",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::NOT_FOUND,
        "HEAD on a missing leading-slash key must be 404 (so rust-s3 is_not_found classifies it), got {}",
        r.status()
    );

    let r = app
        .clone()
        .oneshot(req(
            Method::PUT,
            "/vault//hoodik/chunk.part.4",
            Body::from(vec![7u8; 16]),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "PUT leading-slash key");

    let r = app
        .clone()
        .oneshot(req(
            Method::HEAD,
            "/vault//hoodik/chunk.part.4",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "HEAD stored leading-slash key");
    assert_eq!(r.headers().get("content-length").unwrap(), "16");

    let r = app
        .clone()
        .oneshot(req(
            Method::GET,
            "/vault/hoodik/chunk.part.4",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "GET via the clean single-slash key resolves the same object"
    );

    let r = app
        .clone()
        .oneshot(req(
            Method::DELETE,
            "/vault//hoodik/chunk.part.4",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::NO_CONTENT,
        "DELETE leading-slash key"
    );

    let r = app
        .clone()
        .oneshot(req(
            Method::GET,
            "/vault/hoodik/chunk.part.4",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::NOT_FOUND,
        "object is gone after delete via leading-slash key"
    );
}

#[tokio::test]
async fn list_with_leading_slash_prefix_finds_objects() {
    let (app, _tmp) = app();

    app.clone()
        .oneshot(req(Method::PUT, "/vault2", Body::empty()))
        .await
        .unwrap();
    app.clone()
        .oneshot(req(
            Method::PUT,
            "/vault2/hoodik/a.part.1",
            Body::from(vec![1u8; 4]),
        ))
        .await
        .unwrap();

    let r = app
        .clone()
        .oneshot(req(Method::GET, "/vault2?prefix=/hoodik/", Body::empty()))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body = axum::body::to_bytes(r.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("hoodik/a.part.1"),
        "LIST with a leading-slash prefix should list objects stored under hoodik/, got: {}",
        text
    );
}
