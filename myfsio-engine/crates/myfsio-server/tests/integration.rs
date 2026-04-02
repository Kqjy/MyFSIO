use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

const TEST_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
const TEST_SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

fn test_app() -> (axum::Router, tempfile::TempDir) {
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
        lifecycle_enabled: false,
    };
    let state = myfsio_server::state::AppState::new(config);
    let app = myfsio_server::create_router(state);
    (app, tmp)
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

#[tokio::test]
async fn test_unauthenticated_request_rejected() {
    let (app, _tmp) = test_app();
    let resp = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
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
        resp.into_body().collect().await.unwrap().to_bytes().to_vec(),
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
        resp.into_body().collect().await.unwrap().to_bytes().to_vec(),
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
        .oneshot(signed_request(Method::HEAD, "/hd-bucket/file.bin", Body::empty()))
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
        resp.into_body().collect().await.unwrap().to_bytes().to_vec(),
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
        resp.into_body().collect().await.unwrap().to_bytes().to_vec(),
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
        resp.into_body().collect().await.unwrap().to_bytes().to_vec(),
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
        resp.into_body().collect().await.unwrap().to_bytes().to_vec(),
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
    assert!(resp.headers().get("content-range").unwrap().to_str().unwrap().starts_with("bytes 0-4/"));
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
        resp.into_body().collect().await.unwrap().to_bytes().to_vec(),
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
        resp.into_body().collect().await.unwrap().to_bytes().to_vec(),
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
    let etag1 = resp.headers().get("etag").unwrap().to_str().unwrap().trim_matches('"').to_string();

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
    let etag2 = resp.headers().get("etag").unwrap().to_str().unwrap().trim_matches('"').to_string();

    let complete_xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"{etag1}\"</ETag></Part><Part><PartNumber>2</PartNumber><ETag>\"{etag2}\"</ETag></Part></CompleteMultipartUpload>"
    );

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "/mp-bucket/big-file.bin?uploadId={}",
                    upload_id
                ))
                .header("x-access-key", TEST_ACCESS_KEY)
                .header("x-secret-key", TEST_SECRET_KEY)
                .body(Body::from(complete_xml))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        resp.into_body().collect().await.unwrap().to_bytes().to_vec(),
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

    let delete_xml = r#"<Delete><Object><Key>a.txt</Key></Object><Object><Key>b.txt</Key></Object></Delete>"#;

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
        resp.into_body().collect().await.unwrap().to_bytes().to_vec(),
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
        resp.into_body().collect().await.unwrap().to_bytes().to_vec(),
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
        resp.into_body().collect().await.unwrap().to_bytes().to_vec(),
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
        resp.into_body().collect().await.unwrap().to_bytes().to_vec(),
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
        resp.into_body().collect().await.unwrap().to_bytes().to_vec(),
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
        resp.into_body().collect().await.unwrap().to_bytes().to_vec(),
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
        resp.into_body().collect().await.unwrap().to_bytes().to_vec(),
    )
    .unwrap();
    assert!(body.contains("<TagSet>"));
    assert!(body.contains("</TagSet>"));

    let tag_xml = r#"<Tagging><TagSet><Tag><Key>env</Key><Value>prod</Value></Tag></TagSet></Tagging>"#;
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
        resp.into_body().collect().await.unwrap().to_bytes().to_vec(),
    )
    .unwrap();
    assert!(body.contains("<Key>env</Key>"));
    assert!(body.contains("<Value>prod</Value>"));

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(Method::DELETE, "/tag-bucket/myfile.txt?tagging", Body::empty()),
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
        resp.into_body().collect().await.unwrap().to_bytes().to_vec(),
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
        resp.into_body().collect().await.unwrap().to_bytes().to_vec(),
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
        signed_request(
            Method::PUT,
            "/lh-bucket/obj.txt",
            Body::from("data"),
        ),
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
        resp.into_body().collect().await.unwrap().to_bytes().to_vec(),
    )
    .unwrap();
    assert!(body.contains("<Status>OFF</Status>"));
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
        lifecycle_enabled: false,
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
    let body: serde_json::Value = serde_json::from_slice(
        &resp.into_body().collect().await.unwrap().to_bytes(),
    )
    .unwrap();
    let key_id = body["KeyId"].as_str().unwrap().to_string();
    assert!(!key_id.is_empty());

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(Method::GET, "/kms/keys", Body::empty()),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &resp.into_body().collect().await.unwrap().to_bytes(),
    )
    .unwrap();
    assert_eq!(body["keys"].as_array().unwrap().len(), 1);

    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        signed_request(
            Method::GET,
            &format!("/kms/keys/{}", key_id),
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
    let body: serde_json::Value = serde_json::from_slice(
        &resp.into_body().collect().await.unwrap().to_bytes(),
    )
    .unwrap();
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
    let body: serde_json::Value = serde_json::from_slice(
        &resp.into_body().collect().await.unwrap().to_bytes(),
    )
    .unwrap();
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
    let body: serde_json::Value = serde_json::from_slice(
        &resp.into_body().collect().await.unwrap().to_bytes(),
    )
    .unwrap();
    let pt_b64 = body["Plaintext"].as_str().unwrap();
    let result = B64.decode(pt_b64).unwrap();
    assert_eq!(result, plaintext);
}

