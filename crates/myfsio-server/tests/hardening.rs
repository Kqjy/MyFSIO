use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use http_body_util::BodyExt;
use md5::Digest;
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
        multipart_min_part_size: 1,
        allow_legacy_header_auth: true,
        ..myfsio_server::config::ServerConfig::default()
    };
    let state = myfsio_server::state::AppState::new(config);
    let app = myfsio_server::create_router(state);
    (app, tmp)
}

fn request(method: Method, uri: &str, body: Body) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("x-access-key", TEST_ACCESS_KEY)
        .header("x-secret-key", TEST_SECRET_KEY)
        .body(body)
        .unwrap()
}

fn request_with<F>(method: Method, uri: &str, body: Body, decorate: F) -> Request<Body>
where
    F: FnOnce(axum::http::request::Builder) -> axum::http::request::Builder,
{
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-access-key", TEST_ACCESS_KEY)
        .header("x-secret-key", TEST_SECRET_KEY);
    decorate(builder).body(body).unwrap()
}

async fn body_bytes(resp: axum::response::Response) -> Vec<u8> {
    resp.into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec()
}

#[tokio::test]
async fn checksum_mismatch_rejects_upload_without_committing() {
    let (app, _tmp) = app();
    app.clone()
        .oneshot(request(Method::PUT, "/ck-bucket", Body::empty()))
        .await
        .unwrap();

    let wrong_md5 = B64.encode(md5::Md5::digest(b"other data"));
    let resp = app
        .clone()
        .oneshot(request_with(
            Method::PUT,
            "/ck-bucket/file.txt",
            Body::from("actual data"),
            |b| b.header("content-md5", wrong_md5),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = String::from_utf8(body_bytes(resp).await).unwrap();
    assert!(body.contains("BadDigest"), "expected BadDigest: {}", body);

    let resp = app
        .clone()
        .oneshot(request(Method::GET, "/ck-bucket/file.txt", Body::empty()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let good_md5 = B64.encode(md5::Md5::digest(b"actual data"));
    let resp = app
        .clone()
        .oneshot(request_with(
            Method::PUT,
            "/ck-bucket/file.txt",
            Body::from("actual data"),
            |b| b.header("content-md5", good_md5),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .oneshot(request(Method::GET, "/ck-bucket/file.txt", Body::empty()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_bytes(resp).await, b"actual data");
}

#[tokio::test]
async fn crc32_mismatch_rejected_and_match_accepted() {
    let (app, _tmp) = app();
    app.clone()
        .oneshot(request(Method::PUT, "/crc-bucket", Body::empty()))
        .await
        .unwrap();

    let bad = B64.encode(crc32fast::hash(b"different").to_be_bytes());
    let resp = app
        .clone()
        .oneshot(request_with(
            Method::PUT,
            "/crc-bucket/file.bin",
            Body::from("payload"),
            |b| b.header("x-amz-checksum-crc32", bad),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let good = B64.encode(crc32fast::hash(b"payload").to_be_bytes());
    let resp = app
        .clone()
        .oneshot(request_with(
            Method::PUT,
            "/crc-bucket/file.bin",
            Body::from("payload"),
            |b| b.header("x-amz-checksum-crc32", good),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn if_none_match_star_is_create_only() {
    let (app, _tmp) = app();
    app.clone()
        .oneshot(request(Method::PUT, "/cond-bucket", Body::empty()))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(request_with(
            Method::PUT,
            "/cond-bucket/key.txt",
            Body::from("first"),
            |b| b.header("if-none-match", "*"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(request_with(
            Method::PUT,
            "/cond-bucket/key.txt",
            Body::from("second"),
            |b| b.header("if-none-match", "*"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);

    let resp = app
        .oneshot(request(Method::GET, "/cond-bucket/key.txt", Body::empty()))
        .await
        .unwrap();
    assert_eq!(body_bytes(resp).await, b"first");
}

#[tokio::test]
async fn if_match_enforces_expected_etag() {
    let (app, _tmp) = app();
    app.clone()
        .oneshot(request(Method::PUT, "/etag-bucket", Body::empty()))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(request(
            Method::PUT,
            "/etag-bucket/key.txt",
            Body::from("v1"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let etag = resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let resp = app
        .clone()
        .oneshot(request_with(
            Method::PUT,
            "/etag-bucket/key.txt",
            Body::from("v2"),
            |b| b.header("if-match", "\"deadbeefdeadbeefdeadbeefdeadbeef\""),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);

    let resp = app
        .clone()
        .oneshot(request_with(
            Method::PUT,
            "/etag-bucket/key.txt",
            Body::from("v2"),
            |b| b.header("if-match", etag),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .oneshot(request(Method::GET, "/etag-bucket/key.txt", Body::empty()))
        .await
        .unwrap();
    assert_eq!(body_bytes(resp).await, b"v2");
}

#[tokio::test]
async fn legal_hold_blocks_destructive_overwrite_and_delete() {
    let (app, _tmp) = app();
    app.clone()
        .oneshot(request(Method::PUT, "/lock-bucket", Body::empty()))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(request_with(
            Method::PUT,
            "/lock-bucket/held.txt",
            Body::from("protected"),
            |b| b.header("x-amz-object-lock-legal-hold", "ON"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(request(
            Method::PUT,
            "/lock-bucket/held.txt",
            Body::from("overwrite attempt"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let resp = app
        .clone()
        .oneshot(request(
            Method::DELETE,
            "/lock-bucket/held.txt",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let resp = app
        .oneshot(request(Method::GET, "/lock-bucket/held.txt", Body::empty()))
        .await
        .unwrap();
    assert_eq!(body_bytes(resp).await, b"protected");
}

#[tokio::test]
async fn segmented_multipart_range_and_part_reads_are_correct() {
    let (app, _tmp) = app();
    app.clone()
        .oneshot(request(Method::PUT, "/seg-bucket", Body::empty()))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/seg-bucket/big.bin?uploads",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(body_bytes(resp).await).unwrap();
    let upload_id = body
        .split("<UploadId>")
        .nth(1)
        .unwrap()
        .split("</UploadId>")
        .next()
        .unwrap()
        .to_string();

    let part1 = vec![b'A'; 3000];
    let part2 = vec![b'B'; 3000];
    let part3 = vec![b'C'; 3000];
    let mut etags = Vec::new();
    for (idx, part) in [&part1, &part2, &part3].iter().enumerate() {
        let resp = app
            .clone()
            .oneshot(request(
                Method::PUT,
                &format!(
                    "/seg-bucket/big.bin?uploadId={}&partNumber={}",
                    upload_id,
                    idx + 1
                ),
                Body::from(part.to_vec()),
            ))
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
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"{}\"</ETag></Part><Part><PartNumber>2</PartNumber><ETag>\"{}\"</ETag></Part><Part><PartNumber>3</PartNumber><ETag>\"{}\"</ETag></Part></CompleteMultipartUpload>",
        etags[0], etags[1], etags[2]
    );
    let resp = app
        .clone()
        .oneshot(request(
            Method::POST,
            &format!("/seg-bucket/big.bin?uploadId={}", upload_id),
            Body::from(complete_xml),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(request_with(
            Method::GET,
            "/seg-bucket/big.bin",
            Body::empty(),
            |b| b.header("range", "bytes=3500-4499"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    let ranged = body_bytes(resp).await;
    assert_eq!(ranged.len(), 1000);
    assert!(ranged.iter().all(|b| *b == b'B'));

    let resp = app
        .clone()
        .oneshot(request_with(
            Method::GET,
            "/seg-bucket/big.bin",
            Body::empty(),
            |b| b.header("range", "bytes=-100"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    let suffix = body_bytes(resp).await;
    assert_eq!(suffix.len(), 100);
    assert!(suffix.iter().all(|b| *b == b'C'));

    let resp = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/seg-bucket/big.bin?partNumber=2",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    let part = body_bytes(resp).await;
    assert_eq!(part.len(), 3000);
    assert!(part.iter().all(|b| *b == b'B'));

    let resp = app
        .oneshot(request(Method::GET, "/seg-bucket/big.bin", Body::empty()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let full = body_bytes(resp).await;
    assert_eq!(full.len(), 9000);
    assert_eq!(&full[..3000], part1.as_slice());
    assert_eq!(&full[3000..6000], part2.as_slice());
    assert_eq!(&full[6000..], part3.as_slice());
}

#[tokio::test]
async fn conditional_complete_multipart_respects_if_none_match() {
    let (app, _tmp) = app();
    app.clone()
        .oneshot(request(Method::PUT, "/cmpu-bucket", Body::empty()))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(request(
            Method::PUT,
            "/cmpu-bucket/target.bin",
            Body::from("existing"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/cmpu-bucket/target.bin?uploads",
            Body::empty(),
        ))
        .await
        .unwrap();
    let body = String::from_utf8(body_bytes(resp).await).unwrap();
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
        .oneshot(request(
            Method::PUT,
            &format!(
                "/cmpu-bucket/target.bin?uploadId={}&partNumber=1",
                upload_id
            ),
            Body::from("part data"),
        ))
        .await
        .unwrap();
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
        .oneshot(request_with(
            Method::POST,
            &format!("/cmpu-bucket/target.bin?uploadId={}", upload_id),
            Body::from(complete_xml),
            |b| b.header("if-none-match", "*"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);

    let resp = app
        .oneshot(request(
            Method::GET,
            "/cmpu-bucket/target.bin",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(body_bytes(resp).await, b"existing");
}

async fn encrypted_app() -> (axum::Router, tempfile::TempDir) {
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
        multipart_min_part_size: 1,
        allow_legacy_header_auth: true,
        encryption_enabled: true,
        encryption_chunk_size_bytes: 1024,
        ..myfsio_server::config::ServerConfig::default()
    };
    let state = myfsio_server::state::AppState::new_with_encryption(config).await;
    let app = myfsio_server::create_router(state);
    (app, tmp)
}

#[tokio::test]
async fn sse_s3_streaming_roundtrip_full_and_range() {
    let (app, tmp) = encrypted_app().await;
    app.clone()
        .oneshot(request(Method::PUT, "/enc-bucket", Body::empty()))
        .await
        .unwrap();

    let payload: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
    let resp = app
        .clone()
        .oneshot(request_with(
            Method::PUT,
            "/enc-bucket/secret.bin",
            Body::from(payload.clone()),
            |b| b.header("x-amz-server-side-encryption", "AES256"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-amz-server-side-encryption")
            .unwrap()
            .to_str()
            .unwrap(),
        "AES256"
    );
    let etag = resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .trim_matches('"')
        .to_string();
    let expected_md5 = format!("{:x}", md5::Md5::digest(&payload));
    assert_eq!(etag, expected_md5);

    let live = std::fs::read(tmp.path().join("enc-bucket").join("secret.bin")).unwrap();
    assert_ne!(live.len(), payload.len());
    assert!(!live
        .windows(64.min(payload.len()))
        .any(|w| w == &payload[..64.min(payload.len())]));

    let resp = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/enc-bucket/secret.bin",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("content-length")
            .unwrap()
            .to_str()
            .unwrap(),
        payload.len().to_string()
    );
    assert_eq!(body_bytes(resp).await, payload);

    let resp = app
        .clone()
        .oneshot(request_with(
            Method::GET,
            "/enc-bucket/secret.bin",
            Body::empty(),
            |b| b.header("range", "bytes=2000-4999"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(body_bytes(resp).await, &payload[2000..5000]);

    let resp = app
        .oneshot(request_with(
            Method::GET,
            "/enc-bucket/secret.bin",
            Body::empty(),
            |b| b.header("range", "bytes=-500"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(body_bytes(resp).await, &payload[9500..]);
}

#[tokio::test]
async fn sse_s3_checksum_mismatch_leaves_no_object() {
    let (app, _tmp) = encrypted_app().await;
    app.clone()
        .oneshot(request(Method::PUT, "/enc2-bucket", Body::empty()))
        .await
        .unwrap();

    let wrong_md5 = B64.encode(md5::Md5::digest(b"other"));
    let resp = app
        .clone()
        .oneshot(request_with(
            Method::PUT,
            "/enc2-bucket/x.bin",
            Body::from("real body"),
            |b| {
                b.header("x-amz-server-side-encryption", "AES256")
                    .header("content-md5", wrong_md5)
            },
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let resp = app
        .oneshot(request(Method::GET, "/enc2-bucket/x.bin", Body::empty()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn failed_conditional_single_part_complete_preserves_part_for_retry() {
    let (app, _tmp) = app();
    app.clone()
        .oneshot(request(Method::PUT, "/retry-bucket", Body::empty()))
        .await
        .unwrap();
    app.clone()
        .oneshot(request(
            Method::PUT,
            "/retry-bucket/obj.bin",
            Body::from("existing"),
        ))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/retry-bucket/obj.bin?uploads",
            Body::empty(),
        ))
        .await
        .unwrap();
    let body = String::from_utf8(body_bytes(resp).await).unwrap();
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
        .oneshot(request(
            Method::PUT,
            &format!("/retry-bucket/obj.bin?uploadId={}&partNumber=1", upload_id),
            Body::from("replacement body"),
        ))
        .await
        .unwrap();
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
        .oneshot(request_with(
            Method::POST,
            &format!("/retry-bucket/obj.bin?uploadId={}", upload_id),
            Body::from(complete_xml.clone()),
            |b| b.header("if-none-match", "*"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);

    let resp = app
        .clone()
        .oneshot(request(
            Method::POST,
            &format!("/retry-bucket/obj.bin?uploadId={}", upload_id),
            Body::from(complete_xml),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .oneshot(request(Method::GET, "/retry-bucket/obj.bin", Body::empty()))
        .await
        .unwrap();
    assert_eq!(body_bytes(resp).await, b"replacement body");
}

#[tokio::test]
async fn upload_part_copy_range_from_middle_of_segmented_source() {
    let (app, _tmp) = app();
    app.clone()
        .oneshot(request(Method::PUT, "/upc-bucket", Body::empty()))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/upc-bucket/source.bin?uploads",
            Body::empty(),
        ))
        .await
        .unwrap();
    let body = String::from_utf8(body_bytes(resp).await).unwrap();
    let src_upload = body
        .split("<UploadId>")
        .nth(1)
        .unwrap()
        .split("</UploadId>")
        .next()
        .unwrap()
        .to_string();
    let mut etags = Vec::new();
    for (idx, fill) in [b'A', b'B', b'C'].iter().enumerate() {
        let resp = app
            .clone()
            .oneshot(request(
                Method::PUT,
                &format!(
                    "/upc-bucket/source.bin?uploadId={}&partNumber={}",
                    src_upload,
                    idx + 1
                ),
                Body::from(vec![*fill; 3000]),
            ))
            .await
            .unwrap();
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
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"{}\"</ETag></Part><Part><PartNumber>2</PartNumber><ETag>\"{}\"</ETag></Part><Part><PartNumber>3</PartNumber><ETag>\"{}\"</ETag></Part></CompleteMultipartUpload>",
        etags[0], etags[1], etags[2]
    );
    let resp = app
        .clone()
        .oneshot(request(
            Method::POST,
            &format!("/upc-bucket/source.bin?uploadId={}", src_upload),
            Body::from(complete_xml),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/upc-bucket/dest.bin?uploads",
            Body::empty(),
        ))
        .await
        .unwrap();
    let body = String::from_utf8(body_bytes(resp).await).unwrap();
    let dst_upload = body
        .split("<UploadId>")
        .nth(1)
        .unwrap()
        .split("</UploadId>")
        .next()
        .unwrap()
        .to_string();

    let resp = app
        .clone()
        .oneshot(request_with(
            Method::PUT,
            &format!("/upc-bucket/dest.bin?uploadId={}&partNumber=1", dst_upload),
            Body::empty(),
            |b| {
                b.header("x-amz-copy-source", "/upc-bucket/source.bin")
                    .header("x-amz-copy-source-range", "bytes=4000-6999")
            },
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(body_bytes(resp).await).unwrap();
    let etag = body
        .split("<ETag>")
        .nth(1)
        .unwrap()
        .split("</ETag>")
        .next()
        .unwrap()
        .trim_matches('"')
        .to_string();

    let complete_xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"{}\"</ETag></Part></CompleteMultipartUpload>",
        etag
    );
    let resp = app
        .clone()
        .oneshot(request(
            Method::POST,
            &format!("/upc-bucket/dest.bin?uploadId={}", dst_upload),
            Body::from(complete_xml),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .oneshot(request(Method::GET, "/upc-bucket/dest.bin", Body::empty()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let copied = body_bytes(resp).await;
    assert_eq!(copied.len(), 3000);
    assert!(copied[..2000].iter().all(|b| *b == b'B'));
    assert!(copied[2000..].iter().all(|b| *b == b'C'));
}
