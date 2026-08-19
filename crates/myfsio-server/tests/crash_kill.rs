#![cfg(feature = "failpoints")]

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const ACCESS_KEY: &str = "kill-test-admin";
const SECRET_KEY: &str = "kill-test-secret-0123456789abcdef";

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Server {
    child: Child,
    port: u16,
}

impl Server {
    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{}", self.port, path)
    }

    fn kill(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    fn wait_for_exit(&mut self, timeout: Duration) -> Option<std::process::ExitStatus> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Ok(Some(status)) = self.child.try_wait() {
                return Some(status);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        None
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_server(root: &Path, failpoints: Option<&str>) -> Server {
    let port = free_port();
    let ui_port = free_port();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_myfsio-server"));
    cmd.arg("serve")
        .current_dir(root)
        .env("STORAGE_ROOT", root)
        .env("HOST", "127.0.0.1")
        .env("PORT", port.to_string())
        .env("UI_PORT", ui_port.to_string())
        .env("UI_ENABLED", "false")
        .env("ALLOW_LEGACY_HEADER_AUTH", "true")
        .env("ADMIN_ACCESS_KEY", ACCESS_KEY)
        .env("ADMIN_SECRET_KEY", SECRET_KEY)
        .env("ENCRYPTION_ENABLED", "true")
        .env("MULTIPART_MIN_PART_SIZE", "1")
        .env("LOG_LEVEL", "ERROR")
        .env_remove("MYFSIO_FAILPOINTS")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(spec) = failpoints {
        cmd.env("MYFSIO_FAILPOINTS", spec);
    }
    let child = cmd.spawn().expect("failed to spawn myfsio-server");
    Server { child, port }
}

async fn wait_healthy(client: &reqwest::Client, server: &Server) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if let Ok(resp) = client.get(server.url("/myfsio/health")).send().await {
            if resp.status().is_success() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("server did not become healthy within 30s");
}

fn authed(builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    builder
        .header("x-access-key", ACCESS_KEY)
        .header("x-secret-key", SECRET_KEY)
}

async fn put_object(
    client: &reqwest::Client,
    server: &Server,
    body: &'static [u8],
) -> Result<reqwest::Response, reqwest::Error> {
    authed(client.put(server.url("/crash-bkt/obj.bin")))
        .body(body)
        .send()
        .await
}

async fn get_object(
    client: &reqwest::Client,
    server: &Server,
) -> (reqwest::StatusCode, String, Vec<u8>) {
    let resp = authed(client.get(server.url("/crash-bkt/obj.bin")))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let etag = resp
        .headers()
        .get("etag")
        .map(|v| v.to_str().unwrap_or_default().to_string())
        .unwrap_or_default();
    let body = resp.bytes().await.unwrap().to_vec();
    (status, etag, body)
}

struct SseMultipart {
    upload_id: String,
    completion_xml: String,
    plaintext: Vec<u8>,
}

async fn initiate_sse_multipart(client: &reqwest::Client, server: &Server) -> SseMultipart {
    let response = authed(client.post(server.url("/crash-bkt/obj.bin?uploads")))
        .header("x-amz-server-side-encryption", "AES256")
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let body = response.text().await.unwrap();
    let upload_id = body
        .split("<UploadId>")
        .nth(1)
        .and_then(|value| value.split("</UploadId>").next())
        .unwrap()
        .to_string();
    let first = vec![b'A'; 4096];
    let second = vec![b'B'; 2048];
    let mut etags = Vec::new();
    for (part_number, part) in [(1, first.clone()), (2, second.clone())] {
        let response = authed(client.put(server.url(&format!(
            "/crash-bkt/obj.bin?partNumber={part_number}&uploadId={upload_id}"
        ))))
        .body(part)
        .send()
        .await
        .unwrap();
        assert!(response.status().is_success());
        etags.push(
            response
                .headers()
                .get("etag")
                .unwrap()
                .to_str()
                .unwrap()
                .to_string(),
        );
    }
    let completion_xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part><Part><PartNumber>2</PartNumber><ETag>{}</ETag></Part></CompleteMultipartUpload>",
        etags[0], etags[1]
    );
    let mut plaintext = first;
    plaintext.extend_from_slice(&second);
    SseMultipart {
        upload_id,
        completion_xml,
        plaintext,
    }
}

async fn complete_sse_multipart(
    client: &reqwest::Client,
    server: &Server,
    upload: &SseMultipart,
) -> Result<reqwest::Response, reqwest::Error> {
    authed(client.post(server.url(&format!("/crash-bkt/obj.bin?uploadId={}", upload.upload_id))))
        .header("content-type", "application/xml")
        .body(upload.completion_xml.clone())
        .send()
        .await
}

async fn assert_upload_exists(client: &reqwest::Client, server: &Server, upload_id: &str) {
    let response =
        authed(client.get(server.url(&format!("/crash-bkt/obj.bin?uploadId={upload_id}"))))
            .send()
            .await
            .unwrap();
    assert!(
        response.status().is_success(),
        "multipart upload {upload_id} must remain available"
    );
}

fn committed_metadata(root: &Path) -> serde_json::Value {
    let meta_dir = root
        .join(".myfsio.sys")
        .join("buckets")
        .join("crash-bkt")
        .join("meta");
    for entry in std::fs::read_dir(meta_dir).unwrap().flatten() {
        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(entry.path()).unwrap()).unwrap();
        if value
            .get("metadata")
            .and_then(|metadata| metadata.get("x-amz-encryption-nonce"))
            .is_some()
        {
            return value.get("metadata").unwrap().clone();
        }
    }
    panic!("encrypted object sidecar not found")
}

#[tokio::test]
async fn killing_the_server_mid_put_commit_preserves_the_invariants() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    let server = spawn_server(root, None);
    wait_healthy(&client, &server).await;
    let resp = authed(client.put(server.url("/crash-bkt")))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "bucket creation failed: {}",
        resp.status()
    );
    let resp = put_object(&client, &server, b"vvvv1111").await.unwrap();
    assert!(resp.status().is_success());
    let (status, etag_v1, body) = get_object(&client, &server).await;
    assert!(status.is_success());
    assert_eq!(body, b"vvvv1111");
    assert!(!etag_v1.is_empty());
    server.kill();

    let mut server = spawn_server(root, Some("put:before-data-rename=abort"));
    wait_healthy(&client, &server).await;
    let result = put_object(&client, &server, b"vvvv2222").await;
    assert!(
        result.is_err() || !result.unwrap().status().is_success(),
        "the put must not report success when the process dies mid-commit"
    );
    assert!(
        server.wait_for_exit(Duration::from_secs(10)).is_some(),
        "the abort failpoint must terminate the process"
    );

    let server = spawn_server(root, None);
    wait_healthy(&client, &server).await;
    let (status, etag, body) = get_object(&client, &server).await;
    assert!(status.is_success());
    assert_eq!(
        body, b"vvvv1111",
        "a kill before the data rename must leave the old object untouched across restart"
    );
    assert_eq!(etag, etag_v1);
    let staged_leftovers = std::fs::read_dir(root.join(".myfsio.sys").join("tmp"))
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().ends_with(".sidecar-stage"))
                .count()
        })
        .unwrap_or(0);
    assert_eq!(
        staged_leftovers, 0,
        "commit recovery must discard the staged sidecar of a commit whose data \
         never renamed into place"
    );
    server.kill();

    let mut server = spawn_server(root, Some("put:before-publish-sidecar=abort"));
    wait_healthy(&client, &server).await;
    let result = put_object(&client, &server, b"vvvv3333").await;
    assert!(
        result.is_err() || !result.unwrap().status().is_success(),
        "the put must not report success when the process dies mid-commit"
    );
    assert!(
        server.wait_for_exit(Duration::from_secs(10)).is_some(),
        "the abort failpoint must terminate the process"
    );

    let server = spawn_server(root, None);
    wait_healthy(&client, &server).await;
    let (status, etag, body) = get_object(&client, &server).await;
    assert!(status.is_success());
    assert_eq!(
        body, b"vvvv3333",
        "a kill after the data rename commits the data"
    );
    assert_ne!(
        etag, etag_v1,
        "startup commit recovery must publish the staged sidecar so the metadata \
         describes the committed bytes"
    );
    let staged_leftovers = std::fs::read_dir(root.join(".myfsio.sys").join("tmp"))
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().ends_with(".sidecar-stage"))
                .count()
        })
        .unwrap_or(0);
    assert_eq!(
        staged_leftovers, 0,
        "commit recovery must consume the staged sidecar"
    );

    let resp = put_object(&client, &server, b"vvvv4444").await.unwrap();
    assert!(
        resp.status().is_success(),
        "a normal put after recovery must succeed"
    );
    let (status, etag, body) = get_object(&client, &server).await;
    assert!(status.is_success());
    assert_eq!(body, b"vvvv4444");
    assert_ne!(etag, etag_v1);
    server.kill();
}

#[tokio::test]
async fn storage_full_env_failpoint_returns_internal_error_and_recovers() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let server = spawn_server(root, None);
    wait_healthy(&client, &server).await;
    let response = authed(client.put(server.url("/crash-bkt")))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let response = put_object(&client, &server, b"old-object").await.unwrap();
    assert!(response.status().is_success());
    server.kill();

    let server = spawn_server(root, Some("put:stage-data-write=error:storage_full"));
    wait_healthy(&client, &server).await;
    let response = put_object(&client, &server, b"new-object").await.unwrap();
    assert_eq!(
        response.status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR
    );
    let error_body = response.text().await.unwrap();
    assert!(error_body.contains("InternalError"));
    wait_healthy(&client, &server).await;
    let (status, _, body) = get_object(&client, &server).await;
    assert!(status.is_success());
    assert_eq!(body, b"old-object");
    let listing = authed(client.get(server.url("/crash-bkt?list-type=2")))
        .send()
        .await
        .unwrap();
    assert!(listing.status().is_success());
    let listing = listing.text().await.unwrap();
    assert_eq!(listing.matches("<Key>obj.bin</Key>").count(), 1);
    let ordinary_temps = std::fs::read_dir(root.join(".myfsio.sys").join("tmp"))
        .map(|entries| {
            entries
                .flatten()
                .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
                .count()
        })
        .unwrap_or(0);
    assert_eq!(ordinary_temps, 0);
    server.kill();

    let server = spawn_server(root, None);
    wait_healthy(&client, &server).await;
    let response = put_object(&client, &server, b"new-object").await.unwrap();
    assert!(response.status().is_success());
    let (status, _, body) = get_object(&client, &server).await;
    assert!(status.is_success());
    assert_eq!(body, b"new-object");
    server.kill();
}

async fn run_sse_multipart_precommit_abort(failpoint: &str) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let server = spawn_server(root, None);
    wait_healthy(&client, &server).await;
    let response = authed(client.put(server.url("/crash-bkt")))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let response = put_object(&client, &server, b"old-object").await.unwrap();
    assert!(response.status().is_success());
    let upload = initiate_sse_multipart(&client, &server).await;
    server.kill();

    let spec = format!("{failpoint}=abort");
    let mut crashed = spawn_server(root, Some(&spec));
    wait_healthy(&client, &crashed).await;
    let result = complete_sse_multipart(&client, &crashed, &upload).await;
    assert!(result.is_err() || !result.unwrap().status().is_success());
    assert!(
        crashed.wait_for_exit(Duration::from_secs(10)).is_some(),
        "{failpoint} must terminate the process"
    );
    assert_eq!(
        std::fs::read(root.join("crash-bkt").join("obj.bin")).unwrap(),
        b"old-object",
        "{failpoint} must not publish assembled plaintext"
    );

    let server = spawn_server(root, None);
    wait_healthy(&client, &server).await;
    let (status, _, body) = get_object(&client, &server).await;
    assert!(status.is_success());
    assert_eq!(body, b"old-object");
    assert_upload_exists(&client, &server, &upload.upload_id).await;
    let response = complete_sse_multipart(&client, &server, &upload)
        .await
        .unwrap();
    assert!(
        response.status().is_success(),
        "retry after {failpoint} failed: {}",
        response.status()
    );
    let (status, _, body) = get_object(&client, &server).await;
    assert!(status.is_success());
    assert_eq!(body, upload.plaintext);
    let stored = std::fs::read(root.join("crash-bkt").join("obj.bin")).unwrap();
    assert_ne!(stored, upload.plaintext);
    let metadata = committed_metadata(root);
    assert!(metadata.get("__pending_sse_algorithm__").is_none());
    assert!(metadata.get("__segments__").is_none());
    server.kill();
}

async fn run_sse_multipart_committed_abort(failpoint: &str) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let server = spawn_server(root, None);
    wait_healthy(&client, &server).await;
    let response = authed(client.put(server.url("/crash-bkt")))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let response = put_object(&client, &server, b"old-object").await.unwrap();
    assert!(response.status().is_success());
    let upload = initiate_sse_multipart(&client, &server).await;
    server.kill();

    let spec = format!("{failpoint}=abort");
    let mut crashed = spawn_server(root, Some(&spec));
    wait_healthy(&client, &crashed).await;
    let result = complete_sse_multipart(&client, &crashed, &upload).await;
    assert!(result.is_err() || !result.unwrap().status().is_success());
    assert!(
        crashed.wait_for_exit(Duration::from_secs(10)).is_some(),
        "{failpoint} must terminate the process"
    );

    let server = spawn_server(root, None);
    wait_healthy(&client, &server).await;
    let (status, _, body) = get_object(&client, &server).await;
    assert!(status.is_success());
    assert_eq!(body, upload.plaintext);
    let stored = std::fs::read(root.join("crash-bkt").join("obj.bin")).unwrap();
    assert_ne!(stored, upload.plaintext);
    assert_ne!(stored, b"old-object");
    let metadata = committed_metadata(root);
    assert!(metadata.get("x-amz-encryption-nonce").is_some());
    assert!(metadata.get("__pending_sse_algorithm__").is_none());
    assert!(metadata.get("__segments__").is_none());
    assert_upload_exists(&client, &server, &upload.upload_id).await;
    let response = authed(
        client.delete(server.url(&format!("/crash-bkt/obj.bin?uploadId={}", upload.upload_id))),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::NO_CONTENT);
    server.kill();
}

#[tokio::test]
async fn killing_sse_multipart_before_data_publish_never_exposes_plaintext() {
    for failpoint in [
        "mpu:during-assembly",
        "mpu:after-assembly",
        "mpu:before-encryption",
        "mpu:during-encryption",
        "mpu:after-encryption",
        "mpu:before-commit",
        "put:after-archive",
        "put:stage-sidecar",
        "put:stage-dir-fsync",
        "put:before-data-rename",
    ] {
        run_sse_multipart_precommit_abort(failpoint).await;
    }
}

#[tokio::test]
async fn killing_sse_multipart_after_ciphertext_publish_recovers_encrypted_state() {
    for failpoint in ["put:before-publish-sidecar", "mpu:after-commit"] {
        run_sse_multipart_committed_abort(failpoint).await;
    }
}
