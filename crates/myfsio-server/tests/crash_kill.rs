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
