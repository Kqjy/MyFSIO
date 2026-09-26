use super::*;

const MIB: usize = 1024 * 1024;

fn patterned(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 253) as u8).collect()
}

async fn read_all(backend: &FsStorageBackend, bucket: &str, key: &str) -> Vec<u8> {
    let (_, mut stream) = backend.get_object(bucket, key).await.unwrap();
    let mut out = Vec::new();
    stream.read_to_end(&mut out).await.unwrap();
    out
}

#[cfg(target_os = "linux")]
fn assert_no_excess_allocation(path: &std::path::Path, len: usize) {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).unwrap();
    assert_eq!(meta.len(), len as u64);
    assert!(
        meta.blocks() * 512 < (len + MIB) as u64,
        "preallocated blocks beyond the written bytes must be released"
    );
}

#[tokio::test]
async fn test_sized_put_round_trips_and_keeps_exact_allocation() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("prealloc").await.unwrap();
    let payload = patterned(10 * MIB);
    let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(payload.clone()));
    let meta = backend
        .put_object_with_commit_sized(
            "prealloc",
            "video.bin",
            stream,
            None,
            crate::traits::PutCommitOptions::default(),
            Some(payload.len() as u64),
        )
        .await
        .unwrap();
    assert_eq!(meta.size, payload.len() as u64);
    assert_eq!(read_all(&backend, "prealloc", "video.bin").await, payload);
    #[cfg(target_os = "linux")]
    assert_no_excess_allocation(
        &backend.object_live_path("prealloc", "video.bin"),
        payload.len(),
    );
}

#[tokio::test]
async fn test_overstated_size_hint_does_not_leave_reserved_space() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("prealloc-over").await.unwrap();
    let payload = patterned(5 * MIB);
    let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(payload.clone()));
    backend
        .put_object_with_commit_sized(
            "prealloc-over",
            "short.bin",
            stream,
            None,
            crate::traits::PutCommitOptions::default(),
            Some((payload.len() + 40 * MIB) as u64),
        )
        .await
        .unwrap();
    assert_eq!(
        read_all(&backend, "prealloc-over", "short.bin").await,
        payload
    );
    #[cfg(target_os = "linux")]
    assert_no_excess_allocation(
        &backend.object_live_path("prealloc-over", "short.bin"),
        payload.len(),
    );
}

#[tokio::test]
async fn test_sized_upload_part_round_trips() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("prealloc-mpu").await.unwrap();
    let upload_id = backend
        .initiate_multipart("prealloc-mpu", "parts.bin", None)
        .await
        .unwrap();
    let first = patterned(6 * MIB);
    let second = patterned(MIB);
    let mut parts = Vec::new();
    for (number, data) in [(1u32, &first), (2u32, &second)] {
        let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(data.clone()));
        let etag = backend
            .upload_part_sized(
                "prealloc-mpu",
                &upload_id,
                number,
                stream,
                Some(data.len() as u64),
            )
            .await
            .unwrap();
        parts.push(PartInfo {
            part_number: number,
            etag,
        });
    }
    backend
        .complete_multipart("prealloc-mpu", &upload_id, &parts)
        .await
        .unwrap();
    let mut expected = first.clone();
    expected.extend_from_slice(&second);
    assert_eq!(
        read_all(&backend, "prealloc-mpu", "parts.bin").await,
        expected
    );
}

#[tokio::test]
async fn test_preallocation_can_be_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let backend = FsStorageBackend::new_with_config(
        dir.path().to_path_buf(),
        FsStorageBackendConfig {
            upload_preallocate: false,
            ..FsStorageBackendConfig::default()
        },
    );
    backend.create_bucket("prealloc-off").await.unwrap();
    let payload = patterned(8 * MIB);
    let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(payload.clone()));
    backend
        .put_object_with_commit_sized(
            "prealloc-off",
            "plain.bin",
            stream,
            None,
            crate::traits::PutCommitOptions::default(),
            Some(payload.len() as u64),
        )
        .await
        .unwrap();
    assert_eq!(
        read_all(&backend, "prealloc-off", "plain.bin").await,
        payload
    );
}
