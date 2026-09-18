use super::*;
use crate::traits::StorageEngine;
use tokio::io::AsyncReadExt;

mod basic;
mod casing;
mod commit;
mod concurrency;
mod listing_index;
mod metadata_layout;
mod multipart;
mod object_lock;
mod recovery;

fn create_test_backend() -> (tempfile::TempDir, FsStorageBackend) {
    let dir = tempfile::tempdir().unwrap();
    let backend = FsStorageBackend::new(dir.path().to_path_buf());
    (dir, backend)
}

fn filesystem_stress_test_guard() -> impl Drop {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    struct Guard(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);
    impl Drop for Guard {
        fn drop(&mut self) {}
    }
    Guard(
        LOCK.get_or_init(Default::default)
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    )
}

fn create_listing_backend(
    root: PathBuf,
    enabled: bool,
    compact_min_ops: usize,
) -> FsStorageBackend {
    FsStorageBackend::new_with_config(
        root,
        FsStorageBackendConfig {
            listing_index_enabled: enabled,
            listing_index_compact_min_ops: compact_min_ops,
            ..FsStorageBackendConfig::default()
        },
    )
}

async fn put_listing_object(backend: &FsStorageBackend, bucket: &str, key: &str, body: &[u8]) {
    let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(body.to_vec()));
    backend.put_object(bucket, key, stream, None).await.unwrap();
}

fn block_object_destination(backend: &FsStorageBackend, bucket: &str, key: &str) {
    let blocked = backend.bucket_path(bucket).join(key);
    std::fs::create_dir_all(&blocked).unwrap();
    let destination = blocked.join(KEY_DATA_MARKER_FILE);
    std::fs::create_dir_all(&destination).unwrap();
    std::fs::write(destination.join("occupant"), b"occupied").unwrap();
}

fn failpoint_test_guard() -> impl Drop {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    struct Guard(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);
    impl Drop for Guard {
        fn drop(&mut self) {
            crate::failpoints::clear_all();
        }
    }
    Guard(
        LOCK.get_or_init(Default::default)
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    )
}

fn staged_sidecar_count(backend: &FsStorageBackend) -> usize {
    std::fs::read_dir(backend.tmp_dir())
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().ends_with(".sidecar-stage"))
                .count()
        })
        .unwrap_or(0)
}

fn ordinary_tmp_count(backend: &FsStorageBackend) -> usize {
    std::fs::read_dir(backend.tmp_dir())
        .map(|entries| {
            entries
                .flatten()
                .filter(|entry| {
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    name.ends_with(".tmp") && !name.ends_with(".sidecar-stage")
                })
                .count()
        })
        .unwrap_or(0)
}

fn assert_storage_full<T>(result: StorageResult<T>) {
    match result {
        Err(StorageError::Io(error)) => {
            assert_eq!(error.kind(), std::io::ErrorKind::StorageFull)
        }
        Err(error) => panic!("expected StorageFull I/O error, got {error}"),
        Ok(_) => panic!("expected StorageFull I/O error, got success"),
    }
}

async fn object_bytes(backend: &FsStorageBackend, bucket: &str, key: &str) -> Vec<u8> {
    let (_, mut stream) = backend.get_object(bucket, key).await.unwrap();
    let mut body = Vec::new();
    stream.read_to_end(&mut body).await.unwrap();
    body
}

async fn listed_keys(backend: &FsStorageBackend, bucket: &str) -> Vec<String> {
    backend
        .list_objects(bucket, &ListParams::default())
        .await
        .unwrap()
        .objects
        .into_iter()
        .map(|object| object.key)
        .collect()
}

async fn create_multipart_with_parts(
    backend: &FsStorageBackend,
    bucket: &str,
    key: &str,
    sizes: &[usize],
) -> (String, Vec<PartInfo>, Vec<u8>) {
    let upload_id = backend.initiate_multipart(bucket, key, None).await.unwrap();
    let mut parts = Vec::new();
    let mut expected = Vec::new();
    for (index, size) in sizes.iter().copied().enumerate() {
        let body = vec![b'A' + index as u8; size];
        expected.extend_from_slice(&body);
        let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(body));
        let etag = backend
            .upload_part(bucket, &upload_id, index as u32 + 1, stream)
            .await
            .unwrap();
        parts.push(PartInfo {
            part_number: index as u32 + 1,
            etag,
        });
    }
    (upload_id, parts, expected)
}

fn write_crafted_stage(
    backend: &FsStorageBackend,
    name: &str,
    bucket: &str,
    key: &str,
    etag: &str,
    size: u64,
    mtime: &str,
    extra_meta: &[(&str, &str)],
) -> PathBuf {
    let (_, entry_name) = backend.sidecar_file_for_key(bucket, key);
    let tmp_dir = backend.tmp_dir();
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let staged = tmp_dir.join(format!("{}.sidecar-stage", name));
    let mut meta = serde_json::Map::new();
    meta.insert("__etag__".to_string(), Value::String(etag.to_string()));
    meta.insert("__size__".to_string(), Value::String(size.to_string()));
    meta.insert(
        "__last_modified__".to_string(),
        Value::String(mtime.to_string()),
    );
    for (k, v) in extra_meta {
        meta.insert(k.to_string(), Value::String(v.to_string()));
    }
    std::fs::write(
        &staged,
        serde_json::json!({
            "metadata": meta,
            "__entry_name__": entry_name,
            "__commit_bucket__": bucket,
            "__commit_key__": key
        })
        .to_string(),
    )
    .unwrap();
    staged
}

fn live_ns(backend: &FsStorageBackend, bucket: &str, key: &str) -> (u64, u128, String) {
    let live = backend.object_live_path(bucket, key);
    let meta = std::fs::metadata(&live).unwrap();
    let ns = meta
        .modified()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mtime = backend
        .read_metadata_sync(bucket, key)
        .get("__last_modified__")
        .cloned()
        .unwrap();
    (meta.len(), ns, mtime)
}

fn alter_recorded_commit_ns(
    backend: &FsStorageBackend,
    bucket: &str,
    key: &str,
    new_ns: Option<u128>,
) {
    let mut meta = backend.read_metadata_sync(bucket, key);
    match new_ns {
        Some(ns) => {
            meta.insert(META_KEY_COMMIT_MTIME_NS.to_string(), ns.to_string());
        }
        None => {
            meta.remove(META_KEY_COMMIT_MTIME_NS);
        }
    }
    backend
        .write_live_metadata_entry_sync(bucket, key, &meta)
        .unwrap();
    backend
        .meta_read_cache
        .lock()
        .pop(&(bucket.to_string(), key.to_string()));
}

fn storm_keys() -> Vec<String> {
    (0..40)
        .map(|i| match i % 3 {
            0 => format!("a/k{:02}", i),
            1 => format!("a/b/k{:02}", i),
            _ => format!("c/k{:02}", i),
        })
        .collect()
}

fn storm_rng_next(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state >> 16
}

async fn audit_storm_bucket(backend: &FsStorageBackend, bucket: &str) {
    let params = myfsio_common::types::ListParams {
        max_keys: 1000,
        ..Default::default()
    };
    let listed = backend.list_objects(bucket, &params).await.unwrap();
    assert!(!listed.is_truncated, "audit listing must not be truncated");
    let indexed: Vec<(String, Option<String>, u64)> = listed
        .objects
        .iter()
        .map(|o| (o.key.clone(), o.etag.clone(), o.size))
        .collect();

    backend.invalidate_all_listing_indexes_sync().unwrap();
    let rebuilt = backend.list_objects(bucket, &params).await.unwrap();
    let walked: Vec<(String, Option<String>, u64)> = rebuilt
        .objects
        .iter()
        .map(|o| (o.key.clone(), o.etag.clone(), o.size))
        .collect();
    assert_eq!(
        indexed, walked,
        "the incremental listing index must match a from-scratch rebuild"
    );

    for obj in &listed.objects {
        let (sidecar_path, _) = backend.sidecar_file_for_key(bucket, &obj.key);
        assert!(
            sidecar_path.is_file(),
            "listed object {} must have a metadata sidecar",
            obj.key
        );
        let (meta, mut stream) = backend
            .get_object(bucket, &obj.key)
            .await
            .unwrap_or_else(|e| panic!("listed object {} must be readable: {}", obj.key, e));
        let mut body = Vec::new();
        stream.read_to_end(&mut body).await.unwrap();
        assert_eq!(
            body.len() as u64,
            obj.size,
            "size mismatch between listing and data for {}",
            obj.key
        );
        let mut hasher = Md5::new();
        hasher.update(&body);
        let body_md5 = format!("{:x}", hasher.finalize());
        if let Some(ref etag) = meta.etag {
            if !etag.contains('-') {
                assert_eq!(
                    etag, &body_md5,
                    "etag must match content md5 for {}",
                    obj.key
                );
            }
        }
    }

    let listed_keys: std::collections::HashSet<String> =
        listed.objects.iter().map(|o| o.key.clone()).collect();
    let bucket_root = backend.bucket_path(bucket);
    let mut stack = vec![bucket_root.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            let ft = entry.file_type().unwrap();
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file() {
                let rel = path
                    .strip_prefix(&bucket_root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                assert!(
                    listed_keys.contains(&rel),
                    "data file {} on disk is not listed (orphan)",
                    rel
                );
            }
        }
    }

    for entry in std::fs::read_dir(backend.tmp_dir()).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        assert!(
            !name.ends_with(".sidecar-stage") && !name.ends_with(".tmp"),
            "temp file {} must not survive the storm",
            name
        );
    }
}

async fn complete_listing_multipart(
    backend: &FsStorageBackend,
    bucket: &str,
    key: &str,
    body: &[u8],
) {
    let upload_id = backend.initiate_multipart(bucket, key, None).await.unwrap();
    let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(body.to_vec()));
    let etag = backend
        .upload_part(bucket, &upload_id, 1, stream)
        .await
        .unwrap();
    backend
        .complete_multipart(
            bucket,
            &upload_id,
            &[PartInfo {
                part_number: 1,
                etag,
            }],
        )
        .await
        .unwrap();
}

fn assert_counter_equivalence(backend: &FsStorageBackend, bucket: &str) {
    let counters = backend.live_listing_counters_sync(bucket).unwrap();
    let walked = backend.bucket_stats_walk_sync(bucket).unwrap();
    let rebuilt_versions = backend.build_version_counters_sync(bucket);
    assert_eq!(counters.live_objects, walked.objects);
    assert_eq!(counters.live_logical_bytes, walked.bytes);
    assert_eq!(counters.version_count, walked.version_count);
    assert_eq!(counters.version_logical_bytes, walked.version_bytes);
    assert_eq!(
        counters.delete_marker_count,
        rebuilt_versions.delete_marker_count
    );
}

fn assert_list_results_equal(left: &ListObjectsResult, right: &ListObjectsResult) {
    assert_eq!(
        serde_json::to_value(&left.objects).unwrap(),
        serde_json::to_value(&right.objects).unwrap()
    );
    assert_eq!(left.is_truncated, right.is_truncated);
    assert_eq!(left.next_continuation_token, right.next_continuation_token);
}

fn logical_listing_view(
    result: &ListObjectsResult,
) -> Vec<(String, u64, Option<String>, Option<String>, Option<String>)> {
    result
        .objects
        .iter()
        .map(|object| {
            (
                object.key.clone(),
                object.size,
                object.etag.clone(),
                object.version_id.clone(),
                object.owner.clone(),
            )
        })
        .collect()
}

async fn assert_index_matches_legacy(
    backend: &FsStorageBackend,
    bucket: &str,
    params: &ListParams,
) -> ListObjectsResult {
    let result = backend.list_objects(bucket, params).await.unwrap();
    let legacy = backend.list_objects_legacy_sync(bucket, params).unwrap();
    assert_list_results_equal(&result, &legacy);
    result
}

async fn seed_listing_mutation_scenario(backend: &FsStorageBackend, bucket: &str) {
    backend.create_bucket(bucket).await.unwrap();
    for (key, body) in [
        ("alpha.txt", b"alpha".as_slice()),
        ("docs/a.txt", b"a".as_slice()),
        ("docs/b.txt", b"b".as_slice()),
        ("zeta.txt", b"zeta".as_slice()),
    ] {
        put_listing_object(backend, bucket, key, body).await;
    }
    backend
        .list_objects(bucket, &ListParams::default())
        .await
        .unwrap();
    put_listing_object(backend, bucket, "folder/", b"").await;
    put_listing_object(backend, bucket, "docs/a.txt", b"overwritten").await;
    let mut metadata = backend
        .get_object_metadata(bucket, "zeta.txt")
        .await
        .unwrap();
    metadata.insert(
        "__acl__".to_string(),
        serde_json::json!({"owner": "listing-owner"}).to_string(),
    );
    backend
        .put_object_metadata(bucket, "zeta.txt", &metadata)
        .await
        .unwrap();
    backend.delete_object(bucket, "alpha.txt").await.unwrap();
    backend
        .copy_object(bucket, "zeta.txt", bucket, "copied.txt")
        .await
        .unwrap();
    let upload_id = backend
        .initiate_multipart(bucket, "docs/multipart.bin", None)
        .await
        .unwrap();
    let etag = backend
        .upload_part(
            bucket,
            &upload_id,
            1,
            Box::pin(std::io::Cursor::new(b"multipart".to_vec())),
        )
        .await
        .unwrap();
    backend
        .complete_multipart(
            bucket,
            &upload_id,
            &[PartInfo {
                part_number: 1,
                etag,
            }],
        )
        .await
        .unwrap();
}

async fn read_stream_to_end(mut stream: AsyncReadStream) -> Vec<u8> {
    let mut out = Vec::new();
    stream.read_to_end(&mut out).await.unwrap();
    out
}

async fn seed_segmented_object(
    backend: &FsStorageBackend,
    bucket: &str,
    key: &str,
    parts_data: &[Vec<u8>],
) -> (String, ObjectMeta) {
    let upload_id = backend.initiate_multipart(bucket, key, None).await.unwrap();
    let mut parts = Vec::new();
    for (i, data) in parts_data.iter().enumerate() {
        let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(data.clone()));
        let etag = backend
            .upload_part(bucket, &upload_id, (i + 1) as u32, stream)
            .await
            .unwrap();
        parts.push(PartInfo {
            part_number: (i + 1) as u32,
            etag,
        });
    }
    let obj = backend
        .complete_multipart(bucket, &upload_id, &parts)
        .await
        .unwrap();
    (upload_id, obj)
}

fn segmented_parts() -> Vec<Vec<u8>> {
    vec![
        (0..5000u32).map(|i| (i % 251) as u8).collect(),
        (0..4000u32).map(|i| (i % 13) as u8).collect(),
    ]
}

fn expected_composite_etag(parts_data: &[Vec<u8>]) -> String {
    let mut concat = Vec::new();
    for p in parts_data {
        concat.extend_from_slice(&Md5::digest(p));
    }
    format!("{:x}-{}", Md5::digest(&concat), parts_data.len())
}
