use super::*;

#[tokio::test]
async fn storage_full_multipart_manifest_and_part_writes_are_retryable_and_abortable() {
    let _fp = failpoint_test_guard();
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("enospc-mpu-part").await.unwrap();

    crate::failpoints::set(
        &backend.root,
        "mpu:manifest-write",
        crate::failpoints::FailAction::Error(std::io::ErrorKind::StorageFull),
    );
    let result = backend
        .initiate_multipart("enospc-mpu-part", "manifest.bin", None)
        .await;
    crate::failpoints::clear(&backend.root, "mpu:manifest-write");
    assert_storage_full(result);
    assert_eq!(
        std::fs::read_dir(backend.multipart_bucket_root("enospc-mpu-part"))
            .map(|entries| entries.flatten().count())
            .unwrap_or(0),
        0
    );
    let upload_id = backend
        .initiate_multipart("enospc-mpu-part", "manifest.bin", None)
        .await
        .unwrap();
    backend
        .abort_multipart("enospc-mpu-part", &upload_id)
        .await
        .unwrap();

    for (index, name) in [
        "mpu:part-write",
        "mpu:part-sync",
        "mpu:part-publish",
        "mpu:part-record-write",
    ]
    .into_iter()
    .enumerate()
    {
        let key = format!("retry-{index}.bin");
        let upload_id = backend
            .initiate_multipart("enospc-mpu-part", &key, None)
            .await
            .unwrap();
        crate::failpoints::set(
            &backend.root,
            name,
            crate::failpoints::FailAction::Error(std::io::ErrorKind::StorageFull),
        );
        let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(b"part-body".to_vec()));
        let result = backend
            .upload_part("enospc-mpu-part", &upload_id, 1, stream)
            .await;
        crate::failpoints::clear(&backend.root, name);
        assert_storage_full(result);
        let upload_dir = backend
            .multipart_upload_dir("enospc-mpu-part", &upload_id)
            .unwrap();
        assert!(upload_dir.is_dir());
        assert_eq!(
            std::fs::read_dir(&upload_dir)
                .unwrap()
                .flatten()
                .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
                .count(),
            0
        );
        backend
            .list_parts("enospc-mpu-part", &upload_id)
            .await
            .unwrap();
        let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(b"part-body".to_vec()));
        backend
            .upload_part("enospc-mpu-part", &upload_id, 1, stream)
            .await
            .unwrap();
        assert_eq!(
            backend
                .list_parts("enospc-mpu-part", &upload_id)
                .await
                .unwrap()
                .len(),
            1
        );
        backend
            .abort_multipart("enospc-mpu-part", &upload_id)
            .await
            .unwrap();
        assert!(!upload_dir.exists());
    }
}

#[tokio::test]
async fn a_failed_replacement_keeps_the_previously_acknowledged_part_listed() {
    let _fp = failpoint_test_guard();
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("keep-mpu").await.unwrap();
    let upload_id = backend
        .initiate_multipart("keep-mpu", "kept.bin", None)
        .await
        .unwrap();

    let original = vec![b'a'; 4096];
    let replacement = vec![b'b'; 4096];
    assert_eq!(original.len(), replacement.len());

    let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(original.clone()));
    let original_etag = backend
        .upload_part("keep-mpu", &upload_id, 1, stream)
        .await
        .unwrap();

    let upload_dir = backend
        .multipart_upload_dir("keep-mpu", &upload_id)
        .unwrap();
    let manifest_path = upload_dir.join(MANIFEST_FILE);
    let mut manifest: Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["parts"]["1"] = serde_json::json!({
        "etag": original_etag.clone(),
        "size": original.len(),
    });
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();

    crate::failpoints::set(
        &backend.root,
        "mpu:part-record-retract-manifest",
        crate::failpoints::FailAction::Error(std::io::ErrorKind::StorageFull),
    );
    let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(replacement.clone()));
    let result = backend.upload_part("keep-mpu", &upload_id, 1, stream).await;
    crate::failpoints::clear(&backend.root, "mpu:part-record-retract-manifest");
    assert_storage_full(result);

    assert_eq!(
        std::fs::read(FsStorageBackend::part_data_path(&upload_dir, 1)).unwrap(),
        original,
        "a failed replacement must not disturb the previously acknowledged bytes"
    );

    let listed = backend.list_parts("keep-mpu", &upload_id).await.unwrap();
    assert_eq!(
        listed.len(),
        1,
        "the previously acknowledged part must still be listed after a failed replacement"
    );
    assert_eq!(listed[0].part_number, 1);
    assert_eq!(
        listed[0].etag, original_etag,
        "the restored record must still describe the bytes that are on disk"
    );

    let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(replacement.clone()));
    let retried_etag = backend
        .upload_part("keep-mpu", &upload_id, 1, stream)
        .await
        .expect("retrying the replacement succeeds");
    assert_ne!(retried_etag, original_etag);
    assert_eq!(
        std::fs::read(FsStorageBackend::part_data_path(&upload_dir, 1)).unwrap(),
        replacement
    );
}

#[tokio::test]
async fn failed_part_replacement_never_leaves_a_stale_digest_for_the_new_bytes() {
    let _fp = failpoint_test_guard();
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("replace-mpu").await.unwrap();
    let upload_id = backend
        .initiate_multipart("replace-mpu", "replaced.bin", None)
        .await
        .unwrap();

    let original_first = vec![b'a'; 4096];
    let replacement_first = vec![b'b'; 4096];
    let second = vec![b'c'; 2048];
    assert_eq!(original_first.len(), replacement_first.len());

    let stale_first_etag = backend
        .upload_part(
            "replace-mpu",
            &upload_id,
            1,
            Box::pin(std::io::Cursor::new(original_first.clone())),
        )
        .await
        .unwrap();
    let second_etag = backend
        .upload_part(
            "replace-mpu",
            &upload_id,
            2,
            Box::pin(std::io::Cursor::new(second.clone())),
        )
        .await
        .unwrap();

    crate::failpoints::set(
        &backend.root,
        "mpu:part-record-write",
        crate::failpoints::FailAction::Error(std::io::ErrorKind::StorageFull),
    );
    let replacement = backend
        .upload_part(
            "replace-mpu",
            &upload_id,
            1,
            Box::pin(std::io::Cursor::new(replacement_first.clone())),
        )
        .await;
    crate::failpoints::clear(&backend.root, "mpu:part-record-write");
    assert_storage_full(replacement);

    let upload_dir = backend
        .multipart_upload_dir("replace-mpu", &upload_id)
        .unwrap();
    let first_on_disk = std::fs::read(FsStorageBackend::part_data_path(&upload_dir, 1)).unwrap();
    assert_ne!(first_on_disk, original_first);

    let listed = backend.list_parts("replace-mpu", &upload_id).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].part_number, 2);

    let completed = backend
        .complete_multipart(
            "replace-mpu",
            &upload_id,
            &[
                PartInfo {
                    part_number: 1,
                    etag: stale_first_etag,
                },
                PartInfo {
                    part_number: 2,
                    etag: second_etag,
                },
            ],
        )
        .await
        .unwrap();
    assert_eq!(
        completed.etag.as_deref(),
        Some(expected_composite_etag(&[first_on_disk.clone(), second.clone()]).as_str())
    );
    assert_eq!(
        object_bytes(&backend, "replace-mpu", "replaced.bin").await,
        [first_on_disk, second].concat()
    );
}

#[tokio::test]
async fn failed_part_replacement_retracts_a_legacy_manifest_entry_too() {
    let _fp = failpoint_test_guard();
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("legacy-replace").await.unwrap();
    let upload_id = backend
        .initiate_multipart("legacy-replace", "legacy.bin", None)
        .await
        .unwrap();
    let upload_dir = backend
        .multipart_upload_dir("legacy-replace", &upload_id)
        .unwrap();

    let original = vec![b'a'; 1024];
    let replacement = vec![b'b'; 1024];
    let stale_etag = backend
        .upload_part(
            "legacy-replace",
            &upload_id,
            1,
            Box::pin(std::io::Cursor::new(original.clone())),
        )
        .await
        .unwrap();

    let manifest_path = upload_dir.join(MANIFEST_FILE);
    let mut manifest: Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    manifest["parts"]["1"] = serde_json::json!({
        "etag": stale_etag,
        "size": original.len(),
        "filename": "part-00001.part"
    });
    FsStorageBackend::atomic_write_json_sync(&manifest_path, &manifest, true).unwrap();

    crate::failpoints::set(
        &backend.root,
        "mpu:part-record-write",
        crate::failpoints::FailAction::Error(std::io::ErrorKind::StorageFull),
    );
    let result = backend
        .upload_part(
            "legacy-replace",
            &upload_id,
            1,
            Box::pin(std::io::Cursor::new(replacement.clone())),
        )
        .await;
    crate::failpoints::clear(&backend.root, "mpu:part-record-write");
    assert_storage_full(result);

    assert!(backend
        .list_parts("legacy-replace", &upload_id)
        .await
        .unwrap()
        .is_empty());
    let manifest: Value = serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    assert!(manifest["parts"].get("1").is_none());
}

#[tokio::test]
async fn part_records_without_mtime_are_recomputed_instead_of_trusted() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("legacy-digest").await.unwrap();
    let upload_id = backend
        .initiate_multipart("legacy-digest", "legacy.bin", None)
        .await
        .unwrap();
    let body = vec![b'z'; 1024];
    let etag = backend
        .upload_part(
            "legacy-digest",
            &upload_id,
            1,
            Box::pin(std::io::Cursor::new(body.clone())),
        )
        .await
        .unwrap();

    let upload_dir = backend
        .multipart_upload_dir("legacy-digest", &upload_id)
        .unwrap();
    let legacy_record = serde_json::json!({
        "etag": "00000000000000000000000000000000",
        "size": body.len(),
    });
    FsStorageBackend::atomic_write_json_sync(
        &FsStorageBackend::part_record_path(&upload_dir, 1),
        &legacy_record,
        true,
    )
    .unwrap();

    let listed = backend
        .list_parts("legacy-digest", &upload_id)
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].size, body.len() as u64);

    let completed = backend
        .complete_multipart(
            "legacy-digest",
            &upload_id,
            &[PartInfo {
                part_number: 1,
                etag,
            }],
        )
        .await
        .unwrap();
    assert_eq!(
        completed.etag.as_deref(),
        Some(expected_composite_etag(&[body]).as_str())
    );
}

#[tokio::test]
async fn storage_full_multipart_assembly_sites_preserve_old_object_and_upload() {
    let _fp = failpoint_test_guard();
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("enospc-mpu-complete").await.unwrap();

    for (index, (name, sizes)) in [
        ("mpu:assembly-move", vec![512]),
        ("mpu:during-assembly", vec![512, 512]),
        ("mpu:assembly-sync", vec![512, 512]),
        ("mpu:segment-move", vec![3072, 3072]),
        ("mpu:segment-stub-write", vec![3072, 3072]),
        ("mpu:segment-dir-fsync", vec![3072, 3072]),
        ("mpu:before-finalize", vec![3072, 3072]),
    ]
    .into_iter()
    .enumerate()
    {
        let key = format!("target-{index}.bin");
        put_listing_object(&backend, "enospc-mpu-complete", &key, b"old").await;
        let (upload_id, parts, expected) =
            create_multipart_with_parts(&backend, "enospc-mpu-complete", &key, &sizes).await;
        crate::failpoints::set(
            &backend.root,
            name,
            crate::failpoints::FailAction::Error(std::io::ErrorKind::StorageFull),
        );
        let result = backend
            .complete_multipart("enospc-mpu-complete", &upload_id, &parts)
            .await;
        crate::failpoints::clear(&backend.root, name);
        assert_storage_full(result);
        assert_eq!(
            object_bytes(&backend, "enospc-mpu-complete", &key).await,
            b"old"
        );
        assert!(listed_keys(&backend, "enospc-mpu-complete")
            .await
            .contains(&key));
        assert_eq!(
            backend
                .list_parts("enospc-mpu-complete", &upload_id)
                .await
                .unwrap()
                .len(),
            sizes.len()
        );
        backend
            .complete_multipart("enospc-mpu-complete", &upload_id, &parts)
            .await
            .unwrap();
        assert_eq!(
            object_bytes(&backend, "enospc-mpu-complete", &key).await,
            expected
        );

        let abort_key = format!("abort-{index}.bin");
        let (abort_id, abort_parts, _) =
            create_multipart_with_parts(&backend, "enospc-mpu-complete", &abort_key, &sizes).await;
        crate::failpoints::set(
            &backend.root,
            name,
            crate::failpoints::FailAction::Error(std::io::ErrorKind::StorageFull),
        );
        let result = backend
            .complete_multipart("enospc-mpu-complete", &abort_id, &abort_parts)
            .await;
        crate::failpoints::clear(&backend.root, name);
        assert_storage_full(result);
        backend
            .abort_multipart("enospc-mpu-complete", &abort_id)
            .await
            .unwrap();
        assert!(!backend
            .multipart_upload_dir("enospc-mpu-complete", &abort_id)
            .unwrap()
            .exists());
        assert!(!backend
            .segments_bucket_root("enospc-mpu-complete")
            .join(&abort_id)
            .exists());
    }
}

#[tokio::test]
async fn crash_before_concat_mpu_finalize_is_retryable() {
    let _fp = failpoint_test_guard();
    let (_dir, backend) = create_test_backend();
    let backend = std::sync::Arc::new(backend);
    backend.create_bucket("fp-mpu-c").await.unwrap();

    let upload_id = backend
        .initiate_multipart("fp-mpu-c", "obj.bin", None)
        .await
        .unwrap();
    let part1: AsyncReadStream = Box::pin(std::io::Cursor::new(vec![b'A'; 1024]));
    backend
        .upload_part("fp-mpu-c", &upload_id, 1, part1)
        .await
        .unwrap();
    let part2: AsyncReadStream = Box::pin(std::io::Cursor::new(vec![b'B'; 512]));
    backend
        .upload_part("fp-mpu-c", &upload_id, 2, part2)
        .await
        .unwrap();
    let parts = vec![
        PartInfo {
            part_number: 1,
            etag: String::new(),
        },
        PartInfo {
            part_number: 2,
            etag: String::new(),
        },
    ];

    crate::failpoints::set(
        &backend.root,
        "mpu:before-finalize",
        crate::failpoints::FailAction::Panic,
    );
    let crashed = backend.clone();
    let crashed_upload = upload_id.clone();
    let crashed_parts = parts.clone();
    let join = tokio::spawn(async move {
        crashed
            .complete_multipart("fp-mpu-c", &crashed_upload, &crashed_parts)
            .await
    })
    .await;
    crate::failpoints::clear(&backend.root, "mpu:before-finalize");
    assert!(join.unwrap_err().is_panic());
    assert!(
        backend.get_object("fp-mpu-c", "obj.bin").await.is_err(),
        "no object may be visible after a crash before the commit"
    );

    let obj = backend
        .complete_multipart("fp-mpu-c", &upload_id, &parts)
        .await
        .unwrap();
    assert_eq!(
        obj.size, 1536,
        "the concat path keeps its parts; retrying the complete must succeed"
    );
    let (_, mut stream) = backend.get_object("fp-mpu-c", "obj.bin").await.unwrap();
    let mut body = Vec::new();
    stream.read_to_end(&mut body).await.unwrap();
    assert_eq!(body.len(), 1536);
}

#[tokio::test]
async fn transformed_mpu_precondition_failure_preserves_object_upload_and_temps() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("mpu-transform-cond").await.unwrap();
    put_listing_object(&backend, "mpu-transform-cond", "obj.bin", b"old").await;

    let mut pending = HashMap::new();
    pending.insert(MULTIPART_PENDING_SSE_ALG.to_string(), "AES256".to_string());
    let upload_id = backend
        .initiate_multipart("mpu-transform-cond", "obj.bin", Some(pending))
        .await
        .unwrap();
    let first: AsyncReadStream = Box::pin(std::io::Cursor::new(b"new-".to_vec()));
    let first_etag = backend
        .upload_part("mpu-transform-cond", &upload_id, 1, first)
        .await
        .unwrap();
    let second: AsyncReadStream = Box::pin(std::io::Cursor::new(b"body".to_vec()));
    let second_etag = backend
        .upload_part("mpu-transform-cond", &upload_id, 2, second)
        .await
        .unwrap();
    let parts = vec![
        PartInfo {
            part_number: 1,
            etag: first_etag,
        },
        PartInfo {
            part_number: 2,
            etag: second_etag,
        },
    ];
    let ordinary = backend
        .complete_multipart("mpu-transform-cond", &upload_id, &parts)
        .await;
    assert!(matches!(ordinary, Err(StorageError::InvalidArgument(_))));
    let prepared = backend
        .prepare_multipart_for_transform("mpu-transform-cond", &upload_id, &parts)
        .await
        .unwrap();
    let transformed = backend.allocate_prepared_tmp_path().unwrap();
    std::fs::copy(&prepared.plaintext_path, &transformed).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&transformed)
        .unwrap()
        .sync_all()
        .unwrap();
    let transformed_size = std::fs::metadata(&transformed).unwrap().len();
    let mut final_metadata = prepared.metadata.clone();
    final_metadata.remove(MULTIPART_PENDING_SSE_ALG);
    let result = backend
        .commit_transformed_multipart(
            &prepared,
            &transformed,
            transformed_size,
            final_metadata.clone(),
            crate::traits::PutCommitOptions {
                conditions: crate::traits::PutConditions {
                    if_match: Some("not-the-old-etag".to_string()),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await;
    assert!(matches!(result, Err(StorageError::PreconditionFailed(_))));
    assert!(prepared.plaintext_path.is_file());
    assert!(transformed.is_file());
    assert!(backend
        .multipart_upload_dir("mpu-transform-cond", &upload_id)
        .unwrap()
        .join("part-00001.part")
        .is_file());
    let (_, mut old_stream) = backend
        .get_object("mpu-transform-cond", "obj.bin")
        .await
        .unwrap();
    let mut old_body = Vec::new();
    old_stream.read_to_end(&mut old_body).await.unwrap();
    assert_eq!(old_body, b"old");

    let committed = backend
        .commit_transformed_multipart(
            &prepared,
            &transformed,
            transformed_size,
            final_metadata,
            crate::traits::PutCommitOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        committed.etag.as_deref(),
        Some(prepared.composite_etag.as_str())
    );
    assert!(!backend
        .multipart_upload_dir("mpu-transform-cond", &upload_id)
        .unwrap()
        .exists());
    let _ = std::fs::remove_file(&prepared.plaintext_path);
}

#[tokio::test]
async fn transformed_mpu_assembly_failpoints_preserve_the_upload() {
    let _fp = failpoint_test_guard();
    let (_dir, backend) = create_test_backend();
    let backend = std::sync::Arc::new(backend);
    backend.create_bucket("mpu-transform-fp").await.unwrap();
    let upload_id = backend
        .initiate_multipart("mpu-transform-fp", "obj.bin", None)
        .await
        .unwrap();
    let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(b"payload".to_vec()));
    let etag = backend
        .upload_part("mpu-transform-fp", &upload_id, 1, stream)
        .await
        .unwrap();
    let parts = vec![PartInfo {
        part_number: 1,
        etag,
    }];

    crate::failpoints::set(
        &backend.root,
        "mpu:during-assembly",
        crate::failpoints::FailAction::Error(std::io::ErrorKind::StorageFull),
    );
    assert!(backend
        .prepare_multipart_for_transform("mpu-transform-fp", &upload_id, &parts)
        .await
        .is_err());
    crate::failpoints::clear(&backend.root, "mpu:during-assembly");

    crate::failpoints::set(
        &backend.root,
        "mpu:after-assembly",
        crate::failpoints::FailAction::Panic,
    );
    let crashed = backend.clone();
    let crashed_upload = upload_id.clone();
    let crashed_parts = parts.clone();
    let join = tokio::spawn(async move {
        crashed
            .prepare_multipart_for_transform("mpu-transform-fp", &crashed_upload, &crashed_parts)
            .await
    })
    .await;
    crate::failpoints::clear(&backend.root, "mpu:after-assembly");
    assert!(join.unwrap_err().is_panic());
    assert!(backend
        .multipart_upload_dir("mpu-transform-fp", &upload_id)
        .unwrap()
        .join("part-00001.part")
        .is_file());
    let prepared = backend
        .prepare_multipart_for_transform("mpu-transform-fp", &upload_id, &parts)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&prepared.plaintext_path).unwrap(), b"payload");
    let _ = std::fs::remove_file(&prepared.plaintext_path);
}

#[tokio::test]
async fn crash_before_segments_mpu_finalize_is_recovered_on_retry() {
    let _fp = failpoint_test_guard();
    let (_dir, backend) = create_test_backend();
    let backend = std::sync::Arc::new(backend);
    backend.create_bucket("fp-mpu-s").await.unwrap();

    let upload_id = backend
        .initiate_multipart("fp-mpu-s", "obj.bin", None)
        .await
        .unwrap();
    let part1: AsyncReadStream = Box::pin(std::io::Cursor::new(vec![b'A'; 3072]));
    backend
        .upload_part("fp-mpu-s", &upload_id, 1, part1)
        .await
        .unwrap();
    let part2: AsyncReadStream = Box::pin(std::io::Cursor::new(vec![b'B'; 3072]));
    backend
        .upload_part("fp-mpu-s", &upload_id, 2, part2)
        .await
        .unwrap();
    let parts = vec![
        PartInfo {
            part_number: 1,
            etag: String::new(),
        },
        PartInfo {
            part_number: 2,
            etag: String::new(),
        },
    ];

    crate::failpoints::set(
        &backend.root,
        "mpu:before-finalize",
        crate::failpoints::FailAction::Panic,
    );
    let crashed = backend.clone();
    let crashed_upload = upload_id.clone();
    let crashed_parts = parts.clone();
    let join = tokio::spawn(async move {
        crashed
            .complete_multipart("fp-mpu-s", &crashed_upload, &crashed_parts)
            .await
    })
    .await;
    crate::failpoints::clear(&backend.root, "mpu:before-finalize");
    assert!(join.unwrap_err().is_panic());

    assert!(
        backend.get_object("fp-mpu-s", "obj.bin").await.is_err(),
        "no object may be visible after a crash before the commit"
    );
    let segment_dir = backend.segments_bucket_root("fp-mpu-s").join(&upload_id);
    assert!(
        segment_dir.is_dir(),
        "the moved parts survive as the segment set"
    );

    let obj = backend
        .complete_multipart("fp-mpu-s", &upload_id, &parts)
        .await
        .unwrap();
    assert_eq!(
        obj.size, 6144,
        "retrying the complete must recover the already-moved parts"
    );
    let meta = backend
        .get_object_metadata("fp-mpu-s", "obj.bin")
        .await
        .unwrap();
    assert_eq!(
        meta.get(crate::segments::META_KEY_SEGMENTS),
        Some(&upload_id)
    );
    let (_, mut stream) = backend.get_object("fp-mpu-s", "obj.bin").await.unwrap();
    let mut body = Vec::new();
    stream.read_to_end(&mut body).await.unwrap();
    let mut expected = vec![b'A'; 3072];
    expected.extend_from_slice(&vec![b'B'; 3072]);
    assert_eq!(body, expected);
}

#[tokio::test]
async fn segment_dir_fsync_failure_fails_the_complete_and_retry_succeeds() {
    let _fp = failpoint_test_guard();
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("fp-mpu-f").await.unwrap();

    let upload_id = backend
        .initiate_multipart("fp-mpu-f", "obj.bin", None)
        .await
        .unwrap();
    let part1: AsyncReadStream = Box::pin(std::io::Cursor::new(vec![b'A'; 3072]));
    backend
        .upload_part("fp-mpu-f", &upload_id, 1, part1)
        .await
        .unwrap();
    let part2: AsyncReadStream = Box::pin(std::io::Cursor::new(vec![b'B'; 3072]));
    backend
        .upload_part("fp-mpu-f", &upload_id, 2, part2)
        .await
        .unwrap();
    let parts = vec![
        PartInfo {
            part_number: 1,
            etag: String::new(),
        },
        PartInfo {
            part_number: 2,
            etag: String::new(),
        },
    ];

    crate::failpoints::set(
        &backend.root,
        "mpu:segment-dir-fsync",
        crate::failpoints::FailAction::Error(std::io::ErrorKind::StorageFull),
    );
    let result = backend
        .complete_multipart("fp-mpu-f", &upload_id, &parts)
        .await;
    crate::failpoints::clear(&backend.root, "mpu:segment-dir-fsync");
    assert!(
        result.is_err(),
        "a failed segment-directory fsync must fail the complete instead of \
         acknowledging an upload whose namespace entries may not be durable"
    );
    assert!(
        backend.get_object("fp-mpu-f", "obj.bin").await.is_err(),
        "no object may be visible after the failed complete"
    );
    let segment_dir = backend.segments_bucket_root("fp-mpu-f").join(&upload_id);
    assert!(
        !segment_dir.exists(),
        "the failed complete must roll the parts back out of the segment directory"
    );

    let obj = backend
        .complete_multipart("fp-mpu-f", &upload_id, &parts)
        .await
        .unwrap();
    assert_eq!(obj.size, 6144, "retrying the complete must succeed");
    let (_, mut stream) = backend.get_object("fp-mpu-f", "obj.bin").await.unwrap();
    let mut body = Vec::new();
    stream.read_to_end(&mut body).await.unwrap();
    assert_eq!(body.len(), 6144);
}

#[tokio::test]
async fn partially_moved_mpu_parts_are_recovered_on_complete() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("fp-mpu-p").await.unwrap();

    let upload_id = backend
        .initiate_multipart("fp-mpu-p", "obj.bin", None)
        .await
        .unwrap();
    let part1: AsyncReadStream = Box::pin(std::io::Cursor::new(vec![b'A'; 3072]));
    backend
        .upload_part("fp-mpu-p", &upload_id, 1, part1)
        .await
        .unwrap();
    let part2: AsyncReadStream = Box::pin(std::io::Cursor::new(vec![b'B'; 3072]));
    backend
        .upload_part("fp-mpu-p", &upload_id, 2, part2)
        .await
        .unwrap();

    let upload_dir = backend
        .multipart_upload_dir("fp-mpu-p", &upload_id)
        .unwrap();
    let segment_dir = backend.segments_bucket_root("fp-mpu-p").join(&upload_id);
    std::fs::create_dir_all(&segment_dir).unwrap();
    std::fs::rename(
        upload_dir.join("part-00001.part"),
        segment_dir.join(crate::segments::SegmentSet::seg_file_name(0)),
    )
    .unwrap();

    let parts = vec![
        PartInfo {
            part_number: 1,
            etag: String::new(),
        },
        PartInfo {
            part_number: 2,
            etag: String::new(),
        },
    ];
    let obj = backend
        .complete_multipart("fp-mpu-p", &upload_id, &parts)
        .await
        .unwrap();
    assert_eq!(
        obj.size, 6144,
        "a complete interrupted mid-move must succeed with mixed part sources"
    );
    let (_, mut stream) = backend.get_object("fp-mpu-p", "obj.bin").await.unwrap();
    let mut body = Vec::new();
    stream.read_to_end(&mut body).await.unwrap();
    let mut expected = vec![b'A'; 3072];
    expected.extend_from_slice(&vec![b'B'; 3072]);
    assert_eq!(body, expected);
}

#[tokio::test]
async fn release_segment_dir_ignores_traversal_segment_id() {
    let (dir, backend) = create_test_backend();
    backend.create_bucket("victim").await.unwrap();

    let config_dir = dir.path().join(".myfsio.sys").join("config");
    std::fs::create_dir_all(&config_dir).unwrap();
    let sentinel = config_dir.join("iam.json");
    std::fs::write(&sentinel, b"{}").unwrap();

    backend.release_segment_dir("victim", "../../../config");

    assert!(config_dir.exists());
    assert!(sentinel.exists());
}

#[test]
fn test_part_sizes_roundtrip() {
    let sizes = vec![5_242_880, 5_242_880, 5_242_880, 12_345];
    let encoded = encode_part_sizes(&sizes);
    assert_eq!(encoded, "5242880,5242880,5242880,12345");
    let parsed = parse_part_sizes(&encoded).unwrap();
    assert_eq!(parsed, sizes);
    assert!(parse_part_sizes("").is_none());
    assert!(parse_part_sizes(",,,").is_none());
    assert!(parse_part_sizes("abc").is_none());
    assert!(parse_part_sizes("123,abc").is_none());
    assert!(parse_part_sizes(" ").is_none());
}

#[tokio::test]
async fn test_complete_multipart_persists_part_sizes() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("mp-bucket").await.unwrap();

    let upload_id = backend
        .initiate_multipart("mp-bucket", "obj.bin", None)
        .await
        .unwrap();

    let part1: AsyncReadStream = Box::pin(std::io::Cursor::new(vec![b'A'; 1024]));
    backend
        .upload_part("mp-bucket", &upload_id, 1, part1)
        .await
        .unwrap();
    let part2: AsyncReadStream = Box::pin(std::io::Cursor::new(vec![b'B'; 512]));
    backend
        .upload_part("mp-bucket", &upload_id, 2, part2)
        .await
        .unwrap();

    let parts = vec![
        PartInfo {
            part_number: 1,
            etag: String::new(),
        },
        PartInfo {
            part_number: 2,
            etag: String::new(),
        },
    ];
    let obj = backend
        .complete_multipart("mp-bucket", &upload_id, &parts)
        .await
        .unwrap();
    assert_eq!(obj.size, 1536);

    let stored = backend
        .get_object_metadata("mp-bucket", "obj.bin")
        .await
        .unwrap();
    let raw = stored
        .get(META_KEY_PART_SIZES)
        .expect("part sizes must be persisted on completion");
    assert_eq!(parse_part_sizes(raw).unwrap(), vec![1024u64, 512u64]);
}

#[tokio::test]
async fn multipart_part_records_are_constant_size_and_merge_with_legacy_manifest() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("record-bucket").await.unwrap();
    let upload_id = backend
        .initiate_multipart("record-bucket", "mixed.bin", None)
        .await
        .unwrap();
    let upload_dir = backend
        .multipart_upload_dir("record-bucket", &upload_id)
        .unwrap();
    let manifest_path = upload_dir.join(MANIFEST_FILE);
    let original_manifest = std::fs::read(&manifest_path).unwrap();

    let first = b"record-one".to_vec();
    let second = b"legacy-two".to_vec();
    let first_etag = backend
        .upload_part(
            "record-bucket",
            &upload_id,
            1,
            Box::pin(std::io::Cursor::new(first.clone())),
        )
        .await
        .unwrap();
    let second_etag = backend
        .upload_part(
            "record-bucket",
            &upload_id,
            2,
            Box::pin(std::io::Cursor::new(second.clone())),
        )
        .await
        .unwrap();

    assert_eq!(std::fs::read(&manifest_path).unwrap(), original_manifest);
    assert!(FsStorageBackend::part_record_path(&upload_dir, 1).is_file());
    assert!(FsStorageBackend::part_record_path(&upload_dir, 2).is_file());

    let mut manifest: Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    manifest["parts"]["1"] = serde_json::json!({
        "etag": "00000000000000000000000000000000",
        "size": 999,
        "filename": "part-00001.part"
    });
    manifest["parts"]["2"] = serde_json::json!({
        "etag": second_etag.clone(),
        "size": second.len(),
        "filename": "part-00002.part"
    });
    FsStorageBackend::atomic_write_json_sync(&manifest_path, &manifest, true).unwrap();
    std::fs::remove_file(FsStorageBackend::part_record_path(&upload_dir, 2)).unwrap();

    let listed = backend
        .list_parts("record-bucket", &upload_id)
        .await
        .unwrap();
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].etag, first_etag);
    assert_eq!(listed[0].size, first.len() as u64);
    assert_eq!(listed[1].etag, second_etag);
    assert_eq!(listed[1].size, second.len() as u64);

    let completed = backend
        .complete_multipart(
            "record-bucket",
            &upload_id,
            &[
                PartInfo {
                    part_number: 1,
                    etag: first_etag,
                },
                PartInfo {
                    part_number: 2,
                    etag: second_etag,
                },
            ],
        )
        .await
        .unwrap();
    assert_eq!(completed.size, (first.len() + second.len()) as u64);
    let (_, stream) = backend
        .get_object("record-bucket", "mixed.bin")
        .await
        .unwrap();
    assert_eq!(read_stream_to_end(stream).await, [first, second].concat());
}

#[tokio::test]
async fn test_segmented_complete_roundtrip() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("seg-bkt").await.unwrap();
    let parts_data = segmented_parts();
    let full: Vec<u8> = parts_data.concat();

    let (upload_id, obj) = seed_segmented_object(&backend, "seg-bkt", "v.bin", &parts_data).await;
    assert_eq!(obj.size, full.len() as u64);
    assert_eq!(
        obj.etag.as_deref(),
        Some(expected_composite_etag(&parts_data).as_str())
    );

    let stored = backend
        .get_object_metadata("seg-bkt", "v.bin")
        .await
        .unwrap();
    assert_eq!(
        stored.get(crate::segments::META_KEY_SEGMENTS),
        Some(&upload_id)
    );

    let live_path = backend.object_path("seg-bkt", "v.bin").unwrap();
    let header = crate::segments::read_stub_header(&live_path)
        .unwrap()
        .expect("live file must be a segment stub");
    assert_eq!(header.total, full.len() as u64);
    assert_eq!(
        std::fs::metadata(&live_path).unwrap().len(),
        full.len() as u64
    );
    let seg_dir = backend.segments_bucket_root("seg-bkt").join(&upload_id);
    assert!(seg_dir.is_dir());

    let (meta, stream) = backend.get_object("seg-bkt", "v.bin").await.unwrap();
    assert_eq!(meta.size, full.len() as u64);
    assert_eq!(read_stream_to_end(stream).await, full);

    let (_, stream) = backend
        .get_object_range("seg-bkt", "v.bin", 4990, Some(30))
        .await
        .unwrap();
    assert_eq!(read_stream_to_end(stream).await, &full[4990..5020]);

    let head = backend.head_object("seg-bkt", "v.bin").await.unwrap();
    assert_eq!(head.size, full.len() as u64);

    let listing = backend
        .list_objects("seg-bkt", &ListParams::default())
        .await
        .unwrap();
    let entry = listing
        .objects
        .iter()
        .find(|o| o.key == "v.bin")
        .expect("listed");
    assert_eq!(entry.size, full.len() as u64);
}

#[tokio::test]
async fn segmented_snapshot_links_survive_source_delete_and_clean_up() {
    let (dir, backend) = create_test_backend();
    backend.create_bucket("snap-bkt").await.unwrap();
    let parts_data = segmented_parts();
    let full: Vec<u8> = parts_data.concat();
    seed_segmented_object(&backend, "snap-bkt", "source.bin", &parts_data).await;
    let snapshot_path = dir.path().join("segment-snapshot");

    let (_, source) = backend
        .snapshot_object_to_link("snap-bkt", "source.bin", &snapshot_path)
        .await
        .unwrap();
    assert!(snapshot_path.join("stub").is_file());
    assert!(snapshot_path.join("segments").is_dir());
    backend
        .delete_object("snap-bkt", "source.bin")
        .await
        .unwrap();

    let stream = source.into_range_stream(0, None).await.unwrap();
    assert_eq!(read_stream_to_end(stream).await, full);
    assert!(!snapshot_path.exists());
}

#[tokio::test]
async fn segmented_snapshot_defers_later_size_validation_until_stream_reaches_it() {
    use tokio::io::AsyncReadExt;
    let (dir, backend) = create_test_backend();
    backend.create_bucket("lazy-bkt").await.unwrap();
    let parts_data = segmented_parts();
    let (segment_id, _) =
        seed_segmented_object(&backend, "lazy-bkt", "source.bin", &parts_data).await;
    let second_segment = backend
        .segments_bucket_root("lazy-bkt")
        .join(segment_id)
        .join(crate::segments::SegmentSet::seg_file_name(1));
    std::fs::write(&second_segment, b"short").unwrap();
    let snapshot_path = dir.path().join("lazy-snapshot");

    let (_, source) = backend
        .snapshot_object_to_link("lazy-bkt", "source.bin", &snapshot_path)
        .await
        .unwrap();
    let mut stream = source.into_range_stream(0, None).await.unwrap();
    let mut first = vec![0u8; parts_data[0].len()];
    stream.read_exact(&mut first).await.unwrap();
    assert_eq!(first, parts_data[0]);
    let error = stream.read_to_end(&mut Vec::new()).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn segmented_snapshot_rejects_first_size_mismatch_before_stream_creation() {
    let (dir, backend) = create_test_backend();
    backend.create_bucket("eager-bkt").await.unwrap();
    let parts_data = segmented_parts();
    let (segment_id, _) =
        seed_segmented_object(&backend, "eager-bkt", "source.bin", &parts_data).await;
    let first_segment = backend
        .segments_bucket_root("eager-bkt")
        .join(segment_id)
        .join(crate::segments::SegmentSet::seg_file_name(0));
    std::fs::write(first_segment, b"short").unwrap();
    let snapshot_path = dir.path().join("eager-snapshot");

    match backend
        .snapshot_object_to_link("eager-bkt", "source.bin", &snapshot_path)
        .await
    {
        Err(StorageError::ObjectCorrupted { .. }) => {}
        Err(error) => panic!("expected ObjectCorrupted, got {error}"),
        Ok(_) => panic!("expected ObjectCorrupted, got a snapshot"),
    }
}

#[tokio::test]
async fn test_segmented_and_concat_layouts_agree() {
    let dir = tempfile::tempdir().unwrap();
    let concat_backend = FsStorageBackend::new_with_config(
        dir.path().to_path_buf(),
        FsStorageBackendConfig {
            multipart_layout: MultipartLayout::Concat,
            ..FsStorageBackendConfig::default()
        },
    );
    concat_backend.create_bucket("cmp-bkt").await.unwrap();
    let parts_data = segmented_parts();
    let (_, concat_obj) =
        seed_segmented_object(&concat_backend, "cmp-bkt", "c.bin", &parts_data).await;

    let (_dir2, seg_backend) = create_test_backend();
    seg_backend.create_bucket("cmp-bkt").await.unwrap();
    let (_, seg_obj) = seed_segmented_object(&seg_backend, "cmp-bkt", "c.bin", &parts_data).await;

    assert_eq!(concat_obj.etag, seg_obj.etag);
    assert_eq!(concat_obj.size, seg_obj.size);

    let concat_meta = concat_backend
        .get_object_metadata("cmp-bkt", "c.bin")
        .await
        .unwrap();
    assert!(!concat_meta.contains_key(crate::segments::META_KEY_SEGMENTS));

    let (_, s1) = concat_backend.get_object("cmp-bkt", "c.bin").await.unwrap();
    let (_, s2) = seg_backend.get_object("cmp-bkt", "c.bin").await.unwrap();
    assert_eq!(read_stream_to_end(s1).await, read_stream_to_end(s2).await);
}

#[tokio::test]
async fn test_segmented_delete_releases_segment_dir() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("segdel-bkt").await.unwrap();
    let parts_data = segmented_parts();
    let (upload_id, _) = seed_segmented_object(&backend, "segdel-bkt", "d.bin", &parts_data).await;
    let seg_dir = backend.segments_bucket_root("segdel-bkt").join(&upload_id);
    assert!(seg_dir.is_dir());
    backend.delete_object("segdel-bkt", "d.bin").await.unwrap();
    assert!(!seg_dir.exists());
}

#[tokio::test]
async fn test_segmented_overwrite_releases_old_segment_dir() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("segow-bkt").await.unwrap();
    let parts_data = segmented_parts();
    let (upload_id, _) = seed_segmented_object(&backend, "segow-bkt", "o.bin", &parts_data).await;
    let seg_dir = backend.segments_bucket_root("segow-bkt").join(&upload_id);
    assert!(seg_dir.is_dir());

    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"tiny".to_vec()));
    backend
        .put_object("segow-bkt", "o.bin", data, None)
        .await
        .unwrap();
    assert!(!seg_dir.exists());
    let (_, stream) = backend.get_object("segow-bkt", "o.bin").await.unwrap();
    assert_eq!(read_stream_to_end(stream).await, b"tiny");
}

#[tokio::test]
async fn test_segmented_versioned_overwrite_and_restore() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("segver-bkt").await.unwrap();
    backend.set_versioning("segver-bkt", true).await.unwrap();
    let parts_data = segmented_parts();
    let full: Vec<u8> = parts_data.concat();
    let (upload_id, obj) =
        seed_segmented_object(&backend, "segver-bkt", "vv.bin", &parts_data).await;
    let v1 = obj.version_id.clone().expect("versioned complete");
    let seg_dir = backend.segments_bucket_root("segver-bkt").join(&upload_id);

    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"second".to_vec()));
    backend
        .put_object("segver-bkt", "vv.bin", data, None)
        .await
        .unwrap();
    assert!(
        seg_dir.is_dir(),
        "versioned overwrite must transfer segment ownership, not delete"
    );

    let (_, data_path) = backend.version_record_paths("segver-bkt", "vv.bin", &v1);
    let header = crate::segments::read_stub_header(&data_path)
        .unwrap()
        .expect("archived version must be a stub");
    assert_eq!(header.total, full.len() as u64);
    assert_eq!(
        std::fs::metadata(&data_path).unwrap().len(),
        full.len() as u64
    );

    let (vmeta, vstream) = backend
        .get_object_version("segver-bkt", "vv.bin", &v1)
        .await
        .unwrap();
    assert_eq!(vmeta.size, full.len() as u64);
    assert_eq!(read_stream_to_end(vstream).await, full);

    let (_, vrange) = backend
        .get_object_version_range("segver-bkt", "vv.bin", &v1, 4999, Some(2))
        .await
        .unwrap();
    assert_eq!(read_stream_to_end(vrange).await, &full[4999..5001]);

    let live_meta = backend
        .get_object_metadata("segver-bkt", "vv.bin")
        .await
        .unwrap();
    let v2 = live_meta.get("__version_id__").cloned().unwrap();
    backend
        .delete_object_version("segver-bkt", "vv.bin", &v2)
        .await
        .unwrap();
    let (_, stream) = backend.get_object("segver-bkt", "vv.bin").await.unwrap();
    assert_eq!(
        read_stream_to_end(stream).await,
        full,
        "promoted segmented version must serve original bytes"
    );
    assert!(seg_dir.is_dir());

    backend
        .delete_object_version("segver-bkt", "vv.bin", &v1)
        .await
        .unwrap();
    assert!(
        !seg_dir.exists(),
        "deleting the last owner must release segments"
    );
}

#[tokio::test]
async fn test_segmented_copy_object_hard_links_new_segment_set() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("segcp-bkt").await.unwrap();
    let parts_data = segmented_parts();
    let full: Vec<u8> = parts_data.concat();
    let (source_segment_id, source_meta) =
        seed_segmented_object(&backend, "segcp-bkt", "src.bin", &parts_data).await;

    let copied = backend
        .copy_object("segcp-bkt", "src.bin", "segcp-bkt", "dst.bin")
        .await
        .unwrap();
    assert_eq!(copied.size, full.len() as u64);
    assert_eq!(copied.etag, source_meta.etag);

    let dst_meta = backend
        .get_object_metadata("segcp-bkt", "dst.bin")
        .await
        .unwrap();
    let destination_segment_id = dst_meta
        .get(crate::segments::META_KEY_SEGMENTS)
        .expect("copied object must own a segment set");
    assert_ne!(destination_segment_id, &source_segment_id);
    assert_eq!(
        parse_part_sizes(dst_meta.get(META_KEY_PART_SIZES).unwrap()).unwrap(),
        parts_data
            .iter()
            .map(|part| part.len() as u64)
            .collect::<Vec<_>>()
    );

    let source_segment = backend
        .segments_bucket_root("segcp-bkt")
        .join(&source_segment_id)
        .join(crate::segments::SegmentSet::seg_file_name(0));
    let destination_segment = backend
        .segments_bucket_root("segcp-bkt")
        .join(destination_segment_id)
        .join(crate::segments::SegmentSet::seg_file_name(0));
    let mut changed = parts_data[0].clone();
    changed[0] ^= 0xff;
    std::fs::write(&source_segment, &changed).unwrap();
    assert_eq!(std::fs::read(&destination_segment).unwrap(), changed);
    std::fs::write(&source_segment, &parts_data[0]).unwrap();

    let (_, stream) = backend.get_object("segcp-bkt", "dst.bin").await.unwrap();
    assert_eq!(read_stream_to_end(stream).await, full);

    let dst_path = backend.object_path("segcp-bkt", "dst.bin").unwrap();
    let header = crate::segments::read_stub_header(&dst_path)
        .unwrap()
        .expect("destination must be a segment stub");
    assert_eq!(header.segment_id, destination_segment_id.as_str());
    assert_eq!(header.etag, copied.etag.unwrap());
}

#[tokio::test]
async fn test_segmented_upload_part_copy_across_boundary() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("segpc-bkt").await.unwrap();
    let parts_data = segmented_parts();
    let full: Vec<u8> = parts_data.concat();
    seed_segmented_object(&backend, "segpc-bkt", "src.bin", &parts_data).await;

    let upload_id = backend
        .initiate_multipart("segpc-bkt", "dst.bin", None)
        .await
        .unwrap();
    backend
        .upload_part_copy(
            "segpc-bkt",
            &upload_id,
            1,
            "segpc-bkt",
            "src.bin",
            None,
            Some((4000, 6999)),
        )
        .await
        .unwrap();
    let part_path = backend
        .get_multipart_part_path("segpc-bkt", &upload_id, 1)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&part_path).unwrap(), &full[4000..7000]);
    backend
        .abort_multipart("segpc-bkt", &upload_id)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_segmented_materialize_to_tmp() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("segmat-bkt").await.unwrap();
    let parts_data = segmented_parts();
    let full: Vec<u8> = parts_data.concat();
    seed_segmented_object(&backend, "segmat-bkt", "m.bin", &parts_data).await;

    let tmp = backend
        .materialize_object_to_tmp("segmat-bkt", "m.bin")
        .await
        .unwrap();
    assert_eq!(std::fs::read(&tmp).unwrap(), full);
    let _ = std::fs::remove_file(&tmp);
}

#[tokio::test]
async fn test_small_multipart_falls_back_to_concat() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("segsm-bkt").await.unwrap();
    let parts_data = vec![vec![b'A'; 1024], vec![b'B'; 512]];
    seed_segmented_object(&backend, "segsm-bkt", "s.bin", &parts_data).await;
    let stored = backend
        .get_object_metadata("segsm-bkt", "s.bin")
        .await
        .unwrap();
    assert!(!stored.contains_key(crate::segments::META_KEY_SEGMENTS));
    let (_, stream) = backend.get_object("segsm-bkt", "s.bin").await.unwrap();
    assert_eq!(read_stream_to_end(stream).await, parts_data.concat());
}

#[tokio::test]
async fn test_multipart_upload() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("test-bucket").await.unwrap();

    let upload_id = backend
        .initiate_multipart("test-bucket", "big-file.bin", None)
        .await
        .unwrap();

    let part1: AsyncReadStream = Box::pin(std::io::Cursor::new(b"part1-data".to_vec()));
    let etag1 = backend
        .upload_part("test-bucket", &upload_id, 1, part1)
        .await
        .unwrap();

    let part2: AsyncReadStream = Box::pin(std::io::Cursor::new(b"part2-data".to_vec()));
    let etag2 = backend
        .upload_part("test-bucket", &upload_id, 2, part2)
        .await
        .unwrap();

    let parts = vec![
        PartInfo {
            part_number: 1,
            etag: etag1,
        },
        PartInfo {
            part_number: 2,
            etag: etag2,
        },
    ];

    let result = backend
        .complete_multipart("test-bucket", &upload_id, &parts)
        .await
        .unwrap();
    assert_eq!(result.size, 20);

    let (_, mut stream) = backend
        .get_object("test-bucket", "big-file.bin")
        .await
        .unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    assert_eq!(buf, b"part1-datapart2-data");
}
