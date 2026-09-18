use super::*;

#[tokio::test]
async fn abort_multipart_rejects_traversal_upload_id() {
    let (dir, backend) = create_test_backend();
    backend.create_bucket("victim").await.unwrap();

    let config_dir = dir.path().join(".myfsio.sys").join("config");
    std::fs::create_dir_all(&config_dir).unwrap();
    let sentinel = config_dir.join("iam.json");
    std::fs::write(&sentinel, b"{}").unwrap();

    let result = backend.abort_multipart("victim", "../../config").await;

    assert!(result.is_err());
    assert!(config_dir.exists());
    assert!(sentinel.exists());
}

#[tokio::test]
async fn abort_multipart_accepts_generated_upload_id() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("uploads").await.unwrap();
    let upload_id = backend
        .initiate_multipart("uploads", "object.txt", None)
        .await
        .unwrap();

    backend
        .abort_multipart("uploads", &upload_id)
        .await
        .unwrap();

    assert!(backend.list_parts("uploads", &upload_id).await.is_err());
}

#[tokio::test]
async fn failed_commit_restores_metadata_and_keeps_archived_null_version() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("commit-rollback").await.unwrap();
    backend
        .set_versioning_status("commit-rollback", VersioningStatus::Suspended)
        .await
        .unwrap();

    block_object_destination(&backend, "commit-rollback", "blocked.bin");

    let mut previous = HashMap::new();
    previous.insert("__etag__".to_string(), "oldetag".to_string());
    previous.insert("__size__".to_string(), "3".to_string());
    previous.insert("__version_id__".to_string(), "null".to_string());
    backend
        .put_object_metadata("commit-rollback", "blocked.bin", &previous)
        .await
        .unwrap();

    let version_dir = backend.version_dir("commit-rollback", "blocked.bin");
    std::fs::create_dir_all(&version_dir).unwrap();
    let null_manifest = version_dir.join("null.json");
    let null_data = version_dir.join("null.bin");
    std::fs::write(&null_data, b"old").unwrap();
    std::fs::write(
        &null_manifest,
        serde_json::json!({
            "version_id": "null",
            "key": "blocked.bin",
            "size": 3,
            "archived_at": Utc::now().to_rfc3339(),
            "etag": "oldetag",
            "metadata": previous,
        })
        .to_string(),
    )
    .unwrap();

    let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(b"replacement".to_vec()));
    let result = backend
        .put_object("commit-rollback", "blocked.bin", stream, None)
        .await;
    assert!(result.is_err(), "a failed rename must fail the commit");

    let restored = backend
        .get_object_metadata("commit-rollback", "blocked.bin")
        .await
        .unwrap();
    assert_eq!(restored.get("__etag__"), Some(&"oldetag".to_string()));
    assert_eq!(restored.get("__size__"), Some(&"3".to_string()));
    assert!(
        null_manifest.is_file() && null_data.is_file(),
        "the archived null version must survive a failed commit"
    );
}

#[tokio::test]
async fn failed_commit_before_rename_undoes_the_archived_version() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("commit-archive").await.unwrap();
    backend
        .set_versioning_status("commit-archive", VersioningStatus::Enabled)
        .await
        .unwrap();
    put_listing_object(&backend, "commit-archive", "obj.bin", b"v1").await;

    let before = backend
        .get_object_metadata("commit-archive", "obj.bin")
        .await
        .unwrap();
    let missing_tmp = backend.tmp_dir().join("does-not-exist.tmp");
    let result = backend.finalize_put_sync(
        "commit-archive",
        "obj.bin",
        &missing_tmp,
        "deadbeef".to_string(),
        2,
        None,
        &crate::traits::PutCommitOptions::default(),
    );
    assert!(
        result.is_err(),
        "a missing staged file must fail the commit"
    );

    assert!(
        backend
            .list_object_versions("commit-archive", "obj.bin")
            .await
            .unwrap()
            .is_empty(),
        "the archived version must be undone when the commit aborts before the rename"
    );
    let after = backend
        .get_object_metadata("commit-archive", "obj.bin")
        .await
        .unwrap();
    assert_eq!(after.get("__etag__"), before.get("__etag__"));
    assert_eq!(after.get("__version_id__"), before.get("__version_id__"));

    let (_, mut stream) = backend
        .get_object("commit-archive", "obj.bin")
        .await
        .unwrap();
    let mut body = Vec::new();
    stream.read_to_end(&mut body).await.unwrap();
    assert_eq!(body, b"v1");
}

#[tokio::test]
async fn metadata_publish_is_the_commit_point_for_puts() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("commit-order").await.unwrap();
    put_listing_object(&backend, "commit-order", "obj.bin", b"v1").await;
    let before = backend
        .get_object_metadata("commit-order", "obj.bin")
        .await
        .unwrap();

    let mut new_meta = HashMap::new();
    new_meta.insert("__etag__".to_string(), "newetag".to_string());
    new_meta.insert("__size__".to_string(), "2".to_string());
    let staged = backend
        .stage_live_metadata_sync("commit-order", "obj.bin", &new_meta, None)
        .unwrap();

    let next_tmp = backend.tmp_dir().join("next.tmp");
    std::fs::write(&next_tmp, b"v2").unwrap();
    let destination = backend.object_live_path("commit-order", "obj.bin");
    std::fs::rename(&next_tmp, &destination).unwrap();

    let mid = backend
        .get_object_metadata("commit-order", "obj.bin")
        .await
        .unwrap();
    assert_eq!(
        mid.get("__etag__"),
        before.get("__etag__"),
        "readers must keep seeing the previous metadata until the sidecar is published"
    );

    backend
        .publish_staged_metadata_sync("commit-order", "obj.bin", &staged)
        .unwrap();
    let after = backend
        .get_object_metadata("commit-order", "obj.bin")
        .await
        .unwrap();
    assert_eq!(after.get("__etag__"), Some(&"newetag".to_string()));
    assert!(!staged.exists());
}

#[tokio::test]
async fn successful_put_leaves_no_staged_sidecar_files() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("stage-clean").await.unwrap();
    put_listing_object(&backend, "stage-clean", "obj.bin", b"data").await;

    let (sidecar_path, _) = backend.sidecar_file_for_key("stage-clean", "obj.bin");
    assert!(sidecar_path.is_file(), "the sidecar must be published");

    let strays: Vec<_> = std::fs::read_dir(backend.tmp_dir())
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with(".sidecar-stage"))
        .collect();
    assert!(
        strays.is_empty(),
        "no staged sidecar files may remain after a successful put"
    );
}

#[tokio::test]
async fn storage_full_put_fsops_preserve_previous_object_and_retry() {
    let _fp = failpoint_test_guard();
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("enospc-put").await.unwrap();
    put_listing_object(&backend, "enospc-put", "obj.bin", b"old").await;
    assert_eq!(listed_keys(&backend, "enospc-put").await, ["obj.bin"]);

    for name in [
        "put:stage-data-write",
        "put:stage-data-sync",
        "put:stage-sidecar",
        "put:stage-dir-fsync",
        "put:before-data-rename",
    ] {
        crate::failpoints::set(
            &backend.root,
            name,
            crate::failpoints::FailAction::Error(std::io::ErrorKind::StorageFull),
        );
        let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(b"new".to_vec()));
        let result = backend
            .put_object("enospc-put", "obj.bin", stream, None)
            .await;
        crate::failpoints::clear(&backend.root, name);
        assert_storage_full(result);
        assert_eq!(
            object_bytes(&backend, "enospc-put", "obj.bin").await,
            b"old"
        );
        assert_eq!(listed_keys(&backend, "enospc-put").await, ["obj.bin"]);
        assert_eq!(staged_sidecar_count(&backend), 0);
        assert_eq!(ordinary_tmp_count(&backend), 0);

        let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(b"new".to_vec()));
        backend
            .put_object("enospc-put", "obj.bin", stream, None)
            .await
            .unwrap();
        assert_eq!(
            object_bytes(&backend, "enospc-put", "obj.bin").await,
            b"new"
        );
        let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(b"old".to_vec()));
        backend
            .put_object("enospc-put", "obj.bin", stream, None)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn storage_full_version_archive_preserves_live_version_and_retry() {
    let _fp = failpoint_test_guard();
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("enospc-version").await.unwrap();
    backend
        .set_versioning_status("enospc-version", VersioningStatus::Enabled)
        .await
        .unwrap();
    put_listing_object(&backend, "enospc-version", "obj.bin", b"old-version").await;
    let before = backend
        .get_object_metadata("enospc-version", "obj.bin")
        .await
        .unwrap();

    crate::failpoints::set(
        &backend.root,
        "version:archive-write",
        crate::failpoints::FailAction::Error(std::io::ErrorKind::StorageFull),
    );
    let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(b"new-version".to_vec()));
    let result = backend
        .put_object("enospc-version", "obj.bin", stream, None)
        .await;
    crate::failpoints::clear(&backend.root, "version:archive-write");
    assert_storage_full(result);
    assert_eq!(
        object_bytes(&backend, "enospc-version", "obj.bin").await,
        b"old-version"
    );
    let after = backend
        .get_object_metadata("enospc-version", "obj.bin")
        .await
        .unwrap();
    assert_eq!(after.get("__version_id__"), before.get("__version_id__"));
    assert_eq!(
        backend
            .list_object_versions("enospc-version", "obj.bin")
            .await
            .unwrap()
            .len(),
        0
    );

    let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(b"new-version".to_vec()));
    backend
        .put_object("enospc-version", "obj.bin", stream, None)
        .await
        .unwrap();
    assert_eq!(
        object_bytes(&backend, "enospc-version", "obj.bin").await,
        b"new-version"
    );
}

#[tokio::test]
async fn storage_full_delete_fsops_preserve_object_listing_and_retry() {
    let _fp = failpoint_test_guard();
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("enospc-delete").await.unwrap();

    for name in ["delete:data-remove", "delete:metadata-remove"] {
        put_listing_object(&backend, "enospc-delete", "obj.bin", b"old").await;
        assert_eq!(listed_keys(&backend, "enospc-delete").await, ["obj.bin"]);
        crate::failpoints::set(
            &backend.root,
            name,
            crate::failpoints::FailAction::Error(std::io::ErrorKind::StorageFull),
        );
        let result = backend.delete_object("enospc-delete", "obj.bin").await;
        crate::failpoints::clear(&backend.root, name);
        assert_storage_full(result);
        assert_eq!(
            object_bytes(&backend, "enospc-delete", "obj.bin").await,
            b"old"
        );
        assert_eq!(listed_keys(&backend, "enospc-delete").await, ["obj.bin"]);
        backend
            .delete_object("enospc-delete", "obj.bin")
            .await
            .unwrap();
        assert!(listed_keys(&backend, "enospc-delete").await.is_empty());
    }
}

#[tokio::test]
async fn storage_full_metadata_rewrite_preserves_metadata_and_retry() {
    let _fp = failpoint_test_guard();
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("enospc-meta").await.unwrap();
    let mut original = HashMap::new();
    original.insert("color".to_string(), "blue".to_string());
    let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(b"body".to_vec()));
    backend
        .put_object("enospc-meta", "obj.bin", stream, Some(original.clone()))
        .await
        .unwrap();

    let mut replacement = original.clone();
    replacement.insert("color".to_string(), "green".to_string());
    crate::failpoints::set(
        &backend.root,
        "metadata:rewrite",
        crate::failpoints::FailAction::Error(std::io::ErrorKind::StorageFull),
    );
    let result = backend
        .put_object_metadata("enospc-meta", "obj.bin", &replacement)
        .await;
    crate::failpoints::clear(&backend.root, "metadata:rewrite");
    assert_storage_full(result);
    let after = backend
        .get_object_metadata("enospc-meta", "obj.bin")
        .await
        .unwrap();
    assert_eq!(after.get("color").map(String::as_str), Some("blue"));
    assert_eq!(
        object_bytes(&backend, "enospc-meta", "obj.bin").await,
        b"body"
    );
    assert_eq!(listed_keys(&backend, "enospc-meta").await, ["obj.bin"]);

    backend
        .put_object_metadata("enospc-meta", "obj.bin", &replacement)
        .await
        .unwrap();
    let after = backend
        .get_object_metadata("enospc-meta", "obj.bin")
        .await
        .unwrap();
    assert_eq!(after.get("color").map(String::as_str), Some("green"));
}

#[tokio::test]
async fn storage_full_version_metadata_rewrite_preserves_record_and_retry() {
    let _fp = failpoint_test_guard();
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("enospc-version-meta").await.unwrap();
    backend
        .set_versioning_status("enospc-version-meta", VersioningStatus::Enabled)
        .await
        .unwrap();
    let mut original = HashMap::new();
    original.insert("color".to_string(), "blue".to_string());
    let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(b"old".to_vec()));
    backend
        .put_object(
            "enospc-version-meta",
            "obj.bin",
            stream,
            Some(original.clone()),
        )
        .await
        .unwrap();
    put_listing_object(&backend, "enospc-version-meta", "obj.bin", b"new").await;
    let archived = backend
        .list_object_versions("enospc-version-meta", "obj.bin")
        .await
        .unwrap()
        .into_iter()
        .find(|version| !version.is_latest)
        .unwrap();
    let mut replacement = original.clone();
    replacement.insert("color".to_string(), "green".to_string());

    crate::failpoints::set(
        &backend.root,
        "metadata:version-rewrite",
        crate::failpoints::FailAction::Error(std::io::ErrorKind::StorageFull),
    );
    let result = backend
        .put_object_version_metadata(
            "enospc-version-meta",
            "obj.bin",
            &archived.version_id,
            &replacement,
        )
        .await;
    crate::failpoints::clear(&backend.root, "metadata:version-rewrite");
    assert_storage_full(result);
    let after = backend
        .get_object_version_metadata("enospc-version-meta", "obj.bin", &archived.version_id)
        .await
        .unwrap();
    assert_eq!(after.get("color").map(String::as_str), Some("blue"));
    let (_, mut stream) = backend
        .get_object_version("enospc-version-meta", "obj.bin", &archived.version_id)
        .await
        .unwrap();
    let mut body = Vec::new();
    stream.read_to_end(&mut body).await.unwrap();
    assert_eq!(body, b"old");

    backend
        .put_object_version_metadata(
            "enospc-version-meta",
            "obj.bin",
            &archived.version_id,
            &replacement,
        )
        .await
        .unwrap();
    let after = backend
        .get_object_version_metadata("enospc-version-meta", "obj.bin", &archived.version_id)
        .await
        .unwrap();
    assert_eq!(after.get("color").map(String::as_str), Some("green"));
}

#[tokio::test]
async fn storage_full_bucket_config_write_preserves_config_and_retry() {
    let _fp = failpoint_test_guard();
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("enospc-config").await.unwrap();
    crate::failpoints::set(
        &backend.root,
        "bucket:config-write",
        crate::failpoints::FailAction::Error(std::io::ErrorKind::StorageFull),
    );
    let result = backend
        .set_versioning_status("enospc-config", VersioningStatus::Enabled)
        .await;
    crate::failpoints::clear(&backend.root, "bucket:config-write");
    assert_storage_full(result);
    assert_eq!(
        backend
            .get_versioning_status("enospc-config")
            .await
            .unwrap(),
        VersioningStatus::Disabled
    );

    backend
        .set_versioning_status("enospc-config", VersioningStatus::Enabled)
        .await
        .unwrap();
    assert_eq!(
        backend
            .get_versioning_status("enospc-config")
            .await
            .unwrap(),
        VersioningStatus::Enabled
    );
}

#[tokio::test]
async fn storage_full_version_delete_preserves_archived_version_and_retry() {
    let _fp = failpoint_test_guard();
    let (_dir, backend) = create_test_backend();
    backend
        .create_bucket("enospc-version-delete")
        .await
        .unwrap();
    backend
        .set_versioning_status("enospc-version-delete", VersioningStatus::Enabled)
        .await
        .unwrap();

    for (index, name) in [
        "delete-version:data-remove",
        "delete-version:metadata-remove",
    ]
    .into_iter()
    .enumerate()
    {
        let key = format!("obj-{index}.bin");
        put_listing_object(&backend, "enospc-version-delete", &key, b"old").await;
        put_listing_object(&backend, "enospc-version-delete", &key, b"new").await;
        let archived = backend
            .list_object_versions("enospc-version-delete", &key)
            .await
            .unwrap()
            .into_iter()
            .find(|version| !version.is_latest)
            .unwrap();
        crate::failpoints::set(
            &backend.root,
            name,
            crate::failpoints::FailAction::Error(std::io::ErrorKind::StorageFull),
        );
        let result = backend
            .delete_object_version_checked(
                "enospc-version-delete",
                &key,
                &archived.version_id,
                false,
            )
            .await;
        crate::failpoints::clear(&backend.root, name);
        assert_storage_full(result);
        let (_, mut stream) = backend
            .get_object_version("enospc-version-delete", &key, &archived.version_id)
            .await
            .unwrap();
        let mut body = Vec::new();
        stream.read_to_end(&mut body).await.unwrap();
        assert_eq!(body, b"old");
        assert_eq!(
            object_bytes(&backend, "enospc-version-delete", &key).await,
            b"new"
        );

        backend
            .delete_object_version_checked(
                "enospc-version-delete",
                &key,
                &archived.version_id,
                false,
            )
            .await
            .unwrap();
        assert!(matches!(
            backend
                .get_object_version("enospc-version-delete", &key, &archived.version_id,)
                .await,
            Err(StorageError::VersionNotFound { .. })
        ));
    }
}

#[tokio::test]
async fn storage_full_delete_marker_preserves_live_version_and_retry() {
    let _fp = failpoint_test_guard();
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("enospc-marker").await.unwrap();
    backend
        .set_versioning_status("enospc-marker", VersioningStatus::Enabled)
        .await
        .unwrap();
    put_listing_object(&backend, "enospc-marker", "obj.bin", b"old").await;

    crate::failpoints::set(
        &backend.root,
        "delete:marker-write",
        crate::failpoints::FailAction::Error(std::io::ErrorKind::StorageFull),
    );
    let result = backend.delete_object("enospc-marker", "obj.bin").await;
    crate::failpoints::clear(&backend.root, "delete:marker-write");
    assert_storage_full(result);
    assert_eq!(
        object_bytes(&backend, "enospc-marker", "obj.bin").await,
        b"old"
    );
    assert_eq!(listed_keys(&backend, "enospc-marker").await, ["obj.bin"]);

    backend
        .delete_object("enospc-marker", "obj.bin")
        .await
        .unwrap();
    assert!(matches!(
        backend.get_object("enospc-marker", "obj.bin").await,
        Err(StorageError::DeleteMarker { .. })
    ));
}

#[tokio::test]
async fn storage_full_listing_index_degrades_to_rebuild_without_phantoms() {
    let _fp = failpoint_test_guard();
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("enospc-listing").await.unwrap();
    put_listing_object(&backend, "enospc-listing", "old.bin", b"old").await;

    crate::failpoints::set(
        &backend.root,
        "listing:snapshot-write",
        crate::failpoints::FailAction::Error(std::io::ErrorKind::StorageFull),
    );
    let result = backend.rebuild_listing_index_sync("enospc-listing");
    crate::failpoints::clear(&backend.root, "listing:snapshot-write");
    assert_storage_full(result);
    assert_eq!(listed_keys(&backend, "enospc-listing").await, ["old.bin"]);

    let listing_dir = backend.bucket_listing_dir("enospc-listing");
    assert!(listing_dir.join("snapshot.json").is_file());
    crate::failpoints::set(
        &backend.root,
        "listing:journal-append",
        crate::failpoints::FailAction::Error(std::io::ErrorKind::StorageFull),
    );
    put_listing_object(&backend, "enospc-listing", "new.bin", b"new").await;
    crate::failpoints::clear(&backend.root, "listing:journal-append");
    let mut keys = listed_keys(&backend, "enospc-listing").await;
    keys.sort();
    assert_eq!(keys, ["new.bin", "old.bin"]);
    assert_eq!(
        object_bytes(&backend, "enospc-listing", "old.bin").await,
        b"old"
    );
    assert_eq!(
        object_bytes(&backend, "enospc-listing", "new.bin").await,
        b"new"
    );

    put_listing_object(&backend, "enospc-listing", "new.bin", b"new").await;
    assert_eq!(listed_keys(&backend, "enospc-listing").await.len(), 2);
}

#[tokio::test]
async fn injected_error_during_sidecar_stage_aborts_the_put_cleanly() {
    let _fp = failpoint_test_guard();
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("fp-stage").await.unwrap();
    put_listing_object(&backend, "fp-stage", "obj.bin", b"v1").await;
    let before = backend
        .get_object_metadata("fp-stage", "obj.bin")
        .await
        .unwrap();

    crate::failpoints::set(
        &backend.root,
        "put:stage-sidecar",
        crate::failpoints::FailAction::Error(std::io::ErrorKind::StorageFull),
    );
    let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(b"v2".to_vec()));
    let result = backend
        .put_object("fp-stage", "obj.bin", stream, None)
        .await;
    crate::failpoints::clear(&backend.root, "put:stage-sidecar");
    assert!(result.is_err(), "a failed sidecar stage must fail the put");

    let after = backend
        .get_object_metadata("fp-stage", "obj.bin")
        .await
        .unwrap();
    assert_eq!(after.get("__etag__"), before.get("__etag__"));
    let (_, mut stream) = backend.get_object("fp-stage", "obj.bin").await.unwrap();
    let mut body = Vec::new();
    stream.read_to_end(&mut body).await.unwrap();
    assert_eq!(body, b"v1");
    assert_eq!(staged_sidecar_count(&backend), 0);
}

#[tokio::test]
async fn crash_before_data_rename_leaves_the_old_object_intact() {
    let _fp = failpoint_test_guard();
    let (_dir, backend) = create_test_backend();
    let backend = std::sync::Arc::new(backend);
    backend.create_bucket("fp-crash1").await.unwrap();
    put_listing_object(&backend, "fp-crash1", "obj.bin", b"v1").await;
    let before = backend
        .get_object_metadata("fp-crash1", "obj.bin")
        .await
        .unwrap();

    crate::failpoints::set(
        &backend.root,
        "put:before-data-rename",
        crate::failpoints::FailAction::Panic,
    );
    let crashed = backend.clone();
    let join = tokio::spawn(async move {
        let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(b"v2".to_vec()));
        crashed
            .put_object("fp-crash1", "obj.bin", stream, None)
            .await
    })
    .await;
    crate::failpoints::clear(&backend.root, "put:before-data-rename");
    assert!(
        join.unwrap_err().is_panic(),
        "the failpoint must simulate a crash"
    );

    let after = backend
        .get_object_metadata("fp-crash1", "obj.bin")
        .await
        .unwrap();
    assert_eq!(after.get("__etag__"), before.get("__etag__"));
    let (_, mut stream) = backend.get_object("fp-crash1", "obj.bin").await.unwrap();
    let mut body = Vec::new();
    stream.read_to_end(&mut body).await.unwrap();
    assert_eq!(
        body, b"v1",
        "a crash before the data rename must not change the object"
    );

    let recovery = backend.recover_staged_commits_sync().unwrap();
    assert_eq!(
        recovery.discarded, 1,
        "recovery must discard the staged sidecar because the data was never renamed"
    );
    assert!(recovery.published.is_empty());
    assert_eq!(staged_sidecar_count(&backend), 0);
    let after_recovery = backend
        .get_object_metadata("fp-crash1", "obj.bin")
        .await
        .unwrap();
    assert_eq!(after_recovery.get("__etag__"), before.get("__etag__"));
}

#[tokio::test]
async fn crash_before_sidecar_publish_is_repaired_by_commit_recovery() {
    let _fp = failpoint_test_guard();
    let (_dir, backend) = create_test_backend();
    let backend = std::sync::Arc::new(backend);
    backend.create_bucket("fp-crash2").await.unwrap();
    put_listing_object(&backend, "fp-crash2", "obj.bin", b"v1").await;
    let before = backend
        .get_object_metadata("fp-crash2", "obj.bin")
        .await
        .unwrap();

    crate::failpoints::set(
        &backend.root,
        "put:before-publish-sidecar",
        crate::failpoints::FailAction::Panic,
    );
    let crashed = backend.clone();
    let join = tokio::spawn(async move {
        let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(b"v2".to_vec()));
        crashed
            .put_object("fp-crash2", "obj.bin", stream, None)
            .await
    })
    .await;
    crate::failpoints::clear(&backend.root, "put:before-publish-sidecar");
    assert!(
        join.unwrap_err().is_panic(),
        "the failpoint must simulate a crash"
    );

    let after = backend
        .get_object_metadata("fp-crash2", "obj.bin")
        .await
        .unwrap();
    assert_eq!(
        after.get("__etag__"),
        before.get("__etag__"),
        "the previous sidecar must still be authoritative"
    );
    let (_, mut stream) = backend.get_object("fp-crash2", "obj.bin").await.unwrap();
    let mut body = Vec::new();
    stream.read_to_end(&mut body).await.unwrap();
    assert_eq!(
        body, b"v2",
        "the committed data rename survives the crash; the torn state is new data \
         under the previous metadata, detectable as an etag mismatch"
    );
    assert_eq!(
        staged_sidecar_count(&backend),
        1,
        "the staged sidecar must survive the crash as the commit intent record"
    );

    let recovery = backend.recover_staged_commits_sync().unwrap();
    assert_eq!(
        recovery.published.len(),
        1,
        "recovery must publish the staged sidecar for data that was already renamed"
    );
    assert_eq!(recovery.poisoned, 0);
    assert_eq!(
        staged_sidecar_count(&backend),
        1,
        "the commit intent must survive until replication has been enqueued"
    );
    backend
        .finish_recovered_commit_sync(&recovery.published[0].staged_path)
        .unwrap();
    assert_eq!(staged_sidecar_count(&backend), 0);
    let repaired = backend
        .get_object_metadata("fp-crash2", "obj.bin")
        .await
        .unwrap();
    assert_ne!(
        repaired.get("__etag__"),
        before.get("__etag__"),
        "the recovered metadata must describe the new bytes"
    );
    let (_, mut stream) = backend.get_object("fp-crash2", "obj.bin").await.unwrap();
    let mut body = Vec::new();
    stream.read_to_end(&mut body).await.unwrap();
    assert_eq!(body, b"v2");
}

#[tokio::test]
async fn crash_mid_delete_leaves_a_detectable_ghost() {
    let _fp = failpoint_test_guard();
    let (_dir, backend) = create_test_backend();
    let backend = std::sync::Arc::new(backend);
    backend.create_bucket("fp-del").await.unwrap();
    put_listing_object(&backend, "fp-del", "obj.bin", b"v1").await;

    crate::failpoints::set(
        &backend.root,
        "delete:before-meta-remove",
        crate::failpoints::FailAction::Panic,
    );
    let crashed = backend.clone();
    let join = tokio::spawn(async move { crashed.delete_object("fp-del", "obj.bin").await }).await;
    crate::failpoints::clear(&backend.root, "delete:before-meta-remove");
    assert!(join.unwrap_err().is_panic());

    let meta = backend
        .get_object_metadata("fp-del", "obj.bin")
        .await
        .unwrap();
    assert!(
        meta.contains_key("__etag__"),
        "the sidecar must survive so the half-deleted object fails loudly"
    );
    assert!(
        backend.get_object("fp-del", "obj.bin").await.is_err(),
        "the data is gone; the ghost must error on read, not serve garbage"
    );

    backend.delete_object("fp-del", "obj.bin").await.unwrap();
    let cleaned = backend.get_object_metadata("fp-del", "obj.bin").await;
    assert!(
        cleaned.map(|m| !m.contains_key("__etag__")).unwrap_or(true),
        "a repeated delete must clear the ghost's sidecar"
    );
}

#[tokio::test]
async fn injected_stage_dir_fsync_failure_aborts_the_put_cleanly() {
    let _fp = failpoint_test_guard();
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("fp-stagedir").await.unwrap();
    put_listing_object(&backend, "fp-stagedir", "obj.bin", b"v1").await;
    let before = backend
        .get_object_metadata("fp-stagedir", "obj.bin")
        .await
        .unwrap();

    crate::failpoints::set(
        &backend.root,
        "put:stage-dir-fsync",
        crate::failpoints::FailAction::Error(std::io::ErrorKind::StorageFull),
    );
    let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(b"v2".to_vec()));
    let result = backend
        .put_object("fp-stagedir", "obj.bin", stream, None)
        .await;
    crate::failpoints::clear(&backend.root, "put:stage-dir-fsync");
    assert!(
        result.is_err(),
        "a failed intent-directory fsync must fail the put before any data is renamed"
    );

    let after = backend
        .get_object_metadata("fp-stagedir", "obj.bin")
        .await
        .unwrap();
    assert_eq!(after.get("__etag__"), before.get("__etag__"));
    let (_, mut stream) = backend.get_object("fp-stagedir", "obj.bin").await.unwrap();
    let mut body = Vec::new();
    stream.read_to_end(&mut body).await.unwrap();
    assert_eq!(body, b"v1");
    assert_eq!(staged_sidecar_count(&backend), 0);
}

#[tokio::test]
async fn crash_after_version_archival_preserves_the_live_object() {
    let _fp = failpoint_test_guard();
    let (_dir, backend) = create_test_backend();
    let backend = std::sync::Arc::new(backend);
    backend.create_bucket("fp-arch").await.unwrap();
    backend
        .set_versioning_status("fp-arch", VersioningStatus::Enabled)
        .await
        .unwrap();
    put_listing_object(&backend, "fp-arch", "obj.bin", b"v1").await;
    let before = backend
        .get_object_metadata("fp-arch", "obj.bin")
        .await
        .unwrap();
    let original_vid = before.get("__version_id__").cloned().unwrap();

    crate::failpoints::set(
        &backend.root,
        "put:after-archive",
        crate::failpoints::FailAction::Panic,
    );
    let crashed = backend.clone();
    let join = tokio::spawn(async move {
        let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(b"v2".to_vec()));
        crashed.put_object("fp-arch", "obj.bin", stream, None).await
    })
    .await;
    crate::failpoints::clear(&backend.root, "put:after-archive");
    assert!(join.unwrap_err().is_panic());

    let after = backend
        .get_object_metadata("fp-arch", "obj.bin")
        .await
        .unwrap();
    assert_eq!(after.get("__version_id__"), Some(&original_vid));
    let (_, mut stream) = backend.get_object("fp-arch", "obj.bin").await.unwrap();
    let mut body = Vec::new();
    stream.read_to_end(&mut body).await.unwrap();
    assert_eq!(body, b"v1");
    for version in backend
        .list_object_versions("fp-arch", "obj.bin")
        .await
        .unwrap()
    {
        assert_eq!(
            version.version_id, original_vid,
            "a crash after archival must not surface a version id that was never committed"
        );
    }

    let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(b"v3".to_vec()));
    let committed = backend
        .put_object("fp-arch", "obj.bin", stream, None)
        .await
        .unwrap();
    assert_ne!(committed.version_id.as_deref(), Some(original_vid.as_str()));
    let (_, mut stream) = backend.get_object("fp-arch", "obj.bin").await.unwrap();
    let mut body = Vec::new();
    stream.read_to_end(&mut body).await.unwrap();
    assert_eq!(
        body, b"v3",
        "the next put after the crash must commit normally"
    );
}

#[tokio::test]
async fn failed_commit_leaves_no_metadata_for_a_new_key() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("commit-fresh").await.unwrap();
    block_object_destination(&backend, "commit-fresh", "fresh.bin");

    let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(b"payload".to_vec()));
    let result = backend
        .put_object("commit-fresh", "fresh.bin", stream, None)
        .await;
    assert!(result.is_err(), "a failed rename must fail the commit");

    let metadata = backend
        .get_object_metadata("commit-fresh", "fresh.bin")
        .await
        .unwrap();
    assert!(
        metadata.is_empty(),
        "a failed commit must not leave metadata describing bytes that never landed"
    );
}
