use super::*;

fn create_index_layout_backend() -> (tempfile::TempDir, FsStorageBackend) {
    let dir = tempfile::tempdir().unwrap();
    let backend = FsStorageBackend::new_with_config(
        dir.path().to_path_buf(),
        FsStorageBackendConfig {
            metadata_layout: MetadataLayout::Index,
            ..FsStorageBackendConfig::default()
        },
    );
    (dir, backend)
}

#[tokio::test]
async fn test_sidecar_layout_writes_sidecar_not_index() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("sc-bkt").await.unwrap();
    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"hello".to_vec()));
    backend
        .put_object("sc-bkt", "photos/cat.jpg", data, None)
        .await
        .unwrap();

    let meta_dir = backend.bucket_meta_root("sc-bkt").join("photos");
    let sidecar = meta_dir.join(FsStorageBackend::sidecar_file_name("cat.jpg"));
    assert!(sidecar.is_file(), "sidecar must exist at {:?}", sidecar);
    assert!(
        !meta_dir.join(INDEX_FILE).exists(),
        "_index.json must not be created by sidecar layout"
    );

    let stored = backend
        .get_object_metadata("sc-bkt", "photos/cat.jpg")
        .await
        .unwrap();
    assert!(stored.contains_key("__etag__"));

    let listing = backend
        .list_objects("sc-bkt", &ListParams::default())
        .await
        .unwrap();
    let entry = listing
        .objects
        .iter()
        .find(|o| o.key == "photos/cat.jpg")
        .expect("listed");
    assert!(entry.etag.is_some(), "listing must surface sidecar etag");
}

#[tokio::test]
async fn test_sidecar_shadows_stale_index_entry() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("shadow-bkt").await.unwrap();
    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"v1".to_vec()));
    backend
        .put_object("shadow-bkt", "a/k.txt", data, None)
        .await
        .unwrap();

    let index_path = backend
        .bucket_meta_root("shadow-bkt")
        .join("a")
        .join(INDEX_FILE);
    let stale = serde_json::json!({
        "k.txt": {"metadata": {"__etag__": "stale-etag", "stale": "yes"}}
    });
    std::fs::write(&index_path, serde_json::to_string(&stale).unwrap()).unwrap();
    backend.meta_read_cache.lock().clear();

    let stored = backend
        .get_object_metadata("shadow-bkt", "a/k.txt")
        .await
        .unwrap();
    assert_ne!(
        stored.get("__etag__").map(String::as_str),
        Some("stale-etag"),
        "sidecar must shadow stale index entry"
    );
    assert!(!stored.contains_key("stale"));
}

#[tokio::test]
async fn test_legacy_index_entry_still_readable_and_listed() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("legacy-bkt").await.unwrap();
    std::fs::write(backend.bucket_path("legacy-bkt").join("old.txt"), b"old").unwrap();
    let index_path = backend.bucket_meta_root("legacy-bkt").join(INDEX_FILE);
    std::fs::create_dir_all(index_path.parent().unwrap()).unwrap();
    let legacy = serde_json::json!({
        "old.txt": {"metadata": {"__etag__": "legacy-etag", "__size__": "3"}}
    });
    std::fs::write(&index_path, serde_json::to_string(&legacy).unwrap()).unwrap();

    let stored = backend
        .get_object_metadata("legacy-bkt", "old.txt")
        .await
        .unwrap();
    assert_eq!(
        stored.get("__etag__").map(String::as_str),
        Some("legacy-etag")
    );

    let listing = backend
        .list_objects("legacy-bkt", &ListParams::default())
        .await
        .unwrap();
    let entry = listing
        .objects
        .iter()
        .find(|o| o.key == "old.txt")
        .expect("listed");
    assert_eq!(entry.etag.as_deref(), Some("legacy-etag"));
}

#[tokio::test]
async fn test_corrupt_index_fails_closed_on_read() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("rot-bkt").await.unwrap();
    std::fs::write(backend.bucket_path("rot-bkt").join("f.txt"), b"data").unwrap();
    let index_path = backend.bucket_meta_root("rot-bkt").join(INDEX_FILE);
    std::fs::create_dir_all(index_path.parent().unwrap()).unwrap();
    std::fs::write(&index_path, b"{not valid json").unwrap();

    let stored = backend
        .get_object_metadata("rot-bkt", "f.txt")
        .await
        .unwrap();
    assert!(
        metadata_is_corrupted(&stored),
        "corrupt index must fail closed, got {:?}",
        stored
    );
    assert!(backend.get_object("rot-bkt", "f.txt").await.is_err());
    assert!(
        std::fs::read(&index_path).unwrap() == b"{not valid json",
        "corrupt index must never be rewritten"
    );
}

#[tokio::test]
async fn test_corrupt_sidecar_fails_closed_without_index_fallback() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("rot2-bkt").await.unwrap();
    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"body".to_vec()));
    backend
        .put_object("rot2-bkt", "x.txt", data, None)
        .await
        .unwrap();
    let sidecar = backend
        .bucket_meta_root("rot2-bkt")
        .join(FsStorageBackend::sidecar_file_name("x.txt"));
    std::fs::write(&sidecar, b"garbage").unwrap();
    let index_path = backend.bucket_meta_root("rot2-bkt").join(INDEX_FILE);
    let stale = serde_json::json!({
        "x.txt": {"metadata": {"__etag__": "stale"}}
    });
    std::fs::write(&index_path, serde_json::to_string(&stale).unwrap()).unwrap();
    backend.meta_read_cache.lock().clear();

    let stored = backend
        .get_object_metadata("rot2-bkt", "x.txt")
        .await
        .unwrap();
    assert!(
        metadata_is_corrupted(&stored),
        "corrupt sidecar must fail closed instead of serving stale index data"
    );
}

#[tokio::test]
async fn test_index_layout_write_fails_closed_on_corrupt_index() {
    let (_dir, backend) = create_index_layout_backend();
    backend.create_bucket("idx-bkt").await.unwrap();
    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"one".to_vec()));
    backend
        .put_object("idx-bkt", "keep.txt", data, None)
        .await
        .unwrap();
    let index_path = backend.bucket_meta_root("idx-bkt").join(INDEX_FILE);
    assert!(index_path.is_file(), "index layout must write _index.json");
    std::fs::write(&index_path, b"{broken").unwrap();

    let mut meta = HashMap::new();
    meta.insert("__etag__".to_string(), "abc".to_string());
    let err = backend
        .put_object_metadata("idx-bkt", "keep.txt", &meta)
        .await
        .expect_err("corrupt index must reject writes in index layout");
    drop(err);
    assert_eq!(
        std::fs::read(&index_path).unwrap(),
        b"{broken",
        "corrupt index must not be replaced by an empty map"
    );
}

#[tokio::test]
async fn test_delete_removes_sidecar() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("del-bkt").await.unwrap();
    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"z".to_vec()));
    backend
        .put_object("del-bkt", "gone.txt", data, None)
        .await
        .unwrap();
    let sidecar = backend
        .bucket_meta_root("del-bkt")
        .join(FsStorageBackend::sidecar_file_name("gone.txt"));
    assert!(sidecar.is_file());
    backend.delete_object("del-bkt", "gone.txt").await.unwrap();
    assert!(!sidecar.exists(), "delete must remove the sidecar");
    let stored = backend
        .get_object_metadata("del-bkt", "gone.txt")
        .await
        .unwrap();
    assert!(stored.is_empty());
}

#[tokio::test]
async fn test_long_entry_name_uses_hashed_sidecar() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("long-bkt").await.unwrap();
    let long_name = "l".repeat(240);
    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"long".to_vec()));
    backend
        .put_object("long-bkt", &long_name, data, None)
        .await
        .unwrap();

    let sidecar_name = FsStorageBackend::sidecar_file_name(&long_name);
    assert!(
        sidecar_name.len() <= SIDECAR_MAX_FILE_NAME_BYTES,
        "hashed sidecar name must stay within filesystem limits"
    );
    let sidecar = backend.bucket_meta_root("long-bkt").join(&sidecar_name);
    assert!(sidecar.is_file());

    let stored = backend
        .get_object_metadata("long-bkt", &long_name)
        .await
        .unwrap();
    assert!(stored.contains_key("__etag__"));

    let listing = backend
        .list_objects("long-bkt", &ListParams::default())
        .await
        .unwrap();
    let entry = listing
        .objects
        .iter()
        .find(|o| o.key == long_name)
        .expect("listed");
    assert!(
        entry.etag.is_some(),
        "hashed sidecar must resolve entry name from embedded field"
    );
}

#[tokio::test]
async fn test_migrate_meta_indexes_to_sidecars() {
    let dir = tempfile::tempdir().unwrap();
    let index_backend = FsStorageBackend::new_with_config(
        dir.path().to_path_buf(),
        FsStorageBackendConfig {
            metadata_layout: MetadataLayout::Index,
            ..FsStorageBackendConfig::default()
        },
    );
    index_backend.create_bucket("mig-bkt").await.unwrap();
    for key in ["a.txt", "sub/b.txt", "sub/c.txt"] {
        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"m".to_vec()));
        index_backend
            .put_object("mig-bkt", key, data, None)
            .await
            .unwrap();
    }
    let root_index = index_backend.bucket_meta_root("mig-bkt").join(INDEX_FILE);
    let sub_index = index_backend
        .bucket_meta_root("mig-bkt")
        .join("sub")
        .join(INDEX_FILE);
    assert!(root_index.is_file());
    assert!(sub_index.is_file());

    let preflight = index_backend.preflight_meta_migration();
    assert_eq!(preflight.index_files, 2);
    assert_eq!(preflight.entries, 3);
    assert!(preflight.corrupt.is_empty());
    assert!(preflight.collisions.is_empty());

    let report = index_backend.migrate_meta_indexes_to_sidecars();
    assert_eq!(report.index_files_migrated, 2);
    assert_eq!(report.index_files_failed, 0);
    assert_eq!(report.entries_written, 3);
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert!(!root_index.exists());
    assert!(!sub_index.exists());
    assert!(
        root_index
            .with_file_name(format!("{}.migrated", INDEX_FILE))
            .is_file(),
        "the migrated index must be kept as a rollback backup"
    );
    assert!(sub_index
        .with_file_name(format!("{}.migrated", INDEX_FILE))
        .is_file());

    let sidecar_backend = FsStorageBackend::new(dir.path().to_path_buf());
    for key in ["a.txt", "sub/b.txt", "sub/c.txt"] {
        let stored = sidecar_backend
            .get_object_metadata("mig-bkt", key)
            .await
            .unwrap();
        assert!(
            stored.contains_key("__etag__"),
            "metadata for {} must survive migration",
            key
        );
    }

    let rerun = sidecar_backend.migrate_meta_indexes_to_sidecars();
    assert_eq!(rerun.index_files_migrated, 0);
    assert_eq!(rerun.entries_written, 0);
    assert!(rerun.failures.is_empty());
}

#[tokio::test]
async fn test_migrate_leaves_corrupt_index_in_place() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("migrot-bkt").await.unwrap();
    let index_path = backend.bucket_meta_root("migrot-bkt").join(INDEX_FILE);
    std::fs::create_dir_all(index_path.parent().unwrap()).unwrap();
    std::fs::write(&index_path, b"][").unwrap();

    let preflight = backend.preflight_meta_migration();
    assert_eq!(preflight.corrupt.len(), 1, "{:?}", preflight.corrupt);
    assert!(index_path.is_file(), "preflight must not modify anything");

    let report = backend.migrate_meta_indexes_to_sidecars();
    assert_eq!(report.index_files_failed, 1);
    assert!(index_path.is_file(), "corrupt index must be preserved");
}

fn index_layout_backend() -> (tempfile::TempDir, FsStorageBackend) {
    let dir = tempfile::tempdir().unwrap();
    let backend = FsStorageBackend::new_with_config(
        dir.path().to_path_buf(),
        FsStorageBackendConfig {
            metadata_layout: MetadataLayout::Index,
            ..FsStorageBackendConfig::default()
        },
    );
    (dir, backend)
}

#[tokio::test]
async fn migration_interrupted_by_crash_is_resumable() {
    let _fp = failpoint_test_guard();
    let (dir, index_backend) = index_layout_backend();
    index_backend.create_bucket("mig-crash").await.unwrap();
    let keys = ["a.txt", "b.txt", "c.txt", "d.txt"];
    for key in keys {
        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"m".to_vec()));
        index_backend
            .put_object("mig-crash", key, data, None)
            .await
            .unwrap();
    }
    let index_path = index_backend.bucket_meta_root("mig-crash").join(INDEX_FILE);
    assert!(index_path.is_file());

    crate::failpoints::set(
        &index_backend.root,
        "migrate:sidecar-write",
        crate::failpoints::FailAction::Panic,
    );
    let crash_backend = FsStorageBackend::new_with_config(
        dir.path().to_path_buf(),
        FsStorageBackendConfig {
            metadata_layout: MetadataLayout::Sidecar,
            ..FsStorageBackendConfig::default()
        },
    );
    let join =
        tokio::task::spawn_blocking(move || crash_backend.migrate_meta_indexes_to_sidecars()).await;
    crate::failpoints::clear(&index_backend.root, "migrate:sidecar-write");
    assert!(
        join.unwrap_err().is_panic(),
        "the failpoint must simulate a crash"
    );
    assert!(
        index_path.is_file(),
        "a crash mid-migration must leave the index in place"
    );

    for key in keys {
        let stored = index_backend
            .get_object_metadata("mig-crash", key)
            .await
            .unwrap();
        assert!(
            stored.contains_key("__etag__"),
            "metadata for {} must stay readable after an interrupted migration",
            key
        );
    }

    let resume_backend = FsStorageBackend::new(dir.path().to_path_buf());
    let report = resume_backend.migrate_meta_indexes_to_sidecars();
    assert_eq!(report.index_files_migrated, 1);
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert!(!index_path.is_file());
    assert!(index_path
        .with_file_name(format!("{}.migrated", INDEX_FILE))
        .is_file());
    for key in keys {
        let stored = resume_backend
            .get_object_metadata("mig-crash", key)
            .await
            .unwrap();
        assert!(stored.contains_key("__etag__"));
    }
}

#[tokio::test]
async fn migration_write_failures_keep_the_index_serving() {
    let _fp = failpoint_test_guard();
    let (_dir, index_backend) = index_layout_backend();
    index_backend.create_bucket("mig-fail").await.unwrap();
    for key in ["x.txt", "y.txt"] {
        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"m".to_vec()));
        index_backend
            .put_object("mig-fail", key, data, None)
            .await
            .unwrap();
    }
    let index_path = index_backend.bucket_meta_root("mig-fail").join(INDEX_FILE);

    crate::failpoints::set(
        &index_backend.root,
        "migrate:sidecar-write",
        crate::failpoints::FailAction::Error(std::io::ErrorKind::Other),
    );
    let report = index_backend.migrate_meta_indexes_to_sidecars();
    crate::failpoints::clear(&index_backend.root, "migrate:sidecar-write");
    assert_eq!(report.index_files_migrated, 0);
    assert_eq!(report.index_files_failed, 1);
    assert!(!report.failures.is_empty());
    assert!(
        index_path.is_file(),
        "write failures must leave the index serving reads"
    );

    for key in ["x.txt", "y.txt"] {
        let stored = index_backend
            .get_object_metadata("mig-fail", key)
            .await
            .unwrap();
        assert!(stored.contains_key("__etag__"));
    }

    let retry = index_backend.migrate_meta_indexes_to_sidecars();
    assert_eq!(retry.index_files_migrated, 1);
    assert!(retry.failures.is_empty(), "{:?}", retry.failures);
}

#[tokio::test]
async fn test_rmw_rejected_on_unreadable_sidecar() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("rmw-bkt").await.unwrap();
    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"body".to_vec()));
    backend
        .put_object("rmw-bkt", "k.txt", data, None)
        .await
        .unwrap();
    let sidecar = backend
        .bucket_meta_root("rmw-bkt")
        .join(FsStorageBackend::sidecar_file_name("k.txt"));
    std::fs::write(&sidecar, b"garbage").unwrap();
    backend.meta_read_cache.lock().clear();

    let tags = vec![Tag {
        key: "a".to_string(),
        value: "b".to_string(),
    }];
    assert!(
        backend
            .set_object_tags("rmw-bkt", "k.txt", &tags)
            .await
            .is_err(),
        "tagging must not rewrite an unreadable metadata record"
    );
    assert_eq!(
        std::fs::read(&sidecar).unwrap(),
        b"garbage",
        "corrupt sidecar must be preserved as evidence"
    );
}

#[tokio::test]
async fn test_listing_blanks_fields_for_corrupt_sidecar() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("lb-bkt").await.unwrap();
    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"x".to_vec()));
    backend
        .put_object("lb-bkt", "f.txt", data, None)
        .await
        .unwrap();
    let stale = serde_json::json!({
        "f.txt": {"metadata": {"__etag__": "stale-etag"}}
    });
    std::fs::write(
        backend.bucket_meta_root("lb-bkt").join(INDEX_FILE),
        serde_json::to_string(&stale).unwrap(),
    )
    .unwrap();
    std::fs::write(
        backend
            .bucket_meta_root("lb-bkt")
            .join(FsStorageBackend::sidecar_file_name("f.txt")),
        b"garbage",
    )
    .unwrap();
    backend.meta_read_cache.lock().clear();
    backend.invalidate_bucket_caches("lb-bkt");

    let listing = backend
        .list_objects("lb-bkt", &ListParams::default())
        .await
        .unwrap();
    let entry = listing
        .objects
        .iter()
        .find(|o| o.key == "f.txt")
        .expect("listed");
    assert_eq!(
        entry.etag, None,
        "corrupt sidecar must blank listing fields, not expose stale index data"
    );
}

#[test]
fn test_sidecar_names_reserved_in_validation() {
    assert!(crate::validation::validate_object_key(
        ".__myfsio_meta__x.json",
        DEFAULT_OBJECT_KEY_MAX_BYTES,
        cfg!(windows),
        None
    )
    .is_some());
    assert!(crate::validation::validate_object_key(
        "dir/.__myfsio_meta__x.json",
        DEFAULT_OBJECT_KEY_MAX_BYTES,
        cfg!(windows),
        None
    )
    .is_some());
}
