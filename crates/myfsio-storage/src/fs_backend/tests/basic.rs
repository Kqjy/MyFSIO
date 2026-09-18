use super::*;

#[tokio::test]
async fn corrupt_bucket_config_is_unreadable_and_not_overwritten() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("corrupt-cfg").await.unwrap();

    let config_path = backend.bucket_config_path("corrupt-cfg");
    std::fs::write(&config_path, b"{ this is not json").unwrap();
    backend.bucket_config_cache.clear();

    let config = backend.read_bucket_config_sync("corrupt-cfg");
    assert!(config.unreadable);
    assert!(config.policy.is_none());

    backend.bucket_config_cache.clear();
    assert!(backend
        .mutate_bucket_config("corrupt-cfg", |cfg| cfg.versioning_enabled = true)
        .await
        .is_err());

    backend.bucket_config_cache.clear();
    let mut edited = backend.read_bucket_config_sync("corrupt-cfg");
    edited.versioning_enabled = true;
    assert!(backend
        .set_bucket_config("corrupt-cfg", &edited)
        .await
        .is_err());

    backend.bucket_config_cache.clear();
    let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(b"payload".to_vec()));
    assert!(backend
        .put_object("corrupt-cfg", "object.txt", stream, None)
        .await
        .is_err());

    assert_eq!(
        std::fs::read_to_string(&config_path).unwrap(),
        "{ this is not json"
    );
}

#[tokio::test]
async fn test_create_and_list_buckets() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("test-bucket").await.unwrap();
    let buckets = backend.list_buckets().await.unwrap();
    assert_eq!(buckets.len(), 1);
    assert_eq!(buckets[0].name, "test-bucket");
}

#[tokio::test]
async fn test_bucket_exists() {
    let (_dir, backend) = create_test_backend();
    assert!(!backend.bucket_exists("test-bucket").await.unwrap());
    backend.create_bucket("test-bucket").await.unwrap();
    assert!(backend.bucket_exists("test-bucket").await.unwrap());
}

#[tokio::test]
async fn test_create_bucket_rejects_reserved_name() {
    let (_dir, backend) = create_test_backend();
    let err = backend
        .create_bucket("myfsio")
        .await
        .expect_err("creating reserved bucket name must fail");
    assert!(
        matches!(err, crate::error::StorageError::InvalidBucketName(ref msg) if msg.contains("reserved")),
        "expected InvalidBucketName(reserved …), got {:?}",
        err
    );
    assert!(!backend.bucket_exists("myfsio").await.unwrap());
}

#[tokio::test]
async fn test_bucket_config_reads_legacy_global_policy() {
    let (dir, backend) = create_test_backend();
    backend.create_bucket("legacy-policy").await.unwrap();
    let config_dir = dir.path().join(".myfsio.sys").join("config");
    let policy_path = config_dir.join("bucket_policies.json");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(
        &policy_path,
        serde_json::json!({
            "policies": {
                "legacy-policy": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::legacy-policy/*"
                    }]
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    let config = backend.get_bucket_config("legacy-policy").await.unwrap();
    assert!(config.policy.is_some());
    assert_eq!(
        config
            .policy
            .as_ref()
            .and_then(|p| p.get("Version"))
            .and_then(Value::as_str),
        Some("2012-10-17")
    );

    let mut config = config;
    config.policy = None;
    backend
        .set_bucket_config("legacy-policy", &config)
        .await
        .unwrap();
    let legacy_file =
        serde_json::from_str::<Value>(&std::fs::read_to_string(policy_path).unwrap()).unwrap();
    assert!(legacy_file
        .get("policies")
        .and_then(|policies| policies.get("legacy-policy"))
        .is_none());
    assert!(backend
        .get_bucket_config("legacy-policy")
        .await
        .unwrap()
        .policy
        .is_none());
}

#[tokio::test]
async fn test_delete_bucket() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("test-bucket").await.unwrap();
    backend.delete_bucket("test-bucket").await.unwrap();
    assert!(!backend.bucket_exists("test-bucket").await.unwrap());
}

#[tokio::test]
async fn test_delete_nonempty_bucket_fails() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("test-bucket").await.unwrap();
    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"hello".to_vec()));
    backend
        .put_object("test-bucket", "file.txt", data, None)
        .await
        .unwrap();
    let result = backend.delete_bucket("test-bucket").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_put_and_get_object() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("test-bucket").await.unwrap();

    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"hello world".to_vec()));
    let meta = backend
        .put_object("test-bucket", "greeting.txt", data, None)
        .await
        .unwrap();
    assert_eq!(meta.size, 11);
    assert!(meta.etag.is_some());

    let (obj, mut stream) = backend
        .get_object("test-bucket", "greeting.txt")
        .await
        .unwrap();
    assert_eq!(obj.size, 11);
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    assert_eq!(buf, b"hello world");
}

#[tokio::test]
async fn test_put_object_after_prefix_object() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("test-bucket").await.unwrap();

    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"inner".to_vec()));
    backend
        .put_object("test-bucket", "folder/file", data, None)
        .await
        .unwrap();

    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"outer".to_vec()));
    backend
        .put_object("test-bucket", "folder", data, None)
        .await
        .expect("PUT 'folder' after 'folder/file' should succeed");

    let (obj, mut stream) = backend.get_object("test-bucket", "folder").await.unwrap();
    assert_eq!(obj.size, 5);
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    assert_eq!(buf, b"outer");

    let (_, mut stream) = backend
        .get_object("test-bucket", "folder/file")
        .await
        .unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    assert_eq!(buf, b"inner");
}

#[tokio::test]
async fn test_head_and_delete_collided_object() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("test-bucket").await.unwrap();

    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"inner".to_vec()));
    backend
        .put_object("test-bucket", "folder/file", data, None)
        .await
        .unwrap();
    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"outer".to_vec()));
    backend
        .put_object("test-bucket", "folder", data, None)
        .await
        .unwrap();

    let meta = backend
        .head_object("test-bucket", "folder")
        .await
        .expect("head on collided key");
    assert_eq!(meta.size, 5);

    backend
        .delete_object("test-bucket", "folder")
        .await
        .expect("delete collided key");
    assert!(backend.head_object("test-bucket", "folder").await.is_err());
    let inner = backend
        .head_object("test-bucket", "folder/file")
        .await
        .expect("sibling key survives");
    assert_eq!(inner.size, 5);
}

#[tokio::test]
async fn test_put_prefix_object_after_object() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("test-bucket").await.unwrap();

    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"outer".to_vec()));
    backend
        .put_object("test-bucket", "folder", data, None)
        .await
        .unwrap();

    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"inner".to_vec()));
    backend
        .put_object("test-bucket", "folder/file", data, None)
        .await
        .expect("PUT 'folder/file' after 'folder' should succeed");

    let (_, mut stream) = backend.get_object("test-bucket", "folder").await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    assert_eq!(buf, b"outer");

    let (_, mut stream) = backend
        .get_object("test-bucket", "folder/file")
        .await
        .unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    assert_eq!(buf, b"inner");
}

#[tokio::test]
async fn test_list_carries_per_object_owner() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("test-bucket").await.unwrap();

    let acl_alice = serde_json::to_string(&serde_json::json!({
        "owner": "alice",
        "grants": [],
    }))
    .unwrap();
    let acl_bob = serde_json::to_string(&serde_json::json!({
        "owner": "bob",
        "grants": [],
    }))
    .unwrap();

    let mut meta_a: HashMap<String, String> = HashMap::new();
    meta_a.insert("__acl__".to_string(), acl_alice);
    backend
        .put_object(
            "test-bucket",
            "alice-file",
            Box::pin(std::io::Cursor::new(b"a".to_vec())),
            Some(meta_a),
        )
        .await
        .unwrap();

    let mut meta_b: HashMap<String, String> = HashMap::new();
    meta_b.insert("__acl__".to_string(), acl_bob);
    backend
        .put_object(
            "test-bucket",
            "bob-file",
            Box::pin(std::io::Cursor::new(b"b".to_vec())),
            Some(meta_b),
        )
        .await
        .unwrap();

    let result = backend
        .list_objects(
            "test-bucket",
            &myfsio_common::types::ListParams {
                max_keys: 100,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let by_key: HashMap<_, _> = result
        .objects
        .into_iter()
        .map(|o| (o.key.clone(), o.owner.clone()))
        .collect();
    assert_eq!(
        by_key.get("alice-file").and_then(|o| o.clone()),
        Some("alice".to_string())
    );
    assert_eq!(
        by_key.get("bob-file").and_then(|o| o.clone()),
        Some("bob".to_string())
    );
}

#[tokio::test]
async fn test_list_after_collision_shows_both_keys() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("test-bucket").await.unwrap();

    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"inner".to_vec()));
    backend
        .put_object("test-bucket", "folder/file", data, None)
        .await
        .unwrap();

    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"outer".to_vec()));
    backend
        .put_object("test-bucket", "folder", data, None)
        .await
        .unwrap();

    let params = myfsio_common::types::ListParams {
        max_keys: 100,
        ..Default::default()
    };
    let result = backend.list_objects("test-bucket", &params).await.unwrap();
    let keys: Vec<&str> = result.objects.iter().map(|o| o.key.as_str()).collect();
    assert!(
        keys.contains(&"folder"),
        "flat list missing 'folder' key: {:?}",
        keys
    );
    assert!(
        keys.contains(&"folder/file"),
        "flat list missing 'folder/file' key: {:?}",
        keys
    );
    for k in &keys {
        assert!(
            !k.contains(KEY_DATA_MARKER_FILE),
            "internal marker leaked into listing: {}",
            k
        );
    }

    let shallow_params = myfsio_common::types::ShallowListParams {
        prefix: String::new(),
        delimiter: "/".to_string(),
        max_keys: 100,
        continuation_token: None,
    };
    let shallow = backend
        .list_objects_shallow("test-bucket", &shallow_params)
        .await
        .unwrap();
    let shallow_keys: Vec<&str> = shallow.objects.iter().map(|o| o.key.as_str()).collect();
    assert!(
        shallow_keys.contains(&"folder"),
        "shallow list missing 'folder': {:?}",
        shallow_keys
    );
    assert!(
        shallow.common_prefixes.contains(&"folder/".to_string()),
        "shallow common-prefixes missing 'folder/': {:?}",
        shallow.common_prefixes
    );
    for k in &shallow_keys {
        assert!(
            !k.contains(KEY_DATA_MARKER_FILE),
            "internal marker leaked into shallow listing: {}",
            k
        );
    }
}

#[tokio::test]
async fn test_head_object() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("test-bucket").await.unwrap();

    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"test data".to_vec()));
    backend
        .put_object("test-bucket", "file.txt", data, None)
        .await
        .unwrap();

    let meta = backend
        .head_object("test-bucket", "file.txt")
        .await
        .unwrap();
    assert_eq!(meta.size, 9);
    assert!(meta.etag.is_some());
}

#[tokio::test]
async fn test_delete_object() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("test-bucket").await.unwrap();

    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"delete me".to_vec()));
    backend
        .put_object("test-bucket", "file.txt", data, None)
        .await
        .unwrap();

    backend
        .delete_object("test-bucket", "file.txt")
        .await
        .unwrap();
    let result = backend.head_object("test-bucket", "file.txt").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_put_object_with_metadata() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("test-bucket").await.unwrap();

    let mut user_meta = HashMap::new();
    user_meta.insert("x-amz-meta-custom".to_string(), "myvalue".to_string());
    user_meta.insert("__content_type__".to_string(), "text/plain".to_string());

    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"hello".to_vec()));
    backend
        .put_object("test-bucket", "file.txt", data, Some(user_meta))
        .await
        .unwrap();

    let stored = backend
        .get_object_metadata("test-bucket", "file.txt")
        .await
        .unwrap();
    assert_eq!(stored.get("x-amz-meta-custom").unwrap(), "myvalue");
    assert_eq!(stored.get("__content_type__").unwrap(), "text/plain");
    assert!(stored.contains_key("__etag__"));
}

#[tokio::test]
async fn test_meta_read_cache_evicts_least_recently_used_entry() {
    let dir = tempfile::tempdir().unwrap();
    let backend = FsStorageBackend::new_with_config(
        dir.path().to_path_buf(),
        FsStorageBackendConfig {
            object_cache_max_size: 2,
            ..FsStorageBackendConfig::default()
        },
    );
    backend.create_bucket("metadata-lru").await.unwrap();
    for key in ["a", "b", "c"] {
        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(key.as_bytes().to_vec()));
        backend
            .put_object("metadata-lru", key, data, None)
            .await
            .unwrap();
    }

    backend.meta_read_cache.lock().clear();
    assert!(backend.read_index_entry_sync("metadata-lru", "a").is_some());
    assert!(backend.read_index_entry_sync("metadata-lru", "b").is_some());
    assert!(backend.read_index_entry_sync("metadata-lru", "a").is_some());
    assert!(backend.read_index_entry_sync("metadata-lru", "c").is_some());

    let cache = backend.meta_read_cache.lock();
    assert_eq!(cache.len(), 2);
    assert!(cache
        .peek(&("metadata-lru".to_string(), "a".to_string()))
        .is_some());
    assert!(cache
        .peek(&("metadata-lru".to_string(), "b".to_string()))
        .is_none());
    assert!(cache
        .peek(&("metadata-lru".to_string(), "c".to_string()))
        .is_some());
}

#[tokio::test]
async fn test_poisoned_object_returns_object_corrupted_on_read() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("test-bucket").await.unwrap();

    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"poisoned bytes".to_vec()));
    backend
        .put_object("test-bucket", "rotted.txt", data, None)
        .await
        .unwrap();

    let mut meta = backend
        .get_object_metadata("test-bucket", "rotted.txt")
        .await
        .unwrap();
    meta.insert(META_KEY_CORRUPTED.to_string(), "true".to_string());
    meta.insert(
        META_KEY_CORRUPTION_DETAIL.to_string(),
        "etag mismatch: stored=abc actual=def".to_string(),
    );
    backend
        .put_object_metadata("test-bucket", "rotted.txt", &meta)
        .await
        .unwrap();

    let res = backend.get_object("test-bucket", "rotted.txt").await;
    match res {
        Err(StorageError::ObjectCorrupted { .. }) => {}
        Err(other) => panic!("expected ObjectCorrupted, got {:?}", other),
        Ok(_) => panic!("expected ObjectCorrupted, got Ok"),
    }

    let res = backend.head_object("test-bucket", "rotted.txt").await;
    match res {
        Err(StorageError::ObjectCorrupted { .. }) => {}
        Err(other) => panic!("expected ObjectCorrupted, got {:?}", other),
        Ok(_) => panic!("expected ObjectCorrupted, got Ok"),
    }
}

#[tokio::test]
async fn test_poisoned_object_with_missing_file_still_returns_corrupted() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("test-bucket").await.unwrap();

    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"will be quarantined".to_vec()));
    backend
        .put_object("test-bucket", "rotted.txt", data, None)
        .await
        .unwrap();

    let mut meta = backend
        .get_object_metadata("test-bucket", "rotted.txt")
        .await
        .unwrap();
    meta.insert(META_KEY_CORRUPTED.to_string(), "true".to_string());
    meta.insert(
        META_KEY_CORRUPTION_DETAIL.to_string(),
        "etag mismatch (no peer)".to_string(),
    );
    backend
        .put_object_metadata("test-bucket", "rotted.txt", &meta)
        .await
        .unwrap();

    let live_path = backend
        .get_object_path("test-bucket", "rotted.txt")
        .await
        .expect("path lookup should succeed before quarantine");
    std::fs::remove_file(&live_path).expect("simulate quarantine: remove live file");

    let res = backend.get_object("test-bucket", "rotted.txt").await;
    match res {
        Err(StorageError::ObjectCorrupted { .. }) => {}
        Err(other) => panic!("expected ObjectCorrupted after quarantine, got {:?}", other),
        Ok(_) => panic!("expected ObjectCorrupted, got Ok"),
    }

    let res = backend.head_object("test-bucket", "rotted.txt").await;
    match res {
        Err(StorageError::ObjectCorrupted { .. }) => {}
        Err(other) => panic!("expected ObjectCorrupted after quarantine, got {:?}", other),
        Ok(_) => panic!("expected ObjectCorrupted, got Ok"),
    }

    let res = backend.get_object_path("test-bucket", "rotted.txt").await;
    match res {
        Err(StorageError::ObjectCorrupted { .. }) => {}
        Err(other) => panic!("expected ObjectCorrupted, got {:?}", other),
        Ok(_) => panic!("expected ObjectCorrupted, got Ok"),
    }
}

#[tokio::test]
async fn test_integrity_quarantine_and_verified_install_are_guarded() {
    let (dir, backend) = create_test_backend();
    backend.create_bucket("test-bucket").await.unwrap();
    let original = b"known-good-content";
    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(original.to_vec()));
    backend
        .put_object("test-bucket", "guarded.txt", data, None)
        .await
        .unwrap();
    let stored_etag = backend
        .get_object_metadata("test-bucket", "guarded.txt")
        .await
        .unwrap()["__etag__"]
        .clone();
    let live_path = backend
        .validated_object_path("test-bucket", "guarded.txt")
        .unwrap();
    std::fs::write(&live_path, b"corrupted-content").unwrap();
    let quarantine_relative = PathBuf::from(SYSTEM_ROOT)
        .join("quarantine")
        .join("test-bucket")
        .join("test-run")
        .join("guarded.txt");

    let outcome = backend
        .quarantine_corrupted_object(
            "test-bucket",
            "guarded.txt",
            &stored_etag,
            &quarantine_relative,
            "checksum mismatch",
        )
        .await
        .unwrap();
    assert_eq!(outcome, IntegrityQuarantineOutcome::Quarantined);
    assert!(!live_path.exists());
    assert!(dir.path().join(&quarantine_relative).is_file());
    let poisoned = backend
        .get_object_metadata("test-bucket", "guarded.txt")
        .await
        .unwrap();
    assert!(metadata_is_corrupted(&poisoned));
    assert_eq!(
        poisoned.get(META_KEY_CORRUPTION_RETRY_COUNT),
        Some(&"0".to_string())
    );

    let prepared = live_path.with_file_name("guarded.txt.healing-test");
    std::fs::write(&prepared, original).unwrap();
    assert!(backend
        .install_healed_object_if_still_poisoned(
            "test-bucket",
            "guarded.txt",
            &stored_etag,
            &prepared,
        )
        .await
        .unwrap());
    assert_eq!(std::fs::read(&live_path).unwrap(), original);
    let healed = backend
        .get_object_metadata("test-bucket", "guarded.txt")
        .await
        .unwrap();
    assert!(!metadata_is_corrupted(&healed));
}

#[tokio::test]
async fn test_fresh_put_wins_race_with_poisoned_recovery() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("test-bucket").await.unwrap();
    let original = b"original";
    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(original.to_vec()));
    backend
        .put_object("test-bucket", "raced.txt", data, None)
        .await
        .unwrap();
    let stored_etag = backend
        .get_object_metadata("test-bucket", "raced.txt")
        .await
        .unwrap()["__etag__"]
        .clone();
    let live_path = backend
        .validated_object_path("test-bucket", "raced.txt")
        .unwrap();
    std::fs::write(&live_path, b"bad").unwrap();
    let quarantine_relative = PathBuf::from(SYSTEM_ROOT)
        .join("quarantine")
        .join("test-bucket")
        .join("race")
        .join("raced.txt");
    assert_eq!(
        backend
            .quarantine_corrupted_object(
                "test-bucket",
                "raced.txt",
                &stored_etag,
                &quarantine_relative,
                "checksum mismatch",
            )
            .await
            .unwrap(),
        IntegrityQuarantineOutcome::Quarantined
    );

    let fresh = b"fresh-write";
    let fresh_stream: AsyncReadStream = Box::pin(std::io::Cursor::new(fresh.to_vec()));
    backend
        .put_object("test-bucket", "raced.txt", fresh_stream, None)
        .await
        .unwrap();
    let prepared = live_path.with_file_name("raced.txt.healing-test");
    std::fs::write(&prepared, original).unwrap();
    assert!(!backend
        .install_healed_object_if_still_poisoned(
            "test-bucket",
            "raced.txt",
            &stored_etag,
            &prepared,
        )
        .await
        .unwrap());
    assert_eq!(std::fs::read(&live_path).unwrap(), fresh);
    assert!(!metadata_is_corrupted(
        &backend
            .get_object_metadata("test-bucket", "raced.txt")
            .await
            .unwrap()
    ));
}

#[tokio::test]
async fn test_delete_object_metadata_entry_removes_index_entry() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("test-bucket").await.unwrap();
    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"x".to_vec()));
    backend
        .put_object("test-bucket", "ghost.txt", data, None)
        .await
        .unwrap();
    let path = backend
        .get_object_path("test-bucket", "ghost.txt")
        .await
        .unwrap();
    std::fs::remove_file(&path).unwrap();

    backend
        .delete_object_metadata_entry("test-bucket", "ghost.txt")
        .await
        .unwrap();

    let stored = backend
        .get_object_metadata("test-bucket", "ghost.txt")
        .await
        .unwrap();
    assert!(
        stored.is_empty(),
        "metadata entry must be gone, got: {:?}",
        stored
    );
}

#[tokio::test]
async fn test_conditional_phantom_delete_preserves_changed_or_fresh_object() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("test-bucket").await.unwrap();
    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"old".to_vec()));
    backend
        .put_object("test-bucket", "phantom.txt", data, None)
        .await
        .unwrap();
    let old_etag = backend
        .get_object_metadata("test-bucket", "phantom.txt")
        .await
        .unwrap()["__etag__"]
        .clone();
    let path = backend
        .validated_object_path("test-bucket", "phantom.txt")
        .unwrap();
    std::fs::remove_file(&path).unwrap();

    assert!(!backend
        .delete_phantom_metadata_if_still_missing(
            "test-bucket",
            "phantom.txt",
            Some("different-etag"),
        )
        .await
        .unwrap());
    assert_eq!(
        backend
            .get_object_metadata("test-bucket", "phantom.txt")
            .await
            .unwrap()["__etag__"],
        old_etag
    );

    let fresh_stream: AsyncReadStream = Box::pin(std::io::Cursor::new(b"fresh".to_vec()));
    backend
        .put_object("test-bucket", "phantom.txt", fresh_stream, None)
        .await
        .unwrap();
    assert!(!backend
        .delete_phantom_metadata_if_still_missing("test-bucket", "phantom.txt", Some(&old_etag),)
        .await
        .unwrap());
    assert_eq!(std::fs::read(&path).unwrap(), b"fresh");
}

#[tokio::test]
async fn test_delete_object_clears_poisoned_metadata() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("test-bucket").await.unwrap();

    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"will rot".to_vec()));
    backend
        .put_object("test-bucket", "rot.txt", data, None)
        .await
        .unwrap();

    let mut meta = backend
        .get_object_metadata("test-bucket", "rot.txt")
        .await
        .unwrap();
    meta.insert(META_KEY_CORRUPTED.to_string(), "true".to_string());
    backend
        .put_object_metadata("test-bucket", "rot.txt", &meta)
        .await
        .unwrap();

    let live_path = backend
        .get_object_path("test-bucket", "rot.txt")
        .await
        .unwrap();
    std::fs::remove_file(&live_path).unwrap();

    backend
        .delete_object("test-bucket", "rot.txt")
        .await
        .unwrap();

    match backend.head_object("test-bucket", "rot.txt").await {
        Err(StorageError::ObjectNotFound { .. }) => {}
        other => panic!(
            "after DELETE on a poisoned/quarantined object, HEAD should be ObjectNotFound, got {:?}",
            other
        ),
    }

    let leftover = backend
        .get_object_metadata("test-bucket", "rot.txt")
        .await
        .unwrap();
    assert!(
        leftover.is_empty(),
        "metadata sidecar must be cleared after DELETE on poisoned object"
    );
}

#[tokio::test]
async fn test_put_clears_poison_flag() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("test-bucket").await.unwrap();

    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"first".to_vec()));
    backend
        .put_object("test-bucket", "file.txt", data, None)
        .await
        .unwrap();

    let mut meta = backend
        .get_object_metadata("test-bucket", "file.txt")
        .await
        .unwrap();
    meta.insert(META_KEY_CORRUPTED.to_string(), "true".to_string());
    backend
        .put_object_metadata("test-bucket", "file.txt", &meta)
        .await
        .unwrap();

    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"replacement".to_vec()));
    backend
        .put_object("test-bucket", "file.txt", data, None)
        .await
        .unwrap();

    match backend.get_object("test-bucket", "file.txt").await {
        Ok(_) => {}
        Err(e) => panic!("get must succeed after PUT clears poison, got {:?}", e),
    }
}

#[tokio::test]
async fn test_list_objects() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("test-bucket").await.unwrap();

    for name in &["a.txt", "b.txt", "c.txt"] {
        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"x".to_vec()));
        backend
            .put_object("test-bucket", name, data, None)
            .await
            .unwrap();
    }

    let result = backend
        .list_objects("test-bucket", &ListParams::default())
        .await
        .unwrap();
    assert_eq!(result.objects.len(), 3);
    assert_eq!(result.objects[0].key, "a.txt");
    assert_eq!(result.objects[1].key, "b.txt");
    assert_eq!(result.objects[2].key, "c.txt");
    assert!(!result.is_truncated);
}

#[tokio::test]
async fn test_list_objects_with_prefix() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("test-bucket").await.unwrap();

    for name in &["docs/a.txt", "docs/b.txt", "images/c.png"] {
        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"x".to_vec()));
        backend
            .put_object("test-bucket", name, data, None)
            .await
            .unwrap();
    }

    let params = ListParams {
        prefix: Some("docs/".to_string()),
        ..Default::default()
    };
    let result = backend.list_objects("test-bucket", &params).await.unwrap();
    assert_eq!(result.objects.len(), 2);
}

#[tokio::test]
async fn test_list_objects_pagination() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("test-bucket").await.unwrap();

    for i in 0..5 {
        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"x".to_vec()));
        backend
            .put_object("test-bucket", &format!("file{}.txt", i), data, None)
            .await
            .unwrap();
    }

    let params = ListParams {
        max_keys: 2,
        ..Default::default()
    };
    let result = backend.list_objects("test-bucket", &params).await.unwrap();
    assert_eq!(result.objects.len(), 2);
    assert!(result.is_truncated);
    assert!(result.next_continuation_token.is_some());

    let params2 = ListParams {
        max_keys: 2,
        continuation_token: result.next_continuation_token,
        ..Default::default()
    };
    let result2 = backend.list_objects("test-bucket", &params2).await.unwrap();
    assert_eq!(result2.objects.len(), 2);
    assert!(result2.is_truncated);
}

#[tokio::test]
async fn test_copy_object() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("src-bucket").await.unwrap();
    backend.create_bucket("dst-bucket").await.unwrap();

    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"copy me".to_vec()));
    backend
        .put_object("src-bucket", "original.txt", data, None)
        .await
        .unwrap();

    backend
        .copy_object("src-bucket", "original.txt", "dst-bucket", "copied.txt")
        .await
        .unwrap();

    let (_, mut stream) = backend
        .get_object("dst-bucket", "copied.txt")
        .await
        .unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    assert_eq!(buf, b"copy me");
}

#[tokio::test]
async fn test_versioning() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("test-bucket").await.unwrap();
    backend.set_versioning("test-bucket", true).await.unwrap();

    let data1: AsyncReadStream = Box::pin(std::io::Cursor::new(b"version1".to_vec()));
    let version1 = backend
        .put_object("test-bucket", "file.txt", data1, None)
        .await
        .unwrap()
        .version_id
        .unwrap();

    let data2: AsyncReadStream = Box::pin(std::io::Cursor::new(b"version2".to_vec()));
    backend
        .put_object("test-bucket", "file.txt", data2, None)
        .await
        .unwrap();

    let data3: AsyncReadStream = Box::pin(std::io::Cursor::new(b"version3".to_vec()));
    backend
        .put_object("test-bucket", "file.txt", data3, None)
        .await
        .unwrap();

    let versions = backend
        .list_object_versions("test-bucket", "file.txt")
        .await
        .unwrap();
    assert_eq!(versions.len(), 2);
    assert!(versions.iter().all(|version| version.size == 8));

    let (_, stream) = backend
        .get_object_version("test-bucket", "file.txt", &version1)
        .await
        .unwrap();
    assert_eq!(read_stream_to_end(stream).await, b"version1");

    let invalid_version = format!("../other/{}", versions[0].version_id);
    let result = backend
        .get_object_version("test-bucket", "file.txt", &invalid_version)
        .await;
    assert!(matches!(result, Err(StorageError::VersionNotFound { .. })));
}

#[tokio::test]
async fn test_version_remains_readable_after_live_delete() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("test-bucket").await.unwrap();
    backend.set_versioning("test-bucket", true).await.unwrap();

    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"archived".to_vec()));
    let version_id = backend
        .put_object("test-bucket", "file.txt", data, None)
        .await
        .unwrap()
        .version_id
        .unwrap();

    backend
        .delete_object("test-bucket", "file.txt")
        .await
        .unwrap();

    let (_, stream) = backend
        .get_object_version("test-bucket", "file.txt", &version_id)
        .await
        .unwrap();
    assert_eq!(read_stream_to_end(stream).await, b"archived");
}

#[tokio::test]
async fn test_invalid_bucket_name() {
    let (_dir, backend) = create_test_backend();
    let result = backend.create_bucket("AB").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_bucket_stats() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("test-bucket").await.unwrap();

    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"hello".to_vec()));
    backend
        .put_object("test-bucket", "file.txt", data, None)
        .await
        .unwrap();

    let stats = backend.bucket_stats("test-bucket").await.unwrap();
    assert_eq!(stats.objects, 1);
    assert_eq!(stats.bytes, 5);
}
