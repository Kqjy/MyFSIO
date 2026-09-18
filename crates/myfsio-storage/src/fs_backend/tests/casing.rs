use super::*;

#[test]
fn disk_casing_verification_fails_closed_outside_root() {
    let (dir, mut backend) = create_test_backend();
    backend.case_insensitive_fs = true;
    let outside = dir.path().parent().unwrap().join("outside-case-probe");
    assert!(!backend.verify_disk_casing(&outside).unwrap());
}

#[test]
fn disk_casing_reports_a_removed_entry_as_unlinked() {
    let (dir, mut backend) = create_test_backend();
    backend.case_insensitive_fs = true;
    let canonical_root = std::fs::canonicalize(dir.path()).unwrap();
    let removed = dir.path().join("bkt").join("gone.bin");
    assert_eq!(
        backend
            .resolve_disk_casing(&removed, &canonical_root)
            .unwrap(),
        DiskCasingVerdict::Unlinked
    );
    assert!(
        backend.verify_disk_casing(&removed).unwrap(),
        "a key whose entry is not on disk has no casing to violate"
    );
}

#[test]
fn disk_casing_reports_a_case_aliased_entry_as_aliased() {
    let (dir, backend) = create_test_backend();
    if !backend.case_insensitive_fs {
        return;
    }
    let canonical_root = std::fs::canonicalize(dir.path()).unwrap();
    std::fs::create_dir_all(dir.path().join("Docs")).unwrap();
    std::fs::write(dir.path().join("Docs").join("secret.txt"), b"payload").unwrap();
    assert_eq!(
        backend
            .resolve_disk_casing(&dir.path().join("Docs").join("secret.txt"), &canonical_root)
            .unwrap(),
        DiskCasingVerdict::PathVerified
    );
    assert_eq!(
        backend
            .resolve_disk_casing(&dir.path().join("docs").join("secret.txt"), &canonical_root)
            .unwrap(),
        DiskCasingVerdict::Aliased
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn versioned_key_ops_survive_a_concurrently_unlinked_data_file() {
    let _stress = filesystem_stress_test_guard();
    let (_dir, backend) = create_test_backend();
    let backend = std::sync::Arc::new(backend);
    backend.create_bucket("unlink-race").await.unwrap();
    backend
        .set_versioning_status("unlink-race", VersioningStatus::Enabled)
        .await
        .unwrap();

    const WORKERS: usize = 12;
    const OPS: usize = 200;
    let anchor: AsyncReadStream = Box::pin(std::io::Cursor::new(b"anchor".to_vec()));
    backend
        .put_object("unlink-race", "race/never-deleted", anchor, None)
        .await
        .unwrap();
    let keys: std::sync::Arc<Vec<String>> =
        std::sync::Arc::new((0..4).map(|i| format!("race/k{:02}", i)).collect());

    let mut handles = Vec::new();
    for worker in 0..WORKERS {
        let backend = backend.clone();
        let keys = keys.clone();
        handles.push(tokio::spawn(async move {
            let mut rng: u64 = 0xA24BAED4963EE407u64.wrapping_mul(worker as u64 + 1);
            for op in 0..OPS {
                let roll = storm_rng_next(&mut rng);
                let key = &keys[(roll % keys.len() as u64) as usize];
                match (roll >> 8) % 4 {
                    0 => {
                        let body = format!("w{worker}-o{op}").into_bytes();
                        let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(body));
                        backend
                            .put_object("unlink-race", key, stream, None)
                            .await
                            .unwrap();
                    }
                    1 => {
                        let outcome = backend
                            .delete_object("unlink-race", key)
                            .await
                            .unwrap_or_else(|e| {
                                panic!("a versioned delete must not fail with {e:?}")
                            });
                        assert!(
                            outcome.is_delete_marker,
                            "a versioned delete must record a delete marker"
                        );
                        assert!(outcome.version_id.is_some());
                    }
                    2 => {
                        backend
                            .list_object_versions("unlink-race", key)
                            .await
                            .unwrap_or_else(|e| {
                                panic!("listing versions of {key} must not fail with {e:?}")
                            });
                    }
                    _ => {
                        if let Ok((_, mut stream)) = backend.get_object("unlink-race", key).await {
                            tokio::task::yield_now().await;
                            let mut body = Vec::new();
                            let _ = stream.read_to_end(&mut body).await;
                            tokio::task::yield_now().await;
                        }
                    }
                }
            }
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }

    for key in keys.iter() {
        let outcome = backend.delete_object("unlink-race", key).await.unwrap();
        assert!(outcome.is_delete_marker);
    }
}

#[test]
fn publish_by_rename_recreates_a_pruned_destination_directory() {
    let (dir, backend) = create_test_backend();
    let source = dir.path().join("staged.bin");
    std::fs::write(&source, b"payload").unwrap();
    let destination = dir.path().join("pruned").join("deep").join("obj.bin");
    backend
        .publish_by_rename_sync(&source, &destination)
        .expect("a publish must recreate the directory a concurrent prune removed");
    assert_eq!(std::fs::read(&destination).unwrap(), b"payload");
    assert!(!source.exists());
}

#[test]
fn publish_by_rename_reports_a_missing_source() {
    let (dir, backend) = create_test_backend();
    let source = dir.path().join("never-staged.bin");
    let destination = dir.path().join("obj.bin");
    let err = backend
        .publish_by_rename_sync(&source, &destination)
        .unwrap_err();
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::NotFound,
        "a missing staged file must be reported, not retried away"
    );
    assert!(!destination.exists());
}

#[test]
fn cleanup_empty_parents_spares_a_directory_with_a_publish_in_flight() {
    let (dir, backend) = create_test_backend();
    let prefix = dir.path().join("held").join("deep");
    std::fs::create_dir_all(&prefix).unwrap();
    let published = prefix.join("obj.bin");

    let guard = backend.directory_publish_guard(&prefix);
    backend.cleanup_empty_parents(&published, dir.path());
    assert!(
        prefix.is_dir(),
        "pruning must skip a directory a publisher is writing into"
    );
    drop(guard);

    backend.cleanup_empty_parents(&published, dir.path());
    assert!(
        !prefix.exists(),
        "pruning resumes once the publish has finished"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn put_survives_a_sibling_delete_pruning_the_shared_prefix() {
    let _stress = filesystem_stress_test_guard();
    let (_dir, backend) = create_test_backend();
    let backend = std::sync::Arc::new(backend);
    backend.create_bucket("prefix-prune").await.unwrap();

    const WORKERS: usize = 12;
    const OPS: usize = 200;
    let keys: std::sync::Arc<Vec<String>> =
        std::sync::Arc::new((0..4).map(|i| format!("prune/deep/k{:02}", i)).collect());

    let mut handles = Vec::new();
    for worker in 0..WORKERS {
        let backend = backend.clone();
        let keys = keys.clone();
        handles.push(tokio::spawn(async move {
            let mut rng: u64 = 0xC2B2AE3D27D4EB4Fu64.wrapping_mul(worker as u64 + 1);
            for op in 0..OPS {
                let roll = storm_rng_next(&mut rng);
                let key = &keys[(roll % keys.len() as u64) as usize];
                match (roll >> 8) % 4 {
                    0 | 1 => {
                        let body = format!("w{worker}-o{op}").into_bytes();
                        let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(body));
                        backend
                            .put_object("prefix-prune", key, stream, None)
                            .await
                            .unwrap_or_else(|e| {
                                panic!("a put into {key} must not fail with {e:?}")
                            });
                    }
                    2 => {
                        backend
                            .delete_object("prefix-prune", key)
                            .await
                            .unwrap_or_else(|e| {
                                panic!("a delete of {key} must not fail with {e:?}")
                            });
                    }
                    _ => match backend.get_object("prefix-prune", key).await {
                        Ok((_, mut stream)) => {
                            let mut body = Vec::new();
                            stream.read_to_end(&mut body).await.unwrap();
                        }
                        Err(StorageError::ObjectNotFound { .. }) => {}
                        Err(e) => panic!("unexpected get error under load: {e}"),
                    },
                }
            }
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }

    for key in keys.iter() {
        let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(b"final".to_vec()));
        backend
            .put_object("prefix-prune", key, stream, None)
            .await
            .unwrap();
        let (_, mut stream) = backend.get_object("prefix-prune", key).await.unwrap();
        let mut body = Vec::new();
        stream.read_to_end(&mut body).await.unwrap();
        assert_eq!(body, b"final");
    }
}

#[tokio::test]
async fn case_aliased_keys_fail_closed_on_case_insensitive_fs() {
    let (_dir, backend) = create_test_backend();
    if !backend.case_insensitive_fs {
        return;
    }
    backend.create_bucket("case-guard").await.unwrap();
    let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(b"victim data".to_vec()));
    backend
        .put_object("case-guard", "Docs/secret.txt", stream, None)
        .await
        .unwrap();

    let err = backend
        .get_object_metadata("case-guard", "docs/secret.txt")
        .await
        .unwrap_err();
    assert!(
        matches!(err, StorageError::ObjectNotFound { .. }),
        "aliased metadata read must be NotFound, got {err:?}"
    );

    let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(b"attacker".to_vec()));
    let err = backend
        .put_object("case-guard", "docs/secret.txt", stream, None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, StorageError::InvalidObjectKey(_)),
        "aliased overwrite must be rejected, got {err:?}"
    );

    let err = backend
        .update_object_legal_hold("case-guard", "DOCS/secret.txt", None, true)
        .await
        .unwrap_err();
    assert!(
        matches!(err, StorageError::ObjectNotFound { .. }),
        "aliased metadata mutation must be NotFound, got {err:?}"
    );

    let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(b"sibling".to_vec()));
    let err = backend
        .put_object("case-guard", "Docs/SECRET.txt", stream, None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, StorageError::InvalidObjectKey(_)),
        "sibling file differing only by case must be rejected, got {err:?}"
    );

    let meta = backend
        .get_object_metadata("case-guard", "Docs/secret.txt")
        .await
        .unwrap();
    assert!(
        !meta.is_empty(),
        "exact-cased object must remain readable and intact"
    );
}

#[tokio::test]
async fn case_aliased_version_ops_fail_closed() {
    let (_dir, backend) = create_test_backend();
    if !backend.case_insensitive_fs {
        return;
    }
    backend.create_bucket("case-ver").await.unwrap();
    backend
        .set_versioning_status("case-ver", VersioningStatus::Enabled)
        .await
        .unwrap();
    put_listing_object(&backend, "case-ver", "Vault/item", b"v1").await;
    put_listing_object(&backend, "case-ver", "Vault/item", b"v2").await;

    let versions = backend
        .list_object_versions("case-ver", "Vault/item")
        .await
        .unwrap();
    let list_err = backend
        .list_object_versions("case-ver", "vault/item")
        .await
        .unwrap_err();
    assert!(matches!(list_err, StorageError::ObjectNotFound { .. }));
    let archived = versions
        .iter()
        .find(|v| !v.is_latest)
        .expect("expected an archived version");
    let vid = archived.version_id.clone();

    let read_err = backend
        .get_object_version_metadata("case-ver", "vault/item", &vid)
        .await
        .unwrap_err();
    assert!(
        matches!(read_err, StorageError::ObjectNotFound { .. }),
        "aliased version metadata read must be NotFound, got {read_err:?}"
    );

    let del_err = backend
        .delete_object_version_checked("case-ver", "VAULT/item", &vid, false)
        .await
        .unwrap_err();
    assert!(
        matches!(del_err, StorageError::ObjectNotFound { .. }),
        "aliased version delete must be NotFound, got {del_err:?}"
    );

    backend
        .get_object_version_metadata("case-ver", "Vault/item", &vid)
        .await
        .expect("exact-cased version metadata must remain readable");

    backend
        .delete_object_checked("case-ver", "Vault/item", false)
        .await
        .unwrap();
    let archived_only_err = backend
        .get_object_version_metadata("case-ver", "vault/item", &vid)
        .await
        .unwrap_err();
    assert!(
        matches!(archived_only_err, StorageError::ObjectNotFound { .. }),
        "aliased archived-only version read must be NotFound, got {archived_only_err:?}"
    );
    let mutation_err = backend
        .put_object_version_metadata("case-ver", "vault/item", &vid, &HashMap::new())
        .await
        .unwrap_err();
    assert!(matches!(mutation_err, StorageError::ObjectNotFound { .. }));
    backend
        .get_object_version_metadata("case-ver", "Vault/item", &vid)
        .await
        .expect("exact-cased archived version must remain readable after live delete");
}

#[tokio::test]
async fn recreated_bucket_does_not_inherit_prior_state() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("reborn").await.unwrap();
    backend
        .set_versioning_status("reborn", VersioningStatus::Enabled)
        .await
        .unwrap();

    std::fs::remove_dir_all(backend.bucket_path("reborn")).unwrap();
    assert!(backend.system_bucket_root("reborn").exists());
    let versions_dir = backend.system_bucket_root("reborn").join("versions");
    std::fs::create_dir_all(&versions_dir).unwrap();
    std::fs::write(versions_dir.join("stale.bin"), b"old tenant").unwrap();
    std::fs::create_dir_all(backend.multipart_bucket_root("reborn")).unwrap();
    let legacy_policy_path = backend.legacy_bucket_policies_path();
    std::fs::create_dir_all(legacy_policy_path.parent().unwrap()).unwrap();
    std::fs::write(
        &legacy_policy_path,
        serde_json::json!({
            "policies": {
                "reborn": {
                    "Version": "2012-10-17",
                    "Statement": []
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    backend.create_bucket("reborn").await.unwrap();

    assert!(
        !versions_dir.exists(),
        "stale archived versions must be purged on bucket recreation"
    );
    assert!(!backend.multipart_bucket_root("reborn").exists());
    let config = backend.get_bucket_config("reborn").await.unwrap();
    assert_eq!(
        config.versioning_status(),
        VersioningStatus::Disabled,
        "recreated bucket must not inherit the prior bucket's configuration"
    );
    assert!(config.policy.is_none());
    let legacy_policy: Value =
        serde_json::from_str(&std::fs::read_to_string(legacy_policy_path).unwrap()).unwrap();
    assert!(legacy_policy["policies"].get("reborn").is_none());
}
