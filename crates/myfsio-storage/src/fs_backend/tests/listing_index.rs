use super::*;

#[tokio::test]
async fn test_listing_index_matches_legacy_after_all_primary_mutations() {
    let indexed_dir = tempfile::tempdir().unwrap();
    let legacy_dir = tempfile::tempdir().unwrap();
    let indexed = create_listing_backend(indexed_dir.path().to_path_buf(), true, 4096);
    let legacy = create_listing_backend(legacy_dir.path().to_path_buf(), false, 4096);
    seed_listing_mutation_scenario(&indexed, "list-bkt").await;
    seed_listing_mutation_scenario(&legacy, "list-bkt").await;

    let first_params = ListParams {
        max_keys: 2,
        ..Default::default()
    };
    let indexed_first = assert_index_matches_legacy(&indexed, "list-bkt", &first_params).await;
    let legacy_first = assert_index_matches_legacy(&legacy, "list-bkt", &first_params).await;
    assert_eq!(
        logical_listing_view(&indexed_first),
        logical_listing_view(&legacy_first)
    );
    assert!(indexed_first.is_truncated);
    assert_eq!(
        indexed_first.next_continuation_token,
        legacy_first.next_continuation_token
    );

    let second_params = ListParams {
        max_keys: 2,
        continuation_token: indexed_first.next_continuation_token.clone(),
        ..Default::default()
    };
    let indexed_second = assert_index_matches_legacy(&indexed, "list-bkt", &second_params).await;
    let legacy_second = assert_index_matches_legacy(&legacy, "list-bkt", &second_params).await;
    assert_eq!(
        logical_listing_view(&indexed_second),
        logical_listing_view(&legacy_second)
    );

    let prefix_params = ListParams {
        max_keys: 2,
        prefix: Some("docs/".to_string()),
        ..Default::default()
    };
    let indexed_prefix = assert_index_matches_legacy(&indexed, "list-bkt", &prefix_params).await;
    let legacy_prefix = assert_index_matches_legacy(&legacy, "list-bkt", &prefix_params).await;
    assert_eq!(
        logical_listing_view(&indexed_prefix),
        logical_listing_view(&legacy_prefix)
    );

    let start_after_params = ListParams {
        max_keys: 100,
        prefix: Some("docs/".to_string()),
        start_after: Some("docs/a.txt".to_string()),
        ..Default::default()
    };
    let indexed_start_after =
        assert_index_matches_legacy(&indexed, "list-bkt", &start_after_params).await;
    let legacy_start_after =
        assert_index_matches_legacy(&legacy, "list-bkt", &start_after_params).await;
    assert_eq!(
        logical_listing_view(&indexed_start_after),
        logical_listing_view(&legacy_start_after)
    );
    assert!(indexed_start_after
        .objects
        .iter()
        .all(|object| object.key.starts_with("docs/") && object.key.as_str() > "docs/a.txt"));

    let full = indexed
        .list_objects("list-bkt", &ListParams::default())
        .await
        .unwrap();
    let by_key = full
        .objects
        .iter()
        .map(|object| (object.key.as_str(), object.size))
        .collect::<HashMap<_, _>>();
    assert_eq!(by_key.get("docs/a.txt"), Some(&11));
    assert_eq!(by_key.get("copied.txt"), Some(&4));
    assert_eq!(by_key.get("docs/multipart.bin"), Some(&9));
    assert!(!by_key.contains_key("alpha.txt"));
}

#[tokio::test]
async fn test_listing_index_tracks_version_delete_markers_and_restore() {
    let dir = tempfile::tempdir().unwrap();
    let backend = create_listing_backend(dir.path().to_path_buf(), true, 4096);
    backend.create_bucket("ver-list").await.unwrap();
    backend.set_versioning("ver-list", true).await.unwrap();
    put_listing_object(&backend, "ver-list", "key.txt", b"first").await;
    assert_index_matches_legacy(&backend, "ver-list", &ListParams::default()).await;

    let marker = backend
        .delete_object("ver-list", "key.txt")
        .await
        .unwrap()
        .version_id
        .unwrap();
    let hidden = assert_index_matches_legacy(&backend, "ver-list", &ListParams::default()).await;
    assert!(hidden.objects.is_empty());

    backend
        .delete_object_version("ver-list", "key.txt", &marker)
        .await
        .unwrap();
    let restored = assert_index_matches_legacy(&backend, "ver-list", &ListParams::default()).await;
    assert_eq!(restored.objects.len(), 1);
    assert_eq!(restored.objects[0].key, "key.txt");

    backend.delete_object("ver-list", "key.txt").await.unwrap();
    let hidden_again =
        assert_index_matches_legacy(&backend, "ver-list", &ListParams::default()).await;
    assert!(hidden_again.objects.is_empty());
    put_listing_object(&backend, "ver-list", "key.txt", b"second").await;
    let reinstated =
        assert_index_matches_legacy(&backend, "ver-list", &ListParams::default()).await;
    assert_eq!(reinstated.objects.len(), 1);
    assert_eq!(reinstated.objects[0].size, 6);
}

#[tokio::test]
async fn test_listing_index_persists_and_loads_without_full_walk() {
    let dir = tempfile::tempdir().unwrap();
    {
        let backend = create_listing_backend(dir.path().to_path_buf(), true, 4096);
        backend.create_bucket("persist-list").await.unwrap();
        put_listing_object(&backend, "persist-list", "a.txt", b"a").await;
        put_listing_object(&backend, "persist-list", "b.txt", b"bb").await;
        let result = backend
            .list_objects("persist-list", &ListParams::default())
            .await
            .unwrap();
        assert_eq!(result.objects.len(), 2);
        assert_eq!(
            backend
                .listing_full_builds
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert!(backend
            .bucket_listing_dir("persist-list")
            .join("snapshot.json")
            .is_file());
    }

    let backend = create_listing_backend(dir.path().to_path_buf(), true, 4096);
    assert_eq!(
        backend
            .listing_full_builds
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    let result = backend
        .list_objects("persist-list", &ListParams::default())
        .await
        .unwrap();
    assert_eq!(
        result
            .objects
            .iter()
            .map(|object| object.key.as_str())
            .collect::<Vec<_>>(),
        vec!["a.txt", "b.txt"]
    );
    assert_eq!(
        backend
            .listing_full_builds
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

#[tokio::test]
async fn test_listing_index_corrupt_snapshot_rebuilds() {
    let dir = tempfile::tempdir().unwrap();
    {
        let backend = create_listing_backend(dir.path().to_path_buf(), true, 4096);
        backend.create_bucket("corrupt-list").await.unwrap();
        put_listing_object(&backend, "corrupt-list", "a.txt", b"a").await;
        backend
            .list_objects("corrupt-list", &ListParams::default())
            .await
            .unwrap();
    }
    let snapshot = dir
        .path()
        .join(SYSTEM_ROOT)
        .join(SYSTEM_BUCKETS_DIR)
        .join("corrupt-list")
        .join("listing")
        .join("snapshot.json");
    std::fs::write(&snapshot, b"{\"version\":1").unwrap();

    let backend = create_listing_backend(dir.path().to_path_buf(), true, 4096);
    let result = backend
        .list_objects("corrupt-list", &ListParams::default())
        .await
        .unwrap();
    assert_eq!(result.objects[0].key, "a.txt");
    assert_eq!(
        backend
            .listing_full_builds
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

#[tokio::test]
async fn test_listing_index_tolerates_garbage_journal_tail() {
    let dir = tempfile::tempdir().unwrap();
    let journal;
    {
        let backend = create_listing_backend(dir.path().to_path_buf(), true, 4096);
        backend.create_bucket("tail-list").await.unwrap();
        put_listing_object(&backend, "tail-list", "a.txt", b"a").await;
        backend
            .list_objects("tail-list", &ListParams::default())
            .await
            .unwrap();
        put_listing_object(&backend, "tail-list", "b.txt", b"b").await;
        journal = backend
            .bucket_listing_dir("tail-list")
            .join("journal.1.jsonl");
    }
    let mut bytes = std::fs::read(&journal).unwrap();
    bytes.extend_from_slice(b"garbage tail\n");
    std::fs::write(&journal, bytes).unwrap();

    let backend = create_listing_backend(dir.path().to_path_buf(), true, 4096);
    let result = backend
        .list_objects("tail-list", &ListParams::default())
        .await
        .unwrap();
    assert_eq!(
        result
            .objects
            .iter()
            .map(|object| object.key.as_str())
            .collect::<Vec<_>>(),
        vec!["a.txt", "b.txt"]
    );
    assert_eq!(
        backend
            .listing_full_builds
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    drop(backend);
}

#[tokio::test]
async fn test_listing_index_garbage_journal_middle_rebuilds() {
    let dir = tempfile::tempdir().unwrap();
    let journal;
    {
        let backend = create_listing_backend(dir.path().to_path_buf(), true, 4096);
        backend.create_bucket("middle-list").await.unwrap();
        put_listing_object(&backend, "middle-list", "a.txt", b"a").await;
        backend
            .list_objects("middle-list", &ListParams::default())
            .await
            .unwrap();
        put_listing_object(&backend, "middle-list", "b.txt", b"b").await;
        put_listing_object(&backend, "middle-list", "c.txt", b"c").await;
        journal = backend
            .bucket_listing_dir("middle-list")
            .join("journal.1.jsonl");
    }
    let bytes = std::fs::read(&journal).unwrap();
    let split = bytes.iter().position(|byte| *byte == b'\n').unwrap() + 1;
    let mut corrupt = Vec::new();
    corrupt.extend_from_slice(&bytes[..split]);
    corrupt.extend_from_slice(b"garbage middle\n");
    corrupt.extend_from_slice(&bytes[split..]);
    std::fs::write(&journal, corrupt).unwrap();

    let backend = create_listing_backend(dir.path().to_path_buf(), true, 4096);
    let result = backend
        .list_objects("middle-list", &ListParams::default())
        .await
        .unwrap();
    assert_eq!(result.objects.len(), 3);
    assert_eq!(
        backend
            .listing_full_builds
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    assert_eq!(std::fs::metadata(journal).unwrap().len(), 0);
}

#[tokio::test]
async fn test_listing_index_threshold_does_not_write_snapshot_inline() {
    let dir = tempfile::tempdir().unwrap();
    let backend = create_listing_backend(dir.path().to_path_buf(), true, 1);
    backend.create_bucket("compact-list").await.unwrap();
    put_listing_object(&backend, "compact-list", "a.txt", b"a").await;
    backend
        .list_objects("compact-list", &ListParams::default())
        .await
        .unwrap();
    let snapshot = backend
        .bucket_listing_dir("compact-list")
        .join("snapshot.json");
    let before = std::fs::read(&snapshot).unwrap();
    backend.pause_listing_compactor_after_seal(true);
    put_listing_object(&backend, "compact-list", "b.txt", b"b").await;
    put_listing_object(&backend, "compact-list", "c.txt", b"c").await;
    assert!(
        backend.wait_for_listing_compactor_seal("compact-list", std::time::Duration::from_secs(5))
    );
    assert_eq!(std::fs::read(&snapshot).unwrap(), before);
    assert!(backend
        .bucket_listing_dir("compact-list")
        .join("journal.2.jsonl")
        .is_file());
    backend.pause_listing_compactor_after_seal(false);
    backend.shutdown_listing_compactor();
    let compacted: Value = serde_json::from_slice(&std::fs::read(&snapshot).unwrap()).unwrap();
    assert_eq!(compacted["high_water_generation"], 1);
}

#[tokio::test]
async fn test_listing_index_worker_snapshot_matches_reload_page() {
    let dir = tempfile::tempdir().unwrap();
    let backend = create_listing_backend(dir.path().to_path_buf(), true, 1);
    backend.create_bucket("worker-list").await.unwrap();
    put_listing_object(&backend, "worker-list", "a.txt", b"a").await;
    backend
        .list_objects("worker-list", &ListParams::default())
        .await
        .unwrap();
    backend.pause_listing_compactor_after_seal(true);
    put_listing_object(&backend, "worker-list", "b.txt", b"bb").await;
    put_listing_object(&backend, "worker-list", "c.txt", b"ccc").await;
    assert!(
        backend.wait_for_listing_compactor_seal("worker-list", std::time::Duration::from_secs(5))
    );
    let before = backend
        .list_objects("worker-list", &ListParams::default())
        .await
        .unwrap();
    backend.pause_listing_compactor_after_seal(false);
    backend.shutdown_listing_compactor();
    drop(backend);

    let backend = create_listing_backend(dir.path().to_path_buf(), true, 1);
    let result = backend
        .list_objects("worker-list", &ListParams::default())
        .await
        .unwrap();
    assert_list_results_equal(&before, &result);
    assert_eq!(
        backend
            .listing_full_builds
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

#[test]
fn test_listing_index_crash_before_snapshot_rename_replays_old_chain() {
    let dir = tempfile::tempdir().unwrap();
    let listing_dir = dir.path().join("listing");
    let mut index = BucketListingIndex::from_records(
        listing_dir.clone(),
        vec![ListingRecord::new(
            "a.txt".to_string(),
            1,
            1.0,
            None,
            None,
            None,
        )],
        1,
    );
    index.persist_rebuilt().unwrap();
    index
        .apply_put(ListingRecord::new(
            "b.txt".to_string(),
            2,
            2.0,
            None,
            None,
            None,
        ))
        .unwrap();
    index.request_compaction_retry();
    let sealed = index.seal_for_compaction().unwrap().unwrap();
    let bytes = crate::listing_index::prepare_compaction_snapshot(&sealed).unwrap();
    crate::listing_index::write_snapshot_temp(&listing_dir.join("snapshot.tmp"), &bytes).unwrap();
    drop(index);

    let loaded = BucketListingIndex::load(listing_dir, 1).unwrap();
    let (records, _, _) = loaded.page("", None, 100);
    assert_eq!(
        records
            .iter()
            .map(|record| record.key.as_str())
            .collect::<Vec<_>>(),
        vec!["a.txt", "b.txt"]
    );
}

#[test]
fn test_listing_index_crash_after_rename_ignores_covered_journals() {
    let dir = tempfile::tempdir().unwrap();
    let listing_dir = dir.path().join("listing");
    let mut index = BucketListingIndex::from_records(
        listing_dir.clone(),
        vec![ListingRecord::new(
            "a.txt".to_string(),
            1,
            1.0,
            None,
            None,
            None,
        )],
        1,
    );
    index.persist_rebuilt().unwrap();
    index
        .apply_put(ListingRecord::new(
            "b.txt".to_string(),
            2,
            2.0,
            None,
            None,
            None,
        ))
        .unwrap();
    index.request_compaction_retry();
    let sealed = index.seal_for_compaction().unwrap().unwrap();
    let bytes = crate::listing_index::prepare_compaction_snapshot(&sealed).unwrap();
    let temp = listing_dir.join("snapshot.tmp");
    crate::listing_index::write_snapshot_temp(&temp, &bytes).unwrap();
    crate::listing_index::install_snapshot_temp(&temp, &listing_dir).unwrap();
    std::fs::write(listing_dir.join("journal.1.jsonl"), b"covered garbage\n").unwrap();
    drop(index);

    let loaded = BucketListingIndex::load(listing_dir, 1).unwrap();
    let (records, _, _) = loaded.page("", None, 100);
    assert_eq!(
        records
            .iter()
            .map(|record| record.key.as_str())
            .collect::<Vec<_>>(),
        vec!["a.txt", "b.txt"]
    );
}

#[test]
fn test_listing_index_snapshot_without_journals_opens_next_generation() {
    let dir = tempfile::tempdir().unwrap();
    let listing_dir = dir.path().join("listing");
    let mut index = BucketListingIndex::from_records(
        listing_dir.clone(),
        vec![ListingRecord::new(
            "a.txt".to_string(),
            1,
            1.0,
            None,
            None,
            None,
        )],
        4096,
    );
    index.persist_rebuilt().unwrap();
    drop(index);
    std::fs::remove_file(listing_dir.join("journal.1.jsonl")).unwrap();

    let loaded = BucketListingIndex::load(listing_dir.clone(), 4096).unwrap();
    let (records, _, _) = loaded.page("", None, 100);
    assert_eq!(records.len(), 1);
    assert!(listing_dir.join("journal.1.jsonl").is_file());
}

#[test]
fn test_listing_index_snapshot_temp_io_error_preserves_loadable_chain() {
    let dir = tempfile::tempdir().unwrap();
    let listing_dir = dir.path().join("listing");
    let mut index = BucketListingIndex::from_records(listing_dir.clone(), Vec::new(), 4096);
    index.persist_rebuilt().unwrap();
    index
        .apply_put(ListingRecord::new(
            "a.txt".to_string(),
            1,
            1.0,
            None,
            None,
            None,
        ))
        .unwrap();
    index.request_compaction_retry();
    let sealed = index.seal_for_compaction().unwrap().unwrap();
    let bytes = crate::listing_index::prepare_compaction_snapshot(&sealed).unwrap();
    let blocked_parent = dir.path().join("blocked");
    std::fs::write(&blocked_parent, b"not a directory").unwrap();
    assert!(crate::listing_index::write_snapshot_temp(
        &blocked_parent.join("snapshot.tmp"),
        &bytes
    )
    .is_err());
    drop(index);

    let loaded = BucketListingIndex::load(listing_dir, 4096).unwrap();
    let (records, _, _) = loaded.page("", None, 100);
    assert_eq!(records[0].key, "a.txt");
}

#[tokio::test]
async fn test_listing_index_missing_snapshot_with_journals_rebuilds_sidecars() {
    let dir = tempfile::tempdir().unwrap();
    {
        let backend = create_listing_backend(dir.path().to_path_buf(), true, 4096);
        backend.create_bucket("missing-snapshot").await.unwrap();
        put_listing_object(&backend, "missing-snapshot", "a.txt", b"a").await;
        backend
            .list_objects("missing-snapshot", &ListParams::default())
            .await
            .unwrap();
        std::fs::remove_file(
            backend
                .bucket_listing_dir("missing-snapshot")
                .join("snapshot.json"),
        )
        .unwrap();
    }

    let backend = create_listing_backend(dir.path().to_path_buf(), true, 4096);
    let result = backend
        .list_objects("missing-snapshot", &ListParams::default())
        .await
        .unwrap();
    assert_eq!(result.objects[0].key, "a.txt");
    assert_eq!(
        backend
            .listing_full_builds
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

#[tokio::test]
async fn test_listing_index_legacy_snapshot_rebuilds_sidecars() {
    let dir = tempfile::tempdir().unwrap();
    let snapshot;
    {
        let backend = create_listing_backend(dir.path().to_path_buf(), true, 4096);
        backend.create_bucket("legacy-snapshot").await.unwrap();
        put_listing_object(&backend, "legacy-snapshot", "a.txt", b"a").await;
        backend
            .list_objects("legacy-snapshot", &ListParams::default())
            .await
            .unwrap();
        snapshot = backend
            .bucket_listing_dir("legacy-snapshot")
            .join("snapshot.json");
    }
    std::fs::write(
        &snapshot,
        br#"{"version":1,"checksum":"legacy","entries":[]}"#,
    )
    .unwrap();

    let backend = create_listing_backend(dir.path().to_path_buf(), true, 4096);
    let result = backend
        .list_objects("legacy-snapshot", &ListParams::default())
        .await
        .unwrap();
    assert_eq!(result.objects[0].key, "a.txt");
    assert_eq!(
        backend
            .listing_full_builds
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    let rebuilt: Value = serde_json::from_slice(&std::fs::read(snapshot).unwrap()).unwrap();
    assert_eq!(rebuilt["version"], 3);
}

#[tokio::test]
async fn test_listing_index_compaction_racing_bucket_delete_does_not_resurrect() {
    let dir = tempfile::tempdir().unwrap();
    let backend = create_listing_backend(dir.path().to_path_buf(), true, 1);
    backend.create_bucket("delete-race").await.unwrap();
    put_listing_object(&backend, "delete-race", "a.txt", b"a").await;
    backend
        .list_objects("delete-race", &ListParams::default())
        .await
        .unwrap();
    backend.pause_listing_compactor_after_seal(true);
    put_listing_object(&backend, "delete-race", "b.txt", b"b").await;
    put_listing_object(&backend, "delete-race", "c.txt", b"c").await;
    assert!(
        backend.wait_for_listing_compactor_seal("delete-race", std::time::Duration::from_secs(5))
    );
    for key in ["a.txt", "b.txt", "c.txt"] {
        backend.delete_object("delete-race", key).await.unwrap();
    }
    backend.delete_bucket("delete-race").await.unwrap();
    backend.pause_listing_compactor_after_seal(false);
    backend.shutdown_listing_compactor();
    assert!(!backend.bucket_listing_dir("delete-race").exists());
    assert!(!backend.system_bucket_root("delete-race").exists());
}

#[tokio::test]
async fn test_listing_index_compaction_racing_rebuild_rejects_stale_install() {
    let dir = tempfile::tempdir().unwrap();
    let backend = create_listing_backend(dir.path().to_path_buf(), true, 1);
    backend.create_bucket("rebuild-race").await.unwrap();
    put_listing_object(&backend, "rebuild-race", "a.txt", b"a").await;
    backend
        .list_objects("rebuild-race", &ListParams::default())
        .await
        .unwrap();
    backend.pause_listing_compactor_after_seal(true);
    put_listing_object(&backend, "rebuild-race", "b.txt", b"b").await;
    put_listing_object(&backend, "rebuild-race", "c.txt", b"c").await;
    assert!(
        backend.wait_for_listing_compactor_seal("rebuild-race", std::time::Duration::from_secs(5))
    );
    assert_eq!(
        backend.rebuild_listing_index_sync("rebuild-race").unwrap(),
        3
    );
    let snapshot = backend
        .bucket_listing_dir("rebuild-race")
        .join("snapshot.json");
    let rebuilt = std::fs::read(&snapshot).unwrap();
    backend.pause_listing_compactor_after_seal(false);
    backend.shutdown_listing_compactor();
    assert_eq!(std::fs::read(snapshot).unwrap(), rebuilt);
}

#[tokio::test]
async fn test_listing_index_backend_drop_drains_pending_compaction() {
    let dir = tempfile::tempdir().unwrap();
    let snapshot;
    {
        let backend = create_listing_backend(dir.path().to_path_buf(), true, 1);
        backend.create_bucket("drop-drain").await.unwrap();
        put_listing_object(&backend, "drop-drain", "a.txt", b"a").await;
        backend
            .list_objects("drop-drain", &ListParams::default())
            .await
            .unwrap();
        put_listing_object(&backend, "drop-drain", "b.txt", b"b").await;
        put_listing_object(&backend, "drop-drain", "c.txt", b"c").await;
        snapshot = backend
            .bucket_listing_dir("drop-drain")
            .join("snapshot.json");
    }
    let compacted: Value = serde_json::from_slice(&std::fs::read(snapshot).unwrap()).unwrap();
    assert_eq!(compacted["high_water_generation"], 1);
}

#[tokio::test]
async fn test_listing_index_disabled_uses_legacy_cache_only() {
    let dir = tempfile::tempdir().unwrap();
    let backend = create_listing_backend(dir.path().to_path_buf(), false, 1);
    backend.create_bucket("legacy-list").await.unwrap();
    put_listing_object(&backend, "legacy-list", "a.txt", b"a").await;
    let first = backend
        .list_objects("legacy-list", &ListParams::default())
        .await
        .unwrap();
    assert_eq!(first.objects.len(), 1);
    assert!(backend.list_cache.contains_key("legacy-list"));
    assert_eq!(
        backend
            .listing_full_builds
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    backend
        .list_objects("legacy-list", &ListParams::default())
        .await
        .unwrap();
    assert_eq!(
        backend
            .listing_full_builds
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    assert!(!backend.bucket_listing_dir("legacy-list").exists());
}

#[tokio::test]
async fn test_rebuild_listing_index_sync_writes_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let backend = create_listing_backend(dir.path().to_path_buf(), true, 4096);
    backend.create_bucket("force-list").await.unwrap();
    put_listing_object(&backend, "force-list", "a.txt", b"a").await;
    put_listing_object(&backend, "force-list", "b.txt", b"b").await;
    assert_eq!(backend.rebuild_listing_index_sync("force-list").unwrap(), 2);
    assert!(backend
        .bucket_listing_dir("force-list")
        .join("snapshot.json")
        .is_file());
    let result = backend
        .list_objects("force-list", &ListParams::default())
        .await
        .unwrap();
    assert_eq!(result.objects.len(), 2);
}

#[tokio::test]
async fn test_listing_counter_randomized_mutations_match_full_walk() {
    let dir = tempfile::tempdir().unwrap();
    let backend = create_listing_backend(dir.path().to_path_buf(), true, 4096);
    let bucket = "counter-equivalence";
    backend.create_bucket(bucket).await.unwrap();
    backend
        .list_objects(bucket, &ListParams::default())
        .await
        .unwrap();
    put_listing_object(&backend, bucket, "source", b"source-data").await;
    assert_counter_equivalence(&backend, bucket);

    put_listing_object(&backend, bucket, "target", b"off-a").await;
    assert_counter_equivalence(&backend, bucket);
    put_listing_object(&backend, bucket, "target", b"off-replacement").await;
    assert_counter_equivalence(&backend, bucket);

    backend
        .set_versioning_status(bucket, VersioningStatus::Enabled)
        .await
        .unwrap();
    put_listing_object(&backend, bucket, "target", b"enabled-a").await;
    assert_counter_equivalence(&backend, bucket);
    put_listing_object(&backend, bucket, "target", b"enabled-replacement").await;
    assert_counter_equivalence(&backend, bucket);
    backend
        .copy_object(bucket, "source", bucket, "target")
        .await
        .unwrap();
    assert_counter_equivalence(&backend, bucket);
    let marker = backend.delete_object(bucket, "target").await.unwrap();
    assert_counter_equivalence(&backend, bucket);
    backend
        .delete_object_version(bucket, "target", marker.version_id.as_deref().unwrap())
        .await
        .unwrap();
    assert_counter_equivalence(&backend, bucket);

    backend
        .set_versioning_status(bucket, VersioningStatus::Suspended)
        .await
        .unwrap();
    put_listing_object(&backend, bucket, "target", b"suspended-null").await;
    assert_counter_equivalence(&backend, bucket);
    put_listing_object(&backend, bucket, "target", b"suspended-replacement").await;
    assert_counter_equivalence(&backend, bucket);
    complete_listing_multipart(&backend, bucket, "target", b"multipart-replacement").await;
    assert_counter_equivalence(&backend, bucket);

    let mut seed = 0x5a17_93c4_u64;
    for step in 0..36u64 {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        let key = format!("key-{}", (seed >> 32) % 5);
        match seed % 6 {
            0 => {
                let status = match (seed >> 8) % 3 {
                    0 => VersioningStatus::Disabled,
                    1 => VersioningStatus::Enabled,
                    _ => VersioningStatus::Suspended,
                };
                backend.set_versioning_status(bucket, status).await.unwrap();
                let body = vec![b'a' + (step % 26) as u8; (step as usize % 19) + 1];
                put_listing_object(&backend, bucket, &key, &body).await;
            }
            1 => {
                backend
                    .copy_object(bucket, "source", bucket, &key)
                    .await
                    .unwrap();
            }
            2 => {
                backend.delete_object(bucket, &key).await.unwrap();
            }
            3 => {
                let versions = backend.list_object_versions(bucket, &key).await.unwrap();
                if let Some(version) = versions.iter().find(|version| !version.is_latest) {
                    backend
                        .delete_object_version(bucket, &key, &version.version_id)
                        .await
                        .unwrap();
                }
            }
            4 => {
                let body = vec![b'0' + (step % 10) as u8; (step as usize % 23) + 1];
                complete_listing_multipart(&backend, bucket, &key, &body).await;
            }
            _ => {
                backend
                    .set_versioning_status(bucket, VersioningStatus::Enabled)
                    .await
                    .unwrap();
                let marker = backend.delete_object(bucket, &key).await.unwrap();
                if marker.is_delete_marker {
                    backend
                        .delete_object_version(bucket, &key, marker.version_id.as_deref().unwrap())
                        .await
                        .unwrap();
                }
            }
        }
        assert_counter_equivalence(&backend, bucket);
    }
}

#[test]
fn test_listing_counter_snapshot_replay_generation_fence_prevents_double_count() {
    let dir = tempfile::tempdir().unwrap();
    let listing_dir = dir.path().join("listing");
    let mut index = BucketListingIndex::from_records(listing_dir.clone(), Vec::new(), 1);
    index.persist_rebuilt().unwrap();
    index
        .apply_version_mutation(&VersionMutation {
            version_id: "v1".to_string(),
            kind: VersionMutationKind::Archive,
            logical_size: 7,
            delete_marker: false,
        })
        .unwrap();
    index.request_compaction_retry();
    let sealed = index.seal_for_compaction().unwrap().unwrap();
    let bytes = crate::listing_index::prepare_compaction_snapshot(&sealed).unwrap();
    let temp = listing_dir.join("snapshot.tmp");
    crate::listing_index::write_snapshot_temp(&temp, &bytes).unwrap();
    crate::listing_index::install_snapshot_temp(&temp, &listing_dir).unwrap();
    index.complete_compaction_install(&sealed, true);
    index
        .apply_version_mutation(&VersionMutation {
            version_id: "v2".to_string(),
            kind: VersionMutationKind::Archive,
            logical_size: 3,
            delete_marker: false,
        })
        .unwrap();
    drop(index);

    let covered = std::fs::read(listing_dir.join("journal.1.jsonl")).unwrap();
    let mut duplicate = covered.clone();
    duplicate.extend_from_slice(&covered);
    std::fs::write(listing_dir.join("journal.1.jsonl"), duplicate).unwrap();

    let loaded = BucketListingIndex::load(listing_dir, 1).unwrap();
    let counters = loaded.counters();
    assert_eq!(counters.version_count, 2);
    assert_eq!(counters.version_logical_bytes, 10);
}

#[tokio::test]
async fn test_listing_counter_corrupt_journal_rebuilds_equivalent_counters() {
    let dir = tempfile::tempdir().unwrap();
    let journal;
    {
        let backend = create_listing_backend(dir.path().to_path_buf(), true, 4096);
        backend.create_bucket("counter-dirty").await.unwrap();
        backend
            .set_versioning_status("counter-dirty", VersioningStatus::Enabled)
            .await
            .unwrap();
        put_listing_object(&backend, "counter-dirty", "key", b"first").await;
        backend
            .list_objects("counter-dirty", &ListParams::default())
            .await
            .unwrap();
        put_listing_object(&backend, "counter-dirty", "key", b"second").await;
        journal = backend
            .bucket_listing_dir("counter-dirty")
            .join("journal.1.jsonl");
    }
    let bytes = std::fs::read(&journal).unwrap();
    let split = bytes.iter().position(|byte| *byte == b'\n').unwrap() + 1;
    let mut corrupt = Vec::new();
    corrupt.extend_from_slice(&bytes[..split]);
    corrupt.extend_from_slice(b"counter corruption\n");
    corrupt.extend_from_slice(&bytes[split..]);
    std::fs::write(&journal, corrupt).unwrap();

    let backend = create_listing_backend(dir.path().to_path_buf(), true, 4096);
    backend
        .list_objects("counter-dirty", &ListParams::default())
        .await
        .unwrap();
    assert_eq!(
        backend
            .listing_full_builds
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    assert_counter_equivalence(&backend, "counter-dirty");
}

#[tokio::test]
async fn test_listing_counter_unclean_discard_lazy_rebuild_is_equivalent() {
    let dir = tempfile::tempdir().unwrap();
    let backend = create_listing_backend(dir.path().to_path_buf(), true, 4096);
    backend.create_bucket("counter-unclean").await.unwrap();
    backend
        .set_versioning_status("counter-unclean", VersioningStatus::Enabled)
        .await
        .unwrap();
    put_listing_object(&backend, "counter-unclean", "key", b"first").await;
    backend
        .list_objects("counter-unclean", &ListParams::default())
        .await
        .unwrap();
    put_listing_object(&backend, "counter-unclean", "key", b"second").await;
    assert_counter_equivalence(&backend, "counter-unclean");

    backend.invalidate_all_listing_indexes_sync().unwrap();
    assert!(!backend.bucket_listing_dir("counter-unclean").exists());
    let walks_before = backend
        .stats_full_walks
        .load(std::sync::atomic::Ordering::Relaxed);
    backend.bucket_stats("counter-unclean").await.unwrap();
    assert_eq!(
        backend
            .stats_full_walks
            .load(std::sync::atomic::Ordering::Relaxed),
        walks_before + 1
    );
    backend
        .list_objects("counter-unclean", &ListParams::default())
        .await
        .unwrap();
    assert_counter_equivalence(&backend, "counter-unclean");
}

#[tokio::test]
async fn test_bucket_stats_disabled_listing_index_keeps_walk_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let backend = create_listing_backend(dir.path().to_path_buf(), false, 4096);
    backend.create_bucket("stats-fallback").await.unwrap();
    put_listing_object(&backend, "stats-fallback", "key", b"body").await;
    assert_eq!(
        backend
            .stats_full_walks
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    let stats = backend.bucket_stats("stats-fallback").await.unwrap();
    assert_eq!(stats.objects, 1);
    assert_eq!(stats.bytes, 4);
    assert_eq!(
        backend
            .stats_full_walks
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    backend.bucket_stats("stats-fallback").await.unwrap();
    assert_eq!(
        backend
            .stats_full_walks
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

#[tokio::test]
async fn test_quota_put_with_live_listing_counters_performs_no_walk() {
    let dir = tempfile::tempdir().unwrap();
    let backend = create_listing_backend(dir.path().to_path_buf(), true, 4096);
    backend.create_bucket("quota-counter-fast").await.unwrap();
    put_listing_object(&backend, "quota-counter-fast", "first", b"12345").await;
    backend
        .list_objects("quota-counter-fast", &ListParams::default())
        .await
        .unwrap();
    let mut config = backend
        .get_bucket_config("quota-counter-fast")
        .await
        .unwrap();
    config.quota = Some(QuotaConfig {
        max_bytes: Some(100),
        max_objects: Some(10),
    });
    backend
        .set_bucket_config("quota-counter-fast", &config)
        .await
        .unwrap();
    let walks_before = backend
        .stats_full_walks
        .load(std::sync::atomic::Ordering::Relaxed);
    put_listing_object(&backend, "quota-counter-fast", "second", b"67890").await;
    assert_eq!(
        backend
            .stats_full_walks
            .load(std::sync::atomic::Ordering::Relaxed),
        walks_before
    );
    assert_counter_equivalence(&backend, "quota-counter-fast");
}

#[tokio::test]
async fn test_quota_fallback_sequential_puts_use_fresh_walk() {
    let dir = tempfile::tempdir().unwrap();
    let backend = create_listing_backend(dir.path().to_path_buf(), false, 4096);
    backend.create_bucket("quota-fallback-fresh").await.unwrap();
    let mut config = backend
        .get_bucket_config("quota-fallback-fresh")
        .await
        .unwrap();
    config.quota = Some(QuotaConfig {
        max_bytes: Some(10),
        max_objects: None,
    });
    backend
        .set_bucket_config("quota-fallback-fresh", &config)
        .await
        .unwrap();

    put_listing_object(&backend, "quota-fallback-fresh", "first", b"123456").await;
    let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(b"12345".to_vec()));
    assert!(matches!(
        backend
            .put_object("quota-fallback-fresh", "second", stream, None)
            .await
            .unwrap_err(),
        StorageError::QuotaExceeded(_)
    ));
    assert_eq!(
        backend
            .stats_full_walks
            .load(std::sync::atomic::Ordering::Relaxed),
        2
    );
}

#[tokio::test]
async fn test_quota_regressions_match_with_listing_counters_and_walk_fallback() {
    for enabled in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let backend = create_listing_backend(dir.path().to_path_buf(), enabled, 4096);

        backend.create_bucket("quota-mode-versioned").await.unwrap();
        backend
            .set_versioning_status("quota-mode-versioned", VersioningStatus::Enabled)
            .await
            .unwrap();
        put_listing_object(&backend, "quota-mode-versioned", "key", b"12345").await;
        if enabled {
            backend
                .list_objects("quota-mode-versioned", &ListParams::default())
                .await
                .unwrap();
        }
        let mut config = backend
            .get_bucket_config("quota-mode-versioned")
            .await
            .unwrap();
        config.quota = Some(QuotaConfig {
            max_bytes: Some(5),
            max_objects: Some(2),
        });
        backend
            .set_bucket_config("quota-mode-versioned", &config)
            .await
            .unwrap();
        let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(b"x".to_vec()));
        assert!(matches!(
            backend
                .put_object("quota-mode-versioned", "key", stream, None)
                .await
                .unwrap_err(),
            StorageError::QuotaExceeded(_)
        ));
        config.quota = Some(QuotaConfig {
            max_bytes: Some(100),
            max_objects: Some(1),
        });
        backend
            .set_bucket_config("quota-mode-versioned", &config)
            .await
            .unwrap();
        let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(b"x".to_vec()));
        assert!(matches!(
            backend
                .put_object("quota-mode-versioned", "key", stream, None)
                .await
                .unwrap_err(),
            StorageError::QuotaExceeded(_)
        ));

        backend.create_bucket("quota-mode-suspended").await.unwrap();
        backend
            .set_versioning_status("quota-mode-suspended", VersioningStatus::Enabled)
            .await
            .unwrap();
        put_listing_object(&backend, "quota-mode-suspended", "key", b"1234567").await;
        backend
            .set_versioning_status("quota-mode-suspended", VersioningStatus::Suspended)
            .await
            .unwrap();
        if enabled {
            backend
                .list_objects("quota-mode-suspended", &ListParams::default())
                .await
                .unwrap();
        }
        let mut config = backend
            .get_bucket_config("quota-mode-suspended")
            .await
            .unwrap();
        config.quota = Some(QuotaConfig {
            max_bytes: Some(15),
            max_objects: Some(2),
        });
        backend
            .set_bucket_config("quota-mode-suspended", &config)
            .await
            .unwrap();
        let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(b"123456789".to_vec()));
        assert!(matches!(
            backend
                .put_object("quota-mode-suspended", "key", stream, None)
                .await
                .unwrap_err(),
            StorageError::QuotaExceeded(_)
        ));
        config.quota = Some(QuotaConfig {
            max_bytes: Some(16),
            max_objects: Some(2),
        });
        backend
            .set_bucket_config("quota-mode-suspended", &config)
            .await
            .unwrap();
        put_listing_object(&backend, "quota-mode-suspended", "key", b"123456789").await;

        backend
            .create_bucket("quota-mode-suspended-null")
            .await
            .unwrap();
        put_listing_object(&backend, "quota-mode-suspended-null", "key", b"12345").await;
        backend
            .set_versioning_status("quota-mode-suspended-null", VersioningStatus::Enabled)
            .await
            .unwrap();
        put_listing_object(&backend, "quota-mode-suspended-null", "key", b"1234567").await;
        backend
            .set_versioning_status("quota-mode-suspended-null", VersioningStatus::Suspended)
            .await
            .unwrap();
        if enabled {
            backend
                .list_objects("quota-mode-suspended-null", &ListParams::default())
                .await
                .unwrap();
        }
        let mut config = backend
            .get_bucket_config("quota-mode-suspended-null")
            .await
            .unwrap();
        config.quota = Some(QuotaConfig {
            max_bytes: Some(15),
            max_objects: Some(2),
        });
        backend
            .set_bucket_config("quota-mode-suspended-null", &config)
            .await
            .unwrap();
        let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(b"123456789".to_vec()));
        assert!(matches!(
            backend
                .put_object("quota-mode-suspended-null", "key", stream, None)
                .await
                .unwrap_err(),
            StorageError::QuotaExceeded(_)
        ));
        config.quota = Some(QuotaConfig {
            max_bytes: Some(16),
            max_objects: Some(2),
        });
        backend
            .set_bucket_config("quota-mode-suspended-null", &config)
            .await
            .unwrap();
        put_listing_object(&backend, "quota-mode-suspended-null", "key", b"123456789").await;

        backend.create_bucket("quota-mode-delete").await.unwrap();
        backend
            .set_versioning_status("quota-mode-delete", VersioningStatus::Enabled)
            .await
            .unwrap();
        let version_id = backend
            .put_object(
                "quota-mode-delete",
                "key",
                Box::pin(std::io::Cursor::new(b"data".to_vec())),
                None,
            )
            .await
            .unwrap()
            .version_id
            .unwrap();
        if enabled {
            backend
                .list_objects("quota-mode-delete", &ListParams::default())
                .await
                .unwrap();
        }
        backend
            .delete_object("quota-mode-delete", "key")
            .await
            .unwrap();
        let stats = backend.bucket_stats("quota-mode-delete").await.unwrap();
        assert_eq!(stats.total_bytes(), 4);
        assert_eq!(stats.total_objects(), 1);
        backend
            .delete_object_version("quota-mode-delete", "key", &version_id)
            .await
            .unwrap();
        let stats = backend.bucket_stats("quota-mode-delete").await.unwrap();
        assert_eq!(stats.total_bytes(), 0);
        assert_eq!(stats.total_objects(), 0);
    }
}

#[tokio::test]
async fn test_versioned_overwrite_rejected_at_quota_limit() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("quota-versioned").await.unwrap();
    backend
        .set_versioning_status("quota-versioned", VersioningStatus::Enabled)
        .await
        .unwrap();
    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"12345".to_vec()));
    backend
        .put_object("quota-versioned", "key", data, None)
        .await
        .unwrap();

    let mut config = backend.get_bucket_config("quota-versioned").await.unwrap();
    config.quota = Some(QuotaConfig {
        max_bytes: Some(5),
        max_objects: Some(2),
    });
    backend
        .set_bucket_config("quota-versioned", &config)
        .await
        .unwrap();
    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"x".to_vec()));
    let err = backend
        .put_object("quota-versioned", "key", data, None)
        .await
        .unwrap_err();
    assert!(matches!(err, StorageError::QuotaExceeded(_)));

    config.quota = Some(QuotaConfig {
        max_bytes: Some(100),
        max_objects: Some(1),
    });
    backend
        .set_bucket_config("quota-versioned", &config)
        .await
        .unwrap();
    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"x".to_vec()));
    let err = backend
        .put_object("quota-versioned", "key", data, None)
        .await
        .unwrap_err();
    assert!(matches!(err, StorageError::QuotaExceeded(_)));

    let stats = backend.bucket_stats("quota-versioned").await.unwrap();
    assert_eq!(stats.total_bytes(), 5);
    assert_eq!(stats.total_objects(), 1);
}

#[tokio::test]
async fn test_suspended_overwrite_quota_without_archived_null_version() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("quota-suspended").await.unwrap();
    backend
        .set_versioning_status("quota-suspended", VersioningStatus::Enabled)
        .await
        .unwrap();
    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"1234567".to_vec()));
    backend
        .put_object("quota-suspended", "key", data, None)
        .await
        .unwrap();
    backend
        .set_versioning_status("quota-suspended", VersioningStatus::Suspended)
        .await
        .unwrap();

    let mut config = backend.get_bucket_config("quota-suspended").await.unwrap();
    config.quota = Some(QuotaConfig {
        max_bytes: Some(15),
        max_objects: Some(2),
    });
    backend
        .set_bucket_config("quota-suspended", &config)
        .await
        .unwrap();
    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"123456789".to_vec()));
    let err = backend
        .put_object("quota-suspended", "key", data, None)
        .await
        .unwrap_err();
    assert!(matches!(err, StorageError::QuotaExceeded(_)));

    config.quota = Some(QuotaConfig {
        max_bytes: Some(16),
        max_objects: Some(2),
    });
    backend
        .set_bucket_config("quota-suspended", &config)
        .await
        .unwrap();
    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"123456789".to_vec()));
    backend
        .put_object("quota-suspended", "key", data, None)
        .await
        .unwrap();

    let stats = backend.bucket_stats("quota-suspended").await.unwrap();
    assert_eq!(stats.total_bytes(), 16);
    assert_eq!(stats.total_objects(), 2);
}

#[tokio::test]
async fn test_suspended_overwrite_quota_with_archived_null_version() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("quota-suspended-null").await.unwrap();
    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"12345".to_vec()));
    backend
        .put_object("quota-suspended-null", "key", data, None)
        .await
        .unwrap();
    backend
        .set_versioning_status("quota-suspended-null", VersioningStatus::Enabled)
        .await
        .unwrap();
    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"1234567".to_vec()));
    backend
        .put_object("quota-suspended-null", "key", data, None)
        .await
        .unwrap();
    backend
        .set_versioning_status("quota-suspended-null", VersioningStatus::Suspended)
        .await
        .unwrap();

    let mut config = backend
        .get_bucket_config("quota-suspended-null")
        .await
        .unwrap();
    config.quota = Some(QuotaConfig {
        max_bytes: Some(15),
        max_objects: Some(2),
    });
    backend
        .set_bucket_config("quota-suspended-null", &config)
        .await
        .unwrap();
    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"123456789".to_vec()));
    let err = backend
        .put_object("quota-suspended-null", "key", data, None)
        .await
        .unwrap_err();
    assert!(matches!(err, StorageError::QuotaExceeded(_)));

    config.quota = Some(QuotaConfig {
        max_bytes: Some(16),
        max_objects: Some(2),
    });
    backend
        .set_bucket_config("quota-suspended-null", &config)
        .await
        .unwrap();
    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"123456789".to_vec()));
    backend
        .put_object("quota-suspended-null", "key", data, None)
        .await
        .unwrap();

    let stats = backend.bucket_stats("quota-suspended-null").await.unwrap();
    assert_eq!(stats.total_bytes(), 16);
    assert_eq!(stats.total_objects(), 2);
    let (null_manifest, null_data) =
        backend.version_record_paths("quota-suspended-null", "key", "null");
    assert!(!null_manifest.exists());
    assert!(!null_data.exists());
}

#[tokio::test]
async fn test_delete_marker_preserves_quota_accounting_until_version_purge() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("quota-delete").await.unwrap();
    backend
        .set_versioning_status("quota-delete", VersioningStatus::Enabled)
        .await
        .unwrap();
    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"data".to_vec()));
    let version_id = backend
        .put_object("quota-delete", "key", data, None)
        .await
        .unwrap()
        .version_id
        .unwrap();

    let outcome = backend.delete_object("quota-delete", "key").await.unwrap();
    assert!(outcome.is_delete_marker);
    let stats = backend.bucket_stats("quota-delete").await.unwrap();
    assert_eq!(stats.total_bytes(), 4);
    assert_eq!(stats.total_objects(), 1);

    backend
        .delete_object_version("quota-delete", "key", &version_id)
        .await
        .unwrap();
    let stats = backend.bucket_stats("quota-delete").await.unwrap();
    assert_eq!(stats.total_bytes(), 0);
    assert_eq!(stats.total_objects(), 0);
}
