use super::*;

#[tokio::test]
async fn recovery_discards_staged_sidecars_without_a_destination() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("rec-legacy").await.unwrap();
    put_listing_object(&backend, "rec-legacy", "obj.bin", b"v1").await;

    let tmp_dir = backend.tmp_dir();
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let staged = tmp_dir.join("legacy.sidecar-stage");
    std::fs::write(
        &staged,
        serde_json::json!({
            "metadata": {"__etag__": "\"deadbeef\"", "__size__": "2"},
            "__entry_name__": "obj.bin"
        })
        .to_string(),
    )
    .unwrap();

    let recovery = backend.recover_staged_commits_sync().unwrap();
    assert_eq!(recovery.discarded, 1);
    assert!(recovery.published.is_empty());
    assert!(!staged.exists());
    let meta = backend
        .get_object_metadata("rec-legacy", "obj.bin")
        .await
        .unwrap();
    assert!(
        meta.get("__etag__").is_some_and(|e| e != "\"deadbeef\""),
        "a destination-less staged sidecar must never be published"
    );
}

#[tokio::test]
async fn recovery_hashes_indistinguishable_overwrites_to_the_surviving_write() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("rec-hash").await.unwrap();
    put_listing_object(&backend, "rec-hash", "obj.bin", b"v1").await;
    let before = backend
        .get_object_metadata("rec-hash", "obj.bin")
        .await
        .unwrap();
    let live = backend.object_live_path("rec-hash", "obj.bin");
    let live_len = std::fs::metadata(&live).unwrap().len();
    let mtime = before.get("__last_modified__").cloned().unwrap();

    let staged = write_crafted_stage(
        &backend,
        "collision-lost",
        "rec-hash",
        "obj.bin",
        "0000000000000000000000000000feed",
        live_len,
        &mtime,
        &[],
    );
    let recovery = backend.recover_staged_commits_sync().unwrap();
    assert_eq!(
        recovery.discarded, 1,
        "when the live data hashes to the published object, the staged commit lost"
    );
    assert!(recovery.published.is_empty());
    assert_eq!(recovery.poisoned, 0);
    assert!(!staged.exists());
    let after = backend
        .get_object_metadata("rec-hash", "obj.bin")
        .await
        .unwrap();
    assert_eq!(after.get("__etag__"), before.get("__etag__"));

    let real_etag = before.get("__etag__").cloned().unwrap();
    write_crafted_stage(
        &backend,
        "collision-won",
        "rec-hash",
        "obj.bin",
        &real_etag,
        live_len,
        &mtime,
        &[("x-amz-meta-recovered", "yes")],
    );
    let recovery = backend.recover_staged_commits_sync().unwrap();
    assert_eq!(
        recovery.published.len(),
        1,
        "when the live data hashes to the staged commit, its sidecar must be published"
    );
    let after = backend
        .get_object_metadata("rec-hash", "obj.bin")
        .await
        .unwrap();
    assert_eq!(
        after.get("x-amz-meta-recovered").map(String::as_str),
        Some("yes")
    );
}

#[tokio::test]
async fn recovery_poisons_unattributable_commits_so_reads_fail_closed() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("rec-poison").await.unwrap();
    put_listing_object(&backend, "rec-poison", "obj.bin", b"v1").await;
    let before = backend
        .get_object_metadata("rec-poison", "obj.bin")
        .await
        .unwrap();
    let live = backend.object_live_path("rec-poison", "obj.bin");
    let live_len = std::fs::metadata(&live).unwrap().len();
    let mtime = before.get("__last_modified__").cloned().unwrap();

    let staged = write_crafted_stage(
        &backend,
        "torn",
        "rec-poison",
        "obj.bin",
        "0000000000000000000000000000feed",
        live_len + 7,
        &mtime,
        &[],
    );
    let recovery = backend.recover_staged_commits_sync().unwrap();
    assert_eq!(
        recovery.poisoned, 1,
        "a commit that cannot be attributed to either write must be poisoned"
    );
    assert!(recovery.published.is_empty());
    assert!(
        staged.exists(),
        "the poisoned commit's staged sidecar must remain for inspection"
    );
    let after = backend.read_metadata_sync("rec-poison", "obj.bin");
    assert_eq!(
        after.get(META_KEY_CORRUPTED).map(String::as_str),
        Some("true"),
        "the object must be marked corrupted so reads fail closed"
    );
}

#[tokio::test]
async fn recovery_publishes_same_etag_commits_with_differing_metadata() {
    let _fp = failpoint_test_guard();
    let (_dir, backend) = create_test_backend();
    let backend = std::sync::Arc::new(backend);
    backend.create_bucket("rec-samect").await.unwrap();
    put_listing_object(&backend, "rec-samect", "obj.bin", b"same-bytes").await;
    let before = backend
        .get_object_metadata("rec-samect", "obj.bin")
        .await
        .unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    crate::failpoints::set(
        &backend.root,
        "put:before-publish-sidecar",
        crate::failpoints::FailAction::Panic,
    );
    let crashed = backend.clone();
    let join = tokio::spawn(async move {
        let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(b"same-bytes".to_vec()));
        crashed
            .put_object("rec-samect", "obj.bin", stream, None)
            .await
    })
    .await;
    crate::failpoints::clear(&backend.root, "put:before-publish-sidecar");
    assert!(join.unwrap_err().is_panic());

    let recovery = backend.recover_staged_commits_sync().unwrap();
    assert_eq!(
        recovery.published.len(),
        1,
        "a same-content overwrite carries new commit metadata (for encrypted objects the \
         data key and nonce) and must be published, not discarded on etag equality"
    );
    let after = backend
        .get_object_metadata("rec-samect", "obj.bin")
        .await
        .unwrap();
    assert_eq!(after.get("__etag__"), before.get("__etag__"));
    assert_ne!(
        after.get("__last_modified__"),
        before.get("__last_modified__"),
        "the recovered metadata must be the staged commit's, not the previous write's"
    );
}

#[tokio::test]
async fn recovery_releases_segments_replaced_by_an_interrupted_overwrite() {
    let _fp = failpoint_test_guard();
    let (_dir, backend) = create_test_backend();
    let backend = std::sync::Arc::new(backend);
    backend.create_bucket("rec-seg").await.unwrap();

    let upload_id = backend
        .initiate_multipart("rec-seg", "obj.bin", None)
        .await
        .unwrap();
    let part1: AsyncReadStream = Box::pin(std::io::Cursor::new(vec![b'A'; 3072]));
    backend
        .upload_part("rec-seg", &upload_id, 1, part1)
        .await
        .unwrap();
    let part2: AsyncReadStream = Box::pin(std::io::Cursor::new(vec![b'B'; 3072]));
    backend
        .upload_part("rec-seg", &upload_id, 2, part2)
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
    backend
        .complete_multipart("rec-seg", &upload_id, &parts)
        .await
        .unwrap();
    let segment_dir = backend.segments_bucket_root("rec-seg").join(&upload_id);
    assert!(segment_dir.is_dir());

    crate::failpoints::set(
        &backend.root,
        "put:before-publish-sidecar",
        crate::failpoints::FailAction::Panic,
    );
    let crashed = backend.clone();
    let join = tokio::spawn(async move {
        let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(b"plain-v2".to_vec()));
        crashed.put_object("rec-seg", "obj.bin", stream, None).await
    })
    .await;
    crate::failpoints::clear(&backend.root, "put:before-publish-sidecar");
    assert!(join.unwrap_err().is_panic());

    let recovery = backend.recover_staged_commits_sync().unwrap();
    assert_eq!(recovery.published.len(), 1);
    assert!(
        !segment_dir.exists(),
        "recovery must replay the release of the replaced segment directory"
    );
    let (_, mut stream) = backend.get_object("rec-seg", "obj.bin").await.unwrap();
    let mut body = Vec::new();
    stream.read_to_end(&mut body).await.unwrap();
    assert_eq!(body, b"plain-v2");
}

#[tokio::test]
async fn recovery_attributes_undigestable_commits_only_when_identities_differ() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("rec-enc").await.unwrap();
    put_listing_object(&backend, "rec-enc", "attributed.bin", b"ciphertext-a").await;
    put_listing_object(&backend, "rec-enc", "collided.bin", b"ciphertext-b").await;
    put_listing_object(&backend, "rec-enc", "unknown.bin", b"ciphertext-c").await;

    let (len_a, ns_a, mtime_a) = live_ns(&backend, "rec-enc", "attributed.bin");
    alter_recorded_commit_ns(&backend, "rec-enc", "attributed.bin", Some(ns_a - 777));
    write_crafted_stage(
        &backend,
        "enc-attributed",
        "rec-enc",
        "attributed.bin",
        "0000000000000000000000000000cafe",
        len_a,
        &mtime_a,
        &[
            ("x-amz-server-side-encryption", "AES256"),
            (META_KEY_COMMIT_MTIME_NS, &ns_a.to_string()),
        ],
    );

    let (len_b, ns_b, mtime_b) = live_ns(&backend, "rec-enc", "collided.bin");
    write_crafted_stage(
        &backend,
        "enc-collided",
        "rec-enc",
        "collided.bin",
        "0000000000000000000000000000cafe",
        len_b,
        &mtime_b,
        &[
            ("x-amz-server-side-encryption", "AES256"),
            (META_KEY_COMMIT_MTIME_NS, &ns_b.to_string()),
        ],
    );

    let (len_c, ns_c, mtime_c) = live_ns(&backend, "rec-enc", "unknown.bin");
    alter_recorded_commit_ns(&backend, "rec-enc", "unknown.bin", None);
    write_crafted_stage(
        &backend,
        "enc-unknown",
        "rec-enc",
        "unknown.bin",
        "0000000000000000000000000000cafe",
        len_c,
        &mtime_c,
        &[
            ("x-amz-server-side-encryption", "AES256"),
            (META_KEY_COMMIT_MTIME_NS, &ns_c.to_string()),
        ],
    );

    let recovery = backend.recover_staged_commits_sync().unwrap();
    assert_eq!(
        recovery.published.len(),
        1,
        "the filesystem identity attributes the live data only when it differs from the \
         previously recorded commit identity"
    );
    assert_eq!(
        recovery.poisoned, 2,
        "a timestamp equal to the previous commit's, or a previous commit with no recorded \
         identity, is ambiguous and the opaque-etag object must be poisoned"
    );
    let after_a = backend.read_metadata_sync("rec-enc", "attributed.bin");
    assert_eq!(
        after_a
            .get("x-amz-server-side-encryption")
            .map(String::as_str),
        Some("AES256")
    );
    assert!(!after_a.contains_key(META_KEY_CORRUPTED));
    let after_b = backend.read_metadata_sync("rec-enc", "collided.bin");
    assert_eq!(
        after_b.get(META_KEY_CORRUPTED).map(String::as_str),
        Some("true")
    );
    let after_c = backend.read_metadata_sync("rec-enc", "unknown.bin");
    assert_eq!(
        after_c.get(META_KEY_CORRUPTED).map(String::as_str),
        Some("true")
    );
    backend
        .finish_recovered_commit_sync(&recovery.published[0].staged_path)
        .unwrap();
}

#[tokio::test]
async fn runtime_publish_failure_poisons_the_object_and_recovery_heals_it() {
    let _fp = failpoint_test_guard();
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("fp-torn").await.unwrap();
    put_listing_object(&backend, "fp-torn", "obj.bin", b"v1").await;
    let before = backend
        .get_object_metadata("fp-torn", "obj.bin")
        .await
        .unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    crate::failpoints::set(
        &backend.root,
        "put:before-publish-sidecar",
        crate::failpoints::FailAction::Error(std::io::ErrorKind::StorageFull),
    );
    let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(b"v2-longer".to_vec()));
    let result = backend.put_object("fp-torn", "obj.bin", stream, None).await;
    crate::failpoints::clear(&backend.root, "put:before-publish-sidecar");
    assert!(result.is_err(), "the torn commit must fail the request");

    assert_eq!(
        staged_sidecar_count(&backend),
        1,
        "the commit intent must be retained after a runtime publish failure"
    );
    let poisoned = backend.read_metadata_sync("fp-torn", "obj.bin");
    assert_eq!(
        poisoned.get(META_KEY_CORRUPTED).map(String::as_str),
        Some("true"),
        "the torn object must fail closed instead of serving new bytes under old metadata"
    );

    let recovery = backend.recover_staged_commits_sync().unwrap();
    assert_eq!(
        recovery.published.len(),
        1,
        "recovery must attribute the live data to the retained intent and heal the object"
    );
    let healed = backend.read_metadata_sync("fp-torn", "obj.bin");
    assert!(!healed.contains_key(META_KEY_CORRUPTED));
    assert_ne!(healed.get("__etag__"), before.get("__etag__"));
    let (_, mut stream) = backend.get_object("fp-torn", "obj.bin").await.unwrap();
    let mut body = Vec::new();
    stream.read_to_end(&mut body).await.unwrap();
    assert_eq!(body, b"v2-longer");
    backend
        .finish_recovered_commit_sync(&recovery.published[0].staged_path)
        .unwrap();
    assert_eq!(staged_sidecar_count(&backend), 0);
}
