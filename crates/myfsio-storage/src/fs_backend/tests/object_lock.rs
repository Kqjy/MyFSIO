use super::*;

#[tokio::test]
async fn update_object_retention_rejects_compliance_shortening() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("retention").await.unwrap();
    let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(b"payload".to_vec()));
    backend
        .put_object("retention", "locked.bin", stream, None)
        .await
        .unwrap();

    let far = myfsio_common::object_lock::ObjectLockRetention {
        mode: myfsio_common::object_lock::RetentionMode::COMPLIANCE,
        retain_until_date: Utc::now() + chrono::Duration::days(10),
    };
    backend
        .update_object_retention("retention", "locked.bin", None, &far, false)
        .await
        .unwrap();

    let nearer = myfsio_common::object_lock::ObjectLockRetention {
        mode: myfsio_common::object_lock::RetentionMode::COMPLIANCE,
        retain_until_date: Utc::now() + chrono::Duration::days(1),
    };
    for bypass in [false, true] {
        let err = backend
            .update_object_retention("retention", "locked.bin", None, &nearer, bypass)
            .await
            .unwrap_err();
        assert!(matches!(err, StorageError::ObjectLocked(_)));
    }

    let further = myfsio_common::object_lock::ObjectLockRetention {
        mode: myfsio_common::object_lock::RetentionMode::COMPLIANCE,
        retain_until_date: Utc::now() + chrono::Duration::days(20),
    };
    backend
        .update_object_retention("retention", "locked.bin", None, &further, false)
        .await
        .unwrap();

    let metadata = backend
        .get_object_metadata("retention", "locked.bin")
        .await
        .unwrap();
    let stored = myfsio_common::object_lock::get_object_retention(&metadata).unwrap();
    assert_eq!(stored.retain_until_date, further.retain_until_date);
}

#[tokio::test]
async fn update_object_retention_extends_governance_without_bypass() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("governance").await.unwrap();
    let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(b"payload".to_vec()));
    backend
        .put_object("governance", "obj.bin", stream, None)
        .await
        .unwrap();

    let initial = myfsio_common::object_lock::ObjectLockRetention {
        mode: myfsio_common::object_lock::RetentionMode::GOVERNANCE,
        retain_until_date: Utc::now() + chrono::Duration::days(5),
    };
    backend
        .update_object_retention("governance", "obj.bin", None, &initial, false)
        .await
        .unwrap();

    let longer = myfsio_common::object_lock::ObjectLockRetention {
        mode: myfsio_common::object_lock::RetentionMode::GOVERNANCE,
        retain_until_date: Utc::now() + chrono::Duration::days(9),
    };
    backend
        .update_object_retention("governance", "obj.bin", None, &longer, false)
        .await
        .unwrap();

    let shorter = myfsio_common::object_lock::ObjectLockRetention {
        mode: myfsio_common::object_lock::RetentionMode::GOVERNANCE,
        retain_until_date: Utc::now() + chrono::Duration::days(1),
    };
    let err = backend
        .update_object_retention("governance", "obj.bin", None, &shorter, false)
        .await
        .unwrap_err();
    assert!(matches!(err, StorageError::ObjectLocked(_)));
    backend
        .update_object_retention("governance", "obj.bin", None, &shorter, true)
        .await
        .unwrap();

    let metadata = backend
        .get_object_metadata("governance", "obj.bin")
        .await
        .unwrap();
    let stored = myfsio_common::object_lock::get_object_retention(&metadata).unwrap();
    assert_eq!(stored.retain_until_date, shorter.retain_until_date);
}

#[tokio::test]
async fn update_object_legal_hold_preserves_retention() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("legalhold").await.unwrap();
    let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(b"payload".to_vec()));
    backend
        .put_object("legalhold", "obj.bin", stream, None)
        .await
        .unwrap();

    let retention = myfsio_common::object_lock::ObjectLockRetention {
        mode: myfsio_common::object_lock::RetentionMode::GOVERNANCE,
        retain_until_date: Utc::now() + chrono::Duration::days(3),
    };
    backend
        .update_object_retention("legalhold", "obj.bin", None, &retention, false)
        .await
        .unwrap();
    backend
        .update_object_legal_hold("legalhold", "obj.bin", None, true)
        .await
        .unwrap();

    let metadata = backend
        .get_object_metadata("legalhold", "obj.bin")
        .await
        .unwrap();
    assert!(myfsio_common::object_lock::get_legal_hold(&metadata));
    let stored = myfsio_common::object_lock::get_object_retention(&metadata).unwrap();
    assert_eq!(stored.retain_until_date, retention.retain_until_date);
}

#[tokio::test]
async fn update_object_retention_applies_to_archived_versions() {
    let (_dir, backend) = create_test_backend();
    backend.create_bucket("versioned-lock").await.unwrap();
    backend
        .set_versioning_status("versioned-lock", VersioningStatus::Enabled)
        .await
        .unwrap();
    put_listing_object(&backend, "versioned-lock", "obj.bin", b"v1").await;
    put_listing_object(&backend, "versioned-lock", "obj.bin", b"v2").await;

    let versions = backend
        .list_object_versions("versioned-lock", "obj.bin")
        .await
        .unwrap();
    let archived = versions
        .iter()
        .find(|version| !version.is_latest)
        .expect("expected an archived version");

    let retention = myfsio_common::object_lock::ObjectLockRetention {
        mode: myfsio_common::object_lock::RetentionMode::COMPLIANCE,
        retain_until_date: Utc::now() + chrono::Duration::days(5),
    };
    backend
        .update_object_retention(
            "versioned-lock",
            "obj.bin",
            Some(&archived.version_id),
            &retention,
            false,
        )
        .await
        .unwrap();

    let metadata = backend
        .get_object_version_metadata("versioned-lock", "obj.bin", &archived.version_id)
        .await
        .unwrap();
    let stored = myfsio_common::object_lock::get_object_retention(&metadata).unwrap();
    assert_eq!(stored.retain_until_date, retention.retain_until_date);

    let shorter = myfsio_common::object_lock::ObjectLockRetention {
        mode: myfsio_common::object_lock::RetentionMode::GOVERNANCE,
        retain_until_date: Utc::now() + chrono::Duration::days(1),
    };
    let err = backend
        .update_object_retention(
            "versioned-lock",
            "obj.bin",
            Some(&archived.version_id),
            &shorter,
            true,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, StorageError::ObjectLocked(_)));
}
