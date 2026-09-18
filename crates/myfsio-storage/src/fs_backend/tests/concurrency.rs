use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_put_delete_list_storm_preserves_invariants() {
    let _stress = filesystem_stress_test_guard();
    let (_dir, backend) = create_test_backend();
    let backend = std::sync::Arc::new(backend);
    backend.create_bucket("storm").await.unwrap();

    const WORKERS: usize = 16;
    const OPS: usize = 250;
    let keys = std::sync::Arc::new(storm_keys());

    let mut handles = Vec::new();
    for worker in 0..WORKERS {
        let backend = backend.clone();
        let keys = keys.clone();
        handles.push(tokio::spawn(async move {
            let mut rng: u64 = 0x9E3779B97F4A7C15u64.wrapping_mul(worker as u64 + 1);
            for op in 0..OPS {
                let roll = storm_rng_next(&mut rng);
                let key = &keys[(roll % keys.len() as u64) as usize];
                match (roll >> 8) % 10 {
                    0..=5 => {
                        let body = format!("w{worker}-o{op}-{key}").into_bytes();
                        let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(body));
                        backend
                            .put_object("storm", key, stream, None)
                            .await
                            .unwrap();
                    }
                    6 | 7 => {
                        backend.delete_object("storm", key).await.unwrap();
                    }
                    8 => {
                        let params = myfsio_common::types::ListParams {
                            prefix: Some("a/".to_string()),
                            max_keys: 1000,
                            ..Default::default()
                        };
                        backend.list_objects("storm", &params).await.unwrap();
                    }
                    _ => match backend.get_object("storm", key).await {
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

    audit_storm_bucket(&backend, "storm").await;

    let stats = backend.bucket_stats("storm").await.unwrap();
    let params = myfsio_common::types::ListParams {
        max_keys: 1000,
        ..Default::default()
    };
    let listed = backend.list_objects("storm", &params).await.unwrap();
    assert_eq!(
        stats.objects,
        listed.objects.len() as u64,
        "bucket stats object count must match the listing"
    );
    assert_eq!(
        stats.bytes,
        listed.objects.iter().map(|o| o.size).sum::<u64>(),
        "bucket stats byte count must match the listing"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_versioned_storm_preserves_invariants() {
    let _stress = filesystem_stress_test_guard();
    let (_dir, backend) = create_test_backend();
    let backend = std::sync::Arc::new(backend);
    backend.create_bucket("storm-ver").await.unwrap();
    backend
        .set_versioning_status("storm-ver", VersioningStatus::Enabled)
        .await
        .unwrap();

    const WORKERS: usize = 12;
    const OPS: usize = 120;
    let keys: std::sync::Arc<Vec<String>> =
        std::sync::Arc::new((0..12).map(|i| format!("v/k{:02}", i)).collect());

    let mut handles = Vec::new();
    for worker in 0..WORKERS {
        let backend = backend.clone();
        let keys = keys.clone();
        handles.push(tokio::spawn(async move {
            let mut rng: u64 = 0xD1B54A32D192ED03u64.wrapping_mul(worker as u64 + 1);
            for op in 0..OPS {
                let roll = storm_rng_next(&mut rng);
                let key = &keys[(roll % keys.len() as u64) as usize];
                match (roll >> 8) % 10 {
                    0..=4 => {
                        let body = format!("vw{worker}-o{op}-{key}").into_bytes();
                        let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(body));
                        backend
                            .put_object("storm-ver", key, stream, None)
                            .await
                            .unwrap();
                    }
                    5 | 6 => {
                        backend.delete_object("storm-ver", key).await.unwrap();
                    }
                    7 => {
                        backend
                            .list_object_versions("storm-ver", key)
                            .await
                            .unwrap();
                    }
                    _ => match backend.get_object("storm-ver", key).await {
                        Ok((_, mut stream)) => {
                            let mut body = Vec::new();
                            stream.read_to_end(&mut body).await.unwrap();
                        }
                        Err(StorageError::ObjectNotFound { .. }) => {}
                        Err(StorageError::DeleteMarker { .. }) => {}
                        Err(e) => panic!("unexpected get error under load: {e}"),
                    },
                }
            }
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }

    audit_storm_bucket(&backend, "storm-ver").await;

    for key in keys.iter() {
        let versions = backend
            .list_object_versions("storm-ver", key)
            .await
            .unwrap();
        let mut seen = std::collections::HashSet::new();
        for version in &versions {
            assert!(
                seen.insert(version.version_id.clone()),
                "duplicate version id {} for {}",
                version.version_id,
                key
            );
        }
        assert!(
            versions.iter().filter(|v| v.is_latest).count() <= 1,
            "at most one version of {} may be latest",
            key
        );
    }
}

#[tokio::test]
async fn version_listing_never_fails_while_the_key_is_being_deleted() {
    let (_dir, backend) = create_test_backend();
    let backend = std::sync::Arc::new(backend);
    backend.create_bucket("ver-race").await.unwrap();
    backend
        .set_versioning_status("ver-race", VersioningStatus::Enabled)
        .await
        .unwrap();

    let writer = {
        let backend = backend.clone();
        tokio::spawn(async move {
            for round in 0..150 {
                let body = format!("body-{round}").into_bytes();
                let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(body));
                backend
                    .put_object("ver-race", "racy.bin", stream, None)
                    .await
                    .unwrap();
                backend.delete_object("ver-race", "racy.bin").await.unwrap();
                let versions = backend
                    .list_object_versions("ver-race", "racy.bin")
                    .await
                    .unwrap();
                for version in versions {
                    let _ = backend
                        .delete_object_version("ver-race", "racy.bin", &version.version_id)
                        .await;
                }
            }
        })
    };

    let lister = {
        let backend = backend.clone();
        tokio::spawn(async move {
            for _ in 0..600 {
                backend
                    .list_object_versions("ver-race", "racy.bin")
                    .await
                    .expect("listing versions must tolerate a concurrent delete");
                tokio::task::yield_now().await;
            }
        })
    };

    writer.await.unwrap();
    lister.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_versions_and_config_reads_during_concurrent_puts() {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc as StdArc;

    let _stress = filesystem_stress_test_guard();
    let (_dir, backend) = create_test_backend();
    let backend = StdArc::new(backend);
    backend.create_bucket("blk-bkt").await.unwrap();
    backend.set_versioning("blk-bkt", true).await.unwrap();

    let stop = StdArc::new(AtomicBool::new(false));
    let mut handles = Vec::new();

    for w in 0..2u32 {
        let b = backend.clone();
        let stop = stop.clone();
        handles.push(tokio::spawn(async move {
            let mut i: u32 = 0;
            while !stop.load(Ordering::Relaxed) {
                let body = vec![b'a' + ((w + i) % 4) as u8; 512];
                let data: AsyncReadStream = Box::pin(std::io::Cursor::new(body));
                let _ = b
                    .put_object("blk-bkt", &format!("obj-{}", w), data, None)
                    .await;
                i = i.wrapping_add(1);
            }
        }));
    }

    let reads = StdArc::new(AtomicU64::new(0));
    let failures = StdArc::new(AtomicU64::new(0));
    for _ in 0..4 {
        let b = backend.clone();
        let stop = stop.clone();
        let reads = reads.clone();
        let failures = failures.clone();
        handles.push(tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                match b.get_bucket_config("blk-bkt").await {
                    Ok(config) => {
                        if config.unreadable || !config.versioning_enabled {
                            failures.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(_) => {
                        failures.fetch_add(1, Ordering::Relaxed);
                    }
                }
                match b.list_bucket_object_versions("blk-bkt", None).await {
                    Ok(_) => {
                        reads.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        failures.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }

    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        let _ = h.await;
    }

    let r = reads.load(Ordering::Relaxed);
    let f = failures.load(Ordering::Relaxed);
    assert!(r > 10, "expected some version listings, got {}", r);
    assert_eq!(
        f, 0,
        "observed {} failed config/version reads during concurrent puts",
        f
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_snapshot_to_link_matches_meta() {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc as StdArc;

    let _stress = filesystem_stress_test_guard();
    let (dir, backend) = create_test_backend();
    let root = dir.path().to_path_buf();
    let backend = StdArc::new(backend);
    backend.create_bucket("link-bkt").await.unwrap();

    let tmp_dir = root.join(".myfsio.sys").join("tmp");
    std::fs::create_dir_all(&tmp_dir).unwrap();

    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(vec![b'a'; 4096]));
    backend
        .put_object("link-bkt", "hot", data, None)
        .await
        .unwrap();

    let stop = StdArc::new(std::sync::atomic::AtomicBool::new(false));
    let mut handles = Vec::new();

    for w in 0..2 {
        let b = backend.clone();
        let stop = stop.clone();
        handles.push(tokio::spawn(async move {
            let mut i: u32 = 0;
            while !stop.load(Ordering::Relaxed) {
                let fill = b'a' + (((w + i) % 3) as u8);
                let size = 2048 + ((w + i) % 3) as usize * 1024;
                let body = vec![fill; size];
                let data: AsyncReadStream = Box::pin(std::io::Cursor::new(body));
                let _ = b.put_object("link-bkt", "hot", data, None).await;
                i = i.wrapping_add(1);
            }
        }));
    }

    let reads = StdArc::new(AtomicU64::new(0));
    let mismatches = StdArc::new(AtomicU64::new(0));
    for _ in 0..4 {
        let b = backend.clone();
        let stop = stop.clone();
        let tmp_dir = tmp_dir.clone();
        let reads = reads.clone();
        let mismatches = mismatches.clone();
        handles.push(tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                let link = tmp_dir.join(format!("lnk-{}", Uuid::new_v4()));
                match b.snapshot_object_to_link("link-bkt", "hot", &link).await {
                    Ok((meta, _source)) => {
                        let bytes = std::fs::read(&link).unwrap_or_default();
                        let md5 = format!("{:x}", Md5::digest(&bytes));
                        reads.fetch_add(1, Ordering::Relaxed);
                        if meta.etag.as_deref() != Some(md5.as_str())
                            || bytes.len() as u64 != meta.size
                        {
                            mismatches.fetch_add(1, Ordering::Relaxed);
                        }
                        let _ = std::fs::remove_file(&link);
                    }
                    Err(_) => {
                        let _ = std::fs::remove_file(&link);
                    }
                }
            }
        }));
    }

    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        let _ = h.await;
    }

    let r = reads.load(Ordering::Relaxed);
    let m = mismatches.load(Ordering::Relaxed);
    assert!(r > 10, "expected some snapshot reads, got {}", r);
    assert_eq!(
        m, 0,
        "observed {} snapshot_to_link results where meta etag/size didn't match the linked bytes, out of {}",
        m, r
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_get_object_snapshot_size_matches_body() {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc as StdArc;
    use tokio::io::AsyncReadExt;

    let _stress = filesystem_stress_test_guard();
    let (_dir, backend) = create_test_backend();
    let backend = StdArc::new(backend);
    backend.create_bucket("snap-bkt").await.unwrap();

    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(vec![b'a'; 1024]));
    backend
        .put_object("snap-bkt", "sz", data, None)
        .await
        .unwrap();

    let stop = StdArc::new(std::sync::atomic::AtomicBool::new(false));
    let mut handles = Vec::new();

    for w in 0..2 {
        let b = backend.clone();
        let stop = stop.clone();
        handles.push(tokio::spawn(async move {
            let mut i: u32 = 0;
            while !stop.load(Ordering::Relaxed) {
                let fill = b'a' + ((w + i) % 20) as u8;
                let size = if i.is_multiple_of(2) { 1024 } else { 2048 };
                let body = vec![fill; size];
                let data: AsyncReadStream = Box::pin(std::io::Cursor::new(body));
                let _ = b.put_object("snap-bkt", "sz", data, None).await;
                i = i.wrapping_add(1);
            }
        }));
    }

    let reads = StdArc::new(AtomicU64::new(0));
    let mismatches = StdArc::new(AtomicU64::new(0));
    for _ in 0..4 {
        let b = backend.clone();
        let stop = stop.clone();
        let reads = reads.clone();
        let mismatches = mismatches.clone();
        handles.push(tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                if let Ok((meta, mut file)) = b.get_object_snapshot("snap-bkt", "sz").await {
                    let mut buf = Vec::new();
                    if file.read_to_end(&mut buf).await.is_ok() {
                        reads.fetch_add(1, Ordering::Relaxed);
                        if buf.len() as u64 != meta.size {
                            mismatches.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
        }));
    }

    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        let _ = h.await;
    }

    let r = reads.load(Ordering::Relaxed);
    let m = mismatches.load(Ordering::Relaxed);
    assert!(r > 10, "expected some snapshot reads, got {}", r);
    assert_eq!(
        m, 0,
        "observed {} snapshots where meta.size didn't match body length, out of {} reads",
        m, r
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_range_get_snapshot_consistency() {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc as StdArc;

    let _stress = filesystem_stress_test_guard();
    let (_dir, backend) = create_test_backend();
    let backend = StdArc::new(backend);
    backend.create_bucket("range-bkt").await.unwrap();

    const SIZE: u64 = 256 * 1024;
    let seed = vec![b'a'; SIZE as usize];
    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(seed));
    backend
        .put_object("range-bkt", "hot", data, None)
        .await
        .unwrap();

    let stop = StdArc::new(std::sync::atomic::AtomicBool::new(false));
    let mut handles = Vec::new();

    for w in 0..2 {
        let b = backend.clone();
        let stop = stop.clone();
        handles.push(tokio::spawn(async move {
            let mut i: u8 = 0;
            while !stop.load(Ordering::Relaxed) {
                let fill = b'a' + ((w as u8 * 7 + i) % 20);
                let body = vec![fill; SIZE as usize];
                let data: AsyncReadStream = Box::pin(std::io::Cursor::new(body));
                let _ = b.put_object("range-bkt", "hot", data, None).await;
                i = i.wrapping_add(1);
            }
        }));
    }

    let reads = StdArc::new(AtomicU64::new(0));
    let mismatches = StdArc::new(AtomicU64::new(0));
    for _ in 0..6 {
        let b = backend.clone();
        let stop = stop.clone();
        let reads = reads.clone();
        let mismatches = mismatches.clone();
        handles.push(tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                let start = 1000u64;
                let len = 4000u64;
                if let Ok((meta, mut stream)) = b
                    .get_object_range("range-bkt", "hot", start, Some(len))
                    .await
                {
                    let mut buf = Vec::with_capacity(len as usize);
                    if stream.read_to_end(&mut buf).await.is_ok() && !buf.is_empty() {
                        let fill = buf[0];
                        let all_match = buf.iter().all(|b| *b == fill);
                        let expected_etag = format!("{:x}", Md5::digest(vec![fill; SIZE as usize]));
                        let etag_ok = meta.etag.as_deref() == Some(expected_etag.as_str());
                        reads.fetch_add(1, Ordering::Relaxed);
                        if !(all_match && etag_ok) {
                            mismatches.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
        }));
    }

    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        let _ = h.await;
    }

    let r = reads.load(Ordering::Relaxed);
    let m = mismatches.load(Ordering::Relaxed);
    assert!(r > 10, "expected some Range GETs, got {}", r);
    assert_eq!(
        m, 0,
        "observed {} Range GETs where etag and body fill byte disagreed, out of {} reads",
        m, r
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_upload_part_copy_snapshot_consistency() {
    use myfsio_common::types::PartInfo;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc as StdArc;

    let _stress = filesystem_stress_test_guard();
    let (_dir, backend) = create_test_backend();
    let backend = StdArc::new(backend);
    backend.create_bucket("mp-bkt").await.unwrap();

    const SIZE: u64 = 64 * 1024;
    let etag_a = format!("{:x}", Md5::digest(vec![b'a'; SIZE as usize]));
    let etag_b = format!("{:x}", Md5::digest(vec![b'b'; SIZE as usize]));

    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(vec![b'a'; SIZE as usize]));
    backend
        .put_object("mp-bkt", "src", data, None)
        .await
        .unwrap();

    let stop = StdArc::new(std::sync::atomic::AtomicBool::new(false));
    let mut handles = Vec::new();

    {
        let b = backend.clone();
        let stop = stop.clone();
        handles.push(tokio::spawn(async move {
            let mut flip = false;
            while !stop.load(Ordering::Relaxed) {
                flip = !flip;
                let fill = if flip { b'a' } else { b'b' };
                let data: AsyncReadStream =
                    Box::pin(std::io::Cursor::new(vec![fill; SIZE as usize]));
                let _ = b.put_object("mp-bkt", "src", data, None).await;
            }
        }));
    }

    let ops = StdArc::new(AtomicU64::new(0));
    let bad = StdArc::new(AtomicU64::new(0));
    for _ in 0..4 {
        let b = backend.clone();
        let stop = stop.clone();
        let etag_a = etag_a.clone();
        let etag_b = etag_b.clone();
        let ops = ops.clone();
        let bad = bad.clone();
        handles.push(tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                let upload_id = match b.initiate_multipart("mp-bkt", "dst", None).await {
                    Ok(u) => u,
                    Err(_) => continue,
                };
                let res = b
                    .upload_part_copy("mp-bkt", &upload_id, 1, "mp-bkt", "src", None, None)
                    .await;
                if let Ok((etag, _lm)) = res {
                    if etag != etag_a && etag != etag_b {
                        bad.fetch_add(1, Ordering::Relaxed);
                    }
                    ops.fetch_add(1, Ordering::Relaxed);
                }
                let _ = b.abort_multipart("mp-bkt", &upload_id).await;
            }
        }));
    }

    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        let _ = h.await;
    }

    let o = ops.load(Ordering::Relaxed);
    let x = bad.load(Ordering::Relaxed);
    assert!(
        o >= 4,
        "expected at least a few upload_part_copy ops, got {}",
        o
    );
    assert_eq!(
        x, 0,
        "observed {} upload_part_copy results with etag unrelated to source content (out of {})",
        x, o
    );
    let _ = PartInfo {
        part_number: 1,
        etag: etag_a,
    };
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_contention_does_not_stall_other_async_tasks() {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc as StdArc;

    let _stress = filesystem_stress_test_guard();
    let (_dir, backend) = create_test_backend();
    let backend = StdArc::new(backend);
    backend.create_bucket("contend").await.unwrap();

    let seed = vec![b'x'; 1_048_576];
    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(seed));
    backend
        .put_object("contend", "hot", data, None)
        .await
        .unwrap();

    let stop = StdArc::new(std::sync::atomic::AtomicBool::new(false));
    let mut handles = Vec::new();

    for w in 0..4 {
        let b = backend.clone();
        let stop = stop.clone();
        handles.push(tokio::spawn(async move {
            let mut i: u8 = 0;
            while !stop.load(Ordering::Relaxed) {
                let fill = b'a' + ((w as u8 + i) % 26);
                let body = vec![fill; 1_048_576];
                let data: AsyncReadStream = Box::pin(std::io::Cursor::new(body));
                let _ = b.put_object("contend", "hot", data, None).await;
                i = i.wrapping_add(1);
            }
        }));
    }

    let pings = StdArc::new(AtomicU64::new(0));
    for _ in 0..2 {
        let stop = stop.clone();
        let pings = pings.clone();
        handles.push(tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                tokio::task::yield_now().await;
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                pings.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        let _ = h.await;
    }

    let p = pings.load(Ordering::Relaxed);
    assert!(
        p >= 50,
        "unrelated async tasks stalled during PUT contention: only {} pings in 400ms",
        p
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_put_get_atomicity() {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc as StdArc;

    let _stress = filesystem_stress_test_guard();
    let (_dir, backend) = create_test_backend();
    let backend = StdArc::new(backend);
    backend.create_bucket("race-bucket").await.unwrap();

    const SIZE: usize = 256 * 1024;
    let seed = vec![b'a'; SIZE];
    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(seed));
    backend
        .put_object("race-bucket", "hot", data, None)
        .await
        .unwrap();

    let stop = StdArc::new(std::sync::atomic::AtomicBool::new(false));
    let mismatches = StdArc::new(AtomicU64::new(0));
    let reads = StdArc::new(AtomicU64::new(0));

    let mut handles = Vec::new();
    for w in 0..2 {
        let b = backend.clone();
        let stop = stop.clone();
        handles.push(tokio::spawn(async move {
            let mut i: u8 = 0;
            while !stop.load(Ordering::Relaxed) {
                let fill = b'a'.wrapping_add(w * 8 + i);
                let body = vec![fill; SIZE];
                let data: AsyncReadStream = Box::pin(std::io::Cursor::new(body));
                let _ = b.put_object("race-bucket", "hot", data, None).await;
                i = i.wrapping_add(1);
            }
        }));
    }
    for _ in 0..6 {
        let b = backend.clone();
        let stop = stop.clone();
        let mismatches = mismatches.clone();
        let reads = reads.clone();
        handles.push(tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                if let Ok((obj, mut stream)) = b.get_object("race-bucket", "hot").await {
                    let mut buf = Vec::with_capacity(SIZE);
                    if stream.read_to_end(&mut buf).await.is_ok() {
                        let header_etag = obj.etag.unwrap_or_default();
                        let body_md5 = format!("{:x}", Md5::digest(&buf));
                        reads.fetch_add(1, Ordering::Relaxed);
                        if header_etag != body_md5 {
                            mismatches.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
        }));
    }

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        let _ = h.await;
    }

    let r = reads.load(Ordering::Relaxed);
    let m = mismatches.load(Ordering::Relaxed);
    assert!(r > 10, "expected at least a handful of GETs, got {}", r);
    assert_eq!(
        m, 0,
        "observed {} ETag/body mismatches out of {} reads",
        m, r
    );
}
