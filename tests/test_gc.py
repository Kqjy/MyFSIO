import json
import os
import time
from pathlib import Path

import pytest

from app.gc import GarbageCollector, GCResult


@pytest.fixture
def storage_root(tmp_path):
    root = tmp_path / "data"
    root.mkdir()
    sys_root = root / ".myfsio.sys"
    sys_root.mkdir()
    (sys_root / "config").mkdir(parents=True)
    (sys_root / "tmp").mkdir()
    (sys_root / "multipart").mkdir()
    (sys_root / "buckets").mkdir()
    return root


@pytest.fixture
def gc(storage_root):
    return GarbageCollector(
        storage_root=storage_root,
        interval_hours=1.0,
        temp_file_max_age_hours=1.0,
        multipart_max_age_days=1,
        lock_file_max_age_hours=0.5,
        dry_run=False,
    )


def _make_old(path, hours=48):
    old_time = time.time() - hours * 3600
    os.utime(path, (old_time, old_time))


class TestTempFileCleanup:
    def test_old_temp_files_deleted(self, storage_root, gc):
        tmp_dir = storage_root / ".myfsio.sys" / "tmp"
        old_file = tmp_dir / "abc123.tmp"
        old_file.write_bytes(b"x" * 1000)
        _make_old(old_file, hours=48)

        result = gc.run_now()
        assert result.temp_files_deleted == 1
        assert result.temp_bytes_freed == 1000
        assert not old_file.exists()

    def test_recent_temp_files_kept(self, storage_root, gc):
        tmp_dir = storage_root / ".myfsio.sys" / "tmp"
        new_file = tmp_dir / "recent.tmp"
        new_file.write_bytes(b"data")

        result = gc.run_now()
        assert result.temp_files_deleted == 0
        assert new_file.exists()

    def test_dry_run_keeps_files(self, storage_root, gc):
        gc.dry_run = True
        tmp_dir = storage_root / ".myfsio.sys" / "tmp"
        old_file = tmp_dir / "stale.tmp"
        old_file.write_bytes(b"x" * 500)
        _make_old(old_file, hours=48)

        result = gc.run_now()
        assert result.temp_files_deleted == 1
        assert result.temp_bytes_freed == 500
        assert old_file.exists()


class TestMultipartCleanup:
    def test_old_orphaned_multipart_deleted(self, storage_root, gc):
        bucket = storage_root / "test-bucket"
        bucket.mkdir()
        mp_root = storage_root / ".myfsio.sys" / "multipart" / "test-bucket"
        mp_root.mkdir(parents=True)
        upload_dir = mp_root / "upload-123"
        upload_dir.mkdir()
        manifest = upload_dir / "manifest.json"
        manifest.write_text(json.dumps({"upload_id": "upload-123", "object_key": "foo.txt"}))
        part = upload_dir / "part-00001.part"
        part.write_bytes(b"x" * 2000)
        _make_old(manifest, hours=200)
        _make_old(part, hours=200)
        _make_old(upload_dir, hours=200)

        result = gc.run_now()
        assert result.multipart_uploads_deleted == 1
        assert result.multipart_bytes_freed > 0
        assert not upload_dir.exists()

    def test_recent_multipart_kept(self, storage_root, gc):
        bucket = storage_root / "test-bucket"
        bucket.mkdir()
        mp_root = storage_root / ".myfsio.sys" / "multipart" / "test-bucket"
        mp_root.mkdir(parents=True)
        upload_dir = mp_root / "upload-new"
        upload_dir.mkdir()
        manifest = upload_dir / "manifest.json"
        manifest.write_text(json.dumps({"upload_id": "upload-new", "object_key": "bar.txt"}))

        result = gc.run_now()
        assert result.multipart_uploads_deleted == 0
        assert upload_dir.exists()

    def test_legacy_multipart_cleaned(self, storage_root, gc):
        bucket = storage_root / "test-bucket"
        bucket.mkdir()
        legacy_mp = bucket / ".multipart" / "upload-old"
        legacy_mp.mkdir(parents=True)
        part = legacy_mp / "part-00001.part"
        part.write_bytes(b"y" * 500)
        _make_old(part, hours=200)
        _make_old(legacy_mp, hours=200)

        result = gc.run_now()
        assert result.multipart_uploads_deleted == 1


class TestLockFileCleanup:
    def test_stale_lock_files_deleted(self, storage_root, gc):
        locks_dir = storage_root / ".myfsio.sys" / "buckets" / "test-bucket" / "locks"
        locks_dir.mkdir(parents=True)
        lock = locks_dir / "some_key.lock"
        lock.write_text("")
        _make_old(lock, hours=2)

        result = gc.run_now()
        assert result.lock_files_deleted == 1
        assert not lock.exists()

    def test_recent_lock_kept(self, storage_root, gc):
        locks_dir = storage_root / ".myfsio.sys" / "buckets" / "test-bucket" / "locks"
        locks_dir.mkdir(parents=True)
        lock = locks_dir / "active.lock"
        lock.write_text("")

        result = gc.run_now()
        assert result.lock_files_deleted == 0
        assert lock.exists()


class TestOrphanedMetadataCleanup:
    def test_legacy_orphaned_metadata_deleted(self, storage_root, gc):
        bucket = storage_root / "test-bucket"
        bucket.mkdir()
        meta_dir = bucket / ".meta"
        meta_dir.mkdir()
        orphan = meta_dir / "deleted_file.txt.meta.json"
        orphan.write_text(json.dumps({"etag": "abc"}))

        result = gc.run_now()
        assert result.orphaned_metadata_deleted == 1
        assert not orphan.exists()

    def test_valid_metadata_kept(self, storage_root, gc):
        bucket = storage_root / "test-bucket"
        bucket.mkdir()
        obj = bucket / "exists.txt"
        obj.write_text("hello")
        meta_dir = bucket / ".meta"
        meta_dir.mkdir()
        meta = meta_dir / "exists.txt.meta.json"
        meta.write_text(json.dumps({"etag": "abc"}))

        result = gc.run_now()
        assert result.orphaned_metadata_deleted == 0
        assert meta.exists()

    def test_index_orphaned_entries_cleaned(self, storage_root, gc):
        bucket = storage_root / "test-bucket"
        bucket.mkdir()
        obj = bucket / "keep.txt"
        obj.write_text("hello")

        meta_dir = storage_root / ".myfsio.sys" / "buckets" / "test-bucket" / "meta"
        meta_dir.mkdir(parents=True)
        index = meta_dir / "_index.json"
        index.write_text(json.dumps({"keep.txt": {"etag": "a"}, "gone.txt": {"etag": "b"}}))

        result = gc.run_now()
        assert result.orphaned_metadata_deleted == 1

        updated = json.loads(index.read_text())
        assert "keep.txt" in updated
        assert "gone.txt" not in updated


class TestOrphanedVersionsCleanup:
    def test_orphaned_versions_deleted(self, storage_root, gc):
        bucket = storage_root / "test-bucket"
        bucket.mkdir()
        versions_dir = storage_root / ".myfsio.sys" / "buckets" / "test-bucket" / "versions" / "deleted_obj.txt"
        versions_dir.mkdir(parents=True)
        v_bin = versions_dir / "v1.bin"
        v_json = versions_dir / "v1.json"
        v_bin.write_bytes(b"old data" * 100)
        v_json.write_text(json.dumps({"version_id": "v1", "size": 800}))

        result = gc.run_now()
        assert result.orphaned_versions_deleted == 2
        assert result.orphaned_version_bytes_freed == 800

    def test_active_versions_kept(self, storage_root, gc):
        bucket = storage_root / "test-bucket"
        bucket.mkdir()
        obj = bucket / "active.txt"
        obj.write_text("current")
        versions_dir = storage_root / ".myfsio.sys" / "buckets" / "test-bucket" / "versions" / "active.txt"
        versions_dir.mkdir(parents=True)
        v_bin = versions_dir / "v1.bin"
        v_bin.write_bytes(b"old version")

        result = gc.run_now()
        assert result.orphaned_versions_deleted == 0
        assert v_bin.exists()


class TestEmptyDirCleanup:
    def test_empty_dirs_removed(self, storage_root, gc):
        empty = storage_root / ".myfsio.sys" / "buckets" / "test-bucket" / "locks" / "sub"
        empty.mkdir(parents=True)

        result = gc.run_now()
        assert result.empty_dirs_removed > 0
        assert not empty.exists()


class TestHistory:
    def test_history_recorded(self, storage_root, gc):
        gc.run_now()
        history = gc.get_history()
        assert len(history) == 1
        assert "result" in history[0]
        assert "timestamp" in history[0]

    def test_multiple_runs(self, storage_root, gc):
        gc.run_now()
        gc.run_now()
        gc.run_now()
        history = gc.get_history()
        assert len(history) == 3
        assert history[0]["timestamp"] >= history[1]["timestamp"]


class TestStatus:
    def test_get_status(self, storage_root, gc):
        status = gc.get_status()
        assert status["interval_hours"] == 1.0
        assert status["dry_run"] is False
        assert status["temp_file_max_age_hours"] == 1.0
        assert status["multipart_max_age_days"] == 1
        assert status["lock_file_max_age_hours"] == 0.5


class TestGCResult:
    def test_total_bytes_freed(self):
        r = GCResult(temp_bytes_freed=100, multipart_bytes_freed=200, orphaned_version_bytes_freed=300)
        assert r.total_bytes_freed == 600

    def test_has_work(self):
        assert not GCResult().has_work
        assert GCResult(temp_files_deleted=1).has_work
        assert GCResult(lock_files_deleted=1).has_work
        assert GCResult(empty_dirs_removed=1).has_work


class TestAdminAPI:
    @pytest.fixture
    def gc_app(self, tmp_path):
        from app import create_api_app
        storage_root = tmp_path / "data"
        iam_config = tmp_path / "iam.json"
        bucket_policies = tmp_path / "bucket_policies.json"
        iam_payload = {
            "users": [
                {
                    "access_key": "admin",
                    "secret_key": "adminsecret",
                    "display_name": "Admin",
                    "policies": [{"bucket": "*", "actions": ["list", "read", "write", "delete", "policy", "iam:*"]}],
                }
            ]
        }
        iam_config.write_text(json.dumps(iam_payload))
        flask_app = create_api_app({
            "TESTING": True,
            "SECRET_KEY": "testing",
            "STORAGE_ROOT": storage_root,
            "IAM_CONFIG": iam_config,
            "BUCKET_POLICY_PATH": bucket_policies,
            "GC_ENABLED": True,
            "GC_INTERVAL_HOURS": 1.0,
        })
        yield flask_app
        gc = flask_app.extensions.get("gc")
        if gc:
            gc.stop()

    def test_gc_status(self, gc_app):
        client = gc_app.test_client()
        resp = client.get("/admin/gc/status", headers={"X-Access-Key": "admin", "X-Secret-Key": "adminsecret"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["enabled"] is True

    def test_gc_run(self, gc_app):
        client = gc_app.test_client()
        resp = client.post(
            "/admin/gc/run",
            headers={"X-Access-Key": "admin", "X-Secret-Key": "adminsecret"},
            content_type="application/json",
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "temp_files_deleted" in data

    def test_gc_dry_run(self, gc_app):
        client = gc_app.test_client()
        resp = client.post(
            "/admin/gc/run",
            headers={"X-Access-Key": "admin", "X-Secret-Key": "adminsecret"},
            data=json.dumps({"dry_run": True}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "temp_files_deleted" in data

    def test_gc_history(self, gc_app):
        client = gc_app.test_client()
        client.post("/admin/gc/run", headers={"X-Access-Key": "admin", "X-Secret-Key": "adminsecret"})
        resp = client.get("/admin/gc/history", headers={"X-Access-Key": "admin", "X-Secret-Key": "adminsecret"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data["executions"]) >= 1

    def test_gc_requires_admin(self, gc_app):
        iam = gc_app.extensions["iam"]
        user = iam.create_user(display_name="Regular")
        client = gc_app.test_client()
        resp = client.get(
            "/admin/gc/status",
            headers={"X-Access-Key": user["access_key"], "X-Secret-Key": user["secret_key"]},
        )
        assert resp.status_code == 403
