import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.integrity import IntegrityChecker, IntegrityResult


def _md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def _setup_bucket(storage_root: Path, bucket_name: str, objects: dict[str, bytes]) -> None:
    bucket_path = storage_root / bucket_name
    bucket_path.mkdir(parents=True, exist_ok=True)
    meta_root = storage_root / ".myfsio.sys" / "buckets" / bucket_name / "meta"
    meta_root.mkdir(parents=True, exist_ok=True)
    bucket_json = storage_root / ".myfsio.sys" / "buckets" / bucket_name / ".bucket.json"
    bucket_json.write_text(json.dumps({"created": "2025-01-01"}))

    for key, data in objects.items():
        obj_path = bucket_path / key
        obj_path.parent.mkdir(parents=True, exist_ok=True)
        obj_path.write_bytes(data)

        etag = _md5(data)
        stat = obj_path.stat()
        meta = {
            "__etag__": etag,
            "__size__": str(stat.st_size),
            "__last_modified__": str(stat.st_mtime),
        }

        key_path = Path(key)
        parent = key_path.parent
        key_name = key_path.name
        if parent == Path("."):
            index_path = meta_root / "_index.json"
        else:
            index_path = meta_root / parent / "_index.json"
        index_path.parent.mkdir(parents=True, exist_ok=True)

        index_data = {}
        if index_path.exists():
            index_data = json.loads(index_path.read_text())
        index_data[key_name] = {"metadata": meta}
        index_path.write_text(json.dumps(index_data))


def _issues_of_type(result, issue_type):
    return [i for i in result.issues if i.issue_type == issue_type]


@pytest.fixture
def storage_root(tmp_path):
    root = tmp_path / "data"
    root.mkdir()
    (root / ".myfsio.sys" / "config").mkdir(parents=True, exist_ok=True)
    return root


@pytest.fixture
def checker(storage_root):
    return IntegrityChecker(
        storage_root=storage_root,
        interval_hours=24.0,
        batch_size=1000,
        auto_heal=False,
        dry_run=False,
    )


class TestCorruptedObjects:
    def test_detect_corrupted(self, storage_root, checker):
        _setup_bucket(storage_root, "mybucket", {"file.txt": b"hello world"})
        (storage_root / "mybucket" / "file.txt").write_bytes(b"corrupted data")

        result = checker.run_now()
        assert result.corrupted_objects == 1
        issues = _issues_of_type(result, "corrupted_object")
        assert len(issues) == 1
        assert issues[0].bucket == "mybucket"
        assert issues[0].key == "file.txt"
        assert not issues[0].healed

    def test_heal_corrupted(self, storage_root, checker):
        _setup_bucket(storage_root, "mybucket", {"file.txt": b"hello world"})
        (storage_root / "mybucket" / "file.txt").write_bytes(b"corrupted data")

        result = checker.run_now(auto_heal=True)
        assert result.corrupted_objects == 1
        assert result.issues_healed == 1
        issues = _issues_of_type(result, "corrupted_object")
        assert issues[0].healed

        result2 = checker.run_now()
        assert result2.corrupted_objects == 0

    def test_valid_objects_pass(self, storage_root, checker):
        _setup_bucket(storage_root, "mybucket", {"file.txt": b"hello world"})

        result = checker.run_now()
        assert result.corrupted_objects == 0
        assert result.objects_scanned == 1

    def test_corrupted_nested_key(self, storage_root, checker):
        _setup_bucket(storage_root, "mybucket", {"sub/dir/file.txt": b"nested content"})
        (storage_root / "mybucket" / "sub" / "dir" / "file.txt").write_bytes(b"bad")

        result = checker.run_now()
        assert result.corrupted_objects == 1
        issues = _issues_of_type(result, "corrupted_object")
        assert issues[0].key == "sub/dir/file.txt"


class TestOrphanedObjects:
    def test_detect_orphaned(self, storage_root, checker):
        _setup_bucket(storage_root, "mybucket", {})
        (storage_root / "mybucket" / "orphan.txt").write_bytes(b"orphan data")

        result = checker.run_now()
        assert result.orphaned_objects == 1
        issues = _issues_of_type(result, "orphaned_object")
        assert len(issues) == 1

    def test_heal_orphaned(self, storage_root, checker):
        _setup_bucket(storage_root, "mybucket", {})
        (storage_root / "mybucket" / "orphan.txt").write_bytes(b"orphan data")

        result = checker.run_now(auto_heal=True)
        assert result.orphaned_objects == 1
        assert result.issues_healed == 1
        issues = _issues_of_type(result, "orphaned_object")
        assert issues[0].healed

        result2 = checker.run_now()
        assert result2.orphaned_objects == 0
        assert result2.objects_scanned >= 1


class TestPhantomMetadata:
    def test_detect_phantom(self, storage_root, checker):
        _setup_bucket(storage_root, "mybucket", {"file.txt": b"hello"})
        (storage_root / "mybucket" / "file.txt").unlink()

        result = checker.run_now()
        assert result.phantom_metadata == 1
        issues = _issues_of_type(result, "phantom_metadata")
        assert len(issues) == 1

    def test_heal_phantom(self, storage_root, checker):
        _setup_bucket(storage_root, "mybucket", {"file.txt": b"hello"})
        (storage_root / "mybucket" / "file.txt").unlink()

        result = checker.run_now(auto_heal=True)
        assert result.phantom_metadata == 1
        assert result.issues_healed == 1

        result2 = checker.run_now()
        assert result2.phantom_metadata == 0


class TestStaleVersions:
    def test_manifest_without_data(self, storage_root, checker):
        _setup_bucket(storage_root, "mybucket", {"file.txt": b"hello"})
        versions_root = storage_root / ".myfsio.sys" / "buckets" / "mybucket" / "versions" / "file.txt"
        versions_root.mkdir(parents=True)
        (versions_root / "v1.json").write_text(json.dumps({"etag": "abc"}))

        result = checker.run_now()
        assert result.stale_versions == 1
        issues = _issues_of_type(result, "stale_version")
        assert "manifest without data" in issues[0].detail

    def test_data_without_manifest(self, storage_root, checker):
        _setup_bucket(storage_root, "mybucket", {"file.txt": b"hello"})
        versions_root = storage_root / ".myfsio.sys" / "buckets" / "mybucket" / "versions" / "file.txt"
        versions_root.mkdir(parents=True)
        (versions_root / "v1.bin").write_bytes(b"old data")

        result = checker.run_now()
        assert result.stale_versions == 1
        issues = _issues_of_type(result, "stale_version")
        assert "data without manifest" in issues[0].detail

    def test_heal_stale_versions(self, storage_root, checker):
        _setup_bucket(storage_root, "mybucket", {"file.txt": b"hello"})
        versions_root = storage_root / ".myfsio.sys" / "buckets" / "mybucket" / "versions" / "file.txt"
        versions_root.mkdir(parents=True)
        (versions_root / "v1.json").write_text(json.dumps({"etag": "abc"}))
        (versions_root / "v2.bin").write_bytes(b"old data")

        result = checker.run_now(auto_heal=True)
        assert result.stale_versions == 2
        assert result.issues_healed == 2
        assert not (versions_root / "v1.json").exists()
        assert not (versions_root / "v2.bin").exists()

    def test_valid_versions_pass(self, storage_root, checker):
        _setup_bucket(storage_root, "mybucket", {"file.txt": b"hello"})
        versions_root = storage_root / ".myfsio.sys" / "buckets" / "mybucket" / "versions" / "file.txt"
        versions_root.mkdir(parents=True)
        (versions_root / "v1.json").write_text(json.dumps({"etag": "abc"}))
        (versions_root / "v1.bin").write_bytes(b"old data")

        result = checker.run_now()
        assert result.stale_versions == 0


class TestEtagCache:
    def test_detect_mismatch(self, storage_root, checker):
        _setup_bucket(storage_root, "mybucket", {"file.txt": b"hello"})
        etag_path = storage_root / ".myfsio.sys" / "buckets" / "mybucket" / "etag_index.json"
        etag_path.write_text(json.dumps({"file.txt": "wrong_etag"}))

        result = checker.run_now()
        assert result.etag_cache_inconsistencies == 1
        issues = _issues_of_type(result, "etag_cache_inconsistency")
        assert len(issues) == 1

    def test_heal_mismatch(self, storage_root, checker):
        _setup_bucket(storage_root, "mybucket", {"file.txt": b"hello"})
        etag_path = storage_root / ".myfsio.sys" / "buckets" / "mybucket" / "etag_index.json"
        etag_path.write_text(json.dumps({"file.txt": "wrong_etag"}))

        result = checker.run_now(auto_heal=True)
        assert result.etag_cache_inconsistencies == 1
        assert result.issues_healed == 1
        assert not etag_path.exists()


class TestLegacyMetadata:
    def test_detect_unmigrated(self, storage_root, checker):
        _setup_bucket(storage_root, "mybucket", {"file.txt": b"hello"})

        legacy_meta = storage_root / "mybucket" / ".meta" / "file.txt.meta.json"
        legacy_meta.parent.mkdir(parents=True)
        legacy_meta.write_text(json.dumps({"__etag__": "different_value"}))

        meta_root = storage_root / ".myfsio.sys" / "buckets" / "mybucket" / "meta"
        index_path = meta_root / "_index.json"
        index_path.unlink()

        result = checker.run_now()
        assert result.legacy_metadata_drifts == 1
        issues = _issues_of_type(result, "legacy_metadata_drift")
        assert len(issues) == 1
        assert issues[0].detail == "unmigrated legacy .meta.json"

    def test_detect_drift(self, storage_root, checker):
        _setup_bucket(storage_root, "mybucket", {"file.txt": b"hello"})

        legacy_meta = storage_root / "mybucket" / ".meta" / "file.txt.meta.json"
        legacy_meta.parent.mkdir(parents=True)
        legacy_meta.write_text(json.dumps({"__etag__": "different_value"}))

        result = checker.run_now()
        assert result.legacy_metadata_drifts == 1
        issues = _issues_of_type(result, "legacy_metadata_drift")
        assert "differs from index" in issues[0].detail

    def test_heal_unmigrated(self, storage_root, checker):
        _setup_bucket(storage_root, "mybucket", {"file.txt": b"hello"})

        legacy_meta = storage_root / "mybucket" / ".meta" / "file.txt.meta.json"
        legacy_meta.parent.mkdir(parents=True)
        legacy_data = {"__etag__": _md5(b"hello"), "__size__": "5"}
        legacy_meta.write_text(json.dumps(legacy_data))

        meta_root = storage_root / ".myfsio.sys" / "buckets" / "mybucket" / "meta"
        index_path = meta_root / "_index.json"
        index_path.unlink()

        result = checker.run_now(auto_heal=True)
        assert result.legacy_metadata_drifts == 1
        legacy_issues = _issues_of_type(result, "legacy_metadata_drift")
        assert len(legacy_issues) == 1
        assert legacy_issues[0].healed
        assert not legacy_meta.exists()

        index_data = json.loads(index_path.read_text())
        assert "file.txt" in index_data
        assert index_data["file.txt"]["metadata"]["__etag__"] == _md5(b"hello")

    def test_heal_drift(self, storage_root, checker):
        _setup_bucket(storage_root, "mybucket", {"file.txt": b"hello"})

        legacy_meta = storage_root / "mybucket" / ".meta" / "file.txt.meta.json"
        legacy_meta.parent.mkdir(parents=True)
        legacy_meta.write_text(json.dumps({"__etag__": "different_value"}))

        result = checker.run_now(auto_heal=True)
        assert result.legacy_metadata_drifts == 1
        legacy_issues = _issues_of_type(result, "legacy_metadata_drift")
        assert legacy_issues[0].healed
        assert not legacy_meta.exists()


class TestDryRun:
    def test_dry_run_no_changes(self, storage_root, checker):
        _setup_bucket(storage_root, "mybucket", {"file.txt": b"hello"})
        (storage_root / "mybucket" / "file.txt").write_bytes(b"corrupted")
        (storage_root / "mybucket" / "orphan.txt").write_bytes(b"orphan")

        result = checker.run_now(auto_heal=True, dry_run=True)
        assert result.corrupted_objects == 1
        assert result.orphaned_objects == 1
        assert result.issues_healed == 0

        meta_root = storage_root / ".myfsio.sys" / "buckets" / "mybucket" / "meta"
        index_data = json.loads((meta_root / "_index.json").read_text())
        assert "orphan.txt" not in index_data


class TestBatchSize:
    def test_batch_limits_scan(self, storage_root):
        objects = {f"file{i}.txt": f"data{i}".encode() for i in range(10)}
        _setup_bucket(storage_root, "mybucket", objects)

        checker = IntegrityChecker(
            storage_root=storage_root,
            batch_size=3,
        )
        result = checker.run_now()
        assert result.objects_scanned <= 3


class TestHistory:
    def test_history_recorded(self, storage_root, checker):
        _setup_bucket(storage_root, "mybucket", {"file.txt": b"hello"})

        checker.run_now()
        history = checker.get_history()
        assert len(history) == 1
        assert "corrupted_objects" in history[0]["result"]

    def test_history_multiple(self, storage_root, checker):
        _setup_bucket(storage_root, "mybucket", {"file.txt": b"hello"})

        checker.run_now()
        checker.run_now()
        checker.run_now()
        history = checker.get_history()
        assert len(history) == 3

    def test_history_pagination(self, storage_root, checker):
        _setup_bucket(storage_root, "mybucket", {"file.txt": b"hello"})

        for _ in range(5):
            checker.run_now()

        history = checker.get_history(limit=2, offset=1)
        assert len(history) == 2


AUTH_HEADERS = {"X-Access-Key": "admin", "X-Secret-Key": "adminsecret"}


class TestAdminAPI:
    @pytest.fixture
    def integrity_app(self, tmp_path):
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
            "API_BASE_URL": "http://testserver",
            "INTEGRITY_ENABLED": True,
            "INTEGRITY_AUTO_HEAL": False,
            "INTEGRITY_DRY_RUN": False,
        })
        yield flask_app
        storage = flask_app.extensions.get("object_storage")
        if storage:
            base = getattr(storage, "storage", storage)
            if hasattr(base, "shutdown_stats"):
                base.shutdown_stats()
        ic = flask_app.extensions.get("integrity")
        if ic:
            ic.stop()

    def test_status_endpoint(self, integrity_app):
        client = integrity_app.test_client()
        resp = client.get("/admin/integrity/status", headers=AUTH_HEADERS)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["enabled"] is True
        assert "interval_hours" in data

    def test_run_endpoint(self, integrity_app):
        client = integrity_app.test_client()
        resp = client.post("/admin/integrity/run", headers=AUTH_HEADERS, json={})
        assert resp.status_code == 200
        data = resp.get_json()
        assert "corrupted_objects" in data
        assert "objects_scanned" in data

    def test_run_with_overrides(self, integrity_app):
        client = integrity_app.test_client()
        resp = client.post(
            "/admin/integrity/run",
            headers=AUTH_HEADERS,
            json={"dry_run": True, "auto_heal": True},
        )
        assert resp.status_code == 200

    def test_history_endpoint(self, integrity_app):
        client = integrity_app.test_client()
        client.post("/admin/integrity/run", headers=AUTH_HEADERS, json={})
        resp = client.get("/admin/integrity/history", headers=AUTH_HEADERS)
        assert resp.status_code == 200
        data = resp.get_json()
        assert "executions" in data
        assert len(data["executions"]) >= 1

    def test_auth_required(self, integrity_app):
        client = integrity_app.test_client()
        resp = client.get("/admin/integrity/status")
        assert resp.status_code in (401, 403)

    def test_disabled_status(self, tmp_path):
        from app import create_api_app
        storage_root = tmp_path / "data2"
        iam_config = tmp_path / "iam2.json"
        bucket_policies = tmp_path / "bp2.json"
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
            "API_BASE_URL": "http://testserver",
            "INTEGRITY_ENABLED": False,
        })
        c = flask_app.test_client()
        resp = c.get("/admin/integrity/status", headers=AUTH_HEADERS)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["enabled"] is False

        storage = flask_app.extensions.get("object_storage")
        if storage:
            base = getattr(storage, "storage", storage)
            if hasattr(base, "shutdown_stats"):
                base.shutdown_stats()


class TestMultipleBuckets:
    def test_scans_multiple_buckets(self, storage_root, checker):
        _setup_bucket(storage_root, "bucket1", {"a.txt": b"aaa"})
        _setup_bucket(storage_root, "bucket2", {"b.txt": b"bbb"})

        result = checker.run_now()
        assert result.buckets_scanned == 2
        assert result.objects_scanned == 2
        assert result.corrupted_objects == 0


class TestGetStatus:
    def test_status_fields(self, checker):
        status = checker.get_status()
        assert "enabled" in status
        assert "running" in status
        assert "interval_hours" in status
        assert "batch_size" in status
        assert "auto_heal" in status
        assert "dry_run" in status
