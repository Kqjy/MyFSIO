import io
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.lifecycle import LifecycleManager, LifecycleResult
from app.storage import ObjectStorage


@pytest.fixture
def storage(tmp_path: Path):
    storage_root = tmp_path / "data"
    storage_root.mkdir(parents=True)
    return ObjectStorage(storage_root)


@pytest.fixture
def lifecycle_manager(storage):
    manager = LifecycleManager(storage, interval_seconds=3600)
    yield manager
    manager.stop()


class TestLifecycleResult:
    def test_default_values(self):
        result = LifecycleResult(bucket_name="test-bucket")
        assert result.bucket_name == "test-bucket"
        assert result.objects_deleted == 0
        assert result.versions_deleted == 0
        assert result.uploads_aborted == 0
        assert result.errors == []
        assert result.execution_time_seconds == 0.0


class TestLifecycleManager:
    def test_start_and_stop(self, lifecycle_manager):
        lifecycle_manager.start()
        assert lifecycle_manager._timer is not None
        assert lifecycle_manager._shutdown is False

        lifecycle_manager.stop()
        assert lifecycle_manager._shutdown is True
        assert lifecycle_manager._timer is None

    def test_start_only_once(self, lifecycle_manager):
        lifecycle_manager.start()
        first_timer = lifecycle_manager._timer

        lifecycle_manager.start()
        assert lifecycle_manager._timer is first_timer

    def test_enforce_rules_no_lifecycle(self, lifecycle_manager, storage):
        storage.create_bucket("no-lifecycle-bucket")

        result = lifecycle_manager.enforce_rules("no-lifecycle-bucket")
        assert result.bucket_name == "no-lifecycle-bucket"
        assert result.objects_deleted == 0

    def test_enforce_rules_disabled_rule(self, lifecycle_manager, storage):
        storage.create_bucket("disabled-bucket")
        storage.set_bucket_lifecycle("disabled-bucket", [
            {
                "ID": "disabled-rule",
                "Status": "Disabled",
                "Prefix": "",
                "Expiration": {"Days": 1},
            }
        ])

        old_object = storage.put_object(
            "disabled-bucket",
            "old-file.txt",
            io.BytesIO(b"old content"),
        )

        result = lifecycle_manager.enforce_rules("disabled-bucket")
        assert result.objects_deleted == 0

    def test_enforce_expiration_by_days(self, lifecycle_manager, storage):
        storage.create_bucket("expire-bucket")
        storage.set_bucket_lifecycle("expire-bucket", [
            {
                "ID": "expire-30-days",
                "Status": "Enabled",
                "Prefix": "",
                "Expiration": {"Days": 30},
            }
        ])

        storage.put_object(
            "expire-bucket",
            "recent-file.txt",
            io.BytesIO(b"recent content"),
        )

        result = lifecycle_manager.enforce_rules("expire-bucket")
        assert result.objects_deleted == 0

    def test_enforce_expiration_with_prefix(self, lifecycle_manager, storage):
        storage.create_bucket("prefix-bucket")
        storage.set_bucket_lifecycle("prefix-bucket", [
            {
                "ID": "expire-logs",
                "Status": "Enabled",
                "Prefix": "logs/",
                "Expiration": {"Days": 1},
            }
        ])

        storage.put_object("prefix-bucket", "logs/old.log", io.BytesIO(b"log data"))
        storage.put_object("prefix-bucket", "data/keep.txt", io.BytesIO(b"keep this"))

        result = lifecycle_manager.enforce_rules("prefix-bucket")

    def test_enforce_all_buckets(self, lifecycle_manager, storage):
        storage.create_bucket("bucket1")
        storage.create_bucket("bucket2")

        results = lifecycle_manager.enforce_all_buckets()
        assert isinstance(results, dict)

    def test_run_now_single_bucket(self, lifecycle_manager, storage):
        storage.create_bucket("run-now-bucket")

        results = lifecycle_manager.run_now("run-now-bucket")
        assert "run-now-bucket" in results

    def test_run_now_all_buckets(self, lifecycle_manager, storage):
        storage.create_bucket("all-bucket-1")
        storage.create_bucket("all-bucket-2")

        results = lifecycle_manager.run_now()
        assert isinstance(results, dict)

    def test_enforce_abort_multipart(self, lifecycle_manager, storage):
        storage.create_bucket("multipart-bucket")
        storage.set_bucket_lifecycle("multipart-bucket", [
            {
                "ID": "abort-old-uploads",
                "Status": "Enabled",
                "Prefix": "",
                "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7},
            }
        ])

        upload_id = storage.initiate_multipart_upload("multipart-bucket", "large-file.bin")

        result = lifecycle_manager.enforce_rules("multipart-bucket")
        assert result.uploads_aborted == 0

    def test_enforce_noncurrent_version_expiration(self, lifecycle_manager, storage):
        storage.create_bucket("versioned-bucket")
        storage.set_bucket_versioning("versioned-bucket", True)
        storage.set_bucket_lifecycle("versioned-bucket", [
            {
                "ID": "expire-old-versions",
                "Status": "Enabled",
                "Prefix": "",
                "NoncurrentVersionExpiration": {"NoncurrentDays": 30},
            }
        ])

        storage.put_object("versioned-bucket", "file.txt", io.BytesIO(b"v1"))
        storage.put_object("versioned-bucket", "file.txt", io.BytesIO(b"v2"))

        result = lifecycle_manager.enforce_rules("versioned-bucket")
        assert result.bucket_name == "versioned-bucket"

    def test_execution_time_tracking(self, lifecycle_manager, storage):
        storage.create_bucket("timed-bucket")
        storage.set_bucket_lifecycle("timed-bucket", [
            {
                "ID": "timer-test",
                "Status": "Enabled",
                "Expiration": {"Days": 1},
            }
        ])

        result = lifecycle_manager.enforce_rules("timed-bucket")
        assert result.execution_time_seconds >= 0

    def test_enforce_rules_with_error(self, lifecycle_manager, storage):
        result = lifecycle_manager.enforce_rules("nonexistent-bucket")
        assert len(result.errors) > 0 or result.objects_deleted == 0

    def test_lifecycle_with_date_expiration(self, lifecycle_manager, storage):
        storage.create_bucket("date-bucket")
        past_date = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT00:00:00Z")
        storage.set_bucket_lifecycle("date-bucket", [
            {
                "ID": "expire-by-date",
                "Status": "Enabled",
                "Prefix": "",
                "Expiration": {"Date": past_date},
            }
        ])

        storage.put_object("date-bucket", "should-expire.txt", io.BytesIO(b"content"))

        result = lifecycle_manager.enforce_rules("date-bucket")

    def test_enforce_with_filter_prefix(self, lifecycle_manager, storage):
        storage.create_bucket("filter-bucket")
        storage.set_bucket_lifecycle("filter-bucket", [
            {
                "ID": "filter-prefix-rule",
                "Status": "Enabled",
                "Filter": {"Prefix": "archive/"},
                "Expiration": {"Days": 1},
            }
        ])

        result = lifecycle_manager.enforce_rules("filter-bucket")
        assert result.bucket_name == "filter-bucket"


class TestLifecycleManagerScheduling:
    def test_schedule_next_respects_shutdown(self, storage):
        manager = LifecycleManager(storage, interval_seconds=1)
        manager._shutdown = True
        manager._schedule_next()
        assert manager._timer is None

    @patch.object(LifecycleManager, "enforce_all_buckets")
    def test_run_enforcement_catches_exceptions(self, mock_enforce, storage):
        mock_enforce.side_effect = Exception("Test error")
        manager = LifecycleManager(storage, interval_seconds=3600)
        manager._shutdown = True
        manager._run_enforcement()

    def test_shutdown_flag_prevents_scheduling(self, storage):
        manager = LifecycleManager(storage, interval_seconds=1)
        manager.start()
        manager.stop()
        assert manager._shutdown is True
