import io
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.connections import ConnectionStore, RemoteConnection
from app.replication import (
    ReplicationManager,
    ReplicationRule,
    REPLICATION_MODE_BIDIRECTIONAL,
    REPLICATION_MODE_NEW_ONLY,
)
from app.site_sync import (
    SiteSyncWorker,
    SyncState,
    SyncedObjectInfo,
    SiteSyncStats,
    RemoteObjectMeta,
    CLOCK_SKEW_TOLERANCE_SECONDS,
)
from app.storage import ObjectStorage


@pytest.fixture
def storage(tmp_path: Path):
    storage_root = tmp_path / "data"
    storage_root.mkdir(parents=True)
    return ObjectStorage(storage_root)


@pytest.fixture
def connections(tmp_path: Path):
    connections_path = tmp_path / "connections.json"
    store = ConnectionStore(connections_path)
    conn = RemoteConnection(
        id="test-conn",
        name="Test Remote",
        endpoint_url="http://localhost:9000",
        access_key="remote-access",
        secret_key="remote-secret",
        region="us-east-1",
    )
    store.add(conn)
    return store


@pytest.fixture
def replication_manager(storage, connections, tmp_path):
    rules_path = tmp_path / "replication_rules.json"
    storage_root = tmp_path / "data"
    storage_root.mkdir(exist_ok=True)
    manager = ReplicationManager(storage, connections, rules_path, storage_root)
    yield manager
    manager.shutdown(wait=False)


@pytest.fixture
def site_sync_worker(storage, connections, replication_manager, tmp_path):
    storage_root = tmp_path / "data"
    worker = SiteSyncWorker(
        storage=storage,
        connections=connections,
        replication_manager=replication_manager,
        storage_root=storage_root,
        interval_seconds=60,
        batch_size=100,
    )
    yield worker
    worker.shutdown()


class TestSyncedObjectInfo:
    def test_to_dict(self):
        info = SyncedObjectInfo(
            last_synced_at=1234567890.0,
            remote_etag="abc123",
            source="remote",
        )
        result = info.to_dict()
        assert result["last_synced_at"] == 1234567890.0
        assert result["remote_etag"] == "abc123"
        assert result["source"] == "remote"

    def test_from_dict(self):
        data = {
            "last_synced_at": 9876543210.0,
            "remote_etag": "def456",
            "source": "local",
        }
        info = SyncedObjectInfo.from_dict(data)
        assert info.last_synced_at == 9876543210.0
        assert info.remote_etag == "def456"
        assert info.source == "local"


class TestSyncState:
    def test_to_dict(self):
        state = SyncState(
            synced_objects={
                "test.txt": SyncedObjectInfo(
                    last_synced_at=1000.0,
                    remote_etag="etag1",
                    source="remote",
                )
            },
            last_full_sync=2000.0,
        )
        result = state.to_dict()
        assert "test.txt" in result["synced_objects"]
        assert result["synced_objects"]["test.txt"]["remote_etag"] == "etag1"
        assert result["last_full_sync"] == 2000.0

    def test_from_dict(self):
        data = {
            "synced_objects": {
                "file.txt": {
                    "last_synced_at": 3000.0,
                    "remote_etag": "etag2",
                    "source": "remote",
                }
            },
            "last_full_sync": 4000.0,
        }
        state = SyncState.from_dict(data)
        assert "file.txt" in state.synced_objects
        assert state.synced_objects["file.txt"].remote_etag == "etag2"
        assert state.last_full_sync == 4000.0

    def test_from_dict_empty(self):
        state = SyncState.from_dict({})
        assert state.synced_objects == {}
        assert state.last_full_sync is None


class TestSiteSyncStats:
    def test_to_dict(self):
        stats = SiteSyncStats(
            last_sync_at=1234567890.0,
            objects_pulled=10,
            objects_skipped=5,
            conflicts_resolved=2,
            deletions_applied=1,
            errors=0,
        )
        result = stats.to_dict()
        assert result["objects_pulled"] == 10
        assert result["objects_skipped"] == 5
        assert result["conflicts_resolved"] == 2
        assert result["deletions_applied"] == 1
        assert result["errors"] == 0


class TestRemoteObjectMeta:
    def test_from_s3_object(self):
        obj = {
            "Key": "test/file.txt",
            "Size": 1024,
            "LastModified": datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
            "ETag": '"abc123def456"',
        }
        meta = RemoteObjectMeta.from_s3_object(obj)
        assert meta.key == "test/file.txt"
        assert meta.size == 1024
        assert meta.last_modified == datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        assert meta.etag == "abc123def456"


class TestReplicationRuleBidirectional:
    def test_rule_with_bidirectional_mode(self):
        rule = ReplicationRule(
            bucket_name="sync-bucket",
            target_connection_id="test-conn",
            target_bucket="remote-bucket",
            enabled=True,
            mode=REPLICATION_MODE_BIDIRECTIONAL,
            sync_deletions=True,
        )
        assert rule.mode == REPLICATION_MODE_BIDIRECTIONAL
        assert rule.sync_deletions is True
        assert rule.last_pull_at is None

    def test_rule_to_dict_includes_new_fields(self):
        rule = ReplicationRule(
            bucket_name="sync-bucket",
            target_connection_id="test-conn",
            target_bucket="remote-bucket",
            mode=REPLICATION_MODE_BIDIRECTIONAL,
            sync_deletions=False,
            last_pull_at=1234567890.0,
        )
        result = rule.to_dict()
        assert result["mode"] == REPLICATION_MODE_BIDIRECTIONAL
        assert result["sync_deletions"] is False
        assert result["last_pull_at"] == 1234567890.0

    def test_rule_from_dict_with_new_fields(self):
        data = {
            "bucket_name": "sync-bucket",
            "target_connection_id": "test-conn",
            "target_bucket": "remote-bucket",
            "mode": REPLICATION_MODE_BIDIRECTIONAL,
            "sync_deletions": False,
            "last_pull_at": 1234567890.0,
        }
        rule = ReplicationRule.from_dict(data)
        assert rule.mode == REPLICATION_MODE_BIDIRECTIONAL
        assert rule.sync_deletions is False
        assert rule.last_pull_at == 1234567890.0

    def test_rule_from_dict_defaults_new_fields(self):
        data = {
            "bucket_name": "sync-bucket",
            "target_connection_id": "test-conn",
            "target_bucket": "remote-bucket",
        }
        rule = ReplicationRule.from_dict(data)
        assert rule.sync_deletions is True
        assert rule.last_pull_at is None


class TestSiteSyncWorker:
    def test_start_and_shutdown(self, site_sync_worker):
        site_sync_worker.start()
        assert site_sync_worker._sync_thread is not None
        assert site_sync_worker._sync_thread.is_alive()
        site_sync_worker.shutdown()
        assert not site_sync_worker._sync_thread.is_alive()

    def test_trigger_sync_no_rule(self, site_sync_worker):
        result = site_sync_worker.trigger_sync("nonexistent-bucket")
        assert result is None

    def test_trigger_sync_wrong_mode(self, site_sync_worker, replication_manager):
        rule = ReplicationRule(
            bucket_name="new-only-bucket",
            target_connection_id="test-conn",
            target_bucket="remote-bucket",
            mode=REPLICATION_MODE_NEW_ONLY,
            enabled=True,
        )
        replication_manager.set_rule(rule)
        result = site_sync_worker.trigger_sync("new-only-bucket")
        assert result is None

    def test_trigger_sync_disabled_rule(self, site_sync_worker, replication_manager):
        rule = ReplicationRule(
            bucket_name="disabled-bucket",
            target_connection_id="test-conn",
            target_bucket="remote-bucket",
            mode=REPLICATION_MODE_BIDIRECTIONAL,
            enabled=False,
        )
        replication_manager.set_rule(rule)
        result = site_sync_worker.trigger_sync("disabled-bucket")
        assert result is None

    def test_get_stats_no_sync(self, site_sync_worker):
        stats = site_sync_worker.get_stats("nonexistent")
        assert stats is None

    def test_resolve_conflict_remote_newer(self, site_sync_worker):
        local_meta = MagicMock()
        local_meta.last_modified = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        local_meta.etag = "local123"

        remote_meta = RemoteObjectMeta(
            key="test.txt",
            size=100,
            last_modified=datetime(2025, 1, 2, 12, 0, 0, tzinfo=timezone.utc),
            etag="remote456",
        )

        result = site_sync_worker._resolve_conflict(local_meta, remote_meta)
        assert result == "pull"

    def test_resolve_conflict_local_newer(self, site_sync_worker):
        local_meta = MagicMock()
        local_meta.last_modified = datetime(2025, 1, 2, 12, 0, 0, tzinfo=timezone.utc)
        local_meta.etag = "local123"

        remote_meta = RemoteObjectMeta(
            key="test.txt",
            size=100,
            last_modified=datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
            etag="remote456",
        )

        result = site_sync_worker._resolve_conflict(local_meta, remote_meta)
        assert result == "keep"

    def test_resolve_conflict_same_time_same_etag(self, site_sync_worker):
        ts = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        local_meta = MagicMock()
        local_meta.last_modified = ts
        local_meta.etag = "same123"

        remote_meta = RemoteObjectMeta(
            key="test.txt",
            size=100,
            last_modified=ts,
            etag="same123",
        )

        result = site_sync_worker._resolve_conflict(local_meta, remote_meta)
        assert result == "skip"

    def test_resolve_conflict_same_time_different_etag(self, site_sync_worker):
        ts = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        local_meta = MagicMock()
        local_meta.last_modified = ts
        local_meta.etag = "aaa"

        remote_meta = RemoteObjectMeta(
            key="test.txt",
            size=100,
            last_modified=ts,
            etag="zzz",
        )

        result = site_sync_worker._resolve_conflict(local_meta, remote_meta)
        assert result == "pull"

    def test_sync_state_persistence(self, site_sync_worker, tmp_path):
        bucket_name = "test-bucket"
        state = SyncState(
            synced_objects={
                "file1.txt": SyncedObjectInfo(
                    last_synced_at=time.time(),
                    remote_etag="etag1",
                    source="remote",
                )
            },
            last_full_sync=time.time(),
        )

        site_sync_worker._save_sync_state(bucket_name, state)

        loaded = site_sync_worker._load_sync_state(bucket_name)
        assert "file1.txt" in loaded.synced_objects
        assert loaded.synced_objects["file1.txt"].remote_etag == "etag1"

    def test_load_sync_state_nonexistent(self, site_sync_worker):
        state = site_sync_worker._load_sync_state("nonexistent-bucket")
        assert state.synced_objects == {}
        assert state.last_full_sync is None

    @patch("app.site_sync._create_sync_client")
    def test_list_remote_objects(self, mock_create_client, site_sync_worker, connections, replication_manager):
        mock_client = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Contents": [
                    {
                        "Key": "file1.txt",
                        "Size": 100,
                        "LastModified": datetime(2025, 1, 1, tzinfo=timezone.utc),
                        "ETag": '"etag1"',
                    },
                    {
                        "Key": "file2.txt",
                        "Size": 200,
                        "LastModified": datetime(2025, 1, 2, tzinfo=timezone.utc),
                        "ETag": '"etag2"',
                    },
                ]
            }
        ]
        mock_client.get_paginator.return_value = mock_paginator
        mock_create_client.return_value = mock_client

        rule = ReplicationRule(
            bucket_name="local-bucket",
            target_connection_id="test-conn",
            target_bucket="remote-bucket",
            mode=REPLICATION_MODE_BIDIRECTIONAL,
        )
        conn = connections.get("test-conn")

        result = site_sync_worker._list_remote_objects(rule, conn)

        assert "file1.txt" in result
        assert "file2.txt" in result
        assert result["file1.txt"].size == 100
        assert result["file2.txt"].size == 200

    def test_list_local_objects(self, site_sync_worker, storage):
        storage.create_bucket("test-bucket")
        storage.put_object("test-bucket", "file1.txt", io.BytesIO(b"content1"))
        storage.put_object("test-bucket", "file2.txt", io.BytesIO(b"content2"))

        result = site_sync_worker._list_local_objects("test-bucket")

        assert "file1.txt" in result
        assert "file2.txt" in result

    @patch("app.site_sync._create_sync_client")
    def test_sync_bucket_connection_not_found(self, mock_create_client, site_sync_worker, replication_manager):
        rule = ReplicationRule(
            bucket_name="test-bucket",
            target_connection_id="missing-conn",
            target_bucket="remote-bucket",
            mode=REPLICATION_MODE_BIDIRECTIONAL,
            enabled=True,
        )
        replication_manager.set_rule(rule)

        stats = site_sync_worker._sync_bucket(rule)
        assert stats.errors == 1


class TestSiteSyncIntegration:
    @patch("app.site_sync._create_sync_client")
    def test_full_sync_cycle(self, mock_create_client, site_sync_worker, storage, connections, replication_manager):
        storage.create_bucket("sync-bucket")
        storage.put_object("sync-bucket", "local-only.txt", io.BytesIO(b"local content"))

        mock_client = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Contents": [
                    {
                        "Key": "remote-only.txt",
                        "Size": 100,
                        "LastModified": datetime(2025, 1, 15, tzinfo=timezone.utc),
                        "ETag": '"remoteetag"',
                    },
                ]
            }
        ]
        mock_client.get_paginator.return_value = mock_paginator
        mock_client.head_object.return_value = {"Metadata": {}}

        def mock_download(bucket, key, path):
            Path(path).write_bytes(b"remote content")

        mock_client.download_file.side_effect = mock_download
        mock_create_client.return_value = mock_client

        rule = ReplicationRule(
            bucket_name="sync-bucket",
            target_connection_id="test-conn",
            target_bucket="remote-bucket",
            mode=REPLICATION_MODE_BIDIRECTIONAL,
            enabled=True,
        )
        replication_manager.set_rule(rule)

        stats = site_sync_worker._sync_bucket(rule)

        assert stats.objects_pulled == 1
        assert stats.errors == 0

        objects = site_sync_worker._list_local_objects("sync-bucket")
        assert "local-only.txt" in objects
        assert "remote-only.txt" in objects
