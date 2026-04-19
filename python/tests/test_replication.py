import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.connections import ConnectionStore, RemoteConnection
from app.replication import (
    ReplicationManager,
    ReplicationRule,
    ReplicationStats,
    REPLICATION_MODE_ALL,
    REPLICATION_MODE_NEW_ONLY,
    _create_s3_client,
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


class TestReplicationStats:
    def test_to_dict(self):
        stats = ReplicationStats(
            objects_synced=10,
            objects_pending=5,
            objects_orphaned=2,
            bytes_synced=1024,
            last_sync_at=1234567890.0,
            last_sync_key="test/key.txt",
        )
        result = stats.to_dict()
        assert result["objects_synced"] == 10
        assert result["objects_pending"] == 5
        assert result["objects_orphaned"] == 2
        assert result["bytes_synced"] == 1024
        assert result["last_sync_at"] == 1234567890.0
        assert result["last_sync_key"] == "test/key.txt"

    def test_from_dict(self):
        data = {
            "objects_synced": 15,
            "objects_pending": 3,
            "objects_orphaned": 1,
            "bytes_synced": 2048,
            "last_sync_at": 9876543210.0,
            "last_sync_key": "another/key.txt",
        }
        stats = ReplicationStats.from_dict(data)
        assert stats.objects_synced == 15
        assert stats.objects_pending == 3
        assert stats.objects_orphaned == 1
        assert stats.bytes_synced == 2048
        assert stats.last_sync_at == 9876543210.0
        assert stats.last_sync_key == "another/key.txt"

    def test_from_dict_with_defaults(self):
        stats = ReplicationStats.from_dict({})
        assert stats.objects_synced == 0
        assert stats.objects_pending == 0
        assert stats.objects_orphaned == 0
        assert stats.bytes_synced == 0
        assert stats.last_sync_at is None
        assert stats.last_sync_key is None


class TestReplicationRule:
    def test_to_dict(self):
        rule = ReplicationRule(
            bucket_name="source-bucket",
            target_connection_id="test-conn",
            target_bucket="dest-bucket",
            enabled=True,
            mode=REPLICATION_MODE_ALL,
            created_at=1234567890.0,
        )
        result = rule.to_dict()
        assert result["bucket_name"] == "source-bucket"
        assert result["target_connection_id"] == "test-conn"
        assert result["target_bucket"] == "dest-bucket"
        assert result["enabled"] is True
        assert result["mode"] == REPLICATION_MODE_ALL
        assert result["created_at"] == 1234567890.0
        assert "stats" in result

    def test_from_dict(self):
        data = {
            "bucket_name": "my-bucket",
            "target_connection_id": "conn-123",
            "target_bucket": "remote-bucket",
            "enabled": False,
            "mode": REPLICATION_MODE_NEW_ONLY,
            "created_at": 1111111111.0,
            "stats": {"objects_synced": 5},
        }
        rule = ReplicationRule.from_dict(data)
        assert rule.bucket_name == "my-bucket"
        assert rule.target_connection_id == "conn-123"
        assert rule.target_bucket == "remote-bucket"
        assert rule.enabled is False
        assert rule.mode == REPLICATION_MODE_NEW_ONLY
        assert rule.created_at == 1111111111.0
        assert rule.stats.objects_synced == 5

    def test_from_dict_defaults_mode(self):
        data = {
            "bucket_name": "my-bucket",
            "target_connection_id": "conn-123",
            "target_bucket": "remote-bucket",
        }
        rule = ReplicationRule.from_dict(data)
        assert rule.mode == REPLICATION_MODE_NEW_ONLY
        assert rule.created_at is None


class TestReplicationManager:
    def test_get_rule_not_exists(self, replication_manager):
        rule = replication_manager.get_rule("nonexistent-bucket")
        assert rule is None

    def test_set_and_get_rule(self, replication_manager):
        rule = ReplicationRule(
            bucket_name="my-bucket",
            target_connection_id="test-conn",
            target_bucket="remote-bucket",
            enabled=True,
            mode=REPLICATION_MODE_NEW_ONLY,
            created_at=time.time(),
        )
        replication_manager.set_rule(rule)

        retrieved = replication_manager.get_rule("my-bucket")
        assert retrieved is not None
        assert retrieved.bucket_name == "my-bucket"
        assert retrieved.target_connection_id == "test-conn"
        assert retrieved.target_bucket == "remote-bucket"

    def test_delete_rule(self, replication_manager):
        rule = ReplicationRule(
            bucket_name="to-delete",
            target_connection_id="test-conn",
            target_bucket="remote-bucket",
        )
        replication_manager.set_rule(rule)
        assert replication_manager.get_rule("to-delete") is not None

        replication_manager.delete_rule("to-delete")
        assert replication_manager.get_rule("to-delete") is None

    def test_save_and_reload_rules(self, replication_manager, tmp_path):
        rule = ReplicationRule(
            bucket_name="persistent-bucket",
            target_connection_id="test-conn",
            target_bucket="remote-bucket",
            enabled=True,
        )
        replication_manager.set_rule(rule)

        rules_path = tmp_path / "replication_rules.json"
        assert rules_path.exists()
        data = json.loads(rules_path.read_text())
        assert "persistent-bucket" in data

    @patch("app.replication._create_s3_client")
    def test_check_endpoint_health_success(self, mock_create_client, replication_manager, connections):
        mock_client = MagicMock()
        mock_client.list_buckets.return_value = {"Buckets": []}
        mock_create_client.return_value = mock_client

        conn = connections.get("test-conn")
        result = replication_manager.check_endpoint_health(conn)
        assert result is True
        mock_client.list_buckets.assert_called_once()

    @patch("app.replication._create_s3_client")
    def test_check_endpoint_health_failure(self, mock_create_client, replication_manager, connections):
        mock_client = MagicMock()
        mock_client.list_buckets.side_effect = Exception("Connection refused")
        mock_create_client.return_value = mock_client

        conn = connections.get("test-conn")
        result = replication_manager.check_endpoint_health(conn)
        assert result is False

    def test_trigger_replication_no_rule(self, replication_manager):
        replication_manager.trigger_replication("no-such-bucket", "test.txt", "write")

    def test_trigger_replication_disabled_rule(self, replication_manager):
        rule = ReplicationRule(
            bucket_name="disabled-bucket",
            target_connection_id="test-conn",
            target_bucket="remote-bucket",
            enabled=False,
        )
        replication_manager.set_rule(rule)
        replication_manager.trigger_replication("disabled-bucket", "test.txt", "write")

    def test_trigger_replication_missing_connection(self, replication_manager):
        rule = ReplicationRule(
            bucket_name="orphan-bucket",
            target_connection_id="missing-conn",
            target_bucket="remote-bucket",
            enabled=True,
        )
        replication_manager.set_rule(rule)
        replication_manager.trigger_replication("orphan-bucket", "test.txt", "write")

    def test_replicate_task_path_traversal_blocked(self, replication_manager, connections):
        rule = ReplicationRule(
            bucket_name="secure-bucket",
            target_connection_id="test-conn",
            target_bucket="remote-bucket",
            enabled=True,
        )
        replication_manager.set_rule(rule)
        conn = connections.get("test-conn")

        replication_manager._replicate_task("secure-bucket", "../../../etc/passwd", rule, conn, "write")
        replication_manager._replicate_task("secure-bucket", "/root/secret", rule, conn, "write")
        replication_manager._replicate_task("secure-bucket", "..\\..\\windows\\system32", rule, conn, "write")


class TestCreateS3Client:
    @patch("app.replication.boto3.client")
    def test_creates_client_with_correct_config(self, mock_boto_client):
        conn = RemoteConnection(
            id="test",
            name="Test",
            endpoint_url="http://localhost:9000",
            access_key="access",
            secret_key="secret",
            region="eu-west-1",
        )
        _create_s3_client(conn)

        mock_boto_client.assert_called_once()
        call_kwargs = mock_boto_client.call_args[1]
        assert call_kwargs["endpoint_url"] == "http://localhost:9000"
        assert call_kwargs["aws_access_key_id"] == "access"
        assert call_kwargs["aws_secret_access_key"] == "secret"
        assert call_kwargs["region_name"] == "eu-west-1"

    @patch("app.replication.boto3.client")
    def test_health_check_mode_minimal_retries(self, mock_boto_client):
        conn = RemoteConnection(
            id="test",
            name="Test",
            endpoint_url="http://localhost:9000",
            access_key="access",
            secret_key="secret",
        )
        _create_s3_client(conn, health_check=True)

        call_kwargs = mock_boto_client.call_args[1]
        config = call_kwargs["config"]
        assert config.retries["max_attempts"] == 1
