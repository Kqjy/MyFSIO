import io
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.access_logging import (
    AccessLogEntry,
    AccessLoggingService,
    LoggingConfiguration,
)
from app.storage import ObjectStorage


class TestAccessLogEntry:
    def test_default_values(self):
        entry = AccessLogEntry()
        assert entry.bucket_owner == "-"
        assert entry.bucket == "-"
        assert entry.remote_ip == "-"
        assert entry.requester == "-"
        assert entry.operation == "-"
        assert entry.http_status == 200
        assert len(entry.request_id) == 16

    def test_to_log_line(self):
        entry = AccessLogEntry(
            bucket_owner="owner123",
            bucket="my-bucket",
            remote_ip="192.168.1.1",
            requester="user456",
            request_id="REQ123456789012",
            operation="REST.PUT.OBJECT",
            key="test/key.txt",
            request_uri="PUT /my-bucket/test/key.txt HTTP/1.1",
            http_status=200,
            bytes_sent=1024,
            object_size=2048,
            total_time_ms=150,
            referrer="http://example.com",
            user_agent="aws-cli/2.0",
            version_id="v1",
        )
        log_line = entry.to_log_line()

        assert "owner123" in log_line
        assert "my-bucket" in log_line
        assert "192.168.1.1" in log_line
        assert "user456" in log_line
        assert "REST.PUT.OBJECT" in log_line
        assert "test/key.txt" in log_line
        assert "200" in log_line

    def test_to_dict(self):
        entry = AccessLogEntry(
            bucket_owner="owner",
            bucket="bucket",
            remote_ip="10.0.0.1",
            requester="admin",
            request_id="ABC123",
            operation="REST.GET.OBJECT",
            key="file.txt",
            request_uri="GET /bucket/file.txt HTTP/1.1",
            http_status=200,
            bytes_sent=512,
            object_size=512,
            total_time_ms=50,
        )
        result = entry.to_dict()

        assert result["bucket_owner"] == "owner"
        assert result["bucket"] == "bucket"
        assert result["remote_ip"] == "10.0.0.1"
        assert result["requester"] == "admin"
        assert result["operation"] == "REST.GET.OBJECT"
        assert result["key"] == "file.txt"
        assert result["http_status"] == 200
        assert result["bytes_sent"] == 512


class TestLoggingConfiguration:
    def test_default_values(self):
        config = LoggingConfiguration(target_bucket="log-bucket")
        assert config.target_bucket == "log-bucket"
        assert config.target_prefix == ""
        assert config.enabled is True

    def test_to_dict(self):
        config = LoggingConfiguration(
            target_bucket="logs",
            target_prefix="access-logs/",
            enabled=True,
        )
        result = config.to_dict()

        assert "LoggingEnabled" in result
        assert result["LoggingEnabled"]["TargetBucket"] == "logs"
        assert result["LoggingEnabled"]["TargetPrefix"] == "access-logs/"

    def test_from_dict(self):
        data = {
            "LoggingEnabled": {
                "TargetBucket": "my-logs",
                "TargetPrefix": "bucket-logs/",
            }
        }
        config = LoggingConfiguration.from_dict(data)

        assert config is not None
        assert config.target_bucket == "my-logs"
        assert config.target_prefix == "bucket-logs/"
        assert config.enabled is True

    def test_from_dict_no_logging(self):
        data = {}
        config = LoggingConfiguration.from_dict(data)
        assert config is None


@pytest.fixture
def storage(tmp_path: Path):
    storage_root = tmp_path / "data"
    storage_root.mkdir(parents=True)
    return ObjectStorage(storage_root)


@pytest.fixture
def logging_service(tmp_path: Path, storage):
    service = AccessLoggingService(
        tmp_path,
        flush_interval=3600,
        max_buffer_size=10,
    )
    service.set_storage(storage)
    yield service
    service.shutdown()


class TestAccessLoggingService:
    def test_get_bucket_logging_not_configured(self, logging_service):
        result = logging_service.get_bucket_logging("unconfigured-bucket")
        assert result is None

    def test_set_and_get_bucket_logging(self, logging_service):
        config = LoggingConfiguration(
            target_bucket="log-bucket",
            target_prefix="logs/",
        )
        logging_service.set_bucket_logging("source-bucket", config)

        retrieved = logging_service.get_bucket_logging("source-bucket")
        assert retrieved is not None
        assert retrieved.target_bucket == "log-bucket"
        assert retrieved.target_prefix == "logs/"

    def test_delete_bucket_logging(self, logging_service):
        config = LoggingConfiguration(target_bucket="logs")
        logging_service.set_bucket_logging("to-delete", config)
        assert logging_service.get_bucket_logging("to-delete") is not None

        logging_service.delete_bucket_logging("to-delete")
        logging_service._configs.clear()
        assert logging_service.get_bucket_logging("to-delete") is None

    def test_log_request_no_config(self, logging_service):
        logging_service.log_request(
            "no-config-bucket",
            operation="REST.GET.OBJECT",
            key="test.txt",
        )
        stats = logging_service.get_stats()
        assert stats["buffered_entries"] == 0

    def test_log_request_with_config(self, logging_service, storage):
        storage.create_bucket("log-target")

        config = LoggingConfiguration(
            target_bucket="log-target",
            target_prefix="access/",
        )
        logging_service.set_bucket_logging("source-bucket", config)

        logging_service.log_request(
            "source-bucket",
            operation="REST.PUT.OBJECT",
            key="uploaded.txt",
            remote_ip="192.168.1.100",
            requester="test-user",
            http_status=200,
            bytes_sent=1024,
        )

        stats = logging_service.get_stats()
        assert stats["buffered_entries"] == 1

    def test_log_request_disabled_config(self, logging_service):
        config = LoggingConfiguration(
            target_bucket="logs",
            enabled=False,
        )
        logging_service.set_bucket_logging("disabled-bucket", config)

        logging_service.log_request(
            "disabled-bucket",
            operation="REST.GET.OBJECT",
            key="test.txt",
        )

        stats = logging_service.get_stats()
        assert stats["buffered_entries"] == 0

    def test_flush_buffer(self, logging_service, storage):
        storage.create_bucket("flush-target")

        config = LoggingConfiguration(
            target_bucket="flush-target",
            target_prefix="logs/",
        )
        logging_service.set_bucket_logging("flush-source", config)

        for i in range(3):
            logging_service.log_request(
                "flush-source",
                operation="REST.GET.OBJECT",
                key=f"file{i}.txt",
            )

        logging_service.flush()

        objects = storage.list_objects_all("flush-target")
        assert len(objects) >= 1

    def test_auto_flush_on_buffer_size(self, logging_service, storage):
        storage.create_bucket("auto-flush-target")

        config = LoggingConfiguration(
            target_bucket="auto-flush-target",
            target_prefix="",
        )
        logging_service.set_bucket_logging("auto-source", config)

        for i in range(15):
            logging_service.log_request(
                "auto-source",
                operation="REST.GET.OBJECT",
                key=f"file{i}.txt",
            )

        objects = storage.list_objects_all("auto-flush-target")
        assert len(objects) >= 1

    def test_get_stats(self, logging_service, storage):
        storage.create_bucket("stats-target")
        config = LoggingConfiguration(target_bucket="stats-target")
        logging_service.set_bucket_logging("stats-bucket", config)

        logging_service.log_request(
            "stats-bucket",
            operation="REST.GET.OBJECT",
            key="test.txt",
        )

        stats = logging_service.get_stats()
        assert "buffered_entries" in stats
        assert "target_buckets" in stats
        assert stats["buffered_entries"] >= 1

    def test_shutdown_flushes_buffer(self, tmp_path, storage):
        storage.create_bucket("shutdown-target")

        service = AccessLoggingService(tmp_path, flush_interval=3600, max_buffer_size=100)
        service.set_storage(storage)

        config = LoggingConfiguration(target_bucket="shutdown-target")
        service.set_bucket_logging("shutdown-source", config)

        service.log_request(
            "shutdown-source",
            operation="REST.PUT.OBJECT",
            key="final.txt",
        )

        service.shutdown()

        objects = storage.list_objects_all("shutdown-target")
        assert len(objects) >= 1

    def test_logging_caching(self, logging_service):
        config = LoggingConfiguration(target_bucket="cached-logs")
        logging_service.set_bucket_logging("cached-bucket", config)

        logging_service.get_bucket_logging("cached-bucket")
        assert "cached-bucket" in logging_service._configs

    def test_log_request_all_fields(self, logging_service, storage):
        storage.create_bucket("detailed-target")

        config = LoggingConfiguration(target_bucket="detailed-target", target_prefix="detailed/")
        logging_service.set_bucket_logging("detailed-source", config)

        logging_service.log_request(
            "detailed-source",
            operation="REST.PUT.OBJECT",
            key="detailed/file.txt",
            remote_ip="10.0.0.1",
            requester="admin-user",
            request_uri="PUT /detailed-source/detailed/file.txt HTTP/1.1",
            http_status=201,
            error_code="",
            bytes_sent=2048,
            object_size=2048,
            total_time_ms=100,
            referrer="http://admin.example.com",
            user_agent="curl/7.68.0",
            version_id="v1.0",
            request_id="CUSTOM_REQ_ID",
        )

        stats = logging_service.get_stats()
        assert stats["buffered_entries"] == 1

    def test_failed_flush_returns_to_buffer(self, logging_service):
        config = LoggingConfiguration(target_bucket="nonexistent-target")
        logging_service.set_bucket_logging("fail-source", config)

        logging_service.log_request(
            "fail-source",
            operation="REST.GET.OBJECT",
            key="test.txt",
        )

        initial_count = logging_service.get_stats()["buffered_entries"]
        logging_service.flush()

        final_count = logging_service.get_stats()["buffered_entries"]
        assert final_count >= initial_count
