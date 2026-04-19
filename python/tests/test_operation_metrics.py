import threading
import time
from pathlib import Path

import pytest

from app.operation_metrics import (
    OperationMetricsCollector,
    OperationStats,
    classify_endpoint,
)


class TestOperationStats:
    def test_initial_state(self):
        stats = OperationStats()
        assert stats.count == 0
        assert stats.success_count == 0
        assert stats.error_count == 0
        assert stats.latency_sum_ms == 0.0
        assert stats.bytes_in == 0
        assert stats.bytes_out == 0

    def test_record_success(self):
        stats = OperationStats()
        stats.record(latency_ms=50.0, success=True, bytes_in=100, bytes_out=200)

        assert stats.count == 1
        assert stats.success_count == 1
        assert stats.error_count == 0
        assert stats.latency_sum_ms == 50.0
        assert stats.latency_min_ms == 50.0
        assert stats.latency_max_ms == 50.0
        assert stats.bytes_in == 100
        assert stats.bytes_out == 200

    def test_record_error(self):
        stats = OperationStats()
        stats.record(latency_ms=100.0, success=False, bytes_in=50, bytes_out=0)

        assert stats.count == 1
        assert stats.success_count == 0
        assert stats.error_count == 1

    def test_latency_min_max(self):
        stats = OperationStats()
        stats.record(latency_ms=50.0, success=True)
        stats.record(latency_ms=10.0, success=True)
        stats.record(latency_ms=100.0, success=True)

        assert stats.latency_min_ms == 10.0
        assert stats.latency_max_ms == 100.0
        assert stats.latency_sum_ms == 160.0

    def test_to_dict(self):
        stats = OperationStats()
        stats.record(latency_ms=50.0, success=True, bytes_in=100, bytes_out=200)
        stats.record(latency_ms=100.0, success=False, bytes_in=50, bytes_out=0)

        result = stats.to_dict()
        assert result["count"] == 2
        assert result["success_count"] == 1
        assert result["error_count"] == 1
        assert result["latency_avg_ms"] == 75.0
        assert result["latency_min_ms"] == 50.0
        assert result["latency_max_ms"] == 100.0
        assert result["bytes_in"] == 150
        assert result["bytes_out"] == 200

    def test_to_dict_empty(self):
        stats = OperationStats()
        result = stats.to_dict()
        assert result["count"] == 0
        assert result["latency_avg_ms"] == 0.0
        assert result["latency_min_ms"] == 0.0

    def test_merge(self):
        stats1 = OperationStats()
        stats1.record(latency_ms=50.0, success=True, bytes_in=100, bytes_out=200)

        stats2 = OperationStats()
        stats2.record(latency_ms=10.0, success=True, bytes_in=50, bytes_out=100)
        stats2.record(latency_ms=100.0, success=False, bytes_in=25, bytes_out=50)

        stats1.merge(stats2)

        assert stats1.count == 3
        assert stats1.success_count == 2
        assert stats1.error_count == 1
        assert stats1.latency_min_ms == 10.0
        assert stats1.latency_max_ms == 100.0
        assert stats1.bytes_in == 175
        assert stats1.bytes_out == 350


class TestClassifyEndpoint:
    def test_root_path(self):
        assert classify_endpoint("/") == "service"
        assert classify_endpoint("") == "service"

    def test_ui_paths(self):
        assert classify_endpoint("/ui") == "ui"
        assert classify_endpoint("/ui/buckets") == "ui"
        assert classify_endpoint("/ui/metrics") == "ui"

    def test_kms_paths(self):
        assert classify_endpoint("/kms") == "kms"
        assert classify_endpoint("/kms/keys") == "kms"

    def test_service_paths(self):
        assert classify_endpoint("/myfsio/health") == "service"

    def test_bucket_paths(self):
        assert classify_endpoint("/mybucket") == "bucket"
        assert classify_endpoint("/mybucket/") == "bucket"

    def test_object_paths(self):
        assert classify_endpoint("/mybucket/mykey") == "object"
        assert classify_endpoint("/mybucket/folder/nested/key.txt") == "object"


class TestOperationMetricsCollector:
    def test_record_and_get_stats(self, tmp_path: Path):
        collector = OperationMetricsCollector(
            storage_root=tmp_path,
            interval_minutes=60,
            retention_hours=24,
        )

        try:
            collector.record_request(
                method="GET",
                endpoint_type="bucket",
                status_code=200,
                latency_ms=50.0,
                bytes_in=0,
                bytes_out=1000,
            )

            collector.record_request(
                method="PUT",
                endpoint_type="object",
                status_code=201,
                latency_ms=100.0,
                bytes_in=500,
                bytes_out=0,
            )

            collector.record_request(
                method="GET",
                endpoint_type="object",
                status_code=404,
                latency_ms=25.0,
                bytes_in=0,
                bytes_out=0,
                error_code="NoSuchKey",
            )

            stats = collector.get_current_stats()

            assert stats["totals"]["count"] == 3
            assert stats["totals"]["success_count"] == 2
            assert stats["totals"]["error_count"] == 1

            assert "GET" in stats["by_method"]
            assert stats["by_method"]["GET"]["count"] == 2
            assert "PUT" in stats["by_method"]
            assert stats["by_method"]["PUT"]["count"] == 1

            assert "bucket" in stats["by_endpoint"]
            assert "object" in stats["by_endpoint"]
            assert stats["by_endpoint"]["object"]["count"] == 2

            assert stats["by_status_class"]["2xx"] == 2
            assert stats["by_status_class"]["4xx"] == 1

            assert stats["error_codes"]["NoSuchKey"] == 1
        finally:
            collector.shutdown()

    def test_thread_safety(self, tmp_path: Path):
        collector = OperationMetricsCollector(
            storage_root=tmp_path,
            interval_minutes=60,
            retention_hours=24,
        )

        try:
            num_threads = 5
            requests_per_thread = 100
            threads = []

            def record_requests():
                for _ in range(requests_per_thread):
                    collector.record_request(
                        method="GET",
                        endpoint_type="object",
                        status_code=200,
                        latency_ms=10.0,
                    )

            for _ in range(num_threads):
                t = threading.Thread(target=record_requests)
                threads.append(t)
                t.start()

            for t in threads:
                t.join()

            stats = collector.get_current_stats()
            assert stats["totals"]["count"] == num_threads * requests_per_thread
        finally:
            collector.shutdown()

    def test_status_class_categorization(self, tmp_path: Path):
        collector = OperationMetricsCollector(
            storage_root=tmp_path,
            interval_minutes=60,
            retention_hours=24,
        )

        try:
            collector.record_request("GET", "object", 200, 10.0)
            collector.record_request("GET", "object", 204, 10.0)
            collector.record_request("GET", "object", 301, 10.0)
            collector.record_request("GET", "object", 304, 10.0)
            collector.record_request("GET", "object", 400, 10.0)
            collector.record_request("GET", "object", 403, 10.0)
            collector.record_request("GET", "object", 404, 10.0)
            collector.record_request("GET", "object", 500, 10.0)
            collector.record_request("GET", "object", 503, 10.0)

            stats = collector.get_current_stats()
            assert stats["by_status_class"]["2xx"] == 2
            assert stats["by_status_class"]["3xx"] == 2
            assert stats["by_status_class"]["4xx"] == 3
            assert stats["by_status_class"]["5xx"] == 2
        finally:
            collector.shutdown()

    def test_error_code_tracking(self, tmp_path: Path):
        collector = OperationMetricsCollector(
            storage_root=tmp_path,
            interval_minutes=60,
            retention_hours=24,
        )

        try:
            collector.record_request("GET", "object", 404, 10.0, error_code="NoSuchKey")
            collector.record_request("GET", "object", 404, 10.0, error_code="NoSuchKey")
            collector.record_request("GET", "bucket", 403, 10.0, error_code="AccessDenied")
            collector.record_request("PUT", "object", 500, 10.0, error_code="InternalError")

            stats = collector.get_current_stats()
            assert stats["error_codes"]["NoSuchKey"] == 2
            assert stats["error_codes"]["AccessDenied"] == 1
            assert stats["error_codes"]["InternalError"] == 1
        finally:
            collector.shutdown()

    def test_history_persistence(self, tmp_path: Path):
        collector = OperationMetricsCollector(
            storage_root=tmp_path,
            interval_minutes=60,
            retention_hours=24,
        )

        try:
            collector.record_request("GET", "object", 200, 10.0)
            collector._take_snapshot()

            history = collector.get_history()
            assert len(history) == 1
            assert history[0]["totals"]["count"] == 1

            config_path = tmp_path / ".myfsio.sys" / "config" / "operation_metrics.json"
            assert config_path.exists()
        finally:
            collector.shutdown()

    def test_get_history_with_hours_filter(self, tmp_path: Path):
        collector = OperationMetricsCollector(
            storage_root=tmp_path,
            interval_minutes=60,
            retention_hours=24,
        )

        try:
            collector.record_request("GET", "object", 200, 10.0)
            collector._take_snapshot()

            history_all = collector.get_history()
            history_recent = collector.get_history(hours=1)

            assert len(history_all) >= len(history_recent)
        finally:
            collector.shutdown()
