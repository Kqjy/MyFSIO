from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .storage import ObjectStorage, StorageError

logger = logging.getLogger(__name__)


@dataclass
class LifecycleResult:
    bucket_name: str
    objects_deleted: int = 0
    versions_deleted: int = 0
    uploads_aborted: int = 0
    errors: List[str] = field(default_factory=list)
    execution_time_seconds: float = 0.0


@dataclass
class LifecycleExecutionRecord:
    timestamp: float
    bucket_name: str
    objects_deleted: int
    versions_deleted: int
    uploads_aborted: int
    errors: List[str]
    execution_time_seconds: float

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "bucket_name": self.bucket_name,
            "objects_deleted": self.objects_deleted,
            "versions_deleted": self.versions_deleted,
            "uploads_aborted": self.uploads_aborted,
            "errors": self.errors,
            "execution_time_seconds": self.execution_time_seconds,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "LifecycleExecutionRecord":
        return cls(
            timestamp=data["timestamp"],
            bucket_name=data["bucket_name"],
            objects_deleted=data["objects_deleted"],
            versions_deleted=data["versions_deleted"],
            uploads_aborted=data["uploads_aborted"],
            errors=data.get("errors", []),
            execution_time_seconds=data["execution_time_seconds"],
        )

    @classmethod
    def from_result(cls, result: LifecycleResult) -> "LifecycleExecutionRecord":
        return cls(
            timestamp=time.time(),
            bucket_name=result.bucket_name,
            objects_deleted=result.objects_deleted,
            versions_deleted=result.versions_deleted,
            uploads_aborted=result.uploads_aborted,
            errors=result.errors.copy(),
            execution_time_seconds=result.execution_time_seconds,
        )


class LifecycleHistoryStore:
    def __init__(self, storage_root: Path, max_history_per_bucket: int = 50) -> None:
        self.storage_root = storage_root
        self.max_history_per_bucket = max_history_per_bucket
        self._lock = threading.Lock()

    def _get_history_path(self, bucket_name: str) -> Path:
        return self.storage_root / ".myfsio.sys" / "buckets" / bucket_name / "lifecycle_history.json"

    def load_history(self, bucket_name: str) -> List[LifecycleExecutionRecord]:
        path = self._get_history_path(bucket_name)
        if not path.exists():
            return []
        try:
            with open(path, "r") as f:
                data = json.load(f)
                return [LifecycleExecutionRecord.from_dict(d) for d in data.get("executions", [])]
        except (OSError, ValueError, KeyError) as e:
            logger.error(f"Failed to load lifecycle history for {bucket_name}: {e}")
            return []

    def save_history(self, bucket_name: str, records: List[LifecycleExecutionRecord]) -> None:
        path = self._get_history_path(bucket_name)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {"executions": [r.to_dict() for r in records[:self.max_history_per_bucket]]}
        try:
            with open(path, "w") as f:
                json.dump(data, f, indent=2)
        except OSError as e:
            logger.error(f"Failed to save lifecycle history for {bucket_name}: {e}")

    def add_record(self, bucket_name: str, record: LifecycleExecutionRecord) -> None:
        with self._lock:
            records = self.load_history(bucket_name)
            records.insert(0, record)
            self.save_history(bucket_name, records)

    def get_history(self, bucket_name: str, limit: int = 50, offset: int = 0) -> List[LifecycleExecutionRecord]:
        records = self.load_history(bucket_name)
        return records[offset:offset + limit]


class LifecycleManager:
    def __init__(
        self,
        storage: ObjectStorage,
        interval_seconds: int = 3600,
        storage_root: Optional[Path] = None,
        max_history_per_bucket: int = 50,
    ):
        self.storage = storage
        self.interval_seconds = interval_seconds
        self.storage_root = storage_root
        self._timer: Optional[threading.Timer] = None
        self._shutdown = False
        self._lock = threading.Lock()
        self.history_store = LifecycleHistoryStore(storage_root, max_history_per_bucket) if storage_root else None

    def start(self) -> None:
        if self._timer is not None:
            return
        self._shutdown = False
        self._schedule_next()
        logger.info(f"Lifecycle manager started with interval {self.interval_seconds}s")

    def stop(self) -> None:
        self._shutdown = True
        if self._timer:
            self._timer.cancel()
            self._timer = None
        logger.info("Lifecycle manager stopped")

    def _schedule_next(self) -> None:
        if self._shutdown:
            return
        self._timer = threading.Timer(self.interval_seconds, self._run_enforcement)
        self._timer.daemon = True
        self._timer.start()

    def _run_enforcement(self) -> None:
        if self._shutdown:
            return
        try:
            self.enforce_all_buckets()
        except Exception as e:
            logger.error(f"Lifecycle enforcement failed: {e}")
        finally:
            self._schedule_next()

    def enforce_all_buckets(self) -> Dict[str, LifecycleResult]:
        results = {}
        try:
            buckets = self.storage.list_buckets()
            for bucket in buckets:
                result = self.enforce_rules(bucket.name)
                if result.objects_deleted > 0 or result.versions_deleted > 0 or result.uploads_aborted > 0:
                    results[bucket.name] = result
        except StorageError as e:
            logger.error(f"Failed to list buckets for lifecycle: {e}")
        return results

    def enforce_rules(self, bucket_name: str) -> LifecycleResult:
        start_time = time.time()
        result = LifecycleResult(bucket_name=bucket_name)

        try:
            lifecycle = self.storage.get_bucket_lifecycle(bucket_name)
            if not lifecycle:
                return result

            for rule in lifecycle:
                if rule.get("Status") != "Enabled":
                    continue
                rule_id = rule.get("ID", "unknown")
                prefix = rule.get("Prefix", rule.get("Filter", {}).get("Prefix", ""))

                self._enforce_expiration(bucket_name, rule, prefix, result)
                self._enforce_noncurrent_expiration(bucket_name, rule, prefix, result)
                self._enforce_abort_multipart(bucket_name, rule, result)

        except StorageError as e:
            result.errors.append(str(e))
            logger.error(f"Lifecycle enforcement error for {bucket_name}: {e}")

        result.execution_time_seconds = time.time() - start_time
        if result.objects_deleted > 0 or result.versions_deleted > 0 or result.uploads_aborted > 0 or result.errors:
            logger.info(
                f"Lifecycle enforcement for {bucket_name}: "
                f"deleted={result.objects_deleted}, versions={result.versions_deleted}, "
                f"aborted={result.uploads_aborted}, time={result.execution_time_seconds:.2f}s"
            )
            if self.history_store:
                record = LifecycleExecutionRecord.from_result(result)
                self.history_store.add_record(bucket_name, record)
        return result

    def _enforce_expiration(
        self, bucket_name: str, rule: Dict[str, Any], prefix: str, result: LifecycleResult
    ) -> None:
        expiration = rule.get("Expiration", {})
        if not expiration:
            return

        days = expiration.get("Days")
        date_str = expiration.get("Date")

        if days:
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        elif date_str:
            try:
                cutoff = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            except ValueError:
                return
        else:
            return

        try:
            objects = self.storage.list_objects_all(bucket_name)
            for obj in objects:
                if prefix and not obj.key.startswith(prefix):
                    continue
                if obj.last_modified < cutoff:
                    try:
                        self.storage.delete_object(bucket_name, obj.key)
                        result.objects_deleted += 1
                    except StorageError as e:
                        result.errors.append(f"Failed to delete {obj.key}: {e}")
        except StorageError as e:
            result.errors.append(f"Failed to list objects: {e}")

    def _enforce_noncurrent_expiration(
        self, bucket_name: str, rule: Dict[str, Any], prefix: str, result: LifecycleResult
    ) -> None:
        noncurrent = rule.get("NoncurrentVersionExpiration", {})
        noncurrent_days = noncurrent.get("NoncurrentDays")
        if not noncurrent_days:
            return

        cutoff = datetime.now(timezone.utc) - timedelta(days=noncurrent_days)

        try:
            objects = self.storage.list_objects_all(bucket_name)
            for obj in objects:
                if prefix and not obj.key.startswith(prefix):
                    continue
                try:
                    versions = self.storage.list_object_versions(bucket_name, obj.key)
                    for version in versions:
                        archived_at_str = version.get("archived_at", "")
                        if not archived_at_str:
                            continue
                        try:
                            archived_at = datetime.fromisoformat(archived_at_str.replace("Z", "+00:00"))
                            if archived_at < cutoff:
                                version_id = version.get("version_id")
                                if version_id:
                                    self.storage.delete_object_version(bucket_name, obj.key, version_id)
                                    result.versions_deleted += 1
                        except (ValueError, StorageError) as e:
                            result.errors.append(f"Failed to process version: {e}")
                except StorageError:
                    pass
        except StorageError as e:
            result.errors.append(f"Failed to list objects: {e}")

        try:
            orphaned = self.storage.list_orphaned_objects(bucket_name)
            for item in orphaned:
                obj_key = item.get("key", "")
                if prefix and not obj_key.startswith(prefix):
                    continue
                try:
                    versions = self.storage.list_object_versions(bucket_name, obj_key)
                    for version in versions:
                        archived_at_str = version.get("archived_at", "")
                        if not archived_at_str:
                            continue
                        try:
                            archived_at = datetime.fromisoformat(archived_at_str.replace("Z", "+00:00"))
                            if archived_at < cutoff:
                                version_id = version.get("version_id")
                                if version_id:
                                    self.storage.delete_object_version(bucket_name, obj_key, version_id)
                                    result.versions_deleted += 1
                        except (ValueError, StorageError) as e:
                            result.errors.append(f"Failed to process orphaned version: {e}")
                except StorageError:
                    pass
        except StorageError as e:
            result.errors.append(f"Failed to list orphaned objects: {e}")

    def _enforce_abort_multipart(
        self, bucket_name: str, rule: Dict[str, Any], result: LifecycleResult
    ) -> None:
        abort_config = rule.get("AbortIncompleteMultipartUpload", {})
        days_after = abort_config.get("DaysAfterInitiation")
        if not days_after:
            return

        cutoff = datetime.now(timezone.utc) - timedelta(days=days_after)

        try:
            uploads = self.storage.list_multipart_uploads(bucket_name)
            for upload in uploads:
                created_at_str = upload.get("created_at", "")
                if not created_at_str:
                    continue
                try:
                    created_at = datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
                    if created_at < cutoff:
                        upload_id = upload.get("upload_id")
                        if upload_id:
                            self.storage.abort_multipart_upload(bucket_name, upload_id)
                            result.uploads_aborted += 1
                except (ValueError, StorageError) as e:
                    result.errors.append(f"Failed to abort upload: {e}")
        except StorageError as e:
            result.errors.append(f"Failed to list multipart uploads: {e}")

    def run_now(self, bucket_name: Optional[str] = None) -> Dict[str, LifecycleResult]:
        if bucket_name:
            return {bucket_name: self.enforce_rules(bucket_name)}
        return self.enforce_all_buckets()

    def get_execution_history(self, bucket_name: str, limit: int = 50, offset: int = 0) -> List[LifecycleExecutionRecord]:
        if not self.history_store:
            return []
        return self.history_store.get_history(bucket_name, limit, offset)
