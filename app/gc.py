from __future__ import annotations

import json
import logging
import os
import shutil
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class GCResult:
    temp_files_deleted: int = 0
    temp_bytes_freed: int = 0
    multipart_uploads_deleted: int = 0
    multipart_bytes_freed: int = 0
    lock_files_deleted: int = 0
    orphaned_metadata_deleted: int = 0
    orphaned_versions_deleted: int = 0
    orphaned_version_bytes_freed: int = 0
    empty_dirs_removed: int = 0
    errors: List[str] = field(default_factory=list)
    execution_time_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "temp_files_deleted": self.temp_files_deleted,
            "temp_bytes_freed": self.temp_bytes_freed,
            "multipart_uploads_deleted": self.multipart_uploads_deleted,
            "multipart_bytes_freed": self.multipart_bytes_freed,
            "lock_files_deleted": self.lock_files_deleted,
            "orphaned_metadata_deleted": self.orphaned_metadata_deleted,
            "orphaned_versions_deleted": self.orphaned_versions_deleted,
            "orphaned_version_bytes_freed": self.orphaned_version_bytes_freed,
            "empty_dirs_removed": self.empty_dirs_removed,
            "errors": self.errors,
            "execution_time_seconds": self.execution_time_seconds,
        }

    @property
    def total_bytes_freed(self) -> int:
        return self.temp_bytes_freed + self.multipart_bytes_freed + self.orphaned_version_bytes_freed

    @property
    def has_work(self) -> bool:
        return (
            self.temp_files_deleted > 0
            or self.multipart_uploads_deleted > 0
            or self.lock_files_deleted > 0
            or self.orphaned_metadata_deleted > 0
            or self.orphaned_versions_deleted > 0
            or self.empty_dirs_removed > 0
        )


@dataclass
class GCExecutionRecord:
    timestamp: float
    result: dict
    dry_run: bool

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "result": self.result,
            "dry_run": self.dry_run,
        }

    @classmethod
    def from_dict(cls, data: dict) -> GCExecutionRecord:
        return cls(
            timestamp=data["timestamp"],
            result=data["result"],
            dry_run=data.get("dry_run", False),
        )


class GCHistoryStore:
    def __init__(self, storage_root: Path, max_records: int = 50) -> None:
        self.storage_root = storage_root
        self.max_records = max_records
        self._lock = threading.Lock()

    def _get_path(self) -> Path:
        return self.storage_root / ".myfsio.sys" / "config" / "gc_history.json"

    def load(self) -> List[GCExecutionRecord]:
        path = self._get_path()
        if not path.exists():
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return [GCExecutionRecord.from_dict(d) for d in data.get("executions", [])]
        except (OSError, ValueError, KeyError) as e:
            logger.error("Failed to load GC history: %s", e)
            return []

    def save(self, records: List[GCExecutionRecord]) -> None:
        path = self._get_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {"executions": [r.to_dict() for r in records[: self.max_records]]}
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except OSError as e:
            logger.error("Failed to save GC history: %s", e)

    def add(self, record: GCExecutionRecord) -> None:
        with self._lock:
            records = self.load()
            records.insert(0, record)
            self.save(records)

    def get_history(self, limit: int = 50, offset: int = 0) -> List[GCExecutionRecord]:
        return self.load()[offset : offset + limit]


def _dir_size(path: Path) -> int:
    total = 0
    try:
        for f in path.rglob("*"):
            if f.is_file():
                try:
                    total += f.stat().st_size
                except OSError:
                    pass
    except OSError:
        pass
    return total


def _file_age_hours(path: Path) -> float:
    try:
        mtime = path.stat().st_mtime
        return (time.time() - mtime) / 3600.0
    except OSError:
        return 0.0


class GarbageCollector:
    SYSTEM_ROOT = ".myfsio.sys"
    SYSTEM_TMP_DIR = "tmp"
    SYSTEM_MULTIPART_DIR = "multipart"
    SYSTEM_BUCKETS_DIR = "buckets"
    BUCKET_META_DIR = "meta"
    BUCKET_VERSIONS_DIR = "versions"
    INTERNAL_FOLDERS = {".meta", ".versions", ".multipart"}

    def __init__(
        self,
        storage_root: Path,
        interval_hours: float = 6.0,
        temp_file_max_age_hours: float = 24.0,
        multipart_max_age_days: int = 7,
        lock_file_max_age_hours: float = 1.0,
        dry_run: bool = False,
        max_history: int = 50,
        io_throttle_ms: int = 10,
    ) -> None:
        self.storage_root = Path(storage_root)
        self.interval_seconds = interval_hours * 3600.0
        self.temp_file_max_age_hours = temp_file_max_age_hours
        self.multipart_max_age_days = multipart_max_age_days
        self.lock_file_max_age_hours = lock_file_max_age_hours
        self.dry_run = dry_run
        self._timer: Optional[threading.Timer] = None
        self._shutdown = False
        self._lock = threading.Lock()
        self._io_throttle = max(0, io_throttle_ms) / 1000.0
        self.history_store = GCHistoryStore(storage_root, max_records=max_history)

    def start(self) -> None:
        if self._timer is not None:
            return
        self._shutdown = False
        self._schedule_next()
        logger.info(
            "GC started: interval=%.1fh, temp_max_age=%.1fh, multipart_max_age=%dd, lock_max_age=%.1fh, dry_run=%s",
            self.interval_seconds / 3600.0,
            self.temp_file_max_age_hours,
            self.multipart_max_age_days,
            self.lock_file_max_age_hours,
            self.dry_run,
        )

    def stop(self) -> None:
        self._shutdown = True
        if self._timer:
            self._timer.cancel()
            self._timer = None
        logger.info("GC stopped")

    def _schedule_next(self) -> None:
        if self._shutdown:
            return
        self._timer = threading.Timer(self.interval_seconds, self._run_cycle)
        self._timer.daemon = True
        self._timer.start()

    def _run_cycle(self) -> None:
        if self._shutdown:
            return
        try:
            self.run_now()
        except Exception as e:
            logger.error("GC cycle failed: %s", e)
        finally:
            self._schedule_next()

    def run_now(self) -> GCResult:
        start = time.time()
        result = GCResult()

        self._clean_temp_files(result)
        self._clean_orphaned_multipart(result)
        self._clean_stale_locks(result)
        self._clean_orphaned_metadata(result)
        self._clean_orphaned_versions(result)
        self._clean_empty_dirs(result)

        result.execution_time_seconds = time.time() - start

        if result.has_work or result.errors:
            logger.info(
                "GC completed in %.2fs: temp=%d (%.1f MB), multipart=%d (%.1f MB), "
                "locks=%d, meta=%d, versions=%d (%.1f MB), dirs=%d, errors=%d%s",
                result.execution_time_seconds,
                result.temp_files_deleted,
                result.temp_bytes_freed / (1024 * 1024),
                result.multipart_uploads_deleted,
                result.multipart_bytes_freed / (1024 * 1024),
                result.lock_files_deleted,
                result.orphaned_metadata_deleted,
                result.orphaned_versions_deleted,
                result.orphaned_version_bytes_freed / (1024 * 1024),
                result.empty_dirs_removed,
                len(result.errors),
                " (dry run)" if self.dry_run else "",
            )

        record = GCExecutionRecord(
            timestamp=time.time(),
            result=result.to_dict(),
            dry_run=self.dry_run,
        )
        self.history_store.add(record)

        return result

    def _system_path(self) -> Path:
        return self.storage_root / self.SYSTEM_ROOT

    def _throttle(self) -> bool:
        if self._shutdown:
            return True
        if self._io_throttle > 0:
            time.sleep(self._io_throttle)
        return self._shutdown

    def _list_bucket_names(self) -> List[str]:
        names = []
        try:
            for entry in self.storage_root.iterdir():
                if entry.is_dir() and entry.name != self.SYSTEM_ROOT:
                    names.append(entry.name)
        except OSError:
            pass
        return names

    def _clean_temp_files(self, result: GCResult) -> None:
        tmp_dir = self._system_path() / self.SYSTEM_TMP_DIR
        if not tmp_dir.exists():
            return
        try:
            for entry in tmp_dir.iterdir():
                if self._throttle():
                    return
                if not entry.is_file():
                    continue
                age = _file_age_hours(entry)
                if age < self.temp_file_max_age_hours:
                    continue
                try:
                    size = entry.stat().st_size
                    if not self.dry_run:
                        entry.unlink()
                    result.temp_files_deleted += 1
                    result.temp_bytes_freed += size
                except OSError as e:
                    result.errors.append(f"temp file {entry.name}: {e}")
        except OSError as e:
            result.errors.append(f"scan tmp dir: {e}")

    def _clean_orphaned_multipart(self, result: GCResult) -> None:
        cutoff_hours = self.multipart_max_age_days * 24.0
        bucket_names = self._list_bucket_names()

        for bucket_name in bucket_names:
            if self._shutdown:
                return
            for multipart_root in (
                self._system_path() / self.SYSTEM_MULTIPART_DIR / bucket_name,
                self.storage_root / bucket_name / ".multipart",
            ):
                if not multipart_root.exists():
                    continue
                try:
                    for upload_dir in multipart_root.iterdir():
                        if self._throttle():
                            return
                        if not upload_dir.is_dir():
                            continue
                        self._maybe_clean_upload(upload_dir, cutoff_hours, result)
                except OSError as e:
                    result.errors.append(f"scan multipart {bucket_name}: {e}")

    def _maybe_clean_upload(self, upload_dir: Path, cutoff_hours: float, result: GCResult) -> None:
        manifest_path = upload_dir / "manifest.json"
        age = _file_age_hours(manifest_path) if manifest_path.exists() else _file_age_hours(upload_dir)

        if age < cutoff_hours:
            return

        dir_bytes = _dir_size(upload_dir)
        try:
            if not self.dry_run:
                shutil.rmtree(upload_dir, ignore_errors=True)
            result.multipart_uploads_deleted += 1
            result.multipart_bytes_freed += dir_bytes
        except OSError as e:
            result.errors.append(f"multipart {upload_dir.name}: {e}")

    def _clean_stale_locks(self, result: GCResult) -> None:
        buckets_root = self._system_path() / self.SYSTEM_BUCKETS_DIR
        if not buckets_root.exists():
            return

        try:
            for bucket_dir in buckets_root.iterdir():
                if self._shutdown:
                    return
                if not bucket_dir.is_dir():
                    continue
                locks_dir = bucket_dir / "locks"
                if not locks_dir.exists():
                    continue
                try:
                    for lock_file in locks_dir.iterdir():
                        if self._throttle():
                            return
                        if not lock_file.is_file() or not lock_file.name.endswith(".lock"):
                            continue
                        age = _file_age_hours(lock_file)
                        if age < self.lock_file_max_age_hours:
                            continue
                        try:
                            if not self.dry_run:
                                lock_file.unlink(missing_ok=True)
                            result.lock_files_deleted += 1
                        except OSError as e:
                            result.errors.append(f"lock {lock_file.name}: {e}")
                except OSError as e:
                    result.errors.append(f"scan locks {bucket_dir.name}: {e}")
        except OSError as e:
            result.errors.append(f"scan buckets for locks: {e}")

    def _clean_orphaned_metadata(self, result: GCResult) -> None:
        bucket_names = self._list_bucket_names()

        for bucket_name in bucket_names:
            if self._shutdown:
                return
            legacy_meta = self.storage_root / bucket_name / ".meta"
            if legacy_meta.exists():
                self._clean_legacy_metadata(bucket_name, legacy_meta, result)

            new_meta = self._system_path() / self.SYSTEM_BUCKETS_DIR / bucket_name / self.BUCKET_META_DIR
            if new_meta.exists():
                self._clean_index_metadata(bucket_name, new_meta, result)

    def _clean_legacy_metadata(self, bucket_name: str, meta_root: Path, result: GCResult) -> None:
        bucket_path = self.storage_root / bucket_name
        try:
            for meta_file in meta_root.rglob("*.meta.json"):
                if self._throttle():
                    return
                if not meta_file.is_file():
                    continue
                try:
                    rel = meta_file.relative_to(meta_root)
                    object_key = rel.as_posix().removesuffix(".meta.json")
                    object_path = bucket_path / object_key
                    if not object_path.exists():
                        if not self.dry_run:
                            meta_file.unlink(missing_ok=True)
                        result.orphaned_metadata_deleted += 1
                except (OSError, ValueError) as e:
                    result.errors.append(f"legacy meta {bucket_name}/{meta_file.name}: {e}")
        except OSError as e:
            result.errors.append(f"scan legacy meta {bucket_name}: {e}")

    def _clean_index_metadata(self, bucket_name: str, meta_root: Path, result: GCResult) -> None:
        bucket_path = self.storage_root / bucket_name
        try:
            for index_file in meta_root.rglob("_index.json"):
                if self._throttle():
                    return
                if not index_file.is_file():
                    continue
                try:
                    with open(index_file, "r", encoding="utf-8") as f:
                        index_data = json.load(f)
                except (OSError, json.JSONDecodeError):
                    continue

                keys_to_remove = []
                for key in index_data:
                    rel_dir = index_file.parent.relative_to(meta_root)
                    if rel_dir == Path("."):
                        full_key = key
                    else:
                        full_key = rel_dir.as_posix() + "/" + key
                    object_path = bucket_path / full_key
                    if not object_path.exists():
                        keys_to_remove.append(key)

                if keys_to_remove:
                    if not self.dry_run:
                        for k in keys_to_remove:
                            index_data.pop(k, None)
                        if index_data:
                            try:
                                with open(index_file, "w", encoding="utf-8") as f:
                                    json.dump(index_data, f)
                            except OSError as e:
                                result.errors.append(f"write index {bucket_name}: {e}")
                                continue
                        else:
                            try:
                                index_file.unlink(missing_ok=True)
                            except OSError:
                                pass
                    result.orphaned_metadata_deleted += len(keys_to_remove)
        except OSError as e:
            result.errors.append(f"scan index meta {bucket_name}: {e}")

    def _clean_orphaned_versions(self, result: GCResult) -> None:
        bucket_names = self._list_bucket_names()

        for bucket_name in bucket_names:
            if self._shutdown:
                return
            bucket_path = self.storage_root / bucket_name
            for versions_root in (
                self._system_path() / self.SYSTEM_BUCKETS_DIR / bucket_name / self.BUCKET_VERSIONS_DIR,
                self.storage_root / bucket_name / ".versions",
            ):
                if not versions_root.exists():
                    continue
                try:
                    for key_dir in versions_root.iterdir():
                        if self._throttle():
                            return
                        if not key_dir.is_dir():
                            continue
                        self._clean_versions_for_key(bucket_path, versions_root, key_dir, result)
                except OSError as e:
                    result.errors.append(f"scan versions {bucket_name}: {e}")

    def _clean_versions_for_key(
        self, bucket_path: Path, versions_root: Path, key_dir: Path, result: GCResult
    ) -> None:
        try:
            rel = key_dir.relative_to(versions_root)
        except ValueError:
            return

        object_path = bucket_path / rel
        if object_path.exists():
            return

        version_files = list(key_dir.glob("*.bin")) + list(key_dir.glob("*.json"))
        if not version_files:
            return

        for vf in version_files:
            try:
                size = vf.stat().st_size if vf.suffix == ".bin" else 0
                if not self.dry_run:
                    vf.unlink(missing_ok=True)
                if vf.suffix == ".bin":
                    result.orphaned_version_bytes_freed += size
                result.orphaned_versions_deleted += 1
            except OSError as e:
                result.errors.append(f"version file {vf.name}: {e}")

    def _clean_empty_dirs(self, result: GCResult) -> None:
        targets = [
            self._system_path() / self.SYSTEM_TMP_DIR,
            self._system_path() / self.SYSTEM_MULTIPART_DIR,
            self._system_path() / self.SYSTEM_BUCKETS_DIR,
        ]
        for bucket_name in self._list_bucket_names():
            targets.append(self.storage_root / bucket_name / ".meta")
            targets.append(self.storage_root / bucket_name / ".versions")
            targets.append(self.storage_root / bucket_name / ".multipart")

        for root in targets:
            if not root.exists():
                continue
            self._remove_empty_dirs_recursive(root, root, result)

    def _remove_empty_dirs_recursive(self, path: Path, stop_at: Path, result: GCResult) -> bool:
        if self._shutdown:
            return False
        if not path.is_dir():
            return False

        try:
            children = list(path.iterdir())
        except OSError:
            return False

        all_empty = True
        for child in children:
            if self._throttle():
                return False
            if child.is_dir():
                if not self._remove_empty_dirs_recursive(child, stop_at, result):
                    all_empty = False
            else:
                all_empty = False

        if all_empty and path != stop_at:
            try:
                if not self.dry_run:
                    path.rmdir()
                result.empty_dirs_removed += 1
                return True
            except OSError:
                return False
        return all_empty

    def get_history(self, limit: int = 50, offset: int = 0) -> List[dict]:
        records = self.history_store.get_history(limit, offset)
        return [r.to_dict() for r in records]

    def get_status(self) -> dict:
        return {
            "enabled": not self._shutdown or self._timer is not None,
            "running": self._timer is not None and not self._shutdown,
            "interval_hours": self.interval_seconds / 3600.0,
            "temp_file_max_age_hours": self.temp_file_max_age_hours,
            "multipart_max_age_days": self.multipart_max_age_days,
            "lock_file_max_age_hours": self.lock_file_max_age_hours,
            "dry_run": self.dry_run,
            "io_throttle_ms": round(self._io_throttle * 1000),
        }
