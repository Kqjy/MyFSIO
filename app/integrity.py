from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import myfsio_core as _rc
    _HAS_RUST = True
except ImportError:
    _HAS_RUST = False

logger = logging.getLogger(__name__)


def _compute_etag(path: Path) -> str:
    if _HAS_RUST:
        return _rc.md5_file(str(path))
    checksum = hashlib.md5()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


@dataclass
class IntegrityIssue:
    issue_type: str
    bucket: str
    key: str
    detail: str
    healed: bool = False
    heal_action: str = ""

    def to_dict(self) -> dict:
        return {
            "issue_type": self.issue_type,
            "bucket": self.bucket,
            "key": self.key,
            "detail": self.detail,
            "healed": self.healed,
            "heal_action": self.heal_action,
        }


@dataclass
class IntegrityResult:
    corrupted_objects: int = 0
    orphaned_objects: int = 0
    phantom_metadata: int = 0
    stale_versions: int = 0
    etag_cache_inconsistencies: int = 0
    legacy_metadata_drifts: int = 0
    issues_healed: int = 0
    issues: List[IntegrityIssue] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    objects_scanned: int = 0
    buckets_scanned: int = 0
    execution_time_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "corrupted_objects": self.corrupted_objects,
            "orphaned_objects": self.orphaned_objects,
            "phantom_metadata": self.phantom_metadata,
            "stale_versions": self.stale_versions,
            "etag_cache_inconsistencies": self.etag_cache_inconsistencies,
            "legacy_metadata_drifts": self.legacy_metadata_drifts,
            "issues_healed": self.issues_healed,
            "issues": [i.to_dict() for i in self.issues],
            "errors": self.errors,
            "objects_scanned": self.objects_scanned,
            "buckets_scanned": self.buckets_scanned,
            "execution_time_seconds": self.execution_time_seconds,
        }

    @property
    def total_issues(self) -> int:
        return (
            self.corrupted_objects
            + self.orphaned_objects
            + self.phantom_metadata
            + self.stale_versions
            + self.etag_cache_inconsistencies
            + self.legacy_metadata_drifts
        )

    @property
    def has_issues(self) -> bool:
        return self.total_issues > 0


@dataclass
class IntegrityExecutionRecord:
    timestamp: float
    result: dict
    dry_run: bool
    auto_heal: bool

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "result": self.result,
            "dry_run": self.dry_run,
            "auto_heal": self.auto_heal,
        }

    @classmethod
    def from_dict(cls, data: dict) -> IntegrityExecutionRecord:
        return cls(
            timestamp=data["timestamp"],
            result=data["result"],
            dry_run=data.get("dry_run", False),
            auto_heal=data.get("auto_heal", False),
        )


class IntegrityHistoryStore:
    def __init__(self, storage_root: Path, max_records: int = 50) -> None:
        self.storage_root = storage_root
        self.max_records = max_records
        self._lock = threading.Lock()

    def _get_path(self) -> Path:
        return self.storage_root / ".myfsio.sys" / "config" / "integrity_history.json"

    def load(self) -> List[IntegrityExecutionRecord]:
        path = self._get_path()
        if not path.exists():
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return [IntegrityExecutionRecord.from_dict(d) for d in data.get("executions", [])]
        except (OSError, ValueError, KeyError) as e:
            logger.error("Failed to load integrity history: %s", e)
            return []

    def save(self, records: List[IntegrityExecutionRecord]) -> None:
        path = self._get_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {"executions": [r.to_dict() for r in records[: self.max_records]]}
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except OSError as e:
            logger.error("Failed to save integrity history: %s", e)

    def add(self, record: IntegrityExecutionRecord) -> None:
        with self._lock:
            records = self.load()
            records.insert(0, record)
            self.save(records)

    def get_history(self, limit: int = 50, offset: int = 0) -> List[IntegrityExecutionRecord]:
        return self.load()[offset : offset + limit]


MAX_ISSUES = 500


class IntegrityChecker:
    SYSTEM_ROOT = ".myfsio.sys"
    SYSTEM_BUCKETS_DIR = "buckets"
    BUCKET_META_DIR = "meta"
    BUCKET_VERSIONS_DIR = "versions"
    INTERNAL_FOLDERS = {".meta", ".versions", ".multipart"}

    def __init__(
        self,
        storage_root: Path,
        interval_hours: float = 24.0,
        batch_size: int = 1000,
        auto_heal: bool = False,
        dry_run: bool = False,
        max_history: int = 50,
        io_throttle_ms: int = 10,
    ) -> None:
        self.storage_root = Path(storage_root)
        self.interval_seconds = interval_hours * 3600.0
        self.batch_size = batch_size
        self.auto_heal = auto_heal
        self.dry_run = dry_run
        self._timer: Optional[threading.Timer] = None
        self._shutdown = False
        self._lock = threading.Lock()
        self._scanning = False
        self._scan_start_time: Optional[float] = None
        self._io_throttle = max(0, io_throttle_ms) / 1000.0
        self.history_store = IntegrityHistoryStore(storage_root, max_records=max_history)

    def start(self) -> None:
        if self._timer is not None:
            return
        self._shutdown = False
        self._schedule_next()
        logger.info(
            "Integrity checker started: interval=%.1fh, batch_size=%d, auto_heal=%s, dry_run=%s",
            self.interval_seconds / 3600.0,
            self.batch_size,
            self.auto_heal,
            self.dry_run,
        )

    def stop(self) -> None:
        self._shutdown = True
        if self._timer:
            self._timer.cancel()
            self._timer = None
        logger.info("Integrity checker stopped")

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
            logger.error("Integrity check cycle failed: %s", e)
        finally:
            self._schedule_next()

    def run_now(self, auto_heal: Optional[bool] = None, dry_run: Optional[bool] = None) -> IntegrityResult:
        if not self._lock.acquire(blocking=False):
            raise RuntimeError("Integrity scan is already in progress")

        try:
            self._scanning = True
            self._scan_start_time = time.time()

            effective_auto_heal = auto_heal if auto_heal is not None else self.auto_heal
            effective_dry_run = dry_run if dry_run is not None else self.dry_run

            start = self._scan_start_time
            result = IntegrityResult()

            bucket_names = self._list_bucket_names()

            for bucket_name in bucket_names:
                if self._shutdown or result.objects_scanned >= self.batch_size:
                    break
                result.buckets_scanned += 1
                self._check_corrupted_objects(bucket_name, result, effective_auto_heal, effective_dry_run)
                self._check_orphaned_objects(bucket_name, result, effective_auto_heal, effective_dry_run)
                self._check_phantom_metadata(bucket_name, result, effective_auto_heal, effective_dry_run)
                self._check_stale_versions(bucket_name, result, effective_auto_heal, effective_dry_run)
                self._check_etag_cache(bucket_name, result, effective_auto_heal, effective_dry_run)
                self._check_legacy_metadata(bucket_name, result, effective_auto_heal, effective_dry_run)

            result.execution_time_seconds = time.time() - start

            if result.has_issues or result.errors:
                logger.info(
                    "Integrity check completed in %.2fs: corrupted=%d, orphaned=%d, phantom=%d, "
                    "stale_versions=%d, etag_cache=%d, legacy_drift=%d, healed=%d, errors=%d%s",
                    result.execution_time_seconds,
                    result.corrupted_objects,
                    result.orphaned_objects,
                    result.phantom_metadata,
                    result.stale_versions,
                    result.etag_cache_inconsistencies,
                    result.legacy_metadata_drifts,
                    result.issues_healed,
                    len(result.errors),
                    " (dry run)" if effective_dry_run else "",
                )

            record = IntegrityExecutionRecord(
                timestamp=time.time(),
                result=result.to_dict(),
                dry_run=effective_dry_run,
                auto_heal=effective_auto_heal,
            )
            self.history_store.add(record)

            return result
        finally:
            self._scanning = False
            self._scan_start_time = None
            self._lock.release()

    def run_async(self, auto_heal: Optional[bool] = None, dry_run: Optional[bool] = None) -> bool:
        if self._scanning:
            return False
        t = threading.Thread(target=self.run_now, args=(auto_heal, dry_run), daemon=True)
        t.start()
        return True

    def _system_path(self) -> Path:
        return self.storage_root / self.SYSTEM_ROOT

    def _list_bucket_names(self) -> List[str]:
        names = []
        try:
            for entry in self.storage_root.iterdir():
                if entry.is_dir() and entry.name != self.SYSTEM_ROOT:
                    names.append(entry.name)
        except OSError:
            pass
        return names

    def _throttle(self) -> bool:
        if self._shutdown:
            return True
        if self._io_throttle > 0:
            time.sleep(self._io_throttle)
        return self._shutdown

    def _add_issue(self, result: IntegrityResult, issue: IntegrityIssue) -> None:
        if len(result.issues) < MAX_ISSUES:
            result.issues.append(issue)

    def _check_corrupted_objects(
        self, bucket_name: str, result: IntegrityResult, auto_heal: bool, dry_run: bool
    ) -> None:
        bucket_path = self.storage_root / bucket_name
        meta_root = self._system_path() / self.SYSTEM_BUCKETS_DIR / bucket_name / self.BUCKET_META_DIR

        if not meta_root.exists():
            return

        try:
            for index_file in meta_root.rglob("_index.json"):
                if self._throttle():
                    return
                if result.objects_scanned >= self.batch_size:
                    return
                if not index_file.is_file():
                    continue
                try:
                    index_data = json.loads(index_file.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue

                for key_name, entry in list(index_data.items()):
                    if self._throttle():
                        return
                    if result.objects_scanned >= self.batch_size:
                        return

                    rel_dir = index_file.parent.relative_to(meta_root)
                    if rel_dir == Path("."):
                        full_key = key_name
                    else:
                        full_key = rel_dir.as_posix() + "/" + key_name

                    object_path = bucket_path / full_key
                    if not object_path.exists():
                        continue

                    result.objects_scanned += 1

                    meta = entry.get("metadata", {}) if isinstance(entry, dict) else {}
                    stored_etag = meta.get("__etag__")
                    if not stored_etag:
                        continue

                    try:
                        actual_etag = _compute_etag(object_path)
                    except OSError:
                        continue

                    if actual_etag != stored_etag:
                        result.corrupted_objects += 1
                        issue = IntegrityIssue(
                            issue_type="corrupted_object",
                            bucket=bucket_name,
                            key=full_key,
                            detail=f"stored_etag={stored_etag} actual_etag={actual_etag}",
                        )

                        if auto_heal and not dry_run:
                            try:
                                stat = object_path.stat()
                                meta["__etag__"] = actual_etag
                                meta["__size__"] = str(stat.st_size)
                                meta["__last_modified__"] = str(stat.st_mtime)
                                index_data[key_name] = {"metadata": meta}
                                self._atomic_write_index(index_file, index_data)
                                issue.healed = True
                                issue.heal_action = "updated etag in index"
                                result.issues_healed += 1
                            except OSError as e:
                                result.errors.append(f"heal corrupted {bucket_name}/{full_key}: {e}")

                        self._add_issue(result, issue)
        except OSError as e:
            result.errors.append(f"check corrupted {bucket_name}: {e}")

    def _check_orphaned_objects(
        self, bucket_name: str, result: IntegrityResult, auto_heal: bool, dry_run: bool
    ) -> None:
        bucket_path = self.storage_root / bucket_name
        meta_root = self._system_path() / self.SYSTEM_BUCKETS_DIR / bucket_name / self.BUCKET_META_DIR

        try:
            for entry in bucket_path.rglob("*"):
                if self._throttle():
                    return
                if result.objects_scanned >= self.batch_size:
                    return
                if not entry.is_file():
                    continue
                try:
                    rel = entry.relative_to(bucket_path)
                except ValueError:
                    continue
                if rel.parts and rel.parts[0] in self.INTERNAL_FOLDERS:
                    continue

                full_key = rel.as_posix()
                key_name = rel.name
                parent = rel.parent

                if parent == Path("."):
                    index_path = meta_root / "_index.json"
                else:
                    index_path = meta_root / parent / "_index.json"

                has_entry = False
                if index_path.exists():
                    try:
                        index_data = json.loads(index_path.read_text(encoding="utf-8"))
                        has_entry = key_name in index_data
                    except (OSError, json.JSONDecodeError):
                        pass

                if not has_entry:
                    result.orphaned_objects += 1
                    issue = IntegrityIssue(
                        issue_type="orphaned_object",
                        bucket=bucket_name,
                        key=full_key,
                        detail="file exists without metadata entry",
                    )

                    if auto_heal and not dry_run:
                        try:
                            etag = _compute_etag(entry)
                            stat = entry.stat()
                            meta = {
                                "__etag__": etag,
                                "__size__": str(stat.st_size),
                                "__last_modified__": str(stat.st_mtime),
                            }
                            index_data = {}
                            if index_path.exists():
                                try:
                                    index_data = json.loads(index_path.read_text(encoding="utf-8"))
                                except (OSError, json.JSONDecodeError):
                                    pass
                            index_data[key_name] = {"metadata": meta}
                            self._atomic_write_index(index_path, index_data)
                            issue.healed = True
                            issue.heal_action = "created metadata entry"
                            result.issues_healed += 1
                        except OSError as e:
                            result.errors.append(f"heal orphaned {bucket_name}/{full_key}: {e}")

                    self._add_issue(result, issue)
        except OSError as e:
            result.errors.append(f"check orphaned {bucket_name}: {e}")

    def _check_phantom_metadata(
        self, bucket_name: str, result: IntegrityResult, auto_heal: bool, dry_run: bool
    ) -> None:
        bucket_path = self.storage_root / bucket_name
        meta_root = self._system_path() / self.SYSTEM_BUCKETS_DIR / bucket_name / self.BUCKET_META_DIR

        if not meta_root.exists():
            return

        try:
            for index_file in meta_root.rglob("_index.json"):
                if self._throttle():
                    return
                if not index_file.is_file():
                    continue
                try:
                    index_data = json.loads(index_file.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue

                keys_to_remove = []
                for key_name in list(index_data.keys()):
                    rel_dir = index_file.parent.relative_to(meta_root)
                    if rel_dir == Path("."):
                        full_key = key_name
                    else:
                        full_key = rel_dir.as_posix() + "/" + key_name

                    object_path = bucket_path / full_key
                    if not object_path.exists():
                        result.phantom_metadata += 1
                        issue = IntegrityIssue(
                            issue_type="phantom_metadata",
                            bucket=bucket_name,
                            key=full_key,
                            detail="metadata entry without file on disk",
                        )
                        if auto_heal and not dry_run:
                            keys_to_remove.append(key_name)
                            issue.healed = True
                            issue.heal_action = "removed stale index entry"
                            result.issues_healed += 1
                        self._add_issue(result, issue)

                if keys_to_remove and auto_heal and not dry_run:
                    try:
                        for k in keys_to_remove:
                            index_data.pop(k, None)
                        if index_data:
                            self._atomic_write_index(index_file, index_data)
                        else:
                            index_file.unlink(missing_ok=True)
                    except OSError as e:
                        result.errors.append(f"heal phantom {bucket_name}: {e}")
        except OSError as e:
            result.errors.append(f"check phantom {bucket_name}: {e}")

    def _check_stale_versions(
        self, bucket_name: str, result: IntegrityResult, auto_heal: bool, dry_run: bool
    ) -> None:
        versions_root = self._system_path() / self.SYSTEM_BUCKETS_DIR / bucket_name / self.BUCKET_VERSIONS_DIR

        if not versions_root.exists():
            return

        try:
            for key_dir in versions_root.rglob("*"):
                if self._throttle():
                    return
                if not key_dir.is_dir():
                    continue

                bin_files = {f.stem: f for f in key_dir.glob("*.bin")}
                json_files = {f.stem: f for f in key_dir.glob("*.json")}

                for stem, bin_file in bin_files.items():
                    if stem not in json_files:
                        result.stale_versions += 1
                        issue = IntegrityIssue(
                            issue_type="stale_version",
                            bucket=bucket_name,
                            key=f"{key_dir.relative_to(versions_root).as_posix()}/{bin_file.name}",
                            detail="version data without manifest",
                        )
                        if auto_heal and not dry_run:
                            try:
                                bin_file.unlink(missing_ok=True)
                                issue.healed = True
                                issue.heal_action = "removed orphaned version data"
                                result.issues_healed += 1
                            except OSError as e:
                                result.errors.append(f"heal stale version {bin_file}: {e}")
                        self._add_issue(result, issue)

                for stem, json_file in json_files.items():
                    if stem not in bin_files:
                        result.stale_versions += 1
                        issue = IntegrityIssue(
                            issue_type="stale_version",
                            bucket=bucket_name,
                            key=f"{key_dir.relative_to(versions_root).as_posix()}/{json_file.name}",
                            detail="version manifest without data",
                        )
                        if auto_heal and not dry_run:
                            try:
                                json_file.unlink(missing_ok=True)
                                issue.healed = True
                                issue.heal_action = "removed orphaned version manifest"
                                result.issues_healed += 1
                            except OSError as e:
                                result.errors.append(f"heal stale version {json_file}: {e}")
                        self._add_issue(result, issue)
        except OSError as e:
            result.errors.append(f"check stale versions {bucket_name}: {e}")

    def _check_etag_cache(
        self, bucket_name: str, result: IntegrityResult, auto_heal: bool, dry_run: bool
    ) -> None:
        etag_index_path = self._system_path() / self.SYSTEM_BUCKETS_DIR / bucket_name / "etag_index.json"

        if not etag_index_path.exists():
            return

        meta_root = self._system_path() / self.SYSTEM_BUCKETS_DIR / bucket_name / self.BUCKET_META_DIR
        if not meta_root.exists():
            return

        try:
            etag_cache = json.loads(etag_index_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return

        found_mismatch = False

        for full_key, cached_etag in etag_cache.items():
            key_path = Path(full_key)
            key_name = key_path.name
            parent = key_path.parent

            if parent == Path("."):
                index_path = meta_root / "_index.json"
            else:
                index_path = meta_root / parent / "_index.json"

            if not index_path.exists():
                continue

            try:
                index_data = json.loads(index_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue

            entry = index_data.get(key_name)
            if not entry:
                continue

            meta = entry.get("metadata", {}) if isinstance(entry, dict) else {}
            stored_etag = meta.get("__etag__")

            if stored_etag and cached_etag != stored_etag:
                result.etag_cache_inconsistencies += 1
                found_mismatch = True
                issue = IntegrityIssue(
                    issue_type="etag_cache_inconsistency",
                    bucket=bucket_name,
                    key=full_key,
                    detail=f"cached_etag={cached_etag} index_etag={stored_etag}",
                )
                self._add_issue(result, issue)

        if found_mismatch and auto_heal and not dry_run:
            try:
                etag_index_path.unlink(missing_ok=True)
                for issue in result.issues:
                    if issue.issue_type == "etag_cache_inconsistency" and issue.bucket == bucket_name and not issue.healed:
                        issue.healed = True
                        issue.heal_action = "deleted etag_index.json"
                        result.issues_healed += 1
            except OSError as e:
                result.errors.append(f"heal etag cache {bucket_name}: {e}")

    def _check_legacy_metadata(
        self, bucket_name: str, result: IntegrityResult, auto_heal: bool, dry_run: bool
    ) -> None:
        legacy_meta_root = self.storage_root / bucket_name / ".meta"
        if not legacy_meta_root.exists():
            return

        meta_root = self._system_path() / self.SYSTEM_BUCKETS_DIR / bucket_name / self.BUCKET_META_DIR

        try:
            for meta_file in legacy_meta_root.rglob("*.meta.json"):
                if self._throttle():
                    return
                if not meta_file.is_file():
                    continue

                try:
                    rel = meta_file.relative_to(legacy_meta_root)
                except ValueError:
                    continue

                full_key = rel.as_posix().removesuffix(".meta.json")
                key_path = Path(full_key)
                key_name = key_path.name
                parent = key_path.parent

                if parent == Path("."):
                    index_path = meta_root / "_index.json"
                else:
                    index_path = meta_root / parent / "_index.json"

                try:
                    legacy_data = json.loads(meta_file.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue

                index_entry = None
                if index_path.exists():
                    try:
                        index_data = json.loads(index_path.read_text(encoding="utf-8"))
                        index_entry = index_data.get(key_name)
                    except (OSError, json.JSONDecodeError):
                        pass

                if index_entry is None:
                    result.legacy_metadata_drifts += 1
                    issue = IntegrityIssue(
                        issue_type="legacy_metadata_drift",
                        bucket=bucket_name,
                        key=full_key,
                        detail="unmigrated legacy .meta.json",
                    )

                    if auto_heal and not dry_run:
                        try:
                            index_data = {}
                            if index_path.exists():
                                try:
                                    index_data = json.loads(index_path.read_text(encoding="utf-8"))
                                except (OSError, json.JSONDecodeError):
                                    pass
                            index_data[key_name] = {"metadata": legacy_data}
                            self._atomic_write_index(index_path, index_data)
                            meta_file.unlink(missing_ok=True)
                            issue.healed = True
                            issue.heal_action = "migrated to index and deleted legacy file"
                            result.issues_healed += 1
                        except OSError as e:
                            result.errors.append(f"heal legacy {bucket_name}/{full_key}: {e}")

                    self._add_issue(result, issue)
                else:
                    index_meta = index_entry.get("metadata", {}) if isinstance(index_entry, dict) else {}
                    if legacy_data != index_meta:
                        result.legacy_metadata_drifts += 1
                        issue = IntegrityIssue(
                            issue_type="legacy_metadata_drift",
                            bucket=bucket_name,
                            key=full_key,
                            detail="legacy .meta.json differs from index entry",
                        )

                        if auto_heal and not dry_run:
                            try:
                                meta_file.unlink(missing_ok=True)
                                issue.healed = True
                                issue.heal_action = "deleted legacy file (index is authoritative)"
                                result.issues_healed += 1
                            except OSError as e:
                                result.errors.append(f"heal legacy drift {bucket_name}/{full_key}: {e}")

                        self._add_issue(result, issue)
        except OSError as e:
            result.errors.append(f"check legacy meta {bucket_name}: {e}")

    @staticmethod
    def _atomic_write_index(index_path: Path, data: Dict[str, Any]) -> None:
        index_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = index_path.with_suffix(".tmp")
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(data, f)
            os.replace(str(tmp_path), str(index_path))
        except BaseException:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise

    def get_history(self, limit: int = 50, offset: int = 0) -> List[dict]:
        records = self.history_store.get_history(limit, offset)
        return [r.to_dict() for r in records]

    def get_status(self) -> dict:
        status: Dict[str, Any] = {
            "enabled": not self._shutdown or self._timer is not None,
            "running": self._timer is not None and not self._shutdown,
            "scanning": self._scanning,
            "interval_hours": self.interval_seconds / 3600.0,
            "batch_size": self.batch_size,
            "auto_heal": self.auto_heal,
            "dry_run": self.dry_run,
            "io_throttle_ms": round(self._io_throttle * 1000),
        }
        if self._scanning and self._scan_start_time is not None:
            status["scan_elapsed_seconds"] = round(time.time() - self._scan_start_time, 1)
        return status
