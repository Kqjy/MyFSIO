from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import threading
import time
import unicodedata
import uuid
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Dict, Generator, List, Optional

# Platform-specific file locking
if os.name == "nt":
    import msvcrt
    
    @contextmanager
    def _file_lock(file_handle) -> Generator[None, None, None]:
        """Acquire an exclusive lock on a file (Windows)."""
        try:
            msvcrt.locking(file_handle.fileno(), msvcrt.LK_NBLCK, 1)
            yield
        finally:
            try:
                file_handle.seek(0)
                msvcrt.locking(file_handle.fileno(), msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
else:
    import fcntl  # type: ignore
    
    @contextmanager
    def _file_lock(file_handle) -> Generator[None, None, None]:
        """Acquire an exclusive lock on a file (Unix)."""
        try:
            fcntl.flock(file_handle.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(file_handle.fileno(), fcntl.LOCK_UN)


@contextmanager
def _atomic_lock_file(lock_path: Path, max_retries: int = 10, base_delay: float = 0.1) -> Generator[None, None, None]:
    """Atomically acquire a lock file with exponential backoff.

    Uses O_EXCL to ensure atomic creation of the lock file.
    """
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = None
    for attempt in range(max_retries):
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            break
        except FileExistsError:
            if attempt == max_retries - 1:
                raise BlockingIOError("Another upload to this key is in progress")
            delay = base_delay * (2 ** attempt)
            time.sleep(min(delay, 2.0))
    try:
        yield
    finally:
        if fd is not None:
            os.close(fd)
        try:
            lock_path.unlink(missing_ok=True)
        except OSError:
            pass


WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
}


class StorageError(RuntimeError):
    """Raised when the storage layer encounters an unrecoverable problem."""


class BucketNotFoundError(StorageError):
    """Raised when the bucket does not exist."""


class ObjectNotFoundError(StorageError):
    """Raised when the object does not exist."""


class QuotaExceededError(StorageError):
    """Raised when an operation would exceed bucket quota limits."""
    
    def __init__(self, message: str, quota: Dict[str, Any], usage: Dict[str, int]):
        super().__init__(message)
        self.quota = quota
        self.usage = usage


@dataclass
class ObjectMeta:
    key: str
    size: int
    last_modified: datetime
    etag: Optional[str] = None
    metadata: Optional[Dict[str, str]] = None


@dataclass
class BucketMeta:
    name: str
    created_at: datetime


@dataclass
class ListObjectsResult:
    """Paginated result for object listing."""
    objects: List[ObjectMeta]
    is_truncated: bool
    next_continuation_token: Optional[str]
    total_count: Optional[int] = None


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _utc_isoformat() -> str:
    return _utcnow().isoformat().replace("+00:00", "Z")


class ObjectStorage:
    """Very small filesystem wrapper implementing the bare S3 primitives."""

    INTERNAL_FOLDERS = {".meta", ".versions", ".multipart"}
    SYSTEM_ROOT = ".myfsio.sys"
    SYSTEM_BUCKETS_DIR = "buckets"
    SYSTEM_MULTIPART_DIR = "multipart"
    SYSTEM_TMP_DIR = "tmp"
    BUCKET_META_DIR = "meta"
    BUCKET_VERSIONS_DIR = "versions"
    MULTIPART_MANIFEST = "manifest.json"
    BUCKET_CONFIG_FILE = ".bucket.json"

    def __init__(
        self,
        root: Path,
        cache_ttl: int = 5,
        object_cache_max_size: int = 100,
        bucket_config_cache_ttl: float = 30.0,
        object_key_max_length_bytes: int = 1024,
    ) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._ensure_system_roots()
        self._object_cache: OrderedDict[str, tuple[Dict[str, ObjectMeta], float, float]] = OrderedDict()
        self._cache_lock = threading.Lock()
        self._bucket_locks: Dict[str, threading.Lock] = {}
        self._cache_version: Dict[str, int] = {}
        self._bucket_config_cache: Dict[str, tuple[dict[str, Any], float]] = {}
        self._bucket_config_cache_ttl = bucket_config_cache_ttl
        self._cache_ttl = cache_ttl
        self._object_cache_max_size = object_cache_max_size
        self._object_key_max_length_bytes = object_key_max_length_bytes
        self._sorted_key_cache: Dict[str, tuple[list[str], int]] = {}
        self._cleanup_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ParentCleanup")

    def _get_bucket_lock(self, bucket_id: str) -> threading.Lock:
        """Get or create a lock for a specific bucket. Reduces global lock contention."""
        with self._cache_lock:
            if bucket_id not in self._bucket_locks:
                self._bucket_locks[bucket_id] = threading.Lock()
            return self._bucket_locks[bucket_id]

    def list_buckets(self) -> List[BucketMeta]:
        buckets: List[BucketMeta] = []
        for bucket in sorted(self.root.iterdir()):
            if bucket.is_dir() and bucket.name != self.SYSTEM_ROOT:
                stat = bucket.stat()
                buckets.append(
                    BucketMeta(
                        name=bucket.name,
                        created_at=datetime.fromtimestamp(stat.st_ctime, timezone.utc),
                    )
                )
        return buckets

    def bucket_exists(self, bucket_name: str) -> bool:
        return self._bucket_path(bucket_name).exists()

    def _require_bucket_exists(self, bucket_path: Path) -> None:
        """Raise BucketNotFoundError if bucket does not exist."""
        if not bucket_path.exists():
            raise BucketNotFoundError("Bucket does not exist")

    def _validate_bucket_name(self, bucket_name: str) -> None:
        if len(bucket_name) < 3 or len(bucket_name) > 63:
            raise StorageError("Bucket name must be between 3 and 63 characters")
        if not re.match(r"^[a-z0-9][a-z0-9.-]*[a-z0-9]$", bucket_name):
            raise StorageError("Bucket name must consist of lowercase letters, numbers, periods, and hyphens, and must start and end with a letter or number")
        if ".." in bucket_name:
            raise StorageError("Bucket name must not contain consecutive periods")
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", bucket_name):
            raise StorageError("Bucket name must not be formatted as an IP address")

    def create_bucket(self, bucket_name: str) -> None:
        self._validate_bucket_name(bucket_name)
        bucket_path = self._bucket_path(bucket_name)
        bucket_path.mkdir(parents=True, exist_ok=False)
        self._system_bucket_root(bucket_path.name).mkdir(parents=True, exist_ok=True)

    def bucket_stats(self, bucket_name: str, cache_ttl: int = 60) -> dict[str, int]:
        """Return object count and total size for the bucket (cached).

        Args:
            bucket_name: Name of the bucket
            cache_ttl: Cache time-to-live in seconds (default 60)
        """
        bucket_path = self._bucket_path(bucket_name)
        if not bucket_path.exists():
            raise BucketNotFoundError("Bucket does not exist")

        cache_path = self._system_bucket_root(bucket_name) / "stats.json"
        cached_stats = None
        cache_fresh = False

        if cache_path.exists():
            try:
                cache_fresh = time.time() - cache_path.stat().st_mtime < cache_ttl
                cached_stats = json.loads(cache_path.read_text(encoding="utf-8"))
                if cache_fresh:
                    return cached_stats
            except (OSError, json.JSONDecodeError):
                pass

        object_count = 0
        total_bytes = 0
        version_count = 0
        version_bytes = 0

        try:
            for path in bucket_path.rglob("*"):
                if path.is_file():
                    rel = path.relative_to(bucket_path)
                    if not rel.parts:
                        continue
                    top_folder = rel.parts[0]
                    if top_folder not in self.INTERNAL_FOLDERS:
                        stat = path.stat()
                        object_count += 1
                        total_bytes += stat.st_size

            versions_root = self._bucket_versions_root(bucket_name)
            if versions_root.exists():
                for path in versions_root.rglob("*.bin"):
                    if path.is_file():
                        stat = path.stat()
                        version_count += 1
                        version_bytes += stat.st_size
        except OSError:
            if cached_stats is not None:
                return cached_stats
            raise

        existing_serial = 0
        if cached_stats is not None:
            existing_serial = cached_stats.get("_cache_serial", 0)

        stats = {
            "objects": object_count,
            "bytes": total_bytes,
            "version_count": version_count,
            "version_bytes": version_bytes,
            "total_objects": object_count + version_count,
            "total_bytes": total_bytes + version_bytes,
            "_cache_serial": existing_serial,
        }

        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(json.dumps(stats), encoding="utf-8")
        except OSError:
            pass

        return stats

    def _invalidate_bucket_stats_cache(self, bucket_id: str) -> None:
        """Invalidate the cached bucket statistics."""
        cache_path = self._system_bucket_root(bucket_id) / "stats.json"
        try:
            cache_path.unlink(missing_ok=True)
        except OSError:
            pass

    def _update_bucket_stats_cache(
        self,
        bucket_id: str,
        *,
        bytes_delta: int = 0,
        objects_delta: int = 0,
        version_bytes_delta: int = 0,
        version_count_delta: int = 0,
    ) -> None:
        """Incrementally update cached bucket statistics instead of invalidating.

        This avoids expensive full directory scans on every PUT/DELETE by
        adjusting the cached values directly. Also signals cross-process cache
        invalidation by incrementing _cache_serial.
        """
        cache_path = self._system_bucket_root(bucket_id) / "stats.json"
        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            if cache_path.exists():
                data = json.loads(cache_path.read_text(encoding="utf-8"))
            else:
                data = {"objects": 0, "bytes": 0, "version_count": 0, "version_bytes": 0, "total_objects": 0, "total_bytes": 0, "_cache_serial": 0}
            data["objects"] = max(0, data.get("objects", 0) + objects_delta)
            data["bytes"] = max(0, data.get("bytes", 0) + bytes_delta)
            data["version_count"] = max(0, data.get("version_count", 0) + version_count_delta)
            data["version_bytes"] = max(0, data.get("version_bytes", 0) + version_bytes_delta)
            data["total_objects"] = max(0, data.get("total_objects", 0) + objects_delta + version_count_delta)
            data["total_bytes"] = max(0, data.get("total_bytes", 0) + bytes_delta + version_bytes_delta)
            data["_cache_serial"] = data.get("_cache_serial", 0) + 1
            cache_path.write_text(json.dumps(data), encoding="utf-8")
        except (OSError, json.JSONDecodeError):
            pass

    def delete_bucket(self, bucket_name: str) -> None:
        bucket_path = self._bucket_path(bucket_name)
        if not bucket_path.exists():
            raise BucketNotFoundError("Bucket does not exist")
        has_objects, has_versions, has_multipart = self._check_bucket_contents(bucket_path)
        if has_objects:
            raise StorageError("Bucket not empty")
        if has_versions:
            raise StorageError("Bucket contains archived object versions")
        if has_multipart:
            raise StorageError("Bucket has active multipart uploads")
        self._remove_tree(bucket_path)
        self._remove_tree(self._system_bucket_root(bucket_path.name))
        self._remove_tree(self._multipart_bucket_root(bucket_path.name))

    def list_objects(
        self,
        bucket_name: str,
        *,
        max_keys: int = 1000,
        continuation_token: Optional[str] = None,
        prefix: Optional[str] = None,
    ) -> ListObjectsResult:
        """List objects in a bucket with pagination support.
        
        Args:
            bucket_name: Name of the bucket
            max_keys: Maximum number of objects to return (default 1000)
            continuation_token: Token from previous request for pagination
            prefix: Filter objects by key prefix
            
        Returns:
            ListObjectsResult with objects, truncation status, and continuation token
        """
        import bisect

        bucket_path = self._bucket_path(bucket_name)
        if not bucket_path.exists():
            raise BucketNotFoundError("Bucket does not exist")
        bucket_id = bucket_path.name

        object_cache = self._get_object_cache(bucket_id, bucket_path)

        cache_version = self._cache_version.get(bucket_id, 0)
        cached_entry = self._sorted_key_cache.get(bucket_id)
        if cached_entry and cached_entry[1] == cache_version:
            all_keys = cached_entry[0]
        else:
            all_keys = sorted(object_cache.keys())
            self._sorted_key_cache[bucket_id] = (all_keys, cache_version)

        if prefix:
            lo = bisect.bisect_left(all_keys, prefix)
            hi = len(all_keys)
            for i in range(lo, len(all_keys)):
                if not all_keys[i].startswith(prefix):
                    hi = i
                    break
            all_keys = all_keys[lo:hi]

        total_count = len(all_keys)
        start_index = 0
        if continuation_token:
            start_index = bisect.bisect_right(all_keys, continuation_token)
            if start_index >= total_count:
                return ListObjectsResult(
                    objects=[],
                    is_truncated=False,
                    next_continuation_token=None,
                    total_count=total_count,
                )

        end_index = start_index + max_keys
        keys_slice = all_keys[start_index:end_index]
        is_truncated = end_index < total_count

        objects: List[ObjectMeta] = []
        for key in keys_slice:
            obj = object_cache.get(key)
            if obj:
                objects.append(obj)
        
        next_token = keys_slice[-1] if is_truncated and keys_slice else None
        
        return ListObjectsResult(
            objects=objects,
            is_truncated=is_truncated,
            next_continuation_token=next_token,
            total_count=total_count,
        )

    def list_objects_all(self, bucket_name: str) -> List[ObjectMeta]:
        """List all objects in a bucket (no pagination). Use with caution for large buckets."""
        result = self.list_objects(bucket_name, max_keys=100000)
        return result.objects

    def put_object(
        self,
        bucket_name: str,
        object_key: str,
        stream: BinaryIO,
        *,
        metadata: Optional[Dict[str, str]] = None,
        enforce_quota: bool = True,
    ) -> ObjectMeta:
        bucket_path = self._bucket_path(bucket_name)
        if not bucket_path.exists():
            raise BucketNotFoundError("Bucket does not exist")
        bucket_id = bucket_path.name

        safe_key = self._sanitize_object_key(object_key, self._object_key_max_length_bytes)
        destination = bucket_path / safe_key
        destination.parent.mkdir(parents=True, exist_ok=True)

        is_overwrite = destination.exists()
        existing_size = destination.stat().st_size if is_overwrite else 0

        archived_version_size = 0
        if self._is_versioning_enabled(bucket_path) and is_overwrite:
            archived_version_size = existing_size
            self._archive_current_version(bucket_id, safe_key, reason="overwrite")

        tmp_dir = self._system_root_path() / self.SYSTEM_TMP_DIR
        tmp_dir.mkdir(parents=True, exist_ok=True)
        tmp_path = tmp_dir / f"{uuid.uuid4().hex}.tmp"
        
        try:
            checksum = hashlib.md5()
            with tmp_path.open("wb") as target:
                shutil.copyfileobj(_HashingReader(stream, checksum), target)
            
            new_size = tmp_path.stat().st_size
            size_delta = new_size - existing_size
            object_delta = 0 if is_overwrite else 1

            if enforce_quota:
                quota_check = self.check_quota(
                    bucket_name,
                    additional_bytes=max(0, size_delta),
                    additional_objects=object_delta,
                )
                if not quota_check["allowed"]:
                    raise QuotaExceededError(
                        quota_check["message"] or "Quota exceeded",
                        quota_check["quota"],
                        quota_check["usage"],
                    )

            shutil.move(str(tmp_path), str(destination))
            
        finally:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass

        stat = destination.stat()
        etag = checksum.hexdigest()
        
        internal_meta = {"__etag__": etag, "__size__": str(stat.st_size)}
        combined_meta = {**internal_meta, **(metadata or {})}
        self._write_metadata(bucket_id, safe_key, combined_meta)

        self._update_bucket_stats_cache(
            bucket_id,
            bytes_delta=size_delta,
            objects_delta=object_delta,
            version_bytes_delta=archived_version_size,
            version_count_delta=1 if archived_version_size > 0 else 0,
        )

        obj_meta = ObjectMeta(
            key=safe_key.as_posix(),
            size=stat.st_size,
            last_modified=datetime.fromtimestamp(stat.st_mtime, timezone.utc),
            etag=etag,
            metadata=metadata,
        )
        self._update_object_cache_entry(bucket_id, safe_key.as_posix(), obj_meta)

        return obj_meta

    def get_object_path(self, bucket_name: str, object_key: str) -> Path:
        path = self._object_path(bucket_name, object_key)
        if not path.is_file():
            raise ObjectNotFoundError("Object not found")
        return path

    def get_object_metadata(self, bucket_name: str, object_key: str) -> Dict[str, str]:
        bucket_path = self._bucket_path(bucket_name)
        if not bucket_path.exists():
            return {}
        safe_key = self._sanitize_object_key(object_key, self._object_key_max_length_bytes)
        return self._read_metadata(bucket_path.name, safe_key) or {}

    def _cleanup_empty_parents(self, path: Path, stop_at: Path) -> None:
        """Remove empty parent directories in a background thread.

        On Windows/OneDrive, directories may be locked briefly after file deletion.
        Running this in the background avoids blocking the request thread with retries.
        """
        self._cleanup_executor.submit(self._do_cleanup_empty_parents, path, stop_at)

    def _do_cleanup_empty_parents(self, path: Path, stop_at: Path) -> None:
        for parent in path.parents:
            if parent == stop_at:
                break
            for attempt in range(3):
                try:
                    if parent.exists() and not any(parent.iterdir()):
                        parent.rmdir()
                        break
                except OSError:
                    if attempt < 2:
                        time.sleep(0.1)
                    break

    def delete_object(self, bucket_name: str, object_key: str) -> None:
        bucket_path = self._bucket_path(bucket_name)
        path = self._object_path(bucket_name, object_key)
        if not path.exists():
            return
        deleted_size = path.stat().st_size
        safe_key = path.relative_to(bucket_path)
        bucket_id = bucket_path.name
        archived_version_size = 0
        if self._is_versioning_enabled(bucket_path):
            archived_version_size = deleted_size
            self._archive_current_version(bucket_id, safe_key, reason="delete")
        rel = path.relative_to(bucket_path)
        self._safe_unlink(path)
        self._delete_metadata(bucket_id, rel)

        self._update_bucket_stats_cache(
            bucket_id,
            bytes_delta=-deleted_size,
            objects_delta=-1,
            version_bytes_delta=archived_version_size,
            version_count_delta=1 if archived_version_size > 0 else 0,
        )
        self._update_object_cache_entry(bucket_id, safe_key.as_posix(), None)
        self._cleanup_empty_parents(path, bucket_path)

    def purge_object(self, bucket_name: str, object_key: str) -> None:
        bucket_path = self._bucket_path(bucket_name)
        target = self._object_path(bucket_name, object_key)
        bucket_id = bucket_path.name
        if target.exists():
            rel = target.relative_to(bucket_path)
            self._safe_unlink(target)
            self._delete_metadata(bucket_id, rel)
        else:
            rel = self._sanitize_object_key(object_key, self._object_key_max_length_bytes)
            self._delete_metadata(bucket_id, rel)
        version_dir = self._version_dir(bucket_id, rel)
        if version_dir.exists():
            shutil.rmtree(version_dir, ignore_errors=True)
        legacy_version_dir = self._legacy_version_dir(bucket_id, rel)
        if legacy_version_dir.exists():
            shutil.rmtree(legacy_version_dir, ignore_errors=True)

        self._invalidate_bucket_stats_cache(bucket_id)
        self._update_object_cache_entry(bucket_id, rel.as_posix(), None)
        self._cleanup_empty_parents(target, bucket_path)

    def is_versioning_enabled(self, bucket_name: str) -> bool:
        bucket_path = self._bucket_path(bucket_name)
        if not bucket_path.exists():
            raise BucketNotFoundError("Bucket does not exist")
        return self._is_versioning_enabled(bucket_path)

    def set_bucket_versioning(self, bucket_name: str, enabled: bool) -> None:
        bucket_path = self._require_bucket_path(bucket_name)
        config = self._read_bucket_config(bucket_path.name)
        config["versioning_enabled"] = bool(enabled)
        self._write_bucket_config(bucket_path.name, config)

    def get_bucket_tags(self, bucket_name: str) -> List[Dict[str, str]]:
        bucket_path = self._require_bucket_path(bucket_name)
        config = self._read_bucket_config(bucket_path.name)
        raw_tags = config.get("tags")
        if not isinstance(raw_tags, list):
            return []
        tags: List[Dict[str, str]] = []
        for entry in raw_tags:
            if not isinstance(entry, dict):
                continue
            key = str(entry.get("Key", "")).strip()
            if not key:
                continue
            value = str(entry.get("Value", ""))
            tags.append({"Key": key, "Value": value})
        return tags

    def set_bucket_tags(self, bucket_name: str, tags: Optional[List[Dict[str, str]]]) -> None:
        bucket_path = self._require_bucket_path(bucket_name)
        if not tags:
            self._set_bucket_config_entry(bucket_path.name, "tags", None)
            return
        clean: List[Dict[str, str]] = []
        for entry in tags:
            if not isinstance(entry, dict):
                continue
            key = str(entry.get("Key", "")).strip()
            if not key:
                continue
            clean.append({"Key": key, "Value": str(entry.get("Value", ""))})
        self._set_bucket_config_entry(bucket_path.name, "tags", clean or None)

    def get_bucket_cors(self, bucket_name: str) -> List[Dict[str, Any]]:
        bucket_path = self._require_bucket_path(bucket_name)
        config = self._read_bucket_config(bucket_path.name)
        cors_rules = config.get("cors")
        return cors_rules if isinstance(cors_rules, list) else []

    def set_bucket_cors(self, bucket_name: str, rules: Optional[List[Dict[str, Any]]]) -> None:
        bucket_path = self._require_bucket_path(bucket_name)
        self._set_bucket_config_entry(bucket_path.name, "cors", rules or None)

    def get_bucket_encryption(self, bucket_name: str) -> Dict[str, Any]:
        bucket_path = self._require_bucket_path(bucket_name)
        config = self._read_bucket_config(bucket_path.name)
        payload = config.get("encryption")
        return payload if isinstance(payload, dict) else {}

    def set_bucket_encryption(self, bucket_name: str, config_payload: Optional[Dict[str, Any]]) -> None:
        bucket_path = self._require_bucket_path(bucket_name)
        self._set_bucket_config_entry(bucket_path.name, "encryption", config_payload or None)

    def get_bucket_lifecycle(self, bucket_name: str) -> Optional[List[Dict[str, Any]]]:
        """Get lifecycle configuration for bucket."""
        bucket_path = self._require_bucket_path(bucket_name)
        config = self._read_bucket_config(bucket_path.name)
        lifecycle = config.get("lifecycle")
        return lifecycle if isinstance(lifecycle, list) else None

    def set_bucket_lifecycle(self, bucket_name: str, rules: Optional[List[Dict[str, Any]]]) -> None:
        """Set lifecycle configuration for bucket."""
        bucket_path = self._require_bucket_path(bucket_name)
        self._set_bucket_config_entry(bucket_path.name, "lifecycle", rules)

    def get_bucket_quota(self, bucket_name: str) -> Dict[str, Any]:
        """Get quota configuration for bucket.
        
        Returns:
            Dict with 'max_bytes' and 'max_objects' (None if unlimited).
        """
        bucket_path = self._require_bucket_path(bucket_name)
        config = self._read_bucket_config(bucket_path.name)
        quota = config.get("quota")
        if isinstance(quota, dict):
            return {
                "max_bytes": quota.get("max_bytes"),
                "max_objects": quota.get("max_objects"),
            }
        return {"max_bytes": None, "max_objects": None}

    def set_bucket_quota(
        self,
        bucket_name: str,
        *,
        max_bytes: Optional[int] = None,
        max_objects: Optional[int] = None,
    ) -> None:
        """Set quota limits for a bucket.
        
        Args:
            bucket_name: Name of the bucket
            max_bytes: Maximum total size in bytes (None to remove limit)
            max_objects: Maximum number of objects (None to remove limit)
        """
        bucket_path = self._require_bucket_path(bucket_name)
        
        if max_bytes is None and max_objects is None:
            self._set_bucket_config_entry(bucket_path.name, "quota", None)
            return
        
        quota: Dict[str, Any] = {}
        if max_bytes is not None:
            if max_bytes < 0:
                raise StorageError("max_bytes must be non-negative")
            quota["max_bytes"] = max_bytes
        if max_objects is not None:
            if max_objects < 0:
                raise StorageError("max_objects must be non-negative")
            quota["max_objects"] = max_objects
        
        self._set_bucket_config_entry(bucket_path.name, "quota", quota)

    def check_quota(
        self,
        bucket_name: str,
        additional_bytes: int = 0,
        additional_objects: int = 0,
    ) -> Dict[str, Any]:
        """Check if an operation would exceed bucket quota.
        
        Args:
            bucket_name: Name of the bucket
            additional_bytes: Bytes that would be added
            additional_objects: Objects that would be added
            
        Returns:
            Dict with 'allowed' (bool), 'quota' (current limits),
            'usage' (current usage), and 'message' (if not allowed).
        """
        quota = self.get_bucket_quota(bucket_name)
        if not quota:
            return {
                "allowed": True,
                "quota": None,
                "usage": None,
                "message": None,
            }
        
        stats = self.bucket_stats(bucket_name)
        current_bytes = stats.get("total_bytes", stats.get("bytes", 0))
        current_objects = stats.get("total_objects", stats.get("objects", 0))
        
        result = {
            "allowed": True,
            "quota": quota,
            "usage": {
                "bytes": current_bytes,
                "objects": current_objects,
                "version_count": stats.get("version_count", 0),
                "version_bytes": stats.get("version_bytes", 0),
            },
            "message": None,
        }
        
        max_bytes_limit = quota.get("max_bytes")
        max_objects = quota.get("max_objects")
        
        if max_bytes_limit is not None:
            projected_bytes = current_bytes + additional_bytes
            if projected_bytes > max_bytes_limit:
                result["allowed"] = False
                result["message"] = (
                    f"Quota exceeded: adding {additional_bytes} bytes would result in "
                    f"{projected_bytes} bytes, exceeding limit of {max_bytes_limit} bytes"
                )
                return result
        
        if max_objects is not None:
            projected_objects = current_objects + additional_objects
            if projected_objects > max_objects:
                result["allowed"] = False
                result["message"] = (
                    f"Quota exceeded: adding {additional_objects} objects would result in "
                    f"{projected_objects} objects, exceeding limit of {max_objects} objects"
                )
                return result
        
        return result

    def get_object_tags(self, bucket_name: str, object_key: str) -> List[Dict[str, str]]:
        """Get tags for an object."""
        bucket_path = self._bucket_path(bucket_name)
        if not bucket_path.exists():
            raise BucketNotFoundError("Bucket does not exist")
        safe_key = self._sanitize_object_key(object_key, self._object_key_max_length_bytes)
        object_path = bucket_path / safe_key
        if not object_path.exists():
            raise ObjectNotFoundError("Object does not exist")
        
        for meta_file in (self._metadata_file(bucket_path.name, safe_key), self._legacy_metadata_file(bucket_path.name, safe_key)):
            if not meta_file.exists():
                continue
            try:
                payload = json.loads(meta_file.read_text(encoding="utf-8"))
                tags = payload.get("tags")
                if isinstance(tags, list):
                    return tags
                return []
            except (OSError, json.JSONDecodeError):
                return []
        return []

    def set_object_tags(self, bucket_name: str, object_key: str, tags: Optional[List[Dict[str, str]]]) -> None:
        """Set tags for an object."""
        bucket_path = self._bucket_path(bucket_name)
        if not bucket_path.exists():
            raise BucketNotFoundError("Bucket does not exist")
        safe_key = self._sanitize_object_key(object_key, self._object_key_max_length_bytes)
        object_path = bucket_path / safe_key
        if not object_path.exists():
            raise ObjectNotFoundError("Object does not exist")
        
        meta_file = self._metadata_file(bucket_path.name, safe_key)
        
        existing_payload: Dict[str, Any] = {}
        if meta_file.exists():
            try:
                existing_payload = json.loads(meta_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                pass
        
        if tags:
            existing_payload["tags"] = tags
        else:
            existing_payload.pop("tags", None)
        
        if existing_payload.get("metadata") or existing_payload.get("tags"):
            meta_file.parent.mkdir(parents=True, exist_ok=True)
            meta_file.write_text(json.dumps(existing_payload), encoding="utf-8")
        elif meta_file.exists():
            meta_file.unlink()
            parent = meta_file.parent
            meta_root = self._bucket_meta_root(bucket_path.name)
            while parent != meta_root and parent.exists() and not any(parent.iterdir()):
                parent.rmdir()
                parent = parent.parent

    def delete_object_tags(self, bucket_name: str, object_key: str) -> None:
        """Delete all tags from an object."""
        self.set_object_tags(bucket_name, object_key, None)

    def list_object_versions(self, bucket_name: str, object_key: str) -> List[Dict[str, Any]]:
        bucket_path = self._bucket_path(bucket_name)
        if not bucket_path.exists():
            raise BucketNotFoundError("Bucket does not exist")
        bucket_id = bucket_path.name
        safe_key = self._sanitize_object_key(object_key, self._object_key_max_length_bytes)
        version_dir = self._version_dir(bucket_id, safe_key)
        if not version_dir.exists():
            version_dir = self._legacy_version_dir(bucket_id, safe_key)
            if not version_dir.exists():
                return []
        versions: List[Dict[str, Any]] = []
        for meta_file in version_dir.glob("*.json"):
            try:
                payload = json.loads(meta_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(payload, dict):
                continue
            payload.setdefault("version_id", meta_file.stem)
            versions.append(payload)
        versions.sort(key=lambda item: item.get("archived_at") or "1970-01-01T00:00:00Z", reverse=True)
        return versions

    def restore_object_version(self, bucket_name: str, object_key: str, version_id: str) -> ObjectMeta:
        bucket_path = self._bucket_path(bucket_name)
        if not bucket_path.exists():
            raise BucketNotFoundError("Bucket does not exist")
        bucket_id = bucket_path.name
        safe_key = self._sanitize_object_key(object_key, self._object_key_max_length_bytes)
        version_dir = self._version_dir(bucket_id, safe_key)
        data_path = version_dir / f"{version_id}.bin"
        meta_path = version_dir / f"{version_id}.json"
        if not data_path.exists() or not meta_path.exists():
            raise StorageError("Version not found")
        try:
            payload = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            payload = {}
        metadata = payload.get("metadata") if isinstance(payload, dict) else {}
        if not isinstance(metadata, dict):
            metadata = {}
        destination = bucket_path / safe_key
        restored_size = data_path.stat().st_size
        is_overwrite = destination.exists()
        existing_size = destination.stat().st_size if is_overwrite else 0
        archived_version_size = 0
        if self._is_versioning_enabled(bucket_path) and is_overwrite:
            archived_version_size = existing_size
            self._archive_current_version(bucket_id, safe_key, reason="restore-overwrite")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(data_path, destination)
        if metadata:
            self._write_metadata(bucket_id, safe_key, metadata)
        else:
            self._delete_metadata(bucket_id, safe_key)
        stat = destination.stat()
        self._update_bucket_stats_cache(
            bucket_id,
            bytes_delta=restored_size - existing_size,
            objects_delta=0 if is_overwrite else 1,
            version_bytes_delta=archived_version_size,
            version_count_delta=1 if archived_version_size > 0 else 0,
        )
        return ObjectMeta(
            key=safe_key.as_posix(),
            size=stat.st_size,
            last_modified=datetime.fromtimestamp(stat.st_mtime, timezone.utc),
            etag=self._compute_etag(destination),
            metadata=metadata or None,
        )

    def delete_object_version(self, bucket_name: str, object_key: str, version_id: str) -> None:
        bucket_path = self._bucket_path(bucket_name)
        if not bucket_path.exists():
            raise BucketNotFoundError("Bucket does not exist")
        bucket_id = bucket_path.name
        safe_key = self._sanitize_object_key(object_key, self._object_key_max_length_bytes)
        version_dir = self._version_dir(bucket_id, safe_key)
        data_path = version_dir / f"{version_id}.bin"
        meta_path = version_dir / f"{version_id}.json"
        if not data_path.exists() and not meta_path.exists():
            legacy_version_dir = self._legacy_version_dir(bucket_id, safe_key)
            data_path = legacy_version_dir / f"{version_id}.bin"
            meta_path = legacy_version_dir / f"{version_id}.json"
        if not data_path.exists() and not meta_path.exists():
            raise StorageError(f"Version {version_id} not found")
        deleted_version_size = data_path.stat().st_size if data_path.exists() else 0
        if data_path.exists():
            data_path.unlink()
        if meta_path.exists():
            meta_path.unlink()
        parent = data_path.parent
        if parent.exists() and not any(parent.iterdir()):
            parent.rmdir()
        if deleted_version_size > 0:
            self._update_bucket_stats_cache(
                bucket_id,
                version_bytes_delta=-deleted_version_size,
                version_count_delta=-1,
            )

    def list_orphaned_objects(self, bucket_name: str) -> List[Dict[str, Any]]:
        bucket_path = self._bucket_path(bucket_name)
        if not bucket_path.exists():
            raise BucketNotFoundError("Bucket does not exist")
        bucket_id = bucket_path.name
        version_roots = [self._bucket_versions_root(bucket_id), self._legacy_versions_root(bucket_id)]
        if not any(root.exists() for root in version_roots):
            return []
        aggregated: Dict[str, Dict[str, Any]] = {}
        skipped: set[str] = set()
        for version_root in version_roots:
            if not version_root.exists():
                continue
            for meta_file in version_root.glob("**/*.json"):
                if not meta_file.is_file():
                    continue
                rel = meta_file.parent.relative_to(version_root)
                rel_key = rel.as_posix()
                if rel_key in skipped:
                    continue
                object_path = bucket_path / rel
                if object_path.exists():
                    skipped.add(rel_key)
                    continue
                try:
                    payload = json.loads(meta_file.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    payload = {}
                version_id = payload.get("version_id") or meta_file.stem
                archived_at = payload.get("archived_at") or "1970-01-01T00:00:00Z"
                size = int(payload.get("size") or 0)
                reason = payload.get("reason") or "update"
                record = aggregated.setdefault(
                    rel_key,
                    {
                        "key": rel_key,
                        "versions": 0,
                        "total_size": 0,
                        "latest": None,
                        "_latest_sort": None,
                    },
                )
                record["versions"] += 1
                record["total_size"] += size
                candidate = {
                    "version_id": version_id,
                    "archived_at": archived_at,
                    "size": size,
                    "reason": reason,
                }
                sort_key = (
                    archived_at,
                    meta_file.stat().st_mtime,
                )
                current_sort = record.get("_latest_sort")
                if current_sort is None or sort_key > current_sort:
                    record["_latest_sort"] = sort_key
                    record["latest"] = candidate
        for record in aggregated.values():
            record.pop("_latest_sort", None)
        return sorted(aggregated.values(), key=lambda item: item["key"])

    def initiate_multipart_upload(
        self,
        bucket_name: str,
        object_key: str,
        *,
        metadata: Optional[Dict[str, str]] = None,
    ) -> str:
        bucket_path = self._bucket_path(bucket_name)
        if not bucket_path.exists():
            raise BucketNotFoundError("Bucket does not exist")
        bucket_id = bucket_path.name
        safe_key = self._sanitize_object_key(object_key, self._object_key_max_length_bytes)
        upload_id = uuid.uuid4().hex
        upload_root = self._multipart_dir(bucket_id, upload_id)
        upload_root.mkdir(parents=True, exist_ok=False)
        manifest = {
            "upload_id": upload_id,
            "object_key": safe_key.as_posix(),
            "metadata": self._normalize_metadata(metadata),
            "parts": {},
            "created_at": _utc_isoformat(),
        }
        self._write_multipart_manifest(upload_root, manifest)
        return upload_id

    def upload_multipart_part(
        self,
        bucket_name: str,
        upload_id: str,
        part_number: int,
        stream: BinaryIO,
    ) -> str:
        """Upload a part for a multipart upload.

        Uses file locking to safely update the manifest and handle concurrent uploads.
        """
        if part_number < 1 or part_number > 10000:
            raise StorageError("part_number must be between 1 and 10000")
        bucket_path = self._bucket_path(bucket_name)

        upload_root = self._multipart_dir(bucket_path.name, upload_id)
        if not upload_root.exists():
            upload_root = self._legacy_multipart_dir(bucket_path.name, upload_id)
        if not upload_root.exists():
            raise StorageError("Multipart upload not found")

        checksum = hashlib.md5()
        part_filename = f"part-{part_number:05d}.part"
        part_path = upload_root / part_filename
        temp_path = upload_root / f".{part_filename}.tmp"

        try:
            with temp_path.open("wb") as target:
                shutil.copyfileobj(_HashingReader(stream, checksum), target)
            temp_path.replace(part_path)
        except OSError:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise

        record = {
            "etag": checksum.hexdigest(),
            "size": part_path.stat().st_size,
            "filename": part_filename,
        }

        manifest_path = upload_root / self.MULTIPART_MANIFEST
        lock_path = upload_root / ".manifest.lock"

        max_retries = 3
        for attempt in range(max_retries):
            try:
                with lock_path.open("w") as lock_file:
                    with _file_lock(lock_file):
                        try:
                            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                        except (OSError, json.JSONDecodeError) as exc:
                            if attempt < max_retries - 1:
                                time.sleep(0.1 * (attempt + 1))
                                continue
                            raise StorageError("Multipart manifest unreadable") from exc

                        parts = manifest.setdefault("parts", {})
                        parts[str(part_number)] = record
                        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                break
            except OSError as exc:
                if attempt < max_retries - 1:
                    time.sleep(0.1 * (attempt + 1))
                    continue
                raise StorageError(f"Failed to update multipart manifest: {exc}") from exc

        return record["etag"]

    def upload_part_copy(
        self,
        bucket_name: str,
        upload_id: str,
        part_number: int,
        source_bucket: str,
        source_key: str,
        start_byte: Optional[int] = None,
        end_byte: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Copy a range from an existing object as a multipart part."""
        if part_number < 1 or part_number > 10000:
            raise StorageError("part_number must be between 1 and 10000")

        source_path = self.get_object_path(source_bucket, source_key)
        source_size = source_path.stat().st_size

        if start_byte is None:
            start_byte = 0
        if end_byte is None:
            end_byte = source_size - 1

        if start_byte < 0 or end_byte >= source_size or start_byte > end_byte:
            raise StorageError("Invalid byte range")

        bucket_path = self._bucket_path(bucket_name)
        upload_root = self._multipart_dir(bucket_path.name, upload_id)
        if not upload_root.exists():
            upload_root = self._legacy_multipart_dir(bucket_path.name, upload_id)
        if not upload_root.exists():
            raise StorageError("Multipart upload not found")

        checksum = hashlib.md5()
        part_filename = f"part-{part_number:05d}.part"
        part_path = upload_root / part_filename
        temp_path = upload_root / f".{part_filename}.tmp"

        try:
            with source_path.open("rb") as src:
                src.seek(start_byte)
                bytes_to_copy = end_byte - start_byte + 1
                with temp_path.open("wb") as target:
                    remaining = bytes_to_copy
                    while remaining > 0:
                        chunk_size = min(65536, remaining)
                        chunk = src.read(chunk_size)
                        if not chunk:
                            break
                        checksum.update(chunk)
                        target.write(chunk)
                        remaining -= len(chunk)
            temp_path.replace(part_path)
        except OSError:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise

        record = {
            "etag": checksum.hexdigest(),
            "size": part_path.stat().st_size,
            "filename": part_filename,
        }

        manifest_path = upload_root / self.MULTIPART_MANIFEST
        lock_path = upload_root / ".manifest.lock"

        max_retries = 3
        for attempt in range(max_retries):
            try:
                with lock_path.open("w") as lock_file:
                    with _file_lock(lock_file):
                        try:
                            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                        except (OSError, json.JSONDecodeError) as exc:
                            if attempt < max_retries - 1:
                                time.sleep(0.1 * (attempt + 1))
                                continue
                            raise StorageError("Multipart manifest unreadable") from exc

                        parts = manifest.setdefault("parts", {})
                        parts[str(part_number)] = record
                        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                break
            except OSError as exc:
                if attempt < max_retries - 1:
                    time.sleep(0.1 * (attempt + 1))
                    continue
                raise StorageError(f"Failed to update multipart manifest: {exc}") from exc

        return {
            "etag": record["etag"],
            "last_modified": datetime.fromtimestamp(part_path.stat().st_mtime, timezone.utc),
        }

    def complete_multipart_upload(
        self,
        bucket_name: str,
        upload_id: str,
        ordered_parts: List[Dict[str, Any]],
        enforce_quota: bool = True,
    ) -> ObjectMeta:
        if not ordered_parts:
            raise StorageError("parts list required")
        bucket_path = self._bucket_path(bucket_name)
        bucket_id = bucket_path.name
        manifest, upload_root = self._load_multipart_manifest(bucket_id, upload_id)
        parts_map = manifest.get("parts") or {}
        if not parts_map:
            raise StorageError("No uploaded parts found")
        validated: List[tuple[int, Dict[str, Any]]] = []
        total_size = 0
        for part in ordered_parts:
            raw_number = part.get("part_number")
            if raw_number is None:
                raw_number = part.get("PartNumber")
            try:
                number = int(raw_number)
            except (TypeError, ValueError) as exc:
                raise StorageError("Each part must include part_number") from exc
            if number < 1:
                raise StorageError("part numbers must be >= 1")
            key = str(number)
            record = parts_map.get(key)
            if not record:
                raise StorageError(f"Part {number} missing from upload")
            raw_etag = part.get("etag", part.get("ETag", ""))
            supplied_etag = str(raw_etag).strip() or record.get("etag")
            if supplied_etag and record.get("etag") and supplied_etag.strip('"') != record["etag"]:
                raise StorageError(f"ETag mismatch for part {number}")
            validated.append((number, record))
            total_size += record.get("size", 0)
        validated.sort(key=lambda entry: entry[0])

        safe_key = self._sanitize_object_key(manifest["object_key"], self._object_key_max_length_bytes)
        destination = bucket_path / safe_key

        is_overwrite = destination.exists()
        existing_size = destination.stat().st_size if is_overwrite else 0
        size_delta = total_size - existing_size
        object_delta = 0 if is_overwrite else 1
        versioning_enabled = self._is_versioning_enabled(bucket_path)

        if enforce_quota:
            quota_check = self.check_quota(
                bucket_name,
                additional_bytes=max(0, size_delta),
                additional_objects=object_delta,
            )
            if not quota_check["allowed"]:
                raise QuotaExceededError(
                    quota_check["message"] or "Quota exceeded",
                    quota_check["quota"],
                    quota_check["usage"],
                )

        destination.parent.mkdir(parents=True, exist_ok=True)

        lock_file_path = self._system_bucket_root(bucket_id) / "locks" / f"{safe_key.as_posix().replace('/', '_')}.lock"

        archived_version_size = 0
        try:
            with _atomic_lock_file(lock_file_path):
                if versioning_enabled and destination.exists():
                    archived_version_size = destination.stat().st_size
                    self._archive_current_version(bucket_id, safe_key, reason="overwrite")
                checksum = hashlib.md5()
                with destination.open("wb") as target:
                    for _, record in validated:
                        part_path = upload_root / record["filename"]
                        if not part_path.exists():
                            raise StorageError(f"Missing part file {record['filename']}")
                        with part_path.open("rb") as chunk:
                            while True:
                                data = chunk.read(1024 * 1024)
                                if not data:
                                    break
                                checksum.update(data)
                                target.write(data)
        except BlockingIOError:
            raise StorageError("Another upload to this key is in progress")

        shutil.rmtree(upload_root, ignore_errors=True)

        self._update_bucket_stats_cache(
            bucket_id,
            bytes_delta=size_delta,
            objects_delta=object_delta,
            version_bytes_delta=archived_version_size,
            version_count_delta=1 if archived_version_size > 0 else 0,
        )

        stat = destination.stat()
        etag = checksum.hexdigest()
        metadata = manifest.get("metadata")

        internal_meta = {"__etag__": etag, "__size__": str(stat.st_size)}
        combined_meta = {**internal_meta, **(metadata or {})}
        self._write_metadata(bucket_id, safe_key, combined_meta)

        obj_meta = ObjectMeta(
            key=safe_key.as_posix(),
            size=stat.st_size,
            last_modified=datetime.fromtimestamp(stat.st_mtime, timezone.utc),
            etag=etag,
            metadata=metadata,
        )
        self._update_object_cache_entry(bucket_id, safe_key.as_posix(), obj_meta)

        return obj_meta

    def abort_multipart_upload(self, bucket_name: str, upload_id: str) -> None:
        bucket_path = self._bucket_path(bucket_name)
        upload_root = self._multipart_dir(bucket_path.name, upload_id)
        if upload_root.exists():
            shutil.rmtree(upload_root, ignore_errors=True)
            return
        legacy_root = self._legacy_multipart_dir(bucket_path.name, upload_id)
        if legacy_root.exists():
            shutil.rmtree(legacy_root, ignore_errors=True)

    def list_multipart_parts(self, bucket_name: str, upload_id: str) -> List[Dict[str, Any]]:
        """List uploaded parts for a multipart upload."""
        bucket_path = self._bucket_path(bucket_name)
        manifest, upload_root = self._load_multipart_manifest(bucket_path.name, upload_id)
        
        parts = []
        parts_map = manifest.get("parts", {})
        for part_num_str, record in parts_map.items():
            part_num = int(part_num_str)
            part_filename = record.get("filename")
            if not part_filename:
                continue
            part_path = upload_root / part_filename
            if not part_path.exists():
                continue
                
            stat = part_path.stat()
            parts.append({
                "PartNumber": part_num,
                "Size": stat.st_size,
                "ETag": record.get("etag"),
                "LastModified": datetime.fromtimestamp(stat.st_mtime, timezone.utc)
            })
        
        parts.sort(key=lambda x: x["PartNumber"])
        return parts

    def list_multipart_uploads(self, bucket_name: str, include_orphaned: bool = False) -> List[Dict[str, Any]]:
        """List all active multipart uploads for a bucket.

        Args:
            bucket_name: The bucket to list uploads for.
            include_orphaned: If True, also include upload directories that have
                files but no valid manifest.json (orphaned/interrupted uploads).
        """
        bucket_path = self._bucket_path(bucket_name)
        if not bucket_path.exists():
            raise BucketNotFoundError("Bucket does not exist")
        bucket_id = bucket_path.name
        uploads = []

        for multipart_root in (
            self._multipart_bucket_root(bucket_id),
            self._legacy_multipart_bucket_root(bucket_id),
        ):
            if not multipart_root.exists():
                continue
            for upload_dir in multipart_root.iterdir():
                if not upload_dir.is_dir():
                    continue
                manifest_path = upload_dir / "manifest.json"
                if manifest_path.exists():
                    try:
                        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                        uploads.append({
                            "upload_id": manifest.get("upload_id", upload_dir.name),
                            "object_key": manifest.get("object_key", ""),
                            "created_at": manifest.get("created_at", ""),
                        })
                    except (OSError, json.JSONDecodeError):
                        if include_orphaned:
                            has_files = any(upload_dir.rglob("*"))
                            if has_files:
                                uploads.append({
                                    "upload_id": upload_dir.name,
                                    "object_key": "(unknown)",
                                    "created_at": "",
                                    "orphaned": True,
                                })
                elif include_orphaned:
                    has_files = any(f.is_file() for f in upload_dir.rglob("*"))
                    if has_files:
                        uploads.append({
                            "upload_id": upload_dir.name,
                            "object_key": "(unknown)",
                            "created_at": "",
                            "orphaned": True,
                        })
        return uploads

    def _bucket_path(self, bucket_name: str) -> Path:
        safe_name = self._sanitize_bucket_name(bucket_name)
        return self.root / safe_name

    def _require_bucket_path(self, bucket_name: str) -> Path:
        bucket_path = self._bucket_path(bucket_name)
        if not bucket_path.exists():
            raise StorageError("Bucket does not exist")
        return bucket_path

    def _object_path(self, bucket_name: str, object_key: str) -> Path:
        bucket_path = self._bucket_path(bucket_name)
        safe_key = self._sanitize_object_key(object_key, self._object_key_max_length_bytes)
        return bucket_path / safe_key

    def _system_root_path(self) -> Path:
        return self.root / self.SYSTEM_ROOT

    def _system_buckets_root(self) -> Path:
        return self._system_root_path() / self.SYSTEM_BUCKETS_DIR

    def _system_bucket_root(self, bucket_name: str) -> Path:
        return self._system_buckets_root() / bucket_name

    def _bucket_meta_root(self, bucket_name: str) -> Path:
        return self._system_bucket_root(bucket_name) / self.BUCKET_META_DIR

    def _bucket_versions_root(self, bucket_name: str) -> Path:
        return self._system_bucket_root(bucket_name) / self.BUCKET_VERSIONS_DIR

    def _multipart_root(self) -> Path:
        return self._system_root_path() / self.SYSTEM_MULTIPART_DIR

    def _multipart_bucket_root(self, bucket_name: str) -> Path:
        return self._multipart_root() / bucket_name

    def _legacy_metadata_file(self, bucket_name: str, key: Path) -> Path:
        meta_root = self._legacy_meta_root(bucket_name)
        meta_rel = Path(key.as_posix() + ".meta.json")
        return meta_root / meta_rel

    def _legacy_meta_root(self, bucket_name: str) -> Path:
        return self._bucket_path(bucket_name) / ".meta"

    def _legacy_versions_root(self, bucket_name: str) -> Path:
        return self._bucket_path(bucket_name) / ".versions"

    def _legacy_version_dir(self, bucket_name: str, key: Path) -> Path:
        return self._legacy_versions_root(bucket_name) / key

    def _legacy_multipart_bucket_root(self, bucket_name: str) -> Path:
        return self._bucket_path(bucket_name) / ".multipart"

    def _legacy_multipart_dir(self, bucket_name: str, upload_id: str) -> Path:
        return self._legacy_multipart_bucket_root(bucket_name) / upload_id

    def _fast_list_keys(self, bucket_path: Path) -> List[str]:
        """Fast directory walk using os.scandir instead of pathlib.rglob.
        
        This is significantly faster for large directories (10K+ files).
        Returns just the keys (for backward compatibility).
        """
        return list(self._build_object_cache(bucket_path).keys())

    def _build_object_cache(self, bucket_path: Path) -> Dict[str, ObjectMeta]:
        """Build a complete object metadata cache for a bucket.
        
        Uses os.scandir for fast directory walking and a persistent etag index.
        """
        from concurrent.futures import ThreadPoolExecutor
        
        bucket_id = bucket_path.name
        objects: Dict[str, ObjectMeta] = {}
        bucket_str = str(bucket_path)
        bucket_len = len(bucket_str) + 1
        
        etag_index_path = self._system_bucket_root(bucket_id) / "etag_index.json"
        meta_cache: Dict[str, str] = {}
        index_mtime: float = 0
        
        if etag_index_path.exists():
            try:
                index_mtime = etag_index_path.stat().st_mtime
                with open(etag_index_path, 'r', encoding='utf-8') as f:
                    meta_cache = json.load(f)
            except (OSError, json.JSONDecodeError):
                meta_cache = {}
        
        meta_root = self._bucket_meta_root(bucket_id)
        needs_rebuild = False
        
        if meta_root.exists() and index_mtime > 0:
            def check_newer(dir_path: str) -> bool:
                try:
                    with os.scandir(dir_path) as it:
                        for entry in it:
                            if entry.is_dir(follow_symlinks=False):
                                if check_newer(entry.path):
                                    return True
                            elif entry.is_file(follow_symlinks=False) and entry.name.endswith('.meta.json'):
                                if entry.stat().st_mtime > index_mtime:
                                    return True
                except OSError:
                    pass
                return False
            needs_rebuild = check_newer(str(meta_root))
        elif not meta_cache:
            needs_rebuild = True
            
        if needs_rebuild and meta_root.exists():
            meta_str = str(meta_root)
            meta_len = len(meta_str) + 1
            meta_files: list[tuple[str, str]] = []
            
            def collect_meta_files(dir_path: str) -> None:
                try:
                    with os.scandir(dir_path) as it:
                        for entry in it:
                            if entry.is_dir(follow_symlinks=False):
                                collect_meta_files(entry.path)
                            elif entry.is_file(follow_symlinks=False) and entry.name.endswith('.meta.json'):
                                rel = entry.path[meta_len:]
                                key = rel[:-10].replace(os.sep, '/')
                                meta_files.append((key, entry.path))
                except OSError:
                    pass
            
            collect_meta_files(meta_str)
            
            def read_meta_file(item: tuple[str, str]) -> tuple[str, str | None]:
                key, path = item
                try:
                    with open(path, 'rb') as f:
                        content = f.read()
                    etag_marker = b'"__etag__"'
                    idx = content.find(etag_marker)
                    if idx != -1:
                        start = content.find(b'"', idx + len(etag_marker) + 1)
                        if start != -1:
                            end = content.find(b'"', start + 1)
                            if end != -1:
                                return key, content[start+1:end].decode('utf-8')
                    return key, None
                except (OSError, UnicodeDecodeError):
                    return key, None
            
            if meta_files:
                meta_cache = {}
                max_workers = min((os.cpu_count() or 4) * 2, len(meta_files), 16)
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    for key, etag in executor.map(read_meta_file, meta_files):
                        if etag:
                            meta_cache[key] = etag
                
                try:
                    etag_index_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(etag_index_path, 'w', encoding='utf-8') as f:
                        json.dump(meta_cache, f)
                except OSError:
                    pass
        
        def scan_dir(dir_path: str) -> None:
            try:
                with os.scandir(dir_path) as it:
                    for entry in it:
                        if entry.is_dir(follow_symlinks=False):
                            rel_start = entry.path[bucket_len:].split(os.sep)[0] if len(entry.path) > bucket_len else entry.name
                            if rel_start in self.INTERNAL_FOLDERS:
                                continue
                            scan_dir(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            rel = entry.path[bucket_len:]
                            first_part = rel.split(os.sep)[0] if os.sep in rel else rel
                            if first_part in self.INTERNAL_FOLDERS:
                                continue
                            
                            key = rel.replace(os.sep, '/')
                            try:
                                stat = entry.stat()
                                
                                etag = meta_cache.get(key)

                                objects[key] = ObjectMeta(
                                    key=key,
                                    size=stat.st_size,
                                    last_modified=datetime.fromtimestamp(stat.st_mtime, timezone.utc),
                                    etag=etag,
                                    metadata=None, 
                                )
                            except OSError:
                                pass
            except OSError:
                pass
        
        scan_dir(bucket_str)
        return objects

    def _get_object_cache(self, bucket_id: str, bucket_path: Path) -> Dict[str, ObjectMeta]:
        """Get cached object metadata for a bucket, refreshing if stale.

        Uses LRU eviction to prevent unbounded cache growth.
        Thread-safe with per-bucket locks to reduce contention.
        Checks stats.json for cross-process cache invalidation.
        """
        now = time.time()
        current_stats_mtime = self._get_cache_marker_mtime(bucket_id)

        with self._cache_lock:
            cached = self._object_cache.get(bucket_id)
            if cached:
                objects, timestamp, cached_stats_mtime = cached
                if now - timestamp < self._cache_ttl and current_stats_mtime == cached_stats_mtime:
                    self._object_cache.move_to_end(bucket_id)
                    return objects
            cache_version = self._cache_version.get(bucket_id, 0)

        bucket_lock = self._get_bucket_lock(bucket_id)
        with bucket_lock:
            current_stats_mtime = self._get_cache_marker_mtime(bucket_id)
            with self._cache_lock:
                cached = self._object_cache.get(bucket_id)
                if cached:
                    objects, timestamp, cached_stats_mtime = cached
                    if now - timestamp < self._cache_ttl and current_stats_mtime == cached_stats_mtime:
                        self._object_cache.move_to_end(bucket_id)
                        return objects

            objects = self._build_object_cache(bucket_path)
            new_stats_mtime = self._get_cache_marker_mtime(bucket_id)

            with self._cache_lock:
                current_version = self._cache_version.get(bucket_id, 0)
                if current_version != cache_version:
                    objects = self._build_object_cache(bucket_path)
                    new_stats_mtime = self._get_cache_marker_mtime(bucket_id)
                while len(self._object_cache) >= self._object_cache_max_size:
                    self._object_cache.popitem(last=False)

                self._object_cache[bucket_id] = (objects, time.time(), new_stats_mtime)
                self._object_cache.move_to_end(bucket_id)
                self._cache_version[bucket_id] = current_version + 1
                self._sorted_key_cache.pop(bucket_id, None)

        return objects

    def _invalidate_object_cache(self, bucket_id: str) -> None:
        """Invalidate the object cache and etag index for a bucket.

        Increments version counter to signal stale reads.
        Cross-process invalidation is handled by checking stats.json mtime.
        """
        with self._cache_lock:
            self._object_cache.pop(bucket_id, None)
            self._cache_version[bucket_id] = self._cache_version.get(bucket_id, 0) + 1

        etag_index_path = self._system_bucket_root(bucket_id) / "etag_index.json"
        try:
            etag_index_path.unlink(missing_ok=True)
        except OSError:
            pass

    def _get_cache_marker_mtime(self, bucket_id: str) -> float:
        """Get a cache marker combining serial and object count for cross-process invalidation.

        Returns a combined value that changes if either _cache_serial or object count changes.
        This handles cases where the serial was reset but object count differs.
        """
        stats_path = self._system_bucket_root(bucket_id) / "stats.json"
        try:
            data = json.loads(stats_path.read_text(encoding="utf-8"))
            serial = data.get("_cache_serial", 0)
            count = data.get("objects", 0)
            return float(serial * 1000000 + count)
        except (OSError, json.JSONDecodeError):
            return 0

    def _update_object_cache_entry(self, bucket_id: str, key: str, meta: Optional[ObjectMeta]) -> None:
        """Update a single entry in the object cache instead of invalidating the whole cache.

        This is a performance optimization - lazy update instead of full invalidation.
        Cross-process invalidation is handled by checking stats.json mtime.
        """
        with self._cache_lock:
            cached = self._object_cache.get(bucket_id)
            if cached:
                objects, timestamp, stats_mtime = cached
                if meta is None:
                    objects.pop(key, None)
                else:
                    objects[key] = meta
            self._cache_version[bucket_id] = self._cache_version.get(bucket_id, 0) + 1
            self._sorted_key_cache.pop(bucket_id, None)

    def warm_cache(self, bucket_names: Optional[List[str]] = None) -> None:
        """Pre-warm the object cache for specified buckets or all buckets.

        This is called on startup to ensure the first request is fast.
        """
        if bucket_names is None:
            bucket_names = [b.name for b in self.list_buckets()]

        for bucket_name in bucket_names:
            try:
                bucket_path = self._bucket_path(bucket_name)
                if bucket_path.exists():
                    self._get_object_cache(bucket_path.name, bucket_path)
            except Exception:
                pass

    def warm_cache_async(self, bucket_names: Optional[List[str]] = None) -> threading.Thread:
        """Start cache warming in a background thread.

        Returns the thread object so caller can optionally wait for it.
        """
        thread = threading.Thread(
            target=self.warm_cache,
            args=(bucket_names,),
            daemon=True,
            name="cache-warmer",
        )
        thread.start()
        return thread

    def _ensure_system_roots(self) -> None:
        for path in (
            self._system_root_path(),
            self._system_buckets_root(),
            self._multipart_root(),
            self._system_root_path() / self.SYSTEM_TMP_DIR,
        ):
            path.mkdir(parents=True, exist_ok=True)

    def _multipart_dir(self, bucket_name: str, upload_id: str) -> Path:
        return self._multipart_bucket_root(bucket_name) / upload_id

    def _version_dir(self, bucket_name: str, key: Path) -> Path:
        return self._bucket_versions_root(bucket_name) / key

    def _bucket_config_path(self, bucket_name: str) -> Path:
        return self._system_bucket_root(bucket_name) / self.BUCKET_CONFIG_FILE

    def _read_bucket_config(self, bucket_name: str) -> dict[str, Any]:
        now = time.time()
        cached = self._bucket_config_cache.get(bucket_name)
        if cached:
            config, cached_time = cached
            if now - cached_time < self._bucket_config_cache_ttl:
                return config.copy()

        config_path = self._bucket_config_path(bucket_name)
        if not config_path.exists():
            self._bucket_config_cache[bucket_name] = ({}, now)
            return {}
        try:
            data = json.loads(config_path.read_text(encoding="utf-8"))
            config = data if isinstance(data, dict) else {}
            self._bucket_config_cache[bucket_name] = (config, now)
            return config.copy()
        except (OSError, json.JSONDecodeError):
            self._bucket_config_cache[bucket_name] = ({}, now)
            return {}

    def _write_bucket_config(self, bucket_name: str, payload: dict[str, Any]) -> None:
        config_path = self._bucket_config_path(bucket_name)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps(payload), encoding="utf-8")
        self._bucket_config_cache[bucket_name] = (payload.copy(), time.time())

    def _set_bucket_config_entry(self, bucket_name: str, key: str, value: Any | None) -> None:
        config = self._read_bucket_config(bucket_name)
        if value is None:
            config.pop(key, None)
        else:
            config[key] = value
        self._write_bucket_config(bucket_name, config)

    def _is_versioning_enabled(self, bucket_path: Path) -> bool:
        config = self._read_bucket_config(bucket_path.name)
        return bool(config.get("versioning_enabled"))

    def _load_multipart_manifest(self, bucket_name: str, upload_id: str) -> tuple[dict[str, Any], Path]:
        upload_root = self._multipart_dir(bucket_name, upload_id)
        if not upload_root.exists():
            upload_root = self._legacy_multipart_dir(bucket_name, upload_id)
        manifest_path = upload_root / self.MULTIPART_MANIFEST
        if not manifest_path.exists():
            raise StorageError("Multipart upload not found")
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise StorageError("Multipart manifest unreadable") from exc
        return manifest, upload_root

    def _write_multipart_manifest(self, upload_root: Path, manifest: dict[str, Any]) -> None:
        manifest_path = upload_root / self.MULTIPART_MANIFEST
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    def _metadata_file(self, bucket_name: str, key: Path) -> Path:
        meta_root = self._bucket_meta_root(bucket_name)
        meta_rel = Path(key.as_posix() + ".meta.json")
        return meta_root / meta_rel

    def _normalize_metadata(self, metadata: Optional[Dict[str, str]]) -> Optional[Dict[str, str]]:
        if not metadata:
            return None
        clean = {str(k).strip(): str(v) for k, v in metadata.items() if str(k).strip()}
        return clean or None

    def _write_metadata(self, bucket_name: str, key: Path, metadata: Dict[str, str]) -> None:
        clean = self._normalize_metadata(metadata)
        if not clean:
            self._delete_metadata(bucket_name, key)
            return
        meta_file = self._metadata_file(bucket_name, key)
        meta_file.parent.mkdir(parents=True, exist_ok=True)
        meta_file.write_text(json.dumps({"metadata": clean}), encoding="utf-8")

    def _archive_current_version(self, bucket_name: str, key: Path, *, reason: str) -> None:
        bucket_path = self._bucket_path(bucket_name)
        source = bucket_path / key
        if not source.exists():
            return
        version_dir = self._version_dir(bucket_name, key)
        version_dir.mkdir(parents=True, exist_ok=True)
        now = _utcnow()
        version_id = f"{now.strftime('%Y%m%dT%H%M%S%fZ')}-{uuid.uuid4().hex[:8]}"
        data_path = version_dir / f"{version_id}.bin"
        shutil.copy2(source, data_path)
        metadata = self._read_metadata(bucket_name, key)
        record = {
            "version_id": version_id,
            "key": key.as_posix(),
            "size": source.stat().st_size,
            "archived_at": now.isoformat().replace("+00:00", "Z"),
            "etag": self._compute_etag(source),
            "metadata": metadata or {},
            "reason": reason,
        }
        manifest_path = version_dir / f"{version_id}.json"
        manifest_path.write_text(json.dumps(record), encoding="utf-8")

    def _read_metadata(self, bucket_name: str, key: Path) -> Dict[str, str]:
        for meta_file in (self._metadata_file(bucket_name, key), self._legacy_metadata_file(bucket_name, key)):
            if not meta_file.exists():
                continue
            try:
                payload = json.loads(meta_file.read_text(encoding="utf-8"))
                data = payload.get("metadata")
                return data if isinstance(data, dict) else {}
            except (OSError, json.JSONDecodeError):
                return {}
        return {}

    def _safe_unlink(self, path: Path) -> None:
        attempts = 3
        last_error: PermissionError | None = None
        for attempt in range(attempts):
            try:
                path.unlink()
                return
            except FileNotFoundError:
                return
            except PermissionError as exc:
                last_error = exc
                if os.name == "nt":
                    time.sleep(0.15 * (attempt + 1))
            except OSError as exc:
                raise StorageError(f"Unable to delete object: {exc}") from exc
        message = "Object file is currently in use. Close active previews or wait and try again."
        raise StorageError(message) from last_error

    def _delete_metadata(self, bucket_name: str, key: Path) -> None:
        locations = (
            (self._metadata_file(bucket_name, key), self._bucket_meta_root(bucket_name)),
            (self._legacy_metadata_file(bucket_name, key), self._legacy_meta_root(bucket_name)),
        )
        for meta_file, meta_root in locations:
            try:
                if meta_file.exists():
                    meta_file.unlink()
                    parent = meta_file.parent
                    while parent != meta_root and parent.exists() and not any(parent.iterdir()):
                        parent.rmdir()
                        parent = parent.parent
            except OSError:
                continue

    def _check_bucket_contents(self, bucket_path: Path) -> tuple[bool, bool, bool]:
        """Check bucket for objects, versions, and multipart uploads in a single pass.

        Returns (has_visible_objects, has_archived_versions, has_active_multipart_uploads).
        Uses early exit when all three are found.
        """
        has_objects = False
        has_versions = False
        has_multipart = False
        bucket_name = bucket_path.name

        for path in bucket_path.rglob("*"):
            if has_objects:
                break
            if not path.is_file():
                continue
            rel = path.relative_to(bucket_path)
            if rel.parts and rel.parts[0] in self.INTERNAL_FOLDERS:
                continue
            has_objects = True

        for version_root in (
            self._bucket_versions_root(bucket_name),
            self._legacy_versions_root(bucket_name),
        ):
            if has_versions:
                break
            if version_root.exists():
                for path in version_root.rglob("*"):
                    if path.is_file():
                        has_versions = True
                        break

        for uploads_root in (
            self._multipart_bucket_root(bucket_name),
            self._legacy_multipart_bucket_root(bucket_name),
        ):
            if has_multipart:
                break
            if uploads_root.exists():
                for path in uploads_root.rglob("*"):
                    if path.is_file():
                        has_multipart = True
                        break

        return has_objects, has_versions, has_multipart

    def _has_visible_objects(self, bucket_path: Path) -> bool:
        has_objects, _, _ = self._check_bucket_contents(bucket_path)
        return has_objects

    def _has_archived_versions(self, bucket_path: Path) -> bool:
        _, has_versions, _ = self._check_bucket_contents(bucket_path)
        return has_versions

    def _has_active_multipart_uploads(self, bucket_path: Path) -> bool:
        _, _, has_multipart = self._check_bucket_contents(bucket_path)
        return has_multipart

    def _remove_tree(self, path: Path) -> None:
        if not path.exists():
            return
        def _handle_error(func, target_path, exc_info):
            try:
                os.chmod(target_path, stat.S_IRWXU)
                func(target_path)
            except Exception as exc:
                raise StorageError(f"Unable to delete bucket contents: {exc}") from exc

        try:
            shutil.rmtree(path, onerror=_handle_error)
        except FileNotFoundError:
            return
        except PermissionError as exc:
            raise StorageError("Bucket in use. Close open files and try again") from exc

    @staticmethod
    def _sanitize_bucket_name(bucket_name: str) -> str:
        if not bucket_name:
            raise StorageError("Bucket name required")

        name = bucket_name.lower()
        if len(name) < 3 or len(name) > 63:
            raise StorageError("Bucket name must be between 3 and 63 characters")

        if name.startswith("-") or name.endswith("-"):
            raise StorageError("Bucket name cannot start or end with a hyphen")

        if ".." in name:
            raise StorageError("Bucket name cannot contain consecutive periods")

        if name.startswith("xn--"):
            raise StorageError("Bucket name cannot start with 'xn--'")

        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", name):
            raise StorageError("Bucket name cannot be formatted like an IP address")

        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]+[a-z0-9]", name):
            raise StorageError("Bucket name can contain lowercase letters, numbers, dots, and hyphens")

        return name

    @staticmethod
    def _sanitize_object_key(object_key: str, max_length_bytes: int = 1024) -> Path:
        if not object_key:
            raise StorageError("Object key required")
        if "\x00" in object_key:
            raise StorageError("Object key contains null bytes")
        object_key = unicodedata.normalize("NFC", object_key)
        if len(object_key.encode("utf-8")) > max_length_bytes:
            raise StorageError(f"Object key exceeds maximum length of {max_length_bytes} bytes")
        if object_key.startswith(("/", "\\")):
            raise StorageError("Object key cannot start with a slash")

        candidate = Path(object_key)
        if ".." in candidate.parts:
            raise StorageError("Object key contains parent directory references")
        
        if candidate.is_absolute():
            raise StorageError("Absolute object keys are not allowed")
        if getattr(candidate, "drive", ""):
            raise StorageError("Object key cannot include a drive letter")
        parts = []
        for part in candidate.parts:
            if part in ("", ".", ".."):
                raise StorageError("Object key contains invalid segments")
            if any(ord(ch) < 32 for ch in part):
                raise StorageError("Object key contains control characters")
            if os.name == "nt":
                if any(ch in part for ch in "<>:\"/\\|?*"):
                    raise StorageError("Object key contains characters not supported on Windows filesystems")
                if part.endswith((" ", ".")):
                    raise StorageError("Object key segments cannot end with spaces or periods on Windows")
                trimmed = part.upper().rstrip(". ")
                if trimmed in WINDOWS_RESERVED_NAMES:
                    raise StorageError(f"Invalid filename segment: {part}")
            parts.append(part)
        if parts:
            top_level = parts[0]
            if top_level in ObjectStorage.INTERNAL_FOLDERS or top_level == ObjectStorage.SYSTEM_ROOT:
                raise StorageError("Object key uses a reserved prefix")
        return Path(*parts)

    @staticmethod
    def _compute_etag(path: Path) -> str:
        checksum = hashlib.md5()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(8192), b""):
                checksum.update(chunk)
        return checksum.hexdigest()


class _HashingReader:
    """Wraps a binary stream, updating the checksum as it is read."""

    def __init__(self, stream: BinaryIO, checksum: Any) -> None:
        self.stream = stream
        self.checksum = checksum

    def read(self, size: int = -1) -> bytes:
        data = self.stream.read(size)
        if data:
            self.checksum.update(data)
        return data
