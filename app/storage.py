"""Filesystem-backed object storage helpers."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import time
import unicodedata
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Dict, List, Optional

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


@dataclass
class ObjectMeta:
    key: str
    size: int
    last_modified: datetime
    etag: str
    metadata: Optional[Dict[str, str]] = None


@dataclass
class BucketMeta:
    name: str
    created_at: datetime


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

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._ensure_system_roots()

    # ---------------------- Bucket helpers ----------------------
    def list_buckets(self) -> List[BucketMeta]:
        buckets: List[BucketMeta] = []
        for bucket in sorted(self.root.iterdir()):
            if bucket.is_dir() and bucket.name != self.SYSTEM_ROOT:
                stat = bucket.stat()
                buckets.append(
                    BucketMeta(
                        name=bucket.name,
                        created_at=datetime.fromtimestamp(stat.st_ctime),
                    )
                )
        return buckets

    def bucket_exists(self, bucket_name: str) -> bool:
        return self._bucket_path(bucket_name).exists()

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

    def bucket_stats(self, bucket_name: str) -> dict[str, int]:
        """Return object count and total size for the bucket (cached)."""
        bucket_path = self._bucket_path(bucket_name)
        if not bucket_path.exists():
            raise StorageError("Bucket does not exist")

        # Try to read from cache
        cache_path = self._system_bucket_root(bucket_name) / "stats.json"
        if cache_path.exists():
            try:
                # Check if cache is fresh (e.g., < 60 seconds old)
                if time.time() - cache_path.stat().st_mtime < 60:
                    return json.loads(cache_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                pass

        # Calculate fresh stats
        object_count = 0
        total_bytes = 0
        for path in bucket_path.rglob("*"):
            if path.is_file():
                rel = path.relative_to(bucket_path)
                if rel.parts and rel.parts[0] in self.INTERNAL_FOLDERS:
                    continue
                stat = path.stat()
                object_count += 1
                total_bytes += stat.st_size
        
        stats = {"objects": object_count, "bytes": total_bytes}
        
        # Write to cache
        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(json.dumps(stats), encoding="utf-8")
        except OSError:
            pass
            
        return stats

    def delete_bucket(self, bucket_name: str) -> None:
        bucket_path = self._bucket_path(bucket_name)
        if not bucket_path.exists():
            raise StorageError("Bucket does not exist")
        if self._has_visible_objects(bucket_path):
            raise StorageError("Bucket not empty")
        if self._has_archived_versions(bucket_path):
            raise StorageError("Bucket contains archived object versions")
        if self._has_active_multipart_uploads(bucket_path):
            raise StorageError("Bucket has active multipart uploads")
        self._remove_tree(bucket_path)
        self._remove_tree(self._system_bucket_root(bucket_path.name))
        self._remove_tree(self._multipart_bucket_root(bucket_path.name))

    # ---------------------- Object helpers ----------------------
    def list_objects(self, bucket_name: str) -> List[ObjectMeta]:
        bucket_path = self._bucket_path(bucket_name)
        if not bucket_path.exists():
            raise StorageError("Bucket does not exist")
        bucket_id = bucket_path.name

        objects: List[ObjectMeta] = []
        for path in bucket_path.rglob("*"):
            if path.is_file():
                stat = path.stat()
                rel = path.relative_to(bucket_path)
                if rel.parts and rel.parts[0] in self.INTERNAL_FOLDERS:
                    continue
                metadata = self._read_metadata(bucket_id, rel)
                objects.append(
                    ObjectMeta(
                        key=str(rel.as_posix()),
                        size=stat.st_size,
                        last_modified=datetime.fromtimestamp(stat.st_mtime),
                        etag=self._compute_etag(path),
                        metadata=metadata or None,
                    )
                )
        objects.sort(key=lambda meta: meta.key)
        return objects

    def put_object(
        self,
        bucket_name: str,
        object_key: str,
        stream: BinaryIO,
        *,
        metadata: Optional[Dict[str, str]] = None,
    ) -> ObjectMeta:
        bucket_path = self._bucket_path(bucket_name)
        if not bucket_path.exists():
            raise StorageError("Bucket does not exist")
        bucket_id = bucket_path.name

        safe_key = self._sanitize_object_key(object_key)
        destination = bucket_path / safe_key
        destination.parent.mkdir(parents=True, exist_ok=True)

        if self._is_versioning_enabled(bucket_path) and destination.exists():
            self._archive_current_version(bucket_id, safe_key, reason="overwrite")

        checksum = hashlib.md5()
        with destination.open("wb") as target:
            shutil.copyfileobj(_HashingReader(stream, checksum), target)

        stat = destination.stat()
        if metadata:
            self._write_metadata(bucket_id, safe_key, metadata)
        else:
            self._delete_metadata(bucket_id, safe_key)
        return ObjectMeta(
            key=safe_key.as_posix(),
            size=stat.st_size,
            last_modified=datetime.fromtimestamp(stat.st_mtime),
            etag=checksum.hexdigest(),
            metadata=metadata,
        )

    def get_object_path(self, bucket_name: str, object_key: str) -> Path:
        path = self._object_path(bucket_name, object_key)
        if not path.exists():
            raise StorageError("Object not found")
        return path

    def get_object_metadata(self, bucket_name: str, object_key: str) -> Dict[str, str]:
        bucket_path = self._bucket_path(bucket_name)
        if not bucket_path.exists():
            return {}
        safe_key = self._sanitize_object_key(object_key)
        return self._read_metadata(bucket_path.name, safe_key) or {}

    def delete_object(self, bucket_name: str, object_key: str) -> None:
        bucket_path = self._bucket_path(bucket_name)
        path = self._object_path(bucket_name, object_key)
        if not path.exists():
            return
        safe_key = path.relative_to(bucket_path)
        bucket_id = bucket_path.name
        if self._is_versioning_enabled(bucket_path):
            self._archive_current_version(bucket_id, safe_key, reason="delete")
        rel = path.relative_to(bucket_path)
        self._safe_unlink(path)
        self._delete_metadata(bucket_id, rel)
        for parent in path.parents:
            if parent == bucket_path:
                break
            if parent.exists() and not any(parent.iterdir()):
                parent.rmdir()

    def purge_object(self, bucket_name: str, object_key: str) -> None:
        bucket_path = self._bucket_path(bucket_name)
        target = self._object_path(bucket_name, object_key)
        bucket_id = bucket_path.name
        if target.exists():
            rel = target.relative_to(bucket_path)
            self._safe_unlink(target)
            self._delete_metadata(bucket_id, rel)
        else:
            rel = self._sanitize_object_key(object_key)
            self._delete_metadata(bucket_id, rel)
        version_dir = self._version_dir(bucket_id, rel)
        if version_dir.exists():
            shutil.rmtree(version_dir, ignore_errors=True)
        legacy_version_dir = self._legacy_version_dir(bucket_id, rel)
        if legacy_version_dir.exists():
            shutil.rmtree(legacy_version_dir, ignore_errors=True)
        for parent in target.parents:
            if parent == bucket_path:
                break
            if parent.exists() and not any(parent.iterdir()):
                parent.rmdir()

    # ---------------------- Versioning helpers ----------------------
    def is_versioning_enabled(self, bucket_name: str) -> bool:
        bucket_path = self._bucket_path(bucket_name)
        if not bucket_path.exists():
            raise StorageError("Bucket does not exist")
        return self._is_versioning_enabled(bucket_path)

    def set_bucket_versioning(self, bucket_name: str, enabled: bool) -> None:
        bucket_path = self._require_bucket_path(bucket_name)
        config = self._read_bucket_config(bucket_path.name)
        config["versioning_enabled"] = bool(enabled)
        self._write_bucket_config(bucket_path.name, config)

    # ---------------------- Bucket configuration helpers ----------------------
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

    def list_object_versions(self, bucket_name: str, object_key: str) -> List[Dict[str, Any]]:
        bucket_path = self._bucket_path(bucket_name)
        if not bucket_path.exists():
            raise StorageError("Bucket does not exist")
        bucket_id = bucket_path.name
        safe_key = self._sanitize_object_key(object_key)
        version_dir = self._version_dir(bucket_id, safe_key)
        if not version_dir.exists():
            version_dir = self._legacy_version_dir(bucket_id, safe_key)
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
        versions.sort(key=lambda item: item.get("archived_at", ""), reverse=True)
        return versions

    def restore_object_version(self, bucket_name: str, object_key: str, version_id: str) -> ObjectMeta:
        bucket_path = self._bucket_path(bucket_name)
        if not bucket_path.exists():
            raise StorageError("Bucket does not exist")
        bucket_id = bucket_path.name
        safe_key = self._sanitize_object_key(object_key)
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
        if self._is_versioning_enabled(bucket_path) and destination.exists():
            self._archive_current_version(bucket_id, safe_key, reason="restore-overwrite")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(data_path, destination)
        if metadata:
            self._write_metadata(bucket_id, safe_key, metadata)
        else:
            self._delete_metadata(bucket_id, safe_key)
        stat = destination.stat()
        return ObjectMeta(
            key=safe_key.as_posix(),
            size=stat.st_size,
            last_modified=datetime.fromtimestamp(stat.st_mtime),
            etag=self._compute_etag(destination),
            metadata=metadata or None,
        )

    def list_orphaned_objects(self, bucket_name: str) -> List[Dict[str, Any]]:
        bucket_path = self._bucket_path(bucket_name)
        if not bucket_path.exists():
            raise StorageError("Bucket does not exist")
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
                archived_at = payload.get("archived_at") or ""
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

    # ---------------------- Multipart helpers ----------------------
    def initiate_multipart_upload(
        self,
        bucket_name: str,
        object_key: str,
        *,
        metadata: Optional[Dict[str, str]] = None,
    ) -> str:
        bucket_path = self._bucket_path(bucket_name)
        if not bucket_path.exists():
            raise StorageError("Bucket does not exist")
        bucket_id = bucket_path.name
        safe_key = self._sanitize_object_key(object_key)
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
        if part_number < 1:
            raise StorageError("part_number must be >= 1")
        bucket_path = self._bucket_path(bucket_name)
        manifest, upload_root = self._load_multipart_manifest(bucket_path.name, upload_id)
        checksum = hashlib.md5()
        part_filename = f"part-{part_number:05d}.part"
        part_path = upload_root / part_filename
        with part_path.open("wb") as target:
            shutil.copyfileobj(_HashingReader(stream, checksum), target)
        record = {
            "etag": checksum.hexdigest(),
            "size": part_path.stat().st_size,
            "filename": part_filename,
        }
        parts = manifest.setdefault("parts", {})
        parts[str(part_number)] = record
        self._write_multipart_manifest(upload_root, manifest)
        return record["etag"]

    def complete_multipart_upload(
        self,
        bucket_name: str,
        upload_id: str,
        ordered_parts: List[Dict[str, Any]],
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
        validated.sort(key=lambda entry: entry[0])

        safe_key = self._sanitize_object_key(manifest["object_key"])
        destination = bucket_path / safe_key
        destination.parent.mkdir(parents=True, exist_ok=True)
        if self._is_versioning_enabled(bucket_path) and destination.exists():
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

        metadata = manifest.get("metadata")
        if metadata:
            self._write_metadata(bucket_id, safe_key, metadata)
        else:
            self._delete_metadata(bucket_id, safe_key)

        shutil.rmtree(upload_root, ignore_errors=True)
        stat = destination.stat()
        return ObjectMeta(
            key=safe_key.as_posix(),
            size=stat.st_size,
            last_modified=datetime.fromtimestamp(stat.st_mtime),
            etag=checksum.hexdigest(),
            metadata=metadata,
        )

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

    # ---------------------- internal helpers ----------------------
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
        safe_key = self._sanitize_object_key(object_key)
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
        config_path = self._bucket_config_path(bucket_name)
        if not config_path.exists():
            return {}
        try:
            data = json.loads(config_path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def _write_bucket_config(self, bucket_name: str, payload: dict[str, Any]) -> None:
        config_path = self._bucket_config_path(bucket_name)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps(payload), encoding="utf-8")

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

    def _has_visible_objects(self, bucket_path: Path) -> bool:
        for path in bucket_path.rglob("*"):
            if not path.is_file():
                continue
            rel = path.relative_to(bucket_path)
            if rel.parts and rel.parts[0] in self.INTERNAL_FOLDERS:
                continue
            return True
        return False

    def _has_archived_versions(self, bucket_path: Path) -> bool:
        for version_root in (
            self._bucket_versions_root(bucket_path.name),
            self._legacy_versions_root(bucket_path.name),
        ):
            if version_root.exists() and any(path.is_file() for path in version_root.rglob("*")):
                return True
        return False

    def _has_active_multipart_uploads(self, bucket_path: Path) -> bool:
        for uploads_root in (
            self._multipart_bucket_root(bucket_path.name),
            self._legacy_multipart_bucket_root(bucket_path.name),
        ):
            if uploads_root.exists() and any(path.is_file() for path in uploads_root.rglob("*")):
                return True
        return False

    def _remove_tree(self, path: Path) -> None:
        if not path.exists():
            return
        def _handle_error(func, target_path, exc_info):
            try:
                os.chmod(target_path, stat.S_IRWXU)
                func(target_path)
            except Exception as exc:  # pragma: no cover - fallback failure
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
    def _sanitize_object_key(object_key: str) -> Path:
        if not object_key:
            raise StorageError("Object key required")
        if len(object_key.encode("utf-8")) > 1024:
            raise StorageError("Object key exceeds maximum length of 1024 bytes")
        if "\x00" in object_key:
            raise StorageError("Object key contains null bytes")
        if object_key.startswith(("/", "\\")):
            raise StorageError("Object key cannot start with a slash")
        normalized = unicodedata.normalize("NFC", object_key)
        if normalized != object_key:
            raise StorageError("Object key must use normalized Unicode")
        
        candidate = Path(normalized)
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
