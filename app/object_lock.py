from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional


class RetentionMode(Enum):
    GOVERNANCE = "GOVERNANCE"
    COMPLIANCE = "COMPLIANCE"


class ObjectLockError(Exception):
    pass


@dataclass
class ObjectLockRetention:
    mode: RetentionMode
    retain_until_date: datetime

    def to_dict(self) -> Dict[str, str]:
        return {
            "Mode": self.mode.value,
            "RetainUntilDate": self.retain_until_date.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Optional["ObjectLockRetention"]:
        if not data:
            return None
        mode_str = data.get("Mode")
        date_str = data.get("RetainUntilDate")
        if not mode_str or not date_str:
            return None
        try:
            mode = RetentionMode(mode_str)
            retain_until = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            return cls(mode=mode, retain_until_date=retain_until)
        except (ValueError, KeyError):
            return None

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.retain_until_date


@dataclass
class ObjectLockConfig:
    enabled: bool = False
    default_retention: Optional[ObjectLockRetention] = None

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {"ObjectLockEnabled": "Enabled" if self.enabled else "Disabled"}
        if self.default_retention:
            result["Rule"] = {
                "DefaultRetention": {
                    "Mode": self.default_retention.mode.value,
                    "Days": None,
                    "Years": None,
                }
            }
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ObjectLockConfig":
        enabled = data.get("ObjectLockEnabled") == "Enabled"
        default_retention = None
        rule = data.get("Rule")
        if rule and "DefaultRetention" in rule:
            dr = rule["DefaultRetention"]
            mode_str = dr.get("Mode", "GOVERNANCE")
            days = dr.get("Days")
            years = dr.get("Years")
            if days or years:
                from datetime import timedelta
                now = datetime.now(timezone.utc)
                if years:
                    delta = timedelta(days=int(years) * 365)
                else:
                    delta = timedelta(days=int(days))
                default_retention = ObjectLockRetention(
                    mode=RetentionMode(mode_str),
                    retain_until_date=now + delta,
                )
        return cls(enabled=enabled, default_retention=default_retention)


class ObjectLockService:
    def __init__(self, storage_root: Path):
        self.storage_root = storage_root
        self._config_cache: Dict[str, ObjectLockConfig] = {}

    def _bucket_lock_config_path(self, bucket_name: str) -> Path:
        return self.storage_root / ".myfsio.sys" / "buckets" / bucket_name / "object_lock.json"

    def _object_lock_meta_path(self, bucket_name: str, object_key: str) -> Path:
        safe_key = object_key.replace("/", "_").replace("\\", "_")
        return (
            self.storage_root / ".myfsio.sys" / "buckets" / bucket_name /
            "locks" / f"{safe_key}.lock.json"
        )

    def get_bucket_lock_config(self, bucket_name: str) -> ObjectLockConfig:
        if bucket_name in self._config_cache:
            return self._config_cache[bucket_name]

        config_path = self._bucket_lock_config_path(bucket_name)
        if not config_path.exists():
            return ObjectLockConfig(enabled=False)

        try:
            data = json.loads(config_path.read_text(encoding="utf-8"))
            config = ObjectLockConfig.from_dict(data)
            self._config_cache[bucket_name] = config
            return config
        except (json.JSONDecodeError, OSError):
            return ObjectLockConfig(enabled=False)

    def set_bucket_lock_config(self, bucket_name: str, config: ObjectLockConfig) -> None:
        config_path = self._bucket_lock_config_path(bucket_name)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps(config.to_dict()), encoding="utf-8")
        self._config_cache[bucket_name] = config

    def enable_bucket_lock(self, bucket_name: str) -> None:
        config = self.get_bucket_lock_config(bucket_name)
        config.enabled = True
        self.set_bucket_lock_config(bucket_name, config)

    def is_bucket_lock_enabled(self, bucket_name: str) -> bool:
        return self.get_bucket_lock_config(bucket_name).enabled

    def get_object_retention(self, bucket_name: str, object_key: str) -> Optional[ObjectLockRetention]:
        meta_path = self._object_lock_meta_path(bucket_name, object_key)
        if not meta_path.exists():
            return None
        try:
            data = json.loads(meta_path.read_text(encoding="utf-8"))
            return ObjectLockRetention.from_dict(data.get("retention", {}))
        except (json.JSONDecodeError, OSError):
            return None

    def set_object_retention(
        self,
        bucket_name: str,
        object_key: str,
        retention: ObjectLockRetention,
        bypass_governance: bool = False,
    ) -> None:
        existing = self.get_object_retention(bucket_name, object_key)
        if existing and not existing.is_expired():
            if existing.mode == RetentionMode.COMPLIANCE:
                raise ObjectLockError(
                    "Cannot modify retention on object with COMPLIANCE mode until retention expires"
                )
            if existing.mode == RetentionMode.GOVERNANCE and not bypass_governance:
                raise ObjectLockError(
                    "Cannot modify GOVERNANCE retention without bypass-governance permission"
                )

        meta_path = self._object_lock_meta_path(bucket_name, object_key)
        meta_path.parent.mkdir(parents=True, exist_ok=True)

        existing_data: Dict[str, Any] = {}
        if meta_path.exists():
            try:
                existing_data = json.loads(meta_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass

        existing_data["retention"] = retention.to_dict()
        meta_path.write_text(json.dumps(existing_data), encoding="utf-8")

    def get_legal_hold(self, bucket_name: str, object_key: str) -> bool:
        meta_path = self._object_lock_meta_path(bucket_name, object_key)
        if not meta_path.exists():
            return False
        try:
            data = json.loads(meta_path.read_text(encoding="utf-8"))
            return data.get("legal_hold", False)
        except (json.JSONDecodeError, OSError):
            return False

    def set_legal_hold(self, bucket_name: str, object_key: str, enabled: bool) -> None:
        meta_path = self._object_lock_meta_path(bucket_name, object_key)
        meta_path.parent.mkdir(parents=True, exist_ok=True)

        existing_data: Dict[str, Any] = {}
        if meta_path.exists():
            try:
                existing_data = json.loads(meta_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass

        existing_data["legal_hold"] = enabled
        meta_path.write_text(json.dumps(existing_data), encoding="utf-8")

    def can_delete_object(
        self,
        bucket_name: str,
        object_key: str,
        bypass_governance: bool = False,
    ) -> tuple[bool, str]:
        if self.get_legal_hold(bucket_name, object_key):
            return False, "Object is under legal hold"

        retention = self.get_object_retention(bucket_name, object_key)
        if retention and not retention.is_expired():
            if retention.mode == RetentionMode.COMPLIANCE:
                return False, f"Object is locked in COMPLIANCE mode until {retention.retain_until_date.isoformat()}"
            if retention.mode == RetentionMode.GOVERNANCE:
                if not bypass_governance:
                    return False, f"Object is locked in GOVERNANCE mode until {retention.retain_until_date.isoformat()}"

        return True, ""

    def can_overwrite_object(
        self,
        bucket_name: str,
        object_key: str,
        bypass_governance: bool = False,
    ) -> tuple[bool, str]:
        return self.can_delete_object(bucket_name, object_key, bypass_governance)

    def delete_object_lock_metadata(self, bucket_name: str, object_key: str) -> None:
        meta_path = self._object_lock_meta_path(bucket_name, object_key)
        try:
            if meta_path.exists():
                meta_path.unlink()
        except OSError:
            pass
