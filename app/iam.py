from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from cryptography.fernet import Fernet, InvalidToken


class IamError(RuntimeError):
    """Raised when authentication or authorization fails."""


S3_ACTIONS = {
    "list", "read", "write", "delete", "share", "policy",
    "replication", "lifecycle", "cors",
    "create_bucket", "delete_bucket",
    "versioning", "tagging", "encryption", "quota",
    "object_lock", "notification", "logging", "website",
}
IAM_ACTIONS = {
    "iam:list_users",
    "iam:create_user",
    "iam:delete_user",
    "iam:rotate_key",
    "iam:update_policy",
    "iam:create_key",
    "iam:delete_key",
    "iam:get_user",
    "iam:get_policy",
    "iam:disable_user",
}
ALLOWED_ACTIONS = (S3_ACTIONS | IAM_ACTIONS) | {"iam:*"}

_V1_IMPLIED_ACTIONS = {
    "write": {"create_bucket"},
    "delete": {"delete_bucket"},
    "policy": {
        "versioning", "tagging", "encryption", "quota",
        "object_lock", "notification", "logging", "website",
        "cors", "lifecycle", "replication", "share",
    },
}

ACTION_ALIASES = {
    "list": "list",
    "s3:listbucket": "list",
    "s3:listallmybuckets": "list",
    "s3:listbucketversions": "list",
    "s3:listmultipartuploads": "list",
    "s3:listparts": "list",
    "read": "read",
    "s3:getobject": "read",
    "s3:getobjectversion": "read",
    "s3:getobjecttagging": "read",
    "s3:getobjectversiontagging": "read",
    "s3:getobjectacl": "read",
    "s3:headobject": "read",
    "s3:headbucket": "read",
    "write": "write",
    "s3:putobject": "write",
    "s3:putobjecttagging": "write",
    "s3:createmultipartupload": "write",
    "s3:uploadpart": "write",
    "s3:completemultipartupload": "write",
    "s3:abortmultipartupload": "write",
    "s3:copyobject": "write",
    "delete": "delete",
    "s3:deleteobject": "delete",
    "s3:deleteobjectversion": "delete",
    "s3:deleteobjecttagging": "delete",
    "create_bucket": "create_bucket",
    "s3:createbucket": "create_bucket",
    "delete_bucket": "delete_bucket",
    "s3:deletebucket": "delete_bucket",
    "share": "share",
    "s3:putobjectacl": "share",
    "s3:putbucketacl": "share",
    "s3:getbucketacl": "share",
    "policy": "policy",
    "s3:putbucketpolicy": "policy",
    "s3:getbucketpolicy": "policy",
    "s3:deletebucketpolicy": "policy",
    "replication": "replication",
    "s3:getreplicationconfiguration": "replication",
    "s3:putreplicationconfiguration": "replication",
    "s3:deletereplicationconfiguration": "replication",
    "s3:replicateobject": "replication",
    "s3:replicatetags": "replication",
    "s3:replicatedelete": "replication",
    "lifecycle": "lifecycle",
    "s3:getlifecycleconfiguration": "lifecycle",
    "s3:putlifecycleconfiguration": "lifecycle",
    "s3:deletelifecycleconfiguration": "lifecycle",
    "s3:getbucketlifecycle": "lifecycle",
    "s3:putbucketlifecycle": "lifecycle",
    "cors": "cors",
    "s3:getbucketcors": "cors",
    "s3:putbucketcors": "cors",
    "s3:deletebucketcors": "cors",
    "versioning": "versioning",
    "s3:getbucketversioning": "versioning",
    "s3:putbucketversioning": "versioning",
    "tagging": "tagging",
    "s3:getbuckettagging": "tagging",
    "s3:putbuckettagging": "tagging",
    "s3:deletebuckettagging": "tagging",
    "encryption": "encryption",
    "s3:getencryptionconfiguration": "encryption",
    "s3:putencryptionconfiguration": "encryption",
    "s3:deleteencryptionconfiguration": "encryption",
    "quota": "quota",
    "s3:getbucketquota": "quota",
    "s3:putbucketquota": "quota",
    "s3:deletebucketquota": "quota",
    "object_lock": "object_lock",
    "s3:getobjectlockconfiguration": "object_lock",
    "s3:putobjectlockconfiguration": "object_lock",
    "s3:putobjectretention": "object_lock",
    "s3:getobjectretention": "object_lock",
    "s3:putobjectlegalhold": "object_lock",
    "s3:getobjectlegalhold": "object_lock",
    "notification": "notification",
    "s3:getbucketnotificationconfiguration": "notification",
    "s3:putbucketnotificationconfiguration": "notification",
    "s3:deletebucketnotificationconfiguration": "notification",
    "logging": "logging",
    "s3:getbucketlogging": "logging",
    "s3:putbucketlogging": "logging",
    "s3:deletebucketlogging": "logging",
    "website": "website",
    "s3:getbucketwebsite": "website",
    "s3:putbucketwebsite": "website",
    "s3:deletebucketwebsite": "website",
    "iam:listusers": "iam:list_users",
    "iam:createuser": "iam:create_user",
    "iam:deleteuser": "iam:delete_user",
    "iam:rotateaccesskey": "iam:rotate_key",
    "iam:putuserpolicy": "iam:update_policy",
    "iam:createaccesskey": "iam:create_key",
    "iam:deleteaccesskey": "iam:delete_key",
    "iam:getuser": "iam:get_user",
    "iam:getpolicy": "iam:get_policy",
    "iam:disableuser": "iam:disable_user",
    "iam:*": "iam:*",
}


@dataclass
class Policy:
    bucket: str
    actions: Set[str]
    prefix: str = "*"


@dataclass
class Principal:
    access_key: str
    display_name: str
    policies: List[Policy]


def _derive_fernet_key(secret: str) -> bytes:
    raw = hashlib.pbkdf2_hmac("sha256", secret.encode(), b"myfsio-iam-encryption", 100_000)
    return base64.urlsafe_b64encode(raw)


_IAM_ENCRYPTED_PREFIX = b"MYFSIO_IAM_ENC:"

_CONFIG_VERSION = 2


def _expand_v1_actions(actions: Set[str]) -> Set[str]:
    expanded = set(actions)
    for action, implied in _V1_IMPLIED_ACTIONS.items():
        if action in expanded:
            expanded.update(implied)
    return expanded


class IamService:
    """Loads IAM configuration, manages users, and evaluates policies."""

    def __init__(self, config_path: Path, auth_max_attempts: int = 5, auth_lockout_minutes: int = 15, encryption_key: str | None = None) -> None:
        self.config_path = Path(config_path)
        self.auth_max_attempts = auth_max_attempts
        self.auth_lockout_window = timedelta(minutes=auth_lockout_minutes)
        self._fernet: Fernet | None = None
        if encryption_key:
            self._fernet = Fernet(_derive_fernet_key(encryption_key))
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.config_path.exists():
            self._write_default()
        self._user_records: Dict[str, Dict[str, Any]] = {}
        self._key_index: Dict[str, str] = {}
        self._key_secrets: Dict[str, str] = {}
        self._key_status: Dict[str, str] = {}
        self._raw_config: Dict[str, Any] = {}
        self._failed_attempts: Dict[str, Deque[datetime]] = {}
        self._last_load_time = 0.0
        self._principal_cache: Dict[str, Tuple[Principal, float]] = {}
        self._secret_key_cache: Dict[str, Tuple[str, float]] = {}
        self._cache_ttl = float(os.environ.get("IAM_CACHE_TTL_SECONDS", "5.0"))
        self._last_stat_check = 0.0
        self._stat_check_interval = float(os.environ.get("IAM_STAT_CHECK_INTERVAL_SECONDS", "2.0"))
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._session_lock = threading.Lock()
        self._load()
        self._load_lockout_state()

    def _maybe_reload(self) -> None:
        now = time.time()
        if now - self._last_stat_check < self._stat_check_interval:
            return
        self._last_stat_check = now
        try:
            if self.config_path.stat().st_mtime > self._last_load_time:
                self._load()
                self._principal_cache.clear()
                self._secret_key_cache.clear()
        except OSError:
            pass

    def _check_expiry(self, access_key: str, record: Dict[str, Any]) -> None:
        expires_at = record.get("expires_at")
        if not expires_at:
            return
        try:
            exp_dt = datetime.fromisoformat(expires_at)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) >= exp_dt:
                raise IamError(f"Credentials for '{access_key}' have expired")
        except (ValueError, TypeError):
            pass

    def authenticate(self, access_key: str, secret_key: str) -> Principal:
        self._maybe_reload()
        access_key = (access_key or "").strip()
        secret_key = (secret_key or "").strip()
        if not access_key or not secret_key:
            raise IamError("Missing access credentials")
        if self._is_locked_out(access_key):
            seconds = self._seconds_until_unlock(access_key)
            raise IamError(
                f"Access temporarily locked. Try again in {seconds} seconds."
            )
        user_id = self._key_index.get(access_key)
        stored_secret = self._key_secrets.get(access_key, secrets.token_urlsafe(24))
        if not user_id or not hmac.compare_digest(stored_secret, secret_key):
            self._record_failed_attempt(access_key)
            raise IamError("Invalid credentials")
        key_status = self._key_status.get(access_key, "active")
        if key_status != "active":
            raise IamError("Access key is inactive")
        record = self._user_records.get(user_id)
        if not record:
            self._record_failed_attempt(access_key)
            raise IamError("Invalid credentials")
        if not record.get("enabled", True):
            raise IamError("User account is disabled")
        self._check_expiry(access_key, record)
        self._clear_failed_attempts(access_key)
        return self._build_principal(access_key, record)

    _MAX_LOCKOUT_KEYS = 10000

    def _record_failed_attempt(self, access_key: str) -> None:
        if not access_key:
            return
        if access_key not in self._failed_attempts and len(self._failed_attempts) >= self._MAX_LOCKOUT_KEYS:
            oldest_key = min(self._failed_attempts, key=lambda k: self._failed_attempts[k][0] if self._failed_attempts[k] else datetime.min.replace(tzinfo=timezone.utc))
            del self._failed_attempts[oldest_key]
        attempts = self._failed_attempts.setdefault(access_key, deque())
        self._prune_attempts(attempts)
        attempts.append(datetime.now(timezone.utc))
        self._save_lockout_state()

    def _clear_failed_attempts(self, access_key: str) -> None:
        if not access_key:
            return
        if self._failed_attempts.pop(access_key, None) is not None:
            self._save_lockout_state()

    def _lockout_file(self) -> Path:
        return self.config_path.parent / "lockout_state.json"

    def _load_lockout_state(self) -> None:
        try:
            if self._lockout_file().exists():
                data = json.loads(self._lockout_file().read_text(encoding="utf-8"))
                cutoff = datetime.now(timezone.utc) - self.auth_lockout_window
                for key, timestamps in data.get("failed_attempts", {}).items():
                    valid = []
                    for ts in timestamps:
                        try:
                            dt = datetime.fromisoformat(ts)
                            if dt > cutoff:
                                valid.append(dt)
                        except (ValueError, TypeError):
                            continue
                    if valid:
                        self._failed_attempts[key] = deque(valid)
        except (OSError, json.JSONDecodeError):
            pass

    def _save_lockout_state(self) -> None:
        data: Dict[str, Any] = {"failed_attempts": {}}
        for key, attempts in self._failed_attempts.items():
            data["failed_attempts"][key] = [ts.isoformat() for ts in attempts]
        try:
            self._lockout_file().write_text(json.dumps(data), encoding="utf-8")
        except OSError:
            pass

    def _prune_attempts(self, attempts: Deque[datetime]) -> None:
        cutoff = datetime.now(timezone.utc) - self.auth_lockout_window
        while attempts and attempts[0] < cutoff:
            attempts.popleft()

    def _is_locked_out(self, access_key: str) -> bool:
        if not access_key:
            return False
        attempts = self._failed_attempts.get(access_key)
        if not attempts:
            return False
        self._prune_attempts(attempts)
        return len(attempts) >= self.auth_max_attempts

    def _seconds_until_unlock(self, access_key: str) -> int:
        attempts = self._failed_attempts.get(access_key)
        if not attempts:
            return 0
        self._prune_attempts(attempts)
        if len(attempts) < self.auth_max_attempts:
            return 0
        oldest = attempts[0]
        elapsed = (datetime.now(timezone.utc) - oldest).total_seconds()
        return int(max(0, self.auth_lockout_window.total_seconds() - elapsed))

    def create_session_token(self, access_key: str, duration_seconds: int = 3600) -> str:
        self._maybe_reload()
        user_id = self._key_index.get(access_key)
        if not user_id or user_id not in self._user_records:
            raise IamError("Unknown access key")
        self._cleanup_expired_sessions()
        token = secrets.token_urlsafe(32)
        expires_at = time.time() + duration_seconds
        self._sessions[token] = {
            "access_key": access_key,
            "expires_at": expires_at,
        }
        return token

    def validate_session_token(self, access_key: str, session_token: str) -> bool:
        dummy_key = secrets.token_urlsafe(16)
        dummy_token = secrets.token_urlsafe(32)
        with self._session_lock:
            session = self._sessions.get(session_token)
            if not session:
                hmac.compare_digest(access_key, dummy_key)
                hmac.compare_digest(session_token, dummy_token)
                return False
            key_match = hmac.compare_digest(session["access_key"], access_key)
            if not key_match:
                hmac.compare_digest(session_token, dummy_token)
                return False
            if time.time() > session["expires_at"]:
                self._sessions.pop(session_token, None)
                return False
            return True

    def _cleanup_expired_sessions(self) -> None:
        now = time.time()
        expired = [token for token, data in self._sessions.items() if now > data["expires_at"]]
        for token in expired:
            del self._sessions[token]

    def principal_for_key(self, access_key: str) -> Principal:
        now = time.time()
        cached = self._principal_cache.get(access_key)
        if cached:
            principal, cached_time = cached
            if now - cached_time < self._cache_ttl:
                user_id = self._key_index.get(access_key)
                if user_id:
                    record = self._user_records.get(user_id)
                    if record:
                        self._check_expiry(access_key, record)
                return principal

        self._maybe_reload()
        user_id = self._key_index.get(access_key)
        if not user_id:
            raise IamError("Unknown access key")
        record = self._user_records.get(user_id)
        if not record:
            raise IamError("Unknown access key")
        self._check_expiry(access_key, record)
        principal = self._build_principal(access_key, record)
        self._principal_cache[access_key] = (principal, now)
        return principal

    def secret_for_key(self, access_key: str) -> str:
        self._maybe_reload()
        secret = self._key_secrets.get(access_key)
        if not secret:
            raise IamError("Unknown access key")
        user_id = self._key_index.get(access_key)
        if user_id:
            record = self._user_records.get(user_id)
            if record:
                self._check_expiry(access_key, record)
        return secret

    def authorize(self, principal: Principal, bucket_name: str | None, action: str, *, object_key: str | None = None) -> None:
        action = self._normalize_action(action)
        if action not in ALLOWED_ACTIONS:
            raise IamError(f"Unknown action '{action}'")
        bucket_name = bucket_name or "*"
        normalized = bucket_name.lower() if bucket_name != "*" else bucket_name
        if not self._is_allowed(principal, normalized, action, object_key=object_key):
            raise IamError(f"Access denied for action '{action}' on bucket '{bucket_name}'")

    def check_permissions(self, principal: Principal, bucket_name: str | None, actions: Iterable[str], *, object_key: str | None = None) -> Dict[str, bool]:
        self._maybe_reload()
        bucket_name = (bucket_name or "*").lower() if bucket_name != "*" else (bucket_name or "*")
        normalized_actions = {a: self._normalize_action(a) for a in actions}
        results: Dict[str, bool] = {}
        for original, canonical in normalized_actions.items():
            if canonical not in ALLOWED_ACTIONS:
                results[original] = False
            else:
                results[original] = self._is_allowed(principal, bucket_name, canonical, object_key=object_key)
        return results

    def buckets_for_principal(self, principal: Principal, buckets: Iterable[str]) -> List[str]:
        return [bucket for bucket in buckets if self._is_allowed(principal, bucket, "list")]

    def _is_allowed(self, principal: Principal, bucket_name: str, action: str, *, object_key: str | None = None) -> bool:
        bucket_name = bucket_name.lower()
        for policy in principal.policies:
            if policy.bucket not in {"*", bucket_name}:
                continue
            action_match = "*" in policy.actions or action in policy.actions
            if not action_match and "iam:*" in policy.actions and action.startswith("iam:"):
                action_match = True
            if not action_match:
                continue
            if object_key is not None and policy.prefix != "*":
                prefix = policy.prefix.rstrip("*")
                if not object_key.startswith(prefix):
                    continue
            return True
        return False

    def list_users(self) -> List[Dict[str, Any]]:
        listing: List[Dict[str, Any]] = []
        for user_id, record in self._user_records.items():
            access_keys = []
            for key_info in record.get("access_keys", []):
                access_keys.append({
                    "access_key": key_info["access_key"],
                    "status": key_info.get("status", "active"),
                    "created_at": key_info.get("created_at"),
                })
            user_entry: Dict[str, Any] = {
                "user_id": user_id,
                "display_name": record["display_name"],
                "enabled": record.get("enabled", True),
                "expires_at": record.get("expires_at"),
                "access_keys": access_keys,
                "policies": [
                    {**{"bucket": policy.bucket, "actions": sorted(policy.actions)}, **({"prefix": policy.prefix} if policy.prefix != "*" else {})}
                    for policy in record["policies"]
                ],
            }
            if access_keys:
                user_entry["access_key"] = access_keys[0]["access_key"]
            listing.append(user_entry)
        return listing

    def create_user(
        self,
        *,
        display_name: str,
        policies: Optional[Sequence[Dict[str, Any]]] = None,
        access_key: str | None = None,
        secret_key: str | None = None,
        expires_at: str | None = None,
        user_id: str | None = None,
    ) -> Dict[str, str]:
        access_key = (access_key or self._generate_access_key()).strip()
        if not access_key:
            raise IamError("Access key cannot be empty")
        if access_key in self._key_index:
            raise IamError("Access key already exists")
        if expires_at:
            self._validate_expires_at(expires_at)
        secret_key = secret_key or self._generate_secret_key()
        sanitized_policies = self._prepare_policy_payload(policies)
        user_id = user_id or self._generate_user_id()
        if user_id in self._user_records:
            raise IamError("User ID already exists")
        now_iso = datetime.now(timezone.utc).isoformat()
        record: Dict[str, Any] = {
            "user_id": user_id,
            "display_name": display_name or access_key,
            "enabled": True,
            "access_keys": [
                {
                    "access_key": access_key,
                    "secret_key": secret_key,
                    "status": "active",
                    "created_at": now_iso,
                }
            ],
            "policies": sanitized_policies,
        }
        if expires_at:
            record["expires_at"] = expires_at
        self._raw_config.setdefault("users", []).append(record)
        self._save()
        self._load()
        return {"user_id": user_id, "access_key": access_key, "secret_key": secret_key}

    def create_access_key(self, identifier: str) -> Dict[str, str]:
        user_raw, _ = self._resolve_raw_user(identifier)
        new_access_key = self._generate_access_key()
        new_secret_key = self._generate_secret_key()
        now_iso = datetime.now(timezone.utc).isoformat()
        key_entry = {
            "access_key": new_access_key,
            "secret_key": new_secret_key,
            "status": "active",
            "created_at": now_iso,
        }
        user_raw.setdefault("access_keys", []).append(key_entry)
        self._save()
        self._load()
        return {"access_key": new_access_key, "secret_key": new_secret_key}

    def delete_access_key(self, access_key: str) -> None:
        user_raw, _ = self._resolve_raw_user(access_key)
        keys = user_raw.get("access_keys", [])
        if len(keys) <= 1:
            raise IamError("Cannot delete the only access key for a user")
        remaining = [k for k in keys if k["access_key"] != access_key]
        if len(remaining) == len(keys):
            raise IamError("Access key not found")
        user_raw["access_keys"] = remaining
        self._save()
        self._principal_cache.pop(access_key, None)
        self._secret_key_cache.pop(access_key, None)
        from .s3_api import clear_signing_key_cache
        clear_signing_key_cache()
        self._load()

    def disable_user(self, identifier: str) -> None:
        user_raw, _ = self._resolve_raw_user(identifier)
        user_raw["enabled"] = False
        self._save()
        for key_info in user_raw.get("access_keys", []):
            ak = key_info["access_key"]
            self._principal_cache.pop(ak, None)
            self._secret_key_cache.pop(ak, None)
        from .s3_api import clear_signing_key_cache
        clear_signing_key_cache()
        self._load()

    def enable_user(self, identifier: str) -> None:
        user_raw, _ = self._resolve_raw_user(identifier)
        user_raw["enabled"] = True
        self._save()
        self._load()

    def get_user_by_id(self, user_id: str) -> Dict[str, Any]:
        record = self._user_records.get(user_id)
        if not record:
            raise IamError("User not found")
        access_keys = []
        for key_info in record.get("access_keys", []):
            access_keys.append({
                "access_key": key_info["access_key"],
                "status": key_info.get("status", "active"),
                "created_at": key_info.get("created_at"),
            })
        return {
            "user_id": user_id,
            "display_name": record["display_name"],
            "enabled": record.get("enabled", True),
            "expires_at": record.get("expires_at"),
            "access_keys": access_keys,
            "policies": [
                {"bucket": p.bucket, "actions": sorted(p.actions), "prefix": p.prefix}
                for p in record["policies"]
            ],
        }

    def get_user_policies(self, identifier: str) -> List[Dict[str, Any]]:
        _, user_id = self._resolve_raw_user(identifier)
        record = self._user_records.get(user_id)
        if not record:
            raise IamError("User not found")
        return [
            {**{"bucket": p.bucket, "actions": sorted(p.actions)}, **({"prefix": p.prefix} if p.prefix != "*" else {})}
            for p in record["policies"]
        ]

    def resolve_user_id(self, identifier: str) -> str:
        if identifier in self._user_records:
            return identifier
        user_id = self._key_index.get(identifier)
        if user_id:
            return user_id
        raise IamError("User not found")

    def rotate_secret(self, access_key: str) -> str:
        user_raw, _ = self._resolve_raw_user(access_key)
        new_secret = self._generate_secret_key()
        for key_info in user_raw.get("access_keys", []):
            if key_info["access_key"] == access_key:
                key_info["secret_key"] = new_secret
                break
        else:
            raise IamError("Access key not found")
        self._save()
        self._principal_cache.pop(access_key, None)
        self._secret_key_cache.pop(access_key, None)
        from .s3_api import clear_signing_key_cache
        clear_signing_key_cache()
        self._load()
        return new_secret

    def update_user(self, access_key: str, display_name: str) -> None:
        user_raw, _ = self._resolve_raw_user(access_key)
        user_raw["display_name"] = display_name
        self._save()
        self._load()

    def delete_user(self, access_key: str) -> None:
        users = self._raw_config.get("users", [])
        if len(users) <= 1:
            raise IamError("Cannot delete the only user")
        _, target_user_id = self._resolve_raw_user(access_key)
        target_user_raw = None
        remaining = []
        for u in users:
            if u.get("user_id") == target_user_id:
                target_user_raw = u
            else:
                remaining.append(u)
        if target_user_raw is None:
            raise IamError("User not found")
        self._raw_config["users"] = remaining
        self._save()
        for key_info in target_user_raw.get("access_keys", []):
            ak = key_info["access_key"]
            self._principal_cache.pop(ak, None)
            self._secret_key_cache.pop(ak, None)
        from .s3_api import clear_signing_key_cache
        clear_signing_key_cache()
        self._load()

    def update_user_expiry(self, access_key: str, expires_at: str | None) -> None:
        user_raw, _ = self._resolve_raw_user(access_key)
        if expires_at:
            self._validate_expires_at(expires_at)
            user_raw["expires_at"] = expires_at
        else:
            user_raw.pop("expires_at", None)
        self._save()
        for key_info in user_raw.get("access_keys", []):
            ak = key_info["access_key"]
            self._principal_cache.pop(ak, None)
            self._secret_key_cache.pop(ak, None)
        self._load()

    def update_user_policies(self, access_key: str, policies: Sequence[Dict[str, Any]]) -> None:
        user_raw, _ = self._resolve_raw_user(access_key)
        user_raw["policies"] = self._prepare_policy_payload(policies)
        self._save()
        self._load()

    def _decrypt_content(self, raw_bytes: bytes) -> str:
        if raw_bytes.startswith(_IAM_ENCRYPTED_PREFIX):
            if not self._fernet:
                raise IamError("IAM config is encrypted but no encryption key provided. Set SECRET_KEY or use 'python run.py reset-cred'.")
            try:
                encrypted_data = raw_bytes[len(_IAM_ENCRYPTED_PREFIX):]
                return self._fernet.decrypt(encrypted_data).decode("utf-8")
            except InvalidToken:
                raise IamError("Cannot decrypt IAM config. SECRET_KEY may have changed. Use 'python run.py reset-cred' to reset credentials.")
        return raw_bytes.decode("utf-8")

    def _is_v2_config(self, raw: Dict[str, Any]) -> bool:
        return raw.get("version", 1) >= _CONFIG_VERSION

    def _migrate_v1_to_v2(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        migrated_users = []
        now_iso = datetime.now(timezone.utc).isoformat()
        for user in raw.get("users", []):
            old_policies = user.get("policies", [])
            expanded_policies = []
            for p in old_policies:
                raw_actions = p.get("actions", [])
                if isinstance(raw_actions, str):
                    raw_actions = [raw_actions]
                action_set: Set[str] = set()
                for a in raw_actions:
                    canonical = self._normalize_action(a)
                    if canonical == "*":
                        action_set = set(ALLOWED_ACTIONS)
                        break
                    if canonical:
                        action_set.add(canonical)
                action_set = _expand_v1_actions(action_set)
                expanded_policies.append({
                    "bucket": p.get("bucket", "*"),
                    "actions": sorted(action_set),
                    "prefix": p.get("prefix", "*"),
                })
            migrated_user: Dict[str, Any] = {
                "user_id": user["access_key"],
                "display_name": user.get("display_name", user["access_key"]),
                "enabled": True,
                "access_keys": [
                    {
                        "access_key": user["access_key"],
                        "secret_key": user["secret_key"],
                        "status": "active",
                        "created_at": now_iso,
                    }
                ],
                "policies": expanded_policies,
            }
            if user.get("expires_at"):
                migrated_user["expires_at"] = user["expires_at"]
            migrated_users.append(migrated_user)
        return {"version": _CONFIG_VERSION, "users": migrated_users}

    def _load(self) -> None:
        try:
            self._last_load_time = self.config_path.stat().st_mtime
            raw_bytes = self.config_path.read_bytes()
            content = self._decrypt_content(raw_bytes)
            raw = json.loads(content)
        except IamError:
            raise
        except FileNotFoundError:
            raise IamError(f"IAM config not found: {self.config_path}")
        except json.JSONDecodeError as e:
            raise IamError(f"Corrupted IAM config (invalid JSON): {e}")
        except PermissionError as e:
            raise IamError(f"Cannot read IAM config (permission denied): {e}")
        except (OSError, ValueError) as e:
            raise IamError(f"Failed to load IAM config: {e}")

        was_plaintext = not raw_bytes.startswith(_IAM_ENCRYPTED_PREFIX)
        was_v1 = not self._is_v2_config(raw)

        if was_v1:
            raw = self._migrate_v1_to_v2(raw)

        user_records: Dict[str, Dict[str, Any]] = {}
        key_index: Dict[str, str] = {}
        key_secrets: Dict[str, str] = {}
        key_status_map: Dict[str, str] = {}

        for user in raw.get("users", []):
            user_id = user["user_id"]
            policies = self._build_policy_objects(user.get("policies", []))
            access_keys_raw = user.get("access_keys", [])
            access_keys_info = []
            for key_entry in access_keys_raw:
                ak = key_entry["access_key"]
                sk = key_entry["secret_key"]
                status = key_entry.get("status", "active")
                key_index[ak] = user_id
                key_secrets[ak] = sk
                key_status_map[ak] = status
                access_keys_info.append({
                    "access_key": ak,
                    "secret_key": sk,
                    "status": status,
                    "created_at": key_entry.get("created_at"),
                })
            record: Dict[str, Any] = {
                "display_name": user.get("display_name", user_id),
                "enabled": user.get("enabled", True),
                "policies": policies,
                "access_keys": access_keys_info,
            }
            if user.get("expires_at"):
                record["expires_at"] = user["expires_at"]
            user_records[user_id] = record

        if not user_records:
            raise IamError("IAM configuration contains no users")

        self._user_records = user_records
        self._key_index = key_index
        self._key_secrets = key_secrets
        self._key_status = key_status_map

        raw_users: List[Dict[str, Any]] = []
        for user in raw.get("users", []):
            raw_entry: Dict[str, Any] = {
                "user_id": user["user_id"],
                "display_name": user.get("display_name", user["user_id"]),
                "enabled": user.get("enabled", True),
                "access_keys": user.get("access_keys", []),
                "policies": user.get("policies", []),
            }
            if user.get("expires_at"):
                raw_entry["expires_at"] = user["expires_at"]
            raw_users.append(raw_entry)
        self._raw_config = {"version": _CONFIG_VERSION, "users": raw_users}

        if was_v1 or (was_plaintext and self._fernet):
            self._save()

    def _save(self) -> None:
        try:
            json_text = json.dumps(self._raw_config, indent=2)
            temp_path = self.config_path.with_suffix('.json.tmp')
            if self._fernet:
                encrypted = self._fernet.encrypt(json_text.encode("utf-8"))
                temp_path.write_bytes(_IAM_ENCRYPTED_PREFIX + encrypted)
            else:
                temp_path.write_text(json_text, encoding='utf-8')
            temp_path.replace(self.config_path)
        except (OSError, PermissionError) as e:
            raise IamError(f"Cannot save IAM config: {e}")

    def config_summary(self) -> Dict[str, Any]:
        return {
            "path": str(self.config_path),
            "user_count": len(self._user_records),
            "allowed_actions": sorted(ALLOWED_ACTIONS),
        }

    def export_config(self, mask_secrets: bool = True) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"version": _CONFIG_VERSION, "users": []}
        for user in self._raw_config.get("users", []):
            access_keys = []
            for key_info in user.get("access_keys", []):
                access_keys.append({
                    "access_key": key_info["access_key"],
                    "secret_key": "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022" if mask_secrets else key_info["secret_key"],
                    "status": key_info.get("status", "active"),
                    "created_at": key_info.get("created_at"),
                })
            record: Dict[str, Any] = {
                "user_id": user["user_id"],
                "display_name": user["display_name"],
                "enabled": user.get("enabled", True),
                "access_keys": access_keys,
                "policies": user["policies"],
            }
            if access_keys:
                record["access_key"] = access_keys[0]["access_key"]
            if user.get("expires_at"):
                record["expires_at"] = user["expires_at"]
            payload["users"].append(record)
        return payload

    def _build_policy_objects(self, policies: Sequence[Dict[str, Any]]) -> List[Policy]:
        entries: List[Policy] = []
        for policy in policies:
            bucket = str(policy.get("bucket", "*")).lower()
            prefix = str(policy.get("prefix", "*"))
            raw_actions = policy.get("actions", [])
            if isinstance(raw_actions, str):
                raw_actions = [raw_actions]
            action_set: Set[str] = set()
            for action in raw_actions:
                canonical = self._normalize_action(action)
                if canonical == "*":
                    action_set = set(ALLOWED_ACTIONS)
                    break
                if canonical:
                    action_set.add(canonical)
            if action_set:
                entries.append(Policy(bucket=bucket, actions=action_set, prefix=prefix))
        return entries

    def _prepare_policy_payload(self, policies: Optional[Sequence[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        if not policies:
            policies = (
                {
                    "bucket": "*",
                    "actions": ["list", "read", "write", "delete", "share", "policy",
                                "create_bucket", "delete_bucket"],
                },
            )
        sanitized: List[Dict[str, Any]] = []
        for policy in policies:
            bucket = str(policy.get("bucket", "*")).lower()
            prefix = str(policy.get("prefix", "*"))
            raw_actions = policy.get("actions", [])
            if isinstance(raw_actions, str):
                raw_actions = [raw_actions]
            action_set: Set[str] = set()
            for action in raw_actions:
                canonical = self._normalize_action(action)
                if canonical == "*":
                    action_set = set(ALLOWED_ACTIONS)
                    break
                if canonical:
                    action_set.add(canonical)
            if not action_set:
                continue
            entry: Dict[str, Any] = {"bucket": bucket, "actions": sorted(action_set)}
            if prefix != "*":
                entry["prefix"] = prefix
            sanitized.append(entry)
        if not sanitized:
            raise IamError("At least one policy with valid actions is required")
        return sanitized

    def _build_principal(self, access_key: str, record: Dict[str, Any]) -> Principal:
        return Principal(
            access_key=access_key,
            display_name=record["display_name"],
            policies=record["policies"],
        )

    def _normalize_action(self, action: str) -> str:
        if not action:
            return ""
        lowered = action.strip().lower()
        if lowered == "*":
            return "*"
        candidate = ACTION_ALIASES.get(lowered, lowered)
        return candidate if candidate in ALLOWED_ACTIONS else ""

    def _write_default(self) -> None:
        access_key = os.environ.get("ADMIN_ACCESS_KEY", "").strip() or secrets.token_hex(12)
        secret_key = os.environ.get("ADMIN_SECRET_KEY", "").strip() or secrets.token_urlsafe(32)
        custom_keys = bool(os.environ.get("ADMIN_ACCESS_KEY", "").strip())
        user_id = self._generate_user_id()
        now_iso = datetime.now(timezone.utc).isoformat()
        default = {
            "version": _CONFIG_VERSION,
            "users": [
                {
                    "user_id": user_id,
                    "display_name": "Local Admin",
                    "enabled": True,
                    "access_keys": [
                        {
                            "access_key": access_key,
                            "secret_key": secret_key,
                            "status": "active",
                            "created_at": now_iso,
                        }
                    ],
                    "policies": [
                        {"bucket": "*", "actions": list(ALLOWED_ACTIONS)}
                    ],
                }
            ]
        }
        json_text = json.dumps(default, indent=2)
        if self._fernet:
            encrypted = self._fernet.encrypt(json_text.encode("utf-8"))
            self.config_path.write_bytes(_IAM_ENCRYPTED_PREFIX + encrypted)
        else:
            self.config_path.write_text(json_text)
        print(f"\n{'='*60}")
        print("MYFSIO FIRST RUN - ADMIN CREDENTIALS")
        print(f"{'='*60}")
        if custom_keys:
            print(f"Access Key: {access_key} (from ADMIN_ACCESS_KEY)")
            print(f"Secret Key: {'(from ADMIN_SECRET_KEY)' if os.environ.get('ADMIN_SECRET_KEY', '').strip() else secret_key}")
        else:
            print(f"Access Key: {access_key}")
            print(f"Secret Key: {secret_key}")
        print(f"User ID:    {user_id}")
        print(f"{'='*60}")
        if self._fernet:
            print("IAM config is encrypted at rest.")
            print("Lost credentials? Run: python run.py reset-cred")
        else:
            print(f"Missed this? Check: {self.config_path}")
        print(f"{'='*60}\n")

    def _validate_expires_at(self, expires_at: str) -> None:
        try:
            dt = datetime.fromisoformat(expires_at)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            raise IamError(f"Invalid expires_at format: {expires_at}. Use ISO 8601 (e.g. 2026-12-31T23:59:59Z)")

    def _generate_access_key(self) -> str:
        return secrets.token_hex(8)

    def _generate_secret_key(self) -> str:
        return secrets.token_urlsafe(24)

    def _generate_user_id(self) -> str:
        return f"u-{secrets.token_hex(8)}"

    def _resolve_raw_user(self, identifier: str) -> Tuple[Dict[str, Any], str]:
        for user in self._raw_config.get("users", []):
            if user.get("user_id") == identifier:
                return user, identifier
        for user in self._raw_config.get("users", []):
            for key_info in user.get("access_keys", []):
                if key_info["access_key"] == identifier:
                    return user, user["user_id"]
        raise IamError("User not found")

    def _get_raw_user(self, access_key: str) -> Dict[str, Any]:
        user, _ = self._resolve_raw_user(access_key)
        return user

    def get_secret_key(self, access_key: str) -> str | None:
        now = time.time()
        cached = self._secret_key_cache.get(access_key)
        if cached:
            secret_key, cached_time = cached
            if now - cached_time < self._cache_ttl:
                user_id = self._key_index.get(access_key)
                if user_id:
                    record = self._user_records.get(user_id)
                    if record:
                        self._check_expiry(access_key, record)
                return secret_key

        self._maybe_reload()
        secret = self._key_secrets.get(access_key)
        if secret:
            user_id = self._key_index.get(access_key)
            if user_id:
                record = self._user_records.get(user_id)
                if record:
                    self._check_expiry(access_key, record)
            self._secret_key_cache[access_key] = (secret, now)
            return secret
        return None

    def get_principal(self, access_key: str) -> Principal | None:
        now = time.time()
        cached = self._principal_cache.get(access_key)
        if cached:
            principal, cached_time = cached
            if now - cached_time < self._cache_ttl:
                user_id = self._key_index.get(access_key)
                if user_id:
                    record = self._user_records.get(user_id)
                    if record:
                        self._check_expiry(access_key, record)
                return principal

        self._maybe_reload()
        user_id = self._key_index.get(access_key)
        if user_id:
            record = self._user_records.get(user_id)
            if record:
                self._check_expiry(access_key, record)
                principal = self._build_principal(access_key, record)
                self._principal_cache[access_key] = (principal, now)
                return principal
        return None
