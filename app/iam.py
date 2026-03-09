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
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from cryptography.fernet import Fernet, InvalidToken


class IamError(RuntimeError):
    """Raised when authentication or authorization fails."""


S3_ACTIONS = {"list", "read", "write", "delete", "share", "policy", "replication", "lifecycle", "cors"}
IAM_ACTIONS = {
    "iam:list_users",
    "iam:create_user",
    "iam:delete_user",
    "iam:rotate_key",
    "iam:update_policy",
}
ALLOWED_ACTIONS = (S3_ACTIONS | IAM_ACTIONS) | {"iam:*"}

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
    "s3:getbucketversioning": "read",
    "s3:headobject": "read",
    "s3:headbucket": "read",
    "write": "write",
    "s3:putobject": "write",
    "s3:createbucket": "write",
    "s3:putobjecttagging": "write",
    "s3:putbucketversioning": "write",
    "s3:createmultipartupload": "write",
    "s3:uploadpart": "write",
    "s3:completemultipartupload": "write",
    "s3:abortmultipartupload": "write",
    "s3:copyobject": "write",
    "delete": "delete",
    "s3:deleteobject": "delete",
    "s3:deleteobjectversion": "delete",
    "s3:deletebucket": "delete",
    "s3:deleteobjecttagging": "delete",
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
    "iam:listusers": "iam:list_users",
    "iam:createuser": "iam:create_user",
    "iam:deleteuser": "iam:delete_user",
    "iam:rotateaccesskey": "iam:rotate_key",
    "iam:putuserpolicy": "iam:update_policy",
    "iam:*": "iam:*",
}


@dataclass
class Policy:
    bucket: str
    actions: Set[str]


@dataclass
class Principal:
    access_key: str
    display_name: str
    policies: List[Policy]


def _derive_fernet_key(secret: str) -> bytes:
    raw = hashlib.pbkdf2_hmac("sha256", secret.encode(), b"myfsio-iam-encryption", 100_000)
    return base64.urlsafe_b64encode(raw)


_IAM_ENCRYPTED_PREFIX = b"MYFSIO_IAM_ENC:"


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
        self._users: Dict[str, Dict[str, Any]] = {}
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
        """Reload configuration if the file has changed on disk."""
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
        record = self._users.get(access_key)
        stored_secret = record["secret_key"] if record else secrets.token_urlsafe(24)
        if not record or not hmac.compare_digest(stored_secret, secret_key):
            self._record_failed_attempt(access_key)
            raise IamError("Invalid credentials")
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
        """Load lockout state from disk."""
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
        """Persist lockout state to disk."""
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
        """Create a temporary session token for an access key."""
        self._maybe_reload()
        record = self._users.get(access_key)
        if not record:
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
        """Validate a session token for an access key (thread-safe, constant-time)."""
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
        """Remove expired session tokens."""
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
                record = self._users.get(access_key)
                if record:
                    self._check_expiry(access_key, record)
                return principal

        self._maybe_reload()
        record = self._users.get(access_key)
        if not record:
            raise IamError("Unknown access key")
        self._check_expiry(access_key, record)
        principal = self._build_principal(access_key, record)
        self._principal_cache[access_key] = (principal, now)
        return principal

    def secret_for_key(self, access_key: str) -> str:
        self._maybe_reload()
        record = self._users.get(access_key)
        if not record:
            raise IamError("Unknown access key")
        self._check_expiry(access_key, record)
        return record["secret_key"]

    def authorize(self, principal: Principal, bucket_name: str | None, action: str) -> None:
        action = self._normalize_action(action)
        if action not in ALLOWED_ACTIONS:
            raise IamError(f"Unknown action '{action}'")
        bucket_name = bucket_name or "*"
        normalized = bucket_name.lower() if bucket_name != "*" else bucket_name
        if not self._is_allowed(principal, normalized, action):
            raise IamError(f"Access denied for action '{action}' on bucket '{bucket_name}'")

    def check_permissions(self, principal: Principal, bucket_name: str | None, actions: Iterable[str]) -> Dict[str, bool]:
        self._maybe_reload()
        bucket_name = (bucket_name or "*").lower() if bucket_name != "*" else (bucket_name or "*")
        normalized_actions = {a: self._normalize_action(a) for a in actions}
        results: Dict[str, bool] = {}
        for original, canonical in normalized_actions.items():
            if canonical not in ALLOWED_ACTIONS:
                results[original] = False
            else:
                results[original] = self._is_allowed(principal, bucket_name, canonical)
        return results

    def buckets_for_principal(self, principal: Principal, buckets: Iterable[str]) -> List[str]:
        return [bucket for bucket in buckets if self._is_allowed(principal, bucket, "list")]

    def _is_allowed(self, principal: Principal, bucket_name: str, action: str) -> bool:
        bucket_name = bucket_name.lower()
        for policy in principal.policies:
            if policy.bucket not in {"*", bucket_name}:
                continue
            if "*" in policy.actions or action in policy.actions:
                return True
            if "iam:*" in policy.actions and action.startswith("iam:"):
                return True
        return False

    def list_users(self) -> List[Dict[str, Any]]:
        listing: List[Dict[str, Any]] = []
        for access_key, record in self._users.items():
            listing.append(
                {
                    "access_key": access_key,
                    "display_name": record["display_name"],
                    "expires_at": record.get("expires_at"),
                    "policies": [
                        {"bucket": policy.bucket, "actions": sorted(policy.actions)}
                        for policy in record["policies"]
                    ],
                }
            )
        return listing

    def create_user(
        self,
        *,
        display_name: str,
        policies: Optional[Sequence[Dict[str, Any]]] = None,
        access_key: str | None = None,
        secret_key: str | None = None,
        expires_at: str | None = None,
    ) -> Dict[str, str]:
        access_key = (access_key or self._generate_access_key()).strip()
        if not access_key:
            raise IamError("Access key cannot be empty")
        if access_key in self._users:
            raise IamError("Access key already exists")
        if expires_at:
            self._validate_expires_at(expires_at)
        secret_key = secret_key or self._generate_secret_key()
        sanitized_policies = self._prepare_policy_payload(policies)
        record: Dict[str, Any] = {
            "access_key": access_key,
            "secret_key": secret_key,
            "display_name": display_name or access_key,
            "policies": sanitized_policies,
        }
        if expires_at:
            record["expires_at"] = expires_at
        self._raw_config.setdefault("users", []).append(record)
        self._save()
        self._load()
        return {"access_key": access_key, "secret_key": secret_key}

    def rotate_secret(self, access_key: str) -> str:
        user = self._get_raw_user(access_key)
        new_secret = self._generate_secret_key()
        user["secret_key"] = new_secret
        self._save()
        self._principal_cache.pop(access_key, None)
        self._secret_key_cache.pop(access_key, None)
        from .s3_api import clear_signing_key_cache
        clear_signing_key_cache()
        self._load()
        return new_secret

    def update_user(self, access_key: str, display_name: str) -> None:
        user = self._get_raw_user(access_key)
        user["display_name"] = display_name
        self._save()
        self._load()

    def delete_user(self, access_key: str) -> None:
        users = self._raw_config.get("users", [])
        if len(users) <= 1:
            raise IamError("Cannot delete the only user")
        remaining = [user for user in users if user["access_key"] != access_key]
        if len(remaining) == len(users):
            raise IamError("User not found")
        self._raw_config["users"] = remaining
        self._save()
        self._principal_cache.pop(access_key, None)
        self._secret_key_cache.pop(access_key, None)
        from .s3_api import clear_signing_key_cache
        clear_signing_key_cache()
        self._load()

    def update_user_expiry(self, access_key: str, expires_at: str | None) -> None:
        user = self._get_raw_user(access_key)
        if expires_at:
            self._validate_expires_at(expires_at)
            user["expires_at"] = expires_at
        else:
            user.pop("expires_at", None)
        self._save()
        self._principal_cache.pop(access_key, None)
        self._secret_key_cache.pop(access_key, None)
        self._load()

    def update_user_policies(self, access_key: str, policies: Sequence[Dict[str, Any]]) -> None:
        user = self._get_raw_user(access_key)
        user["policies"] = self._prepare_policy_payload(policies)
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

        users: Dict[str, Dict[str, Any]] = {}
        for user in raw.get("users", []):
            policies = self._build_policy_objects(user.get("policies", []))
            user_record: Dict[str, Any] = {
                "secret_key": user["secret_key"],
                "display_name": user.get("display_name", user["access_key"]),
                "policies": policies,
            }
            if user.get("expires_at"):
                user_record["expires_at"] = user["expires_at"]
            users[user["access_key"]] = user_record
        if not users:
            raise IamError("IAM configuration contains no users")
        self._users = users
        raw_users: List[Dict[str, Any]] = []
        for entry in raw.get("users", []):
            raw_entry: Dict[str, Any] = {
                "access_key": entry["access_key"],
                "secret_key": entry["secret_key"],
                "display_name": entry.get("display_name", entry["access_key"]),
                "policies": entry.get("policies", []),
            }
            if entry.get("expires_at"):
                raw_entry["expires_at"] = entry["expires_at"]
            raw_users.append(raw_entry)
        self._raw_config = {"users": raw_users}

        if was_plaintext and self._fernet:
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
            "user_count": len(self._users),
            "allowed_actions": sorted(ALLOWED_ACTIONS),
        }

    def export_config(self, mask_secrets: bool = True) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"users": []}
        for user in self._raw_config.get("users", []):
            record: Dict[str, Any] = {
                "access_key": user["access_key"],
                "secret_key": "••••••••••" if mask_secrets else user["secret_key"],
                "display_name": user["display_name"],
                "policies": user["policies"],
            }
            if user.get("expires_at"):
                record["expires_at"] = user["expires_at"]
            payload["users"].append(record)
        return payload

    def _build_policy_objects(self, policies: Sequence[Dict[str, Any]]) -> List[Policy]:
        entries: List[Policy] = []
        for policy in policies:
            bucket = str(policy.get("bucket", "*")).lower()
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
                entries.append(Policy(bucket=bucket, actions=action_set))
        return entries

    def _prepare_policy_payload(self, policies: Optional[Sequence[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        if not policies:
            policies = (
                {
                    "bucket": "*",
                    "actions": ["list", "read", "write", "delete", "share", "policy"],
                },
            )
        sanitized: List[Dict[str, Any]] = []
        for policy in policies:
            bucket = str(policy.get("bucket", "*")).lower()
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
            sanitized.append({"bucket": bucket, "actions": sorted(action_set)})
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
        default = {
            "users": [
                {
                    "access_key": access_key,
                    "secret_key": secret_key,
                    "display_name": "Local Admin",
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

    def _get_raw_user(self, access_key: str) -> Dict[str, Any]:
        for user in self._raw_config.get("users", []):
            if user["access_key"] == access_key:
                return user
        raise IamError("User not found")

    def get_secret_key(self, access_key: str) -> str | None:
        now = time.time()
        cached = self._secret_key_cache.get(access_key)
        if cached:
            secret_key, cached_time = cached
            if now - cached_time < self._cache_ttl:
                record = self._users.get(access_key)
                if record:
                    self._check_expiry(access_key, record)
                return secret_key

        self._maybe_reload()
        record = self._users.get(access_key)
        if record:
            self._check_expiry(access_key, record)
            secret_key = record["secret_key"]
            self._secret_key_cache[access_key] = (secret_key, now)
            return secret_key
        return None

    def get_principal(self, access_key: str) -> Principal | None:
        now = time.time()
        cached = self._principal_cache.get(access_key)
        if cached:
            principal, cached_time = cached
            if now - cached_time < self._cache_ttl:
                record = self._users.get(access_key)
                if record:
                    self._check_expiry(access_key, record)
                return principal

        self._maybe_reload()
        record = self._users.get(access_key)
        if record:
            self._check_expiry(access_key, record)
            principal = self._build_principal(access_key, record)
            self._principal_cache[access_key] = (principal, now)
            return principal
        return None
