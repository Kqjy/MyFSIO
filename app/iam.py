"""Lightweight IAM-style user and policy management."""
from __future__ import annotations

import json
import math
import secrets
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Optional, Sequence, Set


class IamError(RuntimeError):
    """Raised when authentication or authorization fails."""


S3_ACTIONS = {"list", "read", "write", "delete", "share", "policy", "replication"}
IAM_ACTIONS = {
    "iam:list_users",
    "iam:create_user",
    "iam:delete_user",
    "iam:rotate_key",
    "iam:update_policy",
}
ALLOWED_ACTIONS = (S3_ACTIONS | IAM_ACTIONS) | {"iam:*"}

ACTION_ALIASES = {
    # List actions
    "list": "list",
    "s3:listbucket": "list",
    "s3:listallmybuckets": "list",
    "s3:listbucketversions": "list",
    "s3:listmultipartuploads": "list",
    "s3:listparts": "list",
    # Read actions
    "read": "read",
    "s3:getobject": "read",
    "s3:getobjectversion": "read",
    "s3:getobjecttagging": "read",
    "s3:getobjectversiontagging": "read",
    "s3:getobjectacl": "read",
    "s3:getbucketversioning": "read",
    "s3:headobject": "read",
    "s3:headbucket": "read",
    # Write actions
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
    # Delete actions
    "delete": "delete",
    "s3:deleteobject": "delete",
    "s3:deleteobjectversion": "delete",
    "s3:deletebucket": "delete",
    "s3:deleteobjecttagging": "delete",
    # Share actions (ACL)
    "share": "share",
    "s3:putobjectacl": "share",
    "s3:putbucketacl": "share",
    "s3:getbucketacl": "share",
    # Policy actions
    "policy": "policy",
    "s3:putbucketpolicy": "policy",
    "s3:getbucketpolicy": "policy",
    "s3:deletebucketpolicy": "policy",
    # Replication actions
    "replication": "replication",
    "s3:getreplicationconfiguration": "replication",
    "s3:putreplicationconfiguration": "replication",
    "s3:deletereplicationconfiguration": "replication",
    "s3:replicateobject": "replication",
    "s3:replicatetags": "replication",
    "s3:replicatedelete": "replication",
    # IAM actions
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


class IamService:
    """Loads IAM configuration, manages users, and evaluates policies."""

    def __init__(self, config_path: Path, auth_max_attempts: int = 5, auth_lockout_minutes: int = 15) -> None:
        self.config_path = Path(config_path)
        self.auth_max_attempts = auth_max_attempts
        self.auth_lockout_window = timedelta(minutes=auth_lockout_minutes)
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.config_path.exists():
            self._write_default()
        self._users: Dict[str, Dict[str, Any]] = {}
        self._raw_config: Dict[str, Any] = {}
        self._failed_attempts: Dict[str, Deque[datetime]] = {}
        self._last_load_time = 0.0
        self._load()

    def _maybe_reload(self) -> None:
        """Reload configuration if the file has changed on disk."""
        try:
            if self.config_path.stat().st_mtime > self._last_load_time:
                self._load()
        except OSError:
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
        if not record or record["secret_key"] != secret_key:
            self._record_failed_attempt(access_key)
            raise IamError("Invalid credentials")
        self._clear_failed_attempts(access_key)
        return self._build_principal(access_key, record)

    def _record_failed_attempt(self, access_key: str) -> None:
        if not access_key:
            return
        attempts = self._failed_attempts.setdefault(access_key, deque())
        self._prune_attempts(attempts)
        attempts.append(datetime.now(timezone.utc))

    def _clear_failed_attempts(self, access_key: str) -> None:
        if not access_key:
            return
        self._failed_attempts.pop(access_key, None)

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

    def principal_for_key(self, access_key: str) -> Principal:
        self._maybe_reload()
        record = self._users.get(access_key)
        if not record:
            raise IamError("Unknown access key")
        return self._build_principal(access_key, record)

    def secret_for_key(self, access_key: str) -> str:
        self._maybe_reload()
        record = self._users.get(access_key)
        if not record:
            raise IamError("Unknown access key")
        return record["secret_key"]

    def authorize(self, principal: Principal, bucket_name: str | None, action: str) -> None:
        action = self._normalize_action(action)
        if action not in ALLOWED_ACTIONS:
            raise IamError(f"Unknown action '{action}'")
        bucket_name = bucket_name or "*"
        normalized = bucket_name.lower() if bucket_name != "*" else bucket_name
        if not self._is_allowed(principal, normalized, action):
            raise IamError(f"Access denied for action '{action}' on bucket '{bucket_name}'")

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
    ) -> Dict[str, str]:
        access_key = (access_key or self._generate_access_key()).strip()
        if not access_key:
            raise IamError("Access key cannot be empty")
        if access_key in self._users:
            raise IamError("Access key already exists")
        secret_key = secret_key or self._generate_secret_key()
        sanitized_policies = self._prepare_policy_payload(policies)
        record = {
            "access_key": access_key,
            "secret_key": secret_key,
            "display_name": display_name or access_key,
            "policies": sanitized_policies,
        }
        self._raw_config.setdefault("users", []).append(record)
        self._save()
        self._load()
        return {"access_key": access_key, "secret_key": secret_key}

    def rotate_secret(self, access_key: str) -> str:
        user = self._get_raw_user(access_key)
        new_secret = self._generate_secret_key()
        user["secret_key"] = new_secret
        self._save()
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
        self._load()

    def update_user_policies(self, access_key: str, policies: Sequence[Dict[str, Any]]) -> None:
        user = self._get_raw_user(access_key)
        user["policies"] = self._prepare_policy_payload(policies)
        self._save()
        self._load()

    def _load(self) -> None:
        try:
            self._last_load_time = self.config_path.stat().st_mtime
            content = self.config_path.read_text(encoding='utf-8')
            raw = json.loads(content)
        except FileNotFoundError:
            raise IamError(f"IAM config not found: {self.config_path}")
        except json.JSONDecodeError as e:
            raise IamError(f"Corrupted IAM config (invalid JSON): {e}")
        except PermissionError as e:
            raise IamError(f"Cannot read IAM config (permission denied): {e}")
        except (OSError, ValueError) as e:
            raise IamError(f"Failed to load IAM config: {e}")
        
        users: Dict[str, Dict[str, Any]] = {}
        for user in raw.get("users", []):
            policies = self._build_policy_objects(user.get("policies", []))
            users[user["access_key"]] = {
                "secret_key": user["secret_key"],
                "display_name": user.get("display_name", user["access_key"]),
                "policies": policies,
            }
        if not users:
            raise IamError("IAM configuration contains no users")
        self._users = users
        self._raw_config = {
            "users": [
                {
                    "access_key": entry["access_key"],
                    "secret_key": entry["secret_key"],
                    "display_name": entry.get("display_name", entry["access_key"]),
                    "policies": entry.get("policies", []),
                }
                for entry in raw.get("users", [])
            ]
        }

    def _save(self) -> None:
        try:
            temp_path = self.config_path.with_suffix('.json.tmp')
            temp_path.write_text(json.dumps(self._raw_config, indent=2), encoding='utf-8')
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
            record = dict(user)
            if mask_secrets and "secret_key" in record:
                record["secret_key"] = "••••••••••"
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
        default = {
            "users": [
                {
                    "access_key": "localadmin",
                    "secret_key": "localadmin",
                    "display_name": "Local Admin",
                    "policies": [
                        {"bucket": "*", "actions": list(ALLOWED_ACTIONS)}
                    ],
                }
            ]
        }
        self.config_path.write_text(json.dumps(default, indent=2))

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
        self._maybe_reload()
        record = self._users.get(access_key)
        return record["secret_key"] if record else None

    def get_principal(self, access_key: str) -> Principal | None:
        self._maybe_reload()
        record = self._users.get(access_key)
        return self._build_principal(access_key, record) if record else None
