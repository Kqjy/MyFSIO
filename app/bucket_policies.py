"""Bucket policy loader/enforcer with a subset of AWS semantics."""
from __future__ import annotations

import json
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence


RESOURCE_PREFIX = "arn:aws:s3:::"

ACTION_ALIASES = {
    # List actions
    "s3:listbucket": "list",
    "s3:listallmybuckets": "list",
    "s3:listbucketversions": "list",
    "s3:listmultipartuploads": "list",
    "s3:listparts": "list",
    # Read actions
    "s3:getobject": "read",
    "s3:getobjectversion": "read",
    "s3:getobjecttagging": "read",
    "s3:getobjectversiontagging": "read",
    "s3:getobjectacl": "read",
    "s3:getbucketversioning": "read",
    "s3:headobject": "read",
    "s3:headbucket": "read",
    # Write actions
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
    "s3:deleteobject": "delete",
    "s3:deleteobjectversion": "delete",
    "s3:deletebucket": "delete",
    "s3:deleteobjecttagging": "delete",
    # Share actions (ACL)
    "s3:putobjectacl": "share",
    "s3:putbucketacl": "share",
    "s3:getbucketacl": "share",
    # Policy actions
    "s3:putbucketpolicy": "policy",
    "s3:getbucketpolicy": "policy",
    "s3:deletebucketpolicy": "policy",
    # Replication actions
    "s3:getreplicationconfiguration": "replication",
    "s3:putreplicationconfiguration": "replication",
    "s3:deletereplicationconfiguration": "replication",
    "s3:replicateobject": "replication",
    "s3:replicatetags": "replication",
    "s3:replicatedelete": "replication",
}


def _normalize_action(action: str) -> str:
    action = action.strip().lower()
    if action == "*":
        return "*"
    return ACTION_ALIASES.get(action, action)


def _normalize_actions(actions: Iterable[str]) -> List[str]:
    values: List[str] = []
    for action in actions:
        canonical = _normalize_action(action)
        if canonical == "*" and "*" not in values:
            return ["*"]
        if canonical and canonical not in values:
            values.append(canonical)
    return values


def _normalize_principals(principal_field: Any) -> List[str] | str:
    if principal_field == "*":
        return "*"

    def _collect(values: Any) -> List[str]:
        if values is None:
            return []
        if values == "*":
            return ["*"]
        if isinstance(values, str):
            return [values]
        if isinstance(values, dict):
            aggregated: List[str] = []
            for nested in values.values():
                chunk = _collect(nested)
                if "*" in chunk:
                    return ["*"]
                aggregated.extend(chunk)
            return aggregated
        if isinstance(values, Iterable):
            aggregated = []
            for nested in values:
                chunk = _collect(nested)
                if "*" in chunk:
                    return ["*"]
                aggregated.extend(chunk)
            return aggregated
        return [str(values)]

    normalized: List[str] = []
    for entry in _collect(principal_field):
        token = str(entry).strip()
        if token == "*":
            return "*"
        if token and token not in normalized:
            normalized.append(token)
    return normalized or "*"


def _parse_resource(resource: str) -> tuple[str | None, str | None]:
    if not resource.startswith(RESOURCE_PREFIX):
        return None, None
    remainder = resource[len(RESOURCE_PREFIX) :]
    if "/" not in remainder:
        bucket = remainder or "*"
        return bucket, None
    bucket, _, key_pattern = remainder.partition("/")
    return bucket or "*", key_pattern or "*"


@dataclass
class BucketPolicyStatement:
    sid: Optional[str]
    effect: str
    principals: List[str] | str
    actions: List[str]
    resources: List[tuple[str | None, str | None]]

    def matches_principal(self, access_key: Optional[str]) -> bool:
        if self.principals == "*":
            return True
        if access_key is None:
            return False
        return access_key in self.principals

    def matches_action(self, action: str) -> bool:
        action = _normalize_action(action)
        return "*" in self.actions or action in self.actions

    def matches_resource(self, bucket: Optional[str], object_key: Optional[str]) -> bool:
        bucket = (bucket or "*").lower()
        key = object_key or ""
        for resource_bucket, key_pattern in self.resources:
            resource_bucket = (resource_bucket or "*").lower()
            if resource_bucket not in {"*", bucket}:
                continue
            if key_pattern is None:
                if not key:
                    return True
                continue
            if fnmatch(key, key_pattern):
                return True
        return False


class BucketPolicyStore:
    """Loads bucket policies from disk and evaluates statements."""

    def __init__(self, policy_path: Path) -> None:
        self.policy_path = Path(policy_path)
        self.policy_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.policy_path.exists():
            self.policy_path.write_text(json.dumps({"policies": {}}, indent=2))
        self._raw: Dict[str, Any] = {}
        self._policies: Dict[str, List[BucketPolicyStatement]] = {}
        self._load()
        self._last_mtime = self._current_mtime()

    def maybe_reload(self) -> None:
        current = self._current_mtime()
        if current is None or current == self._last_mtime:
            return
        self._load()
        self._last_mtime = current

    def _current_mtime(self) -> float | None:
        try:
            return self.policy_path.stat().st_mtime
        except FileNotFoundError:
            return None

    # ------------------------------------------------------------------
    def evaluate(
        self,
        access_key: Optional[str],
        bucket: Optional[str],
        object_key: Optional[str],
        action: str,
    ) -> str | None:
        bucket = (bucket or "").lower()
        statements = self._policies.get(bucket) or []
        decision: Optional[str] = None
        for statement in statements:
            if not statement.matches_principal(access_key):
                continue
            if not statement.matches_action(action):
                continue
            if not statement.matches_resource(bucket, object_key):
                continue
            if statement.effect == "deny":
                return "deny"
            decision = "allow"
        return decision

    def get_policy(self, bucket: str) -> Dict[str, Any] | None:
        return self._raw.get(bucket.lower())

    def set_policy(self, bucket: str, policy_payload: Dict[str, Any]) -> None:
        bucket = bucket.lower()
        statements = self._normalize_policy(policy_payload)
        if not statements:
            raise ValueError("Policy must include at least one valid statement")
        self._raw[bucket] = policy_payload
        self._policies[bucket] = statements
        self._persist()

    def delete_policy(self, bucket: str) -> None:
        bucket = bucket.lower()
        self._raw.pop(bucket, None)
        self._policies.pop(bucket, None)
        self._persist()

    # ------------------------------------------------------------------
    def _load(self) -> None:
        try:
            content = self.policy_path.read_text(encoding='utf-8')
            raw_payload = json.loads(content)
        except FileNotFoundError:
            raw_payload = {"policies": {}}
        except json.JSONDecodeError as e:
            raise ValueError(f"Corrupted bucket policy file (invalid JSON): {e}")
        except PermissionError as e:
            raise ValueError(f"Cannot read bucket policy file (permission denied): {e}")
        except (OSError, ValueError) as e:
            raise ValueError(f"Failed to load bucket policies: {e}")
        
        policies: Dict[str, Any] = raw_payload.get("policies", {})
        parsed: Dict[str, List[BucketPolicyStatement]] = {}
        for bucket, policy in policies.items():
            parsed[bucket.lower()] = self._normalize_policy(policy)
        self._raw = {bucket.lower(): policy for bucket, policy in policies.items()}
        self._policies = parsed

    def _persist(self) -> None:
        payload = {"policies": self._raw}
        self.policy_path.write_text(json.dumps(payload, indent=2))

    def _normalize_policy(self, policy: Dict[str, Any]) -> List[BucketPolicyStatement]:
        statements_raw: Sequence[Dict[str, Any]] = policy.get("Statement", [])
        statements: List[BucketPolicyStatement] = []
        for statement in statements_raw:
            actions = _normalize_actions(statement.get("Action", []))
            principals = _normalize_principals(statement.get("Principal", "*"))
            resources_field = statement.get("Resource", [])
            if isinstance(resources_field, str):
                resources_field = [resources_field]
            resources: List[tuple[str | None, str | None]] = []
            for resource in resources_field:
                bucket, pattern = _parse_resource(str(resource))
                if bucket:
                    resources.append((bucket, pattern))
            if not resources:
                continue
            effect = statement.get("Effect", "Allow").lower()
            statements.append(
                BucketPolicyStatement(
                    sid=statement.get("Sid"),
                    effect=effect,
                    principals=principals,
                    actions=actions or ["*"],
                    resources=resources,
                )
            )
        return statements