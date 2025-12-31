from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


ACL_PERMISSION_FULL_CONTROL = "FULL_CONTROL"
ACL_PERMISSION_WRITE = "WRITE"
ACL_PERMISSION_WRITE_ACP = "WRITE_ACP"
ACL_PERMISSION_READ = "READ"
ACL_PERMISSION_READ_ACP = "READ_ACP"

ALL_PERMISSIONS = {
    ACL_PERMISSION_FULL_CONTROL,
    ACL_PERMISSION_WRITE,
    ACL_PERMISSION_WRITE_ACP,
    ACL_PERMISSION_READ,
    ACL_PERMISSION_READ_ACP,
}

PERMISSION_TO_ACTIONS = {
    ACL_PERMISSION_FULL_CONTROL: {"read", "write", "delete", "list", "share"},
    ACL_PERMISSION_WRITE: {"write", "delete"},
    ACL_PERMISSION_WRITE_ACP: {"share"},
    ACL_PERMISSION_READ: {"read", "list"},
    ACL_PERMISSION_READ_ACP: {"share"},
}

GRANTEE_ALL_USERS = "*"
GRANTEE_AUTHENTICATED_USERS = "authenticated"


@dataclass
class AclGrant:
    grantee: str
    permission: str

    def to_dict(self) -> Dict[str, str]:
        return {"grantee": self.grantee, "permission": self.permission}

    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> "AclGrant":
        return cls(grantee=data["grantee"], permission=data["permission"])


@dataclass
class Acl:
    owner: str
    grants: List[AclGrant] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "owner": self.owner,
            "grants": [g.to_dict() for g in self.grants],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Acl":
        return cls(
            owner=data.get("owner", ""),
            grants=[AclGrant.from_dict(g) for g in data.get("grants", [])],
        )

    def get_allowed_actions(self, principal_id: Optional[str], is_authenticated: bool = True) -> Set[str]:
        actions: Set[str] = set()
        if principal_id and principal_id == self.owner:
            actions.update(PERMISSION_TO_ACTIONS[ACL_PERMISSION_FULL_CONTROL])
        for grant in self.grants:
            if grant.grantee == GRANTEE_ALL_USERS:
                actions.update(PERMISSION_TO_ACTIONS.get(grant.permission, set()))
            elif grant.grantee == GRANTEE_AUTHENTICATED_USERS and is_authenticated:
                actions.update(PERMISSION_TO_ACTIONS.get(grant.permission, set()))
            elif principal_id and grant.grantee == principal_id:
                actions.update(PERMISSION_TO_ACTIONS.get(grant.permission, set()))
        return actions


CANNED_ACLS = {
    "private": lambda owner: Acl(
        owner=owner,
        grants=[AclGrant(grantee=owner, permission=ACL_PERMISSION_FULL_CONTROL)],
    ),
    "public-read": lambda owner: Acl(
        owner=owner,
        grants=[
            AclGrant(grantee=owner, permission=ACL_PERMISSION_FULL_CONTROL),
            AclGrant(grantee=GRANTEE_ALL_USERS, permission=ACL_PERMISSION_READ),
        ],
    ),
    "public-read-write": lambda owner: Acl(
        owner=owner,
        grants=[
            AclGrant(grantee=owner, permission=ACL_PERMISSION_FULL_CONTROL),
            AclGrant(grantee=GRANTEE_ALL_USERS, permission=ACL_PERMISSION_READ),
            AclGrant(grantee=GRANTEE_ALL_USERS, permission=ACL_PERMISSION_WRITE),
        ],
    ),
    "authenticated-read": lambda owner: Acl(
        owner=owner,
        grants=[
            AclGrant(grantee=owner, permission=ACL_PERMISSION_FULL_CONTROL),
            AclGrant(grantee=GRANTEE_AUTHENTICATED_USERS, permission=ACL_PERMISSION_READ),
        ],
    ),
    "bucket-owner-read": lambda owner: Acl(
        owner=owner,
        grants=[
            AclGrant(grantee=owner, permission=ACL_PERMISSION_FULL_CONTROL),
        ],
    ),
    "bucket-owner-full-control": lambda owner: Acl(
        owner=owner,
        grants=[
            AclGrant(grantee=owner, permission=ACL_PERMISSION_FULL_CONTROL),
        ],
    ),
}


def create_canned_acl(canned_acl: str, owner: str) -> Acl:
    factory = CANNED_ACLS.get(canned_acl)
    if not factory:
        return CANNED_ACLS["private"](owner)
    return factory(owner)


class AclService:
    def __init__(self, storage_root: Path):
        self.storage_root = storage_root
        self._bucket_acl_cache: Dict[str, Acl] = {}

    def _bucket_acl_path(self, bucket_name: str) -> Path:
        return self.storage_root / ".myfsio.sys" / "buckets" / bucket_name / ".acl.json"

    def get_bucket_acl(self, bucket_name: str) -> Optional[Acl]:
        if bucket_name in self._bucket_acl_cache:
            return self._bucket_acl_cache[bucket_name]
        acl_path = self._bucket_acl_path(bucket_name)
        if not acl_path.exists():
            return None
        try:
            data = json.loads(acl_path.read_text(encoding="utf-8"))
            acl = Acl.from_dict(data)
            self._bucket_acl_cache[bucket_name] = acl
            return acl
        except (OSError, json.JSONDecodeError):
            return None

    def set_bucket_acl(self, bucket_name: str, acl: Acl) -> None:
        acl_path = self._bucket_acl_path(bucket_name)
        acl_path.parent.mkdir(parents=True, exist_ok=True)
        acl_path.write_text(json.dumps(acl.to_dict(), indent=2), encoding="utf-8")
        self._bucket_acl_cache[bucket_name] = acl

    def set_bucket_canned_acl(self, bucket_name: str, canned_acl: str, owner: str) -> Acl:
        acl = create_canned_acl(canned_acl, owner)
        self.set_bucket_acl(bucket_name, acl)
        return acl

    def delete_bucket_acl(self, bucket_name: str) -> None:
        acl_path = self._bucket_acl_path(bucket_name)
        if acl_path.exists():
            acl_path.unlink()
        self._bucket_acl_cache.pop(bucket_name, None)

    def evaluate_bucket_acl(
        self,
        bucket_name: str,
        principal_id: Optional[str],
        action: str,
        is_authenticated: bool = True,
    ) -> bool:
        acl = self.get_bucket_acl(bucket_name)
        if not acl:
            return False
        allowed_actions = acl.get_allowed_actions(principal_id, is_authenticated)
        return action in allowed_actions

    def get_object_acl(self, bucket_name: str, object_key: str, object_metadata: Dict[str, Any]) -> Optional[Acl]:
        acl_data = object_metadata.get("__acl__")
        if not acl_data:
            return None
        try:
            return Acl.from_dict(acl_data)
        except (TypeError, KeyError):
            return None

    def create_object_acl_metadata(self, acl: Acl) -> Dict[str, Any]:
        return {"__acl__": acl.to_dict()}

    def evaluate_object_acl(
        self,
        object_metadata: Dict[str, Any],
        principal_id: Optional[str],
        action: str,
        is_authenticated: bool = True,
    ) -> bool:
        acl = self.get_object_acl("", "", object_metadata)
        if not acl:
            return False
        allowed_actions = acl.get_allowed_actions(principal_id, is_authenticated)
        return action in allowed_actions
