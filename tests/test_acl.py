import json
from pathlib import Path

import pytest

from app.acl import (
    Acl,
    AclGrant,
    AclService,
    ACL_PERMISSION_FULL_CONTROL,
    ACL_PERMISSION_READ,
    ACL_PERMISSION_WRITE,
    ACL_PERMISSION_READ_ACP,
    ACL_PERMISSION_WRITE_ACP,
    GRANTEE_ALL_USERS,
    GRANTEE_AUTHENTICATED_USERS,
    PERMISSION_TO_ACTIONS,
    create_canned_acl,
    CANNED_ACLS,
)


class TestAclGrant:
    def test_to_dict(self):
        grant = AclGrant(grantee="user123", permission=ACL_PERMISSION_READ)
        result = grant.to_dict()
        assert result == {"grantee": "user123", "permission": "READ"}

    def test_from_dict(self):
        data = {"grantee": "admin", "permission": "FULL_CONTROL"}
        grant = AclGrant.from_dict(data)
        assert grant.grantee == "admin"
        assert grant.permission == ACL_PERMISSION_FULL_CONTROL


class TestAcl:
    def test_to_dict(self):
        acl = Acl(
            owner="owner-user",
            grants=[
                AclGrant(grantee="owner-user", permission=ACL_PERMISSION_FULL_CONTROL),
                AclGrant(grantee=GRANTEE_ALL_USERS, permission=ACL_PERMISSION_READ),
            ],
        )
        result = acl.to_dict()
        assert result["owner"] == "owner-user"
        assert len(result["grants"]) == 2
        assert result["grants"][0]["grantee"] == "owner-user"
        assert result["grants"][1]["grantee"] == "*"

    def test_from_dict(self):
        data = {
            "owner": "the-owner",
            "grants": [
                {"grantee": "the-owner", "permission": "FULL_CONTROL"},
                {"grantee": "authenticated", "permission": "READ"},
            ],
        }
        acl = Acl.from_dict(data)
        assert acl.owner == "the-owner"
        assert len(acl.grants) == 2
        assert acl.grants[0].grantee == "the-owner"
        assert acl.grants[1].grantee == GRANTEE_AUTHENTICATED_USERS

    def test_from_dict_empty_grants(self):
        data = {"owner": "solo-owner"}
        acl = Acl.from_dict(data)
        assert acl.owner == "solo-owner"
        assert len(acl.grants) == 0

    def test_get_allowed_actions_owner(self):
        acl = Acl(owner="owner123", grants=[])
        actions = acl.get_allowed_actions("owner123", is_authenticated=True)
        assert actions == PERMISSION_TO_ACTIONS[ACL_PERMISSION_FULL_CONTROL]

    def test_get_allowed_actions_all_users(self):
        acl = Acl(
            owner="owner",
            grants=[AclGrant(grantee=GRANTEE_ALL_USERS, permission=ACL_PERMISSION_READ)],
        )
        actions = acl.get_allowed_actions(None, is_authenticated=False)
        assert "read" in actions
        assert "list" in actions
        assert "write" not in actions

    def test_get_allowed_actions_authenticated_users(self):
        acl = Acl(
            owner="owner",
            grants=[AclGrant(grantee=GRANTEE_AUTHENTICATED_USERS, permission=ACL_PERMISSION_WRITE)],
        )
        actions_authenticated = acl.get_allowed_actions("some-user", is_authenticated=True)
        assert "write" in actions_authenticated
        assert "delete" in actions_authenticated

        actions_anonymous = acl.get_allowed_actions(None, is_authenticated=False)
        assert "write" not in actions_anonymous

    def test_get_allowed_actions_specific_grantee(self):
        acl = Acl(
            owner="owner",
            grants=[
                AclGrant(grantee="user-abc", permission=ACL_PERMISSION_READ),
                AclGrant(grantee="user-xyz", permission=ACL_PERMISSION_WRITE),
            ],
        )
        abc_actions = acl.get_allowed_actions("user-abc", is_authenticated=True)
        assert "read" in abc_actions
        assert "list" in abc_actions
        assert "write" not in abc_actions

        xyz_actions = acl.get_allowed_actions("user-xyz", is_authenticated=True)
        assert "write" in xyz_actions
        assert "read" not in xyz_actions

    def test_get_allowed_actions_combined(self):
        acl = Acl(
            owner="owner",
            grants=[
                AclGrant(grantee=GRANTEE_ALL_USERS, permission=ACL_PERMISSION_READ),
                AclGrant(grantee="special-user", permission=ACL_PERMISSION_WRITE),
            ],
        )
        actions = acl.get_allowed_actions("special-user", is_authenticated=True)
        assert "read" in actions
        assert "list" in actions
        assert "write" in actions
        assert "delete" in actions


class TestCannedAcls:
    def test_private_acl(self):
        acl = create_canned_acl("private", "the-owner")
        assert acl.owner == "the-owner"
        assert len(acl.grants) == 1
        assert acl.grants[0].grantee == "the-owner"
        assert acl.grants[0].permission == ACL_PERMISSION_FULL_CONTROL

    def test_public_read_acl(self):
        acl = create_canned_acl("public-read", "owner")
        assert acl.owner == "owner"
        has_owner_full_control = any(
            g.grantee == "owner" and g.permission == ACL_PERMISSION_FULL_CONTROL for g in acl.grants
        )
        has_public_read = any(
            g.grantee == GRANTEE_ALL_USERS and g.permission == ACL_PERMISSION_READ for g in acl.grants
        )
        assert has_owner_full_control
        assert has_public_read

    def test_public_read_write_acl(self):
        acl = create_canned_acl("public-read-write", "owner")
        assert acl.owner == "owner"
        has_public_read = any(
            g.grantee == GRANTEE_ALL_USERS and g.permission == ACL_PERMISSION_READ for g in acl.grants
        )
        has_public_write = any(
            g.grantee == GRANTEE_ALL_USERS and g.permission == ACL_PERMISSION_WRITE for g in acl.grants
        )
        assert has_public_read
        assert has_public_write

    def test_authenticated_read_acl(self):
        acl = create_canned_acl("authenticated-read", "owner")
        has_authenticated_read = any(
            g.grantee == GRANTEE_AUTHENTICATED_USERS and g.permission == ACL_PERMISSION_READ for g in acl.grants
        )
        assert has_authenticated_read

    def test_unknown_canned_acl_defaults_to_private(self):
        acl = create_canned_acl("unknown-acl", "owner")
        private_acl = create_canned_acl("private", "owner")
        assert acl.to_dict() == private_acl.to_dict()


@pytest.fixture
def acl_service(tmp_path: Path):
    return AclService(tmp_path)


class TestAclService:
    def test_get_bucket_acl_not_exists(self, acl_service):
        result = acl_service.get_bucket_acl("nonexistent-bucket")
        assert result is None

    def test_set_and_get_bucket_acl(self, acl_service):
        acl = Acl(
            owner="bucket-owner",
            grants=[AclGrant(grantee="bucket-owner", permission=ACL_PERMISSION_FULL_CONTROL)],
        )
        acl_service.set_bucket_acl("my-bucket", acl)

        retrieved = acl_service.get_bucket_acl("my-bucket")
        assert retrieved is not None
        assert retrieved.owner == "bucket-owner"
        assert len(retrieved.grants) == 1

    def test_bucket_acl_caching(self, acl_service):
        acl = Acl(owner="cached-owner", grants=[])
        acl_service.set_bucket_acl("cached-bucket", acl)

        acl_service.get_bucket_acl("cached-bucket")
        assert "cached-bucket" in acl_service._bucket_acl_cache

        retrieved = acl_service.get_bucket_acl("cached-bucket")
        assert retrieved.owner == "cached-owner"

    def test_set_bucket_canned_acl(self, acl_service):
        result = acl_service.set_bucket_canned_acl("new-bucket", "public-read", "the-owner")
        assert result.owner == "the-owner"

        retrieved = acl_service.get_bucket_acl("new-bucket")
        assert retrieved is not None
        has_public_read = any(
            g.grantee == GRANTEE_ALL_USERS and g.permission == ACL_PERMISSION_READ for g in retrieved.grants
        )
        assert has_public_read

    def test_delete_bucket_acl(self, acl_service):
        acl = Acl(owner="to-delete-owner", grants=[])
        acl_service.set_bucket_acl("delete-me", acl)
        assert acl_service.get_bucket_acl("delete-me") is not None

        acl_service.delete_bucket_acl("delete-me")
        acl_service._bucket_acl_cache.clear()
        assert acl_service.get_bucket_acl("delete-me") is None

    def test_evaluate_bucket_acl_allowed(self, acl_service):
        acl = Acl(
            owner="owner",
            grants=[AclGrant(grantee=GRANTEE_ALL_USERS, permission=ACL_PERMISSION_READ)],
        )
        acl_service.set_bucket_acl("public-bucket", acl)

        result = acl_service.evaluate_bucket_acl("public-bucket", None, "read", is_authenticated=False)
        assert result is True

    def test_evaluate_bucket_acl_denied(self, acl_service):
        acl = Acl(
            owner="owner",
            grants=[AclGrant(grantee="owner", permission=ACL_PERMISSION_FULL_CONTROL)],
        )
        acl_service.set_bucket_acl("private-bucket", acl)

        result = acl_service.evaluate_bucket_acl("private-bucket", "other-user", "write", is_authenticated=True)
        assert result is False

    def test_evaluate_bucket_acl_no_acl(self, acl_service):
        result = acl_service.evaluate_bucket_acl("no-acl-bucket", "anyone", "read")
        assert result is False

    def test_get_object_acl_from_metadata(self, acl_service):
        metadata = {
            "__acl__": {
                "owner": "object-owner",
                "grants": [{"grantee": "object-owner", "permission": "FULL_CONTROL"}],
            }
        }
        result = acl_service.get_object_acl("bucket", "key", metadata)
        assert result is not None
        assert result.owner == "object-owner"

    def test_get_object_acl_no_acl_in_metadata(self, acl_service):
        metadata = {"Content-Type": "text/plain"}
        result = acl_service.get_object_acl("bucket", "key", metadata)
        assert result is None

    def test_create_object_acl_metadata(self, acl_service):
        acl = Acl(owner="obj-owner", grants=[])
        result = acl_service.create_object_acl_metadata(acl)
        assert "__acl__" in result
        assert result["__acl__"]["owner"] == "obj-owner"

    def test_evaluate_object_acl(self, acl_service):
        metadata = {
            "__acl__": {
                "owner": "obj-owner",
                "grants": [{"grantee": "*", "permission": "READ"}],
            }
        }
        result = acl_service.evaluate_object_acl(metadata, None, "read", is_authenticated=False)
        assert result is True

        result = acl_service.evaluate_object_acl(metadata, None, "write", is_authenticated=False)
        assert result is False
