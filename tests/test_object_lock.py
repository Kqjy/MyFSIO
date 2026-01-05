import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.object_lock import (
    ObjectLockConfig,
    ObjectLockError,
    ObjectLockRetention,
    ObjectLockService,
    RetentionMode,
)


class TestRetentionMode:
    def test_governance_mode(self):
        assert RetentionMode.GOVERNANCE.value == "GOVERNANCE"

    def test_compliance_mode(self):
        assert RetentionMode.COMPLIANCE.value == "COMPLIANCE"


class TestObjectLockRetention:
    def test_to_dict(self):
        retain_until = datetime(2025, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
        retention = ObjectLockRetention(
            mode=RetentionMode.GOVERNANCE,
            retain_until_date=retain_until,
        )
        result = retention.to_dict()
        assert result["Mode"] == "GOVERNANCE"
        assert "2025-12-31" in result["RetainUntilDate"]

    def test_from_dict(self):
        data = {
            "Mode": "COMPLIANCE",
            "RetainUntilDate": "2030-06-15T12:00:00+00:00",
        }
        retention = ObjectLockRetention.from_dict(data)
        assert retention is not None
        assert retention.mode == RetentionMode.COMPLIANCE
        assert retention.retain_until_date.year == 2030

    def test_from_dict_empty(self):
        result = ObjectLockRetention.from_dict({})
        assert result is None

    def test_from_dict_missing_mode(self):
        data = {"RetainUntilDate": "2030-06-15T12:00:00+00:00"}
        result = ObjectLockRetention.from_dict(data)
        assert result is None

    def test_from_dict_missing_date(self):
        data = {"Mode": "GOVERNANCE"}
        result = ObjectLockRetention.from_dict(data)
        assert result is None

    def test_is_expired_future_date(self):
        future = datetime.now(timezone.utc) + timedelta(days=30)
        retention = ObjectLockRetention(
            mode=RetentionMode.GOVERNANCE,
            retain_until_date=future,
        )
        assert retention.is_expired() is False

    def test_is_expired_past_date(self):
        past = datetime.now(timezone.utc) - timedelta(days=30)
        retention = ObjectLockRetention(
            mode=RetentionMode.GOVERNANCE,
            retain_until_date=past,
        )
        assert retention.is_expired() is True


class TestObjectLockConfig:
    def test_to_dict_enabled(self):
        config = ObjectLockConfig(enabled=True)
        result = config.to_dict()
        assert result["ObjectLockEnabled"] == "Enabled"

    def test_to_dict_disabled(self):
        config = ObjectLockConfig(enabled=False)
        result = config.to_dict()
        assert result["ObjectLockEnabled"] == "Disabled"

    def test_from_dict_enabled(self):
        data = {"ObjectLockEnabled": "Enabled"}
        config = ObjectLockConfig.from_dict(data)
        assert config.enabled is True

    def test_from_dict_disabled(self):
        data = {"ObjectLockEnabled": "Disabled"}
        config = ObjectLockConfig.from_dict(data)
        assert config.enabled is False

    def test_from_dict_with_default_retention_days(self):
        data = {
            "ObjectLockEnabled": "Enabled",
            "Rule": {
                "DefaultRetention": {
                    "Mode": "GOVERNANCE",
                    "Days": 30,
                }
            },
        }
        config = ObjectLockConfig.from_dict(data)
        assert config.enabled is True
        assert config.default_retention is not None
        assert config.default_retention.mode == RetentionMode.GOVERNANCE

    def test_from_dict_with_default_retention_years(self):
        data = {
            "ObjectLockEnabled": "Enabled",
            "Rule": {
                "DefaultRetention": {
                    "Mode": "COMPLIANCE",
                    "Years": 1,
                }
            },
        }
        config = ObjectLockConfig.from_dict(data)
        assert config.enabled is True
        assert config.default_retention is not None
        assert config.default_retention.mode == RetentionMode.COMPLIANCE


@pytest.fixture
def lock_service(tmp_path: Path):
    return ObjectLockService(tmp_path)


class TestObjectLockService:
    def test_get_bucket_lock_config_default(self, lock_service):
        config = lock_service.get_bucket_lock_config("nonexistent-bucket")
        assert config.enabled is False
        assert config.default_retention is None

    def test_set_and_get_bucket_lock_config(self, lock_service):
        config = ObjectLockConfig(enabled=True)
        lock_service.set_bucket_lock_config("my-bucket", config)

        retrieved = lock_service.get_bucket_lock_config("my-bucket")
        assert retrieved.enabled is True

    def test_enable_bucket_lock(self, lock_service):
        lock_service.enable_bucket_lock("lock-bucket")

        config = lock_service.get_bucket_lock_config("lock-bucket")
        assert config.enabled is True

    def test_is_bucket_lock_enabled(self, lock_service):
        assert lock_service.is_bucket_lock_enabled("new-bucket") is False

        lock_service.enable_bucket_lock("new-bucket")
        assert lock_service.is_bucket_lock_enabled("new-bucket") is True

    def test_get_object_retention_not_set(self, lock_service):
        result = lock_service.get_object_retention("bucket", "key.txt")
        assert result is None

    def test_set_and_get_object_retention(self, lock_service):
        future = datetime.now(timezone.utc) + timedelta(days=30)
        retention = ObjectLockRetention(
            mode=RetentionMode.GOVERNANCE,
            retain_until_date=future,
        )
        lock_service.set_object_retention("bucket", "key.txt", retention)

        retrieved = lock_service.get_object_retention("bucket", "key.txt")
        assert retrieved is not None
        assert retrieved.mode == RetentionMode.GOVERNANCE

    def test_cannot_modify_compliance_retention(self, lock_service):
        future = datetime.now(timezone.utc) + timedelta(days=30)
        retention = ObjectLockRetention(
            mode=RetentionMode.COMPLIANCE,
            retain_until_date=future,
        )
        lock_service.set_object_retention("bucket", "locked.txt", retention)

        new_retention = ObjectLockRetention(
            mode=RetentionMode.GOVERNANCE,
            retain_until_date=future + timedelta(days=10),
        )
        with pytest.raises(ObjectLockError) as exc_info:
            lock_service.set_object_retention("bucket", "locked.txt", new_retention)
        assert "COMPLIANCE" in str(exc_info.value)

    def test_cannot_modify_governance_without_bypass(self, lock_service):
        future = datetime.now(timezone.utc) + timedelta(days=30)
        retention = ObjectLockRetention(
            mode=RetentionMode.GOVERNANCE,
            retain_until_date=future,
        )
        lock_service.set_object_retention("bucket", "gov.txt", retention)

        new_retention = ObjectLockRetention(
            mode=RetentionMode.GOVERNANCE,
            retain_until_date=future + timedelta(days=10),
        )
        with pytest.raises(ObjectLockError) as exc_info:
            lock_service.set_object_retention("bucket", "gov.txt", new_retention)
        assert "GOVERNANCE" in str(exc_info.value)

    def test_can_modify_governance_with_bypass(self, lock_service):
        future = datetime.now(timezone.utc) + timedelta(days=30)
        retention = ObjectLockRetention(
            mode=RetentionMode.GOVERNANCE,
            retain_until_date=future,
        )
        lock_service.set_object_retention("bucket", "bypassable.txt", retention)

        new_retention = ObjectLockRetention(
            mode=RetentionMode.GOVERNANCE,
            retain_until_date=future + timedelta(days=10),
        )
        lock_service.set_object_retention("bucket", "bypassable.txt", new_retention, bypass_governance=True)
        retrieved = lock_service.get_object_retention("bucket", "bypassable.txt")
        assert retrieved.retain_until_date > future

    def test_can_modify_expired_retention(self, lock_service):
        past = datetime.now(timezone.utc) - timedelta(days=30)
        retention = ObjectLockRetention(
            mode=RetentionMode.COMPLIANCE,
            retain_until_date=past,
        )
        lock_service.set_object_retention("bucket", "expired.txt", retention)

        future = datetime.now(timezone.utc) + timedelta(days=30)
        new_retention = ObjectLockRetention(
            mode=RetentionMode.GOVERNANCE,
            retain_until_date=future,
        )
        lock_service.set_object_retention("bucket", "expired.txt", new_retention)
        retrieved = lock_service.get_object_retention("bucket", "expired.txt")
        assert retrieved.mode == RetentionMode.GOVERNANCE

    def test_get_legal_hold_not_set(self, lock_service):
        result = lock_service.get_legal_hold("bucket", "key.txt")
        assert result is False

    def test_set_and_get_legal_hold(self, lock_service):
        lock_service.set_legal_hold("bucket", "held.txt", True)
        assert lock_service.get_legal_hold("bucket", "held.txt") is True

        lock_service.set_legal_hold("bucket", "held.txt", False)
        assert lock_service.get_legal_hold("bucket", "held.txt") is False

    def test_can_delete_object_no_lock(self, lock_service):
        can_delete, reason = lock_service.can_delete_object("bucket", "unlocked.txt")
        assert can_delete is True
        assert reason == ""

    def test_cannot_delete_object_with_legal_hold(self, lock_service):
        lock_service.set_legal_hold("bucket", "held.txt", True)

        can_delete, reason = lock_service.can_delete_object("bucket", "held.txt")
        assert can_delete is False
        assert "legal hold" in reason.lower()

    def test_cannot_delete_object_with_compliance_retention(self, lock_service):
        future = datetime.now(timezone.utc) + timedelta(days=30)
        retention = ObjectLockRetention(
            mode=RetentionMode.COMPLIANCE,
            retain_until_date=future,
        )
        lock_service.set_object_retention("bucket", "compliant.txt", retention)

        can_delete, reason = lock_service.can_delete_object("bucket", "compliant.txt")
        assert can_delete is False
        assert "COMPLIANCE" in reason

    def test_cannot_delete_governance_without_bypass(self, lock_service):
        future = datetime.now(timezone.utc) + timedelta(days=30)
        retention = ObjectLockRetention(
            mode=RetentionMode.GOVERNANCE,
            retain_until_date=future,
        )
        lock_service.set_object_retention("bucket", "governed.txt", retention)

        can_delete, reason = lock_service.can_delete_object("bucket", "governed.txt")
        assert can_delete is False
        assert "GOVERNANCE" in reason

    def test_can_delete_governance_with_bypass(self, lock_service):
        future = datetime.now(timezone.utc) + timedelta(days=30)
        retention = ObjectLockRetention(
            mode=RetentionMode.GOVERNANCE,
            retain_until_date=future,
        )
        lock_service.set_object_retention("bucket", "governed.txt", retention)

        can_delete, reason = lock_service.can_delete_object("bucket", "governed.txt", bypass_governance=True)
        assert can_delete is True
        assert reason == ""

    def test_can_delete_expired_retention(self, lock_service):
        past = datetime.now(timezone.utc) - timedelta(days=30)
        retention = ObjectLockRetention(
            mode=RetentionMode.COMPLIANCE,
            retain_until_date=past,
        )
        lock_service.set_object_retention("bucket", "expired.txt", retention)

        can_delete, reason = lock_service.can_delete_object("bucket", "expired.txt")
        assert can_delete is True

    def test_can_overwrite_is_same_as_delete(self, lock_service):
        future = datetime.now(timezone.utc) + timedelta(days=30)
        retention = ObjectLockRetention(
            mode=RetentionMode.GOVERNANCE,
            retain_until_date=future,
        )
        lock_service.set_object_retention("bucket", "overwrite.txt", retention)

        can_overwrite, _ = lock_service.can_overwrite_object("bucket", "overwrite.txt")
        can_delete, _ = lock_service.can_delete_object("bucket", "overwrite.txt")
        assert can_overwrite == can_delete

    def test_delete_object_lock_metadata(self, lock_service):
        lock_service.set_legal_hold("bucket", "cleanup.txt", True)
        lock_service.delete_object_lock_metadata("bucket", "cleanup.txt")

        assert lock_service.get_legal_hold("bucket", "cleanup.txt") is False

    def test_config_caching(self, lock_service):
        config = ObjectLockConfig(enabled=True)
        lock_service.set_bucket_lock_config("cached-bucket", config)

        lock_service.get_bucket_lock_config("cached-bucket")
        assert "cached-bucket" in lock_service._config_cache
