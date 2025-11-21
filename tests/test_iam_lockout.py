import json
import time
from datetime import timedelta

import pytest

from app.iam import IamError, IamService


def _make_service(tmp_path, *, max_attempts=3, lockout_seconds=2):
    config = tmp_path / "iam.json"
    payload = {
        "users": [
            {
                "access_key": "test",
                "secret_key": "secret",
                "display_name": "Test User",
                "policies": [
                    {
                        "bucket": "*",
                        "actions": ["list", "read", "write", "delete", "policy"],
                    }
                ],
            }
        ]
    }
    config.write_text(json.dumps(payload))
    service = IamService(config, auth_max_attempts=max_attempts, auth_lockout_minutes=lockout_seconds/60)
    return service


def test_lockout_triggers_after_failed_attempts(tmp_path):
    service = _make_service(tmp_path, max_attempts=3, lockout_seconds=30)

    for _ in range(service.auth_max_attempts):
        with pytest.raises(IamError) as exc:
            service.authenticate("test", "bad-secret")
        assert "Invalid credentials" in str(exc.value)

    with pytest.raises(IamError) as exc:
        service.authenticate("test", "bad-secret")
    assert "Access temporarily locked" in str(exc.value)


def test_lockout_expires_and_allows_auth(tmp_path):
    service = _make_service(tmp_path, max_attempts=2, lockout_seconds=1)

    for _ in range(service.auth_max_attempts):
        with pytest.raises(IamError):
            service.authenticate("test", "bad-secret")

    with pytest.raises(IamError) as exc:
        service.authenticate("test", "secret")
    assert "Access temporarily locked" in str(exc.value)

    time.sleep(1.1)
    principal = service.authenticate("test", "secret")
    assert principal.access_key == "test"
