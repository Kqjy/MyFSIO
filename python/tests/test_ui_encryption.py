"""Tests for UI-based encryption configuration."""
import json
import threading
from pathlib import Path

import pytest
from werkzeug.serving import make_server

from app import create_app
from app.s3_client import S3ProxyClient


def get_csrf_token(response):
    """Extract CSRF token from response HTML."""
    html = response.data.decode("utf-8")
    import re
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    return match.group(1) if match else None


def _make_encryption_app(tmp_path: Path, *, kms_enabled: bool = True):
    """Create an app with encryption enabled."""
    storage_root = tmp_path / "data"
    iam_config = tmp_path / "iam.json"
    bucket_policies = tmp_path / "bucket_policies.json"
    iam_payload = {
        "users": [
            {
                "access_key": "test",
                "secret_key": "secret",
                "display_name": "Test User",
                "policies": [{"bucket": "*", "actions": ["list", "read", "write", "delete", "policy"]}],
            },
            {
                "access_key": "readonly",
                "secret_key": "secret",
                "display_name": "Read Only User",
                "policies": [{"bucket": "*", "actions": ["list", "read"]}],
            },
        ]
    }
    iam_config.write_text(json.dumps(iam_payload))

    config = {
        "TESTING": True,
        "STORAGE_ROOT": storage_root,
        "IAM_CONFIG": iam_config,
        "BUCKET_POLICY_PATH": bucket_policies,
        "API_BASE_URL": "http://127.0.0.1:0",
        "SECRET_KEY": "testing",
        "ENCRYPTION_ENABLED": True,
        "WTF_CSRF_ENABLED": False,
    }

    if kms_enabled:
        config["KMS_ENABLED"] = True
        config["KMS_KEYS_PATH"] = str(tmp_path / "kms_keys.json")
        config["ENCRYPTION_MASTER_KEY_PATH"] = str(tmp_path / "master.key")

    app = create_app(config)

    server = make_server("127.0.0.1", 0, app)
    host, port = server.server_address
    api_url = f"http://{host}:{port}"
    app.config["API_BASE_URL"] = api_url
    app.extensions["s3_proxy"] = S3ProxyClient(api_base_url=api_url)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    app._test_server = server
    app._test_thread = thread

    storage = app.extensions["object_storage"]
    storage.create_bucket("test-bucket")
    return app


def _shutdown_app(app):
    if hasattr(app, "_test_server"):
        app._test_server.shutdown()
        app._test_thread.join(timeout=2)


class TestUIBucketEncryption:
    """Test bucket encryption configuration via UI."""

    def test_bucket_detail_shows_encryption_card(self, tmp_path):
        """Encryption card should be visible on bucket detail page."""
        app = _make_encryption_app(tmp_path)
        try:
            client = app.test_client()

            client.post("/ui/login", data={"access_key": "test", "secret_key": "secret"}, follow_redirects=True)

            response = client.get("/ui/buckets/test-bucket?tab=properties")
            assert response.status_code == 200

            html = response.data.decode("utf-8")
            assert "Default Encryption" in html
            assert "Encryption Algorithm" in html or "Default encryption disabled" in html
        finally:
            _shutdown_app(app)

    def test_enable_aes256_encryption(self, tmp_path):
        """Should be able to enable AES-256 encryption."""
        app = _make_encryption_app(tmp_path)
        try:
            client = app.test_client()

            client.post("/ui/login", data={"access_key": "test", "secret_key": "secret"}, follow_redirects=True)

            response = client.post(
                "/ui/buckets/test-bucket/encryption",
                data={
                    "action": "enable",
                    "algorithm": "AES256",
                },
                follow_redirects=True,
            )

            assert response.status_code == 200
            html = response.data.decode("utf-8")
            assert "AES-256" in html or "encryption enabled" in html.lower()
        finally:
            _shutdown_app(app)

    def test_enable_kms_encryption(self, tmp_path):
        """Should be able to enable KMS encryption."""
        app = _make_encryption_app(tmp_path, kms_enabled=True)
        try:
            with app.app_context():
                kms = app.extensions.get("kms")
                if kms:
                    key = kms.create_key("test-key")
                    key_id = key.key_id
                else:
                    pytest.skip("KMS not available")

            client = app.test_client()
            client.post("/ui/login", data={"access_key": "test", "secret_key": "secret"}, follow_redirects=True)

            response = client.post(
                "/ui/buckets/test-bucket/encryption",
                data={
                    "action": "enable",
                    "algorithm": "aws:kms",
                    "kms_key_id": key_id,
                },
                follow_redirects=True,
            )

            assert response.status_code == 200
            html = response.data.decode("utf-8")
            assert "KMS" in html or "encryption enabled" in html.lower()
        finally:
            _shutdown_app(app)

    def test_disable_encryption(self, tmp_path):
        """Should be able to disable encryption."""
        app = _make_encryption_app(tmp_path)
        try:
            client = app.test_client()

            client.post("/ui/login", data={"access_key": "test", "secret_key": "secret"}, follow_redirects=True)

            client.post(
                "/ui/buckets/test-bucket/encryption",
                data={
                    "action": "enable",
                    "algorithm": "AES256",
                },
            )

            response = client.post(
                "/ui/buckets/test-bucket/encryption",
                data={
                    "action": "disable",
                },
                follow_redirects=True,
            )

            assert response.status_code == 200
            html = response.data.decode("utf-8")
            assert "disabled" in html.lower() or "Default encryption disabled" in html
        finally:
            _shutdown_app(app)

    def test_invalid_algorithm_rejected(self, tmp_path):
        """Invalid encryption algorithm should be rejected."""
        app = _make_encryption_app(tmp_path)
        try:
            client = app.test_client()

            client.post("/ui/login", data={"access_key": "test", "secret_key": "secret"}, follow_redirects=True)

            response = client.post(
                "/ui/buckets/test-bucket/encryption",
                data={
                    "action": "enable",
                    "algorithm": "INVALID",
                },
                follow_redirects=True,
            )

            assert response.status_code == 200
            html = response.data.decode("utf-8")
            assert "Invalid" in html or "danger" in html
        finally:
            _shutdown_app(app)

    def test_encryption_persists_in_config(self, tmp_path):
        """Encryption config should persist in bucket config."""
        app = _make_encryption_app(tmp_path)
        try:
            client = app.test_client()

            client.post("/ui/login", data={"access_key": "test", "secret_key": "secret"}, follow_redirects=True)

            client.post(
                "/ui/buckets/test-bucket/encryption",
                data={
                    "action": "enable",
                    "algorithm": "AES256",
                },
            )

            with app.app_context():
                storage = app.extensions["object_storage"]
                config = storage.get_bucket_encryption("test-bucket")

                assert "Rules" in config
                assert len(config["Rules"]) == 1
                assert config["Rules"][0]["SSEAlgorithm"] == "AES256"
        finally:
            _shutdown_app(app)


class TestUIEncryptionWithoutPermission:
    """Test encryption UI when user lacks permissions."""

    def test_readonly_user_cannot_change_encryption(self, tmp_path):
        """Read-only user should not be able to change encryption settings."""
        app = _make_encryption_app(tmp_path)
        try:
            client = app.test_client()

            client.post("/ui/login", data={"access_key": "readonly", "secret_key": "secret"}, follow_redirects=True)

            response = client.post(
                "/ui/buckets/test-bucket/encryption",
                data={
                    "action": "enable",
                    "algorithm": "AES256",
                },
                follow_redirects=True,
            )

            assert response.status_code == 200
            html = response.data.decode("utf-8")
            assert "Access denied" in html or "permission" in html.lower() or "not authorized" in html.lower()
        finally:
            _shutdown_app(app)
