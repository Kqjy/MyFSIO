"""Tests for UI-based encryption configuration."""
import json
from pathlib import Path

import pytest

from app import create_app


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
        "API_BASE_URL": "http://testserver",
        "SECRET_KEY": "testing",
        "ENCRYPTION_ENABLED": True,
    }
    
    if kms_enabled:
        config["KMS_ENABLED"] = True
        config["KMS_KEYS_PATH"] = str(tmp_path / "kms_keys.json")
        config["ENCRYPTION_MASTER_KEY_PATH"] = str(tmp_path / "master.key")
    
    app = create_app(config)
    storage = app.extensions["object_storage"]
    storage.create_bucket("test-bucket")
    return app


class TestUIBucketEncryption:
    """Test bucket encryption configuration via UI."""
    
    def test_bucket_detail_shows_encryption_card(self, tmp_path):
        """Encryption card should be visible on bucket detail page."""
        app = _make_encryption_app(tmp_path)
        client = app.test_client()
        
        # Login first
        client.post("/ui/login", data={"access_key": "test", "secret_key": "secret"}, follow_redirects=True)
        
        response = client.get("/ui/buckets/test-bucket?tab=properties")
        assert response.status_code == 200
        
        html = response.data.decode("utf-8")
        assert "Default Encryption" in html
        assert "Encryption Algorithm" in html or "Default encryption disabled" in html
    
    def test_enable_aes256_encryption(self, tmp_path):
        """Should be able to enable AES-256 encryption."""
        app = _make_encryption_app(tmp_path)
        client = app.test_client()
        
        # Login
        client.post("/ui/login", data={"access_key": "test", "secret_key": "secret"}, follow_redirects=True)
        
        # Get CSRF token
        response = client.get("/ui/buckets/test-bucket?tab=properties")
        csrf_token = get_csrf_token(response)
        
        # Enable AES-256 encryption
        response = client.post(
            "/ui/buckets/test-bucket/encryption",
            data={
                "csrf_token": csrf_token,
                "action": "enable",
                "algorithm": "AES256",
            },
            follow_redirects=True,
        )
        
        assert response.status_code == 200
        html = response.data.decode("utf-8")
        # Should see success message or enabled state
        assert "AES-256" in html or "encryption enabled" in html.lower()
    
    def test_enable_kms_encryption(self, tmp_path):
        """Should be able to enable KMS encryption."""
        app = _make_encryption_app(tmp_path, kms_enabled=True)
        client = app.test_client()
        
        # Create a KMS key first
        with app.app_context():
            kms = app.extensions.get("kms")
            if kms:
                key = kms.create_key("test-key")
                key_id = key.key_id
            else:
                pytest.skip("KMS not available")
        
        # Login
        client.post("/ui/login", data={"access_key": "test", "secret_key": "secret"}, follow_redirects=True)
        
        # Get CSRF token
        response = client.get("/ui/buckets/test-bucket?tab=properties")
        csrf_token = get_csrf_token(response)
        
        # Enable KMS encryption
        response = client.post(
            "/ui/buckets/test-bucket/encryption",
            data={
                "csrf_token": csrf_token,
                "action": "enable",
                "algorithm": "aws:kms",
                "kms_key_id": key_id,
            },
            follow_redirects=True,
        )
        
        assert response.status_code == 200
        html = response.data.decode("utf-8")
        assert "KMS" in html or "encryption enabled" in html.lower()
    
    def test_disable_encryption(self, tmp_path):
        """Should be able to disable encryption."""
        app = _make_encryption_app(tmp_path)
        client = app.test_client()
        
        # Login
        client.post("/ui/login", data={"access_key": "test", "secret_key": "secret"}, follow_redirects=True)
        
        # First enable encryption
        response = client.get("/ui/buckets/test-bucket?tab=properties")
        csrf_token = get_csrf_token(response)
        
        client.post(
            "/ui/buckets/test-bucket/encryption",
            data={
                "csrf_token": csrf_token,
                "action": "enable",
                "algorithm": "AES256",
            },
        )
        
        # Now disable it
        response = client.get("/ui/buckets/test-bucket?tab=properties")
        csrf_token = get_csrf_token(response)
        
        response = client.post(
            "/ui/buckets/test-bucket/encryption",
            data={
                "csrf_token": csrf_token,
                "action": "disable",
            },
            follow_redirects=True,
        )
        
        assert response.status_code == 200
        html = response.data.decode("utf-8")
        assert "disabled" in html.lower() or "Default encryption disabled" in html
    
    def test_invalid_algorithm_rejected(self, tmp_path):
        """Invalid encryption algorithm should be rejected."""
        app = _make_encryption_app(tmp_path)
        client = app.test_client()
        
        # Login
        client.post("/ui/login", data={"access_key": "test", "secret_key": "secret"}, follow_redirects=True)
        
        response = client.get("/ui/buckets/test-bucket?tab=properties")
        csrf_token = get_csrf_token(response)
        
        response = client.post(
            "/ui/buckets/test-bucket/encryption",
            data={
                "csrf_token": csrf_token,
                "action": "enable",
                "algorithm": "INVALID",
            },
            follow_redirects=True,
        )
        
        assert response.status_code == 200
        html = response.data.decode("utf-8")
        assert "Invalid" in html or "danger" in html
    
    def test_encryption_persists_in_config(self, tmp_path):
        """Encryption config should persist in bucket config."""
        app = _make_encryption_app(tmp_path)
        client = app.test_client()
        
        # Login
        client.post("/ui/login", data={"access_key": "test", "secret_key": "secret"}, follow_redirects=True)
        
        # Enable encryption
        response = client.get("/ui/buckets/test-bucket?tab=properties")
        csrf_token = get_csrf_token(response)
        
        client.post(
            "/ui/buckets/test-bucket/encryption",
            data={
                "csrf_token": csrf_token,
                "action": "enable",
                "algorithm": "AES256",
            },
        )
        
        # Verify it's stored
        with app.app_context():
            storage = app.extensions["object_storage"]
            config = storage.get_bucket_encryption("test-bucket")
            
            assert "Rules" in config
            assert len(config["Rules"]) == 1
            assert config["Rules"][0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] == "AES256"


class TestUIEncryptionWithoutPermission:
    """Test encryption UI when user lacks permissions."""
    
    def test_readonly_user_cannot_change_encryption(self, tmp_path):
        """Read-only user should not be able to change encryption settings."""
        app = _make_encryption_app(tmp_path)
        client = app.test_client()
        
        # Login as readonly user
        client.post("/ui/login", data={"access_key": "readonly", "secret_key": "secret"}, follow_redirects=True)
        
        # This should fail or be rejected
        response = client.get("/ui/buckets/test-bucket?tab=properties")
        csrf_token = get_csrf_token(response)
        
        response = client.post(
            "/ui/buckets/test-bucket/encryption",
            data={
                "csrf_token": csrf_token,
                "action": "enable",
                "algorithm": "AES256",
            },
            follow_redirects=True,
        )
        
        # Should either redirect with error or show permission denied
        assert response.status_code == 200
        html = response.data.decode("utf-8")
        # Should contain error about permission denied
        assert "Access denied" in html or "permission" in html.lower() or "not authorized" in html.lower()
