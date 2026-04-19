"""Tests for UI pagination of bucket objects."""
import json
import threading
from io import BytesIO
from pathlib import Path

import pytest
from werkzeug.serving import make_server

from app import create_app
from app.s3_client import S3ProxyClient


def _make_app(tmp_path: Path):
    """Create an app for testing with a live API server."""
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
        ]
    }
    iam_config.write_text(json.dumps(iam_payload))

    flask_app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "testing",
            "WTF_CSRF_ENABLED": False,
            "STORAGE_ROOT": storage_root,
            "IAM_CONFIG": iam_config,
            "BUCKET_POLICY_PATH": bucket_policies,
            "API_BASE_URL": "http://127.0.0.1:0",
        }
    )

    server = make_server("127.0.0.1", 0, flask_app)
    host, port = server.server_address
    api_url = f"http://{host}:{port}"
    flask_app.config["API_BASE_URL"] = api_url
    flask_app.extensions["s3_proxy"] = S3ProxyClient(api_base_url=api_url)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    flask_app._test_server = server
    flask_app._test_thread = thread
    return flask_app


def _shutdown_app(app):
    if hasattr(app, "_test_server"):
        app._test_server.shutdown()
        app._test_thread.join(timeout=2)


class TestPaginatedObjectListing:
    """Test paginated object listing API."""

    def test_objects_api_returns_paginated_results(self, tmp_path):
        """Objects API should return paginated results."""
        app = _make_app(tmp_path)
        try:
            storage = app.extensions["object_storage"]
            storage.create_bucket("test-bucket")

            for i in range(10):
                storage.put_object("test-bucket", f"file{i:02d}.txt", BytesIO(b"content"))

            with app.test_client() as client:
                client.post("/ui/login", data={"access_key": "test", "secret_key": "secret"}, follow_redirects=True)

                resp = client.get("/ui/buckets/test-bucket/objects?max_keys=3")
                assert resp.status_code == 200

                data = resp.get_json()
                assert len(data["objects"]) == 3
                assert data["is_truncated"] is True
                assert data["next_continuation_token"] is not None
        finally:
            _shutdown_app(app)

    def test_objects_api_pagination_continuation(self, tmp_path):
        """Objects API should support continuation tokens."""
        app = _make_app(tmp_path)
        try:
            storage = app.extensions["object_storage"]
            storage.create_bucket("test-bucket")

            for i in range(5):
                storage.put_object("test-bucket", f"file{i:02d}.txt", BytesIO(b"content"))

            with app.test_client() as client:
                client.post("/ui/login", data={"access_key": "test", "secret_key": "secret"}, follow_redirects=True)

                resp = client.get("/ui/buckets/test-bucket/objects?max_keys=2")
                assert resp.status_code == 200
                data = resp.get_json()

                first_page_keys = [obj["key"] for obj in data["objects"]]
                assert len(first_page_keys) == 2
                assert data["is_truncated"] is True

                token = data["next_continuation_token"]
                resp = client.get(f"/ui/buckets/test-bucket/objects?max_keys=2&continuation_token={token}")
                assert resp.status_code == 200
                data = resp.get_json()

                second_page_keys = [obj["key"] for obj in data["objects"]]
                assert len(second_page_keys) == 2

                assert set(first_page_keys).isdisjoint(set(second_page_keys))
        finally:
            _shutdown_app(app)

    def test_objects_api_prefix_filter(self, tmp_path):
        """Objects API should support prefix filtering."""
        app = _make_app(tmp_path)
        try:
            storage = app.extensions["object_storage"]
            storage.create_bucket("test-bucket")

            storage.put_object("test-bucket", "logs/access.log", BytesIO(b"log"))
            storage.put_object("test-bucket", "logs/error.log", BytesIO(b"log"))
            storage.put_object("test-bucket", "data/file.txt", BytesIO(b"data"))

            with app.test_client() as client:
                client.post("/ui/login", data={"access_key": "test", "secret_key": "secret"}, follow_redirects=True)

                resp = client.get("/ui/buckets/test-bucket/objects?prefix=logs/")
                assert resp.status_code == 200
                data = resp.get_json()

                keys = [obj["key"] for obj in data["objects"]]
                assert all(k.startswith("logs/") for k in keys)
                assert len(keys) == 2
        finally:
            _shutdown_app(app)

    def test_objects_api_requires_authentication(self, tmp_path):
        """Objects API should require login."""
        app = _make_app(tmp_path)
        try:
            storage = app.extensions["object_storage"]
            storage.create_bucket("test-bucket")

            with app.test_client() as client:
                resp = client.get("/ui/buckets/test-bucket/objects")
                assert resp.status_code == 302
                assert "/ui/login" in resp.headers.get("Location", "")
        finally:
            _shutdown_app(app)

    def test_objects_api_returns_object_metadata(self, tmp_path):
        """Objects API should return complete object metadata."""
        app = _make_app(tmp_path)
        try:
            storage = app.extensions["object_storage"]
            storage.create_bucket("test-bucket")
            storage.put_object("test-bucket", "test.txt", BytesIO(b"test content"))

            with app.test_client() as client:
                client.post("/ui/login", data={"access_key": "test", "secret_key": "secret"}, follow_redirects=True)

                resp = client.get("/ui/buckets/test-bucket/objects")
                assert resp.status_code == 200
                data = resp.get_json()

                assert len(data["objects"]) == 1
                obj = data["objects"][0]

                assert obj["key"] == "test.txt"
                assert obj["size"] == 12
                assert "last_modified" in obj
                assert "last_modified_display" in obj
                assert "etag" in obj

                assert "url_templates" in data
                templates = data["url_templates"]
                assert "preview" in templates
                assert "download" in templates
                assert "delete" in templates
                assert "KEY_PLACEHOLDER" in templates["preview"]
        finally:
            _shutdown_app(app)

    def test_bucket_detail_page_loads_without_objects(self, tmp_path):
        """Bucket detail page should load even with many objects."""
        app = _make_app(tmp_path)
        try:
            storage = app.extensions["object_storage"]
            storage.create_bucket("test-bucket")

            for i in range(100):
                storage.put_object("test-bucket", f"file{i:03d}.txt", BytesIO(b"x"))

            with app.test_client() as client:
                client.post("/ui/login", data={"access_key": "test", "secret_key": "secret"}, follow_redirects=True)

                resp = client.get("/ui/buckets/test-bucket")
                assert resp.status_code == 200

                html = resp.data.decode("utf-8")
                assert "bucket-detail-main.js" in html
        finally:
            _shutdown_app(app)
