import io
import json
import threading
from pathlib import Path

import pytest
from werkzeug.serving import make_server

from app import create_app
from app.s3_client import S3ProxyClient


DENY_LIST_ALLOW_GET_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": ["*"]},
            "Action": ["s3:GetObject"],
            "Resource": ["arn:aws:s3:::testbucket/*"],
        },
        {
            "Effect": "Deny",
            "Principal": {"AWS": ["*"]},
            "Action": ["s3:ListBucket"],
            "Resource": ["arn:aws:s3:::testbucket"],
        },
    ],
}


def _make_ui_app(tmp_path: Path, *, enforce_policies: bool):
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
            }
        ]
    }
    iam_config.write_text(json.dumps(iam_payload))
    app = create_app(
        {
            "TESTING": True,
            "STORAGE_ROOT": storage_root,
            "IAM_CONFIG": iam_config,
            "BUCKET_POLICY_PATH": bucket_policies,
            "API_BASE_URL": "http://127.0.0.1:0",
            "SECRET_KEY": "testing",
            "UI_ENFORCE_BUCKET_POLICIES": enforce_policies,
            "WTF_CSRF_ENABLED": False,
        }
    )

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
    storage.create_bucket("testbucket")
    storage.put_object("testbucket", "vid.mp4", io.BytesIO(b"video"))
    policy_store = app.extensions["bucket_policies"]
    policy_store.set_policy("testbucket", DENY_LIST_ALLOW_GET_POLICY)
    return app


def _shutdown_app(app):
    if hasattr(app, "_test_server"):
        app._test_server.shutdown()
        app._test_thread.join(timeout=2)


@pytest.mark.parametrize("enforce", [True, False])
def test_ui_bucket_policy_enforcement_toggle(tmp_path: Path, enforce: bool):
    app = _make_ui_app(tmp_path, enforce_policies=enforce)
    try:
        client = app.test_client()
        client.post("/ui/login", data={"access_key": "test", "secret_key": "secret"}, follow_redirects=True)
        response = client.get("/ui/buckets/testbucket", follow_redirects=True)
        if enforce:
            assert b"Access denied by bucket policy" in response.data
        else:
            assert response.status_code == 200
            assert b"Access denied by bucket policy" not in response.data
            objects_response = client.get("/ui/buckets/testbucket/objects")
            assert objects_response.status_code == 403
    finally:
        _shutdown_app(app)


def test_ui_bucket_policy_disabled_by_default(tmp_path: Path):
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
            }
        ]
    }
    iam_config.write_text(json.dumps(iam_payload))
    app = create_app(
        {
            "TESTING": True,
            "STORAGE_ROOT": storage_root,
            "IAM_CONFIG": iam_config,
            "BUCKET_POLICY_PATH": bucket_policies,
            "API_BASE_URL": "http://127.0.0.1:0",
            "SECRET_KEY": "testing",
            "WTF_CSRF_ENABLED": False,
        }
    )

    server = make_server("127.0.0.1", 0, app)
    host, port = server.server_address
    api_url = f"http://{host}:{port}"
    app.config["API_BASE_URL"] = api_url
    app.extensions["s3_proxy"] = S3ProxyClient(api_base_url=api_url)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    app._test_server = server
    app._test_thread = thread

    try:
        storage = app.extensions["object_storage"]
        storage.create_bucket("testbucket")
        storage.put_object("testbucket", "vid.mp4", io.BytesIO(b"video"))
        policy_store = app.extensions["bucket_policies"]
        policy_store.set_policy("testbucket", DENY_LIST_ALLOW_GET_POLICY)

        client = app.test_client()
        client.post("/ui/login", data={"access_key": "test", "secret_key": "secret"}, follow_redirects=True)
        response = client.get("/ui/buckets/testbucket", follow_redirects=True)
        assert response.status_code == 200
        assert b"Access denied by bucket policy" not in response.data
        objects_response = client.get("/ui/buckets/testbucket/objects")
        assert objects_response.status_code == 403
    finally:
        _shutdown_app(app)
