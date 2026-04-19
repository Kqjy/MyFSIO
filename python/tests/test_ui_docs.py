import json
from pathlib import Path

from app import create_app


def _build_ui_app(tmp_path: Path):
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
    return create_app(
        {
            "TESTING": True,
            "STORAGE_ROOT": storage_root,
            "IAM_CONFIG": iam_config,
            "BUCKET_POLICY_PATH": bucket_policies,
            "API_BASE_URL": "http://example.test:9000",
            "SECRET_KEY": "testing",
        }
    )


def test_docs_requires_login(tmp_path: Path):
    app = _build_ui_app(tmp_path)
    client = app.test_client()
    response = client.get("/ui/docs")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/ui/login")


def test_docs_render_for_authenticated_user(tmp_path: Path):
    app = _build_ui_app(tmp_path)
    client = app.test_client()
    # Prime session by signing in
    login_response = client.post(
        "/ui/login",
        data={"access_key": "test", "secret_key": "secret"},
        follow_redirects=True,
    )
    assert login_response.status_code == 200

    response = client.get("/ui/docs")
    assert response.status_code == 200
    assert b"Your guide to MyFSIO" in response.data
    assert b"http://example.test:9000" in response.data
