import io
import json
from pathlib import Path

from app import create_app


def _build_app(tmp_path: Path):
    storage_root = tmp_path / "data"
    iam_config = tmp_path / "iam.json"
    bucket_policies = tmp_path / "bucket_policies.json"
    iam_payload = {
        "users": [
            {
                "access_key": "test",
                "secret_key": "secret",
                "display_name": "Bulk Tester",
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
            "API_BASE_URL": "http://localhost",
            "SECRET_KEY": "testing",
        }
    )
    return app


def _login(client):
    return client.post(
        "/ui/login",
        data={"access_key": "test", "secret_key": "secret"},
        follow_redirects=True,
    )


def test_bulk_delete_json_route(tmp_path: Path):
    app = _build_app(tmp_path)
    storage = app.extensions["object_storage"]
    storage.create_bucket("demo")
    storage.put_object("demo", "first.txt", io.BytesIO(b"first"))
    storage.put_object("demo", "second.txt", io.BytesIO(b"second"))

    client = app.test_client()
    assert _login(client).status_code == 200

    response = client.post(
        "/ui/buckets/demo/objects/bulk-delete",
        json={"keys": ["first.txt", "missing.txt"]},
        headers={"X-Requested-With": "XMLHttpRequest"},
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ok"
    assert set(payload["deleted"]) == {"first.txt", "missing.txt"}
    assert payload["errors"] == []

    listing = storage.list_objects_all("demo")
    assert {meta.key for meta in listing} == {"second.txt"}


def test_bulk_delete_validation(tmp_path: Path):
    app = _build_app(tmp_path)
    storage = app.extensions["object_storage"]
    storage.create_bucket("demo")
    storage.put_object("demo", "keep.txt", io.BytesIO(b"keep"))

    client = app.test_client()
    assert _login(client).status_code == 200

    bad_response = client.post(
        "/ui/buckets/demo/objects/bulk-delete",
        json={"keys": []},
        headers={"X-Requested-With": "XMLHttpRequest"},
    )
    assert bad_response.status_code == 400
    assert bad_response.get_json()["status"] == "error"

    too_many = [f"obj-{index}.txt" for index in range(501)]
    limit_response = client.post(
        "/ui/buckets/demo/objects/bulk-delete",
        json={"keys": too_many},
        headers={"X-Requested-With": "XMLHttpRequest"},
    )
    assert limit_response.status_code == 400
    assert limit_response.get_json()["status"] == "error"

    still_there = storage.list_objects_all("demo")
    assert {meta.key for meta in still_there} == {"keep.txt"}
