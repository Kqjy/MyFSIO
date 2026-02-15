import io
import json
from pathlib import Path
from xml.etree.ElementTree import fromstring

import pytest

from app import create_api_app
from app.website_domains import WebsiteDomainStore


def _stream(data: bytes):
    return io.BytesIO(data)


@pytest.fixture()
def website_app(tmp_path: Path):
    storage_root = tmp_path / "data"
    iam_config = tmp_path / "iam.json"
    bucket_policies = tmp_path / "bucket_policies.json"
    iam_payload = {
        "users": [
            {
                "access_key": "test",
                "secret_key": "secret",
                "display_name": "Test User",
                "policies": [{"bucket": "*", "actions": ["list", "read", "write", "delete", "policy", "iam:*"]}],
            }
        ]
    }
    iam_config.write_text(json.dumps(iam_payload))
    flask_app = create_api_app(
        {
            "TESTING": True,
            "SECRET_KEY": "testing",
            "STORAGE_ROOT": storage_root,
            "IAM_CONFIG": iam_config,
            "BUCKET_POLICY_PATH": bucket_policies,
            "API_BASE_URL": "http://testserver",
            "WEBSITE_HOSTING_ENABLED": True,
        }
    )
    yield flask_app


@pytest.fixture()
def website_client(website_app):
    return website_app.test_client()


@pytest.fixture()
def storage(website_app):
    return website_app.extensions["object_storage"]


class TestWebsiteDomainStore:
    def test_empty_store(self, tmp_path):
        store = WebsiteDomainStore(tmp_path / "domains.json")
        assert store.list_all() == []
        assert store.get_bucket("example.com") is None

    def test_set_and_get_mapping(self, tmp_path):
        store = WebsiteDomainStore(tmp_path / "domains.json")
        store.set_mapping("example.com", "my-site")
        assert store.get_bucket("example.com") == "my-site"

    def test_case_insensitive(self, tmp_path):
        store = WebsiteDomainStore(tmp_path / "domains.json")
        store.set_mapping("Example.COM", "my-site")
        assert store.get_bucket("example.com") == "my-site"
        assert store.get_bucket("EXAMPLE.COM") == "my-site"

    def test_list_all(self, tmp_path):
        store = WebsiteDomainStore(tmp_path / "domains.json")
        store.set_mapping("a.com", "bucket-a")
        store.set_mapping("b.com", "bucket-b")
        result = store.list_all()
        domains = {item["domain"] for item in result}
        assert domains == {"a.com", "b.com"}

    def test_delete_mapping(self, tmp_path):
        store = WebsiteDomainStore(tmp_path / "domains.json")
        store.set_mapping("example.com", "my-site")
        assert store.delete_mapping("example.com") is True
        assert store.get_bucket("example.com") is None

    def test_delete_nonexistent(self, tmp_path):
        store = WebsiteDomainStore(tmp_path / "domains.json")
        assert store.delete_mapping("nope.com") is False

    def test_overwrite_mapping(self, tmp_path):
        store = WebsiteDomainStore(tmp_path / "domains.json")
        store.set_mapping("example.com", "old-bucket")
        store.set_mapping("example.com", "new-bucket")
        assert store.get_bucket("example.com") == "new-bucket"

    def test_persistence(self, tmp_path):
        path = tmp_path / "domains.json"
        store1 = WebsiteDomainStore(path)
        store1.set_mapping("example.com", "my-site")
        store2 = WebsiteDomainStore(path)
        assert store2.get_bucket("example.com") == "my-site"

    def test_corrupt_file(self, tmp_path):
        path = tmp_path / "domains.json"
        path.write_text("not json")
        store = WebsiteDomainStore(path)
        assert store.list_all() == []

    def test_non_dict_file(self, tmp_path):
        path = tmp_path / "domains.json"
        path.write_text('["not", "a", "dict"]')
        store = WebsiteDomainStore(path)
        assert store.list_all() == []


class TestStorageWebsiteConfig:
    def test_get_website_no_config(self, storage):
        storage.create_bucket("test-bucket")
        assert storage.get_bucket_website("test-bucket") is None

    def test_set_and_get_website(self, storage):
        storage.create_bucket("test-bucket")
        config = {"index_document": "index.html", "error_document": "error.html"}
        storage.set_bucket_website("test-bucket", config)
        result = storage.get_bucket_website("test-bucket")
        assert result["index_document"] == "index.html"
        assert result["error_document"] == "error.html"

    def test_delete_website_config(self, storage):
        storage.create_bucket("test-bucket")
        storage.set_bucket_website("test-bucket", {"index_document": "index.html"})
        storage.set_bucket_website("test-bucket", None)
        assert storage.get_bucket_website("test-bucket") is None

    def test_nonexistent_bucket(self, storage):
        with pytest.raises(Exception):
            storage.get_bucket_website("no-such-bucket")


class TestS3WebsiteAPI:
    def test_put_website_config(self, website_client, signer):
        headers = signer("PUT", "/site-bucket")
        assert website_client.put("/site-bucket", headers=headers).status_code == 200

        xml_body = b"""<WebsiteConfiguration>
            <IndexDocument><Suffix>index.html</Suffix></IndexDocument>
            <ErrorDocument><Key>404.html</Key></ErrorDocument>
        </WebsiteConfiguration>"""
        headers = signer("PUT", "/site-bucket?website",
                         headers={"Content-Type": "application/xml"}, body=xml_body)
        resp = website_client.put("/site-bucket", query_string={"website": ""},
                                  headers=headers, data=xml_body, content_type="application/xml")
        assert resp.status_code == 200

    def test_get_website_config(self, website_client, signer, storage):
        storage.create_bucket("site-bucket")
        storage.set_bucket_website("site-bucket", {
            "index_document": "index.html",
            "error_document": "error.html",
        })

        headers = signer("GET", "/site-bucket?website")
        resp = website_client.get("/site-bucket", query_string={"website": ""}, headers=headers)
        assert resp.status_code == 200

        root = fromstring(resp.data)
        suffix = root.find(".//{http://s3.amazonaws.com/doc/2006-03-01/}Suffix")
        if suffix is None:
            suffix = root.find(".//Suffix")
        assert suffix is not None
        assert suffix.text == "index.html"

    def test_get_website_config_not_set(self, website_client, signer, storage):
        storage.create_bucket("no-website")
        headers = signer("GET", "/no-website?website")
        resp = website_client.get("/no-website", query_string={"website": ""}, headers=headers)
        assert resp.status_code == 404

    def test_delete_website_config(self, website_client, signer, storage):
        storage.create_bucket("site-bucket")
        storage.set_bucket_website("site-bucket", {"index_document": "index.html"})

        headers = signer("DELETE", "/site-bucket?website")
        resp = website_client.delete("/site-bucket", query_string={"website": ""}, headers=headers)
        assert resp.status_code == 204
        assert storage.get_bucket_website("site-bucket") is None

    def test_put_website_missing_index(self, website_client, signer, storage):
        storage.create_bucket("site-bucket")
        xml_body = b"""<WebsiteConfiguration>
            <ErrorDocument><Key>error.html</Key></ErrorDocument>
        </WebsiteConfiguration>"""
        headers = signer("PUT", "/site-bucket?website",
                         headers={"Content-Type": "application/xml"}, body=xml_body)
        resp = website_client.put("/site-bucket", query_string={"website": ""},
                                  headers=headers, data=xml_body, content_type="application/xml")
        assert resp.status_code == 400

    def test_put_website_slash_in_suffix(self, website_client, signer, storage):
        storage.create_bucket("site-bucket")
        xml_body = b"""<WebsiteConfiguration>
            <IndexDocument><Suffix>path/index.html</Suffix></IndexDocument>
        </WebsiteConfiguration>"""
        headers = signer("PUT", "/site-bucket?website",
                         headers={"Content-Type": "application/xml"}, body=xml_body)
        resp = website_client.put("/site-bucket", query_string={"website": ""},
                                  headers=headers, data=xml_body, content_type="application/xml")
        assert resp.status_code == 400

    def test_put_website_malformed_xml(self, website_client, signer, storage):
        storage.create_bucket("site-bucket")
        xml_body = b"not xml at all"
        headers = signer("PUT", "/site-bucket?website",
                         headers={"Content-Type": "application/xml"}, body=xml_body)
        resp = website_client.put("/site-bucket", query_string={"website": ""},
                                  headers=headers, data=xml_body, content_type="application/xml")
        assert resp.status_code == 400

    def test_website_disabled(self, client, signer):
        headers = signer("PUT", "/test-bucket")
        assert client.put("/test-bucket", headers=headers).status_code == 200
        headers = signer("GET", "/test-bucket?website")
        resp = client.get("/test-bucket", query_string={"website": ""}, headers=headers)
        assert resp.status_code == 400
        assert b"not enabled" in resp.data


class TestAdminWebsiteDomains:
    def _admin_headers(self, signer):
        return signer("GET", "/admin/website-domains")

    def test_list_empty(self, website_client, signer):
        headers = self._admin_headers(signer)
        resp = website_client.get("/admin/website-domains", headers=headers)
        assert resp.status_code == 200
        assert resp.get_json() == []

    def test_create_mapping(self, website_client, signer, storage):
        storage.create_bucket("my-site")
        headers = signer("POST", "/admin/website-domains",
                         headers={"Content-Type": "application/json"},
                         body=json.dumps({"domain": "example.com", "bucket": "my-site"}).encode())
        resp = website_client.post("/admin/website-domains",
                                   headers=headers,
                                   json={"domain": "example.com", "bucket": "my-site"})
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["domain"] == "example.com"
        assert data["bucket"] == "my-site"

    def test_create_duplicate(self, website_client, signer, storage):
        storage.create_bucket("my-site")
        body = json.dumps({"domain": "dup.com", "bucket": "my-site"}).encode()
        headers = signer("POST", "/admin/website-domains",
                         headers={"Content-Type": "application/json"}, body=body)
        website_client.post("/admin/website-domains", headers=headers,
                            json={"domain": "dup.com", "bucket": "my-site"})
        headers = signer("POST", "/admin/website-domains",
                         headers={"Content-Type": "application/json"}, body=body)
        resp = website_client.post("/admin/website-domains", headers=headers,
                                   json={"domain": "dup.com", "bucket": "my-site"})
        assert resp.status_code == 409

    def test_create_missing_domain(self, website_client, signer, storage):
        storage.create_bucket("my-site")
        body = json.dumps({"bucket": "my-site"}).encode()
        headers = signer("POST", "/admin/website-domains",
                         headers={"Content-Type": "application/json"}, body=body)
        resp = website_client.post("/admin/website-domains", headers=headers,
                                   json={"bucket": "my-site"})
        assert resp.status_code == 400

    def test_create_nonexistent_bucket(self, website_client, signer):
        body = json.dumps({"domain": "x.com", "bucket": "no-such"}).encode()
        headers = signer("POST", "/admin/website-domains",
                         headers={"Content-Type": "application/json"}, body=body)
        resp = website_client.post("/admin/website-domains", headers=headers,
                                   json={"domain": "x.com", "bucket": "no-such"})
        assert resp.status_code == 404

    def test_get_mapping(self, website_client, signer, storage):
        storage.create_bucket("my-site")
        body = json.dumps({"domain": "get.com", "bucket": "my-site"}).encode()
        headers = signer("POST", "/admin/website-domains",
                         headers={"Content-Type": "application/json"}, body=body)
        website_client.post("/admin/website-domains", headers=headers,
                            json={"domain": "get.com", "bucket": "my-site"})

        headers = signer("GET", "/admin/website-domains/get.com")
        resp = website_client.get("/admin/website-domains/get.com", headers=headers)
        assert resp.status_code == 200
        assert resp.get_json()["bucket"] == "my-site"

    def test_get_nonexistent(self, website_client, signer):
        headers = signer("GET", "/admin/website-domains/nope.com")
        resp = website_client.get("/admin/website-domains/nope.com", headers=headers)
        assert resp.status_code == 404

    def test_update_mapping(self, website_client, signer, storage):
        storage.create_bucket("old-bucket")
        storage.create_bucket("new-bucket")
        body = json.dumps({"domain": "upd.com", "bucket": "old-bucket"}).encode()
        headers = signer("POST", "/admin/website-domains",
                         headers={"Content-Type": "application/json"}, body=body)
        website_client.post("/admin/website-domains", headers=headers,
                            json={"domain": "upd.com", "bucket": "old-bucket"})

        body = json.dumps({"bucket": "new-bucket"}).encode()
        headers = signer("PUT", "/admin/website-domains/upd.com",
                         headers={"Content-Type": "application/json"}, body=body)
        resp = website_client.put("/admin/website-domains/upd.com", headers=headers,
                                  json={"bucket": "new-bucket"})
        assert resp.status_code == 200
        assert resp.get_json()["bucket"] == "new-bucket"

    def test_delete_mapping(self, website_client, signer, storage):
        storage.create_bucket("del-bucket")
        body = json.dumps({"domain": "del.com", "bucket": "del-bucket"}).encode()
        headers = signer("POST", "/admin/website-domains",
                         headers={"Content-Type": "application/json"}, body=body)
        website_client.post("/admin/website-domains", headers=headers,
                            json={"domain": "del.com", "bucket": "del-bucket"})

        headers = signer("DELETE", "/admin/website-domains/del.com")
        resp = website_client.delete("/admin/website-domains/del.com", headers=headers)
        assert resp.status_code == 204

    def test_delete_nonexistent(self, website_client, signer):
        headers = signer("DELETE", "/admin/website-domains/nope.com")
        resp = website_client.delete("/admin/website-domains/nope.com", headers=headers)
        assert resp.status_code == 404

    def test_disabled(self, website_client, signer):
        with website_client.application.test_request_context():
            website_client.application.config["WEBSITE_HOSTING_ENABLED"] = False
        headers = signer("GET", "/admin/website-domains")
        resp = website_client.get("/admin/website-domains", headers=headers)
        assert resp.status_code == 400
        website_client.application.config["WEBSITE_HOSTING_ENABLED"] = True


class TestWebsiteServing:
    def _setup_website(self, storage, website_app):
        storage.create_bucket("my-site")
        storage.put_object("my-site", "index.html", _stream(b"<h1>Home</h1>"))
        storage.put_object("my-site", "about.html", _stream(b"<h1>About</h1>"))
        storage.put_object("my-site", "assets/style.css", _stream(b"body { color: red; }"))
        storage.put_object("my-site", "sub/index.html", _stream(b"<h1>Sub</h1>"))
        storage.put_object("my-site", "404.html", _stream(b"<h1>Not Found</h1>"))
        storage.set_bucket_website("my-site", {
            "index_document": "index.html",
            "error_document": "404.html",
        })
        store = website_app.extensions["website_domains"]
        store.set_mapping("mysite.example.com", "my-site")

    def test_serve_index(self, website_client, storage, website_app):
        self._setup_website(storage, website_app)
        resp = website_client.get("/", headers={"Host": "mysite.example.com"})
        assert resp.status_code == 200
        assert b"<h1>Home</h1>" in resp.data
        assert "text/html" in resp.content_type

    def test_serve_specific_file(self, website_client, storage, website_app):
        self._setup_website(storage, website_app)
        resp = website_client.get("/about.html", headers={"Host": "mysite.example.com"})
        assert resp.status_code == 200
        assert b"<h1>About</h1>" in resp.data

    def test_serve_css(self, website_client, storage, website_app):
        self._setup_website(storage, website_app)
        resp = website_client.get("/assets/style.css", headers={"Host": "mysite.example.com"})
        assert resp.status_code == 200
        assert b"body { color: red; }" in resp.data
        assert "text/css" in resp.content_type

    def test_serve_subdirectory_index(self, website_client, storage, website_app):
        self._setup_website(storage, website_app)
        resp = website_client.get("/sub/", headers={"Host": "mysite.example.com"})
        assert resp.status_code == 200
        assert b"<h1>Sub</h1>" in resp.data

    def test_serve_subdirectory_no_trailing_slash(self, website_client, storage, website_app):
        self._setup_website(storage, website_app)
        resp = website_client.get("/sub", headers={"Host": "mysite.example.com"})
        assert resp.status_code == 200
        assert b"<h1>Sub</h1>" in resp.data

    def test_serve_error_document(self, website_client, storage, website_app):
        self._setup_website(storage, website_app)
        resp = website_client.get("/nonexistent.html", headers={"Host": "mysite.example.com"})
        assert resp.status_code == 404
        assert b"<h1>Not Found</h1>" in resp.data

    def test_unmapped_host_passes_through(self, website_client, storage, website_app):
        self._setup_website(storage, website_app)
        resp = website_client.get("/", headers={"Host": "unknown.example.com"})
        assert resp.status_code != 200 or b"<h1>Home</h1>" not in resp.data

    def test_head_request(self, website_client, storage, website_app):
        self._setup_website(storage, website_app)
        resp = website_client.head("/index.html", headers={"Host": "mysite.example.com"})
        assert resp.status_code == 200
        assert "Content-Length" in resp.headers
        assert resp.data == b""

    def test_post_not_intercepted(self, website_client, storage, website_app):
        self._setup_website(storage, website_app)
        resp = website_client.post("/index.html", headers={"Host": "mysite.example.com"})
        assert resp.status_code != 200 or b"<h1>Home</h1>" not in resp.data

    def test_bucket_deleted(self, website_client, storage, website_app):
        self._setup_website(storage, website_app)
        for obj in storage.list_objects_all("my-site"):
            storage.delete_object("my-site", obj.key)
        storage.delete_bucket("my-site")
        resp = website_client.get("/", headers={"Host": "mysite.example.com"})
        assert resp.status_code == 404

    def test_no_website_config(self, website_client, storage, website_app):
        storage.create_bucket("bare-bucket")
        store = website_app.extensions["website_domains"]
        store.set_mapping("bare.example.com", "bare-bucket")
        resp = website_client.get("/", headers={"Host": "bare.example.com"})
        assert resp.status_code == 404

    def test_host_with_port(self, website_client, storage, website_app):
        self._setup_website(storage, website_app)
        resp = website_client.get("/", headers={"Host": "mysite.example.com:5000"})
        assert resp.status_code == 200
        assert b"<h1>Home</h1>" in resp.data

    def test_no_error_document(self, website_client, storage, website_app):
        storage.create_bucket("no-err")
        storage.put_object("no-err", "index.html", _stream(b"<h1>Home</h1>"))
        storage.set_bucket_website("no-err", {"index_document": "index.html"})
        store = website_app.extensions["website_domains"]
        store.set_mapping("noerr.example.com", "no-err")
        resp = website_client.get("/missing.html", headers={"Host": "noerr.example.com"})
        assert resp.status_code == 404
        assert b"Not Found" in resp.data
