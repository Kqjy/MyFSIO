"""Tests for newly implemented S3 API endpoints."""
import io
import pytest
from xml.etree.ElementTree import fromstring


# Helper to create file-like stream
def _stream(data: bytes):
    return io.BytesIO(data)


@pytest.fixture
def storage(app):
    """Get the storage instance from the app."""
    return app.extensions["object_storage"]


class TestListObjectsV2:
    """Tests for ListObjectsV2 endpoint."""

    def test_list_objects_v2_basic(self, client, signer, storage):
        # Create bucket and objects
        storage.create_bucket("v2-test")
        storage.put_object("v2-test", "file1.txt", _stream(b"hello"))
        storage.put_object("v2-test", "file2.txt", _stream(b"world"))
        storage.put_object("v2-test", "folder/file3.txt", _stream(b"nested"))

        # ListObjectsV2 request
        headers = signer("GET", "/v2-test?list-type=2")
        resp = client.get("/v2-test", query_string={"list-type": "2"}, headers=headers)
        assert resp.status_code == 200

        root = fromstring(resp.data)
        assert root.find("KeyCount").text == "3"
        assert root.find("IsTruncated").text == "false"

        keys = [el.find("Key").text for el in root.findall("Contents")]
        assert "file1.txt" in keys
        assert "file2.txt" in keys
        assert "folder/file3.txt" in keys

    def test_list_objects_v2_with_prefix_and_delimiter(self, client, signer, storage):
        storage.create_bucket("prefix-test")
        storage.put_object("prefix-test", "photos/2023/jan.jpg", _stream(b"jan"))
        storage.put_object("prefix-test", "photos/2023/feb.jpg", _stream(b"feb"))
        storage.put_object("prefix-test", "photos/2024/mar.jpg", _stream(b"mar"))
        storage.put_object("prefix-test", "docs/readme.md", _stream(b"readme"))

        # List with prefix and delimiter
        headers = signer("GET", "/prefix-test?list-type=2&prefix=photos/&delimiter=/")
        resp = client.get(
            "/prefix-test",
            query_string={"list-type": "2", "prefix": "photos/", "delimiter": "/"},
            headers=headers
        )
        assert resp.status_code == 200

        root = fromstring(resp.data)
        # Should show common prefixes for 2023/ and 2024/
        prefixes = [el.find("Prefix").text for el in root.findall("CommonPrefixes")]
        assert "photos/2023/" in prefixes
        assert "photos/2024/" in prefixes
        assert len(root.findall("Contents")) == 0  # No direct files under photos/


class TestPutBucketVersioning:
    """Tests for PutBucketVersioning endpoint."""

    def test_put_versioning_enabled(self, client, signer, storage):
        storage.create_bucket("version-test")

        payload = b"""<?xml version="1.0" encoding="UTF-8"?>
        <VersioningConfiguration>
            <Status>Enabled</Status>
        </VersioningConfiguration>"""

        headers = signer("PUT", "/version-test?versioning", body=payload)
        resp = client.put("/version-test", query_string={"versioning": ""}, data=payload, headers=headers)
        assert resp.status_code == 200

        # Verify via GET
        headers = signer("GET", "/version-test?versioning")
        resp = client.get("/version-test", query_string={"versioning": ""}, headers=headers)
        root = fromstring(resp.data)
        assert root.find("Status").text == "Enabled"

    def test_put_versioning_suspended(self, client, signer, storage):
        storage.create_bucket("suspend-test")
        storage.set_bucket_versioning("suspend-test", True)

        payload = b"""<?xml version="1.0" encoding="UTF-8"?>
        <VersioningConfiguration>
            <Status>Suspended</Status>
        </VersioningConfiguration>"""

        headers = signer("PUT", "/suspend-test?versioning", body=payload)
        resp = client.put("/suspend-test", query_string={"versioning": ""}, data=payload, headers=headers)
        assert resp.status_code == 200

        headers = signer("GET", "/suspend-test?versioning")
        resp = client.get("/suspend-test", query_string={"versioning": ""}, headers=headers)
        root = fromstring(resp.data)
        assert root.find("Status").text == "Suspended"


class TestDeleteBucketTagging:
    """Tests for DeleteBucketTagging endpoint."""

    def test_delete_bucket_tags(self, client, signer, storage):
        storage.create_bucket("tag-delete-test")
        storage.set_bucket_tags("tag-delete-test", [{"Key": "env", "Value": "test"}])

        # Delete tags
        headers = signer("DELETE", "/tag-delete-test?tagging")
        resp = client.delete("/tag-delete-test", query_string={"tagging": ""}, headers=headers)
        assert resp.status_code == 204

        # Verify tags are gone
        headers = signer("GET", "/tag-delete-test?tagging")
        resp = client.get("/tag-delete-test", query_string={"tagging": ""}, headers=headers)
        assert resp.status_code == 404  # NoSuchTagSet


class TestDeleteBucketCors:
    """Tests for DeleteBucketCors endpoint."""

    def test_delete_bucket_cors(self, client, signer, storage):
        storage.create_bucket("cors-delete-test")
        storage.set_bucket_cors("cors-delete-test", [
            {"AllowedOrigins": ["*"], "AllowedMethods": ["GET"]}
        ])

        # Delete CORS
        headers = signer("DELETE", "/cors-delete-test?cors")
        resp = client.delete("/cors-delete-test", query_string={"cors": ""}, headers=headers)
        assert resp.status_code == 204

        # Verify CORS is gone
        headers = signer("GET", "/cors-delete-test?cors")
        resp = client.get("/cors-delete-test", query_string={"cors": ""}, headers=headers)
        assert resp.status_code == 404  # NoSuchCORSConfiguration


class TestGetBucketLocation:
    """Tests for GetBucketLocation endpoint."""

    def test_get_bucket_location(self, client, signer, storage):
        storage.create_bucket("location-test")

        headers = signer("GET", "/location-test?location")
        resp = client.get("/location-test", query_string={"location": ""}, headers=headers)
        assert resp.status_code == 200

        root = fromstring(resp.data)
        assert root.tag == "LocationConstraint"


class TestBucketAcl:
    """Tests for Bucket ACL operations."""

    def test_get_bucket_acl(self, client, signer, storage):
        storage.create_bucket("acl-test")

        headers = signer("GET", "/acl-test?acl")
        resp = client.get("/acl-test", query_string={"acl": ""}, headers=headers)
        assert resp.status_code == 200

        root = fromstring(resp.data)
        assert root.tag == "AccessControlPolicy"
        assert root.find("Owner/ID") is not None
        assert root.find(".//Permission").text == "FULL_CONTROL"

    def test_put_bucket_acl(self, client, signer, storage):
        storage.create_bucket("acl-put-test")

        # PUT with canned ACL header
        headers = signer("PUT", "/acl-put-test?acl")
        headers["x-amz-acl"] = "public-read"
        resp = client.put("/acl-put-test", query_string={"acl": ""}, headers=headers)
        assert resp.status_code == 200


class TestCopyObject:
    """Tests for CopyObject operation."""

    def test_copy_object_basic(self, client, signer, storage):
        storage.create_bucket("copy-src")
        storage.create_bucket("copy-dst")
        storage.put_object("copy-src", "original.txt", _stream(b"original content"))

        # Copy object
        headers = signer("PUT", "/copy-dst/copied.txt")
        headers["x-amz-copy-source"] = "/copy-src/original.txt"
        resp = client.put("/copy-dst/copied.txt", headers=headers)
        assert resp.status_code == 200

        root = fromstring(resp.data)
        assert root.tag == "CopyObjectResult"
        assert root.find("ETag") is not None
        assert root.find("LastModified") is not None

        # Verify copy exists
        path = storage.get_object_path("copy-dst", "copied.txt")
        assert path.read_bytes() == b"original content"

    def test_copy_object_with_metadata_replace(self, client, signer, storage):
        storage.create_bucket("meta-src")
        storage.create_bucket("meta-dst")
        storage.put_object("meta-src", "source.txt", _stream(b"data"), metadata={"old": "value"})

        # Copy with REPLACE directive
        headers = signer("PUT", "/meta-dst/target.txt")
        headers["x-amz-copy-source"] = "/meta-src/source.txt"
        headers["x-amz-metadata-directive"] = "REPLACE"
        headers["x-amz-meta-new"] = "metadata"
        resp = client.put("/meta-dst/target.txt", headers=headers)
        assert resp.status_code == 200

        # Verify new metadata (note: header keys are Title-Cased)
        meta = storage.get_object_metadata("meta-dst", "target.txt")
        assert "New" in meta or "new" in meta
        assert "old" not in meta and "Old" not in meta


class TestObjectTagging:
    """Tests for Object tagging operations."""

    def test_put_get_delete_object_tags(self, client, signer, storage):
        storage.create_bucket("obj-tag-test")
        storage.put_object("obj-tag-test", "tagged.txt", _stream(b"content"))

        # PUT tags
        payload = b"""<?xml version="1.0" encoding="UTF-8"?>
        <Tagging>
            <TagSet>
                <Tag><Key>project</Key><Value>demo</Value></Tag>
                <Tag><Key>env</Key><Value>test</Value></Tag>
            </TagSet>
        </Tagging>"""

        headers = signer("PUT", "/obj-tag-test/tagged.txt?tagging", body=payload)
        resp = client.put(
            "/obj-tag-test/tagged.txt",
            query_string={"tagging": ""},
            data=payload,
            headers=headers
        )
        assert resp.status_code == 204

        # GET tags
        headers = signer("GET", "/obj-tag-test/tagged.txt?tagging")
        resp = client.get("/obj-tag-test/tagged.txt", query_string={"tagging": ""}, headers=headers)
        assert resp.status_code == 200

        root = fromstring(resp.data)
        tags = {el.find("Key").text: el.find("Value").text for el in root.findall(".//Tag")}
        assert tags["project"] == "demo"
        assert tags["env"] == "test"

        # DELETE tags
        headers = signer("DELETE", "/obj-tag-test/tagged.txt?tagging")
        resp = client.delete("/obj-tag-test/tagged.txt", query_string={"tagging": ""}, headers=headers)
        assert resp.status_code == 204

        # Verify empty
        headers = signer("GET", "/obj-tag-test/tagged.txt?tagging")
        resp = client.get("/obj-tag-test/tagged.txt", query_string={"tagging": ""}, headers=headers)
        root = fromstring(resp.data)
        assert len(root.findall(".//Tag")) == 0

    def test_object_tags_limit(self, client, signer, storage):
        storage.create_bucket("tag-limit")
        storage.put_object("tag-limit", "file.txt", _stream(b"x"))

        # Try to set 11 tags (limit is 10)
        tags = "".join(f"<Tag><Key>key{i}</Key><Value>val{i}</Value></Tag>" for i in range(11))
        payload = f"<Tagging><TagSet>{tags}</TagSet></Tagging>".encode()

        headers = signer("PUT", "/tag-limit/file.txt?tagging", body=payload)
        resp = client.put(
            "/tag-limit/file.txt",
            query_string={"tagging": ""},
            data=payload,
            headers=headers
        )
        assert resp.status_code == 400
