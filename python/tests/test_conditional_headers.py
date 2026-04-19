import hashlib
import time

import pytest


@pytest.fixture()
def bucket(client, signer):
    headers = signer("PUT", "/cond-test")
    client.put("/cond-test", headers=headers)
    return "cond-test"


@pytest.fixture()
def uploaded(client, signer, bucket):
    body = b"hello conditional"
    etag = hashlib.md5(body).hexdigest()
    headers = signer("PUT", f"/{bucket}/obj.txt", body=body)
    resp = client.put(f"/{bucket}/obj.txt", headers=headers, data=body)
    last_modified = resp.headers.get("Last-Modified")
    return {"etag": etag, "last_modified": last_modified}


class TestIfMatch:
    def test_get_matching_etag(self, client, signer, bucket, uploaded):
        headers = signer("GET", f"/{bucket}/obj.txt", headers={"If-Match": f'"{uploaded["etag"]}"'})
        resp = client.get(f"/{bucket}/obj.txt", headers=headers)
        assert resp.status_code == 200

    def test_get_non_matching_etag(self, client, signer, bucket, uploaded):
        headers = signer("GET", f"/{bucket}/obj.txt", headers={"If-Match": '"wrongetag"'})
        resp = client.get(f"/{bucket}/obj.txt", headers=headers)
        assert resp.status_code == 412

    def test_head_matching_etag(self, client, signer, bucket, uploaded):
        headers = signer("HEAD", f"/{bucket}/obj.txt", headers={"If-Match": f'"{uploaded["etag"]}"'})
        resp = client.head(f"/{bucket}/obj.txt", headers=headers)
        assert resp.status_code == 200

    def test_head_non_matching_etag(self, client, signer, bucket, uploaded):
        headers = signer("HEAD", f"/{bucket}/obj.txt", headers={"If-Match": '"wrongetag"'})
        resp = client.head(f"/{bucket}/obj.txt", headers=headers)
        assert resp.status_code == 412

    def test_wildcard_match(self, client, signer, bucket, uploaded):
        headers = signer("GET", f"/{bucket}/obj.txt", headers={"If-Match": "*"})
        resp = client.get(f"/{bucket}/obj.txt", headers=headers)
        assert resp.status_code == 200

    def test_multiple_etags_one_matches(self, client, signer, bucket, uploaded):
        etag_list = f'"bad1", "{uploaded["etag"]}", "bad2"'
        headers = signer("GET", f"/{bucket}/obj.txt", headers={"If-Match": etag_list})
        resp = client.get(f"/{bucket}/obj.txt", headers=headers)
        assert resp.status_code == 200

    def test_multiple_etags_none_match(self, client, signer, bucket, uploaded):
        headers = signer("GET", f"/{bucket}/obj.txt", headers={"If-Match": '"bad1", "bad2"'})
        resp = client.get(f"/{bucket}/obj.txt", headers=headers)
        assert resp.status_code == 412


class TestIfNoneMatch:
    def test_get_matching_etag_returns_304(self, client, signer, bucket, uploaded):
        headers = signer("GET", f"/{bucket}/obj.txt", headers={"If-None-Match": f'"{uploaded["etag"]}"'})
        resp = client.get(f"/{bucket}/obj.txt", headers=headers)
        assert resp.status_code == 304
        assert uploaded["etag"] in resp.headers.get("ETag", "")

    def test_get_non_matching_etag_returns_200(self, client, signer, bucket, uploaded):
        headers = signer("GET", f"/{bucket}/obj.txt", headers={"If-None-Match": '"wrongetag"'})
        resp = client.get(f"/{bucket}/obj.txt", headers=headers)
        assert resp.status_code == 200

    def test_head_matching_etag_returns_304(self, client, signer, bucket, uploaded):
        headers = signer("HEAD", f"/{bucket}/obj.txt", headers={"If-None-Match": f'"{uploaded["etag"]}"'})
        resp = client.head(f"/{bucket}/obj.txt", headers=headers)
        assert resp.status_code == 304

    def test_head_non_matching_etag_returns_200(self, client, signer, bucket, uploaded):
        headers = signer("HEAD", f"/{bucket}/obj.txt", headers={"If-None-Match": '"wrongetag"'})
        resp = client.head(f"/{bucket}/obj.txt", headers=headers)
        assert resp.status_code == 200

    def test_wildcard_returns_304(self, client, signer, bucket, uploaded):
        headers = signer("GET", f"/{bucket}/obj.txt", headers={"If-None-Match": "*"})
        resp = client.get(f"/{bucket}/obj.txt", headers=headers)
        assert resp.status_code == 304


class TestIfModifiedSince:
    def test_not_modified_returns_304(self, client, signer, bucket, uploaded):
        headers = signer("GET", f"/{bucket}/obj.txt", headers={"If-Modified-Since": "Sun, 01 Jan 2034 00:00:00 GMT"})
        resp = client.get(f"/{bucket}/obj.txt", headers=headers)
        assert resp.status_code == 304
        assert "ETag" in resp.headers

    def test_modified_returns_200(self, client, signer, bucket, uploaded):
        headers = signer("GET", f"/{bucket}/obj.txt", headers={"If-Modified-Since": "Sun, 01 Jan 2000 00:00:00 GMT"})
        resp = client.get(f"/{bucket}/obj.txt", headers=headers)
        assert resp.status_code == 200

    def test_head_not_modified(self, client, signer, bucket, uploaded):
        headers = signer("HEAD", f"/{bucket}/obj.txt", headers={"If-Modified-Since": "Sun, 01 Jan 2034 00:00:00 GMT"})
        resp = client.head(f"/{bucket}/obj.txt", headers=headers)
        assert resp.status_code == 304

    def test_if_none_match_takes_precedence(self, client, signer, bucket, uploaded):
        headers = signer("GET", f"/{bucket}/obj.txt", headers={
            "If-None-Match": '"wrongetag"',
            "If-Modified-Since": "Sun, 01 Jan 2034 00:00:00 GMT",
        })
        resp = client.get(f"/{bucket}/obj.txt", headers=headers)
        assert resp.status_code == 200


class TestIfUnmodifiedSince:
    def test_unmodified_returns_200(self, client, signer, bucket, uploaded):
        headers = signer("GET", f"/{bucket}/obj.txt", headers={"If-Unmodified-Since": "Sun, 01 Jan 2034 00:00:00 GMT"})
        resp = client.get(f"/{bucket}/obj.txt", headers=headers)
        assert resp.status_code == 200

    def test_modified_returns_412(self, client, signer, bucket, uploaded):
        headers = signer("GET", f"/{bucket}/obj.txt", headers={"If-Unmodified-Since": "Sun, 01 Jan 2000 00:00:00 GMT"})
        resp = client.get(f"/{bucket}/obj.txt", headers=headers)
        assert resp.status_code == 412

    def test_head_modified_returns_412(self, client, signer, bucket, uploaded):
        headers = signer("HEAD", f"/{bucket}/obj.txt", headers={"If-Unmodified-Since": "Sun, 01 Jan 2000 00:00:00 GMT"})
        resp = client.head(f"/{bucket}/obj.txt", headers=headers)
        assert resp.status_code == 412

    def test_if_match_takes_precedence(self, client, signer, bucket, uploaded):
        headers = signer("GET", f"/{bucket}/obj.txt", headers={
            "If-Match": f'"{uploaded["etag"]}"',
            "If-Unmodified-Since": "Sun, 01 Jan 2000 00:00:00 GMT",
        })
        resp = client.get(f"/{bucket}/obj.txt", headers=headers)
        assert resp.status_code == 200


class TestConditionalWithRange:
    def test_if_match_with_range(self, client, signer, bucket, uploaded):
        headers = signer("GET", f"/{bucket}/obj.txt", headers={
            "If-Match": f'"{uploaded["etag"]}"',
            "Range": "bytes=0-4",
        })
        resp = client.get(f"/{bucket}/obj.txt", headers=headers)
        assert resp.status_code == 206

    def test_if_match_fails_with_range(self, client, signer, bucket, uploaded):
        headers = signer("GET", f"/{bucket}/obj.txt", headers={
            "If-Match": '"wrongetag"',
            "Range": "bytes=0-4",
        })
        resp = client.get(f"/{bucket}/obj.txt", headers=headers)
        assert resp.status_code == 412
