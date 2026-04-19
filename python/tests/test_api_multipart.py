import io
import pytest
from xml.etree.ElementTree import fromstring

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def auth_headers(app):
    return {
        "X-Access-Key": "test",
        "X-Secret-Key": "secret"
    }

def test_multipart_upload_flow(client, auth_headers):
    # 1. Create bucket
    client.put("/test-bucket", headers=auth_headers)

    # 2. Initiate Multipart Upload
    resp = client.post("/test-bucket/large-file.txt?uploads", headers=auth_headers)
    assert resp.status_code == 200
    root = fromstring(resp.data)
    upload_id = root.find("UploadId").text
    assert upload_id

    # 3. Upload Part 1
    resp = client.put(
        f"/test-bucket/large-file.txt?partNumber=1&uploadId={upload_id}",
        headers=auth_headers,
        data=b"part1"
    )
    assert resp.status_code == 200
    etag1 = resp.headers["ETag"]
    assert etag1

    # 4. Upload Part 2
    resp = client.put(
        f"/test-bucket/large-file.txt?partNumber=2&uploadId={upload_id}",
        headers=auth_headers,
        data=b"part2"
    )
    assert resp.status_code == 200
    etag2 = resp.headers["ETag"]
    assert etag2

    # 5. Complete Multipart Upload
    xml_body = f"""
    <CompleteMultipartUpload>
        <Part>
            <PartNumber>1</PartNumber>
            <ETag>{etag1}</ETag>
        </Part>
        <Part>
            <PartNumber>2</PartNumber>
            <ETag>{etag2}</ETag>
        </Part>
    </CompleteMultipartUpload>
    """
    resp = client.post(
        f"/test-bucket/large-file.txt?uploadId={upload_id}",
        headers=auth_headers,
        data=xml_body
    )
    assert resp.status_code == 200
    root = fromstring(resp.data)
    assert root.find("Key").text == "large-file.txt"

    # 6. Verify object content
    resp = client.get("/test-bucket/large-file.txt", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.data == b"part1part2"

def test_abort_multipart_upload(client, auth_headers):
    client.put("/abort-bucket", headers=auth_headers)

    resp = client.post("/abort-bucket/file.txt?uploads", headers=auth_headers)
    upload_id = fromstring(resp.data).find("UploadId").text

    resp = client.delete(f"/abort-bucket/file.txt?uploadId={upload_id}", headers=auth_headers)
    assert resp.status_code == 204

    resp = client.put(
        f"/abort-bucket/file.txt?partNumber=1&uploadId={upload_id}",
        headers=auth_headers,
        data=b"data"
    )
    assert resp.status_code == 404
