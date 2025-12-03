import hashlib
import hmac
import pytest
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

def _sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

def _get_signature_key(key, date_stamp, region_name, service_name):
    k_date = _sign(("AWS4" + key).encode("utf-8"), date_stamp)
    k_region = _sign(k_date, region_name)
    k_service = _sign(k_region, service_name)
    k_signing = _sign(k_service, "aws4_request")
    return k_signing

def create_signed_headers(
    method,
    path,
    headers=None,
    body=None,
    access_key="test",
    secret_key="secret",
    region="us-east-1",
    service="s3",
    timestamp=None
):
    if headers is None:
        headers = {}
    
    if timestamp is None:
        now = datetime.now(timezone.utc)
    else:
        now = timestamp
        
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    
    headers["X-Amz-Date"] = amz_date
    headers["Host"] = "testserver"
    
    canonical_uri = quote(path, safe="/-_.~")
    canonical_query_string = ""
    
    canonical_headers = ""
    signed_headers_list = []
    for k, v in sorted(headers.items(), key=lambda x: x[0].lower()):
        canonical_headers += f"{k.lower()}:{v.strip()}\n"
        signed_headers_list.append(k.lower())
    
    signed_headers = ";".join(signed_headers_list)
    
    payload_hash = hashlib.sha256(body or b"").hexdigest()
    headers["X-Amz-Content-Sha256"] = payload_hash
    
    canonical_request = f"{method}\n{canonical_uri}\n{canonical_query_string}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
    
    signing_key = _get_signature_key(secret_key, date_stamp, region, service)
    signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    
    headers["Authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    return headers

def test_sigv4_old_date(client):
    # Test with a date 20 minutes in the past
    old_time = datetime.now(timezone.utc) - timedelta(minutes=20)
    headers = create_signed_headers("GET", "/", timestamp=old_time)
    
    response = client.get("/", headers=headers)
    assert response.status_code == 403
    assert b"Request timestamp too old" in response.data

def test_sigv4_future_date(client):
    # Test with a date 20 minutes in the future
    future_time = datetime.now(timezone.utc) + timedelta(minutes=20)
    headers = create_signed_headers("GET", "/", timestamp=future_time)
    
    response = client.get("/", headers=headers)
    assert response.status_code == 403
    assert b"Request timestamp too old" in response.data # The error message is the same

def test_path_traversal_in_key(client, signer):
    headers = signer("PUT", "/test-bucket")
    client.put("/test-bucket", headers=headers)
    
    # Try to upload with .. in key
    headers = signer("PUT", "/test-bucket/../secret.txt", body=b"attack")
    response = client.put("/test-bucket/../secret.txt", headers=headers, data=b"attack")
    
    # Should be rejected by storage layer or flask routing
    # Flask might normalize it before it reaches the app, but if it reaches, it should fail.
    # If Flask normalizes /test-bucket/../secret.txt to /secret.txt, then it hits 404 (bucket not found) or 403.
    # But we want to test the storage layer check.
    # We can try to encode the dots?
    
    # If we use a key that doesn't get normalized by Flask routing easily.
    # But wait, the route is /<bucket_name>/<path:object_key>
    # If I send /test-bucket/folder/../file.txt, Flask might pass "folder/../file.txt" as object_key?
    # Let's try.
    
    headers = signer("PUT", "/test-bucket/folder/../file.txt", body=b"attack")
    response = client.put("/test-bucket/folder/../file.txt", headers=headers, data=b"attack")
    
    # If Flask normalizes it, it becomes /test-bucket/file.txt.
    # If it doesn't, it hits our check.
    
    # Let's try to call the storage method directly to verify the check works, 
    # because testing via client depends on Flask's URL handling.
    pass

def test_storage_path_traversal(app):
    storage = app.extensions["object_storage"]
    from app.storage import StorageError, ObjectStorage
    from app.encrypted_storage import EncryptedObjectStorage
    
    # Get the underlying ObjectStorage if wrapped
    if isinstance(storage, EncryptedObjectStorage):
        storage = storage.storage
    
    with pytest.raises(StorageError, match="Object key contains parent directory references"):
        storage._sanitize_object_key("folder/../file.txt")
        
    with pytest.raises(StorageError, match="Object key contains parent directory references"):
        storage._sanitize_object_key("..")

def test_head_bucket(client, signer):
    headers = signer("PUT", "/head-test")
    client.put("/head-test", headers=headers)
    
    headers = signer("HEAD", "/head-test")
    response = client.head("/head-test", headers=headers)
    assert response.status_code == 200
    
    headers = signer("HEAD", "/non-existent")
    response = client.head("/non-existent", headers=headers)
    assert response.status_code == 404

def test_head_object(client, signer):
    headers = signer("PUT", "/head-obj-test")
    client.put("/head-obj-test", headers=headers)
    
    headers = signer("PUT", "/head-obj-test/obj", body=b"content")
    client.put("/head-obj-test/obj", headers=headers, data=b"content")
    
    headers = signer("HEAD", "/head-obj-test/obj")
    response = client.head("/head-obj-test/obj", headers=headers)
    assert response.status_code == 200
    assert response.headers["ETag"]
    assert response.headers["Content-Length"] == "7"
    
    headers = signer("HEAD", "/head-obj-test/missing")
    response = client.head("/head-obj-test/missing", headers=headers)
    assert response.status_code == 404

def test_list_parts(client, signer):
    # Create bucket
    headers = signer("PUT", "/multipart-test")
    client.put("/multipart-test", headers=headers)

    # Initiate multipart upload
    headers = signer("POST", "/multipart-test/obj?uploads")
    response = client.post("/multipart-test/obj?uploads", headers=headers)
    assert response.status_code == 200
    from xml.etree.ElementTree import fromstring
    upload_id = fromstring(response.data).find("UploadId").text
    
    # Upload part 1
    headers = signer("PUT", f"/multipart-test/obj?partNumber=1&uploadId={upload_id}", body=b"part1")
    client.put(f"/multipart-test/obj?partNumber=1&uploadId={upload_id}", headers=headers, data=b"part1")
    
    # Upload part 2
    headers = signer("PUT", f"/multipart-test/obj?partNumber=2&uploadId={upload_id}", body=b"part2")
    client.put(f"/multipart-test/obj?partNumber=2&uploadId={upload_id}", headers=headers, data=b"part2")
    
    # List parts
    headers = signer("GET", f"/multipart-test/obj?uploadId={upload_id}")
    response = client.get(f"/multipart-test/obj?uploadId={upload_id}", headers=headers)
    assert response.status_code == 200
    
    root = fromstring(response.data)
    assert root.tag == "ListPartsResult"
    parts = root.findall("Part")
    assert len(parts) == 2
    assert parts[0].find("PartNumber").text == "1"
    assert parts[1].find("PartNumber").text == "2"
