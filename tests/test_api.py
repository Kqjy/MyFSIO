def test_bucket_and_object_lifecycle(client, signer):
    headers = signer("PUT", "/photos")
    response = client.put("/photos", headers=headers)
    assert response.status_code == 200

    headers = signer("GET", "/")
    response = client.get("/", headers=headers)
    assert response.status_code == 200
    assert b"photos" in response.data

    data = b"hello world"
    headers = signer("PUT", "/photos/image.txt", body=data)
    response = client.put("/photos/image.txt", headers=headers, data=data)
    assert response.status_code == 200
    assert "ETag" in response.headers

    headers = signer("GET", "/photos")
    response = client.get("/photos", headers=headers)
    assert response.status_code == 200
    assert b"image.txt" in response.data

    headers = signer("GET", "/photos/image.txt")
    response = client.get("/photos/image.txt", headers=headers)
    assert response.status_code == 200
    assert response.data == b"hello world"

    headers = signer("DELETE", "/photos/image.txt")
    response = client.delete("/photos/image.txt", headers=headers)
    assert response.status_code == 204

    headers = signer("DELETE", "/photos")
    response = client.delete("/photos", headers=headers)
    assert response.status_code == 204


def test_bulk_delete_objects(client, signer):
    headers = signer("PUT", "/bulk")
    assert client.put("/bulk", headers=headers).status_code == 200
    
    headers = signer("PUT", "/bulk/first.txt", body=b"first")
    assert client.put("/bulk/first.txt", headers=headers, data=b"first").status_code == 200
    
    headers = signer("PUT", "/bulk/second.txt", body=b"second")
    assert client.put("/bulk/second.txt", headers=headers, data=b"second").status_code == 200

    delete_xml = b"""
    <Delete>
      <Object><Key>first.txt</Key></Object>
      <Object><Key>missing.txt</Key></Object>
    </Delete>
    """
    # Note: query_string is part of the path for signing
    headers = signer("POST", "/bulk?delete", headers={"Content-Type": "application/xml"}, body=delete_xml)
    response = client.post(
        "/bulk",
        headers=headers,
        query_string={"delete": ""},
        data=delete_xml,
    )
    assert response.status_code == 200
    assert b"<DeleteResult>" in response.data

    headers = signer("GET", "/bulk")
    listing = client.get("/bulk", headers=headers)
    assert b"first.txt" not in listing.data
    assert b"missing.txt" not in listing.data
    assert b"second.txt" in listing.data


def test_bulk_delete_rejects_version_ids(client, signer):
    headers = signer("PUT", "/bulkv")
    assert client.put("/bulkv", headers=headers).status_code == 200
    
    headers = signer("PUT", "/bulkv/keep.txt", body=b"keep")
    assert client.put("/bulkv/keep.txt", headers=headers, data=b"keep").status_code == 200

    delete_xml = b"""
    <Delete>
      <Object><Key>keep.txt</Key><VersionId>123</VersionId></Object>
    </Delete>
    """
    headers = signer("POST", "/bulkv?delete", headers={"Content-Type": "application/xml"}, body=delete_xml)
    response = client.post(
        "/bulkv",
        headers=headers,
        query_string={"delete": ""},
        data=delete_xml,
    )
    assert response.status_code == 200
    assert b"InvalidRequest" in response.data
    
    headers = signer("GET", "/bulkv")
    listing = client.get("/bulkv", headers=headers)
    assert b"keep.txt" in listing.data


def test_request_id_header_present(client, signer):
    headers = signer("GET", "/")
    response = client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.headers.get("X-Request-ID")


def test_healthcheck_returns_status(client):
    response = client.get("/myfsio/health")
    data = response.get_json()
    assert response.status_code == 200
    assert data["status"] == "ok"
    assert "version" not in data


def test_missing_credentials_denied(client):
    response = client.get("/")
    assert response.status_code == 403


def test_bucket_policies_deny_reads(client, signer):
    import json

    headers = signer("PUT", "/docs")
    assert client.put("/docs", headers=headers).status_code == 200

    headers = signer("PUT", "/docs/readme.txt", body=b"content")
    assert client.put("/docs/readme.txt", headers=headers, data=b"content").status_code == 200

    headers = signer("GET", "/docs/readme.txt")
    response = client.get("/docs/readme.txt", headers=headers)
    assert response.status_code == 200
    assert response.data == b"content"

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyReads",
                "Effect": "Deny",
                "Principal": "*",
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::docs/*"],
            }
        ],
    }
    policy_bytes = json.dumps(policy).encode("utf-8")
    headers = signer("PUT", "/docs?policy", headers={"Content-Type": "application/json"}, body=policy_bytes)
    assert client.put("/docs?policy", headers=headers, json=policy).status_code == 204

    headers = signer("GET", "/docs?policy")
    fetched = client.get("/docs?policy", headers=headers)
    assert fetched.status_code == 200
    assert fetched.get_json()["Version"] == "2012-10-17"

    headers = signer("GET", "/docs/readme.txt")
    denied = client.get("/docs/readme.txt", headers=headers)
    assert denied.status_code == 403

    headers = signer("DELETE", "/docs?policy")
    assert client.delete("/docs?policy", headers=headers).status_code == 204

    headers = signer("DELETE", "/docs/readme.txt")
    assert client.delete("/docs/readme.txt", headers=headers).status_code == 204

    headers = signer("DELETE", "/docs")
    assert client.delete("/docs", headers=headers).status_code == 204


def test_trailing_slash_returns_xml(client):
    response = client.get("/ghost/")
    assert response.status_code == 403
    assert response.mimetype == "application/xml"
    assert b"<Error>" in response.data


def test_public_policy_allows_anonymous_list_and_read(client, signer):
    import json

    headers = signer("PUT", "/public")
    assert client.put("/public", headers=headers).status_code == 200

    headers = signer("PUT", "/public/hello.txt", body=b"hi")
    assert client.put("/public/hello.txt", headers=headers, data=b"hi").status_code == 200

    assert client.get("/public").status_code == 403
    assert client.get("/public/hello.txt").status_code == 403

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowList",
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["s3:ListBucket"],
                "Resource": ["arn:aws:s3:::public"],
            },
            {
                "Sid": "AllowRead",
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::public/*"],
            },
        ],
    }
    policy_bytes = json.dumps(policy).encode("utf-8")
    headers = signer("PUT", "/public?policy", headers={"Content-Type": "application/json"}, body=policy_bytes)
    assert client.put("/public?policy", headers=headers, json=policy).status_code == 204

    list_response = client.get("/public")
    assert list_response.status_code == 200
    assert b"hello.txt" in list_response.data

    obj_response = client.get("/public/hello.txt")
    assert obj_response.status_code == 200
    assert obj_response.data == b"hi"

    headers = signer("DELETE", "/public/hello.txt")
    assert client.delete("/public/hello.txt", headers=headers).status_code == 204

    headers = signer("DELETE", "/public?policy")
    assert client.delete("/public?policy", headers=headers).status_code == 204

    headers = signer("DELETE", "/public")
    assert client.delete("/public", headers=headers).status_code == 204


def test_principal_dict_with_object_get_only(client, signer):
    import json

    headers = signer("PUT", "/mixed")
    assert client.put("/mixed", headers=headers).status_code == 200

    headers = signer("PUT", "/mixed/only.txt", body=b"ok")
    assert client.put("/mixed/only.txt", headers=headers, data=b"ok").status_code == 200

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowObjects",
                "Effect": "Allow",
                "Principal": {"AWS": ["*"]},
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::mixed/*"],
            },
            {
                "Sid": "DenyList",
                "Effect": "Deny",
                "Principal": "*",
                "Action": ["s3:ListBucket"],
                "Resource": ["arn:aws:s3:::mixed"],
            },
        ],
    }
    policy_bytes = json.dumps(policy).encode("utf-8")
    headers = signer("PUT", "/mixed?policy", headers={"Content-Type": "application/json"}, body=policy_bytes)
    assert client.put("/mixed?policy", headers=headers, json=policy).status_code == 204

    assert client.get("/mixed").status_code == 403
    allowed = client.get("/mixed/only.txt")
    assert allowed.status_code == 200
    assert allowed.data == b"ok"

    headers = signer("DELETE", "/mixed/only.txt")
    assert client.delete("/mixed/only.txt", headers=headers).status_code == 204

    headers = signer("DELETE", "/mixed?policy")
    assert client.delete("/mixed?policy", headers=headers).status_code == 204

    headers = signer("DELETE", "/mixed")
    assert client.delete("/mixed", headers=headers).status_code == 204


def test_bucket_policy_wildcard_resource_allows_object_get(client, signer):
    import json

    headers = signer("PUT", "/test")
    assert client.put("/test", headers=headers).status_code == 200

    headers = signer("PUT", "/test/vid.mp4", body=b"video")
    assert client.put("/test/vid.mp4", headers=headers, data=b"video").status_code == 200

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": ["*"]},
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::*/*"],
            },
            {
                "Effect": "Deny",
                "Principal": {"AWS": ["*"]},
                "Action": ["s3:ListBucket"],
                "Resource": ["arn:aws:s3:::*"],
            },
        ],
    }
    policy_bytes = json.dumps(policy).encode("utf-8")
    headers = signer("PUT", "/test?policy", headers={"Content-Type": "application/json"}, body=policy_bytes)
    assert client.put("/test?policy", headers=headers, json=policy).status_code == 204

    listing = client.get("/test")
    assert listing.status_code == 403
    payload = client.get("/test/vid.mp4")
    assert payload.status_code == 200
    assert payload.data == b"video"

    headers = signer("DELETE", "/test/vid.mp4")
    assert client.delete("/test/vid.mp4", headers=headers).status_code == 204

    headers = signer("DELETE", "/test?policy")
    assert client.delete("/test?policy", headers=headers).status_code == 204

    headers = signer("DELETE", "/test")
    assert client.delete("/test", headers=headers).status_code == 204


def test_head_object_returns_metadata(client, signer):
        headers = signer("PUT", "/media")
        assert client.put("/media", headers=headers).status_code == 200
        
        payload = b"metadata"
        upload_headers = {"X-Amz-Meta-Test": "demo"}
        # Signer needs to know about custom headers
        headers = signer("PUT", "/media/info.txt", headers=upload_headers, body=payload)
        assert client.put("/media/info.txt", headers=headers, data=payload).status_code == 200

        headers = signer("HEAD", "/media/info.txt")
        head = client.head("/media/info.txt", headers=headers)
        assert head.status_code == 200
        assert head.data == b""
        assert head.headers["Content-Length"] == str(len(payload))
        assert head.headers["X-Amz-Meta-Test"] == "demo"


def test_bucket_versioning_endpoint(client, signer):
        headers = signer("PUT", "/history")
        assert client.put("/history", headers=headers).status_code == 200
        
        headers = signer("GET", "/history?versioning")
        response = client.get("/history", headers=headers, query_string={"versioning": ""})
        assert response.status_code == 200
        assert b"<Status>Suspended</Status>" in response.data

        storage = client.application.extensions["object_storage"]
        storage.set_bucket_versioning("history", True)

        headers = signer("GET", "/history?versioning")
        enabled = client.get("/history", headers=headers, query_string={"versioning": ""})
        assert enabled.status_code == 200
        assert b"<Status>Enabled</Status>" in enabled.data


def test_bucket_tagging_cors_and_encryption_round_trip(client, signer):
        headers = signer("PUT", "/config")
        assert client.put("/config", headers=headers).status_code == 200

        headers = signer("GET", "/config?tagging")
        missing_tags = client.get("/config", headers=headers, query_string={"tagging": ""})
        assert missing_tags.status_code == 404

        tagging_xml = b"""
        <Tagging>
            <TagSet>
                <Tag><Key>env</Key><Value>dev</Value></Tag>
                <Tag><Key>team</Key><Value>platform</Value></Tag>
            </TagSet>
        </Tagging>
        """
        headers = signer("PUT", "/config?tagging", headers={"Content-Type": "application/xml"}, body=tagging_xml)
        assert (
                client.put(
                        "/config",
                        headers=headers,
                        query_string={"tagging": ""},
                        data=tagging_xml,
                        content_type="application/xml",
                ).status_code
                == 204
        )
        
        headers = signer("GET", "/config?tagging")
        tags = client.get("/config", headers=headers, query_string={"tagging": ""})
        assert tags.status_code == 200
        assert b"<Key>env</Key>" in tags.data
        assert b"<Value>platform</Value>" in tags.data

        headers = signer("GET", "/config?cors")
        missing_cors = client.get("/config", headers=headers, query_string={"cors": ""})
        assert missing_cors.status_code == 404
        
        cors_xml = b"""
        <CORSConfiguration>
            <CORSRule>
                <AllowedOrigin>*</AllowedOrigin>
                <AllowedMethod>GET</AllowedMethod>
                <AllowedHeader>*</AllowedHeader>
                <ExposeHeader>X-Test</ExposeHeader>
                <MaxAgeSeconds>600</MaxAgeSeconds>
            </CORSRule>
        </CORSConfiguration>
        """
        headers = signer("PUT", "/config?cors", headers={"Content-Type": "application/xml"}, body=cors_xml)
        assert (
                client.put(
                        "/config",
                        headers=headers,
                        query_string={"cors": ""},
                        data=cors_xml,
                        content_type="application/xml",
                ).status_code
                == 204
        )
        
        headers = signer("GET", "/config?cors")
        cors = client.get("/config", headers=headers, query_string={"cors": ""})
        assert cors.status_code == 200
        assert b"<AllowedOrigin>*</AllowedOrigin>" in cors.data
        assert b"<AllowedMethod>GET</AllowedMethod>" in cors.data

        # Clearing CORS rules with an empty payload removes the configuration
        headers = signer("PUT", "/config?cors", body=b"")
        assert (
                client.put(
                        "/config",
                        headers=headers,
                        query_string={"cors": ""},
                        data=b"",
                ).status_code
                == 204
        )
        
        headers = signer("GET", "/config?cors")
        cleared_cors = client.get("/config", headers=headers, query_string={"cors": ""})
        assert cleared_cors.status_code == 404

        headers = signer("GET", "/config?encryption")
        missing_enc = client.get("/config", headers=headers, query_string={"encryption": ""})
        assert missing_enc.status_code == 404
        
        encryption_xml = b"""
        <ServerSideEncryptionConfiguration>
            <Rule>
                <ApplyServerSideEncryptionByDefault>
                    <SSEAlgorithm>AES256</SSEAlgorithm>
                </ApplyServerSideEncryptionByDefault>
            </Rule>
        </ServerSideEncryptionConfiguration>
        """
        headers = signer("PUT", "/config?encryption", headers={"Content-Type": "application/xml"}, body=encryption_xml)
        assert (
                client.put(
                        "/config",
                        headers=headers,
                        query_string={"encryption": ""},
                        data=encryption_xml,
                        content_type="application/xml",
                ).status_code
                == 204
        )
        
        headers = signer("GET", "/config?encryption")
        encryption = client.get("/config", headers=headers, query_string={"encryption": ""})
        assert encryption.status_code == 200
        assert b"AES256" in encryption.data