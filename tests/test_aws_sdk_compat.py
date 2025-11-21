import uuid

import boto3
import pytest
from botocore.client import Config


@pytest.mark.integration
def test_boto3_basic_operations(live_server):
    bucket_name = f"boto3-test-{uuid.uuid4().hex[:8]}"
    object_key = "folder/hello.txt"

    s3 = boto3.client(
        "s3",
        endpoint_url=live_server,
        aws_access_key_id="test",
        aws_secret_access_key="secret",
        region_name="us-east-1",
        use_ssl=False,
        config=Config(
            signature_version="s3v4",
            retries={"max_attempts": 1},
            s3={"addressing_style": "path"},
        ),
    )

    # No need to inject custom headers anymore, as we support SigV4
    # def _inject_headers(params, **_kwargs):
    #     headers = params.setdefault("headers", {})
    #     headers["X-Access-Key"] = "test"
    #     headers["X-Secret-Key"] = "secret"

    # s3.meta.events.register("before-call.s3", _inject_headers)

    s3.create_bucket(Bucket=bucket_name)

    try:
        put_response = s3.put_object(Bucket=bucket_name, Key=object_key, Body=b"hello from boto3")
        assert "ETag" in put_response

        obj = s3.get_object(Bucket=bucket_name, Key=object_key)
        assert obj["Body"].read() == b"hello from boto3"

        listing = s3.list_objects_v2(Bucket=bucket_name)
        contents = listing.get("Contents", [])
        assert contents, "list_objects_v2 should return at least the object we uploaded"
        keys = {entry["Key"] for entry in contents}
        assert object_key in keys

        s3.delete_object(Bucket=bucket_name, Key=object_key)
        post_delete = s3.list_objects_v2(Bucket=bucket_name)
        assert not post_delete.get("Contents"), "Object should be removed before deleting bucket"
    finally:
        s3.delete_bucket(Bucket=bucket_name)