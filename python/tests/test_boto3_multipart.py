import uuid
import pytest
import boto3
from botocore.client import Config

@pytest.mark.integration
def test_boto3_multipart_upload(live_server):
    bucket_name = f'mp-test-{uuid.uuid4().hex[:8]}'
    object_key = 'large-file.bin'
    s3 = boto3.client('s3', endpoint_url=live_server, aws_access_key_id='test', aws_secret_access_key='secret', region_name='us-east-1', use_ssl=False, config=Config(signature_version='s3v4', retries={'max_attempts': 1}, s3={'addressing_style': 'path'}))
    s3.create_bucket(Bucket=bucket_name)
    try:
        response = s3.create_multipart_upload(Bucket=bucket_name, Key=object_key)
        upload_id = response['UploadId']
        parts = []
        part1_data = b'A' * 1024
        part2_data = b'B' * 1024
        resp1 = s3.upload_part(Bucket=bucket_name, Key=object_key, PartNumber=1, UploadId=upload_id, Body=part1_data)
        parts.append({'PartNumber': 1, 'ETag': resp1['ETag']})
        resp2 = s3.upload_part(Bucket=bucket_name, Key=object_key, PartNumber=2, UploadId=upload_id, Body=part2_data)
        parts.append({'PartNumber': 2, 'ETag': resp2['ETag']})
        s3.complete_multipart_upload(Bucket=bucket_name, Key=object_key, UploadId=upload_id, MultipartUpload={'Parts': parts})
        obj = s3.get_object(Bucket=bucket_name, Key=object_key)
        content = obj['Body'].read()
        assert content == part1_data + part2_data
        s3.delete_object(Bucket=bucket_name, Key=object_key)
    finally:
        s3.delete_bucket(Bucket=bucket_name)
