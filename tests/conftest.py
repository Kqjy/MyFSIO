import json
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlparse
import hashlib
import hmac

import pytest
from werkzeug.serving import make_server

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_api_app


@pytest.fixture()
def app(tmp_path: Path):
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
    flask_app = create_api_app(
        {
            "TESTING": True,
            "STORAGE_ROOT": storage_root,
            "IAM_CONFIG": iam_config,
            "BUCKET_POLICY_PATH": bucket_policies,
            "API_BASE_URL": "http://testserver",
        }
    )
    yield flask_app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def live_server(app):
    server = make_server("127.0.0.1", 0, app)
    host, port = server.server_address

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.05)

    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        thread.join(timeout=1)


def _sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _get_signature_key(key, date_stamp, region_name, service_name):
    k_date = _sign(("AWS4" + key).encode("utf-8"), date_stamp)
    k_region = _sign(k_date, region_name)
    k_service = _sign(k_region, service_name)
    k_signing = _sign(k_service, "aws4_request")
    return k_signing


@pytest.fixture
def signer():
    def _signer(
        method,
        path,
        headers=None,
        body=None,
        access_key="test",
        secret_key="secret",
        region="us-east-1",
        service="s3",
    ):
        if headers is None:
            headers = {}

        now = datetime.now(timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")

        headers["X-Amz-Date"] = amz_date

        # Host header is required for SigV4
        if "Host" not in headers:
            headers["Host"] = "localhost"  # Default for Flask test client

        # Payload hash
        if body is None:
            body = b""
        elif isinstance(body, str):
            body = body.encode("utf-8")

        payload_hash = hashlib.sha256(body).hexdigest()
        headers["X-Amz-Content-Sha256"] = payload_hash

        # Canonical Request
        canonical_uri = quote(path.split("?")[0])

        # Query string
        parsed = urlparse(path)
        query_args = []
        if parsed.query:
            for pair in parsed.query.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                else:
                    k, v = pair, ""
                query_args.append((k, v))
        query_args.sort(key=lambda x: (x[0], x[1]))

        canonical_query_parts = []
        for k, v in query_args:
            canonical_query_parts.append(f"{quote(k, safe='')}={quote(v, safe='')}")
        canonical_query_string = "&".join(canonical_query_parts)

        # Canonical Headers
        canonical_headers_parts = []
        signed_headers_parts = []
        for k, v in sorted(headers.items(), key=lambda x: x[0].lower()):
            k_lower = k.lower()
            v_trim = " ".join(str(v).split())
            canonical_headers_parts.append(f"{k_lower}:{v_trim}\n")
            signed_headers_parts.append(k_lower)

        canonical_headers = "".join(canonical_headers_parts)
        signed_headers = ";".join(signed_headers_parts)

        canonical_request = (
            f"{method}\n{canonical_uri}\n{canonical_query_string}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        )

        # String to Sign
        credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
        string_to_sign = (
            f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
        )

        # Signature
        signing_key = _get_signature_key(secret_key, date_stamp, region, service)
        signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

        authorization = (
            f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
        )
        headers["Authorization"] = authorization

        return headers

    return _signer
