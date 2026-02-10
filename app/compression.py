from __future__ import annotations

import gzip
import io
from typing import Callable, Iterable, List, Tuple

COMPRESSIBLE_MIMES = frozenset([
    'application/json',
    'application/javascript',
    'application/xml',
    'text/html',
    'text/css',
    'text/plain',
    'text/xml',
    'text/javascript',
    'application/x-ndjson',
])

MIN_SIZE_FOR_COMPRESSION = 500


class GzipMiddleware:
    def __init__(self, app: Callable, compression_level: int = 6, min_size: int = MIN_SIZE_FOR_COMPRESSION):
        self.app = app
        self.compression_level = compression_level
        self.min_size = min_size

    def __call__(self, environ: dict, start_response: Callable) -> Iterable[bytes]:
        accept_encoding = environ.get('HTTP_ACCEPT_ENCODING', '')
        if 'gzip' not in accept_encoding.lower():
            return self.app(environ, start_response)

        response_started = False
        status_code = None
        response_headers: List[Tuple[str, str]] = []
        content_type = None
        content_length = None
        should_compress = False
        passthrough = False
        exc_info_holder = [None]

        def custom_start_response(status: str, headers: List[Tuple[str, str]], exc_info=None):
            nonlocal response_started, status_code, response_headers, content_type, content_length, should_compress, passthrough
            response_started = True
            status_code = int(status.split(' ', 1)[0])
            response_headers = list(headers)
            exc_info_holder[0] = exc_info

            for name, value in headers:
                name_lower = name.lower()
                if name_lower == 'content-type':
                    content_type = value.split(';')[0].strip().lower()
                elif name_lower == 'content-length':
                    try:
                        content_length = int(value)
                    except (ValueError, TypeError):
                        pass
                elif name_lower == 'content-encoding':
                    passthrough = True
                    return start_response(status, headers, exc_info)
                elif name_lower == 'x-stream-response':
                    passthrough = True
                    return start_response(status, headers, exc_info)

            if content_type and content_type in COMPRESSIBLE_MIMES:
                if content_length is None or content_length >= self.min_size:
                    should_compress = True
            else:
                passthrough = True
                return start_response(status, headers, exc_info)

            return None

        app_iter = self.app(environ, custom_start_response)

        if passthrough:
            return app_iter

        response_body = b''.join(app_iter)

        if not response_started:
            return [response_body]

        if should_compress and len(response_body) >= self.min_size:
            buf = io.BytesIO()
            with gzip.GzipFile(fileobj=buf, mode='wb', compresslevel=self.compression_level) as gz:
                gz.write(response_body)
            compressed = buf.getvalue()

            if len(compressed) < len(response_body):
                response_body = compressed
                new_headers = []
                for name, value in response_headers:
                    if name.lower() not in ('content-length', 'content-encoding'):
                        new_headers.append((name, value))
                new_headers.append(('Content-Encoding', 'gzip'))
                new_headers.append(('Content-Length', str(len(response_body))))
                new_headers.append(('Vary', 'Accept-Encoding'))
                response_headers = new_headers

        status_str = f"{status_code} " + {
            200: "OK", 201: "Created", 204: "No Content", 206: "Partial Content",
            301: "Moved Permanently", 302: "Found", 304: "Not Modified",
            400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
            405: "Method Not Allowed", 409: "Conflict", 500: "Internal Server Error",
        }.get(status_code, "Unknown")

        start_response(status_str, response_headers, exc_info_holder[0])
        return [response_body]
