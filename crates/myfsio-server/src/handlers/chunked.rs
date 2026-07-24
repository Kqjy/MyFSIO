use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bytes::{Buf, BytesMut};
use md5::Digest;
use sha1::Sha1;
use sha2::Sha256;
use tokio::io::{AsyncRead, ReadBuf};

use crate::middleware::{StreamingPayloadVariant, StreamingSigV4Context};

const MAX_CHUNK_HEADER_LINE: usize = 1024;
const MAX_TRAILER_BYTES: usize = 16_384;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AwsChunkedErrorKind {
    IncompleteBody,
    InvalidRequest,
    SignatureDoesNotMatch,
}

#[derive(Debug)]
pub struct AwsChunkedError {
    kind: AwsChunkedErrorKind,
    message: String,
}

impl AwsChunkedError {
    pub fn kind(&self) -> AwsChunkedErrorKind {
        self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for AwsChunkedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for AwsChunkedError {}

pub fn aws_chunked_error<'a>(err: &'a (dyn Error + 'static)) -> Option<&'a AwsChunkedError> {
    if let Some(chunked) = err.downcast_ref::<AwsChunkedError>() {
        return Some(chunked);
    }
    if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
        if let Some(inner) = io_err.get_ref() {
            return aws_chunked_error(inner);
        }
        return None;
    }
    err.source().and_then(aws_chunked_error)
}

fn stream_error(kind: AwsChunkedErrorKind, message: impl Into<String>) -> std::io::Error {
    let io_kind = if kind == AwsChunkedErrorKind::IncompleteBody {
        std::io::ErrorKind::UnexpectedEof
    } else {
        std::io::ErrorKind::InvalidData
    };
    std::io::Error::new(
        io_kind,
        AwsChunkedError {
            kind,
            message: message.into(),
        },
    )
}

enum State {
    ReadSize,
    ReadData(u64),
    ReadDataTerminator,
    ReadTrailer,
    Finished,
}

struct StreamChecksums {
    sha256: Sha256,
    sha1: Sha1,
    crc32: crc_fast::Digest,
    crc32c: crc_fast::Digest,
    crc64nvme: crc_fast::Digest,
}

impl StreamChecksums {
    fn new() -> Self {
        Self {
            sha256: Sha256::new(),
            sha1: Sha1::new(),
            crc32: crc_fast::Digest::new(crc_fast::CrcAlgorithm::Crc32IsoHdlc),
            crc32c: crc_fast::Digest::new(crc_fast::CrcAlgorithm::Crc32Iscsi),
            crc64nvme: crc_fast::Digest::new(crc_fast::CrcAlgorithm::Crc64Nvme),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.sha256.update(data);
        self.sha1.update(data);
        self.crc32.update(data);
        self.crc32c.update(data);
        self.crc64nvme.update(data);
    }

    fn value(&self, name: &str) -> Option<Vec<u8>> {
        match name {
            "x-amz-checksum-sha256" => Some(self.sha256.clone().finalize().to_vec()),
            "x-amz-checksum-sha1" => Some(self.sha1.clone().finalize().to_vec()),
            "x-amz-checksum-crc32" => Some((self.crc32.finalize() as u32).to_be_bytes().to_vec()),
            "x-amz-checksum-crc32c" => Some((self.crc32c.finalize() as u32).to_be_bytes().to_vec()),
            "x-amz-checksum-crc64nvme" => Some(self.crc64nvme.finalize().to_be_bytes().to_vec()),
            _ => None,
        }
    }
}

pub struct AwsChunkedStream<S> {
    inner: S,
    buffer: BytesMut,
    state: State,
    eof: bool,
    trailer_bytes_read: usize,
    declared_trailers: BTreeSet<String>,
    trailers: BTreeMap<String, String>,
    checksums: StreamChecksums,
    signing_context: Option<StreamingSigV4Context>,
    strict_signatures: bool,
    previous_signature: Option<String>,
    expected_chunk_signature: Option<String>,
    chunk_hasher: Sha256,
}

impl<S> AwsChunkedStream<S> {
    #[cfg(test)]
    fn new(inner: S) -> Self {
        Self::with_options(inner, BTreeSet::new(), None, true)
    }

    fn with_options(
        inner: S,
        declared_trailers: BTreeSet<String>,
        signing_context: Option<StreamingSigV4Context>,
        strict_signatures: bool,
    ) -> Self {
        let previous_signature = signing_context
            .as_ref()
            .map(|context| context.seed_signature.clone());
        Self {
            inner,
            buffer: BytesMut::with_capacity(8192),
            state: State::ReadSize,
            eof: false,
            trailer_bytes_read: 0,
            declared_trailers,
            trailers: BTreeMap::new(),
            checksums: StreamChecksums::new(),
            signing_context,
            strict_signatures,
            previous_signature,
            expected_chunk_signature: None,
            chunk_hasher: Sha256::new(),
        }
    }

    fn find_crlf(&self) -> Option<usize> {
        (0..self.buffer.len().saturating_sub(1))
            .find(|&i| self.buffer[i] == b'\r' && self.buffer[i + 1] == b'\n')
    }

    fn parse_chunk_header(&self, line: &[u8]) -> std::io::Result<(u64, Option<String>)> {
        let text = std::str::from_utf8(line).map_err(|_| {
            stream_error(
                AwsChunkedErrorKind::InvalidRequest,
                "Invalid aws-chunked size encoding",
            )
        })?;
        let mut parts = text.split(';');
        let head = parts.next().unwrap_or("").trim();
        let size = u64::from_str_radix(head, 16).map_err(|_| {
            stream_error(
                AwsChunkedErrorKind::InvalidRequest,
                format!("Invalid aws-chunked size: {}", head),
            )
        })?;
        let mut signature = None;
        for extension in parts {
            let Some((name, value)) = extension.trim().split_once('=') else {
                return Err(stream_error(
                    AwsChunkedErrorKind::InvalidRequest,
                    "Malformed aws-chunked extension",
                ));
            };
            if name.trim().eq_ignore_ascii_case("chunk-signature") {
                let value = value.trim();
                if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err(stream_error(
                        AwsChunkedErrorKind::SignatureDoesNotMatch,
                        "Invalid aws-chunked chunk signature",
                    ));
                }
                if signature.replace(value.to_ascii_lowercase()).is_some() {
                    return Err(stream_error(
                        AwsChunkedErrorKind::InvalidRequest,
                        "Duplicate aws-chunked chunk signature",
                    ));
                }
            }
        }
        if self.signing_context.is_some() && self.strict_signatures && signature.is_none() {
            return Err(stream_error(
                AwsChunkedErrorKind::SignatureDoesNotMatch,
                "Missing aws-chunked chunk signature",
            ));
        }
        Ok((size, signature))
    }

    fn verify_current_chunk_signature(&mut self) -> std::io::Result<()> {
        let Some(context) = self.signing_context.as_ref() else {
            return Ok(());
        };
        if !self.strict_signatures {
            return Ok(());
        }
        let provided = self.expected_chunk_signature.take().ok_or_else(|| {
            stream_error(
                AwsChunkedErrorKind::SignatureDoesNotMatch,
                "Missing aws-chunked chunk signature",
            )
        })?;
        let previous = self.previous_signature.as_deref().ok_or_else(|| {
            stream_error(
                AwsChunkedErrorKind::SignatureDoesNotMatch,
                "Missing aws-chunked signature chain seed",
            )
        })?;
        let chunk_hash = hex::encode(self.chunk_hasher.clone().finalize());
        let empty_hash = myfsio_auth::sigv4::sha256_hex(b"");
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256-PAYLOAD\n{}\n{}\n{}\n{}\n{}",
            context.timestamp, context.credential_scope, previous, empty_hash, chunk_hash
        );
        let calculated =
            myfsio_auth::sigv4::compute_signature(&context.signing_key, &string_to_sign);
        if !myfsio_auth::sigv4::constant_time_compare(&calculated, &provided) {
            return Err(stream_error(
                AwsChunkedErrorKind::SignatureDoesNotMatch,
                "The aws-chunked chunk signature does not match",
            ));
        }
        self.previous_signature = Some(provided);
        Ok(())
    }

    fn parse_trailer_line(&mut self, line: &[u8]) -> std::io::Result<()> {
        let text = std::str::from_utf8(line).map_err(|_| {
            stream_error(
                AwsChunkedErrorKind::InvalidRequest,
                "Invalid aws-chunked trailer encoding",
            )
        })?;
        let (name, value) = text.split_once(':').ok_or_else(|| {
            stream_error(
                AwsChunkedErrorKind::InvalidRequest,
                "Malformed aws-chunked trailer",
            )
        })?;
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(stream_error(
                AwsChunkedErrorKind::InvalidRequest,
                "Malformed aws-chunked trailer name",
            ));
        }
        let value = value.split_whitespace().collect::<Vec<_>>().join(" ");
        if self.trailers.insert(name.clone(), value).is_some() {
            return Err(stream_error(
                AwsChunkedErrorKind::InvalidRequest,
                format!("Duplicate aws-chunked trailer {}", name),
            ));
        }
        Ok(())
    }

    fn verify_trailers(&self) -> std::io::Result<()> {
        for name in &self.declared_trailers {
            if !self.trailers.contains_key(name) {
                return Err(stream_error(
                    AwsChunkedErrorKind::InvalidRequest,
                    format!("Missing declared aws-chunked trailer {}", name),
                ));
            }
        }
        for name in self.trailers.keys() {
            if name.starts_with("x-amz-checksum-") && !self.declared_trailers.contains(name) {
                return Err(stream_error(
                    AwsChunkedErrorKind::InvalidRequest,
                    format!("Undeclared aws-chunked checksum trailer {}", name),
                ));
            }
        }
        for name in &self.declared_trailers {
            if !name.starts_with("x-amz-checksum-") {
                continue;
            }
            let expected = self.checksums.value(name).ok_or_else(|| {
                stream_error(
                    AwsChunkedErrorKind::InvalidRequest,
                    format!("Unsupported aws-chunked checksum trailer {}", name),
                )
            })?;
            let value = self.trailers.get(name).expect("declared trailer checked");
            let provided = STANDARD.decode(value).map_err(|_| {
                stream_error(
                    AwsChunkedErrorKind::InvalidRequest,
                    format!("Invalid base64 value for {}", name),
                )
            })?;
            if provided != expected {
                return Err(stream_error(
                    AwsChunkedErrorKind::InvalidRequest,
                    format!("The {} you specified did not match what we received", name),
                ));
            }
        }
        let Some(context) = self.signing_context.as_ref() else {
            return Ok(());
        };
        if context.payload_variant != StreamingPayloadVariant::SignedPayloadTrailer
            || !self.strict_signatures
        {
            return Ok(());
        }
        let provided = self
            .trailers
            .get("x-amz-trailer-signature")
            .ok_or_else(|| {
                stream_error(
                    AwsChunkedErrorKind::SignatureDoesNotMatch,
                    "Missing aws-chunked trailer signature",
                )
            })?;
        if provided.len() != 64 || !provided.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(stream_error(
                AwsChunkedErrorKind::SignatureDoesNotMatch,
                "Invalid aws-chunked trailer signature",
            ));
        }
        let mut canonical = String::new();
        for name in &self.declared_trailers {
            let value = self.trailers.get(name).expect("declared trailer checked");
            canonical.push_str(name);
            canonical.push(':');
            canonical.push_str(value);
            canonical.push('\n');
        }
        let previous = self.previous_signature.as_deref().ok_or_else(|| {
            stream_error(
                AwsChunkedErrorKind::SignatureDoesNotMatch,
                "Missing aws-chunked trailer signature chain",
            )
        })?;
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256-TRAILER\n{}\n{}\n{}\n{}",
            context.timestamp,
            context.credential_scope,
            previous,
            myfsio_auth::sigv4::sha256_hex(canonical.as_bytes())
        );
        let calculated =
            myfsio_auth::sigv4::compute_signature(&context.signing_key, &string_to_sign);
        if !myfsio_auth::sigv4::constant_time_compare(&calculated, provided) {
            return Err(stream_error(
                AwsChunkedErrorKind::SignatureDoesNotMatch,
                "The aws-chunked trailer signature does not match",
            ));
        }
        Ok(())
    }

    fn try_advance(&mut self, out: &mut ReadBuf<'_>) -> std::io::Result<bool> {
        loop {
            if out.remaining() == 0 {
                return Ok(true);
            }
            match self.state {
                State::Finished => return Ok(true),
                State::ReadSize => {
                    let idx = match self.find_crlf() {
                        Some(index) => index,
                        None => {
                            if self.buffer.len() > MAX_CHUNK_HEADER_LINE {
                                return Err(stream_error(
                                    AwsChunkedErrorKind::InvalidRequest,
                                    "Aws-chunked size line exceeds maximum length",
                                ));
                            }
                            return Ok(false);
                        }
                    };
                    if idx > MAX_CHUNK_HEADER_LINE {
                        return Err(stream_error(
                            AwsChunkedErrorKind::InvalidRequest,
                            "Aws-chunked size line exceeds maximum length",
                        ));
                    }
                    let line = self.buffer.split_to(idx);
                    self.buffer.advance(2);
                    let (size, signature) = self.parse_chunk_header(&line)?;
                    self.expected_chunk_signature = signature;
                    self.chunk_hasher = Sha256::new();
                    if size == 0 {
                        self.verify_current_chunk_signature()?;
                        self.state = State::ReadTrailer;
                        self.trailer_bytes_read = 0;
                    } else {
                        self.state = State::ReadData(size);
                    }
                }
                State::ReadData(remaining) => {
                    if self.buffer.is_empty() {
                        return Ok(false);
                    }
                    let take = std::cmp::min(
                        std::cmp::min(self.buffer.len() as u64, remaining) as usize,
                        out.remaining(),
                    );
                    let data = &self.buffer[..take];
                    self.chunk_hasher.update(data);
                    self.checksums.update(data);
                    out.put_slice(data);
                    self.buffer.advance(take);
                    let remaining = remaining - take as u64;
                    if remaining == 0 {
                        self.state = State::ReadDataTerminator;
                    } else {
                        self.state = State::ReadData(remaining);
                    }
                    return Ok(true);
                }
                State::ReadDataTerminator => {
                    if self.buffer.len() < 2 {
                        return Ok(false);
                    }
                    if &self.buffer[..2] != b"\r\n" {
                        return Err(stream_error(
                            AwsChunkedErrorKind::InvalidRequest,
                            "Malformed aws-chunked chunk terminator",
                        ));
                    }
                    self.buffer.advance(2);
                    self.verify_current_chunk_signature()?;
                    self.state = State::ReadSize;
                }
                State::ReadTrailer => {
                    let idx = match self.find_crlf() {
                        Some(index) => index,
                        None => {
                            if self.buffer.len() > MAX_CHUNK_HEADER_LINE {
                                return Err(stream_error(
                                    AwsChunkedErrorKind::InvalidRequest,
                                    "Aws-chunked trailer line exceeds maximum length",
                                ));
                            }
                            if self.trailer_bytes_read + self.buffer.len() > MAX_TRAILER_BYTES {
                                return Err(stream_error(
                                    AwsChunkedErrorKind::InvalidRequest,
                                    "Aws-chunked trailer section exceeds maximum size",
                                ));
                            }
                            return Ok(false);
                        }
                    };
                    if idx > MAX_CHUNK_HEADER_LINE {
                        return Err(stream_error(
                            AwsChunkedErrorKind::InvalidRequest,
                            "Aws-chunked trailer line exceeds maximum length",
                        ));
                    }
                    self.trailer_bytes_read = self.trailer_bytes_read.saturating_add(idx + 2);
                    if self.trailer_bytes_read > MAX_TRAILER_BYTES {
                        return Err(stream_error(
                            AwsChunkedErrorKind::InvalidRequest,
                            "Aws-chunked trailer section exceeds maximum size",
                        ));
                    }
                    let line = self.buffer.split_to(idx);
                    self.buffer.advance(2);
                    if line.is_empty() {
                        self.verify_trailers()?;
                        self.state = State::Finished;
                    } else {
                        self.parse_trailer_line(&line)?;
                    }
                }
            }
        }
    }
}

impl<S> AsyncRead for AwsChunkedStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            let before = buf.filled().len();
            let done = match self.try_advance(buf) {
                Ok(value) => value,
                Err(error) => return Poll::Ready(Err(error)),
            };
            if buf.filled().len() > before {
                return Poll::Ready(Ok(()));
            }
            if done {
                return Poll::Ready(Ok(()));
            }
            if self.eof {
                return Poll::Ready(Err(stream_error(
                    AwsChunkedErrorKind::IncompleteBody,
                    "Unexpected EOF in aws-chunked stream",
                )));
            }
            let mut tmp = [0u8; 8192];
            let mut read_buf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    if read_buf.filled().is_empty() {
                        self.eof = true;
                    } else {
                        self.buffer.extend_from_slice(read_buf.filled());
                    }
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

fn declared_trailers(headers: &axum::http::HeaderMap) -> Result<BTreeSet<String>, AwsChunkedError> {
    let Some(value) = headers.get("x-amz-trailer") else {
        return Ok(BTreeSet::new());
    };
    let value = value.to_str().map_err(|_| AwsChunkedError {
        kind: AwsChunkedErrorKind::InvalidRequest,
        message: "Invalid x-amz-trailer declaration".to_string(),
    })?;
    let mut names = BTreeSet::new();
    for name in value.split(',') {
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(AwsChunkedError {
                kind: AwsChunkedErrorKind::InvalidRequest,
                message: "Invalid x-amz-trailer declaration".to_string(),
            });
        }
        names.insert(name);
    }
    Ok(names)
}

pub fn decode_body(
    body: axum::body::Body,
    headers: &axum::http::HeaderMap,
    signing_context: Option<StreamingSigV4Context>,
    strict_signatures: bool,
) -> Result<impl AsyncRead + Send + Unpin, AwsChunkedError> {
    use futures::TryStreamExt;
    let signed_streaming = headers
        .get("x-amz-content-sha256")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.eq_ignore_ascii_case("STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
                || value.eq_ignore_ascii_case("STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER")
        });
    if strict_signatures && signed_streaming && signing_context.is_none() {
        return Err(AwsChunkedError {
            kind: AwsChunkedErrorKind::SignatureDoesNotMatch,
            message: "Missing streaming SigV4 signing context".to_string(),
        });
    }
    let stream = tokio_util::io::StreamReader::new(
        http_body_util::BodyStream::new(body)
            .map_ok(|frame| frame.into_data().unwrap_or_default())
            .map_err(std::io::Error::other),
    );
    Ok(AwsChunkedStream::with_options(
        stream,
        declared_trailers(headers)?,
        signing_context,
        strict_signatures,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tokio::io::AsyncReadExt;

    fn signed_context(payload_variant: StreamingPayloadVariant) -> StreamingSigV4Context {
        StreamingSigV4Context {
            signing_key: myfsio_auth::sigv4::derive_signing_key(
                "secret",
                "20260723",
                "us-east-1",
                "s3",
            ),
            timestamp: "20260723T120000Z".to_string(),
            credential_scope: "20260723/us-east-1/s3/aws4_request".to_string(),
            seed_signature: "0".repeat(64),
            payload_variant,
        }
    }

    fn chunk_signature(context: &StreamingSigV4Context, previous: &str, data: &[u8]) -> String {
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256-PAYLOAD\n{}\n{}\n{}\n{}\n{}",
            context.timestamp,
            context.credential_scope,
            previous,
            myfsio_auth::sigv4::sha256_hex(b""),
            myfsio_auth::sigv4::sha256_hex(data)
        );
        myfsio_auth::sigv4::compute_signature(&context.signing_key, &string_to_sign)
    }

    #[tokio::test]
    async fn rejects_oversized_chunk_size_line() {
        let huge: Vec<u8> = std::iter::repeat_n(b'A', MAX_CHUNK_HEADER_LINE + 16).collect();
        let mut stream = AwsChunkedStream::new(Cursor::new(huge));
        let mut output = Vec::new();
        let error = stream.read_to_end(&mut output).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn decodes_normal_chunked_body() {
        let payload = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let mut stream = AwsChunkedStream::new(Cursor::new(payload.to_vec()));
        let mut output = Vec::new();
        stream.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, b"hello world");
    }

    #[tokio::test]
    async fn verifies_checksum_trailer_and_rejects_tampering() {
        let checksum = STANDARD.encode(
            (crc_fast::checksum(crc_fast::CrcAlgorithm::Crc32Iscsi, b"hello") as u32).to_be_bytes(),
        );
        let declared = BTreeSet::from(["x-amz-checksum-crc32c".to_string()]);
        let payload = format!(
            "5\r\nhello\r\n0\r\nx-amz-checksum-crc32c:{}\r\n\r\n",
            checksum
        );
        let mut stream =
            AwsChunkedStream::with_options(Cursor::new(payload.into_bytes()), declared, None, true);
        let mut output = Vec::new();
        stream.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, b"hello");

        let declared = BTreeSet::from(["x-amz-checksum-crc32c".to_string()]);
        let payload = "5\r\nhello\r\n0\r\nx-amz-checksum-crc32c:AAAAAA==\r\n\r\n";
        let mut stream =
            AwsChunkedStream::with_options(Cursor::new(payload.as_bytes()), declared, None, true);
        let error = stream.read_to_end(&mut Vec::new()).await.unwrap_err();
        assert_eq!(
            aws_chunked_error(&error).unwrap().kind(),
            AwsChunkedErrorKind::InvalidRequest
        );
    }

    #[tokio::test]
    async fn rejects_truncated_trailer() {
        let declared = BTreeSet::from(["x-amz-checksum-crc32c".to_string()]);
        let payload = b"5\r\nhello\r\n0\r\nx-amz-checksum-crc32c:";
        let mut stream = AwsChunkedStream::with_options(Cursor::new(payload), declared, None, true);
        let error = stream.read_to_end(&mut Vec::new()).await.unwrap_err();
        assert_eq!(
            aws_chunked_error(&error).unwrap().kind(),
            AwsChunkedErrorKind::IncompleteBody
        );
    }

    #[tokio::test]
    async fn verifies_signed_chunk_chain_and_final_chunk() {
        let context = signed_context(StreamingPayloadVariant::SignedPayload);
        let first = chunk_signature(&context, &context.seed_signature, b"hello");
        let final_signature = chunk_signature(&context, &first, b"");
        let payload = format!(
            "5;chunk-signature={}\r\nhello\r\n0;chunk-signature={}\r\n\r\n",
            first, final_signature
        );
        let mut stream = AwsChunkedStream::with_options(
            Cursor::new(payload.into_bytes()),
            BTreeSet::new(),
            Some(context),
            true,
        );
        let mut output = Vec::new();
        stream.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, b"hello");
    }

    #[tokio::test]
    async fn rejects_tampered_signed_chunk_and_missing_final_chunk() {
        let context = signed_context(StreamingPayloadVariant::SignedPayload);
        let first = chunk_signature(&context, &context.seed_signature, b"hello");
        let final_signature = chunk_signature(&context, &first, b"");
        let payload = format!(
            "5;chunk-signature={}\r\njello\r\n0;chunk-signature={}\r\n\r\n",
            first, final_signature
        );
        let mut stream = AwsChunkedStream::with_options(
            Cursor::new(payload.into_bytes()),
            BTreeSet::new(),
            Some(context.clone()),
            true,
        );
        let error = stream.read_to_end(&mut Vec::new()).await.unwrap_err();
        assert_eq!(
            aws_chunked_error(&error).unwrap().kind(),
            AwsChunkedErrorKind::SignatureDoesNotMatch
        );

        let payload = format!("5;chunk-signature={}\r\nhello\r\n", first);
        let mut stream = AwsChunkedStream::with_options(
            Cursor::new(payload.into_bytes()),
            BTreeSet::new(),
            Some(context),
            true,
        );
        let error = stream.read_to_end(&mut Vec::new()).await.unwrap_err();
        assert_eq!(
            aws_chunked_error(&error).unwrap().kind(),
            AwsChunkedErrorKind::IncompleteBody
        );
    }

    #[tokio::test]
    async fn verifies_signed_trailer_signature() {
        let context = signed_context(StreamingPayloadVariant::SignedPayloadTrailer);
        let first = chunk_signature(&context, &context.seed_signature, b"hello");
        let final_signature = chunk_signature(&context, &first, b"");
        let checksum = STANDARD.encode(Sha1::digest(b"hello"));
        let canonical = format!("x-amz-checksum-sha1:{}\n", checksum);
        let trailer_string = format!(
            "AWS4-HMAC-SHA256-TRAILER\n{}\n{}\n{}\n{}",
            context.timestamp,
            context.credential_scope,
            final_signature,
            myfsio_auth::sigv4::sha256_hex(canonical.as_bytes())
        );
        let trailer_signature =
            myfsio_auth::sigv4::compute_signature(&context.signing_key, &trailer_string);
        let payload = format!(
            "5;chunk-signature={}\r\nhello\r\n0;chunk-signature={}\r\nx-amz-checksum-sha1:{}\r\nx-amz-trailer-signature:{}\r\n\r\n",
            first, final_signature, checksum, trailer_signature
        );
        let declared = BTreeSet::from(["x-amz-checksum-sha1".to_string()]);
        let mut stream = AwsChunkedStream::with_options(
            Cursor::new(payload.into_bytes()),
            declared,
            Some(context.clone()),
            true,
        );
        stream.read_to_end(&mut Vec::new()).await.unwrap();

        let payload = format!(
            "5;chunk-signature={}\r\nhello\r\n0;chunk-signature={}\r\nx-amz-checksum-sha1:{}\r\nx-amz-trailer-signature:{}\r\n\r\n",
            first,
            final_signature,
            checksum,
            "0".repeat(64)
        );
        let declared = BTreeSet::from(["x-amz-checksum-sha1".to_string()]);
        let mut stream = AwsChunkedStream::with_options(
            Cursor::new(payload.into_bytes()),
            declared,
            Some(context),
            true,
        );
        let error = stream.read_to_end(&mut Vec::new()).await.unwrap_err();
        assert_eq!(
            aws_chunked_error(&error).unwrap().kind(),
            AwsChunkedErrorKind::SignatureDoesNotMatch
        );
    }

    #[tokio::test]
    async fn strict_false_accepts_invalid_signatures() {
        let context = signed_context(StreamingPayloadVariant::SignedPayload);
        let payload = format!(
            "5;chunk-signature={}\r\nhello\r\n0;chunk-signature={}\r\n\r\n",
            "0".repeat(64),
            "0".repeat(64)
        );
        let mut stream = AwsChunkedStream::with_options(
            Cursor::new(payload.into_bytes()),
            BTreeSet::new(),
            Some(context),
            false,
        );
        let mut output = Vec::new();
        stream.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, b"hello");
    }

    #[tokio::test]
    async fn signed_streaming_without_context_respects_strict_mode() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "x-amz-content-sha256",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD".parse().unwrap(),
        );
        let payload = axum::body::Body::from("5\r\nhello\r\n0\r\n\r\n");
        let error = match decode_body(payload, &headers, None, true) {
            Ok(_) => panic!("strict streaming request without context was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), AwsChunkedErrorKind::SignatureDoesNotMatch);

        let payload = axum::body::Body::from("5\r\nhello\r\n0\r\n\r\n");
        let mut stream = decode_body(payload, &headers, None, false).unwrap();
        let mut output = Vec::new();
        stream.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, b"hello");
    }
}
