use md5::{Digest as Md5Digest, Md5};
use sha2::Sha256;
use std::error::Error;
use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};

#[derive(Debug)]
pub struct UploadChecksumMismatchError {
    message: String,
}

impl UploadChecksumMismatchError {
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for UploadChecksumMismatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BadDigest: {}", self.message)
    }
}

impl Error for UploadChecksumMismatchError {}

pub fn upload_checksum_mismatch_message(err: &(dyn Error + 'static)) -> Option<String> {
    if let Some(mismatch) = err.downcast_ref::<UploadChecksumMismatchError>() {
        return Some(mismatch.message().to_string());
    }
    if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
        if let Some(inner) = io_err.get_ref() {
            return upload_checksum_mismatch_message(inner);
        }
        return None;
    }
    err.source().and_then(upload_checksum_mismatch_message)
}

#[derive(Default)]
pub struct ExpectedUploadChecksums {
    pub md5: Option<Vec<u8>>,
    pub sha256: Option<Vec<u8>>,
    pub crc32: Option<[u8; 4]>,
}

impl ExpectedUploadChecksums {
    pub fn is_empty(&self) -> bool {
        self.md5.is_none() && self.sha256.is_none() && self.crc32.is_none()
    }
}

pub struct ChecksumVerifyReader {
    inner: myfsio_storage::traits::AsyncReadStream,
    md5: Option<(Md5, Vec<u8>)>,
    sha256: Option<(Sha256, Vec<u8>)>,
    crc32: Option<(crc32fast::Hasher, [u8; 4])>,
    verified: bool,
}

impl ChecksumVerifyReader {
    pub fn new(
        inner: myfsio_storage::traits::AsyncReadStream,
        expected: ExpectedUploadChecksums,
    ) -> Self {
        Self {
            inner,
            md5: expected.md5.map(|e| (Md5::new(), e)),
            sha256: expected.sha256.map(|e| (Sha256::new(), e)),
            crc32: expected.crc32.map(|e| (crc32fast::Hasher::new(), e)),
            verified: false,
        }
    }

    fn verify(&mut self) -> std::io::Result<()> {
        if self.verified {
            return Ok(());
        }
        self.verified = true;
        let mismatch = |message: &str| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                UploadChecksumMismatchError {
                    message: message.to_string(),
                },
            )
        };
        if let Some((hasher, expected)) = self.md5.take() {
            if hasher.finalize().as_slice() != expected.as_slice() {
                return Err(mismatch(
                    "The Content-MD5 you specified did not match what we received",
                ));
            }
        }
        if let Some((hasher, expected)) = self.sha256.take() {
            if hasher.finalize().as_slice() != expected.as_slice() {
                return Err(mismatch(
                    "The x-amz-checksum-sha256 you specified did not match what we received",
                ));
            }
        }
        if let Some((hasher, expected)) = self.crc32.take() {
            if hasher.finalize().to_be_bytes() != expected {
                return Err(mismatch(
                    "The x-amz-checksum-crc32 you specified did not match what we received",
                ));
            }
        }
        Ok(())
    }
}

impl AsyncRead for ChecksumVerifyReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {
                let filled = &buf.filled()[before..];
                if filled.is_empty() {
                    Poll::Ready(self.verify())
                } else {
                    if let Some((hasher, _)) = self.md5.as_mut() {
                        hasher.update(filled);
                    }
                    if let Some((hasher, _)) = self.sha256.as_mut() {
                        hasher.update(filled);
                    }
                    if let Some((hasher, _)) = self.crc32.as_mut() {
                        hasher.update(filled);
                    }
                    Poll::Ready(Ok(()))
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct PostContentLengthError {
    pub min: u64,
    pub max: u64,
    pub too_large: bool,
}

impl fmt::Display for PostContentLengthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Content length must be between {} and {}",
            self.min, self.max
        )
    }
}

impl Error for PostContentLengthError {}

pub fn post_content_length_violation<'a>(
    err: &'a (dyn Error + 'static),
) -> Option<&'a PostContentLengthError> {
    if let Some(violation) = err.downcast_ref::<PostContentLengthError>() {
        return Some(violation);
    }
    if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
        if let Some(inner) = io_err.get_ref() {
            return post_content_length_violation(inner);
        }
        return None;
    }
    err.source().and_then(post_content_length_violation)
}

pub struct LengthRangeReader {
    inner: myfsio_storage::traits::AsyncReadStream,
    min: u64,
    max: u64,
    seen: u64,
    checked_eof: bool,
    pending_violation: bool,
}

impl LengthRangeReader {
    pub fn new(inner: myfsio_storage::traits::AsyncReadStream, min: u64, max: u64) -> Self {
        Self {
            inner,
            min,
            max,
            seen: 0,
            checked_eof: false,
            pending_violation: false,
        }
    }

    fn violation(&self, too_large: bool) -> std::io::Error {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            PostContentLengthError {
                min: self.min,
                max: self.max,
                too_large,
            },
        )
    }
}

impl AsyncRead for LengthRangeReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pending_violation {
            return Poll::Ready(Err(self.violation(true)));
        }
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {
                let added = (buf.filled().len() - before) as u64;
                if added == 0 {
                    if !self.checked_eof {
                        self.checked_eof = true;
                        if self.seen < self.min {
                            return Poll::Ready(Err(self.violation(false)));
                        }
                    }
                    return Poll::Ready(Ok(()));
                }
                self.seen += added;
                if self.seen > self.max {
                    self.pending_violation = true;
                }
                Poll::Ready(Ok(()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    fn stream_of(data: &[u8]) -> myfsio_storage::traits::AsyncReadStream {
        Box::pin(std::io::Cursor::new(data.to_vec()))
    }

    #[tokio::test]
    async fn checksum_reader_passes_matching_digests() {
        let data = b"hello world";
        let expected = ExpectedUploadChecksums {
            md5: Some(Md5::digest(data).to_vec()),
            sha256: Some(Sha256::digest(data).to_vec()),
            crc32: Some(crc32fast::hash(data).to_be_bytes()),
        };
        let mut reader = ChecksumVerifyReader::new(stream_of(data), expected);
        let mut out = Vec::new();
        reader.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, data);
    }

    #[tokio::test]
    async fn checksum_reader_rejects_bad_md5() {
        let data = b"hello world";
        let expected = ExpectedUploadChecksums {
            md5: Some(Md5::digest(b"other").to_vec()),
            ..Default::default()
        };
        let mut reader = ChecksumVerifyReader::new(stream_of(data), expected);
        let mut out = Vec::new();
        let err = reader.read_to_end(&mut out).await.unwrap_err();
        let msg = upload_checksum_mismatch_message(&err).expect("typed mismatch");
        assert!(msg.contains("Content-MD5"));
    }

    #[tokio::test]
    async fn checksum_reader_rejects_bad_crc32() {
        let data = b"hello world";
        let expected = ExpectedUploadChecksums {
            crc32: Some(crc32fast::hash(b"other").to_be_bytes()),
            ..Default::default()
        };
        let mut reader = ChecksumVerifyReader::new(stream_of(data), expected);
        let mut out = Vec::new();
        let err = reader.read_to_end(&mut out).await.unwrap_err();
        assert!(upload_checksum_mismatch_message(&err).is_some());
    }

    #[tokio::test]
    async fn length_range_reader_rejects_too_large_mid_stream() {
        let data = vec![0u8; 100];
        let mut reader = LengthRangeReader::new(stream_of(&data), 0, 10);
        let mut out = Vec::new();
        let err = reader.read_to_end(&mut out).await.unwrap_err();
        let violation = post_content_length_violation(&err).expect("typed violation");
        assert!(violation.too_large);
    }

    #[tokio::test]
    async fn length_range_reader_rejects_too_small_at_eof() {
        let data = vec![0u8; 3];
        let mut reader = LengthRangeReader::new(stream_of(&data), 10, 100);
        let mut out = Vec::new();
        let err = reader.read_to_end(&mut out).await.unwrap_err();
        let violation = post_content_length_violation(&err).expect("typed violation");
        assert!(!violation.too_large);
    }

    #[tokio::test]
    async fn length_range_reader_accepts_in_range() {
        let data = vec![7u8; 50];
        let mut reader = LengthRangeReader::new(stream_of(&data), 10, 100);
        let mut out = Vec::new();
        reader.read_to_end(&mut out).await.unwrap();
        assert_eq!(out.len(), 50);
    }
}
