use axum::body::Body;
use bytes::Bytes;
use http_body::{Body as HttpBody, Frame};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};

#[derive(Debug)]
struct Sha256MismatchError {
    expected: String,
    computed: String,
}

impl Sha256MismatchError {
    fn message(&self) -> String {
        format!(
            "The x-amz-content-sha256 you specified did not match what we received (expected {}, computed {})",
            self.expected, self.computed
        )
    }
}

impl fmt::Display for Sha256MismatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "XAmzContentSHA256Mismatch: expected {}, computed {}",
            self.expected, self.computed
        )
    }
}

impl Error for Sha256MismatchError {}

pub struct Sha256VerifyBody {
    inner: Body,
    expected: String,
    hasher: Option<Sha256>,
}

impl Sha256VerifyBody {
    pub fn new(inner: Body, expected_hex: String) -> Self {
        Self {
            inner,
            expected: expected_hex.to_ascii_lowercase(),
            hasher: Some(Sha256::new()),
        }
    }
}

impl HttpBody for Sha256VerifyBody {
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(Box::new(e)))),
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    if let Some(h) = this.hasher.as_mut() {
                        h.update(data);
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(None) => {
                if let Some(hasher) = this.hasher.take() {
                    let computed = hex::encode(hasher.finalize());
                    if computed != this.expected {
                        return Poll::Ready(Some(Err(Box::new(Sha256MismatchError {
                            expected: this.expected.clone(),
                            computed,
                        }))));
                    }
                }
                Poll::Ready(None)
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

pub fn is_hex_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn sha256_mismatch_message(err: &(dyn Error + 'static)) -> Option<String> {
    if let Some(mismatch) = err.downcast_ref::<Sha256MismatchError>() {
        return Some(mismatch.message());
    }

    err.source().and_then(sha256_mismatch_message)
}
