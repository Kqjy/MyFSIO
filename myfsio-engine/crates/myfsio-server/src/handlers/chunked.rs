use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, ReadBuf};

enum State {
    ReadSize,
    ReadData(u64),
    ReadTrailer,
    Finished,
}

pub struct AwsChunkedStream<S> {
    inner: S,
    buffer: BytesMut,
    state: State,
    pending: BytesMut,
    eof: bool,
}

impl<S> AwsChunkedStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            buffer: BytesMut::with_capacity(8192),
            state: State::ReadSize,
            pending: BytesMut::new(),
            eof: false,
        }
    }

    fn find_crlf(&self) -> Option<usize> {
        for i in 0..self.buffer.len().saturating_sub(1) {
            if self.buffer[i] == b'\r' && self.buffer[i + 1] == b'\n' {
                return Some(i);
            }
        }
        None
    }

    fn parse_chunk_size(line: &[u8]) -> std::io::Result<u64> {
        let text = std::str::from_utf8(line).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid chunk size encoding")
        })?;
        let head = text.split(';').next().unwrap_or("").trim();
        u64::from_str_radix(head, 16).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid chunk size: {}", head),
            )
        })
    }

    fn try_advance(&mut self, out: &mut ReadBuf<'_>) -> std::io::Result<bool> {
        loop {
            if out.remaining() == 0 {
                return Ok(true);
            }

            if !self.pending.is_empty() {
                let take = std::cmp::min(self.pending.len(), out.remaining());
                out.put_slice(&self.pending[..take]);
                self.pending.advance(take);
                continue;
            }

            match self.state {
                State::Finished => return Ok(true),
                State::ReadSize => {
                    let idx = match self.find_crlf() {
                        Some(i) => i,
                        None => return Ok(false),
                    };
                    let line = self.buffer.split_to(idx);
                    self.buffer.advance(2);
                    let size = Self::parse_chunk_size(&line)?;
                    if size == 0 {
                        self.state = State::ReadTrailer;
                    } else {
                        self.state = State::ReadData(size);
                    }
                }
                State::ReadData(remaining) => {
                    if self.buffer.is_empty() {
                        return Ok(false);
                    }
                    let avail = std::cmp::min(self.buffer.len() as u64, remaining) as usize;
                    let take = std::cmp::min(avail, out.remaining());
                    out.put_slice(&self.buffer[..take]);
                    self.buffer.advance(take);
                    let new_remaining = remaining - take as u64;
                    if new_remaining == 0 {
                        if self.buffer.len() < 2 {
                            self.state = State::ReadData(0);
                            return Ok(false);
                        }
                        if &self.buffer[..2] != b"\r\n" {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "malformed chunk terminator",
                            ));
                        }
                        self.buffer.advance(2);
                        self.state = State::ReadSize;
                    } else {
                        self.state = State::ReadData(new_remaining);
                    }
                }
                State::ReadTrailer => {
                    let idx = match self.find_crlf() {
                        Some(i) => i,
                        None => return Ok(false),
                    };
                    if idx == 0 {
                        self.buffer.advance(2);
                        self.state = State::Finished;
                    } else {
                        self.buffer.advance(idx + 2);
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
                Ok(v) => v,
                Err(e) => return Poll::Ready(Err(e)),
            };
            if buf.filled().len() > before {
                return Poll::Ready(Ok(()));
            }
            if done {
                return Poll::Ready(Ok(()));
            }
            if self.eof {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "unexpected EOF in aws-chunked stream",
                )));
            }

            let mut tmp = [0u8; 8192];
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    if n == 0 {
                        self.eof = true;
                        continue;
                    }
                    self.buffer.extend_from_slice(rb.filled());
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

pub fn decode_body(body: axum::body::Body) -> impl AsyncRead + Send + Unpin {
    use futures::TryStreamExt;
    let stream = tokio_util::io::StreamReader::new(
        http_body_util::BodyStream::new(body)
            .map_ok(|frame| frame.into_data().unwrap_or_default())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)),
    );
    AwsChunkedStream::new(stream)
}

