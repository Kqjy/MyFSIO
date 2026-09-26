use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::{header, Method};
use axum::response::Response;
use bytes::Bytes;
use http_body::{Frame, SizeHint};

use crate::services::metrics::MetricsService;

type DoneCallback = Box<dyn FnOnce(u64) + Send>;

pub(crate) fn response_bytes_out(method: &Method, response: &Response) -> Option<u64> {
    let status = response.status();
    if *method == Method::HEAD
        || status.is_informational()
        || status == axum::http::StatusCode::NO_CONTENT
        || status == axum::http::StatusCode::NOT_MODIFIED
    {
        return Some(0);
    }
    response
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .or_else(|| http_body::Body::size_hint(response.body()).exact())
}

pub(crate) fn count_streamed_bytes(
    response: Response,
    metrics: Arc<MetricsService>,
    method: &str,
    endpoint_type: &'static str,
    source: &'static str,
) -> Response {
    let method = method.to_string();
    response.map(move |body| {
        Body::new(CountingBody::new(
            body,
            Box::new(move |bytes| metrics.record_bytes_out(source, &method, endpoint_type, bytes)),
        ))
    })
}

struct CountingBody {
    inner: Body,
    bytes: u64,
    on_done: Option<DoneCallback>,
}

impl CountingBody {
    fn new(inner: Body, on_done: DoneCallback) -> Self {
        Self {
            inner,
            bytes: 0,
            on_done: Some(on_done),
        }
    }

    fn finish(&mut self) {
        if let Some(callback) = self.on_done.take() {
            callback(self.bytes);
        }
    }
}

impl http_body::Body for CountingBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.bytes += data.len() as u64;
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(None) => {
                this.finish();
                Poll::Ready(None)
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for CountingBody {
    fn drop(&mut self) {
        self.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use std::sync::Mutex;

    fn streamed(chunks: Vec<&'static [u8]>) -> Body {
        let stream = futures::stream::iter(
            chunks
                .into_iter()
                .map(|chunk| Ok::<_, std::io::Error>(Bytes::from_static(chunk))),
        );
        Body::from_stream(stream)
    }

    #[test]
    fn head_and_empty_statuses_report_zero_bytes() {
        let response = Response::builder()
            .header(header::CONTENT_LENGTH, "1048576")
            .body(Body::empty())
            .unwrap();
        assert_eq!(response_bytes_out(&Method::HEAD, &response), Some(0));
        assert_eq!(response_bytes_out(&Method::GET, &response), Some(1_048_576));

        let not_modified = Response::builder().status(304).body(Body::empty()).unwrap();
        assert_eq!(response_bytes_out(&Method::GET, &not_modified), Some(0));
    }

    #[test]
    fn exact_size_hint_covers_missing_content_length() {
        let response = Response::new(Body::from("hello world"));
        assert!(response.headers().get(header::CONTENT_LENGTH).is_none());
        assert_eq!(response_bytes_out(&Method::GET, &response), Some(11));

        let streaming = Response::new(streamed(vec![b"abc"]));
        assert_eq!(response_bytes_out(&Method::GET, &streaming), None);
    }

    #[tokio::test]
    async fn counting_body_reports_streamed_bytes_once() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let body = CountingBody::new(
            streamed(vec![b"abcd", b"efghij"]),
            Box::new(move |bytes| sink.lock().unwrap().push(bytes)),
        );
        let collected = Body::new(body).collect().await.unwrap().to_bytes();
        assert_eq!(collected.len(), 10);
        assert_eq!(*seen.lock().unwrap(), vec![10]);
    }

    #[tokio::test]
    async fn counting_body_reports_partial_bytes_when_dropped() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let mut body = Body::new(CountingBody::new(
            streamed(vec![b"abcd", b"efghij"]),
            Box::new(move |bytes| sink.lock().unwrap().push(bytes)),
        ));
        let first = body.frame().await.unwrap().unwrap();
        assert_eq!(first.data_ref().unwrap().len(), 4);
        drop(body);
        assert_eq!(*seen.lock().unwrap(), vec![4]);
    }
}
