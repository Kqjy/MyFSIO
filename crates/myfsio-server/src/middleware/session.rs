use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use cookie::{time::Duration as CookieDuration, Cookie, SameSite};
use parking_lot::Mutex;

use crate::session::{
    csrf_tokens_match, SessionData, SessionStore, CSRF_FIELD_NAME, CSRF_HEADER_NAME,
    SESSION_COOKIE_NAME,
};

#[derive(Clone)]
pub struct SessionLayerState {
    pub store: Arc<SessionStore>,
    pub secure: bool,
    pub ttl: Duration,
}

#[derive(Clone)]
pub struct SessionHandle {
    pub id: String,
    inner: Arc<Mutex<SessionData>>,
    dirty: Arc<Mutex<bool>>,
    rotated_id: Arc<Mutex<Option<String>>>,
    destroy_old: Arc<Mutex<Option<String>>>,
}

impl SessionHandle {
    pub fn new(id: String, data: SessionData) -> Self {
        Self {
            id,
            inner: Arc::new(Mutex::new(data)),
            dirty: Arc::new(Mutex::new(false)),
            rotated_id: Arc::new(Mutex::new(None)),
            destroy_old: Arc::new(Mutex::new(None)),
        }
    }

    pub fn read<R>(&self, f: impl FnOnce(&SessionData) -> R) -> R {
        let guard = self.inner.lock();
        f(&guard)
    }

    pub fn write<R>(&self, f: impl FnOnce(&mut SessionData) -> R) -> R {
        let mut guard = self.inner.lock();
        let out = f(&mut guard);
        *self.dirty.lock() = true;
        out
    }

    pub fn snapshot(&self) -> SessionData {
        self.inner.lock().clone()
    }

    pub fn is_dirty(&self) -> bool {
        *self.dirty.lock()
    }

    pub fn rotate_id(&self) {
        let new_id = crate::session::generate_token(32);
        *self.destroy_old.lock() = Some(self.id.clone());
        *self.rotated_id.lock() = Some(new_id);
        *self.dirty.lock() = true;
    }

    pub(crate) fn take_rotated_id(&self) -> Option<String> {
        self.rotated_id.lock().take()
    }

    pub(crate) fn take_destroy_old(&self) -> Option<String> {
        self.destroy_old.lock().take()
    }
}

pub async fn session_layer(
    State(state): State<SessionLayerState>,
    mut req: Request,
    next: Next,
) -> Response {
    let cookie_id = extract_session_cookie(&req);

    let (session_id, session_data) =
        match cookie_id.and_then(|id| state.store.get(&id).map(|data| (id.clone(), data))) {
            Some((id, data)) => (id, data),
            None => state.store.create(),
        };

    let handle = SessionHandle::new(session_id.clone(), session_data);
    req.extensions_mut().insert(handle.clone());

    let mut resp = next.run(req).await;

    let rotated = handle.take_rotated_id();
    let destroy_old = handle.take_destroy_old();

    let effective_id = rotated.unwrap_or_else(|| handle.id.clone());

    if handle.is_dirty() {
        state.store.save(&effective_id, handle.snapshot());
    }

    if let Some(old) = destroy_old {
        state.store.destroy(&old);
    }

    let cookie = build_session_cookie(&effective_id, state.secure, state.ttl);
    if let Ok(value) = HeaderValue::from_str(&cookie.to_string()) {
        resp.headers_mut().append(header::SET_COOKIE, value);
    }

    resp
}

pub async fn csrf_layer(
    State(state): State<crate::state::AppState>,
    req: Request,
    next: Next,
) -> Response {
    const CSRF_HEADER_ALIAS: &str = "x-csrftoken";

    let method = req.method().clone();
    let needs_check = matches!(
        method,
        axum::http::Method::POST
            | axum::http::Method::PUT
            | axum::http::Method::PATCH
            | axum::http::Method::DELETE
    );

    if !needs_check {
        return next.run(req).await;
    }

    let is_ui = req.uri().path().starts_with("/ui/")
        || req.uri().path() == "/ui"
        || req.uri().path() == "/login"
        || req.uri().path() == "/logout";
    if !is_ui {
        return next.run(req).await;
    }

    let handle = match req.extensions().get::<SessionHandle>() {
        Some(h) => h.clone(),
        None => return (StatusCode::FORBIDDEN, "Missing session").into_response(),
    };

    let expected = handle.read(|s| s.csrf_token.clone());

    let header_token = req
        .headers()
        .get(CSRF_HEADER_NAME)
        .or_else(|| req.headers().get(CSRF_HEADER_ALIAS))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    if let Some(token) = header_token.as_deref() {
        if csrf_tokens_match(&expected, token) {
            return next.run(req).await;
        }
    }

    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    const NON_MULTIPART_BODY_LIMIT: usize = 1 << 20;
    const MULTIPART_PREFIX_LIMIT: usize = 256 * 1024;

    let is_multipart = content_type.starts_with("multipart/form-data");
    let is_form = content_type.starts_with("application/x-www-form-urlencoded");
    let is_json = content_type.starts_with("application/json");

    let (parts, body) = req.into_parts();

    let mismatch_response = |parts: &axum::http::request::Parts,
                             handle: SessionHandle,
                             state: crate::state::AppState,
                             content_type: &str,
                             expected_len: usize,
                             header_present: bool|
     -> Response {
        tracing::warn!(
            path = %parts.uri.path(),
            content_type = %content_type,
            expected_len = expected_len,
            header_present = header_present,
            "CSRF token mismatch"
        );
        let accept = parts
            .headers
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let is_form_submit = content_type.starts_with("application/x-www-form-urlencoded")
            || content_type.starts_with("multipart/form-data");
        let wants_json =
            accept.contains("application/json") || content_type.starts_with("application/json");
        if is_form_submit && !wants_json {
            let ctx = crate::handlers::ui::base_context(&handle, None);
            let mut resp = crate::handlers::ui::render(&state, "csrf_error.html", &ctx);
            *resp.status_mut() = StatusCode::FORBIDDEN;
            return resp;
        }
        let mut resp = (
            StatusCode::FORBIDDEN,
            [(header::CONTENT_TYPE, "application/json")],
            r#"{"error":"Invalid CSRF token. Send it via the X-CSRF-Token header or a csrf_token field in the form/JSON body."}"#,
        )
            .into_response();
        *resp.status_mut() = StatusCode::FORBIDDEN;
        resp
    };

    if is_multipart {
        use futures::StreamExt;
        use http_body_util::BodyStream;

        let mut frames = BodyStream::new(body);
        let mut prefix_chunks: Vec<bytes::Bytes> = Vec::new();
        let mut prefix_buf: Vec<u8> = Vec::with_capacity(8192);
        let mut found_token: Option<String> = None;
        let mut prefix_eof = false;

        while prefix_buf.len() < MULTIPART_PREFIX_LIMIT {
            match frames.next().await {
                Some(Ok(frame)) => {
                    let data = frame.into_data().unwrap_or_default();
                    if data.is_empty() {
                        continue;
                    }
                    prefix_buf.extend_from_slice(&data);
                    prefix_chunks.push(data);
                    if let Some(token) = extract_multipart_token(&content_type, &prefix_buf) {
                        found_token = Some(token);
                        break;
                    }
                }
                Some(Err(_)) => {
                    return (StatusCode::BAD_REQUEST, "Body read failed").into_response();
                }
                None => {
                    prefix_eof = true;
                    break;
                }
            }
        }

        let valid = found_token
            .as_deref()
            .map(|t| csrf_tokens_match(&expected, t))
            .unwrap_or(false);

        if !valid {
            return mismatch_response(
                &parts,
                handle.clone(),
                state.clone(),
                &content_type,
                expected.len(),
                header_token.is_some(),
            );
        }

        let prefix_stream = futures::stream::iter(
            prefix_chunks
                .into_iter()
                .map(Ok::<bytes::Bytes, std::io::Error>),
        );
        let new_body = if prefix_eof {
            axum::body::Body::from_stream(prefix_stream)
        } else {
            let rest_stream = frames
                .map(|res| {
                    res.map(|frame| frame.into_data().unwrap_or_default())
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
                });
            axum::body::Body::from_stream(prefix_stream.chain(rest_stream))
        };
        let req = Request::from_parts(parts, new_body);
        return next.run(req).await;
    }

    let bytes = match axum::body::to_bytes(body, NON_MULTIPART_BODY_LIMIT).await {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                [(header::CONTENT_TYPE, "application/json")],
                r#"{"error":"CSRF token must be sent in the X-CSRF-Token header for large requests."}"#,
            )
                .into_response();
        }
    };

    let form_token = if is_form {
        extract_form_token(&bytes)
    } else if is_json {
        extract_json_token(&bytes)
    } else {
        None
    };

    if let Some(token) = form_token {
        if csrf_tokens_match(&expected, &token) {
            let req = Request::from_parts(parts, axum::body::Body::from(bytes));
            return next.run(req).await;
        }
    }

    mismatch_response(
        &parts,
        handle,
        state,
        &content_type,
        expected.len(),
        header_token.is_some(),
    )
}

fn extract_multipart_token(content_type: &str, body: &[u8]) -> Option<String> {
    let boundary = multer::parse_boundary(content_type).ok()?;
    let prefix = format!("--{}", boundary);
    let text = std::str::from_utf8(body).ok()?;
    let needle = "name=\"csrf_token\"";
    let idx = text.find(needle)?;
    let after = &text[idx + needle.len()..];
    let body_start = after.find("\r\n\r\n")? + 4;
    let tail = &after[body_start..];
    let end = tail
        .find(&format!("\r\n--{}", prefix.trim_start_matches("--")))
        .or_else(|| tail.find("\r\n--"))
        .unwrap_or(tail.len());
    Some(tail[..end].trim().to_string())
}

fn extract_session_cookie(req: &Request) -> Option<String> {
    let raw = req.headers().get(header::COOKIE)?.to_str().ok()?;
    for pair in raw.split(';') {
        if let Ok(cookie) = Cookie::parse(pair.trim().to_string()) {
            if cookie.name() == SESSION_COOKIE_NAME {
                return Some(cookie.value().to_string());
            }
        }
    }
    None
}

fn build_session_cookie(id: &str, secure: bool, ttl: Duration) -> Cookie<'static> {
    let mut cookie = Cookie::new(SESSION_COOKIE_NAME, id.to_string());
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_secure(secure);
    cookie.set_path("/");
    let secs = i64::try_from(ttl.as_secs()).unwrap_or(i64::MAX);
    cookie.set_max_age(CookieDuration::seconds(secs));
    cookie
}

fn extract_json_token(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    value
        .get(CSRF_FIELD_NAME)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn extract_form_token(body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    let prefix = format!("{}=", CSRF_FIELD_NAME);
    for pair in text.split('&') {
        if let Some(rest) = pair.strip_prefix(&prefix) {
            return urldecode(rest);
        }
    }
    None
}

fn urldecode(s: &str) -> Option<String> {
    percent_encoding::percent_decode_str(&s.replace('+', " "))
        .decode_utf8()
        .ok()
        .map(|c| c.into_owned())
}
