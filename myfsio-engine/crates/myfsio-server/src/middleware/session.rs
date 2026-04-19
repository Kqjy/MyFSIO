use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use cookie::{Cookie, SameSite};
use parking_lot::Mutex;

use crate::session::{
    csrf_tokens_match, SessionData, SessionStore, CSRF_FIELD_NAME, CSRF_HEADER_NAME,
    SESSION_COOKIE_NAME,
};

#[derive(Clone)]
pub struct SessionLayerState {
    pub store: Arc<SessionStore>,
    pub secure: bool,
}

#[derive(Clone)]
pub struct SessionHandle {
    pub id: String,
    inner: Arc<Mutex<SessionData>>,
    dirty: Arc<Mutex<bool>>,
}

impl SessionHandle {
    pub fn new(id: String, data: SessionData) -> Self {
        Self {
            id,
            inner: Arc::new(Mutex::new(data)),
            dirty: Arc::new(Mutex::new(false)),
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
}

pub async fn session_layer(
    State(state): State<SessionLayerState>,
    mut req: Request,
    next: Next,
) -> Response {
    let cookie_id = extract_session_cookie(&req);

    let (session_id, session_data, is_new) = match cookie_id.and_then(|id| {
        state
            .store
            .get(&id)
            .map(|data| (id.clone(), data))
    }) {
        Some((id, data)) => (id, data, false),
        None => {
            let (id, data) = state.store.create();
            (id, data, true)
        }
    };

    let handle = SessionHandle::new(session_id.clone(), session_data);
    req.extensions_mut().insert(handle.clone());

    let mut resp = next.run(req).await;

    if handle.is_dirty() {
        state.store.save(&handle.id, handle.snapshot());
    }

    if is_new {
        let cookie = build_session_cookie(&session_id, state.secure);
        if let Ok(value) = HeaderValue::from_str(&cookie.to_string()) {
            resp.headers_mut().append(header::SET_COOKIE, value);
        }
    }

    resp
}

pub async fn csrf_layer(req: Request, next: Next) -> Response {
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
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    if let Some(token) = header_token {
        if csrf_tokens_match(&expected, &token) {
            return next.run(req).await;
        }
    }

    let (parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "Body read failed").into_response(),
    };

    let content_type = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let form_token = if content_type.starts_with("application/x-www-form-urlencoded") {
        extract_form_token(&bytes)
    } else {
        None
    };

    if let Some(token) = form_token {
        if csrf_tokens_match(&expected, &token) {
            let req = Request::from_parts(parts, axum::body::Body::from(bytes));
            return next.run(req).await;
        }
    }

    (StatusCode::FORBIDDEN, "Invalid CSRF token").into_response()
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

fn build_session_cookie(id: &str, secure: bool) -> Cookie<'static> {
    let mut cookie = Cookie::new(SESSION_COOKIE_NAME, id.to_string());
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_secure(secure);
    cookie.set_path("/");
    cookie
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
