use std::collections::HashMap;
use std::error::Error as StdError;

use axum::extract::{Extension, Form, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use tera::Context;

use crate::middleware::session::SessionHandle;
use crate::session::FlashMessage;
use crate::state::AppState;

pub async fn login_page(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
) -> Response {
    if session.read(|s| s.is_authenticated()) {
        return Redirect::to("/ui/buckets").into_response();
    }

    let mut ctx = base_context(&session, None);
    let flashed = session.write(|s| s.take_flash());
    inject_flash(&mut ctx, flashed);

    render(&state, "login.html", &ctx)
}

#[derive(serde::Deserialize)]
pub struct LoginForm {
    pub access_key: String,
    pub secret_key: String,
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub next: Option<String>,
}

pub async fn login_submit(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
    Form(form): Form<LoginForm>,
) -> Response {
    let access_key = form.access_key.trim();
    let secret_key = form.secret_key.trim();

    match state.iam.get_secret_key(access_key) {
        Some(expected) if constant_time_eq_str(&expected, secret_key) => {
            let display = state
                .iam
                .get_user(access_key)
                .await
                .and_then(|v| {
                    v.get("display_name")
                        .and_then(|d| d.as_str())
                        .map(|s| s.to_string())
                })
                .unwrap_or_else(|| access_key.to_string());

            session.rotate_id();
            session.write(|s| {
                s.user_id = Some(access_key.to_string());
                s.display_name = Some(display);
                s.rotate_csrf();
                s.push_flash("success", "Signed in successfully.");
            });

            let next = form
                .next
                .as_deref()
                .filter(|n| is_allowed_redirect(n, &state.config.allowed_redirect_hosts))
                .unwrap_or("/ui/buckets")
                .to_string();
            Redirect::to(&next).into_response()
        }
        _ => {
            session.write(|s| {
                s.push_flash("danger", "Invalid access key or secret key.");
            });
            Redirect::to("/login").into_response()
        }
    }
}

fn is_allowed_redirect(target: &str, allowed_hosts: &[String]) -> bool {
    if target == "/ui" || target.starts_with("/ui/") {
        return true;
    }
    let Some(rest) = target
        .strip_prefix("https://")
        .or_else(|| target.strip_prefix("http://"))
    else {
        return false;
    };
    let host = rest
        .split('/')
        .next()
        .unwrap_or_default()
        .split('@')
        .next_back()
        .unwrap_or_default()
        .split(':')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    allowed_hosts
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&host))
}

pub async fn logout(Extension(session): Extension<SessionHandle>) -> Response {
    session.write(|s| {
        s.user_id = None;
        s.display_name = None;
        s.flash.clear();
        s.rotate_csrf();
        s.push_flash("info", "Signed out.");
    });
    Redirect::to("/login").into_response()
}

pub async fn root_redirect() -> Response {
    Redirect::to("/ui/buckets").into_response()
}

pub async fn not_found_page(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
) -> Response {
    let ctx = base_context(&session, None);
    let mut resp = render(&state, "404.html", &ctx);
    *resp.status_mut() = StatusCode::NOT_FOUND;
    resp
}

pub async fn require_login(
    Extension(session): Extension<SessionHandle>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if session.read(|s| s.is_authenticated()) {
        return next.run(req).await;
    }
    let path = req.uri().path().to_string();
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{}", q))
        .unwrap_or_default();
    let next_url = format!("{}{}", path, query);
    let encoded =
        percent_encoding::utf8_percent_encode(&next_url, percent_encoding::NON_ALPHANUMERIC)
            .to_string();
    let target = format!("/login?next={}", encoded);
    Redirect::to(&target).into_response()
}

fn session_principal(
    state: &AppState,
    session: &SessionHandle,
) -> Option<myfsio_common::types::Principal> {
    let access_key = session.read(|s| s.user_id.clone())?;
    state.iam.get_principal(&access_key)
}

pub fn current_principal(
    state: &AppState,
    session: &SessionHandle,
) -> Option<myfsio_common::types::Principal> {
    session_principal(state, session)
}

pub fn ensure_admin(
    state: &AppState,
    session: &SessionHandle,
    headers: &HeaderMap,
) -> Option<Response> {
    let is_admin = current_principal(state, session)
        .map(|p| p.is_admin)
        .unwrap_or(false);
    if is_admin {
        return None;
    }
    let wants_json = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("application/json"))
        .unwrap_or(false)
        || headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.starts_with("application/json"))
            .unwrap_or(false);
    if wants_json {
        return Some(
            (
                StatusCode::FORBIDDEN,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                serde_json::json!({"error": "Admin privileges required."}).to_string(),
            )
                .into_response(),
        );
    }
    session.write(|s| s.push_flash("danger", "Admin privileges required."));
    Some(Redirect::to("/ui/buckets").into_response())
}

pub async fn ui_admin_audit_layer(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let method = req.method().clone();
    let should_audit = matches!(
        method,
        axum::http::Method::POST
            | axum::http::Method::PUT
            | axum::http::Method::PATCH
            | axum::http::Method::DELETE
    );
    let path = req.uri().path().to_string();
    let response = next.run(req).await;
    if should_audit && state.audit_log.enabled() {
        let status = response.status().as_u16();
        audit_admin_action(
            &state,
            &session,
            &format!("ui:{} {}", method, path),
            method.as_str(),
            &path,
            status,
            None,
        );
    }
    response
}

pub fn audit_admin_action(
    state: &AppState,
    session: &SessionHandle,
    action: &str,
    method: &str,
    path: &str,
    status_code: u16,
    error: Option<String>,
) {
    if !state.audit_log.enabled() {
        return;
    }
    let admin_user = session.read(|s| s.user_id.clone());
    let result = if (200..400).contains(&status_code) {
        "ok".to_string()
    } else {
        "error".to_string()
    };
    state
        .audit_log
        .record(crate::services::audit_log::AuditEntry {
            ts: chrono::Utc::now().to_rfc3339(),
            correlation_id: uuid::Uuid::new_v4().to_string(),
            origin_site_id: None,
            admin_user_id: admin_user,
            action: action.to_string(),
            method: method.to_string(),
            path: path.to_string(),
            target: crate::services::audit_log::AuditTarget::Local,
            result,
            status_code,
            peer_ip: None,
            idempotency_key: None,
            error,
            attribution: Some(crate::services::audit_log::ATTRIBUTION_VERIFIED.to_string()),
        });
}

pub async fn require_admin(
    State(state): State<AppState>,
    Extension(session): Extension<SessionHandle>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let principal = match session_principal(&state, &session) {
        Some(p) => p,
        None => {
            return forbid(&state, &session, &req, "Sign in as an admin to continue.");
        }
    };
    if !principal.is_admin {
        return forbid(
            &state,
            &session,
            &req,
            "Admin privileges are required for this action.",
        );
    }
    next.run(req).await
}

fn forbid(
    _state: &AppState,
    session: &SessionHandle,
    req: &axum::extract::Request,
    message: &str,
) -> Response {
    let wants_json = req
        .headers()
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("application/json"))
        .unwrap_or(false)
        || req
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.starts_with("application/json"))
            .unwrap_or(false);
    if wants_json {
        return (
            StatusCode::FORBIDDEN,
            [(
                axum::http::header::CONTENT_TYPE,
                "application/json",
            )],
            serde_json::json!({ "error": message }).to_string(),
        )
            .into_response();
    }
    session.write(|s| s.push_flash("danger", message.to_string()));
    Redirect::to("/ui/buckets").into_response()
}

pub fn render(state: &AppState, template: &str, ctx: &Context) -> Response {
    let engine = match &state.templates {
        Some(e) => e,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Templates not configured",
            )
                .into_response();
        }
    };
    match engine.render(template, ctx) {
        Ok(html) => {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                "text/html; charset=utf-8".parse().unwrap(),
            );
            (StatusCode::OK, headers, html).into_response()
        }
        Err(e) => {
            let mut detail = format!("{}", e);
            let mut src = StdError::source(&e);
            while let Some(s) = src {
                detail.push_str(" | ");
                detail.push_str(&s.to_string());
                src = s.source();
            }
            tracing::error!("Template render failed ({}): {}", template, detail);
            let fallback_ctx = Context::new();
            let body = if template != "500.html" {
                engine
                    .render("500.html", &fallback_ctx)
                    .unwrap_or_else(|_| "Internal Server Error".to_string())
            } else {
                "Internal Server Error".to_string()
            };
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                "text/html; charset=utf-8".parse().unwrap(),
            );
            (StatusCode::INTERNAL_SERVER_ERROR, headers, body).into_response()
        }
    }
}

pub fn base_context(session: &SessionHandle, endpoint: Option<&str>) -> Context {
    let mut ctx = Context::new();
    let snapshot = session.snapshot();
    ctx.insert("csrf_token_value", &snapshot.csrf_token);
    ctx.insert("is_authenticated", &snapshot.user_id.is_some());
    ctx.insert("current_user", &snapshot.user_id);
    ctx.insert("current_user_display_name", &snapshot.display_name);
    ctx.insert("current_endpoint", &endpoint.unwrap_or(""));
    ctx.insert("request_args", &HashMap::<String, String>::new());
    ctx.insert("null", &serde_json::Value::Null);
    ctx.insert("none", &serde_json::Value::Null);
    ctx
}

pub fn inject_flash(ctx: &mut Context, flashed: Vec<FlashMessage>) {
    ctx.insert("flashed_messages", &flashed);
}

fn constant_time_eq_str(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    subtle::ConstantTimeEq::ct_eq(a.as_bytes(), b.as_bytes()).into()
}
