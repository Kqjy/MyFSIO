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
        .last()
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
