use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use myfsio_storage::traits::StorageEngine;

use crate::state::AppState;

#[derive(Debug, Default, Clone)]
struct CorsRule {
    allowed_origins: Vec<String>,
    allowed_methods: Vec<String>,
    allowed_headers: Vec<String>,
    expose_headers: Vec<String>,
    max_age_seconds: Option<u64>,
}

fn parse_cors_config(xml: &str) -> Vec<CorsRule> {
    let doc = match roxmltree::Document::parse(xml) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    let mut rules = Vec::new();
    for rule_node in doc
        .descendants()
        .filter(|node| node.is_element() && node.tag_name().name() == "CORSRule")
    {
        let mut rule = CorsRule::default();
        for child in rule_node.children().filter(|n| n.is_element()) {
            let text = child.text().unwrap_or("").trim().to_string();
            match child.tag_name().name() {
                "AllowedOrigin" => rule.allowed_origins.push(text),
                "AllowedMethod" => rule.allowed_methods.push(text.to_ascii_uppercase()),
                "AllowedHeader" => rule.allowed_headers.push(text),
                "ExposeHeader" => rule.expose_headers.push(text),
                "MaxAgeSeconds" => {
                    if let Ok(v) = text.parse::<u64>() {
                        rule.max_age_seconds = Some(v);
                    }
                }
                _ => {}
            }
        }
        rules.push(rule);
    }
    rules
}

fn match_origin(pattern: &str, origin: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if pattern == origin {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return origin.ends_with(suffix);
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return origin.starts_with(prefix);
    }
    false
}

fn match_header(pattern: &str, header: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    pattern.eq_ignore_ascii_case(header)
}

fn find_matching_rule<'a>(
    rules: &'a [CorsRule],
    origin: &str,
    method: &str,
    request_headers: &[&str],
) -> Option<&'a CorsRule> {
    rules.iter().find(|rule| {
        let origin_match = rule.allowed_origins.iter().any(|p| match_origin(p, origin));
        if !origin_match {
            return false;
        }
        let method_match = rule
            .allowed_methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(method));
        if !method_match {
            return false;
        }
        request_headers.iter().all(|h| {
            rule.allowed_headers
                .iter()
                .any(|pattern| match_header(pattern, h))
        })
    })
}

fn find_matching_rule_for_actual<'a>(
    rules: &'a [CorsRule],
    origin: &str,
    method: &str,
) -> Option<&'a CorsRule> {
    rules.iter().find(|rule| {
        rule.allowed_origins.iter().any(|p| match_origin(p, origin))
            && rule
                .allowed_methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case(method))
    })
}

fn bucket_from_path(path: &str) -> Option<&str> {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with("admin/")
        || trimmed.starts_with("myfsio/")
        || trimmed.starts_with("kms/")
    {
        return None;
    }
    let first = trimmed.split('/').next().unwrap_or("");
    if myfsio_storage::validation::validate_bucket_name(first).is_some() {
        return None;
    }
    Some(first)
}

async fn bucket_from_host(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let host = headers
        .get("host")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(':').next())?
        .trim()
        .to_ascii_lowercase();
    let (candidate, _) = host.split_once('.')?;
    if myfsio_storage::validation::validate_bucket_name(candidate).is_some() {
        return None;
    }
    match state.storage.bucket_exists(candidate).await {
        Ok(true) => Some(candidate.to_string()),
        _ => None,
    }
}

async fn resolve_bucket(state: &AppState, headers: &HeaderMap, path: &str) -> Option<String> {
    if let Some(name) = bucket_from_host(state, headers).await {
        return Some(name);
    }
    bucket_from_path(path).map(str::to_string)
}

fn apply_rule_headers(headers: &mut axum::http::HeaderMap, rule: &CorsRule, origin: &str) {
    headers.remove("access-control-allow-origin");
    headers.remove("vary");
    if let Ok(val) = HeaderValue::from_str(origin) {
        headers.insert("access-control-allow-origin", val);
    }
    headers.insert("vary", HeaderValue::from_static("Origin"));
    if !rule.expose_headers.is_empty() {
        let value = rule.expose_headers.join(", ");
        if let Ok(val) = HeaderValue::from_str(&value) {
            headers.remove("access-control-expose-headers");
            headers.insert("access-control-expose-headers", val);
        }
    }
}

fn strip_cors_response_headers(headers: &mut HeaderMap) {
    headers.remove("access-control-allow-origin");
    headers.remove("access-control-allow-credentials");
    headers.remove("access-control-expose-headers");
    headers.remove("access-control-allow-methods");
    headers.remove("access-control-allow-headers");
    headers.remove("access-control-max-age");
}

pub async fn bucket_cors_layer(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();
    let bucket = match resolve_bucket(&state, req.headers(), &path).await {
        Some(name) => name,
        None => return next.run(req).await,
    };

    let origin = req
        .headers()
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let bucket_rules = if origin.is_some() {
        match state.storage.get_bucket_config(&bucket).await {
            Ok(cfg) => cfg
                .cors
                .as_ref()
                .map(|v| match v {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .map(|xml| parse_cors_config(&xml))
                .filter(|rules| !rules.is_empty()),
            Err(_) => None,
        }
    } else {
        None
    };

    let is_preflight = req.method() == Method::OPTIONS
        && req.headers().contains_key("access-control-request-method");

    if is_preflight {
        if let (Some(origin), Some(rules)) = (origin.as_deref(), bucket_rules.as_ref()) {
            let req_method = req
                .headers()
                .get("access-control-request-method")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let req_headers_raw = req
                .headers()
                .get("access-control-request-headers")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let req_headers: Vec<&str> = req_headers_raw
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();

            if let Some(rule) = find_matching_rule(rules, origin, req_method, &req_headers) {
                let mut resp = StatusCode::NO_CONTENT.into_response();
                apply_rule_headers(resp.headers_mut(), rule, origin);
                let methods_value = rule.allowed_methods.join(", ");
                if let Ok(val) = HeaderValue::from_str(&methods_value) {
                    resp.headers_mut()
                        .insert("access-control-allow-methods", val);
                }
                let headers_value = if rule.allowed_headers.iter().any(|h| h == "*") {
                    req_headers_raw.to_string()
                } else {
                    rule.allowed_headers.join(", ")
                };
                if !headers_value.is_empty() {
                    if let Ok(val) = HeaderValue::from_str(&headers_value) {
                        resp.headers_mut()
                            .insert("access-control-allow-headers", val);
                    }
                }
                if let Some(max_age) = rule.max_age_seconds {
                    if let Ok(val) = HeaderValue::from_str(&max_age.to_string()) {
                        resp.headers_mut().insert("access-control-max-age", val);
                    }
                }
                return resp;
            }
            return (StatusCode::FORBIDDEN, "CORSResponse: CORS is not enabled").into_response();
        }
    }

    let method = req.method().clone();
    let mut resp = next.run(req).await;

    if let (Some(origin), Some(rules)) = (origin.as_deref(), bucket_rules.as_ref()) {
        if let Some(rule) = find_matching_rule_for_actual(rules, origin, method.as_str()) {
            apply_rule_headers(resp.headers_mut(), rule, origin);
        } else {
            strip_cors_response_headers(resp.headers_mut());
        }
    }

    resp
}
