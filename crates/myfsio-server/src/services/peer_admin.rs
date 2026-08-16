use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use serde_json::Value;

use crate::services::safe_resolver::SafeResolver;

#[derive(Debug, Clone, Default)]
pub struct PeerErrorBody {
    pub detail: String,
    pub source: Option<String>,
}

fn parse_error_body(body: &str, server_header: Option<&str>) -> PeerErrorBody {
    let mut source = server_header
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| truncate_chars(s, 60));
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return PeerErrorBody {
            detail: String::new(),
            source,
        };
    }

    if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
        let err = value.get("error").unwrap_or(&value);
        let code = err
            .get("code")
            .or_else(|| err.get("Code"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let message = err
            .get("message")
            .or_else(|| err.get("Message"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let detail = match (code, message) {
            (Some(c), Some(m)) => format!("{}: {}", c, m),
            (Some(c), None) => c.to_string(),
            (None, Some(m)) => m.to_string(),
            (None, None) => String::new(),
        };
        if !detail.is_empty() {
            return PeerErrorBody {
                detail: truncate_chars(&detail, 240),
                source,
            };
        }
    }

    if looks_like_html(trimmed) {
        let (detail, html_source) = parse_html_error(trimmed);
        if html_source.is_some() {
            source = html_source;
        }
        if !detail.is_empty() {
            return PeerErrorBody { detail, source };
        }
    }

    if trimmed.starts_with('<') {
        let code = extract_xml_tag(trimmed, "Code");
        let message = extract_xml_tag(trimmed, "Message");
        let detail = match (code, message) {
            (Some(c), Some(m)) => format!("{} — {}", c, m),
            (Some(c), None) => c,
            (None, Some(m)) => m,
            (None, None) => String::new(),
        };
        if !detail.is_empty() {
            return PeerErrorBody {
                detail: truncate_chars(&detail, 240),
                source,
            };
        }
    }

    let collapsed = trimmed
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    PeerErrorBody {
        detail: truncate_chars(&collapsed, 240),
        source,
    }
}

fn looks_like_html(body: &str) -> bool {
    let head = body
        .chars()
        .take(512)
        .collect::<String>()
        .to_ascii_lowercase();
    head.contains("<html") || head.contains("<!doctype html") || head.contains("<body")
}

fn parse_html_error(html: &str) -> (String, Option<String>) {
    let source = html_footer_source(html);
    let detail = html_tag_text(html, "h1")
        .or_else(|| html_tag_text(html, "title"))
        .unwrap_or_else(|| truncate_chars(&html_to_text(html), 240));
    (detail, source)
}

fn html_tag_text(html: &str, tag: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let open = format!("<{}", tag);
    let close = format!("</{}", tag);
    let mut from = 0usize;
    while let Some(offset) = lower[from..].find(&open) {
        let after_name = from + offset + open.len();
        let boundary = lower[after_name..].chars().next();
        if !matches!(boundary, Some(c) if c == '>' || c == '/' || c.is_whitespace()) {
            from = after_name;
            continue;
        }
        let gt = lower[after_name..].find('>')?;
        let text_start = after_name + gt + 1;
        let text_end = match lower[text_start..].find(&close) {
            Some(end) => text_start + end,
            None => html.len(),
        };
        let text = html_to_text(&html[text_start..text_end]);
        if !text.is_empty() {
            return Some(truncate_chars(&text, 240));
        }
        from = text_start;
    }
    None
}

fn html_footer_source(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let start = lower.rfind("<hr")?;
    let text = html_to_text(&html[start..]);
    let text = text.trim();
    if text.is_empty() || text.chars().count() > 60 {
        None
    } else {
        Some(text.to_string())
    }
}

fn html_to_text(html: &str) -> String {
    let lower = html.to_ascii_lowercase();
    let bytes = html.as_bytes();
    let mut out = String::with_capacity(html.len().min(8192));
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'<' {
            let rest = &lower[i..];
            if rest.starts_with("<script") || rest.starts_with("<style") {
                let close = if rest.starts_with("<script") {
                    "</script"
                } else {
                    "</style"
                };
                match lower[i..].find(close) {
                    Some(offset) => i += offset,
                    None => break,
                }
            }
            match lower[i..].find('>') {
                Some(offset) => {
                    i += offset + 1;
                    out.push(' ');
                }
                None => break,
            }
            continue;
        }
        let ch = html[i..].chars().next().unwrap_or(' ');
        out.push(ch);
        i += ch.len_utf8();
    }
    decode_entities(&out.split_whitespace().collect::<Vec<_>>().join(" "))
}

fn decode_entities(text: &str) -> String {
    text.replace("&nbsp;", " ")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)?;
    let value = xml[start..start + end].trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    match s.char_indices().nth(max_chars) {
        Some((boundary, _)) => format!("{}…", &s[..boundary]),
        None => s.to_string(),
    }
}

use myfsio_auth::sigv4::{
    aws_uri_encode, build_string_to_sign, compute_signature, derive_signing_key, sha256_hex,
};

use crate::stores::connections::RemoteConnection;

pub struct PeerAdminClient {
    client: reqwest::Client,
    allow_internal_endpoints: bool,
}

pub enum PeerAdminStatus {
    Ok(Value),
    Unauthorized { status: u16, body: PeerErrorBody },
    HttpError { status: u16, body: PeerErrorBody },
    InvalidJson(String),
    Unreachable(String),
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PeerFailure {
    pub kind: &'static str,
    pub status: Option<u16>,
    pub title: String,
    pub summary: String,
    pub detail: Option<String>,
    pub source: Option<String>,
    pub hint: Option<String>,
}

impl PeerFailure {
    pub fn message(&self) -> String {
        match self.detail.as_deref() {
            Some(d) if !d.is_empty() && !self.summary.contains(d) => {
                format!("{} ({})", self.summary, d)
            }
            _ => self.summary.clone(),
        }
    }

    pub fn legacy_status(&self) -> &'static str {
        match self.kind {
            "unauthorized" => "unauthorized",
            "unreachable" | "not_configured" => "unreachable",
            _ => "error",
        }
    }

    pub fn not_configured() -> Self {
        PeerFailure {
            kind: "not_configured",
            status: None,
            title: "No connection configured".to_string(),
            summary: "This site has no saved connection, so its status cannot be polled."
                .to_string(),
            detail: None,
            source: None,
            hint: Some(
                "Attach a connection holding this peer's credentials from the Sites page."
                    .to_string(),
            ),
        }
    }

    fn http(status: u16, body: PeerErrorBody, unauthorized: bool) -> Self {
        let reason = reason_phrase(status);
        let source = body.source.filter(|s| !s.is_empty());
        let via_proxy = source.is_some();
        let title = match status {
            401 | 403 if via_proxy => "Blocked before reaching the peer".to_string(),
            401 | 403 => "Peer rejected these credentials".to_string(),
            404 => "Admin API not found at this endpoint".to_string(),
            429 => "Peer is rate limiting cluster polls".to_string(),
            502..=504 => "Peer is not serving requests".to_string(),
            s if s >= 500 => "Peer returned a server error".to_string(),
            _ => format!("Peer returned {} {}", status, reason),
        };
        let summary = match &source {
            Some(src) => format!(
                "{} answered {} {} before the request reached the peer's admin API.",
                src, status, reason
            ),
            None => format!("The peer's admin API answered {} {}.", status, reason),
        };
        let hint = match status {
            401 | 403 if via_proxy => Some(
                "Allow /myfsio/admin/cluster/* through the proxy or WAF in front of this peer, and keep the SigV4 Authorization header intact."
                    .to_string(),
            ),
            401 | 403 => Some(
                "Re-issue a peer credential on the remote site and update this site's saved connection."
                    .to_string(),
            ),
            404 => Some(
                "Point the endpoint at the peer's S3 API listener (PORT), not the web UI (UI_PORT)."
                    .to_string(),
            ),
            429 => Some("Raise RATE_LIMIT_ADMIN on the peer or poll less often.".to_string()),
            s if s >= 500 => Some("Check the peer's server logs for the failing request.".to_string()),
            _ => None,
        };
        let detail = body
            .detail
            .trim()
            .to_string()
            .into_option()
            .filter(|d| !is_status_echo(d, status, reason));
        PeerFailure {
            kind: if unauthorized { "unauthorized" } else { "http" },
            status: Some(status),
            title,
            summary,
            detail,
            source,
            hint,
        }
    }

    fn unreachable(detail: String) -> Self {
        let lower = detail.to_ascii_lowercase();
        if lower.contains("no connection configured") {
            return PeerFailure::not_configured();
        }
        let (title, summary, hint) = if lower.contains("endpoint rejected") {
            (
                "Endpoint blocked by policy",
                "The outbound guard refused this endpoint before any request was sent.",
                Some("Set ALLOW_INTERNAL_ENDPOINTS=true if this peer really does live on a private network."),
            )
        } else if lower.contains("timed out") || lower.contains("timeout") {
            (
                "Connection timed out",
                "The peer did not answer within the cluster poll timeout.",
                Some("Confirm the peer is running and reachable from this host."),
            )
        } else if lower.contains("dns") || lower.contains("resolve") {
            (
                "DNS lookup failed",
                "The peer hostname could not be resolved.",
                Some("Check the endpoint hostname on the Sites page."),
            )
        } else if lower.contains("certificate") || lower.contains("tls") || lower.contains("ssl") {
            (
                "TLS handshake failed",
                "The TLS connection to the peer could not be established.",
                Some("Check the peer's certificate chain and hostname."),
            )
        } else if lower.contains("refused") || lower.contains("connect") {
            (
                "Connection refused",
                "Nothing accepted a connection at the peer endpoint.",
                Some("Check the endpoint host and port, and that the peer's API listener is up."),
            )
        } else {
            (
                "Peer unreachable",
                "The request to the peer could not be completed.",
                None,
            )
        };
        PeerFailure {
            kind: "unreachable",
            status: None,
            title: title.to_string(),
            summary: summary.to_string(),
            detail: detail.trim().to_string().into_option(),
            source: None,
            hint: hint.map(str::to_string),
        }
    }

    fn invalid_response(detail: String) -> Self {
        PeerFailure {
            kind: "invalid_response",
            status: None,
            title: "Unexpected response".to_string(),
            summary: "The peer answered successfully but the body was not a MyFSIO admin payload."
                .to_string(),
            detail: detail.trim().to_string().into_option(),
            source: None,
            hint: Some(
                "Confirm the endpoint points at MyFSIO rather than a proxy landing page."
                    .to_string(),
            ),
        }
    }
}

impl PeerAdminStatus {
    pub fn into_result(self) -> Result<Value, PeerFailure> {
        match self {
            PeerAdminStatus::Ok(v) => Ok(v),
            PeerAdminStatus::Unauthorized { status, body } => {
                Err(PeerFailure::http(status, body, true))
            }
            PeerAdminStatus::HttpError { status, body } => {
                Err(PeerFailure::http(status, body, false))
            }
            PeerAdminStatus::InvalidJson(detail) => Err(PeerFailure::invalid_response(detail)),
            PeerAdminStatus::Unreachable(detail) => Err(PeerFailure::unreachable(detail)),
        }
    }
}

trait IntoOption {
    fn into_option(self) -> Option<String>;
}

impl IntoOption for String {
    fn into_option(self) -> Option<String> {
        if self.is_empty() {
            None
        } else {
            Some(self)
        }
    }
}

fn reason_phrase(status: u16) -> &'static str {
    reqwest::StatusCode::from_u16(status)
        .ok()
        .and_then(|s| s.canonical_reason())
        .unwrap_or("Error")
}

fn is_status_echo(detail: &str, status: u16, reason: &str) -> bool {
    let normalized = detail
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    normalized == format!("{} {}", status, reason).to_ascii_lowercase()
        || normalized == reason.to_ascii_lowercase()
        || normalized == status.to_string()
}

impl PeerAdminClient {
    pub fn new(
        connect_timeout: Duration,
        read_timeout: Duration,
        allow_internal_endpoints: bool,
    ) -> Self {
        let resolver: Arc<SafeResolver> = Arc::new(SafeResolver::new(allow_internal_endpoints));
        let client = reqwest::Client::builder()
            .connect_timeout(connect_timeout)
            .timeout(read_timeout)
            .dns_resolver(resolver)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            client,
            allow_internal_endpoints,
        }
    }

    fn sign_get(
        &self,
        endpoint: &str,
        path_and_query: &str,
        connection: &RemoteConnection,
    ) -> Result<reqwest::RequestBuilder, String> {
        let url = format!(
            "{}{}",
            endpoint.trim_end_matches('/'),
            if path_and_query.starts_with('/') {
                path_and_query.to_string()
            } else {
                format!("/{}", path_and_query)
            }
        );
        let parsed = reqwest::Url::parse(&url).map_err(|e| format!("invalid url: {}", e))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| "missing host".to_string())?
            .to_string();
        let host_with_port = match parsed.port() {
            Some(p) => format!("{}:{}", host, p),
            None => host.clone(),
        };
        let canonical_uri = parsed.path().to_string();
        let canonical_uri = if canonical_uri.is_empty() {
            "/".to_string()
        } else {
            canonical_uri
        };

        let now = Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();
        let region = if connection.region.is_empty() {
            "us-east-1".to_string()
        } else {
            connection.region.clone()
        };
        let service = "s3";
        let payload_hash = sha256_hex(b"");
        let nonce = uuid::Uuid::new_v4().simple().to_string();

        let canonical_headers = format!(
            "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\nx-myfsio-nonce:{}\n",
            host_with_port, payload_hash, amz_date, nonce
        );
        let signed_headers = "host;x-amz-content-sha256;x-amz-date;x-myfsio-nonce";

        let canonical_query = parsed
            .query()
            .map(|q| {
                let mut pairs: Vec<(String, String)> = q
                    .split('&')
                    .filter(|p| !p.is_empty())
                    .map(|p| {
                        let mut it = p.splitn(2, '=');
                        let k = it.next().unwrap_or("").to_string();
                        let v = it.next().unwrap_or("").to_string();
                        (k, v)
                    })
                    .collect();
                pairs.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
                pairs
                    .iter()
                    .map(|(k, v)| format!("{}={}", aws_uri_encode(k), aws_uri_encode(v)))
                    .collect::<Vec<_>>()
                    .join("&")
            })
            .unwrap_or_default();

        let canonical_request = format!(
            "GET\n{}\n{}\n{}\n{}\n{}",
            canonical_uri, canonical_query, canonical_headers, signed_headers, payload_hash
        );

        let credential_scope = format!("{}/{}/{}/aws4_request", date_stamp, region, service);
        let string_to_sign = build_string_to_sign(&amz_date, &credential_scope, &canonical_request);
        let signing_key = derive_signing_key(&connection.secret_key, &date_stamp, &region, service);
        let signature = compute_signature(&signing_key, &string_to_sign);

        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{},SignedHeaders={},Signature={}",
            connection.access_key, credential_scope, signed_headers, signature
        );

        Ok(self
            .client
            .get(&url)
            .header("host", &host_with_port)
            .header("x-amz-content-sha256", &payload_hash)
            .header("x-amz-date", &amz_date)
            .header("x-myfsio-nonce", &nonce)
            .header("authorization", &authorization))
    }

    async fn guard_endpoint(&self, endpoint: &str) -> Result<(), String> {
        if self.allow_internal_endpoints {
            return Ok(());
        }
        crate::handlers::ui_api::guard_external_endpoint_async(endpoint)
            .await
            .map_err(|reason| {
                format!(
                    "endpoint rejected: {}. Set ALLOW_INTERNAL_ENDPOINTS=true to allow private targets.",
                    reason
                )
            })
    }

    pub async fn fetch_admin_json(
        &self,
        endpoint: &str,
        path_and_query: &str,
        connection: &RemoteConnection,
    ) -> Result<Value, String> {
        self.fetch_admin_status(endpoint, path_and_query, connection)
            .await
            .into_result()
            .map_err(|failure| failure.message())
    }

    pub async fn fetch_admin_status(
        &self,
        endpoint: &str,
        path_and_query: &str,
        connection: &RemoteConnection,
    ) -> PeerAdminStatus {
        if let Err(e) = self.guard_endpoint(endpoint).await {
            return PeerAdminStatus::Unreachable(e);
        }
        let req = match self.sign_get(endpoint, path_and_query, connection) {
            Ok(r) => r,
            Err(e) => return PeerAdminStatus::Unreachable(e),
        };
        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => return PeerAdminStatus::Unreachable(format!("request failed: {}", e)),
        };
        let status = resp.status();
        if status.is_success() {
            return match resp.json::<Value>().await {
                Ok(v) => PeerAdminStatus::Ok(v),
                Err(e) => PeerAdminStatus::InvalidJson(format!("invalid json: {}", e)),
            };
        }
        let server_header = resp
            .headers()
            .get(reqwest::header::SERVER)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_string());
        let body_text = resp.text().await.unwrap_or_default();
        let body = parse_error_body(&body_text, server_header.as_deref());
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            PeerAdminStatus::Unauthorized {
                status: status.as_u16(),
                body,
            }
        } else {
            PeerAdminStatus::HttpError {
                status: status.as_u16(),
                body,
            }
        }
    }

    pub async fn fetch_cluster_overview(
        &self,
        endpoint: &str,
        connection: &RemoteConnection,
    ) -> Result<Value, String> {
        self.fetch_admin_json(
            endpoint,
            "/myfsio/admin/cluster/overview?local_only=1",
            connection,
        )
        .await
    }

    pub async fn check_peer_endpoint_health(
        &self,
        endpoint: &str,
        connection: &RemoteConnection,
    ) -> Result<(), String> {
        self.fetch_admin_status(
            endpoint,
            "/myfsio/admin/cluster/overview?local_only=1",
            connection,
        )
        .await
        .into_result()
        .map(|_| ())
        .map_err(|failure| failure.message())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn relay_request(
        &self,
        endpoint: &str,
        method: &str,
        path_and_query: &str,
        connection: &RemoteConnection,
        body: Vec<u8>,
        content_type: Option<&str>,
        cluster_psk: &str,
        origin_site_id: &str,
        admin_user_id: &str,
        idempotency_key: &str,
        correlation_id: &str,
    ) -> Result<RelayResponse, String> {
        self.guard_endpoint(endpoint).await?;
        let url = format!(
            "{}{}",
            endpoint.trim_end_matches('/'),
            if path_and_query.starts_with('/') {
                path_and_query.to_string()
            } else {
                format!("/{}", path_and_query)
            }
        );
        let parsed = reqwest::Url::parse(&url).map_err(|e| format!("invalid url: {}", e))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| "missing host".to_string())?
            .to_string();
        let host_with_port = match parsed.port() {
            Some(p) => format!("{}:{}", host, p),
            None => host.clone(),
        };
        let canonical_uri = parsed.path().to_string();
        let canonical_uri = if canonical_uri.is_empty() {
            "/".to_string()
        } else {
            canonical_uri
        };

        let now = Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();
        let region = if connection.region.is_empty() {
            "us-east-1".to_string()
        } else {
            connection.region.clone()
        };
        let service = "s3";
        let payload_hash = sha256_hex(&body);
        let nonce = uuid::Uuid::new_v4().simple().to_string();

        let cluster_attest = crate::services::cluster_attest::cluster_attest(
            cluster_psk,
            &amz_date,
            origin_site_id,
            idempotency_key,
        );
        let admin_attest_value = crate::services::cluster_attest::admin_attest(
            cluster_psk,
            &amz_date,
            admin_user_id,
            method,
            &canonical_uri,
            &payload_hash,
            idempotency_key,
        );

        let ct_header = content_type.unwrap_or("application/json");
        let mut header_pairs: Vec<(String, String)> = vec![
            ("content-type".to_string(), ct_header.to_string()),
            ("host".to_string(), host_with_port.clone()),
            ("x-amz-content-sha256".to_string(), payload_hash.clone()),
            ("x-amz-date".to_string(), amz_date.clone()),
            (
                "x-myfsio-admin-attest".to_string(),
                admin_attest_value.clone(),
            ),
            ("x-myfsio-admin-user".to_string(), admin_user_id.to_string()),
            (
                "x-myfsio-cluster-attest".to_string(),
                cluster_attest.clone(),
            ),
            (
                "x-myfsio-correlation-id".to_string(),
                correlation_id.to_string(),
            ),
            (
                "x-myfsio-idempotency-key".to_string(),
                idempotency_key.to_string(),
            ),
            ("x-myfsio-nonce".to_string(), nonce.clone()),
            (
                "x-myfsio-origin-site".to_string(),
                origin_site_id.to_string(),
            ),
        ];
        header_pairs.sort_by(|a, b| a.0.cmp(&b.0));

        let canonical_headers: String = header_pairs
            .iter()
            .map(|(k, v)| format!("{}:{}\n", k, v))
            .collect();
        let signed_headers = header_pairs
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>()
            .join(";");

        let canonical_query = parsed
            .query()
            .map(|q| {
                let mut pairs: Vec<(String, String)> = q
                    .split('&')
                    .filter(|p| !p.is_empty())
                    .map(|p| {
                        let mut it = p.splitn(2, '=');
                        let k = it.next().unwrap_or("").to_string();
                        let v = it.next().unwrap_or("").to_string();
                        (k, v)
                    })
                    .collect();
                pairs.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
                pairs
                    .iter()
                    .map(|(k, v)| format!("{}={}", aws_uri_encode(k), aws_uri_encode(v)))
                    .collect::<Vec<_>>()
                    .join("&")
            })
            .unwrap_or_default();

        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method, canonical_uri, canonical_query, canonical_headers, signed_headers, payload_hash
        );

        let credential_scope = format!("{}/{}/{}/aws4_request", date_stamp, region, service);
        let string_to_sign = build_string_to_sign(&amz_date, &credential_scope, &canonical_request);
        let signing_key = derive_signing_key(&connection.secret_key, &date_stamp, &region, service);
        let signature = compute_signature(&signing_key, &string_to_sign);

        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{},SignedHeaders={},Signature={}",
            connection.access_key, credential_scope, signed_headers, signature
        );

        let req_method = match method {
            "GET" => reqwest::Method::GET,
            "POST" => reqwest::Method::POST,
            "PUT" => reqwest::Method::PUT,
            "DELETE" => reqwest::Method::DELETE,
            "PATCH" => reqwest::Method::PATCH,
            other => return Err(format!("unsupported method: {}", other)),
        };

        let mut req = self.client.request(req_method, &url);
        for (k, v) in &header_pairs {
            req = req.header(k, v);
        }
        req = req.header("authorization", &authorization);
        if !body.is_empty() {
            req = req.body(body);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| format!("request failed: {}", e))?;
        let status = resp.status().as_u16();
        let resp_content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let mut peer_headers: Vec<(String, String)> = Vec::new();
        for (name, value) in resp.headers().iter() {
            if name.as_str().starts_with("x-myfsio-") {
                if let Ok(v) = value.to_str() {
                    peer_headers.push((name.as_str().to_string(), v.to_string()));
                }
            }
        }
        let resp_body = resp
            .bytes()
            .await
            .map_err(|e| format!("body read failed: {}", e))?
            .to_vec();
        Ok(RelayResponse {
            status,
            content_type: resp_content_type,
            body: resp_body,
            peer_headers,
        })
    }
}

pub struct RelayResponse {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
    pub peer_headers: Vec<(String, String)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLOUDFLARE_403: &str = "<html>\n<head><title>403 Forbidden</title></head>\n<body>\n<center><h1>403 Forbidden</h1></center>\n<hr><center>cloudflare</center>\n</body>\n</html>";

    #[test]
    fn html_error_page_yields_summary_and_source() {
        let body = parse_error_body(CLOUDFLARE_403, None);
        assert_eq!(body.detail, "403 Forbidden");
        assert_eq!(body.source.as_deref(), Some("cloudflare"));
    }

    #[test]
    fn html_error_page_never_leaks_markup() {
        let failure = PeerAdminStatus::Unauthorized {
            status: 403,
            body: parse_error_body(CLOUDFLARE_403, None),
        }
        .into_result()
        .unwrap_err();
        assert!(!failure.message().contains('<'));
        assert_eq!(failure.kind, "unauthorized");
        assert_eq!(failure.status, Some(403));
        assert_eq!(failure.source.as_deref(), Some("cloudflare"));
        assert!(failure.detail.is_none());
        assert!(failure.summary.contains("cloudflare"));
        assert!(failure.hint.is_some());
    }

    #[test]
    fn server_header_supplies_source_when_body_is_empty() {
        let body = parse_error_body("", Some("cloudflare"));
        assert!(body.detail.is_empty());
        assert_eq!(body.source.as_deref(), Some("cloudflare"));
    }

    #[test]
    fn script_and_style_blocks_are_dropped() {
        let html = "<html><head><style>h1 { color: red }</style><script>var a = 1 < 2;</script><title>502 Bad Gateway</title></head><body><h1>502 Bad Gateway</h1></body></html>";
        let body = parse_error_body(html, None);
        assert_eq!(body.detail, "502 Bad Gateway");
    }

    #[test]
    fn entities_are_decoded() {
        let html = "<html><body><h1>Access &amp; policy denied</h1></body></html>";
        assert_eq!(
            parse_error_body(html, None).detail,
            "Access & policy denied"
        );
    }

    #[test]
    fn json_and_xml_errors_still_parse() {
        assert_eq!(
            parse_error_body(
                r#"{"error":{"code":"AccessDenied","message":"nope"}}"#,
                None
            )
            .detail,
            "AccessDenied: nope"
        );
        assert_eq!(
            parse_error_body(
                "<?xml version=\"1.0\"?><Error><Code>AccessDenied</Code><Message>nope</Message></Error>",
                None
            )
            .detail,
            "AccessDenied — nope"
        );
    }

    #[test]
    fn peer_body_detail_is_kept_when_it_adds_information() {
        let failure = PeerAdminStatus::HttpError {
            status: 500,
            body: parse_error_body(
                r#"{"error":{"message":"listing index rebuild failed"}}"#,
                None,
            ),
        }
        .into_result()
        .unwrap_err();
        assert_eq!(
            failure.detail.as_deref(),
            Some("listing index rebuild failed")
        );
        assert!(failure.message().contains("listing index rebuild failed"));
    }

    #[test]
    fn unreachable_details_are_classified() {
        let timeout = PeerAdminStatus::Unreachable(
            "request failed: error sending request: operation timed out".to_string(),
        )
        .into_result()
        .unwrap_err();
        assert_eq!(timeout.title, "Connection timed out");
        assert_eq!(timeout.legacy_status(), "unreachable");

        let missing = PeerAdminStatus::Unreachable("no connection configured".to_string())
            .into_result()
            .unwrap_err();
        assert_eq!(missing.kind, "not_configured");
        assert!(missing.detail.is_none());
    }
}
