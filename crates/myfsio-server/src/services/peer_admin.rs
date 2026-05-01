use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use serde_json::Value;

use crate::services::safe_resolver::SafeResolver;

fn extract_error_detail(body: &str) -> String {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return String::new();
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
            return truncate_chars(&detail, 240);
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
            return truncate_chars(&detail, 240);
        }
    }

    let collapsed = trimmed
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    truncate_chars(&collapsed, 240)
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
    Unauthorized(String),
    HttpError { status: u16, detail: String },
    InvalidJson(String),
    Unreachable(String),
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
        let signing_key =
            derive_signing_key(&connection.secret_key, &date_stamp, &region, service);
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
        match self.fetch_admin_status(endpoint, path_and_query, connection).await {
            PeerAdminStatus::Ok(v) => Ok(v),
            PeerAdminStatus::Unauthorized(detail) => Err(detail),
            PeerAdminStatus::HttpError { status, detail } => {
                Err(format!("peer returned status {} — {}", status, detail))
            }
            PeerAdminStatus::InvalidJson(detail) => Err(detail),
            PeerAdminStatus::Unreachable(detail) => Err(detail),
        }
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
            Err(e) => {
                return PeerAdminStatus::Unreachable(format!("request failed: {}", e))
            }
        };
        let status = resp.status();
        if status.is_success() {
            return match resp.json::<Value>().await {
                Ok(v) => PeerAdminStatus::Ok(v),
                Err(e) => PeerAdminStatus::InvalidJson(format!("invalid json: {}", e)),
            };
        }
        let body_text = resp.text().await.unwrap_or_default();
        let detail = extract_error_detail(&body_text);
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            let message = if detail.is_empty() {
                format!("peer returned status {}", status.as_u16())
            } else {
                format!("peer returned status {} — {}", status.as_u16(), detail)
            };
            PeerAdminStatus::Unauthorized(message)
        } else {
            PeerAdminStatus::HttpError {
                status: status.as_u16(),
                detail,
            }
        }
    }

    pub async fn fetch_cluster_overview(
        &self,
        endpoint: &str,
        connection: &RemoteConnection,
    ) -> Result<Value, String> {
        self.fetch_admin_json(endpoint, "/myfsio/admin/cluster/overview?local_only=1", connection)
            .await
    }

    pub async fn check_peer_endpoint_health(
        &self,
        endpoint: &str,
        connection: &RemoteConnection,
    ) -> Result<(), String> {
        match self
            .fetch_admin_status(endpoint, "/myfsio/admin/cluster/overview?local_only=1", connection)
            .await
        {
            PeerAdminStatus::Ok(_) => Ok(()),
            PeerAdminStatus::InvalidJson(detail) => Err(format!(
                "peer responded but body was not valid JSON: {}",
                detail
            )),
            PeerAdminStatus::Unauthorized(detail) => {
                Err(format!("peer credentials rejected: {}", detail))
            }
            PeerAdminStatus::HttpError { status, detail } => {
                Err(format!("peer returned status {} — {}", status, detail))
            }
            PeerAdminStatus::Unreachable(detail) => Err(detail),
        }
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
        if let Err(e) = self.guard_endpoint(endpoint).await {
            return Err(e);
        }
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

        let cluster_attest =
            crate::services::cluster_attest::cluster_attest(cluster_psk, &amz_date, origin_site_id, idempotency_key);
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
            ("x-myfsio-admin-attest".to_string(), admin_attest_value.clone()),
            ("x-myfsio-admin-user".to_string(), admin_user_id.to_string()),
            ("x-myfsio-cluster-attest".to_string(), cluster_attest.clone()),
            ("x-myfsio-correlation-id".to_string(), correlation_id.to_string()),
            ("x-myfsio-idempotency-key".to_string(), idempotency_key.to_string()),
            ("x-myfsio-nonce".to_string(), nonce.clone()),
            ("x-myfsio-origin-site".to_string(), origin_site_id.to_string()),
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
        let signing_key =
            derive_signing_key(&connection.secret_key, &date_stamp, &region, service);
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
