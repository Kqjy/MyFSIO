use std::time::Duration;

use chrono::Utc;
use serde_json::Value;

use myfsio_auth::sigv4::{
    aws_uri_encode, build_string_to_sign, compute_signature, derive_signing_key, sha256_hex,
};

use crate::stores::connections::RemoteConnection;

pub struct PeerAdminClient {
    client: reqwest::Client,
}

impl PeerAdminClient {
    pub fn new(connect_timeout: Duration, read_timeout: Duration) -> Self {
        let client = reqwest::Client::builder()
            .connect_timeout(connect_timeout)
            .timeout(read_timeout)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self { client }
    }

    pub async fn fetch_cluster_overview(
        &self,
        endpoint: &str,
        connection: &RemoteConnection,
    ) -> Result<Value, String> {
        let url = format!(
            "{}/admin/cluster/overview",
            endpoint.trim_end_matches('/')
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

        let canonical_headers = format!(
            "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
            host_with_port, payload_hash, amz_date
        );
        let signed_headers = "host;x-amz-content-sha256;x-amz-date";

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

        let resp = self
            .client
            .get(&url)
            .header("host", &host_with_port)
            .header("x-amz-content-sha256", &payload_hash)
            .header("x-amz-date", &amz_date)
            .header("authorization", &authorization)
            .send()
            .await
            .map_err(|e| format!("request failed: {}", e))?;

        let status = resp.status();
        if !status.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            let detail = body_text
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty())
                .collect::<Vec<_>>()
                .join(" ");
            let detail = match detail.char_indices().nth(240) {
                Some((boundary, _)) => format!("{}…", &detail[..boundary]),
                None => detail,
            };
            if detail.is_empty() {
                return Err(format!("peer returned status {}", status.as_u16()));
            }
            return Err(format!(
                "peer returned status {} — {}",
                status.as_u16(),
                detail
            ));
        }
        let body: Value = resp
            .json()
            .await
            .map_err(|e| format!("invalid json: {}", e))?;
        Ok(body)
    }
}
