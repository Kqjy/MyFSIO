use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use parking_lot::Mutex;

use crate::config::RateLimitSetting;

#[derive(Clone)]
pub struct RateLimitLayerState {
    limiter: Arc<FixedWindowLimiter>,
    num_trusted_proxies: usize,
}

impl RateLimitLayerState {
    pub fn new(setting: RateLimitSetting, num_trusted_proxies: usize) -> Self {
        Self {
            limiter: Arc::new(FixedWindowLimiter::new(setting)),
            num_trusted_proxies,
        }
    }
}

#[derive(Debug)]
struct FixedWindowLimiter {
    setting: RateLimitSetting,
    state: Mutex<LimiterState>,
}

#[derive(Debug)]
struct LimiterState {
    entries: HashMap<String, LimitEntry>,
    last_sweep: Instant,
}

#[derive(Debug, Clone, Copy)]
struct LimitEntry {
    window_started: Instant,
    count: u32,
}

const SWEEP_MIN_INTERVAL: Duration = Duration::from_secs(60);
const SWEEP_ENTRY_THRESHOLD: usize = 1024;

impl FixedWindowLimiter {
    fn new(setting: RateLimitSetting) -> Self {
        Self {
            setting,
            state: Mutex::new(LimiterState {
                entries: HashMap::new(),
                last_sweep: Instant::now(),
            }),
        }
    }

    fn check(&self, key: &str) -> Result<(), u64> {
        let now = Instant::now();
        let window = Duration::from_secs(self.setting.window_seconds.max(1));
        let mut state = self.state.lock();

        if state.entries.len() >= SWEEP_ENTRY_THRESHOLD
            && now.duration_since(state.last_sweep) >= SWEEP_MIN_INTERVAL
        {
            state
                .entries
                .retain(|_, entry| now.duration_since(entry.window_started) < window);
            state.last_sweep = now;
        }

        let entry = state.entries.entry(key.to_string()).or_insert(LimitEntry {
            window_started: now,
            count: 0,
        });

        if now.duration_since(entry.window_started) >= window {
            entry.window_started = now;
            entry.count = 0;
        }

        if entry.count >= self.setting.max_requests {
            let elapsed = now.duration_since(entry.window_started);
            let retry_after = window.saturating_sub(elapsed).as_secs().max(1);
            return Err(retry_after);
        }

        entry.count += 1;
        Ok(())
    }
}

pub async fn rate_limit_layer(
    State(state): State<RateLimitLayerState>,
    req: Request,
    next: Next,
) -> Response {
    let key = rate_limit_key(&req, state.num_trusted_proxies);
    match state.limiter.check(&key) {
        Ok(()) => next.run(req).await,
        Err(retry_after) => too_many_requests(retry_after),
    }
}

fn too_many_requests(retry_after: u64) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [
            (header::CONTENT_TYPE, "application/xml".to_string()),
            (header::RETRY_AFTER, retry_after.to_string()),
        ],
        myfsio_xml::response::rate_limit_exceeded_xml(),
    )
        .into_response()
}

fn rate_limit_key(req: &Request, num_trusted_proxies: usize) -> String {
    format!("ip:{}", client_ip(req, num_trusted_proxies))
}

fn client_ip(req: &Request, num_trusted_proxies: usize) -> String {
    if num_trusted_proxies > 0 {
        if let Some(value) = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
        {
            let parts = value
                .split(',')
                .map(|part| part.trim())
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>();
            if parts.len() > num_trusted_proxies {
                let index = parts.len() - num_trusted_proxies - 1;
                return parts[index].to_string();
            }
        }

        if let Some(value) = req.headers().get("x-real-ip").and_then(|v| v.to_str().ok()) {
            if !value.trim().is_empty() {
                return value.trim().to_string();
            }
        }
    }

    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    #[test]
    fn honors_trusted_proxy_count_for_forwarded_for() {
        let req = Request::builder()
            .header("x-forwarded-for", "198.51.100.1, 10.0.0.1, 10.0.0.2")
            .body(Body::empty())
            .unwrap();
        assert_eq!(rate_limit_key(&req, 2), "ip:198.51.100.1");
        assert_eq!(rate_limit_key(&req, 1), "ip:10.0.0.1");
    }

    #[test]
    fn falls_back_to_connect_info_when_forwarded_for_has_too_few_hops() {
        let mut req = Request::builder()
            .header("x-forwarded-for", "198.51.100.1")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 9], 443))));

        assert_eq!(rate_limit_key(&req, 2), "ip:203.0.113.9");
    }

    #[test]
    fn ignores_forwarded_headers_when_no_proxies_are_trusted() {
        let mut req = Request::builder()
            .header("x-forwarded-for", "198.51.100.1")
            .header("x-real-ip", "198.51.100.2")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 9], 443))));

        assert_eq!(rate_limit_key(&req, 0), "ip:203.0.113.9");
    }

    #[test]
    fn uses_connect_info_for_direct_clients() {
        let mut req = Request::builder().body(Body::empty()).unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 10], 443))));

        assert_eq!(rate_limit_key(&req, 0), "ip:203.0.113.10");
    }

    #[test]
    fn fixed_window_rejects_after_quota() {
        let limiter = FixedWindowLimiter::new(RateLimitSetting::new(2, 60));
        assert!(limiter.check("k").is_ok());
        assert!(limiter.check("k").is_ok());
        assert!(limiter.check("k").is_err());
    }

    #[test]
    fn sweep_removes_expired_entries() {
        let limiter = FixedWindowLimiter::new(RateLimitSetting::new(10, 1));
        let far_past = Instant::now() - (SWEEP_MIN_INTERVAL + Duration::from_secs(5));
        {
            let mut state = limiter.state.lock();
            for i in 0..(SWEEP_ENTRY_THRESHOLD + 1024) {
                state.entries.insert(
                    format!("stale-{}", i),
                    LimitEntry {
                        window_started: far_past,
                        count: 5,
                    },
                );
            }
            state.last_sweep = far_past;
        }
        let seeded = limiter.state.lock().entries.len();
        assert_eq!(seeded, SWEEP_ENTRY_THRESHOLD + 1024);

        assert!(limiter.check("fresh").is_ok());

        let remaining = limiter.state.lock().entries.len();
        assert_eq!(
            remaining, 1,
            "expected sweep to leave only the fresh entry, got {}",
            remaining
        );
    }
}
