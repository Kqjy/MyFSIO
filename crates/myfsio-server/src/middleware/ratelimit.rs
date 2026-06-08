use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use parking_lot::Mutex;

use crate::config::RateLimitSetting;

#[derive(Clone)]
pub struct RateLimitLayerState {
    default_limiter: Arc<TokenBucketLimiter>,
    list_buckets_limiter: Option<Arc<TokenBucketLimiter>>,
    bucket_ops_limiter: Option<Arc<TokenBucketLimiter>>,
    object_ops_limiter: Option<Arc<TokenBucketLimiter>>,
    head_ops_limiter: Option<Arc<TokenBucketLimiter>>,
    num_trusted_proxies: usize,
}

impl RateLimitLayerState {
    pub fn new(setting: RateLimitSetting, num_trusted_proxies: usize) -> Self {
        Self {
            default_limiter: Arc::new(TokenBucketLimiter::new(setting)),
            list_buckets_limiter: None,
            bucket_ops_limiter: None,
            object_ops_limiter: None,
            head_ops_limiter: None,
            num_trusted_proxies,
        }
    }

    pub fn with_per_op(
        default: RateLimitSetting,
        list_buckets: RateLimitSetting,
        bucket_ops: RateLimitSetting,
        object_ops: RateLimitSetting,
        head_ops: RateLimitSetting,
        num_trusted_proxies: usize,
    ) -> Self {
        Self {
            default_limiter: Arc::new(TokenBucketLimiter::new(default)),
            list_buckets_limiter: (list_buckets != default)
                .then(|| Arc::new(TokenBucketLimiter::new(list_buckets))),
            bucket_ops_limiter: (bucket_ops != default)
                .then(|| Arc::new(TokenBucketLimiter::new(bucket_ops))),
            object_ops_limiter: (object_ops != default)
                .then(|| Arc::new(TokenBucketLimiter::new(object_ops))),
            head_ops_limiter: (head_ops != default)
                .then(|| Arc::new(TokenBucketLimiter::new(head_ops))),
            num_trusted_proxies,
        }
    }

    fn select_limiter_and_scope(&self, req: &Request) -> (&Arc<TokenBucketLimiter>, &'static str) {
        let path = req.uri().path();
        let method = req.method();
        if path == "/" && *method == Method::GET {
            if let Some(ref limiter) = self.list_buckets_limiter {
                return (limiter, "list_buckets");
            }
        } else {
            if *method == Method::HEAD {
                if let Some(ref limiter) = self.head_ops_limiter {
                    return (limiter, "head");
                }
            }
            let segments: Vec<&str> = path
                .trim_start_matches('/')
                .split('/')
                .filter(|s| !s.is_empty())
                .collect();
            if segments.len() == 1 {
                if let Some(ref limiter) = self.bucket_ops_limiter {
                    return (limiter, "bucket");
                }
            } else if segments.len() >= 2 {
                if let Some(ref limiter) = self.object_ops_limiter {
                    return (limiter, "object");
                }
            }
        }
        (&self.default_limiter, "default")
    }
}

#[derive(Debug)]
struct TokenBucketLimiter {
    capacity: f64,
    refill_per_sec: f64,
    state: Mutex<LimiterState>,
}

#[derive(Debug)]
struct LimiterState {
    entries: HashMap<String, BucketEntry>,
    last_sweep: Instant,
}

#[derive(Debug, Clone, Copy)]
struct BucketEntry {
    tokens: f64,
    last_refill: Instant,
}

const SWEEP_MIN_INTERVAL: Duration = Duration::from_secs(60);
const SWEEP_ENTRY_THRESHOLD: usize = 1024;

impl TokenBucketLimiter {
    fn new(setting: RateLimitSetting) -> Self {
        let capacity = setting.max_requests.max(1) as f64;
        let window = setting.window_seconds.max(1) as f64;
        Self {
            capacity,
            refill_per_sec: capacity / window,
            state: Mutex::new(LimiterState {
                entries: HashMap::new(),
                last_sweep: Instant::now(),
            }),
        }
    }

    fn check(&self, key: &str) -> Result<(), u64> {
        let now = Instant::now();
        let mut state = self.state.lock();

        if state.entries.len() >= SWEEP_ENTRY_THRESHOLD
            && now.duration_since(state.last_sweep) >= SWEEP_MIN_INTERVAL
        {
            let capacity = self.capacity;
            let refill = self.refill_per_sec;
            state.entries.retain(|_, entry| {
                let elapsed = now.duration_since(entry.last_refill).as_secs_f64();
                let projected = (entry.tokens + elapsed * refill).min(capacity);
                projected < capacity
            });
            state.last_sweep = now;
        }

        let entry = state.entries.entry(key.to_string()).or_insert(BucketEntry {
            tokens: self.capacity,
            last_refill: now,
        });

        let elapsed = now.duration_since(entry.last_refill).as_secs_f64();
        entry.tokens = (entry.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        entry.last_refill = now;

        if entry.tokens < 1.0 {
            let deficit = 1.0 - entry.tokens;
            let wait_secs = (deficit / self.refill_per_sec).ceil().max(1.0) as u64;
            return Err(wait_secs);
        }

        entry.tokens -= 1.0;
        Ok(())
    }
}

pub async fn rate_limit_layer(
    State(state): State<RateLimitLayerState>,
    req: Request,
    next: Next,
) -> Response {
    let ip = client_ip(&req, state.num_trusted_proxies);
    let (limiter, scope) = state.select_limiter_and_scope(&req);
    let key = format!("{}:{}", scope, ip);
    match limiter.check(&key) {
        Ok(()) => next.run(req).await,
        Err(retry_after) => {
            let resource = req.uri().path().to_string();
            too_many_requests(retry_after, &resource)
        }
    }
}

fn too_many_requests(retry_after: u64, resource: &str) -> Response {
    let request_id = uuid::Uuid::new_v4().simple().to_string();
    let body = myfsio_xml::response::rate_limit_exceeded_xml(resource, &request_id);
    let mut response = (
        StatusCode::SERVICE_UNAVAILABLE,
        [
            (header::CONTENT_TYPE, "application/xml".to_string()),
            (header::RETRY_AFTER, retry_after.to_string()),
        ],
        body,
    )
        .into_response();
    if let Ok(value) = request_id.parse() {
        response.headers_mut().insert("x-amz-request-id", value);
    }
    response
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

    fn key_for(req: &Request, proxies: usize) -> String {
        format!("ip:{}", client_ip(req, proxies))
    }

    #[test]
    fn honors_trusted_proxy_count_for_forwarded_for() {
        let req = Request::builder()
            .header("x-forwarded-for", "198.51.100.1, 10.0.0.1, 10.0.0.2")
            .body(Body::empty())
            .unwrap();
        assert_eq!(key_for(&req, 2), "ip:198.51.100.1");
        assert_eq!(key_for(&req, 1), "ip:10.0.0.1");
    }

    #[test]
    fn falls_back_to_connect_info_when_forwarded_for_has_too_few_hops() {
        let mut req = Request::builder()
            .header("x-forwarded-for", "198.51.100.1")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 9], 443))));

        assert_eq!(key_for(&req, 2), "ip:203.0.113.9");
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

        assert_eq!(key_for(&req, 0), "ip:203.0.113.9");
    }

    #[test]
    fn uses_connect_info_for_direct_clients() {
        let mut req = Request::builder().body(Body::empty()).unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 10], 443))));

        assert_eq!(key_for(&req, 0), "ip:203.0.113.10");
    }

    fn build_req(method: Method, path: &str) -> Request {
        Request::builder()
            .method(method)
            .uri(path)
            .body(Body::empty())
            .unwrap()
    }

    #[test]
    fn shared_default_limiter_uses_a_single_scope_across_op_classes() {
        let state = RateLimitLayerState::new(RateLimitSetting::new(100, 60), 0);
        let scope_get_root = state
            .select_limiter_and_scope(&build_req(Method::GET, "/"))
            .1;
        let scope_bucket = state
            .select_limiter_and_scope(&build_req(Method::GET, "/mybucket"))
            .1;
        let scope_object = state
            .select_limiter_and_scope(&build_req(Method::GET, "/mybucket/key"))
            .1;
        let scope_head = state
            .select_limiter_and_scope(&build_req(Method::HEAD, "/mybucket/key"))
            .1;
        assert_eq!(scope_get_root, "default");
        assert_eq!(scope_bucket, "default");
        assert_eq!(scope_object, "default");
        assert_eq!(scope_head, "default");
    }

    #[test]
    fn head_without_head_specific_override_falls_through_to_path_limiter() {
        let state = RateLimitLayerState::with_per_op(
            RateLimitSetting::new(100, 60),
            RateLimitSetting::new(100, 60),
            RateLimitSetting::new(50, 60),
            RateLimitSetting::new(25, 60),
            RateLimitSetting::new(100, 60),
            0,
        );
        assert_eq!(
            state
                .select_limiter_and_scope(&build_req(Method::HEAD, "/bucket/key"))
                .1,
            "object"
        );
        assert_eq!(
            state
                .select_limiter_and_scope(&build_req(Method::HEAD, "/bucket"))
                .1,
            "bucket"
        );
    }

    #[test]
    fn explicit_per_op_limiter_gets_its_own_scope() {
        let state = RateLimitLayerState::with_per_op(
            RateLimitSetting::new(100, 60),
            RateLimitSetting::new(200, 60),
            RateLimitSetting::new(100, 60),
            RateLimitSetting::new(300, 60),
            RateLimitSetting::new(100, 60),
            0,
        );
        assert_eq!(
            state
                .select_limiter_and_scope(&build_req(Method::GET, "/"))
                .1,
            "list_buckets"
        );
        assert_eq!(
            state
                .select_limiter_and_scope(&build_req(Method::GET, "/bucket"))
                .1,
            "default",
            "bucket_ops not configured ⇒ shared default scope"
        );
        assert_eq!(
            state
                .select_limiter_and_scope(&build_req(Method::GET, "/bucket/key"))
                .1,
            "object",
            "object_ops configured ⇒ its own scope"
        );
    }

    #[test]
    fn token_bucket_allows_burst_up_to_capacity() {
        let limiter = TokenBucketLimiter::new(RateLimitSetting::new(3, 60));
        assert!(limiter.check("k").is_ok());
        assert!(limiter.check("k").is_ok());
        assert!(limiter.check("k").is_ok());
        assert!(limiter.check("k").is_err());
    }

    #[test]
    fn token_bucket_refills_over_time() {
        let limiter = TokenBucketLimiter::new(RateLimitSetting::new(60, 60));
        for _ in 0..60 {
            assert!(limiter.check("k").is_ok());
        }
        assert!(limiter.check("k").is_err());
        {
            let mut state = limiter.state.lock();
            let entry = state.entries.get_mut("k").unwrap();
            entry.last_refill -= Duration::from_secs(2);
        }
        assert!(limiter.check("k").is_ok());
        assert!(limiter.check("k").is_ok());
        assert!(limiter.check("k").is_err());
    }

    #[test]
    fn sweep_removes_full_entries() {
        let limiter = TokenBucketLimiter::new(RateLimitSetting::new(10, 1));
        let far_past = Instant::now() - (SWEEP_MIN_INTERVAL + Duration::from_secs(60));
        {
            let mut state = limiter.state.lock();
            for i in 0..(SWEEP_ENTRY_THRESHOLD + 1024) {
                state.entries.insert(
                    format!("idle-{}", i),
                    BucketEntry {
                        tokens: 0.0,
                        last_refill: far_past,
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
