use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
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

    fn select_limiter_and_scope(&self, req: &Request) -> (&Arc<TokenBucketLimiter>, LimitScope) {
        let path = req.uri().path();
        let method = req.method();
        if path == "/" && *method == Method::GET {
            if let Some(ref limiter) = self.list_buckets_limiter {
                return (limiter, LimitScope::ListBuckets);
            }
        } else {
            if *method == Method::HEAD {
                if let Some(ref limiter) = self.head_ops_limiter {
                    return (limiter, LimitScope::Head);
                }
            }
            let mut segments = path
                .trim_start_matches('/')
                .split('/')
                .filter(|s| !s.is_empty());
            let first = segments.next();
            let second = segments.next();
            if first.is_some() && second.is_none() {
                if let Some(ref limiter) = self.bucket_ops_limiter {
                    return (limiter, LimitScope::Bucket);
                }
            } else if second.is_some() {
                if let Some(ref limiter) = self.object_ops_limiter {
                    return (limiter, LimitScope::Object);
                }
            }
        }
        (&self.default_limiter, LimitScope::Default)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum LimitScope {
    Default,
    ListBuckets,
    Bucket,
    Object,
    Head,
    UiLogin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct LimiterKey {
    scope: LimitScope,
    ip: Option<IpAddr>,
}

#[derive(Debug)]
struct TokenBucketLimiter {
    capacity: f64,
    refill_per_sec: f64,
    shards: [Mutex<LimiterState>; LIMITER_SHARDS],
}

#[derive(Debug)]
struct LimiterState {
    entries: HashMap<LimiterKey, BucketEntry>,
    last_sweep: Instant,
}

#[derive(Debug, Clone, Copy)]
struct BucketEntry {
    tokens: f64,
    last_refill: Instant,
}

const SWEEP_MIN_INTERVAL: Duration = Duration::from_secs(60);
const SWEEP_ENTRY_THRESHOLD: usize = 1024;
const LIMITER_SHARDS: usize = 32;
const SHARD_SWEEP_ENTRY_THRESHOLD: usize = SWEEP_ENTRY_THRESHOLD.div_ceil(LIMITER_SHARDS);

impl TokenBucketLimiter {
    fn new(setting: RateLimitSetting) -> Self {
        let capacity = setting.max_requests.max(1) as f64;
        let window = setting.window_seconds.max(1) as f64;
        Self {
            capacity,
            refill_per_sec: capacity / window,
            shards: std::array::from_fn(|_| {
                Mutex::new(LimiterState {
                    entries: HashMap::new(),
                    last_sweep: Instant::now(),
                })
            }),
        }
    }

    fn shard_index(key: &LimiterKey) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish() as usize & (LIMITER_SHARDS - 1)
    }

    fn check(&self, key: LimiterKey) -> Result<(), u64> {
        let now = Instant::now();
        let mut state = self.shards[Self::shard_index(&key)].lock();

        if state.entries.len() >= SHARD_SWEEP_ENTRY_THRESHOLD
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

        let entry = state.entries.entry(key).or_insert(BucketEntry {
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
    match limiter.check(LimiterKey { scope, ip }) {
        Ok(()) => next.run(req).await,
        Err(retry_after) => {
            let resource = req.uri().path().to_string();
            too_many_requests(retry_after, &resource)
        }
    }
}

#[derive(Clone)]
pub struct UiLoginRateLimitState {
    app: crate::state::AppState,
    limiter: Arc<TokenBucketLimiter>,
    num_trusted_proxies: usize,
}

impl UiLoginRateLimitState {
    pub fn new(
        app: crate::state::AppState,
        setting: RateLimitSetting,
        num_trusted_proxies: usize,
    ) -> Self {
        Self {
            app,
            limiter: Arc::new(TokenBucketLimiter::new(setting)),
            num_trusted_proxies,
        }
    }
}

pub async fn ui_login_rate_limit_layer(
    State(state): State<UiLoginRateLimitState>,
    req: Request,
    next: Next,
) -> Response {
    let ip = client_ip(&req, state.num_trusted_proxies);
    let Err(retry_after) = state.limiter.check(LimiterKey {
        scope: LimitScope::UiLogin,
        ip,
    }) else {
        return next.run(req).await;
    };

    tracing::warn!(client_ip = ?ip, "Login rate limit exceeded");

    let accept = req
        .headers()
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let wants_json =
        accept.contains("application/json") || content_type.starts_with("application/json");

    let mut response = if wants_json {
        (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::CONTENT_TYPE, "application/json")],
            serde_json::json!({
                "error": "Too many login attempts. Please wait a moment and try again."
            })
            .to_string(),
        )
            .into_response()
    } else {
        let handle = req
            .extensions()
            .get::<crate::middleware::session::SessionHandle>()
            .cloned();
        let ctx = match handle {
            Some(handle) => crate::handlers::ui::base_context(&handle, None),
            None => tera::Context::new(),
        };
        let mut rendered = crate::handlers::ui::render(&state.app, "login_rate_limited.html", &ctx);
        if rendered.status() == StatusCode::OK {
            *rendered.status_mut() = StatusCode::TOO_MANY_REQUESTS;
        }
        rendered
    };

    if let Ok(value) = retry_after.to_string().parse() {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
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

fn client_ip(req: &Request, num_trusted_proxies: usize) -> Option<IpAddr> {
    if num_trusted_proxies > 0 {
        if let Some(value) = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
        {
            if let Some(candidate) = value
                .split(',')
                .map(str::trim)
                .filter(|part| !part.is_empty())
                .rev()
                .nth(num_trusted_proxies)
            {
                if let Ok(ip) = candidate.parse() {
                    return Some(ip);
                }
            }
        }

        if let Some(value) = req.headers().get("x-real-ip").and_then(|v| v.to_str().ok()) {
            if let Ok(ip) = value.trim().parse() {
                return Some(ip);
            }
        }
    }

    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    fn parsed_ip(raw: &str) -> Option<IpAddr> {
        Some(raw.parse().unwrap())
    }

    #[test]
    fn honors_trusted_proxy_count_for_forwarded_for() {
        let req = Request::builder()
            .header("x-forwarded-for", "198.51.100.1, 10.0.0.1, 10.0.0.2")
            .body(Body::empty())
            .unwrap();
        assert_eq!(client_ip(&req, 2), parsed_ip("198.51.100.1"));
        assert_eq!(client_ip(&req, 1), parsed_ip("10.0.0.1"));
    }

    #[test]
    fn falls_back_to_connect_info_when_forwarded_for_has_too_few_hops() {
        let mut req = Request::builder()
            .header("x-forwarded-for", "198.51.100.1")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 9], 443))));

        assert_eq!(client_ip(&req, 2), parsed_ip("203.0.113.9"));
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

        assert_eq!(client_ip(&req, 0), parsed_ip("203.0.113.9"));
    }

    #[test]
    fn uses_connect_info_for_direct_clients() {
        let mut req = Request::builder().body(Body::empty()).unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 10], 443))));

        assert_eq!(client_ip(&req, 0), parsed_ip("203.0.113.10"));
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
        assert_eq!(scope_get_root, LimitScope::Default);
        assert_eq!(scope_bucket, LimitScope::Default);
        assert_eq!(scope_object, LimitScope::Default);
        assert_eq!(scope_head, LimitScope::Default);
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
            LimitScope::Object
        );
        assert_eq!(
            state
                .select_limiter_and_scope(&build_req(Method::HEAD, "/bucket"))
                .1,
            LimitScope::Bucket
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
            LimitScope::ListBuckets
        );
        assert_eq!(
            state
                .select_limiter_and_scope(&build_req(Method::GET, "/bucket"))
                .1,
            LimitScope::Default,
            "bucket_ops not configured ⇒ shared default scope"
        );
        assert_eq!(
            state
                .select_limiter_and_scope(&build_req(Method::GET, "/bucket/key"))
                .1,
            LimitScope::Object,
            "object_ops configured ⇒ its own scope"
        );
    }

    #[test]
    fn token_bucket_allows_burst_up_to_capacity() {
        let limiter = TokenBucketLimiter::new(RateLimitSetting::new(3, 60));
        let key = LimiterKey {
            scope: LimitScope::Default,
            ip: parsed_ip("192.0.2.1"),
        };
        assert!(limiter.check(key).is_ok());
        assert!(limiter.check(key).is_ok());
        assert!(limiter.check(key).is_ok());
        assert!(limiter.check(key).is_err());
    }

    #[test]
    fn token_bucket_refills_over_time() {
        let limiter = TokenBucketLimiter::new(RateLimitSetting::new(60, 60));
        let key = LimiterKey {
            scope: LimitScope::Default,
            ip: parsed_ip("192.0.2.2"),
        };
        for _ in 0..60 {
            assert!(limiter.check(key).is_ok());
        }
        assert!(limiter.check(key).is_err());
        {
            let mut state = limiter.shards[TokenBucketLimiter::shard_index(&key)].lock();
            let entry = state.entries.get_mut(&key).unwrap();
            entry.last_refill -= Duration::from_secs(2);
        }
        assert!(limiter.check(key).is_ok());
        assert!(limiter.check(key).is_ok());
        assert!(limiter.check(key).is_err());
    }

    #[test]
    fn sweep_removes_full_entries() {
        let limiter = TokenBucketLimiter::new(RateLimitSetting::new(10, 1));
        let far_past = Instant::now() - (SWEEP_MIN_INTERVAL + Duration::from_secs(60));
        let seed = LimiterKey {
            scope: LimitScope::Default,
            ip: parsed_ip("198.51.100.10"),
        };
        let shard_index = TokenBucketLimiter::shard_index(&seed);
        {
            let mut state = limiter.shards[shard_index].lock();
            for _ in 0..(SHARD_SWEEP_ENTRY_THRESHOLD + 32) {
                let key = (1u32..)
                    .map(|n| LimiterKey {
                        scope: LimitScope::Default,
                        ip: Some(IpAddr::V4(std::net::Ipv4Addr::from(n))),
                    })
                    .find(|key| {
                        TokenBucketLimiter::shard_index(key) == shard_index
                            && !state.entries.contains_key(key)
                    })
                    .unwrap();
                state.entries.insert(
                    key,
                    BucketEntry {
                        tokens: 0.0,
                        last_refill: far_past,
                    },
                );
            }
            state.last_sweep = far_past;
        }
        let seeded = limiter.shards[shard_index].lock().entries.len();
        assert_eq!(seeded, SHARD_SWEEP_ENTRY_THRESHOLD + 32);

        assert!(limiter.check(seed).is_ok());

        let remaining = limiter.shards[shard_index].lock().entries.len();
        assert_eq!(
            remaining, 1,
            "expected sweep to leave only the fresh entry, got {}",
            remaining
        );
    }

    #[test]
    fn limiter_distributes_clients_across_shards() {
        let limiter = TokenBucketLimiter::new(RateLimitSetting::new(10, 60));
        let mut used = std::collections::HashSet::new();
        for value in 1..=128u32 {
            let key = LimiterKey {
                scope: LimitScope::Object,
                ip: Some(IpAddr::V4(std::net::Ipv4Addr::from(value))),
            };
            used.insert(TokenBucketLimiter::shard_index(&key));
            limiter.check(key).unwrap();
        }
        assert!(used.len() > 1);
        let populated = limiter
            .shards
            .iter()
            .filter(|shard| !shard.lock().entries.is_empty())
            .count();
        assert_eq!(populated, used.len());
    }
}
