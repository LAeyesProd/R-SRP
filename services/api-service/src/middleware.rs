//! API Middleware

use axum::{
    body::Body,
    extract::Request,
    extract::State,
    http::{
        header::{HeaderName, HeaderValue, RETRY_AFTER},
        HeaderMap, StatusCode,
    },
    middleware::Next,
    response::{IntoResponse, Response},
};
use ipnet::IpNet;
use serde_json::json;
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct IpRateLimiterConfig {
    pub limit_per_window: u32,
    pub window: Duration,
    pub bucket_ttl: Duration,
    pub max_buckets: usize,
    pub ipv6_prefix_len: u8,
}

impl Default for IpRateLimiterConfig {
    fn default() -> Self {
        Self {
            limit_per_window: 100,
            window: Duration::from_secs(60),
            bucket_ttl: Duration::from_secs(300),
            max_buckets: 50_000,
            ipv6_prefix_len: 64,
        }
    }
}

impl IpRateLimiterConfig {
    pub fn from_env() -> Self {
        let mut cfg = Self::default();
        if let Ok(v) = std::env::var("RATE_LIMIT_PER_WINDOW") {
            if let Ok(parsed) = v.parse::<u32>() {
                cfg.limit_per_window = parsed.max(1);
            }
        }
        if let Ok(v) = std::env::var("RATE_LIMIT_WINDOW_SECONDS") {
            if let Ok(parsed) = v.parse::<u64>() {
                cfg.window = Duration::from_secs(parsed.max(1));
            }
        }
        if let Ok(v) = std::env::var("RATE_LIMIT_BUCKET_TTL_SECONDS") {
            if let Ok(parsed) = v.parse::<u64>() {
                cfg.bucket_ttl = Duration::from_secs(parsed.max(cfg.window.as_secs()));
            }
        }
        if let Ok(v) = std::env::var("RATE_LIMIT_MAX_BUCKETS") {
            if let Ok(parsed) = v.parse::<usize>() {
                cfg.max_buckets = parsed.max(100);
            }
        }
        if let Ok(v) = std::env::var("RATE_LIMIT_IPV6_PREFIX_LEN") {
            if let Ok(parsed) = v.parse::<u8>() {
                cfg.ipv6_prefix_len = parsed.min(128);
            }
        }
        cfg
    }
}

#[derive(Debug, Clone)]
pub struct IdentityRateLimiterConfig {
    pub limit_per_hour: u32,
    pub bucket_ttl: Duration,
    pub max_identities: usize,
}

impl Default for IdentityRateLimiterConfig {
    fn default() -> Self {
        Self {
            limit_per_hour: 200,
            bucket_ttl: Duration::from_secs(24 * 60 * 60),
            max_identities: 50_000,
        }
    }
}

impl IdentityRateLimiterConfig {
    pub fn from_env() -> Self {
        let mut cfg = Self::default();
        if let Ok(v) = std::env::var("IDENTITY_RATE_LIMIT_PER_HOUR") {
            if let Ok(parsed) = v.parse::<u32>() {
                cfg.limit_per_hour = parsed.max(1);
            }
        }
        if let Ok(v) = std::env::var("IDENTITY_RATE_LIMIT_BUCKET_TTL_SECONDS") {
            if let Ok(parsed) = v.parse::<u64>() {
                cfg.bucket_ttl = Duration::from_secs(parsed.max(3600));
            }
        }
        if let Ok(v) = std::env::var("IDENTITY_RATE_LIMIT_MAX_IDENTITIES") {
            if let Ok(parsed) = v.parse::<usize>() {
                cfg.max_identities = parsed.max(100);
            }
        }
        cfg
    }
}

#[derive(Debug, Clone)]
struct WindowBucket {
    window_started_at: Instant,
    last_seen_at: Instant,
    hits: u32,
}

#[derive(Debug, Clone)]
struct IdentityBucket {
    events: VecDeque<Instant>,
    last_seen_at: Instant,
}

#[derive(Debug, Clone, Copy)]
pub struct IdentityObservation {
    pub requests_last_hour: u32,
    pub requests_last_24h: u32,
}

/// Simple in-memory IP/token bucket limiter.
#[derive(Debug)]
pub struct IpRateLimiter {
    config: IpRateLimiterConfig,
    buckets: Mutex<HashMap<String, WindowBucket>>,
    trusted_proxies: TrustedProxyConfig,
}

/// In-memory per-identity limiter used to enforce and derive trusted CRUE counters.
#[derive(Debug)]
pub struct IdentityRateLimiter {
    config: IdentityRateLimiterConfig,
    buckets: Mutex<HashMap<String, IdentityBucket>>,
}

#[derive(Debug, Clone, Default)]
pub struct TrustedProxyConfig {
    cidrs: Vec<IpNet>,
}

impl IpRateLimiter {
    pub fn new(config: IpRateLimiterConfig, trusted_proxies: TrustedProxyConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            buckets: Mutex::new(HashMap::new()),
            trusted_proxies,
        })
    }

    async fn check_and_count(&self, key: &str) -> Result<(), u64> {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().await;
        // TTL/LRU eviction to cap memory usage under key-flood attacks.
        buckets.retain(|_, v| now.duration_since(v.last_seen_at) <= self.config.bucket_ttl);
        if !buckets.contains_key(key) && buckets.len() >= self.config.max_buckets {
            let oldest = buckets
                .iter()
                .min_by_key(|(_, v)| v.last_seen_at)
                .map(|(k, _)| k.clone());
            if let Some(oldest_key) = oldest {
                buckets.remove(&oldest_key);
            }
        }
        if !buckets.contains_key(key) && buckets.len() >= self.config.max_buckets {
            return Err(1);
        }

        let bucket = buckets
            .entry(key.to_string())
            .or_insert_with(|| WindowBucket {
                window_started_at: now,
                last_seen_at: now,
                hits: 0,
            });
        bucket.last_seen_at = now;

        if now.duration_since(bucket.window_started_at) >= self.config.window {
            bucket.window_started_at = now;
            bucket.hits = 0;
        }

        if bucket.hits >= self.config.limit_per_window {
            let elapsed = now.duration_since(bucket.window_started_at);
            let retry_after = self.config.window.saturating_sub(elapsed).as_secs().max(1);
            return Err(retry_after);
        }

        bucket.hits += 1;
        Ok(())
    }
}

impl IdentityRateLimiter {
    pub fn new(config: IdentityRateLimiterConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            buckets: Mutex::new(HashMap::new()),
        })
    }

    pub async fn observe_identity(&self, identity: &str) -> Result<IdentityObservation, u64> {
        let now = Instant::now();
        let identity = if identity.trim().is_empty() {
            "unknown"
        } else {
            identity
        };
        let mut buckets = self.buckets.lock().await;

        buckets.retain(|_, v| now.duration_since(v.last_seen_at) <= self.config.bucket_ttl);
        if !buckets.contains_key(identity) && buckets.len() >= self.config.max_identities {
            let oldest = buckets
                .iter()
                .min_by_key(|(_, v)| v.last_seen_at)
                .map(|(k, _)| k.clone());
            if let Some(oldest_key) = oldest {
                buckets.remove(&oldest_key);
            }
        }
        if !buckets.contains_key(identity) && buckets.len() >= self.config.max_identities {
            return Err(1);
        }

        let bucket = buckets
            .entry(identity.to_string())
            .or_insert_with(|| IdentityBucket {
                events: VecDeque::new(),
                last_seen_at: now,
            });
        bucket.last_seen_at = now;

        let day_window = Duration::from_secs(24 * 60 * 60);
        while let Some(ts) = bucket.events.front() {
            if now.duration_since(*ts) > day_window {
                bucket.events.pop_front();
            } else {
                break;
            }
        }

        let hour_window = Duration::from_secs(60 * 60);
        let requests_last_hour = bucket
            .events
            .iter()
            .rev()
            .take_while(|ts| now.duration_since(**ts) <= hour_window)
            .count() as u32;
        let requests_last_24h = bucket.events.len() as u32;

        if requests_last_hour >= self.config.limit_per_hour {
            let retry_after = bucket
                .events
                .iter()
                .find(|ts| now.duration_since(**ts) <= hour_window)
                .map(|ts| {
                    hour_window
                        .saturating_sub(now.duration_since(*ts))
                        .as_secs()
                        .max(1)
                })
                .unwrap_or(1);
            return Err(retry_after);
        }

        bucket.events.push_back(now);
        Ok(IdentityObservation {
            requests_last_hour: requests_last_hour + 1,
            requests_last_24h: requests_last_24h + 1,
        })
    }
}

impl TrustedProxyConfig {
    pub fn from_env() -> Self {
        let raw = std::env::var("TRUSTED_PROXY_CIDRS").unwrap_or_default();
        if raw.trim().is_empty() {
            return Self { cidrs: Vec::new() };
        }
        let mut cidrs = Vec::new();
        for part in raw.split(',').map(str::trim).filter(|v| !v.is_empty()) {
            match part.parse::<IpNet>() {
                Ok(net) => cidrs.push(net),
                Err(err) => {
                    tracing::warn!("Ignoring invalid TRUSTED_PROXY_CIDRS entry {part}: {err}")
                }
            }
        }
        Self { cidrs }
    }

    pub fn len(&self) -> usize {
        self.cidrs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cidrs.is_empty()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.cidrs.iter().any(|net| net.contains(&ip))
    }

    #[cfg(test)]
    fn from_cidrs(cidrs: Vec<IpNet>) -> Self {
        Self { cidrs }
    }
}

fn first_forwarded_ip(headers: &HeaderMap) -> Option<IpAddr> {
    let forwarded_for = HeaderName::from_static("x-forwarded-for");
    let value = headers.get(forwarded_for)?.to_str().ok()?;
    let first = value.split(',').next()?.trim();
    if first.is_empty() {
        return None;
    }
    if let Ok(ip) = first.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Ok(sock) = first.parse::<SocketAddr>() {
        return Some(sock.ip());
    }
    None
}

pub fn resolve_client_ip(
    headers: &HeaderMap,
    peer_ip: Option<IpAddr>,
    trusted_proxies: &TrustedProxyConfig,
) -> Option<String> {
    let peer_ip = peer_ip?;
    if trusted_proxies.contains(peer_ip) {
        if let Some(forwarded) = first_forwarded_ip(headers) {
            return Some(forwarded.to_string());
        }
    }
    Some(peer_ip.to_string())
}

fn client_key_from_request(
    headers: &HeaderMap,
    request: &Request,
    trusted_proxies: &TrustedProxyConfig,
    ipv6_prefix_len: u8,
) -> String {
    let peer_ip = request
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|connect_info| connect_info.0.ip());
    let client_ip = resolve_client_ip(headers, peer_ip, trusted_proxies);
    let normalized = client_ip
        .and_then(|ip| ip.parse::<IpAddr>().ok())
        .map(|ip| normalize_ip_for_rate_key(ip, ipv6_prefix_len).to_string())
        .unwrap_or_else(|| "unknown".to_string());
    format!("ip:{normalized}")
}

/// Per-IP rate limiting middleware.
pub async fn ip_rate_limit_middleware(
    State(rate_limiter): State<Arc<IpRateLimiter>>,
    request: Request,
    next: Next,
) -> Response {
    let key = client_key_from_request(
        request.headers(),
        &request,
        &rate_limiter.trusted_proxies,
        rate_limiter.config.ipv6_prefix_len,
    );
    match rate_limiter.check_and_count(&key).await {
        Ok(()) => next.run(request).await,
        Err(retry_after_secs) => {
            let mut response = (
                StatusCode::TOO_MANY_REQUESTS,
                axum::Json(json!({
                    "error": "rate limit exceeded",
                    "retry_after_seconds": retry_after_secs
                })),
            )
                .into_response();
            if let Ok(v) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                response.headers_mut().insert(RETRY_AFTER, v);
            }
            response
        }
    }
}

fn normalize_ip_for_rate_key(ip: IpAddr, ipv6_prefix_len: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => {
            let prefix = ipv6_prefix_len.min(128);
            let raw = u128::from_be_bytes(v6.octets());
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            IpAddr::V6(std::net::Ipv6Addr::from((raw & mask).to_be_bytes()))
        }
    }
}

/// Request timing middleware
pub async fn timing_middleware(request: Request, next: Next) -> Response {
    let start = Instant::now();

    let mut response = next.run(request).await;

    let duration = start.elapsed();
    let elapsed_ms = duration.as_millis().to_string();
    if let Ok(value) = HeaderValue::from_str(&elapsed_ms) {
        response
            .headers_mut()
            .insert(HeaderName::from_static("x-response-time-ms"), value);
    }
    tracing::debug!("Request processed in {}ms", elapsed_ms);

    response
}

/// Request ID middleware
pub async fn request_id_middleware(mut request: Request, next: Next) -> Response {
    let request_id = uuid::Uuid::new_v4().to_string();

    request.extensions_mut().insert(request_id.clone());

    tracing::info!("Processing request: {}", request_id);

    let mut response: Response<Body> = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response
            .headers_mut()
            .insert(HeaderName::from_static("x-request-id"), value);
    }
    response
}

pub async fn security_headers_middleware(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    response.headers_mut().insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    response.headers_mut().insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    response.headers_mut().insert(
        HeaderName::from_static("cache-control"),
        HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        HeaderName::from_static("pragma"),
        HeaderValue::from_static("no-cache"),
    );
    response.headers_mut().insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("geolocation=(), microphone=(), camera=()"),
    );
    response.headers_mut().insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'; base-uri 'none'"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Router};
    use tower::ServiceExt;

    #[test]
    fn test_resolve_client_ip_ignores_xff_when_proxy_untrusted() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-forwarded-for"),
            "198.51.100.7, 10.0.0.1".parse().unwrap(),
        );
        let trusted = TrustedProxyConfig::default();
        let resolved = resolve_client_ip(&headers, Some("203.0.113.10".parse().unwrap()), &trusted);
        assert_eq!(resolved.as_deref(), Some("203.0.113.10"));
    }

    #[test]
    fn test_resolve_client_ip_uses_xff_when_proxy_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-forwarded-for"),
            "198.51.100.7, 10.0.0.1".parse().unwrap(),
        );
        let trusted = TrustedProxyConfig::from_cidrs(vec!["203.0.113.0/24".parse().unwrap()]);
        let resolved = resolve_client_ip(&headers, Some("203.0.113.10".parse().unwrap()), &trusted);
        assert_eq!(resolved.as_deref(), Some("198.51.100.7"));
    }

    #[test]
    fn test_normalize_ip_for_rate_key_ipv6_prefix() {
        let ip: IpAddr = "2001:db8:abcd:1234:1111:2222:3333:4444".parse().unwrap();
        let normalized = normalize_ip_for_rate_key(ip, 64);
        assert_eq!(normalized.to_string(), "2001:db8:abcd:1234::");
    }

    #[tokio::test]
    async fn test_identity_rate_limiter_observation_and_limit() {
        let limiter = IdentityRateLimiter::new(IdentityRateLimiterConfig {
            limit_per_hour: 2,
            bucket_ttl: Duration::from_secs(24 * 60 * 60),
            max_identities: 100,
        });

        let o1 = limiter.observe_identity("agent-1").await.expect("o1");
        assert_eq!(o1.requests_last_hour, 1);
        let o2 = limiter.observe_identity("agent-1").await.expect("o2");
        assert_eq!(o2.requests_last_hour, 2);
        assert!(limiter.observe_identity("agent-1").await.is_err());
    }

    #[tokio::test]
    async fn test_security_headers_middleware_adds_headers() {
        let app = Router::new()
            .route("/ok", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(security_headers_middleware));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ok")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(
            response.headers().get("x-content-type-options").unwrap(),
            "nosniff"
        );
        assert_eq!(response.headers().get("x-frame-options").unwrap(), "DENY");
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    }
}
