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
    collections::HashMap,
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
struct WindowBucket {
    window_started_at: Instant,
    last_seen_at: Instant,
    hits: u32,
}

/// Simple in-memory IP/token bucket limiter.
#[derive(Debug)]
pub struct IpRateLimiter {
    config: IpRateLimiterConfig,
    buckets: Mutex<HashMap<String, WindowBucket>>,
    trusted_proxies: TrustedProxyConfig,
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
    config: &IpRateLimiter,
) -> String {
    let peer_ip = request
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|connect_info| connect_info.0.ip());
    let client_ip = resolve_client_ip(headers, peer_ip, &config.trusted_proxies)
        .unwrap_or_else(|| "unknown".to_string());
    let normalized = client_ip
        .parse::<IpAddr>()
        .map(|ip| normalize_ip_for_rate_key(ip, config.config.ipv6_prefix_len).to_string())
        .unwrap_or(client_ip);
    format!("ip:{normalized}")
}

/// Per-IP rate limiting middleware.
pub async fn ip_rate_limit_middleware(
    State(rate_limiter): State<Arc<IpRateLimiter>>,
    request: Request,
    next: Next,
) -> Response {
    let key = client_key_from_request(request.headers(), &request, &rate_limiter);
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_normalize_ipv6_rate_key_to_prefix() {
        let ip: IpAddr = "2001:db8:abcd:1234:5678:9abc:def0:1234".parse().unwrap();
        let normalized = normalize_ip_for_rate_key(ip, 64);
        assert_eq!(normalized.to_string(), "2001:db8:abcd:1234::");
    }
}
