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
use serde_json::json;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct IpRateLimiterConfig {
    pub limit_per_window: u32,
    pub window: Duration,
}

impl Default for IpRateLimiterConfig {
    fn default() -> Self {
        Self {
            limit_per_window: 100,
            window: Duration::from_secs(60),
        }
    }
}

#[derive(Debug, Clone)]
struct WindowBucket {
    window_started_at: Instant,
    hits: u32,
}

/// Simple in-memory IP/token bucket limiter.
#[derive(Debug)]
pub struct IpRateLimiter {
    config: IpRateLimiterConfig,
    buckets: Mutex<HashMap<String, WindowBucket>>,
}

impl IpRateLimiter {
    pub fn new(config: IpRateLimiterConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            buckets: Mutex::new(HashMap::new()),
        })
    }

    async fn check_and_count(&self, key: &str) -> Result<(), u64> {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().await;
        let bucket = buckets
            .entry(key.to_string())
            .or_insert_with(|| WindowBucket {
                window_started_at: now,
                hits: 0,
            });

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

fn client_key_from_request(headers: &HeaderMap, request: &Request) -> String {
    let forwarded_for = HeaderName::from_static("x-forwarded-for");
    if let Some(value) = headers.get(forwarded_for).and_then(|v| v.to_str().ok()) {
        if let Some(first) = value.split(',').next() {
            let ip = first.trim();
            if !ip.is_empty() {
                return format!("ip:{ip}");
            }
        }
    }

    if let Some(connect_info) = request
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
    {
        return format!("ip:{}", connect_info.0.ip());
    }

    "ip:unknown".to_string()
}

/// Per-IP rate limiting middleware.
pub async fn ip_rate_limit_middleware(
    State(rate_limiter): State<Arc<IpRateLimiter>>,
    request: Request,
    next: Next,
) -> Response {
    let key = client_key_from_request(request.headers(), &request);
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
