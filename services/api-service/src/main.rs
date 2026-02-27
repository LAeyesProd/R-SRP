//! R-SRP Ultra - Zero-Trust API Gateway
//!
//! Main API service that implements:
//! - CRUE rule evaluation
//! - Immutable audit logging
//! - JWT authentication
//! - Rate limiting
//! - mTLS (Zero-Trust)

mod auth;
mod error;
mod handlers;
#[allow(dead_code)]
mod incident;
mod middleware;
mod mission_schedule;
mod models;
mod tls;

use axum::{
    http::{
        header::HeaderName, header::HeaderValue, header::ACCEPT, header::AUTHORIZATION,
        header::CONTENT_TYPE, Method,
    },
    middleware::{from_fn, from_fn_with_state},
    routing::{get, post},
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use crue_engine::engine::CrueEngine;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::Duration;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

struct AuditPublicationSignature {
    signature: Vec<u8>,
    algorithm: String,
    key_id: String,
    public_key_hex: Option<String>,
    verified: Option<bool>,
}

enum AuditPublicationSigner {
    SoftwareEd25519 {
        key_pair: Box<crypto_core::signature::Ed25519KeyPair>,
        key_id: String,
        public_key_hex: String,
    },
    SoftHsm {
        signer: crypto_core::hsm::HsmSigner,
        key_id: String,
    },
}

impl AuditPublicationSigner {
    fn provider_name(&self) -> &'static str {
        match self {
            Self::SoftwareEd25519 { .. } => "software-ed25519",
            Self::SoftHsm { .. } => "softhsm",
        }
    }

    fn sign_publication_payload(
        &mut self,
        payload: &[u8],
    ) -> Result<AuditPublicationSignature, crypto_core::CryptoError> {
        match self {
            Self::SoftwareEd25519 {
                key_pair,
                key_id,
                public_key_hex,
            } => {
                let signature = crypto_core::signature::sign(payload, key_pair)?;
                let verified = crypto_core::signature::verify(
                    payload,
                    &signature,
                    &key_pair.verifying_key(),
                    crypto_core::SignatureAlgorithm::Ed25519,
                )?;
                Ok(AuditPublicationSignature {
                    signature,
                    algorithm: "ED25519".to_string(),
                    key_id: key_id.clone(),
                    public_key_hex: Some(public_key_hex.clone()),
                    verified: Some(verified),
                })
            }
            Self::SoftHsm { signer, key_id } => {
                let signature = signer.sign(payload)?;
                let verified = signer.verify(payload, &signature).ok();
                Ok(AuditPublicationSignature {
                    signature,
                    algorithm: "ED25519-SOFTHSM".to_string(),
                    key_id: key_id.clone(),
                    public_key_hex: None,
                    verified,
                })
            }
        }
    }

    fn verify_publication_signature(
        &mut self,
        payload: &[u8],
        signature: &[u8],
        algorithm: &str,
        key_id: &str,
    ) -> Result<bool, crypto_core::CryptoError> {
        match self {
            Self::SoftwareEd25519 {
                key_pair,
                key_id: configured_key_id,
                ..
            } => {
                if algorithm != "ED25519" || key_id != configured_key_id {
                    return Ok(false);
                }
                crypto_core::signature::verify(
                    payload,
                    signature,
                    &key_pair.verifying_key(),
                    crypto_core::SignatureAlgorithm::Ed25519,
                )
            }
            Self::SoftHsm {
                signer,
                key_id: configured_key_id,
            } => {
                if algorithm != "ED25519-SOFTHSM" || key_id != configured_key_id {
                    return Ok(false);
                }
                signer.verify(payload, signature)
            }
        }
    }

    fn verification_public_key_hex(&self) -> Option<String> {
        match self {
            Self::SoftwareEd25519 { public_key_hex, .. } => Some(public_key_hex.clone()),
            Self::SoftHsm { .. } => None,
        }
    }
}

struct AppState {
    engine: CrueEngine,
    logging: immutable_logging::ImmutableLog,
    mission_schedule: mission_schedule::MissionScheduleStore,
    entropy_health: Mutex<EntropyHealthState>,
    entropy_health_enabled: bool,
    entropy_fail_closed: bool,
    publication_service: Mutex<immutable_logging::publication::PublicationService>,
    publication_daily_lock: Mutex<()>,
    metrics: ApiMetrics,
    identity_rate_limiter: Arc<middleware::IdentityRateLimiter>,
    audit_publications_dir: Option<PathBuf>,
    audit_publication_signer: Option<Mutex<AuditPublicationSigner>>,
    audit_tsa_url: Option<String>,
    audit_tsa_trust_store_pem: Option<PathBuf>,
    trusted_proxies: middleware::TrustedProxyConfig,
}

#[derive(Debug, Clone, Default)]
struct EntropyHealthState {
    healthy: bool,
    last_checked_at: Option<String>,
    last_error: Option<String>,
}

#[derive(Default)]
struct ApiMetrics {
    total_requests: AtomicU64,
    allowed_requests: AtomicU64,
    blocked_requests: AtomicU64,
    warnings: AtomicU64,
    total_evaluation_time_ms: AtomicU64,
}

impl AppState {
    fn record_validation_metrics(
        &self,
        decision: crue_engine::decision::Decision,
        evaluation_time_ms: u64,
    ) {
        self.metrics.total_requests.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .total_evaluation_time_ms
            .fetch_add(evaluation_time_ms, Ordering::Relaxed);
        match decision {
            crue_engine::decision::Decision::Allow => {
                self.metrics
                    .allowed_requests
                    .fetch_add(1, Ordering::Relaxed);
            }
            crue_engine::decision::Decision::Block => {
                self.metrics
                    .blocked_requests
                    .fetch_add(1, Ordering::Relaxed);
            }
            crue_engine::decision::Decision::Warn
            | crue_engine::decision::Decision::ApprovalRequired => {
                self.metrics.warnings.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn metrics_snapshot(&self) -> (u64, u64, u64, u64, f64) {
        let total_requests = self.metrics.total_requests.load(Ordering::Relaxed);
        let allowed_requests = self.metrics.allowed_requests.load(Ordering::Relaxed);
        let blocked_requests = self.metrics.blocked_requests.load(Ordering::Relaxed);
        let warnings = self.metrics.warnings.load(Ordering::Relaxed);
        let total_eval = self
            .metrics
            .total_evaluation_time_ms
            .load(Ordering::Relaxed);
        let avg = if total_requests == 0 {
            0.0
        } else {
            total_eval as f64 / total_requests as f64
        };
        (
            total_requests,
            allowed_requests,
            blocked_requests,
            warnings,
            avg,
        )
    }
}

fn parse_bool_env(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(default)
}

fn parse_u64_env(name: &str, default: u64) -> Result<u64, std::io::Error> {
    let Some(raw) = std::env::var(name).ok() else {
        return Ok(default);
    };
    if raw.trim().is_empty() {
        return Ok(default);
    }
    raw.trim().parse::<u64>().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Invalid {name} value `{raw}`: {e}"),
        )
    })
}

fn is_production_environment() -> bool {
    [
        std::env::var("ENV").ok(),
        std::env::var("APP_ENV").ok(),
        std::env::var("RUST_ENV").ok(),
    ]
    .into_iter()
    .flatten()
    .any(|v| matches!(v.to_ascii_lowercase().as_str(), "prod" | "production"))
}

fn should_expose_public_health_routes(production_env: bool) -> bool {
    !production_env || parse_bool_env("PUBLIC_HEALTH_ENDPOINTS", false)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RateLimitBackend {
    InMemory,
    External,
}

fn parse_rate_limit_backend() -> Result<RateLimitBackend, std::io::Error> {
    let raw = std::env::var("RATE_LIMIT_BACKEND").unwrap_or_else(|_| "in-memory".to_string());
    match raw.trim().to_ascii_lowercase().as_str() {
        "in-memory" | "memory" => Ok(RateLimitBackend::InMemory),
        "external" => Ok(RateLimitBackend::External),
        other => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Unsupported RATE_LIMIT_BACKEND value: {other}"),
        )),
    }
}

fn cors_layer_from_env() -> Result<CorsLayer, Box<dyn std::error::Error>> {
    let configured = std::env::var("CORS_ALLOWED_ORIGINS")
        .unwrap_or_else(|_| "http://localhost:3000,http://127.0.0.1:3000".to_string());
    let origins: Vec<HeaderValue> = configured
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(HeaderValue::from_str)
        .collect::<Result<Vec<_>, _>>()?;
    if origins.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "CORS_ALLOWED_ORIGINS must contain at least one origin",
        )
        .into());
    }

    Ok(CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([
            AUTHORIZATION,
            CONTENT_TYPE,
            ACCEPT,
            HeaderName::from_static("x-request-id"),
        ]))
}

async fn refresh_entropy_health(state: &Arc<AppState>) {
    let checked_at = chrono::Utc::now().to_rfc3339();
    let mut health = state.entropy_health.lock().await;
    match crypto_core::entropy::entropy_health_check() {
        Ok(_) => {
            health.healthy = true;
            health.last_checked_at = Some(checked_at);
            health.last_error = None;
        }
        Err(err) => {
            health.healthy = false;
            health.last_checked_at = Some(checked_at);
            health.last_error = Some(err.to_string());
            tracing::error!(error = %err, "Entropy health check failed");
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,api_service=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting R-SRP Ultra API Gateway");
    let production_env = is_production_environment();

    // Security controls
    let tls_enabled = parse_bool_env("TLS_ENABLED", false);
    if !tls_enabled && !cfg!(debug_assertions) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TLS_ENABLED must be true for release builds",
        )
        .into());
    }
    let entropy_health_enabled = parse_bool_env("ENTROPY_HEALTHCHECK_ENABLED", true);
    if production_env && !entropy_health_enabled {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "ENTROPY_HEALTHCHECK_ENABLED=false is forbidden in production",
        )
        .into());
    }
    let entropy_fail_closed = parse_bool_env("ENTROPY_FAIL_CLOSED", production_env);
    let entropy_interval_seconds =
        parse_u64_env("ENTROPY_HEALTHCHECK_INTERVAL_SECONDS", 60)?.max(1);
    let initial_entropy_health = if entropy_health_enabled {
        let checked_at = chrono::Utc::now().to_rfc3339();
        match crypto_core::entropy::entropy_health_check() {
            Ok(_) => EntropyHealthState {
                healthy: true,
                last_checked_at: Some(checked_at),
                last_error: None,
            },
            Err(err) => EntropyHealthState {
                healthy: false,
                last_checked_at: Some(checked_at),
                last_error: Some(err.to_string()),
            },
        }
    } else {
        EntropyHealthState {
            healthy: true,
            last_checked_at: None,
            last_error: None,
        }
    };
    if entropy_health_enabled {
        if initial_entropy_health.healthy {
            tracing::info!("Initial entropy self-test passed");
        } else {
            tracing::error!(
                error = %initial_entropy_health.last_error.as_deref().unwrap_or("unknown error"),
                "Initial entropy self-test failed"
            );
        }
    }
    if entropy_health_enabled && entropy_fail_closed && !initial_entropy_health.healthy {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Entropy self-test failed during startup: {}",
                initial_entropy_health
                    .last_error
                    .as_deref()
                    .unwrap_or("unknown error")
            ),
        )
        .into());
    }
    let auth_config = auth::JwtAuthConfig::from_env()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    let mission_schedule = mission_schedule::MissionScheduleStore::from_env()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    // Initialize CRUE engine
    let engine = CrueEngine::new();
    tracing::info!("CRUE Engine initialized with {} rules", engine.rule_count());

    // Initialize immutable logging (optionally from WAL replay).
    let immutable_log_wal_path = std::env::var("IMMUTABLE_LOG_WAL_PATH")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from);
    let logging = if let Some(path) = immutable_log_wal_path.as_ref() {
        tracing::info!("Immutable log WAL enabled: {}", path.display());
        immutable_logging::ImmutableLog::with_wal_path(path)
            .await
            .map_err(|e| std::io::Error::other(format!("Failed to initialize WAL log: {e}")))?
    } else {
        immutable_logging::ImmutableLog::new()
    };
    let audit_publications_dir = std::env::var("AUDIT_PUBLICATIONS_DIR")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from);
    let audit_publication_signing_secret = std::env::var("AUDIT_PUBLICATION_SIGNING_SECRET")
        .ok()
        .filter(|v| !v.trim().is_empty());
    let audit_publication_signing_provider = std::env::var("AUDIT_PUBLICATION_SIGNING_PROVIDER")
        .ok()
        .filter(|v| !v.trim().is_empty());
    let audit_publication_signing_key_id = std::env::var("AUDIT_PUBLICATION_SIGNING_KEY_ID")
        .ok()
        .filter(|v| !v.trim().is_empty());
    let audit_tsa_url = std::env::var("AUDIT_TSA_URL")
        .ok()
        .filter(|v| !v.trim().is_empty());
    let audit_tsa_trust_store_pem = std::env::var("AUDIT_TSA_TRUST_STORE_PEM")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from);
    if let Some(dir) = &audit_publications_dir {
        tracing::info!("Audit publication directory configured: {}", dir.display());
    } else {
        tracing::warn!(
            "AUDIT_PUBLICATIONS_DIR not configured; daily root endpoint will return 503."
        );
    }
    let audit_publication_signer = match audit_publication_signing_provider.as_deref() {
        Some("none") => None,
        Some("software-ed25519") => {
            let secret = audit_publication_signing_secret.as_deref().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "AUDIT_PUBLICATION_SIGNING_PROVIDER=software-ed25519 requires AUDIT_PUBLICATION_SIGNING_SECRET",
                )
            })?;
            let key_id = audit_publication_signing_key_id
                .clone()
                .unwrap_or_else(|| "api-service-ed25519".to_string());
            let key_pair = crypto_core::signature::Ed25519KeyPair::derive_from_secret(
                secret.as_bytes(),
                Some(key_id.clone()),
            );
            let public_key_hex = key_pair
                .verifying_key()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();
            Some(Mutex::new(AuditPublicationSigner::SoftwareEd25519 {
                key_pair: Box::new(key_pair),
                key_id,
                public_key_hex,
            }))
        }
        Some("softhsm") => {
            let key_id = audit_publication_signing_key_id
                .clone()
                .unwrap_or_else(|| "api-service-softhsm".to_string());
            let slot = std::env::var("AUDIT_PUBLICATION_HSM_SLOT")
                .ok()
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(0);
            let connection = std::env::var("AUDIT_PUBLICATION_HSM_CONNECTION")
                .unwrap_or_else(|_| "local://softhsm".to_string());
            let key_label_prefix = std::env::var("AUDIT_PUBLICATION_HSM_LABEL_PREFIX")
                .unwrap_or_else(|_| "audit-publication".to_string());
            let config = crypto_core::hsm::HsmConfig {
                hsm_type: crypto_core::hsm::HsmType::SoftHSM,
                connection,
                slot,
                key_label_prefix,
            };
            let signer = crypto_core::hsm::HsmSigner::new(config, &key_id).map_err(|e| {
                std::io::Error::other(format!("Failed to initialize SoftHSM signer: {e}"))
            })?;
            Some(Mutex::new(AuditPublicationSigner::SoftHsm {
                signer,
                key_id,
            }))
        }
        Some(other) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Unsupported AUDIT_PUBLICATION_SIGNING_PROVIDER: {other}"),
            )
            .into())
        }
        None => {
            if let Some(secret) = audit_publication_signing_secret.as_deref() {
                let key_id = audit_publication_signing_key_id
                    .clone()
                    .unwrap_or_else(|| "api-service-ed25519".to_string());
                let key_pair = crypto_core::signature::Ed25519KeyPair::derive_from_secret(
                    secret.as_bytes(),
                    Some(key_id.clone()),
                );
                let public_key_hex = key_pair
                    .verifying_key()
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>();
                Some(Mutex::new(AuditPublicationSigner::SoftwareEd25519 {
                    key_pair: Box::new(key_pair),
                    key_id,
                    public_key_hex,
                }))
            } else {
                None
            }
        }
    };

    if audit_publication_signer.is_some() {
        let provider_name = audit_publication_signer
            .as_ref()
            .and_then(|m| m.try_lock().ok().map(|g| g.provider_name().to_string()))
            .unwrap_or_else(|| "unknown".to_string());
        tracing::info!(
            "Audit publication signing enabled (provider={}, key_id={})",
            provider_name,
            audit_publication_signing_key_id
                .as_deref()
                .unwrap_or("api-service-signing")
        );
    } else if audit_publication_signing_provider.as_deref() == Some("none") {
        tracing::warn!(
            "Audit publication signing disabled (AUDIT_PUBLICATION_SIGNING_PROVIDER=none)."
        );
    } else {
        tracing::warn!(
            "AUDIT_PUBLICATION_SIGNING_SECRET not configured; daily publications will be unsigned."
        );
    }

    if production_env && audit_publication_signer.is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "production requires audit publication signer (set AUDIT_PUBLICATION_SIGNING_PROVIDER=softhsm and related HSM settings)",
        )
        .into());
    }

    if audit_publication_signer
        .as_ref()
        .and_then(|m| m.try_lock().ok().map(|g| g.provider_name().to_string()))
        .as_deref()
        == Some("software-ed25519")
    {
        if production_env {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "software-ed25519 signer is forbidden in production. Use AUDIT_PUBLICATION_SIGNING_PROVIDER=softhsm",
            )
            .into());
        }
        if !cfg!(debug_assertions) {
            tracing::warn!(
                "Audit publication signer uses software-ed25519. Prefer softhsm/HSM for non-development environments."
            );
        }
    }
    if let Some(tsa_url) = &audit_tsa_url {
        tracing::info!("Audit TSA URL configured: {}", tsa_url);
    }
    if let Some(path) = &audit_tsa_trust_store_pem {
        tracing::info!("Audit TSA trust store configured: {}", path.display());
    }

    let trusted_proxies = middleware::TrustedProxyConfig::from_env();
    if trusted_proxies.is_empty() {
        tracing::warn!(
            "TRUSTED_PROXY_CIDRS is empty; X-Forwarded-For will be ignored (direct peer IP only)."
        );
    } else {
        tracing::info!(
            "Trusted proxy CIDRs configured (count={})",
            trusted_proxies.len()
        );
    }

    let identity_rate_limiter =
        middleware::IdentityRateLimiter::new(middleware::IdentityRateLimiterConfig::from_env());

    let state = Arc::new(AppState {
        engine,
        logging,
        mission_schedule,
        entropy_health: Mutex::new(initial_entropy_health),
        entropy_health_enabled,
        entropy_fail_closed,
        publication_service: Mutex::new(immutable_logging::publication::PublicationService::new()),
        publication_daily_lock: Mutex::new(()),
        metrics: ApiMetrics::default(),
        identity_rate_limiter,
        audit_publications_dir,
        audit_publication_signer,
        audit_tsa_url,
        audit_tsa_trust_store_pem,
        trusted_proxies: trusted_proxies.clone(),
    });
    if entropy_health_enabled {
        tracing::info!(
            interval_seconds = entropy_interval_seconds,
            fail_closed = entropy_fail_closed,
            "Entropy health check enabled"
        );
        let state_for_entropy = state.clone();
        tokio::spawn(async move {
            let interval = Duration::from_secs(entropy_interval_seconds);
            loop {
                tokio::time::sleep(interval).await;
                refresh_entropy_health(&state_for_entropy).await;
            }
        });
    } else {
        tracing::warn!("Entropy health check disabled");
    }

    let rate_limit_backend = parse_rate_limit_backend()?;
    let rate_limiter = match rate_limit_backend {
        RateLimitBackend::InMemory => {
            if is_production_environment() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "RATE_LIMIT_BACKEND=in-memory is forbidden in production; use RATE_LIMIT_BACKEND=external",
                )
                .into());
            }
            Some(middleware::IpRateLimiter::new(
                middleware::IpRateLimiterConfig::from_env(),
                trusted_proxies,
            ))
        }
        RateLimitBackend::External => {
            tracing::info!("Rate limiting delegated to external enforcement layer");
            None
        }
    };
    if is_production_environment() && rate_limiter.is_none() {
        tracing::info!(
            "Production mode: in-process rate limiter disabled; external backend is required."
        );
    }
    let cors = cors_layer_from_env()?;

    // Build protected API routers
    let validate_routes = Router::new()
        .route("/validate", get(handlers::validate_access))
        .route("/validate", post(handlers::validate_access_post))
        .route_layer(from_fn_with_state(auth_config.clone(), auth::require_agent));

    let audit_read_routes = Router::new()
        .route("/audit/chain/verify", get(handlers::verify_chain))
        .route("/audit/daily/{date}/root", get(handlers::get_daily_root))
        .route(
            "/audit/daily/{date}/verify",
            get(handlers::verify_daily_publication),
        )
        .route_layer(from_fn_with_state(
            auth_config.clone(),
            auth::require_auditor,
        ));

    let audit_admin_routes = Router::new()
        .route("/audit/daily/publish", post(handlers::publish_daily))
        .route_layer(from_fn_with_state(auth_config.clone(), auth::require_admin));

    let metrics_routes = Router::new()
        .route("/metrics", get(handlers::metrics))
        .route_layer(from_fn_with_state(
            auth_config.clone(),
            auth::require_auditor,
        ));

    let mut api_v1 = Router::new()
        .merge(validate_routes)
        .merge(audit_read_routes)
        .merge(audit_admin_routes)
        .merge(metrics_routes)
        .layer(RequestBodyLimitLayer::new(64 * 1024));
    if let Some(rate_limiter) = rate_limiter {
        api_v1 = api_v1.layer(from_fn_with_state(
            rate_limiter,
            middleware::ip_rate_limit_middleware,
        ));
    }

    let expose_public_health = should_expose_public_health_routes(is_production_environment());
    let mut app = Router::new().nest("/api/v1", api_v1);
    if expose_public_health {
        app = app
            .route("/health", get(handlers::health_check))
            .route("/ready", get(handlers::ready_check));
    } else {
        tracing::info!("Public /health and /ready endpoints disabled in production");
    }

    let app = app
        // Apply middleware
        .layer(from_fn(middleware::request_id_middleware))
        .layer(from_fn(middleware::timing_middleware))
        .layer(from_fn(middleware::security_headers_middleware))
        .layer(cors)
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .layer(tower::limit::ConcurrencyLimitLayer::new(100))
        .with_state(state);

    // Start server
    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    tracing::info!("Listening on {}", addr);

    if tls_enabled {
        let cert_path = std::env::var("TLS_CERT_PATH").map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TLS_CERT_PATH is required when TLS_ENABLED=true",
            )
        })?;
        let key_path = std::env::var("TLS_KEY_PATH").map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TLS_KEY_PATH is required when TLS_ENABLED=true",
            )
        })?;
        let client_ca_path = std::env::var("TLS_CLIENT_CA_PATH").ok();
        let tls_conf = tls::TlsConfig::from_files(
            std::path::Path::new(&cert_path),
            std::path::Path::new(&key_path),
            client_ca_path.as_deref().map(std::path::Path::new),
        )
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
        let server_config = tls_conf
            .build_server_config()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
        let tls = RustlsConfig::from_config(Arc::new(server_config));
        tracing::info!("TLS enabled (mTLS enforce={})", tls_conf.enforce_mtls);
        axum_server::bind_rustls(addr, tls)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .map_err(|e| {
                tracing::error!("HTTPS server error: {}", e);
                e
            })?;
    } else {
        tracing::warn!("TLS disabled: development HTTP mode only.");
        let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| {
            tracing::error!("Failed to bind to {}: {}", addr, e);
            e
        })?;

        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .map_err(|e| {
            tracing::error!("Server error: {}", e);
            e
        })?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::sync::{Mutex as StdMutex, OnceLock};
    use tower::ServiceExt;

    fn env_test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<StdMutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| StdMutex::new(()))
            .lock()
            .expect("env lock")
    }

    fn build_health_probe_router(production_env: bool) -> Router {
        let state = Arc::new(AppState {
            engine: CrueEngine::new(),
            logging: immutable_logging::ImmutableLog::new(),
            mission_schedule: mission_schedule::MissionScheduleStore::default(),
            entropy_health: tokio::sync::Mutex::new(EntropyHealthState {
                healthy: true,
                last_checked_at: None,
                last_error: None,
            }),
            entropy_health_enabled: true,
            entropy_fail_closed: true,
            publication_service: tokio::sync::Mutex::new(
                immutable_logging::publication::PublicationService::new(),
            ),
            publication_daily_lock: tokio::sync::Mutex::new(()),
            metrics: ApiMetrics::default(),
            identity_rate_limiter: middleware::IdentityRateLimiter::new(
                middleware::IdentityRateLimiterConfig::default(),
            ),
            audit_publications_dir: None,
            audit_publication_signer: None,
            audit_tsa_url: None,
            audit_tsa_trust_store_pem: None,
            trusted_proxies: middleware::TrustedProxyConfig::default(),
        });

        let mut app = Router::new();
        if should_expose_public_health_routes(production_env) {
            app = app
                .route("/health", get(handlers::health_check))
                .route("/ready", get(handlers::ready_check));
        }
        app.with_state(state)
    }

    #[test]
    fn test_should_expose_public_health_routes_defaults_to_hidden_in_production() {
        let _guard = env_test_lock();
        let previous = std::env::var("PUBLIC_HEALTH_ENDPOINTS").ok();
        std::env::remove_var("PUBLIC_HEALTH_ENDPOINTS");

        assert!(!should_expose_public_health_routes(true));
        assert!(should_expose_public_health_routes(false));

        match previous {
            Some(value) => std::env::set_var("PUBLIC_HEALTH_ENDPOINTS", value),
            None => std::env::remove_var("PUBLIC_HEALTH_ENDPOINTS"),
        }
    }

    #[tokio::test]
    async fn test_production_profile_disables_public_health_and_ready_routes() {
        let _guard = env_test_lock();
        let previous = std::env::var("PUBLIC_HEALTH_ENDPOINTS").ok();
        std::env::remove_var("PUBLIC_HEALTH_ENDPOINTS");
        let app = build_health_probe_router(true);

        let health = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("health request"),
            )
            .await
            .expect("health response");
        assert_eq!(health.status(), StatusCode::NOT_FOUND);

        let ready = app
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .expect("ready request"),
            )
            .await
            .expect("ready response");
        assert_eq!(ready.status(), StatusCode::NOT_FOUND);

        match previous {
            Some(value) => std::env::set_var("PUBLIC_HEALTH_ENDPOINTS", value),
            None => std::env::remove_var("PUBLIC_HEALTH_ENDPOINTS"),
        }
    }

    #[tokio::test]
    async fn test_production_health_opt_in_still_redacts_version() {
        let _guard = env_test_lock();
        let prev_public = std::env::var("PUBLIC_HEALTH_ENDPOINTS").ok();
        let prev_version = std::env::var("HEALTH_EXPOSE_VERSION").ok();
        let prev_env = std::env::var("ENV").ok();
        std::env::set_var("PUBLIC_HEALTH_ENDPOINTS", "true");
        std::env::remove_var("HEALTH_EXPOSE_VERSION");
        std::env::set_var("ENV", "production");
        let app = build_health_probe_router(true);

        let health = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("health request"),
            )
            .await
            .expect("health response");
        assert_eq!(health.status(), StatusCode::OK);
        let body = axum::body::to_bytes(health.into_body(), usize::MAX)
            .await
            .expect("health body");
        let payload: serde_json::Value = serde_json::from_slice(&body).expect("health json");
        assert_eq!(payload["version"].as_str(), Some("redacted"));
        assert!(payload.get("status").is_some());
        assert!(payload.get("timestamp").is_some());

        match prev_public {
            Some(value) => std::env::set_var("PUBLIC_HEALTH_ENDPOINTS", value),
            None => std::env::remove_var("PUBLIC_HEALTH_ENDPOINTS"),
        }
        match prev_version {
            Some(value) => std::env::set_var("HEALTH_EXPOSE_VERSION", value),
            None => std::env::remove_var("HEALTH_EXPOSE_VERSION"),
        }
        match prev_env {
            Some(value) => std::env::set_var("ENV", value),
            None => std::env::remove_var("ENV"),
        }
    }
}
