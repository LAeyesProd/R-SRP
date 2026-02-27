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
use tower_http::cors::CorsLayer;
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
        key_pair: crypto_core::signature::Ed25519KeyPair,
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
    publication_service: Mutex<immutable_logging::publication::PublicationService>,
    metrics: ApiMetrics,
    audit_publications_dir: Option<PathBuf>,
    audit_publication_signer: Option<Mutex<AuditPublicationSigner>>,
    audit_tsa_url: Option<String>,
    audit_tsa_trust_store_pem: Option<PathBuf>,
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

    // Security controls
    let tls_enabled = parse_bool_env("TLS_ENABLED", false);
    if !tls_enabled && !cfg!(debug_assertions) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TLS_ENABLED must be true for release builds",
        )
        .into());
    }
    let jwt_secret = std::env::var("JWT_SECRET").map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "JWT_SECRET is required")
    })?;
    let auth_config = auth::JwtAuthConfig::from_secret(&jwt_secret)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    // Initialize CRUE engine
    let engine = CrueEngine::new();
    tracing::info!("CRUE Engine initialized with {} rules", engine.rule_count());

    // Initialize logging
    let logging = immutable_logging::ImmutableLog::new();
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
                key_pair,
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
                    key_pair,
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
    if let Some(tsa_url) = &audit_tsa_url {
        tracing::info!("Audit TSA URL configured: {}", tsa_url);
    }
    if let Some(path) = &audit_tsa_trust_store_pem {
        tracing::info!("Audit TSA trust store configured: {}", path.display());
    }

    let state = Arc::new(AppState {
        engine,
        logging,
        publication_service: Mutex::new(immutable_logging::publication::PublicationService::new()),
        metrics: ApiMetrics::default(),
        audit_publications_dir,
        audit_publication_signer,
        audit_tsa_url,
        audit_tsa_trust_store_pem,
    });

    let rate_limiter = middleware::IpRateLimiter::new(middleware::IpRateLimiterConfig::default());
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

    let api_v1 = Router::new()
        .merge(validate_routes)
        .merge(audit_read_routes)
        .merge(audit_admin_routes)
        .merge(metrics_routes)
        .layer(from_fn_with_state(
            rate_limiter.clone(),
            middleware::ip_rate_limit_middleware,
        ));

    let app = Router::new()
        // Health checks
        .route("/health", get(handlers::health_check))
        .route("/ready", get(handlers::ready_check))
        .nest("/api/v1", api_v1)
        // Apply middleware
        .layer(from_fn(middleware::request_id_middleware))
        .layer(from_fn(middleware::timing_middleware))
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
