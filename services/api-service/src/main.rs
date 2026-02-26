//! R-SRP Ultra - Zero-Trust API Gateway
//! 
//! Main API service that implements:
//! - CRUE rule evaluation
//! - Immutable audit logging
//! - JWT authentication
//! - Rate limiting
//! - mTLS (Zero-Trust)

mod handlers;
#[allow(dead_code)]
mod middleware;
mod models;
mod error;
#[allow(dead_code)]
mod tls;
#[allow(dead_code)]
mod incident;

use axum::{
    Router,
    routing::{get, post},
};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower_http::cors::{CorsLayer, Any};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use crue_engine::engine::CrueEngine;

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
                    algorithm: "SOFTHSM-HMAC-SHA256-PLACEHOLDER".to_string(),
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
                if algorithm != "SOFTHSM-HMAC-SHA256-PLACEHOLDER" || key_id != configured_key_id {
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
    audit_publications_dir: Option<PathBuf>,
    audit_publication_signer: Option<Mutex<AuditPublicationSigner>>,
    audit_tsa_url: Option<String>,
    audit_tsa_trust_store_pem: Option<PathBuf>,
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
    
    // Check for TLS configuration (mTLS)
    let tls_enabled = std::env::var("TLS_ENABLED").unwrap_or_default() == "true";
    if tls_enabled {
        tracing::error!("TLS_ENABLED=true but HTTPS listener integration is not wired in this binary yet.");
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TLS requested but server is currently HTTP-only",
        )
        .into());
    } else {
        tracing::warn!("Running in INSECURE mode - no TLS. Set TLS_ENABLED=true for production.");
    }
    
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
        tracing::warn!("AUDIT_PUBLICATIONS_DIR not configured; daily root endpoint will return 503.");
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
            let signer = crypto_core::hsm::HsmSigner::new(config, &key_id)
                .map_err(|e| std::io::Error::other(format!("Failed to initialize SoftHSM signer: {e}")))?;
            Some(Mutex::new(AuditPublicationSigner::SoftHsm { signer, key_id }))
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
        tracing::warn!("Audit publication signing disabled (AUDIT_PUBLICATION_SIGNING_PROVIDER=none).");
    } else {
        tracing::warn!("AUDIT_PUBLICATION_SIGNING_SECRET not configured; daily publications will be unsigned.");
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
        audit_publications_dir,
        audit_publication_signer,
        audit_tsa_url,
        audit_tsa_trust_store_pem,
    });
    
    // CORS configuration
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);
    
    // Build router
    let app = Router::new()
        // Health checks
        .route("/health", get(handlers::health_check))
        .route("/ready", get(handlers::ready_check))
        // API routes
        .route("/api/v1/validate", get(handlers::validate_access))
        .route("/api/v1/validate", post(handlers::validate_access_post))
        // Audit routes
        .route("/api/v1/audit/chain/verify", get(handlers::verify_chain))
        .route("/api/v1/audit/daily/{date}/root", get(handlers::get_daily_root))
        .route("/api/v1/audit/daily/{date}/verify", get(handlers::verify_daily_publication))
        .route("/api/v1/audit/daily/publish", post(handlers::publish_daily))
        // Metrics
        .route("/metrics", get(handlers::metrics))
        // Apply middleware
        .layer(cors)
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .layer(tower::limit::ConcurrencyLimitLayer::new(100))
        .with_state(state);
    
    // Start server
    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    tracing::info!("Listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await
        .map_err(|e| {
            tracing::error!("Failed to bind to {}: {}", addr, e);
            e
        })?;
    
    axum::serve(listener, app)
        .await
        .map_err(|e| {
            tracing::error!("Server error: {}", e);
            e
        })?;

    Ok(())
}
