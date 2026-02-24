//! R-SRP Ultra - Zero-Trust API Gateway
//! 
//! Main API service that implements:
//! - CRUE rule evaluation
//! - Immutable audit logging
//! - JWT authentication
//! - Rate limiting

mod handlers;
mod middleware;
mod models;
mod error;

use axum::{
    Router,
    routing::get,
    middleware,
};
use std::net::SocketAddr;
use tower::ServiceBuilder;
use tower_http::cors::{CorsLayer, Any};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone)]
struct AppState {
    engine: crue_engine::CrueEngine,
    // logging: immutable_logging::ImmutableLog,
}

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,api_service=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
    
    tracing::info!("Starting R-SRP Ultra API Gateway");
    
    // Initialize CRUE engine
    let engine = crue_engine::CrueEngine::new();
    tracing::info!("CRUE Engine initialized with {} rules", engine.rule_count());
    
    // Initialize logging
    // let logging = immutable_logging::ImmutableLog::new();
    
    let state = AppState {
        engine,
        // logging,
    };
    
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
        // Metrics
        .route("/metrics", get(handlers::metrics))
        // Apply middleware
        .layer(
            ServiceBuilder::new()
                .layer(cors)
                .layer(tower_http::trace::TraceLayer::new_for_http())
                .layer(tower::limit::ConcurrencyLimitLayer::new(100))
                .into_inner(),
        )
        .with_state(state);
    
    // Start server
    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    tracing::info!("Listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
