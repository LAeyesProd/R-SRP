//! API Middleware

use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
};
use std::time::Instant;

/// Request timing middleware
pub async fn timing_middleware(
    request: Request,
    next: Next,
) -> Response {
    let start = Instant::now();
    
    let response = next.run(request).await;
    
    let duration = start.elapsed();
    tracing::debug!("Request processed in {:?}", duration);
    
    response
}

/// Request ID middleware
pub async fn request_id_middleware(
    mut request: Request,
    next: Next,
) -> Response {
    let request_id = uuid::Uuid::new_v4().to_string();
    
    request.extensions_mut().insert(request_id.clone());
    
    tracing::info!("Processing request: {}", request_id);
    
    next.run(request).await
}
