# R-SRP Ultra API Service Dockerfile
# Production Hardened Version

# ========== Build Stage ==========
FROM rust:1.76-alpine AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev openssl-dev

WORKDIR /app

# Copy workspace manifest
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main(){}" > src/main.rs

# Build dependencies first (for caching)
RUN cargo fetch

# Copy actual source
COPY crates/crue-dsl ./crates/crue-dsl
COPY crates/crypto-core ./crates/crypto-core
COPY crates/crue-engine ./crates/crue-engine
COPY crates/immutable-logging ./crates/immutable-logging
COPY services/api-service ./services/api-service

# Build with optimizations
WORKDIR /app/services/api-service
RUN RUSTFLAGS="-C target-cpu=native" cargo build --release --locked

# ========== Runtime Stage ==========
# Use distroless for minimal attack surface
FROM gcr.io/distroless/cc:nonroot

WORKDIR /app

# Copy binary (stripped of debug symbols)
COPY --from=builder /app/services/api-service/target/release/api-service /app/api-service

# Copy config if exists
COPY --chown=nonroot:nonroot config/ /app/config/

# Set ownership
RUN chown -R nonroot:nonroot /app

# Expose port
EXPOSE 8080

# Health check using pure HTTP (no curl)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["wget", "-q", "--spider", "http://localhost:8080/health"]

# Run as non-root
USER nonroot:nonroot

# Run the service
ENTRYPOINT ["/app/api-service"]
