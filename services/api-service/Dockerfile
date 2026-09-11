# R-SRP Ultra API Service Dockerfile
# Production Hardened Version

# ========== Build Stage ==========
FROM rust:1.93.1-bookworm@sha256:7c4ae649a84014c467d79319bbf17ce2632ae8b8be123ac2fb2ea5be46823f31 AS builder

# Install build dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the complete workspace before resolving dependencies
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY rsrp-demo ./rsrp-demo
COPY services/api-service ./services/api-service

RUN cargo fetch --locked

# Build with optimizations
RUN cargo build --release --locked --package api-service

# ========== Runtime Stage ==========
# Use distroless for minimal attack surface
FROM gcr.io/distroless/cc:nonroot@sha256:26474572388bb8bcbf837002e07b3c068e31b053f0ed1865218fc1e25a7650f6

WORKDIR /app

# Copy binary (stripped of debug symbols)
COPY --from=builder --chown=nonroot:nonroot /app/target/release/api-service /app/api-service

# Expose port
EXPOSE 8080

# Health probes are configured by the orchestrator; distroless has no HTTP client.

# Run as non-root
USER nonroot:nonroot

# Run the service
ENTRYPOINT ["/app/api-service"]
