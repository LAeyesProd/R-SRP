# R-SRP Ultra+ MVP

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    R-SRP Ultra+ MVP                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                  API Service                         │   │
│  │                  (Rust/Axum)                       │   │
│  └─────────────────────────────────────────────────────┘   │
│                              │                               │
│         ┌────────────────────┼────────────────────┐        │
│         │                    │                    │        │
│         ▼                    ▼                    ▼        │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐ │
│  │  CRUE      │     │   PQC       │     │ Immutable   │ │
│  │  Engine    │     │   Crypto    │     │  Logging    │ │
│  └─────────────┘     └─────────────┘     └─────────────┘ │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Composants

| Composant | Description | Tech |
|-----------|-------------|------|
| **api-service** | API Gateway REST | Rust + Axum |
| **crue-engine** | Moteur de règles | Rust |
| **crue-dsl** | Parser règles | Rust |
| **crypto-core** | Primitives crypto | Rust |
| **immutable-logging** | Audit immuable | Rust |
| **pqcrypto** | Crypto PQC | Rust |

## Build

```bash
# Build release
cargo build --release --workspace

# Run tests
cargo test --workspace

# Run with Docker
docker build -t rsrp-ultra:latest .
```

## Configuration

Les variables d'environnement :

| Variable | Description | Défaut |
|----------|-------------|--------|
| `RUST_LOG` | Niveau de log | info |
| `DATABASE_URL` | URL base données | - |
| `HSM_ENDPOINT` | Endpoint HSM | - |

## Docker

```bash
# Build
docker build -t rsrp-ultra/api-service:latest services/api-service/

# Run
docker run -p 8080:8080 rsrp-ultra/api-service:latest
```

## CI/CD

Les workflows GitHub incluent :

- Tests unitaires
- Analyse statique (Clippy)
- Audit sécurité (cargo-audit)
- Build conteneur
- Signature Cosign

## License

EUPL-1.2
