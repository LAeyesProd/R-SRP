# 🏛 R-SRP Ultra — Registre National des Comptes Bancaires

**Architecture Zero-Trust niveau État**

## Vue d'Ensemble

R-SRP Ultra est une plateforme complète Zero-Trust pour un registre national bancaire, conçue selon les standards:
- **ANSSI** (Agence Nationale de la Sécurité des Systèmes d'Information)
- **NIS2** (Network and Information Security Directive)
- **DORA** (Digital Operational Resilience Act)

## Stack Technique

| Composant | Langage | Technology |
|-----------|---------|-------------|
| Moteur CRUE | Rust | Memory-safe, performant |
| DSL Compilateur | Rust | Parser + Compilateur bytecode |
| Cryptographie | Rust + HSM | SHA-256/512, Ed25519, RSA-PSS |
| API Gateway | Rust (Axum) | Microservices async |
| Logging Immuable | Rust | Merkle Tree, hash chainé |
| Infrastructure | Terraform | Kubernetes hardening |

## Architecture du Projet

```
├── Cargo.toml                 # Workspace principal
├── crates/
│   ├── crue-dsl/             # DSL Parser & Compilateur
│   │   ├── src/
│   │   │   ├── lib.rs       # Types principaux
│   │   │   ├── ast.rs       # Abstract Syntax Tree
│   │   │   ├── parser.rs    # Parser DSL
│   │   │   ├── compiler.rs  # Compilateur bytecode
│   │   │   └── signature.rs # Signature RSA-PSS
│   │
│   ├── crypto-core/          # Primitives cryptographiques
│   │   ├── src/
│   │   │   ├── hash.rs      # SHA-256, SHA-512, BLAKE3
│   │   │   ├── signature.rs # Ed25519, RSA-PSS
│   │   │   ├── merkle.rs    # Arbre de Merkle
│   │   │   └── hsm.rs       # Intégration HSM
│   │
│   ├── crue-engine/          # Moteur de règles
│   │   ├── src/
│   │   │   ├── engine.rs     # Moteur principal
│   │   │   ├── context.rs   # Contexte d'évaluation
│   │   │   ├── decision.rs  # Types de décision
│   │   │   └── rules.rs     # Registre des règles
│   │
│   └── immutable-logging/    # Logging immuable
│       ├── src/
│       │   ├── log_entry.rs # Structure des entrées
│       │   ├── chain.rs     # Chaînage hash
│       │   ├── merkle_service.rs # Merkle horaire
│       │   └── publication.rs    # Publication quotidienne
│
├── services/
│   └── api-service/          # API Gateway Axum
│       ├── src/
│       │   ├── main.rs      # Point d'entrée
│       │   ├── handlers.rs  # Handlers API
│       │   ├── models.rs    # Modèles request/response
│       │   ├── middleware.rs# Middleware
│       │   └── error.rs     # Types d'erreur
│       └── Dockerfile       # Image conteneur
│
├── charts/                   # Helm charts
│   └── rsrp-api/
│       ├── Chart.yaml
│       └── values.yaml
│
└── terraform/                # Infrastructure as Code
    └── main.tf              # Configuration AWS EKS
```

## Règles CRUE Implémentées

| ID | Nom | Description | Action |
|----|-----|-------------|--------|
| CRUE_001 | VOLUME_MAX | Max 50 requêtes/heure | BLOCK |
| CRUE_002 | JUSTIFICATION_OBLIG | Justification requise | BLOCK |
| CRUE_003 | EXPORT_INTERDIT | Pas d'export bulk | BLOCK |
| CRUE_007 | TEMPS_REQUETE | Max 10 secondes | WARN |

## Compilation et Déploiement

### Build

```bash
# Compiler le workspace
cargo build --release

# Compiler un crate spécifique
cargo build -p crue-engine --release
```

### Production Build (Hardened)

```bash
# Build sécurisé avec optimisations et reproducibilité
RUSTFLAGS="-C target-cpu=native -C link-arg=-s" \
cargo build --release --locked

# Strip des symbols (si pas fait via link-arg)
strip target/release/api-service
```

> **Security Notes:**
> - `--locked` ensures Cargo.lock is not modified (reproducible builds)
> - `-C target-cpu=native` enables CPU-specific optimizations
> - `-C link-arg=-s` strips debug symbols for smaller binary

### Docker

```bash
# Build l'image
docker build -t rsrp/api-service:1.0.0 -f services/api-service/Dockerfile .

# Runner le conteneur
docker run -p 8080:8080 rsrp/api-service:1.0.0
```

### Kubernetes

```bash
# Déployer avec Helm
helm install rsrp-api charts/rsrp-api -n rsrp
```

### Terraform

```bash
# Initialiser Terraform
terraform init

# Planifier
terraform plan

# Appliquer
terraform apply
```

## API Endpoints

| Méthode | Chemin | Description |
|---------|--------|-------------|
| GET | `/health` | Health check |
| GET | `/ready` | Readiness check |
| GET/POST | `/api/v1/validate` | Valider accès |
| GET | `/api/v1/audit/chain/verify` | Vérifier chaîne |
| GET | `/api/v1/audit/daily/{date}/root` | Root quotidien |
| GET | `/metrics` | Métriques Prometheus |

## Sécurité

### Principes Zero-Trust

1. **Jamais fiables, toujours vérifier** - Chaque requête est validée
2. **M principe du moindre privilège** - Accès minimal requis
3. **Assume breach** - Détection d'intrusion permanente
4. **Vérifier explicitement** - Source, destination, données

### Cryptographie

- **HSM**: Thales Luna (PKCS#11)
- **Algorithmes**: SHA-256/SHA-512, Ed25519, RSA-PSS 4096
- **PKI**: Interne souveraine avec publication quotidienne

### Journalisation

- **Immuable**: WORM, hash chainé SHA-256
- **Merkle Tree**: Racine horaire publiée
- **Publication**: Journal Officiel + Blockchain consortium
- **Rétention**: 10 ans (conformité RGPD)

## Tests

```bash
# Tests unitaires
cargo test

# Tests d'intégration
cargo test --test '*'

# Tests de sécurité
cargo audit
cargo clippy
```

## Conformité

- ✅ **ANSSI**: Recommandations pour systèmes critiques
- ✅ **NIS2**: Mesures de cybersécurité
- ✅ **DORA**: Résilience numérique
- ✅ **RGPD**: Protection des données

## Licence

EUPL-1.2 (European Union Public License)
