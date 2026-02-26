# RSRP Immutable Ledger (Repository Status)

Cryptographically secured append-only audit trail for critical applications.

This document describes the current implementation state in this repository (Rust workspace), and separates shipped features from roadmap items.

Publisher: Rsrp Systems  
Author: Aymeric Le Cloitre-Maternat (ALM)

## Status

- `Implemented`: append-only chain hashing, Merkle proofs, daily publication structures
- `Implemented (placeholder/mock)`: TSA timestamp hook (`mock://` only)
- `Partial`: publication signatures and audit API endpoints (structures exist, some handlers still return placeholders)
- `Not implemented in this repo`: production RFC 3161 TSA client, .NET package/API shown in older product-oriented examples

## Scope (Current Repo)

The Rust implementation is provided by:

- Crate package: `rsrp-immutable-ledger`
- Rust import path: `immutable_logging`

Related crates:

- `rsrp-security-core` (hashing, signatures, Merkle utilities)
- `rsrp-proof-engine` (CRUE decision engine)
- `api-service` (HTTP service layer, still partially placeholder for audit endpoints)

## Implemented Features

### Hash Chaining

- Append-only log entries chained by hash
- Tamper evidence through chain verification
- Unit tests covering append and chain proof validation

### Merkle Trees

- Merkle root generation for grouped entries
- Inclusion proof generation and verification
- Hourly/daily publication support structures

### Daily Publication

- Daily publication object with root hash, entry count, chaining to previous day root
- Signature field support
- TSA timestamp metadata field support

### TSA Timestamp Hook (Mock Only)

- `PublicationService::add_tsa_timestamp(...)` is currently a mock/test hook
- Only `mock://...` URLs are accepted
- Real RFC 3161 network integration is not implemented yet

## Quick Start (Rust)

```rust
use immutable_logging::{ImmutableLog, log_entry::{EventType, LogEntry}};

# tokio_test::block_on(async {
let log = ImmutableLog::new();

let entry = LogEntry::new(
    EventType::AccountQuery,
    "agent-001".to_string(),
    "org-001".to_string(),
);

let appended = log.append(entry).await.expect("append");
let proof = log.get_chain_proof(&appended.id).await;

assert!(log.verify().await.expect("verify"));
assert!(proof.is_some());
# });
```

## Important Limitations (Current State)

### TSA / Time Proof

- Docs/specs may mention RFC 3161 TSA and third-party proof of existence
- Current code implements a mock provider for local testing only
- Do not claim external timestamp non-repudiation for production audits yet

### Audit API Endpoints

- Some audit endpoints in `api-service` return placeholder values
- They are useful for integration scaffolding, not final audit evidence workflows

### Product Docs vs Repository Docs

- Older docs in `docs/` may describe a productized `.NET` package (`Rsrp.ImmutableLedger`)
- This repository currently ships the Rust implementation and Rust crates

## Roadmap (Planned / Not Yet Shipped)

- Real RFC 3161 TSA client integration (request/response parsing, token validation)
- Canonical JSON export format with deterministic serialization guarantees
- Compressed export options (e.g., gzip)
- External publication backends (WORM/object storage, transparency-style publication)
- .NET wrapper/package documentation aligned to an actual released artifact

## Verification

Repository-level verification command:

```bash
cargo test --workspace
```

## Security Positioning (Documentation Hygiene)

This README intentionally distinguishes:

- `implemented` features
- `placeholder/mock` features
- `planned` features

This avoids over-claiming capabilities in audit or compliance contexts.

## License

See repository root `Cargo.toml` and project licensing docs for the effective license metadata used by the Rust workspace.

