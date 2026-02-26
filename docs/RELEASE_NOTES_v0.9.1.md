# Release Notes v0.9.1

Release date: 2026-02-26

This release focuses on audit ledger reliability, publication workflows, API integration, and TSA verification groundwork.

## Published crates (crates.io)

- `rsrp-security-core` `0.9.1`
- `rsrp-policy-dsl` `0.9.1`
- `rsrp-immutable-ledger` `0.9.1`
- `rsrp-pqcrypto` `0.9.1`
- `rsrp-proof-engine` `0.9.1`

## Highlights

- Workspace version bump to `0.9.1`
- `cargo test --workspace` passing on the audited workspace state
- Audit API endpoints now read/write real publication and chain data (not placeholders)
- Daily publication export supports canonical JSON and gzip
- Daily publication signing is wired into the API (`software-ed25519` and `softhsm` providers)
- Daily publication verification endpoint checks:
  - content root integrity (`hourly_roots` -> `root_hash`)
  - previous-day chain continuity
  - publication signature (when configured)
  - TSA metadata/token structural checks
  - optional CMS/PKCS#7 TSA verification backend (feature-gated)

## Audit / Ledger Changes

- Fixed Merkle proof path ordering and sibling selection
- Added `DailyPublication` helpers:
  - canonical JSON export
  - gzip export
  - deterministic filesystem/object basename
  - root hash recomputation and verification
- Filesystem publication backend added (`publish_to_filesystem`)
- TSA support expanded:
  - `mock://` test provider retained
  - experimental `http(s)` RFC3161 transport path (request/response token retrieval)
  - improved token inspection (base64/DER/time extraction)
  - optional CMS verification backend via OpenSSL feature

## API Service Changes

- `/api/v1/audit/chain/verify` now checks the real in-memory immutable chain
- `/api/v1/audit/daily/{date}/root` reads real publications from `AUDIT_PUBLICATIONS_DIR`
- `POST /api/v1/audit/daily/publish` creates and persists daily publications (`.json` + `.json.gz`)
- Validation endpoints append immutable audit log entries (best-effort)
- `GET /api/v1/audit/daily/{date}/verify` added:
  - root integrity verification
  - previous-day link verification
  - signature verification
  - TSA status reporting
  - CMS TSA verification attempt when trust store is configured

## Security / Operational Behavior

- `TLS_ENABLED=true` now fails fast instead of claiming TLS while serving HTTP
- Readiness probe reflects engine state (`rule_count > 0`)
- API publication signing providers:
  - `software-ed25519`
  - `softhsm`
  - `none`

## Features and Build Flags

### `rsrp-immutable-ledger`

- New optional feature: `tsa-cms-openssl`
  - Enables CMS/PKCS#7 TSA token signature verification using OpenSSL
  - If not enabled, API returns `cms-backend-unavailable` for CMS verification attempts

### `api-service`

- New local feature alias: `tsa-cms-openssl`
  - Forwards to `rsrp-immutable-ledger/tsa-cms-openssl`

Example:

```powershell
cargo run -p api-service --features tsa-cms-openssl
```

## Runtime Configuration (Audit/TSA)

- `AUDIT_PUBLICATIONS_DIR`
- `AUDIT_PUBLICATION_SIGNING_PROVIDER` = `software-ed25519 | softhsm | none`
- `AUDIT_PUBLICATION_SIGNING_SECRET` (required for `software-ed25519`)
- `AUDIT_PUBLICATION_SIGNING_KEY_ID`
- `AUDIT_PUBLICATION_HSM_SLOT` (SoftHSM path)
- `AUDIT_PUBLICATION_HSM_CONNECTION` (SoftHSM path)
- `AUDIT_PUBLICATION_HSM_LABEL_PREFIX` (SoftHSM path)
- `AUDIT_TSA_URL` (optional)
- `AUDIT_TSA_TRUST_STORE_PEM` (optional, used by `/verify` for CMS verification)

## Known Limitations

- Full RFC3161 semantic validation is not complete yet (message imprint / nonce / policy checks)
- CMS verification backend requires a working OpenSSL toolchain/config on the host
- API server TLS/mTLS listener integration is still pending (fail-fast behavior prevents false security)

## Tagging Note

If publication was done with `--allow-dirty`, create a commit first before tagging `v0.9.1`, otherwise the tag will not represent the exact published source state.

