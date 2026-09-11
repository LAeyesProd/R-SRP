# rsrp-immutable-ledger

Append-only immutable audit logging with hash chaining, Merkle roots, and publication support.

Crates.io package: `rsrp-immutable-ledger`  
Rust import path: `immutable_logging`

## Quick Start

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

## Scope

- Tamper-evident chain hashing
- Merkle aggregation services
- Daily publication structures
- TSA timestamp integration hooks

## Real OpenSSL/TSA release checks

```sh
cargo test --locked -p rsrp-immutable-ledger --features tsa-http-client,tsa-cms-openssl
```

Run from the repository root with the OpenSSL CLI, development libraries, and
pkg-config installed. The `tsa_openssl` integration tests generate short-lived
local TSA certificates and real RFC3161 replies, then exercise trusted CMS
verification, tampered signatures, invalid/empty trust stores, and unrelated
roots. A loopback HTTP TSA signs the application's actual query and tests
successful retrieval plus HTTP errors, malformed DER, and TSA rejection.
No public TSA service or checked-in private key is needed; missing OpenSSL is a
test failure, not a skip.

CMS verification checks the timestamp-signing certificate purpose and chain.
The application still does **not** enforce RFC3161 message-imprint, nonce, or
policy binding during CMS verification, and retrieval does not automatically
verify the token. These tests are not evidence of full RFC3161 validation.
