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

