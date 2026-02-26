# rsrp-proof-engine

Deterministic proof engine for high-integrity Rust applications.

Crates.io package: `rsrp-proof-engine`  
Rust import path: `crue_engine`

## Quick Start

```rust
use crue_engine::engine::CrueEngine;
use crue_engine::{EvaluationRequest, decision::Decision};

let engine = CrueEngine::default();

let req = EvaluationRequest {
    request_id: "req-001".into(),
    agent_id: "agent-001".into(),
    agent_org: "org-001".into(),
    agent_level: "standard".into(),
    mission_id: None,
    mission_type: None,
    query_type: None,
    justification: None,
    export_format: None,
    result_limit: None,
    requests_last_hour: 0,
    requests_last_24h: 0,
    results_last_query: 0,
    account_department: None,
    allowed_departments: vec![],
    request_hour: 12,
    is_within_mission_hours: true,
};

let result = engine.evaluate(&req);
assert!(matches!(result.decision, Decision::Allow | Decision::Block | Decision::Warn));
```

## Scope

- Deterministic rule evaluation
- First-match rule execution model
- Strict-mode error handling
- CRUE DSL integration

