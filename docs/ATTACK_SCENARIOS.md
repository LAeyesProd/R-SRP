# R-SRP Formal Attack Scenarios

Version: 0.9.8
Date: 2026-02-27

## Scenario AS-01: Hybrid Signature Forgery Attempt

Goal:
- Produce a valid decision proof with only one valid signature component.

Preconditions:
- Attacker can modify proof envelope payload.
- Attacker has at most one private key class (classical or PQ).

Attack steps:
1. Replace payload while preserving only Ed25519 signature.
2. Replace payload while preserving only ML-DSA signature.
3. Attempt crafted dual-forgery payload.

Expected control behavior:
- Verification rejects if either signature component fails.

Evidence:
- Hybrid verification tests in `crates/pqcrypto`.
- Production profile with hybrid requirement enabled.

## Scenario AS-02: Temporal RBAC Bypass

Goal:
- Execute restricted request outside mission schedule.

Preconditions:
- Request uses valid identity but invalid mission time window.

Attack steps:
1. Submit request outside scheduled window.
2. Submit request with missing mission schedule data.
3. Replay previously accepted request at invalid time.

Expected control behavior:
- Fail-closed denial for out-of-window or missing schedule data.

Evidence:
- Mission schedule validation and temporal authorization tests.

## Scenario AS-03: Merkle/Log Manipulation

Goal:
- Modify audit entry while preserving a valid-looking proof.

Preconditions:
- Attacker can edit stored log data or proof fields.

Attack steps:
1. Attempt second preimage with leaf/node ambiguity.
2. Tamper compact chain proof path sibling hash.
3. Tamper target entry hash.

Expected control behavior:
- Verification fails due to domain-separated hashing and proof mismatch.

Evidence:
- `H(0x00 || data)` leaves and `H(0x01 || left || right)` internal nodes.
- Compact proof tamper tests in `crates/immutable-logging/src/chain.rs`.

## Scenario AS-04: Replay/Continuity Attack

Goal:
- Reuse stale proof against current chain state.

Preconditions:
- Attacker has previously valid proof payload.

Attack steps:
1. Replay stale proof after additional log entries.
2. Claim stale chain head as current.

Expected control behavior:
- Current head comparison or root continuity checks reject stale evidence.

Evidence:
- Chain head hash binding in compact chain proof.
- Operational requirement to validate expected head/root at verifier boundary.

## Scenario AS-05: Key Extraction Window

Goal:
- Recover private key bytes from process memory after lifecycle end.

Preconditions:
- Attacker can inspect process memory dumps.

Attack steps:
1. Trigger signing operations.
2. Force object drop.
3. Scan memory snapshots for key remnants.

Expected control behavior:
- Key bytes are zeroized on drop and not retained in logs/errors.

Evidence:
- Zeroization controls in crypto crates.
- Memory-safety and lifecycle policy documentation.

## Scenario AS-06: Supply-Chain Substitution

Goal:
- Introduce malicious dependency or unsigned artifact.

Preconditions:
- Attacker can influence dependency source or artifact distribution path.

Attack steps:
1. Introduce dependency drift outside lockfile.
2. Inject unsigned artifact into release path.
3. Use untrusted registry/git source.

Expected control behavior:
- CI fails on lockfile/audit/deny/source policy violations.
- Signature/provenance checks block promotion.

Evidence:
- `deny.toml` source and policy gates.
- CI workflow `production-gate.yml` plus SBOM/signing workflows.
