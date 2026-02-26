# RSRP - Risk Secure Runtime Protocol
## A Deterministic, Policy-Driven, Quantum-Resilient Proof Stack

Version: `0.9.1`  
Status: `Pre-1.0 Research Architecture`  
Date: `2026-02-26`

## 1. Abstract

RSRP (Risk Secure Runtime Protocol) is a deterministic security runtime architecture designed to bind:

- policy evaluation,
- cryptographic proof materialization,
- immutable ledger append,
- and verification semantics

into a reproducible execution pipeline.

Unlike blockchain systems, RSRP does not implement distributed consensus.  
Unlike logging systems, RSRP does not only store events.  
Unlike policy engines, RSRP is intended to produce verifiable cryptographic evidence of decisions.

Target pipeline:

`Policy -> Decision -> Proof -> Ledger -> Verification`

Current `v0.9.1` assessment: the architecture direction is strong, but several components remain prototype-grade and require hardening before production adoption.

## 2. Design Goals

### 2.1 Determinism

For a fixed tuple `(P, I, S, K)`:

- `P`: policy set / rule bytecode
- `I`: request/input
- `S`: state/context
- `K`: cryptographic key material / verifier set

RSRP aims to guarantee reproducible decisions and proofs.

Determinism requirements:

- canonical serialization,
- explicit clock injection (not ambient wall clock),
- no hidden random paths in proof generation,
- versioned schemas for proof/ledger artifacts.

### 2.2 Cryptographic Resilience

RSRP separates classical primitives and post-quantum primitives:

- `rsrp-security-core`: hashes, signatures, Merkle helpers, HSM abstractions
- `rsrp-pqcrypto`: PQ and hybrid cryptographic APIs

Objective:

- long-term audit survivability,
- cryptographic provenance of decisions,
- verifiable tamper evidence.

### 2.3 Separation of Concerns

Intended crate boundaries:

| Layer | Responsibility |
|---|---|
| `rsrp-security-core` | Base crypto primitives & traits |
| `rsrp-pqcrypto` | Post-quantum / hybrid signatures and KEM |
| `rsrp-policy-dsl` | Policy syntax, parsing, compilation |
| `rsrp-proof-engine` | Deterministic evaluation and proof semantics |
| `rsrp-immutable-ledger` | Append-only audit chain and publication |

In `v0.9.1`, these boundaries exist conceptually but are not yet fully enforced in runtime composition.

## 3. Architectural Model

### 3.1 Logical Flow (Target)

```text
                +--------------------+
                |   Policy DSL       |
                +---------+----------+
                          |
                          v
                +--------------------+
                |  Proof Engine      |
                +---------+----------+
                          |
                          v
                +--------------------+
                | Immutable Ledger   |
                +---------+----------+
                          |
                          v
                +--------------------+
                | Verification Layer |
                +--------------------+
```

### 3.2 Dependency Direction (Target)

```text
security-core
      ^
pqcrypto
      ^
policy-dsl
      ^
proof-engine
      ^
immutable-ledger
```

Constraint:

- no cyclic dependencies,
- IO/network adapters must not leak into deterministic core evaluation.

### 3.3 Observed v0.9.1 Deviation

`rsrp-proof-engine` depends on `rsrp-policy-dsl` and `rsrp-security-core`, but evaluates built-in runtime rules rather than compiled DSL bytecode (`crates/crue-engine/Cargo.toml:33`, `crates/crue-engine/Cargo.toml:34`, `crates/crue-engine/src/rules.rs:144`).

## 4. Formal Execution Model

Let:

- `P` = policy
- `I` = input
- `S` = state
- `D` = decision
- `pi` = proof
- `L` = ledger

Define:

- `D = Eval(P, I, S)`
- `pi = Prove(P, I, S, D)`
- `L_n = Append(L_(n-1), Commit(D, pi))`
- `Verify(L_n) = true`

Where `Commit` is a deterministic cryptographic commitment over versioned canonical encodings.

Intended guarantee:

If:

- `Verify(L_n) = true`
- `VerifyProof(pi) = true`
- and policy/inputs/state hashes match recomputation

then `D` was derived from `(P, I, S)` under the specified runtime semantics.

Important `v0.9.1` caveat:

- this guarantee is **architectural**, not fully realized in code paths yet (notably PQ verification placeholders and simplified chain proof verification).

## 5. Cryptographic Layer

### 5.1 Requirements

RSRP cryptographic layer should provide:

- collision-resistant hash commitments,
- deterministic hashing of canonical data,
- signature verification (classical and/or PQ),
- Merkle inclusion/consistency proofs,
- explicit key provenance (key IDs, algorithms, validity).

### 5.2 Security Assumptions

- hash collision resistance of selected hash function,
- EUF-CMA security of signature scheme(s),
- canonical serialization stability,
- trustworthy key custody (HSM/KMS or equivalent),
- runtime integrity of host environment (outside protocol scope).

### 5.3 v0.9.1 Audit Notes (Critical)

`rsrp-pqcrypto` exposes prototype PQ APIs with placeholder behavior:

- Dilithium verify returns `Ok(true)` (`crates/pqcrypto/src/signature.rs:157`, `crates/pqcrypto/src/signature.rs:183`)
- hybrid verification effectively depends on quantum branch only (`crates/pqcrypto/src/hybrid.rs:236`, `crates/pqcrypto/src/hybrid.rs:247`)

This is acceptable for research prototyping if explicitly marked `mock`, but not as production cryptography.

Workspace post-audit note (implementation progress):

- explicit `mock-crypto` / `real-crypto` feature split and provider abstraction are now implemented
- placeholder `Ok(true)` verification paths were removed from the mock signature flow
- hybrid verification now supports a public-key-only verification path (`HybridPublicKey`)
- `real-crypto` OQS path is wired, but local validation on this workstation remains environment-blocked (`libclang` toolchain setup)

## 6. Threat Model

### 6.1 Adversary Capabilities

Adversary may:

- replay requests/inputs,
- attempt policy bypass,
- tamper with stored logs,
- inject forged proof artifacts,
- exploit schema mismatches,
- trigger runtime error paths for denial/blocking behavior.

### 6.2 Non-Goals

RSRP does not aim to:

- provide distributed consensus,
- secure a fully compromised host kernel/hypervisor,
- replace enterprise key custody systems,
- solve identity proofing or endpoint trust by itself.

## 7. Policy DSL Formalization

### 7.1 Requirements

Policy language should be:

- total (well-defined semantics for all inputs),
- statically validated,
- serializable and hashable,
- deterministic in parsing/compilation,
- versioned with compatibility policy.

Conceptual structure:

```rust
Policy {
    conditions: Vec<Clause>,
    effects: Vec<Action>,
    version: u32,
}
```

Policy hash must be an input to proof materialization.

### 7.2 v0.9.1 DSL Status

Present:

- AST
- parser
- bytecode compiler (partial)
- signature abstraction

Gaps:

- parser action coverage incomplete (`THEN` mostly `BLOCK`) (`crates/crue-dsl/src/parser.rs:407`)
- bytecode compilation focuses on `WHEN`, not complete action semantics (`crates/crue-dsl/src/compiler.rs:66`)
- signature path uses inconsistent sign/verify placeholder mechanisms (`crates/crue-dsl/src/signature.rs:53`, `crates/crue-dsl/src/signature.rs:86`)

Workspace post-audit note (implementation progress):

- `rsrp-policy-dsl` compiler now emits explicit `THEN` action bytecode (`action_instructions`) alongside condition bytecode
- parser coverage limitations still apply for some `THEN` syntactic variants; engine keeps compatibility behavior

## 8. Immutable Ledger Model

### 8.1 Target Properties

Ledger entries must be:

- append-only,
- hash-chained,
- canonicalized,
- non-mutable after commit,
- optionally checkpointed via Merkle roots and publication anchors.

Formal chain:

- `H_n = Hash(H_(n-1) || Entry_n_canonical)`

Tampering with any prior entry invalidates all descendants.

### 8.2 v0.9.1 Ledger Status

Strengths:

- append path exists
- chain hash maintained
- hourly Merkle roots and daily publication structure present
- TSA integration path scaffolded

Critical gaps:

- `LogEntry` fields are publicly mutable and content hash coverage is partial (`crates/immutable-logging/src/log_entry.rs:66`, `crates/immutable-logging/src/log_entry.rs:150`, `crates/immutable-logging/src/log_entry.rs:168`)
- `verify_chain_proof` is non-cryptographic (`crates/immutable-logging/src/chain.rs:158`)
- `MerkleService::build_proof_path` returns empty proof path placeholder (`crates/immutable-logging/src/merkle_service.rs:164`, `crates/immutable-logging/src/merkle_service.rs:166`)

Workspace post-audit note (implementation progress):

- these three gaps have been addressed in the workspace (immutable `LogEntry`, cryptographic chain proof recomputation, Merkle proof generation/verification)
- this section remains the historical `v0.9.1` snapshot assessment

## 9. Proof Engine Semantics

### 9.1 Intended Proof Content

A proof object should minimally bind:

- `policy_hash`
- `input_hash`
- `state_hash`
- `decision`
- `runtime_version`
- `signature`

Example conceptual form:

```rust
Proof {
    policy_hash,
    input_hash,
    state_hash,
    decision,
    signature,
}
```

Verification recomputes all hashes and validates signature under declared algorithm and key identity.

### 9.2 v0.9.1 Engine Status

`rsrp-proof-engine` currently operates as a deterministic rule evaluator with built-in rules and structured outputs, but it is not yet a full proof VM linked to compiled DSL bytecode (`crates/crue-engine/src/engine.rs:30`, `crates/crue-engine/src/rules.rs:144`).

Observed correctness risk:

- strict mode defaults to block-on-error (`crates/crue-engine/src/engine.rs:20`, `crates/crue-engine/src/engine.rs:78`)
- built-in rule type assumptions can mismatch context field types (e.g. `request.export_format`) (`crates/crue-engine/src/rules.rs:201`, `crates/crue-engine/src/context.rs:43`)

Workspace post-audit note (implementation progress):

- compiled DSL path is now active in the engine (`compiled rules -> VM`) with legacy fallback preserved
- proof binding and signed proof envelopes (Ed25519 bootstrap + feature-gated PQ/hybrid) are implemented
- canonical `ProofEnvelopeV1` attestation schema is now implemented (Ed25519 + feature-gated hybrid variants)
- VM uses explicit instructions (`EmitDecision`, jumps) and precompiled match programs; compiled actions are executed via a deterministic action VM
- legacy built-in rule risks remain relevant until the legacy path is deprecated or fully hardened

## 10. Deterministic Serialization Requirement

All proof- and ledger-relevant structures must use canonical serialization with:

- explicit field ordering (or canonical encoding format),
- version tags,
- no floating-point ambiguity,
- no locale-dependent formatting,
- no ambient timestamps injected during parsing/evaluation.

`v0.9.1` note:

`DailyPublication` deterministic JSON relies on `serde_json::to_vec(self)` and struct field order (`crates/immutable-logging/src/publication.rs:31`, `crates/immutable-logging/src/publication.rs:33`). This is useful, but v1.0 should formalize a canonical encoding contract independent of incidental struct layout.

## 11. Performance Considerations

Target asymptotics:

- append: `O(1)` amortized for hash chain
- Merkle proof verification: `O(log n)`
- signature verification: bounded by selected classical/PQ algorithm

Pre-v1.0 requirements:

- benchmark suites for append/eval/prove/verify,
- proof size measurements,
- latency variance analysis under load,
- serialization overhead baselines.

## 12. Comparison Matrix

| Feature | RSRP | Blockchain | OPA |
|---|---:|---:|---:|
| Consensus | No | Yes | No |
| Deterministic proof pipeline | Yes (target) | Partial | No |
| PQ crypto readiness | Yes (architecture) | Rare | No |
| Compliance traceability | Yes | Indirect | Partial |
| Modular crate stack | Yes | Often heavy | Partial |

Interpretation:

- RSRP is not a consensus network,
- RSRP is a verifiable policy-decision runtime substrate.

## 13. Production Readiness Gaps (v0.9.1)

Before `v1.0`, required:

- API freeze and semver policy
- explicit mock vs production crypto backends
- deterministic serialization specification
- error taxonomy normalization
- fuzzing (DSL parser, proof decoders, ledger codecs)
- property tests (chain invariants, proof invariants)
- benchmark publication
- threat model publication
- unsafe code audit (currently no `unsafe` blocks observed in audited crates)
- external crypto review for PQ and signature paths

Workspace post-audit note (implementation progress):

- several items above are now partially or fully implemented in code (mock/prod backend split, typed IR, chain proof verification, compiled DSL path)
- benchmark publication, fuzzing campaign, and security review package remain outstanding
- formal proof schema publication has started via a canonical `ProofEnvelopeV1` specification draft (`docs/PROOF_ENVELOPE_V1_SPEC.md`)

## 14. Strategic Positioning

RSRP is best positioned as:

- deterministic compliance runtime
- quantum-ready audit/proof substrate
- policy decision attestation layer
- CRUE-integrated security execution substrate
- financial risk / regulated workflow proof layer

It is especially valuable where organizations need:

- explainable decisions,
- tamper evidence,
- reproducible verification,
- cryptographic retention-grade evidence.

## 15. Conclusion

RSRP defines a strong architecture pattern:

- deterministic execution
- policy-driven control
- cryptographic proof binding
- immutable audit traceability

At `v0.9.1`, the suite is a promising research/prototype stack, not yet a production security platform. The path to credibility is clear:

- separate mocks from real cryptography,
- stabilize schemas and APIs,
- enforce determinism contracts,
- harden ledger proof verification,
- integrate DSL bytecode into proof-engine execution,
- publish test/benchmark/security evidence.

RSRP is not a blockchain.  
RSRP is not only a policy engine.  
RSRP is a verification substrate.

## Appendix A - v0.9.1 Crate Mapping (Published vs Internal Module Names)

| Published crate | Internal lib name |
|---|---|
| `rsrp-policy-dsl` | `crue_dsl` |
| `rsrp-proof-engine` | `crue_engine` |
| `rsrp-security-core` | `crypto_core` |
| `rsrp-immutable-ledger` | `immutable_logging` |
| `rsrp-pqcrypto` | `pqcrypto` |

## Appendix B - Research-to-Production Transition Checklist (Condensed)

- [ ] Real PQ backend (`oqs`/validated provider) behind explicit feature flags
- [ ] Canonical proof schema v1
- [ ] Immutable `LogEntry` + full-field hash coverage
- [ ] Cryptographic `ChainProof` verification
- [ ] Typed rule IR (no stringly operators/actions)
- [ ] DSL compiler-to-engine integration
- [ ] Security review package (threat model, SBOM, vuln policy)

## Appendix C - Post-v0.9.1 Workspace Progress Delta (2026-02-26)

This appendix records implementation progress applied in the workspace after the `v0.9.1` audit snapshot.
It does not change the historical assessment above.

### Implemented (workspace hardening/progress)

- `rsrp-pqcrypto`: explicit `mock-crypto` / `real-crypto` feature split with release guardrails
- `rsrp-pqcrypto`: provider abstractions for signatures and KEM; OQS-backed `real-crypto` path scaffolded and wired
- `rsrp-immutable-ledger`: immutable `LogEntry` builder + canonical hash coverage + cryptographic chain proof recomputation
- `rsrp-immutable-ledger`: Merkle proof path generation/verification implemented
- `rsrp-proof-engine`: compiled DSL path integrated (`compiled rules -> VM`)
- `rsrp-proof-engine`: strict `ProofBinding` (bytecode hash, runtime version, backend ID, serialization version)
- `rsrp-proof-engine`: signed proof envelopes (Ed25519 bootstrap and PQ/hybrid feature-gated envelope)
- `rsrp-proof-engine`: canonical `ProofEnvelopeV1` (Ed25519 + feature-gated hybrid attestation APIs)
- `rsrp-proof-engine`: explicit VM instructions with `EmitDecision` and precompiled match programs
- `rsrp-proof-engine`: compiled action execution moved to explicit `ActionVm` instruction program
- `rsrp-proof-engine`: `ProofBinding` now carries explicit `policy_hash`
- `rsrp-pqcrypto`: hybrid verification now supports public-key-only verification (`HybridPublicKey`)

### Still pending / not production-complete

- OQS `real-crypto` runtime verification on this workstation (local build blocked by missing LLVM/Clang/libclang setup)
- parser coverage completion for all `THEN` variants (compiler emits action bytecode, parser still partially limits syntax forms)
- benchmark publication / fuzzing / external crypto review

### Updated status of Appendix B items (workspace progress only)

- `[~]` Real PQ backend behind feature flags: wired and implemented, but local OQS build validation is environment-blocked here
- `[~]` Canonical proof schema v1: canonical `ProofEnvelopeV1` implemented and documented; stabilization/review pending
- `[x]` Immutable `LogEntry` + full-field hash coverage (implemented in workspace)
- `[x]` Cryptographic `ChainProof` verification (implemented in workspace)
- `[x]` Typed rule IR (operators/actions; action VM path implemented in engine)
- `[x]` DSL compiler-to-engine integration (condition + `THEN` action bytecode emitted; parser coverage still partial for some forms)
- `[ ]` Security review package (not yet assembled)
