# RSRP Threat Model (STRIDE)
Date: `2026-02-27`  
Status: `Pre-1.0 Security Baseline`  
Scope: `Policy -> Decision -> Proof -> Ledger -> Verification`

## 1. System Scope and Assumptions
- In scope:
  - `rsrp-policy-dsl`
  - `rsrp-proof-engine`
  - `rsrp-security-core`
  - `rsrp-pqcrypto`
  - `rsrp-immutable-ledger`
  - `services/api-service`
- Out of scope:
  - Host kernel/hypervisor compromise
  - Enterprise IAM provisioning quality
  - Physical datacenter attacks
- Assumptions:
  - Keys are generated/stored in approved custody paths.
  - CI artifacts are produced from protected branches and reviewed code.
  - Audit storage is append-only and monitored.

## 2. Trust Boundaries
1. External client -> API boundary (untrusted to authenticated edge).
2. API -> deterministic engine boundary (validated request model only).
3. Engine -> crypto boundary (strict algorithm/key selection).
4. Engine -> ledger boundary (canonical bytes + hash-chained append).
5. Internal build/release -> public artifacts boundary (signed provenance/SBOM).

## 3. Security Assets
- Signing private keys (Ed25519, hybrid PQ where enabled).
- KEM secret material (classical + PQ shared secrets).
- Canonical proof bytes (`ProofEnvelopeV1`).
- Policy source, compiled bytecode, and policy hash bindings.
- Ledger entries, Merkle roots, chain proofs, publication signatures.
- CI release artifacts and SBOM integrity metadata.

## 4. STRIDE Analysis

### 4.1 Spoofing
- Threats:
  - Forged caller identity at API layer.
  - Forged signer identity in proof/publication metadata.
- Mitigations:
  - AuthN middleware + explicit request context extraction.
  - Signature verification on proof/publication payloads.
  - Key ID binding and algorithm tagging in envelopes.
- Residual risk:
  - Misconfigured key custody mapping outside protocol scope.

### 4.2 Tampering
- Threats:
  - Mutation of ledger content after append.
  - Policy/bytecode substitution with unchanged metadata.
  - Tampered KEM ciphertext parts (classical or PQ branch).
- Mitigations:
  - Immutable `LogEntry` builder and canonical content hash coverage.
  - `ProofBinding` verification with policy and bytecode hash recomputation.
  - Hybrid KEM decapsulation failure on tampered classical/PQ components.
  - Merkle proof generation and verification implemented.
- Residual risk:
  - Transitional legacy rule fallback path until full deprecation.

### 4.3 Repudiation
- Threats:
  - Denial of issued decision/proof by producer.
  - Dispute on publication integrity timeline.
- Mitigations:
  - Signed proof envelopes and deterministic canonical encoding.
  - Hash-chained ledger + chain proof verification.
  - Daily publication signatures and optional TSA token handling.
- Residual risk:
  - TSA trust policy maturity depends on deployment policy.

### 4.4 Information Disclosure
- Threats:
  - Secret key leakage via memory/object exposure.
  - Sensitive context leakage via logs or diagnostics.
- Mitigations:
  - Secret material encapsulation and zeroization in crypto paths.
  - No public exposure of hybrid private key fields.
  - Scoped logging and explicit audit field mapping.
- Residual risk:
  - External telemetry pipelines may leak if misconfigured.

### 4.5 Denial of Service
- Threats:
  - Expensive parse/eval payloads and malformed requests.
  - Build pipeline instability blocking release confidence.
- Mitigations:
  - Parser validation and typed rule IR in engine path.
  - CI gates: tests, clippy strict, audit, deny, reproducible builds.
  - Dedicated Linux `real-crypto` build job for OQS path validation.
- Residual risk:
  - Resource exhaustion still possible without runtime quotas/WAF upstream.

### 4.6 Elevation of Privilege
- Threats:
  - Bypass of compiled policy path via permissive fallback behavior.
  - Misuse of signing providers to mint unauthorized attestations.
- Mitigations:
  - VM-first compiled rule path active.
  - Signed envelopes bind runtime/version/backend identifiers.
  - Branch protections + required reviews + mandatory CI checks.
- Residual risk:
  - Legacy compatibility mode must be sunset on defined timeline.

## 5. Abuse Cases
1. Attacker submits syntactically valid but malicious policy update to bypass action semantics.
2. Insider attempts to append forged ledger entry with modified decision metadata.
3. Build agent compromise attempts to publish modified SBOM without valid signature.
4. Client replays old proof envelope with mismatched policy hash and context.
5. Adversary tampers one component of hybrid KEM ciphertext to force weak fallback.

## 6. Control Mapping (Implemented)
- Deterministic serialization + canonical test vectors: `ProofEnvelopeV1`.
- Cryptographic integrity:
  - Signature verification (Ed25519/hybrid paths).
  - Chain proof recomputation.
  - Merkle proof verification.
- Supply-chain controls:
  - `cargo audit`, `cargo deny`, strict `clippy`, workspace tests.
  - Signed SBOM artifacts (Cosign keyless/OIDC).
  - Reproducible build checks across runners.

## 7. Open Risks and Follow-ups
- OQS `real-crypto` runtime validation requires fully provisioned `cmake/clang/libclang` in all target CI environments.
- `rustls-pemfile` remains transitive via `axum-server`; track removal path and upstream migration timeline.
- Legacy fallback rule path should move to explicit deprecation/removal milestone before `v1.0`.

## 8. Review Cadence
- Re-review triggers:
  - Any crypto backend change.
  - Proof/ledger schema change.
  - CI signing/provenance workflow change.
  - External audit findings.
- Minimum periodicity: quarterly.
