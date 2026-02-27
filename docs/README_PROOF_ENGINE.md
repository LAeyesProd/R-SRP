# Rsrp.ProofEngine

Tamper-evident deterministic decision engine for critical .NET systems.

*Publisher: Rsrp Systems | Author: Aymeric Le Cloitre-Maternat (ALM)*

## Why RSRP?

Modern systems log events. Critical systems must prove decisions.

RSRP provides:
- **Deterministic rule execution** — Same input always produces same output
- **Cryptographic proof generation** — Every decision can be verified mathematically
- **Immutable decision chains** — Hash chaining prevents tampering
- **Post-quantum extensibility** — Hybrid signatures ready for PQ era

## Quick Start

```bash
dotnet add package Rsrp.ProofEngine
```

```csharp
// Configure the engine
services.AddRsrpProofEngine(options =>
{
    options.EnableImmutableLedger();
    options.UseEd25519();
});

// Evaluate a policy
var decision = await engine.EvaluateAsync(policy, input);

// Generate proof
var proof = decision.GenerateProof();

// Verify
bool valid = proof.Verify();
```

## Use Cases

- **Financial compliance** — Prove regulatory decisions were made correctly
- **AI decision traceability** — Cryptographically verify AI/ML decisions
- **Legal-grade audit trails** — Admissible in court, mathematically provable
- **Zero-trust logging** — Every access decision is verifiable
- **Critical infrastructure** — Nuclear, aviation, healthcare systems

## Features

### Deterministic Evaluation
- Policy DSL (CRUE) for declarative rules
- Versioned policies with hash verification
- No external dependencies at runtime
- Reproducible results

### Proof Generation
- SHA-256 / BLAKE3 hashing
- Ed25519 signatures
- Hybrid classical + post-quantum (optional)
- Canonical JSON export

### Integration
- ASP.NET Core middleware
- Dependency injection helpers
- Health checks
- OpenTelemetry tracing

## Security Model

| Component | Algorithm |
|-----------|-----------|
| Hashing | SHA-256 (default), BLAKE3 (fast) |
| Signing | Ed25519, RSA-PSS |
| PQ (optional) | Dilithium2, Falcon-512 |
| Chain | SHA-256 hash linking |

## API Reference

```csharp
// Core interfaces
IProofEngine       // Main engine
IDecisionResult    // Decision output
IProof             // Verifiable proof
IPolicy            // Policy definition
IEvaluationInput   // Context for evaluation
```

## Installation

```bash
# Latest stable
dotnet add package Rsrp.ProofEngine

# With post-quantum support
dotnet add package Rsrp.Security.Core
```

## Documentation

- [API Documentation](https://docs.rsrp.io)
- [Policy DSL Reference](https://docs.rsrp.io/dsl)
- [Security Model](https://docs.rsrp.io/security)

## Enterprise Features

Need HSM integration or mTLS mesh? Contact: **enterprise@rsrp.io**

Includes:
- PKCS#11 HSM support
- Thales Luna / AWS CloudHSM
- Vault integration
- 24/7 SLA support
- Certification assistance

## License

Apache 2.0 — Free for commercial and open-source use.

---

**RSRP** — Proof Infrastructure Layer for Critical Applications
