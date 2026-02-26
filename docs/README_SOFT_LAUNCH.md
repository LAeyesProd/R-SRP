# Rsrp.ProofEngine

Deterministic Proof Engine for Rust

---

## Install (Rust)

```bash
# Add to Cargo.toml
cargo add crue-engine
cargo add crue-dsl
```

Or in `Cargo.toml`:

```toml
[dependencies]
crue-engine = "1.0"
crue-dsl = "1.0"
```

## Quick Start

```csharp
using Rsrp.ProofEngine;

var engine = new ProofEngine();
var decision = engine.Evaluate(policy, input);
var proof = decision.GenerateProof();

Console.WriteLine(proof.Verify() ? "Valid" : "Invalid");
```

## Features

- Deterministic rule evaluation
- Cryptographic proof generation
- SHA-256 / BLAKE3 hashing
- Ed25519 signatures

## License

Apache 2.0

---

Rsrp Systems
