# Rsrp

Deterministic Proof Engine for Rust

---

## Install (All-in-One)

```bash
# Add to your Cargo.toml
[dependencies]
crue-engine = "1.0"
immutable-logging = "1.0"
crypto-core = "1.0"
pqcrypto = "1.0"
```

Or use cargo add:

```bash
cargo add crue-engine
cargo add immutable-logging
cargo add crypto-core
cargo add pqcrypto
```

## Quick Start

```csharp
using Rsrp;

services.AddRsrp(options =>
{
    options.UseEd25519();
    options.EnableImmutableLedger();
});

var decision = engine.Evaluate(policy, input);
var proof = decision.GenerateProof();

Console.WriteLine(proof.Verify() ? "Valid" : "Invalid");
```

## Features

- **Deterministic rule evaluation** - Same input, same output
- **Cryptographic proof generation** - Verify every decision
- **Immutable audit ledger** - Tamper-evident logging
- **ASP.NET Core integration** - Middleware and DI helpers
- **SHA-256 / BLAKE3 hashing** - Fast, secure hashing
- **Ed25519 signatures** - Modern elliptic curve signatures
- **Post-quantum ready** - Hybrid classical/PQ available

## Packages

| Package | Description |
|---------|-------------|
| Rsrp.ProofEngine | Decision engine |
| Rsrp.ImmutableLedger | Audit ledger |
| Rsrp.Security.Core | Crypto primitives |
| Rsrp.AspNetCore | ASP.NET integration |

## Individual Installation

```bash
# Just the engine
dotnet add package Rsrp.ProofEngine

# Just the ledger
dotnet add package Rsrp.ImmutableLedger

# Just crypto
dotnet add package Rsrp.Security.Core

# Just ASP.NET
dotnet add package Rsrp.AspNetCore
```

## License

Apache 2.0

---

Rsrp Systems
