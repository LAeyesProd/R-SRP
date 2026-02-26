# rsrp-pqcrypto

Hybrid post-quantum cryptographic primitives (classical + PQ).

Crates.io package: `rsrp-pqcrypto`  
Rust import path: `pqcrypto`

## Quick Start

```rust
use pqcrypto::{Dilithium, DilithiumLevel};

let dilithium = Dilithium::new(DilithiumLevel::Dilithium2);
let (public_key, secret_key) = dilithium.generate_keypair().expect("keygen");

let msg = b"hello";
let sig = dilithium.sign(&secret_key, msg).expect("sign");
let ok = dilithium.verify(&public_key, msg, &sig).expect("verify");

assert!(ok);
```

## Scope

- Dilithium-like signature API (simulation scaffolding)
- Kyber-like KEM API (simulation scaffolding)
- Hybrid signature / hybrid KEM composition

## Note

Current implementations include placeholder/simulated logic in parts of the API and are not a drop-in replacement for audited production PQC libraries.

