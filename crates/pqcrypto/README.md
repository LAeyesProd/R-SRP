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

## Real-backend release checks

From the repository root:

```sh
cargo test --locked --release -p rsrp-pqcrypto --no-default-features --features production
```

This executes the unit and integration tests, rather than only compiling them.
The production integration tests assert the `oqs` backend, ML-DSA-65 and
ML-KEM-768 identifiers/sizes, round trips, wrong-key and tamper rejection, and
rejection of non-frozen levels. Hybrid tests exercise both components with the
same frozen levels. `mock-crypto` must not be combined with `production`.
The debug-only mock tests are not evidence of real PQ cryptography.

Building the existing `oqs` dependency requires a C compiler, CMake, libclang
(for bindgen), pkg-config, and OpenSSL development libraries. Keep `RUST_LOG`
free of debug/trace directives and do not disable `RSRP_HYBRID_REQUIRED`.
