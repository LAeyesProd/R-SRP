# rsrp-security-core

Security primitives for deterministic proof systems.

Crates.io package: `rsrp-security-core`  
Rust import path: `crypto_core`

## Quick Start

```rust
use crypto_core::hash::{hex_encode, sha256};
use crypto_core::signature::Ed25519KeyPair;

let digest = sha256(b"hello");
assert_eq!(digest.len(), 32);
let hex = hex_encode(&digest);
assert_eq!(hex.len(), 64);

let kp = Ed25519KeyPair::generate().expect("key generation");
let sig = kp.sign(b"hello");
assert!(kp.verify(b"hello", &sig));
```

## Scope

- Hashing: SHA-256, SHA-512, BLAKE3
- Ed25519 signing/verification
- Merkle helpers
- HSM abstraction hooks (placeholder/extension points)

