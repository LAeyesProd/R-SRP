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

## HSM release checks and limitations

```sh
cargo test --locked -p rsrp-security-core --features hsm
bash scripts/test-pkcs11.sh
```

Run these from the repository root. The Rust tests cover the application's
**in-memory Ed25519 simulation**, including opt-in, production rejection,
unsupported hardware backends, tampering, wrong keys, and closed sessions.
`SoftHsm` is not the SoftHSM2 PKCS#11 module.

The shell check separately generates an RSA key and signs/verifies through the
**actual external SoftHSM2 module**, requiring explicit rejection of modified
messages and signatures. It requires Linux, `softhsm2`/`libsofthsm2`, OpenSC
(`pkcs11-tool`), OpenSSL, and Python 3. It creates an isolated token store under
`target/`, never uses an existing token store, and removes its test data on exit.
Missing tools fail the check rather than silently skipping it.

Neither check demonstrates an application PKCS#11 backend (none is implemented)
or integration with physical HSM hardware.
