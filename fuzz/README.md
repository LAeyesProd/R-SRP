# RSRP Fuzz Targets

This directory contains minimal `cargo-fuzz` targets for pre-1.0 hardening:

- `dsl_parser`: fuzzes `crue_dsl::parser::parse` with UTF-8 input
- `proof_envelope_decode`: fuzzes `ProofEnvelopeV1::from_canonical_bytes`
- `log_entry_deserialize`: fuzzes `serde_json` deserialization of `LogEntry`

Run examples:

```bash
cargo fuzz run dsl_parser
cargo fuzz run proof_envelope_decode
cargo fuzz run log_entry_deserialize
```
