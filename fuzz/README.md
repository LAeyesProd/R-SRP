# RSRP Fuzz Targets

This directory contains `cargo-fuzz` targets used for security hardening and audit evidence:

- `dsl_parser`: fuzzes `crue_dsl::parser::parse` with UTF-8 input
- `proof_envelope_decode`: fuzzes `ProofEnvelopeV1::from_canonical_bytes`
- `log_entry_deserialize`: fuzzes `serde_json` deserialization of `LogEntry`

## Quick run

```bash
cargo fuzz run dsl_parser
cargo fuzz run proof_envelope_decode
cargo fuzz run log_entry_deserialize
```

## Evidence run (audit-ready)

Use the campaign script to generate structured evidence (`duration`, `corpus`, `crash artifacts`) for all targets:

```bash
bash scripts/run_fuzz_evidence.sh
```

Default behavior:
- duration per target: `600` seconds
- evidence output: `fuzz/evidence/<run-id>/fuzz-evidence.json`
- crash behavior: fail the command if crashes are found

Environment knobs:
- `FUZZ_DURATION_SECONDS` (example: `172800` for a 48h campaign per target)
- `FUZZ_FAIL_ON_CRASH` (`1` or `0`)
- `FUZZ_TARGETS` (space-separated target list)
- `FUZZ_EVIDENCE_DIR` (custom evidence directory)

Example 48h campaign:

```bash
FUZZ_DURATION_SECONDS=172800 FUZZ_FAIL_ON_CRASH=1 bash scripts/run_fuzz_evidence.sh
```
