# Merkle Security Model

## Scope
This document defines the integrity model for `rsrp-immutable-ledger` Merkle roots and proofs.

## Domain Separation
- Leaf hash: `H(0x00 || canonical_entry_bytes)`
- Internal node hash: `H(0x01 || left_hash || right_hash)`

The `0x00` and `0x01` prefixes are mandatory and prevent leaf/node ambiguity.

## Security Property
Given collision resistance and second-preimage resistance of SHA-256:
- It is infeasible to transform a leaf payload into an internal node pair that yields the same hash.
- Inclusion proofs are bound to a unique leaf path and root.

## Verification Rules
- Reject non-hex sibling hashes.
- Reject invalid `side` values (must be `left` or `right`).
- Recompute root iteratively from leaf hash and proof path.
- Accept only if recomputed root equals declared root.

## Test Coverage
- `test_merkle_proof_roundtrip`
- `test_leaf_and_node_hash_domain_separation`

These tests validate proof correctness and explicit leaf/node separation.
