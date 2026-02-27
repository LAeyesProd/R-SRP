# Merkle Security Model

## Scope
This document defines the integrity model for `rsrp-immutable-ledger` Merkle roots and proofs.

## Domain Separation
- Leaf hash: `H(0x00 || canonical_entry_bytes)`
- Internal node hash: `H(0x01 || left_hash || right_hash)`
- Chain-proof leaf hash: `H(0x02 || chain_entry_hash_bytes)`
- Chain-proof node hash: `H(0x03 || left_hash || right_hash)`

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

## Odd-Leaf Handling
- For odd-size levels, the last node is duplicated (`right = left`) before hashing the parent.
- This is a deliberate, deterministic rule used in:
  - `crates/immutable-logging/src/chain.rs` (compact chain proof tree),
  - `crates/immutable-logging/src/publication.rs` (daily publication Merkle aggregation).
- Security implication:
  - deterministic inclusion proof remains valid and verifiable,
  - small odd trees have structural duplication on the last branch, which is acceptable with domain-separated hashing and collision-resistant digest assumptions.

## Test Coverage
- `test_merkle_proof_roundtrip`
- `test_leaf_and_node_hash_domain_separation`
- `test_chain_proof_is_compact_logarithmic`

These tests validate proof correctness and explicit leaf/node separation.
