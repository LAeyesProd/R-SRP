# RSRP Pre-Audit Automatique
Date: `2026-02-27`  
Contexte: verification technique avant audit externe.

## Scope execute
- `cargo fmt --all -- --check`
- `cargo test --workspace --all-targets`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo audit --json`
- `cargo deny check bans licenses sources advisories`
- `scripts/check-oqs-env.ps1`
- `cargo check -p rsrp-pqcrypto --release --no-default-features --features real-crypto`
- Interop vectors:
  - `python scripts/interop/verify_proof_envelope_v1_vectors.py ...`
  - `node scripts/interop/verify_proof_envelope_v1_vectors.ts ...`

## Resultats
### PASS
- Formatting: `PASS`
- Tests workspace: `PASS` (tous les tests unitaires/all-targets)
- ProofEnvelopeV1 vectors:
  - Python: `PASS`
  - TypeScript/Node: `PASS`

### FAIL / BLOQUANTS
1. Vulnerabilite crypto dependance (`cargo audit`)
- `RUSTSEC-2023-0071` sur `rsa 0.9.10` (Marvin attack timing side-channel)
- Statut: `OPEN` (pas de patch upstream disponible)

2. Dependances non maintenues (`cargo audit` / `cargo deny`)
- `rustls-pemfile` (1.0.4 et 2.2.0) marque unmaintained (`RUSTSEC-2025-0134`)
- Statut: `OPEN`

3. Qualite stricte (`clippy -D warnings`)
- Echec sur plusieurs crates (derive defaults, `is_multiple_of`, `div_ceil`, etc.)
- Statut: `OPEN`

4. OQS real-crypto non validable localement
- `cmake` absent
- `clang` absent
- `LIBCLANG_PATH` non configure
- `cargo check ... --features real-crypto` echoue (bindgen/libclang)
- Statut: `OPEN`

5. Policy `cargo deny`
- `rsrp-demo` sans license declaree (`unlicensed`)
- Licenses manquantes dans allow-list (`BSD-2-Clause`, `OpenSSL`)
- Wildcard path dependencies dans `rsrp-demo/Cargo.toml`
- Vuln/advisories remontees (cf points 1 et 2)
- Statut: `OPEN`

### LIMITATIONS ENVIRONNEMENT
- `go` non installe (checker interop Go non execute)
- `terraform` non installe (validation infra locale non execute)

## Correctifs appliques pendant ce pre-audit
1. `services/api-service/src/handlers.rs`
- Correction regression de compilation (imports/extractors axum)
- Alignement appels audit (`record_validation_decision_audit(...)`)
- Propagation effective `ip_address` / `user_agent` vers `AuditRequestContext`

2. `crates/crue-engine/Cargo.toml`
- Feature `pq-proof` alignee pour tests: `pqcrypto/mock-crypto` active avec `pq-proof`
- Effet: suppression des faux echecs tests hybrides sans backend selectionne

3. `deny.toml`
- Re-ecrit en schema compatible `cargo-deny` moderne (parse OK)
- Le check fonctionne et remonte maintenant des findings reelles

## Priorites avant audit externe
### P0 (bloquant audit)
1. Traiter la strategie `rsa` (suppression/isolement chemin exposable reseau ou mitigation forte documentee)
2. Remplacer/eliminer `rustls-pemfile` dans les chemins controlables
3. Outiller machine CI/local pour `real-crypto`:
   - installer `cmake`
   - installer `clang/libclang`
   - configurer `LIBCLANG_PATH`

### P1
1. Fermer `clippy -D warnings` sur workspace
2. Declarer license de `rsrp-demo` + supprimer wildcard deps
3. Etendre allow-list licenses si juridiquement valide (ex: `BSD-2-Clause`, `OpenSSL`)
4. Ajouter job Go interop et Terraform validate dans CI (ou documenter exclusion)

## Verdict pre-audit
- Niveau actuel: **techniquement stable pour tests unitaires**, mais **pas encore pret audit externe**.
- Raisons: vulnerabilite crypto dependance ouverte, advisories unmaintained, et absence de validation `real-crypto` sur environnement outille.
