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
- Clippy strict: `PASS` (`cargo clippy --workspace --all-targets -- -D warnings`)
- Security audit: `PASS` (`cargo audit` -> `0 vulnerabilities`)
- Policy `cargo deny`: `PASS` (`advisories ok, bans ok, licenses ok, sources ok`)
- ProofEnvelopeV1 vectors:
  - Python: `PASS`
  - TypeScript/Node: `PASS`

### OPEN / POINTS RESIDUELS
1. Dependance transitive unmaintained (`cargo audit`)
- `rustls-pemfile 2.2.0` remonte en warning `RUSTSEC-2025-0134` (via `axum-server`).
- Statut: `OPEN` (transitive; direct usages supprimes dans `api-service`).

2. OQS real-crypto non validable localement
- `cmake` absent
- `clang` absent
- `LIBCLANG_PATH` non configure
- `cargo check ... --features real-crypto` echoue (bindgen/libclang)
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

4. Durcissement crypto / supply-chain
- Suppression de la dependance `rsa` du workspace et de `rsrp-security-core`
- Chemin RSA-PSS legacy force en `disabled` explicite (erreur claire; plus de crypto operationnelle RSA)
- `Cargo.lock` regenere sans `rsa` (`RUSTSEC-2023-0071` elimine)

5. Remediation `rustls-pemfile` cote code applicatif
- Suppression des dependances directes `rustls-pemfile` + `pem` dans `services/api-service/Cargo.toml`
- Parsing PEM migre vers `rustls::pki_types::pem::PemObject` dans `services/api-service/src/tls.rs`

6. Qualite stricte workspace
- Corrections `clippy -D warnings` appliquees (`derive(Default)`, `is_multiple_of`, `div_ceil`, `len/is_empty`, `io::Error::other`, `large_enum_variant`, etc.)
- Resultat: clippy strict `PASS` sur tout le workspace

7. CI `real-crypto` Linux obligatoire
- Ajout d'un job dedie dans `.github/workflows/reproducible-build.yml`
- Install deps: `cmake`, `clang`, `llvm-dev`, `libclang-dev`
- Build gate: `cargo check -p rsrp-pqcrypto --release --no-default-features --features real-crypto`

8. SBOM signe
- Workflow remanie `.github/workflows/sbom.yml`
- Generation CycloneDX (`cargo-cyclonedx`)
- Archive + hash + signature keyless Cosign (OIDC)
- Verification de signature en CI
- Publication des artefacts signes (et assets release sur event `release`)

9. Threat model STRIDE formel
- Nouveau document: `docs/THREAT_MODEL_STRIDE.md`
- Contient: trust boundaries, assets, attack vectors STRIDE, abuse cases, mitigations, risques residuels

## Priorites avant audit externe
### P0 (bloquant audit)
1. Outiller machine CI/local pour `real-crypto`:
   - installer `cmake`
   - installer `clang/libclang`
   - configurer `LIBCLANG_PATH`
2. Documenter et suivre la sortie de `rustls-pemfile` transitive des dependances serveur (actuellement warning unmaintained, non vuln exploit connue).

### P1
1. Ajouter job Go interop et Terraform validate dans CI (ou documenter exclusion)
2. Reduire les warnings `cargo-deny` non bloquants (duplicates lockfile/allow-list non rencontree)
3. Finaliser verification operationnelle du workflow SBOM sur release publique (assets + verification externe)

## Verdict pre-audit
- Niveau actuel: **pre-audit technique solide** (tests + clippy strict + audit vuln + deny passent, CI `real-crypto` et SBOM signe en place, STRIDE formel documente).
- Bloquants restants pour audit externe: **validation `real-crypto` OQS** sur tous environnements cibles et resolution/suivi de la dependance transitive unmaintained `rustls-pemfile`.
