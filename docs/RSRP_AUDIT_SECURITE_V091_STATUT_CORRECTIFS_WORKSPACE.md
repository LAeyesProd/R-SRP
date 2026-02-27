# Audit de Securite - RSRP v0.9.1
## Statut des Correctifs et Risques Residus (Workspace Post-Audit)

Version cible analysee: `v0.9.1` (snapshot historique)  
Etat du code verifie: `workspace local/post-correctifs` (apres hardening et integration preuve/ledger)  
Date: `2026-02-26`

## 1. Resume Executif

Le diagnostic initial (4 critiques + 4 elevees) est **correct pour la version historique `v0.9.1`**.

Le workspace actuel n'est plus dans l'etat "research prototype" sur les points structurants:

- separation explicite `mock-crypto` / `real-crypto`
- ledger immuable avec hash canonique et recomputation cryptographique
- verification Merkle fonctionnelle
- chemin moteur `compiled DSL -> VM`
- schema canonique `ProofEnvelopeV1`

Conclusion operative:

- **Ne pas deployer le snapshot `v0.9.1` historique tel quel**
- **Le workspace actuel est de niveau `Pre-1.0 stable cryptographic runtime`**
- Les blocages restants pour credibilite externe sont surtout:
  - validation OQS `real-crypto` sur environnement outille,
  - fuzzing / benchmarks,
  - revue crypto externe,
  - deprecation du fallback legacy du moteur

## 2. Scope et Methode

Ce rapport consolide:

- l'audit de securite historique `v0.9.1`,
- les correctifs implementes dans le workspace,
- les limites residuelles documentees dans le whitepaper et la spec `ProofEnvelopeV1`.

Sources techniques principales:

- `docs/RSRP_WHITEPAPER_ULTRA_TECHNICAL_v0.9.1.md`
- `docs/RSRP_SUITE_AUDIT_RESTRUCTURATION_0.9.1.md`
- `docs/PROOF_ENVELOPE_V1_SPEC.md`
- code `crates/pqcrypto`, `crates/immutable-logging`, `crates/crue-engine`, `crates/crue-dsl`

## 3. Matrice des Vulnerabilites (Historique vs Workspace)

### SEC-001 - Verification Dilithium factice (`Ok(true)`)

- Gravite historique `v0.9.1`: `CRITIQUE`
- Statut workspace actuel: `Traite (mock encadre / provider split)`

Constat historique:

- verification PQ retournee artificiellement `Ok(true)` dans le chemin prototype

Etat actuel:

- split `mock-crypto` / `real-crypto` implemente
- abstraction provider de signature en place
- verification hybride public-key-only disponible

References:

- `crates/pqcrypto/src/signature.rs`
- `crates/pqcrypto/src/hybrid.rs:88`
- `crates/pqcrypto/src/hybrid.rs:258`

Risque residuel:

- backend `real-crypto` OQS cable mais validation locale bloquee par environnement (`libclang`/LLVM)

### SEC-002 - Verification hybride incomplete (branche classique ignoree)

- Gravite historique `v0.9.1`: `CRITIQUE`
- Statut workspace actuel: `Traite (verification hybride renforcee)`

Etat actuel:

- `HybridPublicKey`
- `HybridVerifier::verify_public(...)`
- chemin `verify(...)` delegue vers public-only

References:

- `crates/pqcrypto/src/hybrid.rs:88`
- `crates/pqcrypto/src/hybrid.rs:251`
- `crates/pqcrypto/src/hybrid.rs:258`
- `crates/pqcrypto/src/hybrid.rs:445`

### SEC-003 - `LogEntry` mutable post-commit

- Gravite historique `v0.9.1`: `CRITIQUE`
- Statut workspace actuel: `Corrige`

Etat actuel:

- champs `LogEntry` encapsules
- builder immuable
- hash de contenu canonique
- attestation `ProofEnvelopeV1` embarquable dans l'entree ledger et incluse dans le hash

References:

- `crates/immutable-logging/src/log_entry.rs:98`
- `crates/immutable-logging/src/log_entry.rs:115`
- `crates/immutable-logging/src/log_entry.rs:178`
- `crates/immutable-logging/src/log_entry.rs:340`

### SEC-004 - `verify_chain_proof()` non cryptographique

- Gravite historique `v0.9.1`: `CRITIQUE`
- Statut workspace actuel: `Corrige`

Etat actuel:

- verification par recomputation cryptographique de chaine + checks associes

References:

- `crates/immutable-logging/src/chain.rs:141`
- `crates/immutable-logging/src/chain.rs:228`
- `crates/immutable-logging/src/chain.rs:231`

### SEC-005 - Merkle proof path vide / placeholder

- Gravite historique `v0.9.1`: `ELEVEE`
- Statut workspace actuel: `Corrige`

Etat actuel:

- generation de chemin de preuve Merkle implementee
- verification Merkle implementee

References:

- `crates/immutable-logging/src/merkle_service.rs:151`
- `crates/immutable-logging/src/merkle_service.rs:203`

### SEC-006 - Serialisation non canonique / dependance ordre des champs

- Gravite historique `v0.9.1`: `ELEVEE`
- Statut workspace actuel: `Partiellement traite`

Etat actuel:

- `ProofEnvelopeV1` introduit un encodage binaire canonique strict pour l'attestation
- test vectors publies (Rust + checkers interop Python/TS/Go)

References:

- `crates/crue-engine/src/proof.rs:99`
- `crates/crue-engine/src/proof.rs:400`
- `docs/PROOF_ENVELOPE_V1_SPEC.md`
- `docs/PROOF_ENVELOPE_V1_TEST_VECTORS.json`
- `scripts/interop/verify_proof_envelope_v1_vectors.py`

Risque residuel:

- la normalisation canonique cross-crate n'est pas encore uniformement formalisee au meme niveau que `ProofEnvelopeV1`

### SEC-007 - Parser DSL incomplet (`THEN`)

- Gravite historique `v0.9.1`: `ELEVEE`
- Statut workspace actuel: `Partiellement traite (structurellement de-risque)`

Etat actuel:

- compiler DSL emet `action_instructions` natifs pour `THEN`
- moteur execute via `ActionVm`
- le risque devient principalement ergonomique / couverture syntaxique parser

References:

- `crates/crue-dsl/src/compiler.rs:54`
- `crates/crue-dsl/src/compiler.rs:100`
- `crates/crue-engine/src/engine.rs`
- `crates/crue-engine/src/vm.rs`

### SEC-008 - Moteur built-in bypassant le chemin DSL compile

- Gravite historique `v0.9.1`: `ELEVEE`
- Statut workspace actuel: `Largement reduit (fallback legacy toujours present)`

Etat actuel:

- chemin compile `compiled rules -> VM` actif
- preuves `ProofBinding` / `ProofEnvelopeV1` sur chemin compile
- fallback legacy preserve pour compatibilite

References:

- `crates/crue-engine/src/engine.rs:114`
- `crates/crue-engine/src/engine.rs:186`
- `crates/crue-engine/src/engine.rs:260`

Risque residuel:

- divergence de comportement potentielle tant que le fallback legacy n'est pas deprecie/supprime

## 4. Etat de Securite du Workspace (Synthese)

### Ce qui est maintenant solide

- Pipeline formel `Policy -> Decision -> Proof -> Ledger -> Verification`
- VM-first compile path dans `rsrp-proof-engine`
- `ProofEnvelopeV1` canonique + spec + fixtures + checkers interop
- ledger immuable avec hash de contenu canonique et preuve Merkle
- hardening crypto API (`mock` vs `real`, provider abstractions, hybrid public-only verify)

### Ce qui reste fragile mais maitrisable

1. `runtime_version: u16` (`major.minor`, patch ignore)
2. metadata signature v1 basee sur `hash(key_id)` / `hash(backend_id)` (pas d'identite KMS/X.509 structuree)
3. couverture parser DSL partielle sur certaines variantes `THEN`

## 5. Recommandations Correctives (Priorites)

### Priorite P0 (avant communication "production-ready")

1. Valider `real-crypto` OQS sur environnement outille (LLVM/Clang + `libclang`)
2. Revue crypto externe (signature backend + encodage canonique + hash coverage)
3. Fuzzing (parser DSL, decoders preuve, codecs ledger)

### Priorite P1 (stabilisation pre-1.0)

1. Geler `ProofEnvelopeV1` (table de codes officielle + vectors supplementaires)
2. Benchmarks publics (eval/prove/verify/append + variance)
3. Plan de deprecation du fallback legacy moteur

### Priorite P2 (v1.0/v1.1)

1. Evolution de `runtime_version` (`u32` ou champ patch en v2)
2. Identite signature structuree (KMS/X.509/DID)
3. Extension interop multi-lang avec verification de signature (pas seulement structure/sha256)

## 6. Position de Deploiement Recommandee

### Snapshot historique `v0.9.1`

- `NON RECOMMANDE` pour production
- `OUI` pour reference d'architecture / recherche

### Workspace actuel (post-correctifs)

- `OUI` pour:
  - POC avance / pilote interne
  - attestation technique / SaaS ferme
  - integration progressive avec revue securite
- `PAS ENCORE` pour:
  - marche regule / audit externe lourd
  - claims marketing "production-grade" sans fuzz/bench/review externe

## 7. Evidence de Progression (Commits Recents)

- `f78fbbe` - hardening RSRP + `ProofEnvelopeV1`
- `be00799` - nettoyage docs top-level + `.gitignore`
- `ecdd495` - checkers interop `ProofEnvelopeV1` (Python/TS/Go)
- `c18f3be` - alignement `api-service` avec builder immuable du ledger

## 8. Conclusion

Le rapport d'audit initial est pertinent pour `v0.9.1`.

Le workspace actuel a corrige les faiblesses cryptographiques et ledger les plus critiques, et a introduit un contrat d'attestation canonique (`ProofEnvelopeV1`) suffisamment robuste pour soutenir une trajectoire `pre-1.0 stable`.

Le prochain saut de credibilite ne depend plus principalement du bytecode/VM, mais de:

- validation `real-crypto`,
- evidence de robustesse (fuzz/bench),
- revue externe,
- et discipline de freeze de schema/API.

## 9. Addendum Hardening v0.9.4 (Workspace)

Correctifs appliques apres cette synthese:

- `SEC-A01`: branche classique Hybrid KEM remplacee par X25519 ECDH reel (cle eph + decapsulation reelle) et derivee HKDF
- `SEC-A01`: ajout d'un tag de liaison classique/quantique (fail-on-tamper) pour rejeter les alterations ciphertext
- `SEC-A02`: pipeline DSL signature/verification aligne sur Ed25519 (suppression du chemin HMAC/BLAKE3 incoherent)
- `SEC-A03`: reduction de surface d'exposition des secrets (secret fields non publics sur keypairs hybrides)
- `LogEntry::new(...)`: suppression du fallback silencieux, API fail-closed en `Result`
- `ProofBinding`: encodage canonique binaire structure (plus de payload JSON dans l'attestation)
- `ProofEnvelopeV1`: `runtime_version` migre en `u32` (`major.minor.patch`)
- `crates/crypto-core`: stubs RSA-PSS remplaces par sign/verify RSA-PSS-SHA256 reels
- `DSL compiler`: operateurs `IN` et `BETWEEN` compiles et verifies en execution VM
