# RSRP Suite 0.9.1 - Audit & Restructuration

Version auditée: `0.9.1`  
Date: `2026-02-26`  
Périmètre: `rsrp-immutable-ledger`, `rsrp-policy-dsl`, `rsrp-pqcrypto`, `rsrp-proof-engine`, `rsrp-security-core`

## Résumé exécutif

RSRP 0.9.1 est une base prometteuse pour une stack "Deterministic Security & Proof Runtime", mais elle reste au stade **prototype intégré**:

- les crates sont publiées sous les bons noms, mais les frontières d'API restent instables (`crue_*`, `immutable_logging`);
- la chaîne "Policy -> Proof Engine -> Ledger -> Proof" n'est pas réellement unifiée;
- la couche `rsrp-pqcrypto` expose des **placeholders non cryptographiquement valides** derrière une API qui ressemble à une API production;
- l'engine par défaut peut bloquer sur erreurs de schéma/champs manquants au lieu d'évaluer des policies compilées;
- le ledger a une bonne direction (chaîne de hash + publication + TSA), mais la **preuve de chaîne** et la **couverture d'intégrité des champs** sont insuffisantes.

Conclusion: **crédible pour démonstration technique**, **non prête pour adoption professionnelle** sans plan de durcissement v1.0.

## Méthode d'audit

- Revue statique des crates Rust du workspace
- Cartographie des dépendances via `cargo tree`
- Vérification locale via `cargo test --workspace --lib` (tests passent)

## Phase 1 - Audit technique profond

### 1. Architecture globale (constats)

Constats majeurs:

- `rsrp-proof-engine` dépend de `rsrp-policy-dsl` et `rsrp-security-core` (`crates/crue-engine/Cargo.toml:33`, `crates/crue-engine/Cargo.toml:34`) mais exécute des règles hardcodées (`crates/crue-engine/src/rules.rs:144`) au lieu de règles compilées du DSL.
- Le DSL compile uniquement la condition `WHEN` et ignore les actions `THEN` dans le bytecode (`crates/crue-dsl/src/compiler.rs:66`, `crates/crue-dsl/src/compiler.rs:68`, `crates/crue-dsl/src/compiler.rs:69`).
- Le ledger immuable expose des preuves, mais la vérification de preuve de chaîne est triviale/non cryptographique (`crates/immutable-logging/src/chain.rs:158`).
- `rsrp-security-core` et `rsrp-pqcrypto` mélangent API "production-like" et implémentations placeholder non explicitement séparées.

### 2. Risques détaillés (priorisés)

#### Critique

1. `rsrp-pqcrypto` vérifie des signatures Dilithium en retournant toujours `true`
- `crates/pqcrypto/src/signature.rs:157`
- `crates/pqcrypto/src/signature.rs:183`
- Impact: compromission complète de l'authenticité si utilisé comme primitive réelle.

2. `HybridVerifier` ne valide pas réellement la partie classique et retourne seulement `quantum_valid`
- `crates/pqcrypto/src/hybrid.rs:236`
- `crates/pqcrypto/src/hybrid.rs:247`
- Impact: la promesse "both must verify" est fausse en pratique.

3. Intégrité du ledger incomplète: `LogEntry` expose des champs publics non couverts par `compute_content_hash`
- Champs mutables publics: `crates/immutable-logging/src/log_entry.rs:66`, `crates/immutable-logging/src/log_entry.rs:80`, `crates/immutable-logging/src/log_entry.rs:82`, `crates/immutable-logging/src/log_entry.rs:86`, `crates/immutable-logging/src/log_entry.rs:88`
- Hash de contenu partiel: `crates/immutable-logging/src/log_entry.rs:150`, `crates/immutable-logging/src/log_entry.rs:158`
- Hash de chaîne basé sur `integrity.content_hash` pré-calculé: `crates/immutable-logging/src/log_entry.rs:168`, `crates/immutable-logging/src/log_entry.rs:172`
- Impact: mutation de champs métier après création sans invalidation de chaîne.

4. Vérification de preuve de chaîne non cryptographique
- `crates/immutable-logging/src/chain.rs:158`
- Implémentation = "hash non vide && path non vide"
- Impact: faux sentiment de vérifiabilité.

5. `rsrp-proof-engine` par défaut peut bloquer en `ENGINE_ERROR` sur règles built-in incohérentes
- Strict mode activé par défaut: `crates/crue-engine/src/engine.rs:20`
- Blocage sur erreur d'évaluation: `crates/crue-engine/src/engine.rs:78`, `crates/crue-engine/src/engine.rs:85`, `crates/crue-engine/src/engine.rs:86`
- `request.export_format` est stocké en `String` (`crates/crue-engine/src/context.rs:43`) mais évalué via moteur numérique/boolean (`crates/crue-engine/src/rules.rs:63`, `crates/crue-engine/src/rules.rs:69`)
- Règle built-in incriminée: `crates/crue-engine/src/rules.rs:201`, `crates/crue-engine/src/rules.rs:203`
- Impact: comportement bloquant non déterministe vis-à-vis du schéma d'entrée.

#### High

1. `rsrp-pqcrypto` expose des placeholders comme des implémentations standards
- Signatures/keys simulées via `thread_rng`: `crates/pqcrypto/src/signature.rs:107`, `crates/pqcrypto/src/signature.rs:131`, `crates/pqcrypto/src/signature.rs:157`
- Hybrid classique simulé: `crates/pqcrypto/src/hybrid.rs:176`, `crates/pqcrypto/src/hybrid.rs:197`, `crates/pqcrypto/src/hybrid.rs:268`, `crates/pqcrypto/src/hybrid.rs:291`
- KEM placeholder (relation clé publique injectée dans secret): `crates/pqcrypto/src/kem.rs:119`, `crates/pqcrypto/src/kem.rs:121`
- Impact: confusion forte entre "API PQC" et "mock cryptographique".

2. Identifiants ML-KEM incohérents/mappage incorrect
- `crates/pqcrypto/src/lib.rs:32`, `crates/pqcrypto/src/lib.rs:33`, `crates/pqcrypto/src/lib.rs:34`
- `crates/pqcrypto/src/kem.rs:26`, `crates/pqcrypto/src/kem.rs:27`, `crates/pqcrypto/src/kem.rs:28`
- Impact: incompatibilité d'interopérabilité / artefacts mal étiquetés.

3. Signature DSL incohérente entre `sign` et `verify`
- Signer BLAKE3 keyed: `crates/crue-dsl/src/signature.rs:53`
- Vérification SHA-256 prefix: `crates/crue-dsl/src/signature.rs:81`, `crates/crue-dsl/src/signature.rs:86`
- Impact: API de signature inutilisable en flux réel.

4. Parser DSL incomplet pour actions `THEN`
- `parse_actions` traite seulement `BLOCK`: `crates/crue-dsl/src/parser.rs:407`, `crates/crue-dsl/src/parser.rs:410`
- Impact: surface DSL publiée > capacité réelle du parser.

5. Preuve Merkle ledger incomplète
- JSON serialization errors avalées: `crates/immutable-logging/src/merkle_service.rs:74`
- `build_proof_path` stub vide: `crates/immutable-logging/src/merkle_service.rs:164`, `crates/immutable-logging/src/merkle_service.rs:166`
- Impact: preuve Merkle non exploitable.

6. `rsrp-security-core` annonce plusieurs algorithmes/HSM mais reste partiellement non implémenté
- HSM not implemented: `crates/crypto-core/src/signature.rs:160`, `crates/crypto-core/src/signature.rs:163`
- RSA-PSS placeholders: `crates/crypto-core/src/signature.rs:257`, `crates/crypto-core/src/signature.rs:264`
- Impact: contrat d'API trop large pour l'état réel.

#### Medium

1. Déterminisme incomplet (timestamps injectés dans parser/engine/rules)
- Parser metadata timestamp runtime: `crates/crue-dsl/src/parser.rs:280`, `crates/crue-dsl/src/parser.rs:288`
- Built-in rules `valid_from = Utc::now()`: `crates/crue-engine/src/rules.rs:164`, `crates/crue-engine/src/rules.rs:188`, `crates/crue-engine/src/rules.rs:212`, `crates/crue-engine/src/rules.rs:236`

2. API stringly-typed dans `rsrp-proof-engine`
- `RuleCondition` / `RuleAction` en `String`: `crates/crue-engine/src/rules.rs:26`, `crates/crue-engine/src/rules.rs:27`, `crates/crue-engine/src/rules.rs:28`, `crates/crue-engine/src/rules.rs:34`, `crates/crue-engine/src/rules.rs:35`

3. Parser DSL: parsing fragile / pertes d'information
- `num.parse().unwrap_or(0)` => coercition silencieuse: `crates/crue-dsl/src/parser.rs:132`
- Parsing `message` casse les chaînes non vides: `crates/crue-dsl/src/parser.rs:421`, `crates/crue-dsl/src/parser.rs:422`

4. `crypto-core::merkle` avale des erreurs et continue
- `crates/crypto-core/src/merkle.rs:53`
- `crates/crypto-core/src/merkle.rs:151`, `crates/crypto-core/src/merkle.rs:152`, `crates/crypto-core/src/merkle.rs:155`, `crates/crypto-core/src/merkle.rs:163`

5. FIPS mode ambigu / fallback non conforme
- Env custom `RUST_FIPS`: `crates/crypto-core/src/signature.rs:34`
- Fallback avec warning `eprintln!`: `crates/crypto-core/src/signature.rs:111`, `crates/crypto-core/src/signature.rs:113`
- Fallback `StdRng::from_entropy`: `crates/crypto-core/src/signature.rs:148`, `crates/crypto-core/src/signature.rs:153`

6. TSA transport expérimental sans validation RFC3161 complète
- Limitation documentée: `crates/immutable-logging/src/publication.rs:271`, `crates/immutable-logging/src/publication.rs:272`
- HTTP autorisé: `crates/immutable-logging/src/publication.rs:326`
- Client sans timeout explicite: `crates/immutable-logging/src/publication.rs:334`
- CMS OK mais pas `message imprint/nonce/policy`: `crates/immutable-logging/src/publication.rs:423`, `crates/immutable-logging/src/publication.rs:424`

#### Low

1. Duplication de types d'erreur crypto (`CryptoError` vs `CryptoCoreError`)
- `crates/crypto-core/src/lib.rs:85`
- `crates/crypto-core/src/error.rs:6`

2. Documentation PQC imprécise (références FIPS et mapping dans commentaires)
- `crates/pqcrypto/src/lib.rs:14`, `crates/pqcrypto/src/lib.rs:15`, `crates/pqcrypto/src/lib.rs:16`

3. Convention de nommage interne historique (`crue_*`, `immutable_logging`) vs noms de crates publiées
- Augmente la friction de maintenance/documentation.

### 3. Audit sécurité (surface d'attaque / panic / unsafe / erreurs)

- `unsafe`: aucun bloc `unsafe` détecté dans les crates auditées.
- `panic` en production path: peu de `unwrap/expect` hors tests, mais plusieurs `unwrap_or_default` masquent des erreurs critiques (ledger/Merkle).
- Gestion d'erreurs: hétérogène; certaines fonctions exposent `Result`, d'autres masquent les défauts et continuent avec des valeurs par défaut.
- Surface réseau: `reqwest` dans `publication` sans timeout/strict TLS policy applicative.
- Surface d'API: forte exposition d'objets mutables (`pub` fields) sur structures d'intégrité.

## Phase 2 - Restructuration architecturale

### Architecture cible (v1.0)

Objectif: séparation nette entre "core déterministe", "cryptographie réelle", "adaptateurs IO".

- `rsrp-core` (nouvelle crate): types de domaine stables, IDs, timestamps, erreurs, traits (`Clock`, `Signer`, `Hasher`, `LedgerStore`).
- `rsrp-policy-dsl`: parser + AST + compiler + validation statique (sans crypto ni runtime clock par défaut).
- `rsrp-proof-engine`: VM/rule evaluator déterministe sur bytecode compilé (pas de règles hardcodées).
- `rsrp-security-core`: hash, signatures classiques, Merkle, interfaces KMS/HSM (impl réelles + mocks clairement séparés).
- `rsrp-pqcrypto`: backend PQC sous trait + feature-gated providers (`mock`, `oqs`, `fips` future).
- `rsrp-immutable-ledger`: append-only store + proofs + publication; persistance et TSA en adaptateurs.
- `rsrp-integrations-*` (optionnel): TSA HTTP, object storage, KMS cloud, OPA bridge, SIEM bridge.

### Schéma logique des dépendances (cible)

```text
          +--------------------+
          |    rsrp-core       |
          | traits + domain    |
          +---------+----------+
                    |
      +-------------+--------------+
      |                            |
+-----v------+              +------v------+
| rsrp-policy |              | rsrp-security|
|   -dsl      |              |   -core      |
+-----+------+              +------+-------+
      |                            |
      +-------------+--------------+
                    |
             +------v------+
             | rsrp-proof  |
             |   -engine   |
             +------+------+
                    |
             +------v------+
             | rsrp-immutable|
             |   -ledger     |
             +------+--------+
                    |
       +------------+-------------+
       |                          |
+------v-------+          +-------v--------+
| rsrp-pqcrypto |          | integrations-* |
| (pluggable)   |          | TSA/KMS/Store  |
+---------------+          +----------------+
```

Règles de dépendance:

- `proof-engine` ne dépend pas directement de `reqwest`, `chrono::Utc::now()`, ni de formats de persistance.
- `policy-dsl` ne dépend pas de crypto runtime; la signature de policy doit passer par un trait/adapter.
- `pqcrypto` ne doit jamais exporter un mock sous la même API "production" sans marquage explicite.

### Séparation Core / Crypto / Policy / Proof / Ledger

- Core: types immuables, identités, codecs canoniques, clock abstraite, erreurs.
- Crypto: hash/signatures/Merkle/KMS, sans logique métier "policy" ni "ledger".
- Policy: syntaxe, AST, compilation, lint, compatibilité de versions.
- Proof: VM déterministe + exécution + trace + attestations.
- Ledger: persist/append/proofs/publication/TSA connectors.

### Convention de versioning stable

Politique recommandée:

- `0.9.x`: stabilisation interne, corrections critiques, dépréciations annotées.
- `1.0.0-rc1`: API freeze sur types publics + formats sérialisés + error contracts.
- `1.0.0`: engagement compatibilité semver pour APIs publiques et schémas de preuve versionnés.

Règles semver:

- Breaking API Rust: `MAJOR`.
- Changement de format de preuve/ledger/publication: `MAJOR` (même si API Rust inchangée).
- Ajout non-breaking de variant enum public: considérer `MAJOR` si pattern matching exhaustif attendu côté client.

### Guidelines pour passer en v1.0

1. Introduire un mode `mock` explicite et un mode `production` bloquant sans backend crypto réel.
2. Geler les formats (`RuleBytecode`, `ProofEnvelope`, `LedgerEntryCanonical`) avec version de schéma.
3. Rendre immuables les structures critiques (constructeurs + setters validés, champs privés).
4. Remplacer les strings d'opérateurs/actions par enums et IR typé.
5. Retirer/séparer les placeholders (`RSA-PSS not implemented`, `Ok(true)`).
6. Ajouter tests de propriétés / vectors / differential tests / fuzzing parser.
7. Ajouter threat model, SLO sécurité, politique de disclosure et SBOM.

## Phase 3 - Démo intégrée

Projet ajouté: `rsrp-demo/`

Ce que montre la démo:

- création d'une policy (DSL parse + compile)
- évaluation policy (proof-engine avec registre custom)
- signature "post-quantique" (API actuelle `Dilithium`)
- append dans ledger immuable
- génération preuve de chaîne
- vérification preuve de chaîne

Notes:

- la démo reflète l'état actuel des APIs;
- la vérification PQ et la vérification de preuve de chaîne sont **placeholder** dans 0.9.1 (voir risques critiques).

## Phase 4 - Positionnement stratégique

### Proposition de valeur claire

RSRP n'est pas une blockchain ni un simple moteur de policy.  
C'est une **stack de décision déterministe + journalisation vérifiable + preuves exportables** pour environnements de sécurité et conformité.

Positionnement cible:

`Deterministic Security & Proof Runtime`  
`Quantum-Resilient. Policy-Driven. Verifiable.`

### Cas d'usage entreprise

- Contrôle d'accès à données sensibles (banque, santé, administration)
- Exécution de politiques de sécurité explicables et auditables
- Chaînes de décisions à preuve exportable (forensics, litige, audit interne)
- Journaux immuables pour workflows humains + automates
- Attestation de décisions de service (API gateways, IAM, fraud/risk gates)

### Différenciation

Vs Blockchain:

- + Plus simple à opérer en contexte entreprise
- + Déterministe et orienté policy/runtime (pas de consensus distribué requis)
- + Données privées/on-prem plus naturelles
- - Moins de décentralisation/neutralité

Vs Open Policy Agent (OPA):

- + Focus preuve/ledger/tamper-evidence natif
- + Chaînage cryptographique et publication d'attestations
- - Écosystème et maturité inférieurs aujourd'hui
- - Langage/pipeline policy moins mature que Rego

Vs Simple logging system:

- + Intégrité, preuves, publication, timestamping
- + Corrélation décision/policy/preuve
- - Complexité plus élevée

### Marché cible

Priorité marché:

1. SaaS B2B sécurité/compliance (fintech, healthtech, regtech)
2. Éditeurs IAM/PAM/Zero Trust
3. Intégrateurs pour secteurs régulés (banque, assurance, public)
4. Plateformes audit-forensics / risk operations

## Phase 5 - Maturité sécurité (checklist)

### Ready for production?

- `Non` (0.9.1)
- Bloquants:
  - placeholders crypto/PQ actifs
  - preuve de chaîne non vérifiée cryptographiquement
  - intégrité ledger partielle
  - engine default path fragile sur champs absents/types

### Ready for audit ISO?

- `Partiellement` (documentation possible, contrôle technique insuffisant)
- Nécessaire avant audit sérieux:
  - politiques de gestion clés/KMS
  - traces de test sécurité/revue crypto
  - hardening réseau/TSA
  - processus vulnérabilités / patch management / SBOM

### Ready for SaaS?

- `Non`
- Nécessaire:
  - multi-tenant isolation model
  - persistence durability guarantees
  - secrets management / KMS
  - rate limits / quotas / abuse protection
  - observability + incident response playbooks

### Ready for regulated market?

- `Non`
- Nécessaire:
  - formalisation du threat model
  - validation crypto indépendante
  - evidence packs (change mgmt, test evidence, access control)
  - conformité data governance (retention, minimization, legal basis)

## Roadmap recommandé (90 jours)

### Sprint 1 (stabilisation critique)

- Désactiver/renommer les placeholders crypto (`mock_*`) par défaut
- Corriger engine built-ins / typing / erreurs de schéma
- Rendre `LogEntry` immuable + hash canonique de tous les champs
- Implémenter vraie vérification de `ChainProof`

### Sprint 2 (architecture v1.0)

- Brancher `proof-engine` sur bytecode du DSL
- Introduire traits `Signer`, `Hasher`, `Clock`, `TsaClient`
- Stabiliser schémas de sérialisation (versionnés)

### Sprint 3 (assurance qualité & go-to-market technique)

- Tests vectors/fuzz/property
- Benchmarks + profils de latence
- Threat model + security docs + API stability policy
- `1.0.0-rc1`

## Conclusion

RSRP 0.9.1 a déjà les bons axes produits (policy + preuve + ledger + TSA + ambition PQ), mais doit passer d'un prototype couplé à une plateforme modulaire avec contrats explicites.

La trajectoire recommandée est claire:

- **séparer les mocks des implémentations réelles**
- **stabiliser les formats de preuve et d'API**
- **garantir le déterminisme et l'intégrité end-to-end**
- **industrialiser la posture sécurité/compliance**

Alors RSRP peut devenir une stack crédible:

**Deterministic Security & Proof Runtime**  
**Quantum-Resilient. Policy-Driven. Verifiable.**

## Addendum - Post-Audit Implementation Progress (Workspace, 2026-02-26)

This addendum reflects concrete implementation work completed after publication of the `v0.9.1` audit snapshot.
It does not invalidate the original risk prioritization for `v0.9.1`.

### Completed in workspace (hardening + phase-2 progress)

- `rsrp-pqcrypto`
  - explicit `mock-crypto` / `real-crypto` feature separation
  - release guardrails (mock backend forbidden in release)
  - provider-based signature and KEM abstraction
  - OQS-backed `real-crypto` implementations wired (signature + KEM)
  - hybrid verification hardened and public-key-only verification path added
- `rsrp-immutable-ledger`
  - immutable `LogEntry` builder + private fields
  - canonicalized hash computation with version/schema prefix
  - hash coverage extended across entry payload
  - cryptographic chain proof recomputation
  - Merkle proof generation/verification implemented
- `rsrp-proof-engine`
  - compiled DSL -> VM evaluation path integrated with fallback legacy rules
  - strict `ProofBinding` with bytecode/input/state hashes
  - signed proof envelopes (Ed25519 bootstrap + feature-gated PQ/hybrid envelope)
  - explicit VM instruction model (`EmitDecision`, jump instructions)
  - precompiled match-program execution for compiled rules
  - compiled action semantics executed via explicit `ActionVm` instruction program
  - typed IR extended (`Operator`, `ActionKind`, `RuleEffect`, `ActionInstruction`)
- `rsrp-demo`
  - integrated flow now exercises compiled engine path + signed proof envelope + ledger proof verification

### Remaining gaps before claiming Phase 2 completion (strict interpretation)

- DSL compiler (`rsrp-policy-dsl`) still compiles `WHEN` expressions only; `THEN` actions are compiled into engine-side action VM, not DSL bytecode yet
- formal published proof schema specification (`v1`) still missing
- OQS `real-crypto` validation remains environment-blocked on this workstation (missing LLVM/Clang/libclang for `oqs-sys` bindgen)

### Recommended next steps (updated)

1. Extend `rsrp-policy-dsl` compiler to emit action semantics (not only conditions)
2. Publish canonical proof schema/spec (`ProofBinding`/`ProofEnvelope`) with compatibility policy
3. Add fuzz/property/benchmark suites and publish results
4. Package security artifacts (`SECURITY.md`, SBOM, vuln disclosure policy, threat model)
