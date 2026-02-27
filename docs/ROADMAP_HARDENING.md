# ROADMAP_HARDENING

## 1. Baseline de référence

Le projet part d'un état déjà durci sur les points critiques du hard audit: hybrid signature réelle, RBAC temporel fail-closed, Merkle prefixé, zeroization, posture FIPS stricte, modèle HSM corrigé, JWT EdDSA strict, rate limiting borné, WAL append-only, UUID complets et TLS strict.

Objectif de cette roadmap: transformer cet état en trajectoire complète de hardening opérationnel, conformité et pré-certification, avec critères de sortie vérifiables et blocage fail-closed de toute release non conforme.

## 2. Principes de pilotage

- Toute exigence de sécurité est traduite en contrôle vérifiable.
- Toute absence d'information critique entraîne un refus explicite.
- Toute dérogation est tracée, bornée et approuvée formellement.
- Toute preuve doit être exportable pour audit externe.
- Toute build de release doit être reproductible, signée et attestée.

## 3. Roadmap logique

## Bloc A - Supply chain et builds reproductibles

- Objectif sécurité: empêcher l'injection de dépendances malveillantes et garantir l'intégrité bit-à-bit des artefacts.
- Modifs code/config/infra attendues: verrouillage strict `Cargo.lock`; politique `deny.toml` bloquante (advisories, bans, sources, licenses); suppression des sources non autorisées; builds déterministes avec `--locked --frozen`; comparaison d'empreintes multi-environnements; génération SBOM systématique; signatures et attestations de provenance attachées aux artefacts.
- Tests à ajouter: test CI de dérive lockfile; test CI de rejet source git non approuvée; test de reproductibilité inter-runners; test de vérification signature/provenance avant promotion; property test sur stabilité de hash d'artefacts de build.
- Artefacts de preuve: `deny.toml`; logs `cargo deny`/`cargo audit`; rapports de comparaison de hash; bundles SBOM CycloneDX/SPDX; signatures Cosign; attestations provenance (in-toto/SLSA); runbook de gestion des exceptions supply-chain.
- Critères de sortie: aucune dépendance hors registre autorisé; `cargo deny` bloquant vert; `cargo audit` bloquant vert hors exceptions documentées; hash de reproductibilité identiques sur runners de référence; SBOM généré pour chaque artefact relâché; signature et provenance vérifiées en pipeline.

## Bloc B - CI/CD sécurisé et policy production-build-only

- Objectif sécurité: interdire toute release qui n'emploie pas le profil cryptographique production.
- Modifs code/config/infra attendues: workflow dédié de gate production; build obligatoire avec `--no-default-features --features production`; rejet explicite de `mock-crypto` dans le graphe de features; tests ciblés en profil production; contrôle branch protection avec checks requis; politique de promotion conditionnée aux preuves signées.
- Tests à ajouter: test CI négatif qui force `mock-crypto` et attend un échec; test d'intégration release profile sur `rsrp-demo` et `rsrp-pqcrypto`; fuzz ciblé sur les frontières de parsing/validation en mode production; test de non-régression des compile-time guards.
- Artefacts de preuve: définition du workflow gate; logs de jobs bloquants; rapport de graphe de features; preuves de refus des builds non conformes; attestation de promotion d'image/artefact.
- Critères de sortie: aucun artefact release produit si le check production échoue; aucune trace `mock-crypto` dans le graphe production; tous les checks requis activés en protection de branche; promotion impossible sans signature+provenance valides.

## Bloc C - Key lifecycle opérationnel (rotation, révocation, destruction)

- Objectif sécurité: contrôler l'intégralité du cycle de vie des clés avec traçabilité et destruction vérifiable.
- Modifs code/config/infra attendues: machine d'état explicite `Generated -> Active -> Rotating -> Revoked -> Destroyed`; métadonnées de version et owner pour chaque clé; registre d'inventaire des clés; mécanisme de rotation contrôlée; liste de révocation exploitable en runtime; destruction logique et matérielle documentée; intégration HSM/KMS avec séparation des privilèges.
- Tests à ajouter: tests unitaires de transitions d'état interdites; tests d'intégration de rotation sans downtime fonctionnel; tests de révocation immédiate et effet runtime; tests mémoire post-destruction (zeroization); property tests d'invariants de cycle de vie.
- Artefacts de preuve: `KEY_LIFECYCLE_POLICY.md`; journal d'événements de cycle de vie; preuves de révocation; comptes-rendus de rotation; runbook d'urgence compromission de clé; traces d'audit signées.
- Critères de sortie: aucune clé active sans owner et policy; aucune transition illégale possible; révocation effective vérifiée en tests d'intégration; destruction validée par tests techniques et procédure documentaire; audit trail complet exportable.

## Bloc D - Entropy boundary et RNG (posture FIPS)

- Objectif sécurité: garantir une frontière d'entropie explicite et un comportement fail-closed en cas de source RNG non conforme.
- Modifs code/config/infra attendues: définition formelle de la boundary d'entropie; auto-tests de démarrage RNG; health checks continus sur disponibilité/qualité des sources; mode FIPS qui refuse tout fallback; instrumentation d'alerte sur dégradation RNG; stratégie de boot qui bloque la mise en service si RNG invalide.
- Tests à ajouter: test de démarrage avec RNG indisponible; test de démarrage avec config FIPS invalide; test de non-fallback silencieux; tests de chaos engineering sur défaillance RNG; fuzz des entrées de configuration RNG.
- Artefacts de preuve: documentation entropy boundary; logs de health checks RNG; matrice de comportements de boot; rapports de tests de défaillance; preuves de refus explicite en mode FIPS.
- Critères de sortie: service non démarrable si RNG critique est non conforme; aucun chemin de fallback implicite actif; événements RNG critiques auditables; comportement de refus validé par tests automatisés.

## Bloc E - Observabilité contrôlée (no-leak, redaction, no-debug prod)

- Objectif sécurité: garantir la détection opérationnelle sans fuite d'information sensible.
- Modifs code/config/infra attendues: classification des données loggables/non-loggables; redaction centralisée des champs sensibles; format de logs canonique; interdiction de logs debug/trace en production; politique de rétention et accès restreint aux logs; validation automatique des messages sensibles dans CI.
- Tests à ajouter: tests unitaires de redaction; tests d'intégration vérifiant l'absence de secrets en logs; tests de non-régression sur formats structurés; fuzz sur chaînes d'erreur pour détecter fuite de secrets; tests de conformité de niveaux de log en mode production.
- Artefacts de preuve: politique de logging sécurisé; extraits de logs anonymisés; rapports d'outils de détection de secrets; runbook d'investigation sans exfiltration; preuves CI d'interdiction debug prod.
- Critères de sortie: zéro secret détecté dans les logs de test; debug/trace interdits et bloqués en production; redaction prouvée sur tous champs sensibles catalogués; accès aux logs traçable et restreint.

## Bloc F - Threat model et Security Target alignés au code

- Objectif sécurité: rendre la posture de sécurité démontrable et traçable de l'exigence au test.
- Modifs code/config/infra attendues: matrice de traçabilité `Threat -> Control -> Test -> Evidence`; harmonisation `THREAT_MODEL`, `THREAT_MODEL_STRIDE` et `SECURITY_TARGET`; cartographie des frontières de confiance; formalisation des hypothèses d'exploitation; couverture explicite du mode "hostile host".
- Tests à ajouter: tests de scénario d'attaque alignés STRIDE; tests de régression des contrôles associés aux menaces critiques; tests de robustesse des hypothèses de confiance (absence dépendance composant non fiable).
- Artefacts de preuve: `THREAT_MODEL.md`; `THREAT_MODEL_STRIDE.md`; `SECURITY_TARGET.md`; `ATTACK_SCENARIOS.md`; matrice de traçabilité signée; comptes-rendus de revues d'architecture sécurité.
- Critères de sortie: chaque menace critique a un contrôle, un test et une preuve; aucun contrôle critique sans owner; aucun écart non justifié entre documentation et implémentation; mode hostile host explicitement traité et testé.

## Bloc G - Dossier pré-certification (CSPN réaliste, EUCC Substantial possible)

- Objectif sécurité: constituer un paquet d'évidence prêt pour audit externe et évaluation pré-certification.
- Modifs code/config/infra attendues: normalisation du bundle de conformité; index d'évidences versionné; procédures de collecte d'artefacts CI; gel des exigences de sécurité release; formalisation des scénarios d'attaque et des résultats de tests correspondants.
- Tests à ajouter: test de complétude du bundle documentaire; test CI de présence des artefacts obligatoires; test de vérification cryptographique des preuves (signatures, checksums, provenance); exercice de relecture indépendante du dossier.
- Artefacts de preuve: `CERTIFICATION_BUNDLE.md`; Security Target; threat model; registre des risques; politiques cycle de vie clés; politique supply-chain; résultats de tests; SBOM; provenance; signatures; runbooks opérationnels.
- Critères de sortie: bundle complet générable automatiquement; aucune pièce obligatoire manquante; toutes preuves cryptographiques vérifiables; traçabilité exigences-controles-tests complète; dossier exploitable sans connaissance tacite du contexte équipe.

## Bloc H - Attacker model "hostile host" (compromission container/VM)

- Objectif sécurité: maintenir les garanties essentielles même en cas d'hôte partiellement compromis.
- Modifs code/config/infra attendues: séparation stricte secrets/process; limitation des capacités runtime; exécution rootless; politiques seccomp/apparmor/SELinux; chiffrement en mémoire et au repos selon boundary; remote attestation quand disponible; stratégie de rotation/révocation accélérée post-compromission; contrôle d'intégrité des artefacts au démarrage.
- Tests à ajouter: tests d'intégration avec privilèges réduits; tests de démarrage avec artefact altéré; tests de récupération après compromission simulée; tests de refus d'opérations sensibles sans attestation/contexte valide; fuzz de surfaces d'entrée exposées host.
- Artefacts de preuve: modèle d'attaquant hostile host; durcissement runtime documenté; logs de détection d'altération; runbook incident compromission hôte; rapport d'exercice de restauration de confiance.
- Critères de sortie: secrets non exploitables hors boundary défini; artefact altéré toujours refusé au boot; compromission hôte déclenche réponse automatisée et révocation; reprise en état de confiance démontrée par procédure testée.

## 4. Checklist finale release production (fail-closed)

- [ ] Build exécuté en mode production uniquement (`--no-default-features --features production`).
- [ ] Aucun backend mock présent dans le graphe de features release.
- [ ] `cargo fmt`, `clippy -D warnings`, tests unitaires et intégration sécurité passent.
- [ ] Tests de hardening critiques passent: hybrid signature, RBAC temporel, Merkle prefixé, zeroization, FIPS fail-closed, TLS strict.
- [ ] `cargo deny` passe sur advisories, bans, licenses, sources.
- [ ] `cargo audit` passe selon politique d'exceptions documentées.
- [ ] Build reproductible vérifié sur runners de référence avec hash identiques.
- [ ] SBOM généré pour tous artefacts relâchés.
- [ ] Artefacts signés et signatures vérifiées avant publication.
- [ ] Provenance/attestation générée et vérifiée (in-toto/SLSA compatible).
- [ ] Journal de cycle de vie des clés à jour et révocations appliquées.
- [ ] Contrôles RNG/FIPS validés au démarrage sans fallback silencieux.
- [ ] Politique de logs sécurisés validée, aucune fuite de secrets détectée.
- [ ] Dossier pré-certification complet et cohérent avec le code livré.
- [ ] Contrôles hostile host validés, procédures de réponse incident testées.
- [ ] Promotion release bloquée automatiquement si un item ci-dessus échoue.

## 5. Règle de refus automatique

Toute build qui ne satisfait pas l'ensemble de la checklist de release production est rejetée sans dérogation implicite.
