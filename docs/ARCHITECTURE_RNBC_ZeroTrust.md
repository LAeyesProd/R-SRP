# 🔐 Architecture Zero-Trust du Registre National des Comptes Bancaires

## Document de référence : RNBC-ZT-2026-v1.0

---

## 1. Principes Fondamentaux

### 1.1 Philosophie Zero-Trust

Cette architecture repose sur le principe fondamental **"Ne jamais faire confiance, toujours vérifier"** (Never Trust, Always Verify). Chaque requête, chaque session, chaque accès est traité comme potentiellement compromis jusqu'à preuve du contraire.

```
┌─────────────────────────────────────────────────────────────────────┐
│                    PRINCIPE ZERO-TRUST                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   ┌─────────┐      ┌──────────────┐      ┌────────────────────┐   │
│   │ Acteur  │──────▶  Vérification │──────▶ Ressource        │   │
│   │ (User/  │      │   Continue    │      │ (Donnée/API/       │   │
│   │ Service)│      │               │      │ Service)           │   │
│   └─────────┘      └──────────────┘      └────────────────────┘   │
│        │                  │                        │               │
│        ▼                  ▼                        ▼               │
│   ┌─────────────────────────────────────────────────────────┐      │
│   │  Authentification + Autorisation + Context + Logging   │      │
│   │           À CHAQUE ÉTAPE DE CHAQUE REQUÊTE               │      │
│   └─────────────────────────────────────────────────────────┘      │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.2 Objectifs de Sécurité

| Objectif | Métrique Cible | Mécanisme |
|----------|----------------|-----------|
| Prévention identifiants compromis | 0 mot de passe seul | MFA FIDO2 + Certificate |
| Réduction périmètre d'accès | -85% surface d'attaque | Micro-segmentation |
| Détection extraction anormale | < 5 min MTD | IA + Règles déterministes |
| Traçabilité juridiquement exploitable | 100% non-répudiation | Logs immuables + hash |
| Conformité RGPD | 100% gouvernance | Data minimization |
| Auto-défense | < 30s réponse | Automatisation |

### 1.3 Périmètre Applicatif

- **Base de données** : Registre national des comptes bancaires (类似 FICOBA)
- **Organismes accédants** : Administration fiscale, Justice, Gendarmerie, Douanes, Banque centrale
- **Volume** : Plusieurs millions de consultations/jour
- **Exigence** : Disponibilité 24/7, tolérance zéro sur altération des logs

---

## 2. Vue d'Ensemble de l'Architecture

### 2.1 Architecture Globale (Diagramme Logique)

```
┌────────────────────────────────────────────────────────────────────────────────────┐
│                        REGISTRE NATIONAL BANCAIRE - ARCHITECTURE                 │
├────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                    │
│  ╔════════════════════════════════════════════════════════════════════════════╗  │
│  ║                           ZONE DEMATERIALISEE                               ║  │
│  ║  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        ║  │
│  ║  │   FISCALITÉ  │  │   JUSTICE   │  │  POLICE/    │  │   AUTRES    │        ║  │
│  ║  │              │  │              │  │  GENDARMERIE │  │  ORGANISMES │        ║  │
│  ║  │  Portail     │  │  Portail     │  │  Portail     │  │  Portail     │        ║  │
│  ║  │  SAML/OIDC   │  │  SAML/OIDC  │  │  SAML/OIDC   │  │  SAML/OIDC  │        ║  │
│  ║  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘        ║  │
│  ║         │                 │                 │                 │                ║  │
│  ║         ▼                 ▼                 ▼                 ▼                ║  │
│  ║  ┌─────────────────────────────────────────────────────────────────────┐     ║  │
│  ║  │                    IDENTITY PROVIDER NATIONAL                     │     ║  │
│  ║  │         (FIDO2 + Certificat + Device Binding + Context)           │     ║  │
│  ║  └─────────────────────────────────┬───────────────────────────────────┘     ║  │
│  ║                                    │                                          ║  │
│  ╚════════════════════════════════════╪════════════════════════════════════════╝  │
│                                       │                                               │
│                                       ▼                                               │
│  ╔════════════════════════════════════════════════════════════════════════════╗  │
│  ║                         PERIMETRE SECURISE                                ║  │
│  ║                                                                         ║  │
│  ║   ┌─────────────────────────────────────────────────────────────────┐   ║  │
│  ║   │                    API GATEWAY CENTRALISEE                       │   ║  │
│  ║   │         (mTLS + WAF + Rate Limiting + JWT Validation)          │   ║  │
│  ║   └─────────────────────────┬───────────────────────────────────────┘   ║  │
│  ║                               │                                            ║  │
│  ║                               ▼                                            ║  │
│  ║   ┌─────────────────────────────────────────────────────────────────┐   ║  │
│  ║   │              DETERMINISTIC CONTROL ENGINE (CRUE)                │   ║  │
│  ║   │     (Règles non contournables + Validation croisée + JIT)      │   ║  │
│  ║   └─────────────────────────┬───────────────────────────────────────┘   ║  │
│  ║                               │                                            ║  │
│  ║         ┌───────────────────┼───────────────────┐                          ║  │
│  ║         ▼                   ▼                   ▼                          ║  │
│  ║  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐                   ║  │
│  ║  │   MICRO-SEG  │   │   MICRO-SEG  │   │   MICRO-SEG  │                   ║  │
│  ║  │   FISCALITÉ  │   │   JUSTICE    │   │   POLICE     │                   ║  │
│  ║  │              │   │              │   │              │                   ║  │
│  ║  │  API Service │   │  API Service │   │  API Service │                   ║  │
│  ║  └──────┬───────┘   └──────┬───────┘   └──────┬───────┘                   ║  │
│  ║         │                  │                  │                           ║  │
│  ║         ▼                  ▼                  ▼                           ║  │
│  ║  ┌─────────────────────────────────────────────────────────────────┐   ║  │
│  ║  │                   DATA LAYER MICRO-SEGMENTEE                    │   ║  │
│  ║  │    ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐  │   ║  │
│  ║  │    │  Vault    │  │  Vault    │  │  Vault    │  │  Vault    │  │   ║  │
│  ║  │    │ FISCALITÉ │  │  JUSTICE  │  │  POLICE   │  │   AUTRES  │  │   ║  │
│  ║  │    └───────────┘  └───────────┘  └───────────┘  └───────────┘  │   ║  │
│  ║  └─────────────────────────────────────────────────────────────────┘   ║  │
│  ║                                                                         ║  │
│  ╚════════════════════════════════════════════════════════════════════════╝  │
│                                                                                    │
│  ╔════════════════════════════════════════════════════════════════════════════╗  │
│  ║                    COUCHE OBSERVABILITÉ & DÉFENSE                           ║  │
│  ║                                                                         ║  │
│  ║  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐               ║  │
│  ║  │ IMMUTABLE      │  │  ANOMALY       │  │  EVENT        │               ║  │
│  ║  │ LOGGING        │  │  DETECTION     │  │  BUS          │               ║  │
│  ║  │ (Merkle Tree)  │  │  (AI/ML)       │  │  (Kafka)      │               ║  │
│  ║  └───────┬────────┘  └───────┬────────┘  └───────┬────────┘               ║  │
│  ║          │                   │                   │                         ║  │
│  ║          └───────────────────┼───────────────────┘                         ║  │
│  ║                              ▼                                             ║  │
│  ║                    ┌─────────────────┐                                     ║  │
│  ║                    │  SIEM / SOC     │                                     ║  │
│  ║                    │  (Splunk/QRadar)│                                     ║  │
│  ║                    └────────┬────────┘                                     ║  │
│  ║                             │                                              ║  │
│  ║                             ▼                                              ║  │
│  ║                    ┌─────────────────┐                                     ║  │
│  ║                    │ AUTOMATED       │                                     ║  │
│  ║                    │ RESPONSE       │                                     ║  │
│  ║                    │ (Revocation)   │                                     ║  │
│  ║                    └─────────────────┘                                     ║  │
│  ║                                                                         ║  │
│  ╚════════════════════════════════════════════════════════════════════════════╝  │
│                                                                                    │
└────────────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Composants Principaux

| Composant | Fonction | Criticité |
|-----------|----------|-----------|
| **Identity Provider** | Authentification MFA forte | Critique |
| **API Gateway** | Point d'entrée unique, authentification,限流 | Critique |
| **Deterministic Control Engine** | Moteur de règles inviolables | Critique |
| **Data Vaults** | Stockage segmenté par périmètre | Critique |
| **Immutable Logger** | Journalisation à preuve cryptographique | Critique |
| **Anomaly Detection** | Détection comportementale par IA | Élevée |
| **Event Bus** | Orchestration event-driven | Élevée |
| **Automated Response** | Réponse automatique aux incidents | Élevée |

---

## 3. Flux d'Authentification

### 3.1 Flow d'Authentification Zero-Trust

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    FLUX D'AUTHENTIFICATION ZERO-TRUST                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. INITIATION                                                            │
│  ┌──────────┐      ┌──────────────────────────────────────────────┐       │
│  │ Utilisateur │────▶│ Portail Organisme (SAML SP)                 │       │
│  │ (Agent)     │     │ Redirect vers IdP National                  │       │
│  └──────────┘      └──────────────────────────────────────────────┘       │
│                                     │                                       │
│                                     ▼                                       │
│  2. AUTHENTIFICATION FORTE                                                  │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                    IDENTITY PROVIDER NATIONAL                         │   │
│  │                                                                       │   │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │   │
│  │  │  a) Vérification credentials (interdit si seul)               │  │   │
│  │  └─────────────────────────────────────────────────────────────────┘  │   │
│  │                               │                                       │   │
│  │                              ▼                                       │   │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │   │
│  │  │  b) Challenge FIDO2 / Certificat matériel                      │  │   │
│  │  │     - Device binding vérifié                                    │  │   │
│  │  │     - Attestation certificate validée                           │  │   │
│  │  └─────────────────────────────────────────────────────────────────┘  │   │
│  │                              │                                       │   │
│  │                              ▼                                       │   │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │   │
│  │  │  c) Validation contextuelle                                     │  │   │
│  │  │     - IP connue vs historique                                   │  │   │
│  │  │     - Géolocalisation cohérente                                 │  │   │
│  │  │     - Horaire conforme à mission                                │  │   │
│  │  │     - Device non compromis                                      │  │   │
│  │  └─────────────────────────────────────────────────────────────────┘  │   │
│  │                              │                                       │   │
│  │                              ▼                                       │   │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │   │
│  │  │  d) Vérification mission active                                  │  │   │
│  │  │     - Code mission valide                                        │  │   │
│  │  │     - Périmètre autorisé                                        │  │   │
│  │  │     - Date de fin non dépassée                                  │  │   │
│  │  └─────────────────────────────────────────────────────────────────┘  │   │
│  │                                                                       │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                     │                                       │
│                          ┌─────────┴─────────┐                             │
│                          ▼                   ▼                             │
│                    ┌──────────┐         ┌──────────┐                        │
│                    │  ÉCHEC   │         │ SUCCÈS   │                        │
│                    │          │         │          │                        │
│                    │ - Refus  │         │ - Token  │                        │
│                    │ - Alerte │         │ - JWT    │                        │
│                    │ - Audit  │         │ - Claims │                        │
│                    └──────────┘         └────┬─────┘                        │
│                                               │                              │
│                                               ▼                              │
│  3. ACCÈS                                                                  │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  Utilisateur authentifié ──▶ API Gateway (JWT + mTLS)              │   │
│  │                                                                       │   │
│  │  - Session isolée                                                    │   │
│  │  - Bastion dédié                                                      │   │
│  │  - Vérification continue                                             │   │
│  │                                                                       │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Détail des Étapes d'Authentification

| Étape | Vérification | Action si Échec |
|-------|-------------|-----------------|
| 1. Credentials | Login + Mot de passe (interdit seul) | Refus immédiat |
| 2. MFA FIDO2 | Challenge hardware | Refus + Alerte |
| 3. Device Binding | Attestation certificate | Quarantaine |
| 4. IP Context | Liste blanche IP connue | Challenge additionnel |
| 5. Géolocation | Cohérence avec historique | Alerte + Blocage si anomal |
| 6. Temporalité | Horaire de mission | Refus si hors périmètre |
| 7. Mission Active | Validation BDD mission | Refus |

---

## 4. Flux de Consultation

### 4.1 Flow Complet de Requête

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    FLUX DE CONSULTATION - SEQQUENCE                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  UTILISATEUR                                                                 │
│      │                                                                     │
│      │ 1. Requête (IBAN/Nom)                                               │
│      ▼                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 2. API GATEWAY                                                         │   │
│  │    - Validation JWT                                                    │   │
│  │    - mTLS handshake                                                    │   │
│  │    - WAF (SQL injection, XSS)                                         │   │
│  │    - Rate limiting                                                     │   │
│  └──────────────────────────┬──────────────────────────────────────────┘   │
│                             │                                                │
│                             ▼                                                │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 3. DETERMINISTIC CONTROL ENGINE (CRUE)                              │   │
│  │                                                                        │   │
│  │    ┌──────────────────────────────────────────────────────────────┐  │   │
│  │    │ RÈGLE: Max 50 consultations/heure                           │  │   │
│  │    └──────────────────────────────────────────────────────────────┘  │   │
│  │    ┌──────────────────────────────────────────────────────────────┐  │   │
│  │    │ RÈGLE: Motif de recherche obligatoire                       │  │   │
│  │    └──────────────────────────────────────────────────────────────┘  │   │
│  │    ┌──────────────────────────────────────────────────────────────┐  │   │
│  │    │ RÈGLE: Vérification mission active                           │  │   │
│  │    └──────────────────────────────────────────────────────────────┘  │   │
│  │    ┌──────────────────────────────────────────────────────────────┐  │   │
│  │    │ RÈGLE: Interdiction export CSV                               │  │   │
│  │    └──────────────────────────────────────────────────────────────┘  │   │
│  │                                                                        │   │
│  └──────────────────────────┬──────────────────────────────────────────┘   │
│                             │                                                │
│              ┌──────────────┴──────────────┐                                 │
│              ▼                             ▼                                 │
│         ┌─────────┐                   ┌─────────┐                           │
│         │ REFUS   │                   │ AUTORISÉ│                           │
│         │         │                   │         │                           │
│         │ - Log   │                   │ - Pass  │                           │
│         │ - Alerte│                   │  à Data │                           │
│         │ - Block │                   │  Layer  │                           │
│         └─────────┘                   └────┬────┘                           │
│                                             │                                │
│                                             ▼                                │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 4. DATA LAYER (Vault segmenté)                                      │   │
│  │     - Requête paramétrée (pas de SELECT *)                         │   │
│  │     - Validation périmètre mission                                  │   │
│  │     - Chiffrement résultats                                         │   │
│  └──────────────────────────┬──────────────────────────────────────────┘   │
│                             │                                                │
│                             ▼                                                │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 5. IMMUTABLE LOGGING                                                │   │
│  │     - Hash requête                                                   │   │
│  │     - Timestamp signé                                                │   │
│  │     - Résultat agrégé                                               │   │
│  │     - Merkle Tree horaire                                           │   │
│  └──────────────────────────┬──────────────────────────────────────────┘   │
│                             │                                                │
│                             ▼                                                │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 6. EVENT BUS                                                        │   │
│  │     - Publication événement {type, actor, scope, volume}          │   │
│  │     - Consumption SIEM                                              │   │
│  │     - Consumption Anomaly Detection                                 │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Mécanismes de Détection

### 5.1 Tableau de Bord Détection

| Mécanisme | Détection | Réponse Automatique |
|-----------|-----------|---------------------|
| **Volume anormal** | > 50 req/h par agent | Warning + MFA |
| **Pattern inédit** | Nouvelle séquence de requêtes | Alerte SOC |
| **Accès hors horaires** | Horaire != mission | Refus |
| **Séquence inhabituelle** | Pattern打破了历史模型 | Blocage + Revalidation |
| **Export massif** | > 10 résultats en 5 min | Blocage immédiat |
| **IP anormale** | Nouvelle géolocation | Quarantaine |

### 5.2 Logique de Détection IA

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    MOTEUR DE DÉTECTION D'ANOMALIES                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    COLLECTE DONNÉES                                 │   │
│  │                                                                      │   │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐               │   │
│  │  │ Requêtes│  │  Utilis.│  │ Device  │  │ Contexte│               │   │
│  │  │  (Log)  │  │ Profile │  │  Score  │  │ Session │               │   │
│  │  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘               │   │
│  └───────┼───────────┼───────────┼───────────┼───────────────────────┘   │
│          │           │           │           │                            │
│          └───────────┴───────────┼───────────┘                            │
│                                  ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    ANALYSE MULTI-COUCHE                             │   │
│  │                                                                      │   │
│  │  ┌────────────────────────────────────────────────────────────────┐  │   │
│  │  │ COUCHE 1: RÈGLES DÉTERMINISTES                                │  │   │
│  │  │  - Seuil volume (50/h)                                        │  │   │
│  │  │  - Interdiction export                                        │  │   │
│  │  │  - Plage horaire                                              │  │   │
│  │  └────────────────────────────────────────────────────────────────┘  │   │
│  │                              │                                        │   │
│  │                              ▼                                        │   │
│  │  ┌────────────────────────────────────────────────────────────────┐  │   │
│  │  │ COUCHE 2: ANALYSE STATISTIQUE                                 │  │   │
│  │  │  - Z-Score sur volume journalier                               │  │   │
│  │  │  - Détection pic anomal                                       │  │   │
│  │  │  - Analyse distribution                                        │  │   │
│  │  └────────────────────────────────────────────────────────────────┘  │   │
│  │                              │                                        │   │
│  │                              ▼                                        │   │
│  │  ┌────────────────────────────────────────────────────────────────┐  │   │
│  │  │ COUCHE 3: ML/IA                                                │  │   │
│  │  │  - Modèle LSTM détection séquence                              │  │   │
│  │  │  - Clustering comportement utilisateurs                         │  │   │
│  │  │  - Autoencoder détectionnovel patterns                         │  │   │
│  │  └────────────────────────────────────────────────────────────────┘  │   │
│  │                              │                                        │   │
│  └──────────────────────────────┼────────────────────────────────────────┘   │
│                                 │                                           │
│                                 ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    DÉCISION & RÉPONSE                               │   │
│  │                                                                      │   │
│  │    ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                │   │
│  │    │   VERT      │  │   ORANGE    │  │    ROUGE    │                │   │
│  │    │             │  │             │  │             │                │   │
│  │    │  Normal     │  │  Suspect     │  │  Critique   │                │   │
│  │    │  - Continue │  │ - MFA fresh │  │ - Blocage   │                │   │
│  │    │             │  │ - Alerte SOC│  │ - Revocation│                │   │
│  │    │             │  │ - Log détail│  │ - Notification│              │   │
│  │    │             │  │             │  │ - Rapportauto│              │   │
│  │    └─────────────┘  └─────────────┘  └─────────────┘                │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Mécanismes de Preuve Cryptographique

### 6.1 Architecture de Journalisation Immuable

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    JOURNALISATION IMMUABLE - ARCHITECTURE                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    GÉNÉRATION ÉVÉNEMENT                             │   │
│  │                                                                      │   │
│  │   {                                                                 │   │
│  │     "event_id": "evt_20260223_143021_a7f9",                        │   │
│  │     "event_type": "ACCOUNT_QUERY",                                  │   │
│  │     "actor_id": "AGENT_4571",                                       │   │
│  │     "actor_org": "GENDARMERIE_NATIONALE",                          │   │
│  │     "mission_id": "MIS_2026_0234",                                  │   │
│  │     "scope": "REGION_75",                                           │   │
│  │     "query_hash": "sha256:8f14e45f...",                            │   │
│  │     "result_count": 12,                                             │   │
│  │     "timestamp": "2026-02-23T14:30:21.123Z",                       │   │
│  │     "client_ip": "192.168.xx.xx",                                   │   │
│  │     "device_fingerprint": "fp_9a7b3c..."                           │   │
│  │   }                                                                 │   │
│  │                                                                      │   │
│  └─────────────────────────────┬───────────────────────────────────────┘   │
│                                │                                            │
│                                ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    HACHAGE IMMÉDIAT                                │   │
│  │                                                                      │   │
│  │   event_hash = SHA-256(JSON.stringify(event) + nonce)              │   │
│  │                                                                      │   │
│  │   H(evt_20260223_143021_a7f9) =                                    │   │
│  │   "a7f9b3c2d1e8f4..."                                               │   │
│  │                                                                      │   │
│  └─────────────────────────────┬───────────────────────────────────────┘   │
│                                │                                            │
│                                ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    CONSTRUCTION MERKLE TREE                        │   │
│  │                                                                      │   │
│  │                     ┌──────────┐                                    │   │
│  │                     │  Root    │  H3 = H(H1 || H2)                  │   │
│  │                     │  Hash    │  H4 = H(H3 || H4) ← Publiée      │   │
│  │                     └────┬─────┘                                    │   │
│  │                    ┌─────┴─────┐                                    │   │
│  │               ┌────┴────┐ ┌────┴────┐                                │   │
│  │               │  H1     │ │  H2     │                                │   │
│  │               │ (09:00) │ │(10:00)  │                                │   │
│  │               └────┬────┘ └────┬────┘                                │   │
│  │              ┌─────┴────┐ ┌─────┴────┐                               │   │
│  │         ┌────┴────┐┌────┴────┐┌────┴────┐                            │   │
│  │         │Leaf 1   ││Leaf 2   ││Leaf N   │ ...                       │   │
│  │         │evt_xxx ││evt_yyy  ││evt_zzz  │                            │   │
│  │         └─────────┘└─────────┘└─────────┘                            │   │
│  │                                                                      │   │
│  │   Chaque heure: Publication Root Hash (timestamp + signature)       │   │
│  │                                                                      │   │
│  └─────────────────────────────┬───────────────────────────────────────┘   │
│                                │                                            │
│                                ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    PUBLICATION QUOTIDIENNE                         │   │
│  │                                                                      │   │
│  │   ┌──────────────────────────────────────────────────────────────┐  │   │
│  │   │ ROOT HASH QUOTIDIEN (Journal Officiel / blockchain)         │  │   │
│  │   │                                                               │  │   │
│  │   │ {                                                             │  │   │
│  │   │   "date": "2026-02-23",                                       │  │   │
│  │   │   "root_hash": "9f8e7d6c5b4a3...",                           │  │   │
│  │   │   "signature": "RSA_SIGN(sha256, private_key_AUDIT)",       │  │   │
│  │   │   "event_count": 15432,                                       │  │   │
│  │   │   "previous_hash": "8e7d6c5b4a3..."                          │  │   │
│  │   │ }                                                             │  │   │
│  │   │                                                               │  │   │
│  │   │ Publication: Journal Officiel + Blockchain consortium       │  │   │
│  │   └──────────────────────────────────────────────────────────────┘  │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 6.2 Exemple de Log Immuable

```json
{
  "log_entry": {
    "entry_id": "le_20260223143021457a89",
    "version": "1.0",
    "timestamp_unix": 1736687421,
    "timestamp_iso": "2026-02-23T14:30:21.457Z",
    "signature_algorithm": "RSA-SHA256",
    
    "event": {
      "event_id": "evt_20260223_143021_a7f9",
      "event_type": "ACCOUNT_QUERY",
      "event_version": "1.0"
    },
    
    "actor": {
      "agent_id": "AGENT_4571",
      "agent_name": "Jean DUPONT",
      "agent_org": "GENDARMERIE_NATIONALE",
      "org_code": "GND_075",
      "mission_id": "MIS_2026_0234",
      "mission_type": "ENQUETE_JUDICIAIRE",
      "mission_authorization": "JUG_2026_0156"
    },
    
    "request": {
      "query_type": "SEARCH_BY_NAME",
      "query_params_hash": "sha256:a1b2c3d4e5f6...",
      "query_params_encrypted": "gpg:AES256:xxxxx...",
      "justification": "Enquête disparition",
      "result_limit": 50,
      "actual_results": 12
    },
    
    "context": {
      "ip_address": "192.168.45.123",
      "ip_geolocation": {
        "country": "FR",
        "region": "IDF",
        "city": "PARIS"
      },
      "device_fingerprint": "fp_9a7b3c2d1e8",
      "device_platform": "WINDOWS_11",
      "mfa_method": "FIDO2_HW_KEY",
      "session_id": "sess_a1b2c3d4e5"
    },
    
    "integrity": {
      "content_hash": "sha256:b2c3d4e5f6a7b8c9...",
      "previous_entry_hash": "sha256:a1b2c3d4e5f6g7h8...",
      "merkle_proof": [
        {
          "side": "right",
          "hash": "sha256:c3d4e5f6a7b8c9d0..."
        }
      ]
    },
    
    "compliance": {
      "gdpr_legal_basis": "MISSION_PUBLIQUE",
      "retention_period_years": 10,
      "anonymization_date": "2036-02-23T00:00:00Z"
    }
  }
}
```

---

## 7. Stratégie de Réponse Automatique

### 7.1 Matrice de Réponse

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    STRATÉGIE DE RÉPONSE AUTOMATIQUE                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  NIVEAU 1: AVERTISSEMENT                                                    │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Déclencheur: > 30 requêtes/heure                                   │   │
│  │  Actions:                                                            │   │
│  │    - Notification agent (email + popup)                             │   │
│  │    - Augmentation niveau logging                                   │   │
│  │    - Message warning dans réponse API                               │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  NIVEAU 2: REVÁLIDATION                                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Déclencheur: > 45 requêtes/heure OU pattern suspect               │   │
│  │  Actions:                                                            │   │
│  │    - Demande re-authentification MFA                                │   │
│  │    - Réduction temporaire du périmètre                             │   │
│  │    - Alerte superviseur hiérarchique                               │   │
│  │    - Escalade SOC (niveau 1)                                        │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  NIVEAU 3: BLOQUAGE TEMPORAIRE                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Déclencheur: > 50 requêtes/heure OU nouvelle IP anormale          │   │
│  │  Actions:                                                            │   │
│  │    - Suspension compte 15 minutes                                   │   │
│  │    - Invalidation tous tokens actifs                                │   │
│  │    - Notification superviseur immédiat                              │   │
│  │    - Blocage IP si malveillant                                      │   │
│  │    - Création ticket incident SOC                                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  NIVEAU 4: REVOCATION COMPLÈTE                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Déclencheur: Extraction massive OU compromission confirmée       │   │
│  │  Actions:                                                            │   │
│  │    - Révocation définitive compte                                   │   │
│  │    - Invalidation certificats                                      │   │
│  │    - Révocation devicebinding                                       │   │
│  │    - Notification DIRECTE hiérarchie + DSI                          │   │
│  │    - Rapport automatique autorités                                  │   │
│  │    - Archivage forensic complet                                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  FLUX D'ESCALADE                                                            │
│                                                                             │
│       ┌──────┐    ┌──────┐    ┌──────┐    ┌──────┐                        │
│       │ L1   │───▶│ L2   │───▶│ L3   │───▶│ L4   │                        │
│       │Warning│    │MFA   │    │Block │    │Revoke│                        │
│       └──────┘    └──────┘    └──────┘    └──────┘                        │
│         │           │           │           │                              │
│         └───────────┴───────────┴───────────┘                              │
│                         │                                                   │
│                         ▼                                                   │
│              ┌──────────────────────┐                                       │
│              │    SOC 24/7           │                                       │
│              │    + NOTIFICATIONS    │                                       │
│              └──────────────────────┘                                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 8. Modèle de Données par Périmètre

### 8.1 Structure de Micro-Segmentation

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    MICRO-SEGMENTATION DES DONNÉES                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    VAULTS INDÉPENDANTS                             │   │
│  │                                                                      │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │   │
│  │  │   VAULT      │  │   VAULT      │  │   VAULT      │               │   │
│  │  │  FISCALITÉ   │  │   JUSTICE    │  │   POLICE     │               │   │
│  │  │              │  │              │  │              │               │   │
│  │  │ - Impôt      │  │ - PJ         │  │ - GN         │               │   │
│  │  │ - Douanes    │  │ - Tribunal   │  │ - Police     │               │   │
│  │  │ - URSSAF     │  │ - Procès     │  │ - Douanes    │               │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘               │   │
│  │                                                                      │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │   │
│  │  │   VAULT      │  │   VAULT      │  │   VAULT      │               │   │
│  │  │   BANQUE     │  │   AUTRES     │  │   AUDIT      │               │   │
│  │  │   CENTRALE   │  │  MINISTÈRES  │  │   EXTERNE    │               │   │
│  │  │              │  │              │  │              │               │   │
│  │  │ - Supervision│  │ - Travail    │  │ - Cour des   │               │   │
│  │  │ - BCE        │  │ - Santé      │  │   Comptes    │               │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘               │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  RÈGLES D'ACCÈS PAR VAULT                                                   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  FISCALITÉ                                                            │   │
│  │  ├── Accès: Agents agréés DFiP, DGDDI, URSSAF                     │   │
│  │  ├── Périmètre: Contribivables zone géographique                  │   │
│  │  ├── Type requêtes: IBAN, nom, NIR (avec motif)                   │   │
│  │  └── Export: INTERDIT (affichage uniquement)                      │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │  JUSTICE                                                              │   │
│  │  ├── Accès: Magistrats, greffiers (sur commission)                │   │
│  │  ├── Périmètre: Dossier judiciaire en cours                        │   │
│  │  ├── Type requêtes: IBAN, nom, NIR, historique complet            │   │
│  │  └── Export: Autorisé avec mention (para. judicial)               │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │  POLICE/GENDARMERIE                                                  │   │
│  │  ├── Accès: Officiers de police judiciaire                         │   │
│  │  ├── Périmètre: Enquête en cours                                   │   │
│  │  ├── Type requêtes: IBAN, nom                                      │   │
│  │  └── Export: INTERDIT (affichage uniquement)                      │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │  BANQUE CENTRALE                                                     │   │
│  │  ├── Accès: Agents Autorité contrôle prudentiel                    │   │
│  │  ├── Périmètre: Établissements supervisés                         │   │
│  │  ├── Type requêtes: Agrégats statistiques                          │   │
│  │  └── Export: Statistiques anonymisées                             │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 9. Modèle de Règles Déterministes (CRUE)

### 9.1 Spécification du Moteur de Règles

```
┌─────────────────────────────────────────────────────────────────────────────┐
│              MOTEUR DE RÈGLES DÉTERMINISTES (CRUE)                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  PRINCIPES                                                                │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  1. Immuabilité: Les règles ne peuvent être modifiées runtime    │   │
│  │  2. Versionnage: Chaque规则est versionnée et signée               │   │
│  │  3. Non-contournabilité: Pas de override ou bypass                 │   │
│  │  4. Atomicité: Toutes les règles appliquées ou aucune             │   │
│  │  5. Traçabilité: Chaque décision est loguée immuablement          │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  RÈGLES IMPLEMENTÉES                                                      │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  RÈGLE #1: VOLUME_MAX                                              │   │
│  │  ─────────────────────────────────────────────────────────────────  │   │
│  │  SI: agent.nb_requetes_1h >= 50                                    │   │
│  │  ALORS: REJETER with code "VOLUME_EXCEEDED"                       │   │
│  │  EXCEPTION: Non                                                    │   │
│  │  VERSION: 1.2.0 (signée par Autorité_Règles)                      │   │
│  │  DATE_VALIDATION: 2026-01-15                                       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  RÈGLE #2: JUSTIFICATION_OBLIGATOIRE                               │   │
│  │  ─────────────────────────────────────────────────────────────────  │   │
│  │  SI: requête.type IN [SEARCH_BY_NAME, SEARCH_BY_NIR]             │   │
│  │  ET: requête.justification EST NULL OU justification.longueur < 10│  │
│  │  ALORS: REJETER with code "JUSTIFICATION_REQUIRED"               │   │
│  │  VERSION: 1.1.0                                                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  RÈGLE #3: INTERDICTION_EXPORT_BRUT                               │   │
│  │  ─────────────────────────────────────────────────────────────────  │   │
│  │  SI: requête.format_export IN [CSV, XML, JSON_BULK]              │   │
│  │  ALORS: REJETER with code "EXPORT_FORBIDDEN"                      │   │
│  │  VERSION: 2.0.0                                                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  RÈGLE #4: MISSION_ACTIVE                                         │   │
│  │  ─────────────────────────────────────────────────────────────────  │   │
│  │  SI: NOT EXISTS(SELECT 1 FROM missions m                          │   │
│  │            WHERE m.id = session.mission_id                       │   │
│  │            AND m.date_fin >= NOW()                                │   │
│  │            AND m.statut = 'ACTIVE')                               │   │
│  │  ALORS: REJETER with code "MISSION_INACTIVE"                      │   │
│  │  VERSION: 1.0.0                                                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  RÈGLE #5: DOUBLE_VALIDATION_EXTRACTION                           │   │
│  │  ─────────────────────────────────────────────────────────────────  │   │
│  │  SI: (agent.nb_requetes_1h >= 30                                  │   │
│  │       ET requête.result_count >= 10)                              │   │
│  │  ALORS: DEMANDER_VALIDATION_CHEF                                   │   │
│  │  VERSION: 1.0.0                                                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  RÈGLE #6: PERIMETRE_GEOGRAPHIQUE                                 │   │
│  │  ─────────────────────────────────────────────────────────────────  │   │
│  │  SI: agent.perimetre = 'REGIONAL'                                 │   │
│  │  ET: compte.departement NOT IN agent.departements                 │   │
│  │  ALORS: REJETER with code "SCOPE_VIOLATION"                       │   │
│  │  VERSION: 1.0.0                                                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  MOTEUR D'EXÉCUTION                                                        │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Language: Drools / OpenL Tablets (règles métier)                 │   │
│  │  Stockage: Blockchain consortium (version + hash)                  │   │
│  │  Validation: Comité de gouvernance (3/5 signatures)              │   │
│  │  Mise à jour: Hebdomadaire (fenêtre maintenance)                  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 10. Architecture Event-Driven

### 10.1 Modèle d'Événements

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ARCHITECTURE EVENT-DRIVEN                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  BUS D'ÉVÉNEMENTS (Apache Kafka)                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                                                                      │   │
│  │  Topics partitionnés par organisme:                                │   │
│  │                                                                      │   │
│  │  ┌────────────────────┐  ┌────────────────────┐                     │   │
│  │  │ rnbc.events.fiscal │  │ rnbc.events.justice│                    │   │
│  │  │ rnbc.events.police │  │ rnbc.events.banque │                    │   │
│  │  │ rnbc.events.audit  │  │ rnbc.events.admin  │                    │   │
│  │  └────────────────────┘  └────────────────────┘                     │   │
│  │                                                                      │   │
│  │  Rétention: 7 ans (conformité RGPD)                                │   │
│  │  Chiffrement: AES-256 at rest                                      │   │
│  │  Replication: 3 répliques minimum                                   │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  TYPES D'ÉVÉNEMENTS                                                        │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  EVENT: ACCOUNT_QUERY                                              │   │
│  │  ─────────────────────────────────────────────────────────────────  │   │
│  │  {                                                                 │   │
│  │    "event": "ACCOUNT_QUERY",                                       │   │
│  │    "event_version": "1.0",                                         │   │
│  │    "timestamp": "2026-02-23T14:30:21.123Z",                       │   │
│  │    "actor_id": "AGENT_4571",                                       │   │
│  │    "actor_org": "GENDARMERIE_NATIONALE",                          │   │
│  │    "mission_id": "MIS_2026_0234",                                  │   │
│  │    "scope": "REGION_75",                                           │   │
│  │    "query_type": "SEARCH_BY_NAME",                                 │   │
│  │    "volume": 12,                                                    │   │
│  │    "result_count": 5,                                               │   │
│  │    "hash": "sha256:a7f9b3..."                                      │   │
│  │  }                                                                 │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  EVENT: AUTHENTICATION_SUCCESS / FAILURE                          │   │
│  │  EVENT: SESSION_START / END                                        │   │
│  │  EVENT: RULE_VIOLATION_DETECTED                                    │   │
│  │  EVENT: ANOMALY_DETECTED                                            │   │
│  │  EVENT: ACCOUNT_SUSPENDED                                           │   │
│  │  EVENT: TOKEN_REVOKED                                               │   │
│  │  EVENT: PERIMETER_CHANGE                                           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  CONSOMMATEURS                                                             │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    ┌─────────────┐                                   │   │
│  │                    │   SIEM      │                                   │   │
│  │                    │ Splunk/     │◀── Logs agrégés                   │   │
│  │                    │ QRadar      │                                   │   │
│  │                    └─────────────┘                                   │   │
│  │                          │                                           │   │
│  │                    ┌─────────────┐                                   │   │
│  │                    │   AI/ML     │                                   │   │
│  │                    │ Anomaly     │◀── Métriques temps réel          │   │
│  │                    │ Detection   │                                   │   │
│  │                    └─────────────┘                                   │   │
│  │                          │                                           │   │
│  │                    ┌─────────────┐                                   │   │
│  │                    │ Immutable   │                                   │   │
│  │                    │ Logger      │◀── Hachage + Merkle              │   │
│  │                    └─────────────┘                                   │   │
│  │                          │                                           │   │
│  │                    ┌─────────────┐                                   │   │
│  │                    │ Automated   │                                   │   │
│  │                    │ Response    │◀── Décisions automatisées        │   │
│  │                    └─────────────┘                                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 11. Synthèse des Composants

| Couche | Composant | Technology Recommandée |
|--------|-----------|----------------------|
| **Identity** | IdP National | Keycloak / Azure AD B2C (FIDO2) |
| **Auth** | Certificats Hardware | YubiKey / Thales Luna |
| **Gateway** | API Gateway | Kong / Apigee / AWS API Gateway |
| **PAM** | Bastion + Session Rec | CyberArk / BeyondTrust |
| **Contrôle** | Rules Engine | Drools / OpenL Tablets |
| **Data** | Vault Segmenté | HashiCorp Vault + PostgreSQL |
| **Logging** | Immutable Log | Chainalysis / custom blockchain |
| **Events** | Event Bus | Apache Kafka |
| **Detection** | AI/ML | Splunk Enterprise Security / custom |
| **SIEM** | Monitoring | Splunk / QRadar |
| **Response** | SOAR | Splunk SOAR / Palo Alto XSOAR |
| **Network** | Segmentation | VMWare NSX / Cisco ACI |

---

*Document généré pour le projet de modernisation du Registre National des Comptes Bancaires*
*Version: 1.0 | Date: 2026-02-23 | Classification: Usage Interne*
