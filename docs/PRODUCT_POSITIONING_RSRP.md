# 🏛️ R-SRP: RNBC Secure Registry Platform
## Plateforme d'Infrastructure de Registre Souverain Compliant-by-Design

---

## 📋 Positionnement Stratégique

### Vision

**R-SRP** (RNBC Secure Registry Platform) est une plateforme d'infrastructure souveraine Zero-Trust conçue pour les registres nationaux sensibles de l'Union Européenne. Elle offre une protection maximale des données critiques tout en garantissant la conformité réglementaire européenne.

### Proposition de Valeur

> *"Transformez vos registres nationaux en infrastructures souveraines, traçables, prouvables et auto-défidentes."*

### Marchés Cibles

| Segment | Description | Potentiel |
|---------|-------------|-----------|
| **Ministères des Finances** | Registres fiscaux, douanes, URSSAF | €€€ |
| **Ministères de la Justice** | Casier judiciaire, registres tribunaux | €€ |
| **Autorités de régulation** | ACPR, AMF, BCE (supervision) | €€ |
| **Registres nationaux** | FICOBA, cadastre, RCS, bénéficiaires effectifs | €€€ |
| **Agences AML** | TRACFIN, cellules de renseignement financier | €€ |

---

## 🏗️ Architecture Modulaire

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    R-SRP - PLATEFORME COMPLÈTE                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    MODULES R-SRP                                     │   │
│  │                                                                      │   │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐                │   │
│  │  │    R-SRP     │ │    R-SRP     │ │    R-SRP     │                │   │
│  │  │   Identity   │ │  Deterministic│ │    Proof     │                │   │
│  │  │    Secure    │ │    Control    │ │    Ledger    │                │   │
│  │  │    (Module 1)│ │    Engine     │ │   (Module 3) │                │   │
│  │  │              │ │   (Module 2)  │ │              │                │   │
│  │  └──────────────┘ └──────────────┘ └──────────────┘                │   │
│  │                                                                      │   │
│  │  ┌──────────────┐ ┌──────────────┐                                │   │
│  │  │    R-SRP     │ │    R-SRP     │                                │   │
│  │  │  Behavioral  │ │   Privilege  │                                │   │
│  │  │   Shield     │ │    Guard     │                                │   │
│  │  │   (Module 4) │ │   (Module 5) │                                │   │
│  │  └──────────────┘ └──────────────┘                                │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                 INFRASTRUCTURE COMMUNALE                             │   │
│  │                                                                      │   │
│  │  API Gateway │ Event Bus │ SIEM │ Monitoring │ Blockchain Consortium│   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔐 MODULE 1: R-SRP Identity Secure

### Description

Couche d'authentification Zero-Trust souveraine avec vérification continue et contrôle d'accès basé sur la mission.

### Fonctionnalités

| Fonctionnalité | Description |
|---------------|-------------|
| **IdP Durci** | Identity Provider national, contrôlé par l'État |
| **MFA FIDO2 Obligatoire** | Authentification hardware (YubiKey, Thales) |
| **Device Binding** | Liaison sécurisée appareil-utilisateur |
| **Mission-Based Access** | Accès conditionné à mission active |
| **Context Validation** | IP, géolocalisation, horaire, comportement |

### Spécifications Techniques

- Déploiement: On-premise ou cloud souverain (OVH, Scaleway)
- Protocoles: SAML 2.0 + OIDC
- Hardware: YubiKey 5 Series / Thales IDPrime
- Certification: eIDAS (TSM)

### Conformité Réglementaire

| Réglementation | Alignement |
|----------------|------------|
| **RGPD Art. 32** | Contrôle d'accès pseudonymisé |
| **eIDAS 2.0** | Conformité niveau substantiel |
| **NIS2** | Gestion d'identité sécurisée |

### Packaging

| Édition | Fonctionnalités | Prix (Guide) |
|---------|-----------------|--------------|
| **Standard** | IdP + MFA + Device Binding | 200-400 K€ |
| **Premium** | + Mission-Based + Context | 400-600 K€ |
| **Enterprise** | + Multi-annuaires + Haute dispo | 600-900 K€ |

---

## 🧠 MODULE 2: R-SRP Deterministic Control Engine

### Description

Moteur de règles déterministes inviolables - **différenciateur stratégique** de la plateforme. Ce module implémente des contrôles automatisés non contournables.

### Fonctionnalités

| Fonctionnalité | Description |
|---------------|-------------|
| **Règles Immuables** | Versionnées, signées, non modifiables runtime |
| **Catalogue Paramétrable** | 10+ règles prêtes (volume, export, périmètre) |
| **Blocage Auto Exfiltration** | Interdiction export CSV/XML massif |
| **Justification Obligatoire** | Traçabilité de chaque requête |
| **Double Validation** | Approbation superviseur pour volumes élevés |

### Catalogue de Règles Inclus

| Règle | Description | Impact |
|-------|-------------|--------|
| VOLUME_MAX | Max 50 requêtes/agent/heure | Blocage |
| EXPORT_INTERDIT | Pas d'export massif | Blocage |
| JUSTIFICATION_OBLIG | Texte obligatoire | Blocage |
| PERIMETRE_GEO | Respect zone mission | Blocage |
| MISSION_ACTIVE | Vérification valide | Blocage |
| TEMPS_REQUETE | Max 10 secondes | Warning |
| SEQUENCE_INHABITUELLE | Détection pattern | Alert |

### Conformité Réglementaire

| Réglementation | Alignement |
|----------------|------------|
| **DORA Art. 9** | Contrôles automatisés |
| **AMLD6** | Mesures de prévention blanchiment |
| **Cyber Resilience Act** | Security by design |

### Packaging

| Édition | Fonctionnalités | Prix (Guide) |
|---------|----------------|--------------|
| **Essential** | 5 règles de base | 150-250 K€ |
| **Professional** | 10 règles + custom | 250-400 K€ |
| **Regulatory** | + Conformité DORA/AMLD | 400-600 K€ |

---

## 🔒 MODULE 3: R-SRP Proof Ledger

### Description

Système de journalisation immuable avec preuve cryptographique juridiquement exploitable.

### Fonctionnalités

| Fonctionnalité | Description |
|---------------|-------------|
| **Append-Only Logging** | Écriture impossible à modifier |
| **Merkle Tree Horaire** | Preuve d'intégrité |
| **Publication Quotidienne** | Hash racine publié JO + Blockchain |
| **Signature Qualifiée** | HSM + TSA eIDAS |
| **Vérification API** | Preuve à la demande |

### Architecture de Preuve

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PREUVE CRYPTOGRAPHIQUE                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  CHAÎNE:                                                                   │
│  Entry(n) → H(n) → Chain → Merkle Tree → Root Hash → Publication          │
│                                                                             │
│  PUBLICATION:                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Journal Officiel (France) - Publication quotidienne                │   │
│  │  Blockchain Consortium (Hyperledger Fabric)                         │   │
│  │  Service Web Vérification (API)                                    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  VALEUR PROBANTE:                                                          │
│  ✓ Accepté en justice                                                     │
│  ✓ Horodatage TSA qualifié eIDAS                                          │
│  ✓ Non-répudiation garantie                                               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Conformité Réglementaire

| Réglementation | Alignement |
|----------------|------------|
| **RGPD Art. 30** | Registre traitements |
| **eIDAS** | Signature électronique qualifié |
| **DORA Art. 24** | Conservation journaux |

### Packaging

| Édition | Fonctionnalités | Prix (Guide) |
|---------|----------------|--------------|
| **Basic** | Logging + Hachage | 200-300 K€ |
| **Advanced** | + Merkle + Publication JO | 300-500 K€ |
| **Premium** | + Blockchain + Preuve qualifiée | 500-800 K€ |

---

## 🤖 MODULE 4: R-SRP Behavioral Shield

### Description

Système de détection d'anomalies par intelligence artificielle pour défense comportementale proactive.

### Fonctionnalités

| Fonctionnalité | Description |
|---------------|-------------|
| **LSTM Détection Séquence** | Identifie patterns inhabituels |
| **Autoencoder Novelty** | Détecte comportements jamais vus |
| **Isolation Forest** | Scoring comportemental |
| **Risk Scoring** | Agrégation multi-sources |
| **Intégration SIEM** | Alertes en temps réel |

### Modèles ML

| Modèle | Détection | Seuil |
|--------|-----------|-------|
| **LSTM Séquence** | Séquence anormale | > 0.7 score |
| **Autoencoder** | Novel patterns | > 0.5 reconstruction error |
| **Isolation Forest** | Anomalies globales | > 0.6 anomaly score |

### Métriques de Performance

| Métrique | Cible |
|----------|-------|
| Recall | > 95% |
| False Positive Rate | < 5% |
| Latence inference | < 200ms |
| Disponibilité | 99.9% |

### Conformité Réglementaire

| Réglementation | Alignement |
|----------------|------------|
| **NIS2** | Détection incidents |
| **DORA** | Threat intelligence |
| **RGPD Art. 35** | AIPD (si traitementlarge) |

### Packaging

| Édition | Fonctionnalités | Prix (Guide) |
|---------|----------------|--------------|
| **Detection** | 1 modèle ML | 250-350 K€ |
| **Defense** | 3 modèles + scoring | 350-500 K€ |
| **Autonomous** | + Réponse auto SOAR | 500-700 K€ |

---

## 🛡️ MODULE 5: R-SRP Privilege Guard

### Description

Gestion des accès privilégiés Just-in-Time avec isolation des sessions et enregistrement complet.

### Fonctionnalités

| Fonctionnalité | Description |
|---------------|-------------|
| **Zero Persistent Privilege** | Accès temporaire uniquement |
| **Just-in-Time (JIT)** | Attribution dynamique |
| **Session Isolation** | Bastion dédié |
| **Session Recording** | Vidéo + commandes |
| **Auto-Révocation** | Fin automatique + anomalie |

### Workflow JIT

```
DEMANDE → APPROBATION → ATTRIBUTION TEMPO → UTILISATION → REVOCATION
```

### Conformité Réglementaire

| Réglementation | Alignement |
|----------------|------------|
| **NIS2** | Gestion privileges |
| **DORA** | Accès IAM |
| **ISO 27001** | Contrôle accès |

### Packaging

| Édition | Fonctionnalités | Prix (Guide) |
|---------|----------------|--------------|
| **Standard** | JIT + Bastion | 300-450 K€ |
| **Complete** | + Recording + Auto-revoke | 450-600 K€ |
| **Enterprise** | + Multi-vault + HA | 600-900 K€ |

---

## 💰 Modèle Économique

### Option A: Licence On-Premise

| Configuration | Licence Initiale | Maintenance (an) |
|--------------|-----------------|------------------|
| **Essentiel** (3 modules) | 1.5 - 3 M€ | 18-22% |
| **Standard** (4 modules) | 2.5 - 5 M€ | 18-22% |
| **Premium** (5 modules) | 4 - 8 M€ | 18-22% |
| **Full Stack** | 6 - 12 M€ | 18-22% |

### Option B: SaaS Souverain (Cloud Certifié)

| Tier | Agents | Prix/Mois | Inclus |
|------|--------|-----------|--------|
| **Starter** | < 500 | 15-25 K€ | Module 1+2 |
| **Professional** | 500-5000 | 25-80 K€ | Module 1+2+3 |
| **Enterprise** | 5000+ | Sur devis | Tous modules |

### Option C: Modèle Hybride

- **Licence**: 50-70% du prix on-premise
- **Intégration**: 100-300 K€
- **Support SOC 24/7**: 150-300 K€/an

---

## 🇪🇺 Conformité Réglementaire Globale

### Matrice de Conformité

| Réglementation | Module 1 | Module 2 | Module 3 | Module 4 | Module 5 |
|---------------|----------|----------|----------|----------|----------|
| **RGPD** | ✓ | ✓ | ✓ | ✓ | ✓ |
| **NIS2** | ✓ | ✓ | ✓ | ✓ | ✓ |
| **DORA** | - | ✓ | ✓ | ✓ | - |
| **eIDAS 2.0** | ✓ | - | ✓ | - | - |
| **AMLD6** | - | ✓ | - | ✓ | - |
| **Cyber Resilience Act** | ✓ | ✓ | - | ✓ | ✓ |

### Certifications Cibles

| Certification | Statut | Échéance |
|--------------|--------|----------|
| ISO 27001 | Requis | Phase 2 |
| eIDAS (TSP) | Requis | Phase 3 |
| SecNumCloud | Optionnel | Phase 3 |

---

## 🚀 Roadmap Produit

### Phase 1: Foundation (Q1-Q2 2026)
- [ ] Module 1: Identity Secure (GA)
- [ ] Module 3: Proof Ledger (GA)
- [ ] Certification ISO 27001

### Phase 2: Intelligence (Q3-Q4 2026)
- [ ] Module 2: Deterministic Engine (GA)
- [ ] Module 4: Behavioral Shield (Beta)
- [ ] Certification eIDAS

### Phase 3: Autonomy (Q1-Q2 2027)
- [ ] Module 5: Privilege Guard (GA)
- [ ] Module 4: Behavioral Shield (GA)
- [ ] Option SecNumCloud

---

## 📞 Contact Commercial

### Pour toute démonstration ou devis :

**Email**: commercial@r-srp.eu  
**Téléphone**: +33 1 XX XX XX XX  
**Web**: https://r-srp.eu

---

*R-SRP: Sovereign Registry Infrastructure - Compliant-by-Design*
*Version: 1.0 | Date: 2026-02-23*
