# 🏛️ R-SRP: RNBC Secure Registry Platform
## Plateforme d'Infrastructure de Registre Souverain Compliant-by-Design

## 📋 Résumé Exécutif

Ce projet définit l'architecture sécurisée de nouvelle génération pour un registre national de comptes bancaires (similaire à FICOBA), conçue pour :

- ✅ **Empêcher l'exploitation d'identifiants compromis** (MFA FIDO2 + Device Binding)
- ✅ **Réduire drastiquement le périmètre d'accès** (Micro-segmentation)
- ✅ **Détecter toute extraction anormale** (IA + Règles déterministes)
- ✅ **Rendre chaque consultation traçable et juridiquement vérifiable** (Logs immuables + Preuve cryptographique)
- ✅ **Intégrer un modèle Zero-Trust complet** (Vérification continue)

---

## 🎯 Transformation en Produit Commercial

L'architecture a été transformée en **plateforme modulable commercialisable** pour les États membres de l'UE. Voir le document de positionnement marketing :

### 📦 R-SRP: RNBC Secure Registry Platform

| Module | Nom Commercial | Description |
|--------|--------------|-------------|
| 1 | **R-SRP Identity Secure** | IdP durci, MFA FIDO2, Device binding, Mission-based access |
| 2 | **R-SRP Deterministic Control Engine** | Moteur règles inviolables, Catalogue réglementaire |
| 3 | **R-SRP Proof Ledger** | Logging append-only, Merkle trees, Signature qualifiée |
| 4 | **R-SRP Behavioral Shield** | LSTM, Isolation Forest, Risk scoring |
| 5 | **R-SRP Privilege Guard** | JIT, Bastion, Session recording, Auto-revocation |

### Prix Guide (Licence On-Premise)

| Configuration | Licence | Maintenance/an |
|--------------|---------|----------------|
| Essentiel (3 modules) | 1.5 - 3 M€ | 18-22% |
| Standard (4 modules) | 2.5 - 5 M€ | 18-22% |
| Premium (5 modules) | 4 - 8 M€ | 18-22% |

---

## 📁 Livrables Produits

| Document | Description | Fichier |
|----------|-------------|---------|
| **Architecture Principale** | Vue d'ensemble, principes, composants, flux | [`ARCHITECTURE_RNBC_ZeroTrust.md`](ARCHITECTURE_RNBC_ZeroTrust.md) |
| **Positionnement Produit** | Module commercial, tarifs, conformité UE | [`PRODUCT_POSITIONING_RSRP.md`](PRODUCT_POSITIONING_RSRP.md) |
| **Plan de Déploiement** | Déploiement en 3 phases (18 mois) | [`DEPLOYMENT_PLAN_3PHASES.md`](DEPLOYMENT_PLAN_3PHASES.md) |
| **Stack Technologique** | Technologies recommandées par composant | [`TECHNOLOGY_STACK.md`](TECHNOLOGY_STACK.md) |
| **Spécification IAM** | Identity Layer Zero-Trust (FIDO2, device binding, contexte) | [`SPEC_IDENTITY_LAYER.md`](SPEC_IDENTITY_LAYER.md) |
| **Spécification CRUE** | Moteur de règles déterministes inviolables | [`SPEC_CRUE_ENGINE.md`](SPEC_CRUE_ENGINE.md) |
| **Spécification Logging** | Journalisation immuable + preuve cryptographique | [`SPEC_IMMUTABLE_LOGGING.md`](SPEC_IMMUTABLE_LOGGING.md) |
| **Spécification IA** | Détection d'anomalies par Machine Learning | [`SPEC_ANOMALY_DETECTION.md`](SPEC_ANOMALY_DETECTION.md) |
| **Spécification PAM** | Gestion des accès privilégiés JIT | [`SPEC_PAM.md`](SPEC_PAM.md) |

---

## 🏗️ Composants de l'Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ARCHITECTURE ZERO-TRUST RNBC                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ╔═══════════════════════════════════════════════════════════════════════╗ │
│  ║                     ZONE DEMATERIALISÉE                               ║ │
│  ║  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐            ║ │
│  ║  │ FISCALITÉ│  │ JUSTICE  │  │ POLICE   │  │ AUTRES   │            ║ │
│  ║  │ Portail  │  │ Portail  │  │ Portail  │  │ Portail  │            ║ │
│  ║  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘            ║ │
│  ╚════════╪════════════╪════════════╪══════════════════════════════════╝ │
│           │              │              │                                   │
│           ▼              ▼              ▼                                   │
│  ╔═══════════════════════════════════════════════════════════════════════╗ │
│  ║              IDENTITY PROVIDER NATIONAL                              ║ │
│  ║        (FIDO2 + Certificat + Device Binding + Context)             ║ │
│  ╚════════════════════════════════════╪════════════════════════════════╝ │
│                                        │                                    │
│                                        ▼                                    │
│  ╔═══════════════════════════════════════════════════════════════════════╗ │
│  ║                    API GATEWAY CENTRALISÉE                            ║ │
│  ║              (mTLS + WAF + Rate Limiting + JWT)                     ║ │
│  ╚════════════════════════════════════╪════════════════════════════════╝ │
│                                        │                                    │
│                                        ▼                                    │
│  ╔═══════════════════════════════════════════════════════════════════════╗ │
│  ║           DETERMINISTIC CONTROL ENGINE (CRUE)                       ║ │
│  ║          (Règles non contournables + Validation croisée)           ║ │
│  ╚════════════════════════════════════╪════════════════════════════════╝ │
│                                        │                                    │
│          ┌─────────────────────────────┼────────────────────────────┐    │
│          ▼                             ▼                            ▼    │
│  ┌──────────────┐            ┌──────────────┐            ┌──────────────┐ │
│  │   MICRO-SEG  │            │   MICRO-SEG   │            │   MICRO-SEG  │ │
│  │   FISCALITÉ  │            │   JUSTICE     │            │   POLICE     │ │
│  │  API Service │            │  API Service  │            │  API Service │ │
│  └──────┬───────┘            └──────┬───────┘            └──────┬───────┘ │
│         │                          │                          │          │
│         ▼                          ▼                          ▼          │
│  ╔═══════════════════════════════════════════════════════════════════════╗ │
│  ║                  DATA LAYER MICRO-SEGMENTÉE                           ║ │
│  ║         (Vaults FISCALITÉ / JUSTICE / POLICE / AUTRES)             ║ │
│  ╚═══════════════════════════════════════════════════════════════════════╝ │
│                                                                             │
│  ╔═══════════════════════════════════════════════════════════════════════╗ │
│  ║               COUCHE OBSERVABILITÉ & DÉFENSE                          ║ │
│  ║  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                ║ │
│  ║  │ IMMUTABLE    │  │   ANOMALY    │  │   EVENT      │                ║ │
│  ║  │ LOGGING      │  │  DETECTION   │  │    BUS       │                ║ │
│  ║  │(Merkle Tree)│  │    (AI/ML)   │  │   (Kafka)    │                ║ │
│  ║  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘                ║ │
│  ╚════════╪══════════════════╪══════════════════╪════════════════════════╝ │
│           │                    │                   │                        │
│           └────────────────────┼───────────────────┘                        │
│                                ▼                                           │
│                       ┌─────────────┐                                      │
│                       │    SOC      │                                      │
│                       │  (Splunk)   │                                      │
│                       └──────┬──────┘                                      │
│                              │                                             │
│                              ▼                                             │
│                       ┌─────────────┐                                      │
│                       │ AUTOMATED   │                                      │
│                       │  RESPONSE   │                                      │
│                       │  (SOAR)     │                                      │
│                       └─────────────┘                                      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🎯 Objectifs Atteints

| Objectif | Mécanisme | Livrable |
|----------|-----------|----------|
| **Empêcher identifiants compromis** | MFA FIDO2 obligatoire + Device binding | [`SPEC_IDENTITY_LAYER.md`](SPEC_IDENTITY_LAYER.md) |
| **Réduire périmètre accès** | Micro-segmentation par Vault | [`ARCHITECTURE_RNBC_ZeroTrust.md`](ARCHITECTURE_RNBC_ZeroTrust.md) |
| **Détecter extraction anormale** | IA (LSTM, Autoencoder, Isolation Forest) | [`SPEC_ANOMALY_DETECTION.md`](SPEC_ANOMALY_DETECTION.md) |
| **Traçabilité juridiquement vérifiable** | Merkle Tree + Publication JO + Blockchain | [`SPEC_IMMUTABLE_LOGGING.md`](SPEC_IMMUTABLE_LOGGING.md) |
| **Modèle Zero-Trust** | Vérification continue à chaque requête | [`SPEC_IDENTITY_LAYER.md`](SPEC_IDENTITY_LAYER.md) |

---

## 🔒 Mécanismes de Sécurité Clés

### 1. Zero-Trust Identity Layer
- ✅ MFA FIDO2 obligatoire
- ✅ Device binding avec attestation
- ✅ Validation contextuelle (IP, géoloc, horaire)
- ✅ Vérification mission active

### 2. Privileged Access Management
- ✅ Accès Just-in-Time (JIT)
- ✅ Sessions isolées via bastion
- ✅ Enregistrement vidéo des sessions
- ✅ Double validation pour volumes élevés

### 3. Micro-Segmentation
- ✅ Vaults dédiés par organisme
- ✅ Requêtes paramétrées (pas de SELECT *)
- ✅ Périmètre géographique obligatoire

### 4. Contrôle Déterministe (CRUE)
- ✅ Règles inviolables versionnées
- ✅ Interdiction export CSV/XML
- ✅ Max 50 requêtes/heure
- ✅ Justification obligatoire

### 5. Journalisation Immuable
- ✅ Hachage chaîne (chaque entrée hash la précédente)
- ✅ Merkle Tree horaire
- ✅ Publication racine quotidienne (JO + Blockchain)
- ✅ Signature HSM + TSA

### 6. Détection IA
- ✅ Modèle LSTM détection de séquence
- ✅ Autoencoder détection novel patterns
- ✅ Isolation Forest scoring comportemental

### 7. Réponse Automatique
- ✅ Réponse automatisée < 30 secondes
- ✅ Révocation immédiate si compromission
- ✅ Notification hiérarchique

---

## 📅 Plan de Déploiement

| Phase | Durée | Focus | Budget Estimé |
|-------|-------|-------|---------------|
| **Phase 1** | 6 mois | Fondations (IdP, API Gateway, Logging) | 2.0-3.3 M€ |
| **Phase 2** | 6 mois | Renforcement (PAM, Micro-seg, CRUE, SIEM) | 1.9-3.0 M€ |
| **Phase 3** | 6 mois | Auto-défense (IA, SOAR, Preuve crypto) | 1.2-1.8 M€ |
| **TOTAL** | **18 mois** | | **5.1-8.1 M€** |

---

## 📊 Métriques Cibles

| Métrique | Avant | Après | Amélioration |
|----------|-------|-------|--------------|
| Surface d'attaque | 100% (accès global) | 15% (segmenté) | -85% |
| Temps détection anomalie | > 24h | < 5 min | -99% |
| Traçabilité | Partielle | 100% (hash + Merkle) | +100% |
| Conformité RGPD | Partielle | 100% | +100% |
| Réponse incident | Manuel (heures) | Automatisé (secondes) | -99% |

---

## 📞 Support

Pour toute question sur cette architecture :
- Consulter les documents de spécification détaillés
- Se référer au plan de déploiement pour les jalons
- Contacter l'équipe architecture sécurité

---

*Document généré pour le projet de modernisation du Registre National des Comptes Bancaires*
*Version: 1.0 | Date: 2026-02-23 | Classification: Usage Interne*

---

## Hardening and Pre-Certification

- Roadmap logique de hardening, conformit� et pr�-certification: [`ROADMAP_HARDENING.md`](ROADMAP_HARDENING.md)
