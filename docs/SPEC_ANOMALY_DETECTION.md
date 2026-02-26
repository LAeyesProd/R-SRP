# 🤖 Spécification: Détection d'Anomalies par IA

## 1. Vue d'Ensemble

Ce document spécifie le système de détection d'anomalies basé sur l'intelligence artificielle, conçu pour identifier les comportements suspects, les extractions massives et les patterns d'attaque émergents en temps réel.

---

## 2. Architecture du Système

### 2.1 Vue d'Ensemble

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ARCHITECTURE DÉTECTION D'ANOMALIES                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                       COUCHE COLLECTE                                │   │
│  │                                                                      │   │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐                 │   │
│  │  │    Kafka    │ │    Logs     │ │   Métriques │                 │   │
│  │  │   Topics    │ │   (ELK)     │ │ Prometheus  │                 │   │
│  │  └──────┬──────┘ └──────┬──────┘ └──────┬──────┘                 │   │
│  │         │                │                │                          │   │
│  │         └────────────────┼────────────────┘                          │   │
│  │                          ▼                                             │   │
│  │               ┌─────────────────┐                                      │   │
│  │               │   Apache Flink  │                                      │   │
│  │               │  Stream Process │                                      │   │
│  │               │                 │                                      │   │
│  │               │  - Enrichment  │                                      │   │
│  │               │  - Aggregation  │                                      │   │
│  │               │  - Feature Eng  │                                      │   │
│  │               └────────┬────────┘                                      │   │
│  └────────────────────────┼───────────────────────────────────────────────┘   │
│                           │                                                │
│                           ▼                                                │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                       COUCHE DÉTECTION                               │   │
│  │                                                                      │   │
│  │  ┌────────────────────────────────────────────────────────────────┐  │   │
│  │  │                    MODÈLES ML                                   │  │   │
│  │  │                                                                 │  │   │
│  │  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │  │   │
│  │  │  │   LSTM       │  │ Autoencoder   │  │  Isolation   │     │  │   │
│  │  │  │  Séquence    │  │   anomaly     │  │   Forest     │     │  │   │
│  │  │  │  Detection   │  │   Detection   │  │   Scoring    │     │  │   │
│  │  │  └──────────────┘  └──────────────┘  └──────────────┘     │  │   │
│  │  │                                                                 │  │   │
│  │  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │  │   │
│  │  │  │   Rules      │  │   Statistical│  │   Behavior   │     │  │   │
│  │  │  │   Engine     │  │   Analysis   │  │   Clustering │     │  │   │
│  │  │  │  (CRUE ext.) │  │               │  │               │     │  │   │
│  │  │  └──────────────┘  └──────────────┘  └──────────────┘     │  │   │
│  │  │                                                                 │  │   │
│  │  └────────────────────────────────────────────────────────────────┘  │   │
│  └───────────────────────────────────────────────────────────────────────┘   │
│                           │                                                │
│                           ▼                                                │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    COUCHE DÉCISION                                  │   │
│  │                                                                      │   │
│  │  ┌────────────────────────────────────────────────────────────────┐  │   │
│  │  │              SCORE DE RISQUE AGREGÉ                             │  │   │
│  │  │                                                                 │  │   │
│  │  │    0-30: VERT (Normal)                                         │  │   │
│  │  │    31-60: ORANGE (Warning)                                     │  │   │
│  │  │    61-80: ROUGE (Elevated)                                     │  │   │
│  │  │    81-100: CRITIQUE (Critical)                                 │  │   │
│  │  │                                                                 │  │   │
│  │  └────────────────────────────────────────────────────────────────┘  │   │
│  └───────────────────────────────────────────────────────────────────────┘   │
│                           │                                                │
│                           ▼                                                │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    COUCHE RÉPONSE                                   │   │
│  │                                                                      │   │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐                 │   │
│  │  │    SOAR     │ │   Blocking   │ │ Notification│                 │   │
│  │  │  Playbooks  │ │   (实时)     │ │   (SOC)     │                 │   │
│  │  └─────────────┘ └─────────────┘ └─────────────┘                 │   │
│  └───────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Modèles de Détection

### 3.1 Modèle LSTM - Détection de Séquence

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    MODÈLE LSTM - DÉTECTION SÉQUENCE                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Objectif: Détecter des séquences de requêtes inhabituelles               │
│                                                                             │
│  Architecture:                                                              │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                                                                      │   │
│  │  INPUT: Séquence de N requêtes (fenêtre glissante 1h)            │   │
│  │  ┌──────────────────────────────────────────────────────────────┐  │   │
│  │  │ [req_1, req_2, req_3, ..., req_N]                           │  │   │
│  │  │   │      │      │          │                                 │  │   │
│  │  │  type  org   time    result                                  │  │   │
│  │  └──────────────────────────────────────────────────────────────┘  │   │
│  │                              │                                        │   │
│  │                              ▼                                        │   │
│  │  ┌─────────────────────────────────────────────────────────────┐  │   │
│  │  │              COUCHES LSTM                                      │  │   │
│  │  │                                                               │  │   │
│  │  │  ┌─────────────────────────────────────────────────────────┐│  │   │
│  │  │  │  LSTM Layer 1 (128 units)                               ││  │   │
│  │  │  │  Dropout: 0.2                                           ││  │   │
│  │  │  └─────────────────────────────────────────────────────────┘│  │   │
│  │  │                           │                                     │   │
│  │  │  ┌─────────────────────────────────────────────────────────┐│  │   │
│  │  │  │  LSTM Layer 2 (64 units)                                ││  │   │
│  │  │  │  Dropout: 0.2                                           ││  │   │
│  │  │  └─────────────────────────────────────────────────────────┘│  │   │
│  │  │                           │                                     │   │
│  │  │  ┌─────────────────────────────────────────────────────────┐│  │   │
│  │  │  │  Dense Layer (32) + ReLU                               ││  │   │
│  │  │  └─────────────────────────────────────────────────────────┘│  │   │
│  │  │                           │                                     │   │
│  │  │                           ▼                                     │   │
│  │  │  ┌─────────────────────────────────────────────────────────┐│  │   │
│  │  │  │  Output: Probability of Anomaly (0-1)                  ││  │   │
│  │  │  └─────────────────────────────────────────────────────────┘│  │   │
│  │  │                                                               │  │   │
│  │  └─────────────────────────────────────────────────────────────┘  │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  CARACTÉRISTIQUES D'ENTRÉE:                                                │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Feature                    Description                Encoding      │   │
│  │  ─────────────────────────────────────────────────────────────────  │   │
│  │  query_type                Type de requête           One-hot        │   │
│  │  time_delta                Temps depuis requête      Normalized     │   │
│  │  result_count              Nombre résultats          Normalized     │   │
│  │  hour_of_day              Heure (0-23)              Cyclic (sin/cos)│   │
│  │  day_of_week              Jour semaine              Cyclic          │   │
│  │  org_type                 Type organisme             Embedding      │   │
│  │  mission_type             Type mission              Embedding      │   │
│  │  geo_distance             Distance vs base          Normalized     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ENTRAÎNEMENT:                                                              │
│  - Dataset: 2 ans d'historique                                             │
│  - Positives: Séquences ayant conduit à incident                           │
│  - Negatives: Séquences normales                                            │
│  - Métriques: Recall > 95%, False Positive < 5%                            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Modèle Autoencoder - Détection Novel Patterns

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    MODÈLE AUTOENCODER - NOVEL PATTERNS                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Objectif: Détecter des patterns jamais vus ou radicalement différents     │
│                                                                             │
│  Architecture:                                                              │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                                                                      │   │
│  │  PHASE ENTRAÎNEMENT (données normales uniquement)                  │   │
│  │                                                                      │   │
│  │       INPUT (128 features)                                          │   │
│  │            │                                                         │   │
│  │            ▼                                                         │   │
│  │    ┌──────────────────────┐                                         │   │
│  │    │   Encoder            │                                         │   │
│  │    │   128 → 64 → 32 → 16 │  (bottleneck)                          │   │
│  │    └──────────────────────┘                                         │   │
│  │            │                                                         │   │
│  │            ▼                                                         │   │
│  │    ┌──────────────────────┐                                         │   │
│  │    │   Decoder             │                                         │   │
│  │    │   16 → 32 → 64 → 128 │                                         │   │
│  │    └──────────────────────┘                                         │   │
│  │            │                                                         │   │
│  │            ▼                                                         │   │
│  │        RECONSTRUCTION                                                │   │
│  │                                                                      │   │
│  │  Entraîné à minimiser: MSE(input, reconstruction)                  │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  PHASE INFERENCE:                                                          │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Nouvelle requête → Features → Autoencoder → Reconstruction         │   │
│  │                                                                      │   │
│  │  Reconstruction Error = ||input - reconstruction||                   │   │
│  │                                                                      │   │
│  │  Seuil (threshold): RE_mean + 3 * RE_std                            │   │
│  │                                                                      │   │
│  │  Si Reconstruction Error > seuil → NOVEL PATTERN DETECTED           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  EXEMPLES DE DÉTECTION:                                                    │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Type d'anomalie              Reconstruction Error                  │   │
│  │  ─────────────────────────────────────────────────────────────────  │   │
│  │  Nouveau type de requête      ÉLEVÉE (jamais vu)                   │   │
│  │  Séquence inhabituelle       MOYENNE (reconstruction difficile)    │   │
│  │  Accès atypique              ÉLEVÉE (features anormaux)            │   │
│  │  Recherche inhabituelle       MOYENNE                               │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.3 Modèle Isolation Forest - Scoring

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ISOLATION FOREST - SCORING                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Objectif: Identifier les points "anormaux" par isolation rapide          │
│                                                                             │
│  Principe: Les anomalies sont plusfaciles à isoler que les points normaux  │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                                                                      │   │
│  │  Algorithme:                                                         │   │
│  │                                                                      │   │
│  │  1. Construire N arbres de décision aléatoires                     │   │
│  │     - Sélection feature aléatoire                                   │   │
│  │     - Sélection split aléatoire (min/max valeur)                    │   │
│  │                                                                      │   │
│  │  2. Pour chaque point:                                              │   │
│  │     - Calculer profondeur moyenne d'isolation                       │   │
│  │     - Plus court = plus anomal                                      │   │
│  │                                                                      │   │
│  │  3. Score = f(longueur_moyenne)                                     │   │
│  │     - Score proche de 1 → Anomalie                                  │   │
│  │     - Score proche de 0 → Normal                                    │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  APPLICATION AU RNBC:                                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Features analysées:                                                │   │
│  │  - Agent behavior profile (historique)                             │   │
│  │  - Query patterns                                                   │   │
│  │  - Temporal patterns                                               │   │
│  │  - Volume patterns                                                 │   │
│  │  - Geographic patterns                                             │   │
│  │                                                                      │   │
│  │  Mise à jour continue: chaque nouvelle requête refine le modèle    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Types d'Anomalies Détectées

### 4.1 Catalogue des Détections

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    TYPES D'ANOMALIES DÉTECTÉES                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  CATÉGORIE 1: VOLUME ANORMAL                                        │   │
│  │  ─────────────────────────────────────────────────────────────────  │   │
│  │                                                                      │   │
│  │  Détection: Pic soudain de requêtes                                 │   │
│  │  Modèle: Statistical (Z-score) + LSTM                               │   │
│  │  Seuil: > 3std du profil historique                                 │   │
│  │  Réponse: Alert + Block si > 5std                                  │   │
│  │                                                                      │   │
│  │  Exemples:                                                          │   │
│  │    - Agent habitué à 10 req/h → 80 req/h                          │   │
│  │    - Organisme 50 req/j → 5000 req/j                             │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  CATÉGORIE 2: PATTERN INÉDIT                                       │   │
│  │  ─────────────────────────────────────────────────────────────────  │   │
│  │                                                                      │   │
│  │  Détection: Séquence de requêtes jamais observée                   │   │
│  │  Modèle: Autoencoder + LSTM                                         │   │
│  │  Seuil: Reconstruction error > threshold                            │   │
│  │  Réponse: Warning + MFA revalidation                                │   │
│  │                                                                      │   │
│  │  Exemples:                                                          │   │
│  │    - Nouveau type de requête                                        │   │
│  │    - Combinaison requête/résultats inhabituelle                    │   │
│  │    - Requête à des heures inhabituelles                            │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  CATÉGORIE 3: EXTRACTION MASSIVE                                   │   │
│  │  ─────────────────────────────────────────────────────────────────  │   │
│  │                                                                      │   │
│  │  Détection: Tentative d'export ou consultation excessive            │   │
│  │  Modèle: Rules (CRUE) + Isolation Forest                           │   │
│  │  Seuil: > 50 résultats en 5 minutes                                 │   │
│  │  Réponse: Blocage immédiat + SOC                                    │   │
│  │                                                                      │   │
│  │  Exemples:                                                          │   │
│  │    - Pagination agressive (bulk download)                          │   │
│  │    - Requêtes séquentielles sur IBAN                               │   │
│  │    - Extractionnom/adresse massive                                 │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  CATÉGORIE 4: ACCÈS HORS PERIMETRE                                 │   │
│  │  ─────────────────────────────────────────────────────────────────  │   │
│  │                                                                      │   │
│  │  Détection: Accès à des données hors mission                       │   │
│  │  Modèle: Rules (CRUE) + Statistical                                │   │
│  │  Seuil: Périmètre différent de mission                            │   │
│  │  Réponse: Blocage + Alerte hiérarchie                              │   │
│  │                                                                      │   │
│  │  Exemples:                                                          │   │
│  │    - Agent Île-de-France accède Bretagne                          │   │
│  │    - Agent fiscal accède données police                            │   │
│  │    - Accès compte fermé                                            │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  CATÉGORIE 5: COMPROMISSION                                        │   │
│  │  ─────────────────────────────────────────────────────────────────  │   │
│  │                                                                      │   │
│  │  Détection: Signes de compte compromis                             │   │
│  │  Modèle: Multi-sources (IA + Rules + Device)                     │   │
│  │  Seuil: Score agrégé > 80                                          │   │
│  │  Réponse: Révocation immédiate + Forensic                         │   │
│  │                                                                      │   │
│  │  Indicateurs:                                                       │   │
│  │    - IP变更nattendue                                               │   │
│  │    - Multi-échecs MFA                                              │   │
│  │    - Comportement radicalement différent                          │   │
│  │    - Tentatives multiples de contournement                        │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Flux de Détection Temps Réel

### 5.1 Pipeline de Traitement

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PIPELINE TEMPS RÉEL                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  ÉVÉNEMENT REÇU                                                    │   │
│  │  {                                                                  │   │
│  │    "event_type": "ACCOUNT_QUERY",                                   │   │
│  │    "agent_id": "AGENT_4571",                                       │   │
│  │    "timestamp": "2026-02-23T14:30:21Z",                          │   │
│  │    "query_type": "SEARCH_BY_NAME",                                 │   │
│  │    "result_count": 15,                                              │   │
│  │    "ip_address": "192.168.45.123"                                  │   │
│  │  }                                                                  │   │
│  └─────────────────────────┬───────────────────────────────────────────┘   │
│                            │                                                │
│                            ▼                                                │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  ÉTAPE 1: ENRICHISSEMENT (Flink)                                   │   │
│  │  ┌──────────────────────────────────────────────────────────────┐  │   │
│  │  │ Ajout features:                                                │  │   │
│  │  │  - Profil agent (historique, moyenne requêtes)                │  │   │
│  │  │  - Statistiques temps réel (1h, 24h)                          │  │   │
│  │  │  - Contexte mission (périmètre, horaires)                     │  │   │
│  │  │  - Géolocation (IP → pays, région)                           │  │   │
│  │  └──────────────────────────────────────────────────────────────┘  │   │
│  └─────────────────────────┬───────────────────────────────────────────┘   │
│                            │                                                │
│                            ▼                                                │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  ÉTAPE 2: INFERENCE MODÈLES                                        │   │
│  │  ┌──────────────────────────────────────────────────────────────┐  │   │
│  │  │  Parallel inference:                                         │  │   │
│  │  │                                                                │  │   │
│  │  │  ┌───────────────┐ ┌───────────────┐ ┌───────────────┐      │  │   │
│  │  │  │    LSTM       │ │  Autoencoder  │ │ Isolation     │      │  │   │
│  │  │  │  (sequence)   │ │  (novelty)    │ │ Forest        │      │  │   │
│  │  │  │               │ │               │ │               │      │  │   │
│  │  │  │ score: 0.72   │ │ score: 0.15   │ │ score: 0.89  │      │  │   │
│  │  │  └───────────────┘ └───────────────┘ └───────────────┘      │  │   │
│  │  │                                                                │  │   │
│  │  │  + Rules Engine (CRUE):                                        │  │   │
│  │  │  ┌───────────────┐                                            │  │   │
│  │  │  │  Violations:  │                                            │  │   │
│  │  │  │  - VOLUME     │                                            │  │   │
│  │  │  │  - PERIMETER  │                                            │  │   │
│  │  │  └───────────────┘                                            │  │   │
│  │  └──────────────────────────────────────────────────────────────┘  │   │
│  └─────────────────────────┬───────────────────────────────────────────┘   │
│                            │                                                │
│                            ▼                                                │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  ÉTAPE 3: AGREGATION SCORE                                         │   │
│  │  ┌──────────────────────────────────────────────────────────────┐  │   │
│  │  │                                                                │  │   │
│  │  │   SCORE FINAL = w1*LSTM + w2*AE + w3*IF + w4*Rules          │  │   │
│  │  │                                                                │  │   │
│  │  │   = 0.25*0.72 + 0.25*0.15 + 0.25*0.89 + 0.25*1.0          │  │   │
│  │  │   = 0.69                                                      │  │   │
│  │  │                                                                │  │   │
│  │  │   RISQUE: ORANGE (Warning)                                    │  │   │
│  │  │                                                                │  │   │
│  │  └──────────────────────────────────────────────────────────────┘  │   │
│  └─────────────────────────┬───────────────────────────────────────────┘   │
│                            │                                                │
│                            ▼                                                │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  ÉTAPE 4: DÉCISION & ACTION                                        │   │
│  │  ┌──────────────────────────────────────────────────────────────┐  │   │
│  │  │                                                                │  │   │
│  │  │   Score 0-30:     CONTINUE (Log only)                        │  │   │
│  │  │   Score 31-60:    WARNING + Log + Notify supervisor         │  │   │
│  │  │   Score 61-80:    BLOCK + MFA revalidation                  │  │   │
│  │  │   Score 81-100:   BLOCK + REVOKE + SOC + Forensics          │  │   │
│  │  │                                                                │  │   │
│  │  │   Score = 0.69 → Score 31-60 (ORANGE)                        │  │   │
│  │  │   Action: WARNING + NOTIFY SUPERVISOR                        │  │   │
│  │  │                                                                │  │   │
│  │  └──────────────────────────────────────────────────────────────┘  │   │
│  └───────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Configuration des Seils

### 6.1 Tableau de Bord des Seils

| Anomalie | Modèle Principal | Seuil Warning | Seuil Critical | Action Warning | Action Critical |
|----------|-----------------|----------------|-----------------|----------------|------------------|
| Volume anormal | LSTM + Stats | > 2σ | > 4σ | Alert | Block |
| Pattern inédite | Autoencoder | > 0.5 | > 0.8 | MFA | Block |
| Extraction massive | Rules (CRUE) | N/A | N/A | Block | Block |
| Score isolatif | Isolation Forest | > 0.6 | > 0.8 | Monitor | MFA |
| Composite | Aggregated | > 60 | > 80 | MFA | Revoke |

### 6.2 Pondération du Score Final

```python
# Configuration des poids par défaut
SCORE_WEIGHTS = {
    'lstm_sequence': 0.25,        # Détection séquence
    'autoencoder_novelty': 0.25,  # Novel patterns
    'isolation_forest': 0.25,    # Scoring comportement
    'rules_engine': 0.25          # Règles métier
}

def calculate_composite_score(event, models_results):
    """
    Calcule le score de risque agrégé
    """
    score = 0
    
    # LSTM
    score += SCORE_WEIGHTS['lstm_sequence'] * models_results['lstm'].anomaly_score
    
    # Autoencoder
    score += SCORE_WEIGHTS['autoencoder_novelty'] * models_results['autoencoder'].reconstruction_error
    
    # Isolation Forest
    score += SCORE_WEIGHTS['isolation_forest'] * models_results['iforest'].anomaly_score
    
    # Rules (binaire)
    if models_results['rules'].has_violation:
        score += SCORE_WEIGHTS['rules_engine'] * 1.0
    
    return min(score * 100, 100)  # Normaliser 0-100
```

---

## 7. Monitoring et Métriques

### 7.1 Métriques ML Ops

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    MÉTRIQUES MONITORING                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  PERFORMANCE MODÈLE                                                   │   │
│  │  ────────────────────                                               │   │
│  │                                                                      │   │
│  │  - inference_latency_p50: < 50ms                                    │   │
│  │  - inference_latency_p99: < 200ms                                   │   │
│  │  - model_accuracy: > 95% (mis à jour hebdo)                          │   │
│  │  - false_positive_rate: < 5%                                        │   │
│  │  - true_positive_rate: > 95%                                        │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  ACTIVITÉ DÉTECTION                                                  │   │
│  │  ───────────────────                                                 │   │
│  │                                                                      │   │
│  │  - alerts_total: Compteur total d'alertes                           │   │
│  │  - alerts_by_severity: {warning: X, critical: Y}                  │   │
│  │  - alerts_by_type: {volume: X, pattern: Y, massive: Z}            │   │
│  │  - actions_taken: {block: X, mfa: Y, notify: Z}                   │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  DATA DRIFT                                                          │   │
│  │  ──────────                                                          │   │
│  │                                                                      │   │
│  │  - feature_distribution_shift: KS test entre train et inference     │   │
│  │  - prediction_drift: Chi-square sur prédictions                     │   │
│  │  - Si drift > 10%: Retraining triggered                             │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 8. Checklist Implémentation

```
□ Composant                  Statut      Date
─────────────────────────────────────────────────────
□ Infrastructure ML          [ ]         _________
□ Dataset historique        [ ]         _________
□ Modèle LSTM entraîné      [ ]         _________
□ Modèle AE entraîné        [ ]         _________
□ Modèle IF entraîné        [ ]         _________
□ API Inference             [ ]         _________
□ Intégration Kafka        [ ]         _________
□ Tests performance         [ ]         _________
□ Validation accuracy       [ ]         _________
□ Mise en production       [ ]         _________
□ Monitoring configuré      [ ]         _________
□ Retraining pipeline      [ ]         _________
□ Documentation             [ ]         _________
□ Go-Live                   [ ]         _________
```

---

*Document Spécification Détection Anomalies - Version 1.0*
*Date: 2026-02-23*
