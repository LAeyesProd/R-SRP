# ⚙️ Spécification: Moteur de Règles Déterministes (CRUE)

## 1. Vue d'Ensemble

Le Moteur de Règles Déterministes (CRUE - Contrôle Rationnel Unique et Exclusif) constitue le cœur du système de contrôle d'accès. Il implémente des règles **inviolables, versionnées et non contournables** qui s'appliquent à chaque requête.

---

## 2. Principes Fondamentaux

### 2.1 Caractéristiques Essentielles

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PRINCIPES CRUE                                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  1. IMMUABILITÉ                                                     │   │
│  │     ─────────────────                                             │   │
│  │     Les règles ne peuvent JAMAIS être modifiées à runtime         │   │
│  │     Toute modification nécessite un cycle de release complet      │   │
│  │                                                                     │   │
│  │     Runtime: Lecture seule                                          │   │
│  │     Update: Nouveau déploiement (version increment)               │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  2. VERSIONNAGE                                                     │   │
│  │     ─────────────                                                   │   │
│  │     Chaque règle est versionnée et signé cryptographiquement      │   │
│  │                                                                     │   │
│  │     Version: 1.0.0 → 1.0.1 → 2.0.0                                 │   │
│  │     Signature: RSA-PSS de chaque version                          │   │
│  │     Stockage: Git + Blockchain consortium                           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  3. NON-CONTOURNABILITÉ                                            │   │
│  │     ─────────────────────                                           │   │
│  │     Pas de override, bypass ou exception administrative            │   │
│  │     Toute requête passe par le moteur                              │   │
│  │     Aucune API directe vers la base                                │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  4. ATOMICITÉ                                                       │   │
│  │     ────────────                                                    │   │
│  │     Toutes les règles s'appliquent ou aucune ne s'applique        │   │
│  │     Pas de succès partiel                                           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  5. TRAÇABILITÉ                                                     │   │
│  │     ───────────                                                     │   │
│  │     Chaque décision est loguée immuablement                        │   │
│  │     Preuve de la règle appliquée                                   │   │
│  │     Justification de l'acceptation ou rejet                        │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Catalogue de Règles

### 3.1 Règles Implémentées

| ID | Nom | Description | Sévérité | Version |
|----|-----|-------------|----------|---------|
| CRUE-001 | VOLUME_MAX | Max 50 requêtes/heure | BLOCK | 1.2.0 |
| CRUE-002 | JUSTIFICATION_OBLIG | Justification texte requise | BLOCK | 1.1.0 |
| CRUE-003 | EXPORT_INTERDIT | Pas d'export CSV/XML/JSON bulk | BLOCK | 2.0.0 |
| CRUE-004 | MISSION_ACTIVE | Mission active requise | BLOCK | 1.0.0 |
| CRUE-005 | DOUBLE_VALIDATION | Validation chef si >30 req + >10 résultats | WARN | 1.0.0 |
| CRUE-006 | PERIMETRE_GEO | Respect périmètre géographique | BLOCK | 1.0.0 |
| CRUE-007 | TEMPS_REQUETE | Max 10 secondes | WARN | 1.0.0 |
| CRUE-008 | SEQUENCE_INHABITUELLE | Détection pattern inédite | WARN | 1.0.0 |
| CRUE-009 | ACCES_HORAIRES | Accès pendant horaires mission | BLOCK | 1.0.0 |
| CRUE-010 | TYPE_REQUETE_AUTORISE | Type de requête autorisé | BLOCK | 1.0.0 |

### 3.2 Détail des Règles

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    DÉTAIL DES RÈGLES                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  CRUE-001: VOLUME_MAX                                               │   │
│  │  ─────────────────────────────────────────────────────────────────  │   │
│  │  Description: Limite le nombre de requêtes par agent/heure         │   │
│  │                                                                     │   │
│  │  CONDITION:                                                         │   │
│  │    agent.nb_requetes_1h >= 50                                       │   │
│  │                                                                     │   │
│  │  ACTION:                                                            │   │
│  │    REJETER(code: VOLUME_EXCEEDED)                                  │   │
│  │    Message: "Quota de consultation dépassé (50/h)"                │   │
│  │    Log: BLOCK + ALERT_SOC                                          │   │
│  │                                                                     │   │
│  │  EXCEPTION: AUCUNE                                                   │   │
│  │                                                                     │   │
│  │  METADONNÉES:                                                       │   │
│  │    Version: 1.2.0 | Validée: 2026-01-15 | Signée: Autorité_Règles │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  CRUE-002: JUSTIFICATION_OBLIGATOIRE                               │   │
│  │  ─────────────────────────────────────────────────────────────────  │   │
│  │  Description: Force la justification de chaque requête           │   │
│  │                                                                     │   │
│  │  CONDITION:                                                         │   │
│  │    query.type IN [SEARCH_BY_NAME, SEARCH_BY_NIR, SEARCH_BY_IBAN]  │   │
│  │    AND (query.justification IS NULL                                │   │
│  │         OR LENGTH(query.justification) < 10)                      │   │
│  │                                                                     │   │
│  │  ACTION:                                                            │   │
│  │    REJETER(code: JUSTIFICATION_REQUIRED)                           │   │
│  │    Message: "Justification obligatoire (min 10 caractères)"        │   │
│  │                                                                     │   │
│  │  METADONNÉES:                                                       │   │
│  │    Version: 1.1.0 | Validée: 2026-01-20 | Signée: Autorité_Règles │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  CRUE-003: EXPORT_INTERDIT                                         │   │
│  │  ─────────────────────────────────────────────────────────────────  │   │
│  │  Description: Interdit tout export massif                          │   │
│  │                                                                     │   │
│  │  CONDITION:                                                         │   │
│  │    request.format_export IN [CSV, XML, JSON_BULK, EXCEL, PDF_BULK] │   │
│  │    OR request.limit > 100                                          │   │
│  │                                                                     │   │
│  │  ACTION:                                                            │   │
│  │    REJETER(code: EXPORT_FORBIDDEN)                                 │   │
│  │    Message: "Export de masse non autorisé"                         │   │
│  │    Log: CRITICAL + ALERT_SOC                                       │   │
│  │                                                                     │   │
│  │  NOTE: Exception possible uniquement via processus                 │   │
│  │        judiciaire formel (requête écrite + validation)            │   │
│  │                                                                     │   │
│  │  METADONNÉES:                                                       │   │
│  │    Version: 2.0.0 | Validée: 2026-01-25 | Signée: Autorité_Règles  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  CRUE-004: MISSION_ACTIVE                                          │   │
│  │  ─────────────────────────────────────────────────────────────────  │   │
│  │  Description: Vérifie la validité de la mission active            │   │
│  │                                                                     │   │
│  │  CONDITION:                                                         │   │
│  │    NOT EXISTS (SELECT 1 FROM missions m                            │   │
│  │      WHERE m.id = session.mission_id                               │   │
│  │      AND m.statut = 'ACTIVE'                                       │   │
│  │      AND m.date_fin >= CURRENT_TIMESTAMP                          │   │
│  │      AND m.agent_id = session.agent_id)                            │   │
│  │                                                                     │   │
│  │  ACTION:                                                            │   │
│  │    REJETER(code: MISSION_INACTIVE)                                │   │
│  │    Message: "Aucune mission active pour cet agent"                 │   │
│  │    Log: WARNING                                                     │   │
│  │                                                                     │   │
│  │  METADONNÉES:                                                       │   │
│  │    Version: 1.0.0 | Validée: 2026-01-10 | Signée: Autorité_Règles  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  CRUE-005: DOUBLE_VALIDATION                                       │   │
│  │  ─────────────────────────────────────────────────────────────────  │   │
│  │  Description: Exige validation du supérieur pour volumes élevés   │   │
│  │                                                                     │   │
│  │  CONDITION:                                                         │   │
│  │    (agent.nb_requetes_1h >= 30 AND query.result_count >= 10)       │   │
│  │    OR (agent.nb_requetes_24h >= 200)                               │   │
│  │                                                                     │   │
│  │  ACTION:                                                            │   │
│  │    SUSPENDRE_JUSQU_VALIDATION(code: APPROVAL_REQUIRED)            │   │
│  │    Envoyer notification superviseur                                │   │
│  │    Timeout: 30 minutes                                             │   │
│  │                                                                     │   │
│  │  METADONNÉES:                                                       │   │
│  │    Version: 1.0.0 | Validée: 2026-01-12 | Signée: Autorité_Règles  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  CRUE-006: PERIMETRE_GEOGRAPHIQUE                                  │   │
│  │  ─────────────────────────────────────────────────────────────────  │   │
│  │  Description: Respecte le périmètre géographique de la mission    │   │
│  │                                                                     │   │
│  │  CONDITION:                                                         │   │
│  │    agent.perimetre_type = 'REGIONAL'                               │   │
│  │    AND compte.departement NOT IN agent.departements               │   │
│  │                                                                     │   │
│  │  ACTION:                                                            │   │
│  │    REJETER(code: SCOPE_VIOLATION)                                  │   │
│  │    Message: "Compte hors périmètre géographique"                   │   │
│  │    Log: WARNING                                                     │   │
│  │                                                                     │   │
│  │  METADONNÉES:                                                       │   │
│  │    Version: 1.0.0 | Validée: 2026-01-10 | Signée: Autorité_Règles  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Architecture Technique

### 4.1 Architecture Drools

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ARCHITECTURE MOTEUR DE RÈGLES                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      COUCHE PRESENTATION                             │   │
│  │  ┌─────────────────────────────────────────────────────────────┐   │   │
│  │  │               DROOLS BUSINESS CENTRAL                        │   │   │
│  │  │                                                              │   │   │
│  │  │   ┌───────────────┐    ┌───────────────┐                    │   │   │
│  │  │   │  Modélisation │    │    Tests      │                    │   │   │
│  │  │   │   Règles DRL  │    │   Unitaires   │                    │   │   │
│  │  │   │   Décision    │    │   KIE-Server  │                    │   │   │
│  │  │   │   Tables      │    │               │                    │   │   │
│  │  │   └───────────────┘    └───────────────┘                    │   │   │
│  │  │                                                              │   │   │
│  │  │   Interface Web: https://drools.rnbc.internal              │   │   │
│  │  │   Git Integration: GitLab / GitHub Enterprise                │   │   │
│  │  └─────────────────────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      COUCHE EXÉCUTION                              │   │
│  │  ┌─────────────────────────────────────────────────────────────┐   │   │
│  │  │                   DROOLS KIE SERVER                          │   │   │
│  │  │                    (Kubernetes Pod)                          │   │   │
│  │  │                                                              │   │   │
│  │  │   ┌──────────────────────────────────────────────────────┐  │   │   │
│  │  │   │  Container KIE Server                                 │  │   │   │
│  │  │   │   - Drools Core Engine                               │  │   │   │
│  │  │   │   - Decision Engine                                   │  │   │   │
│  │  │   │   - Rules Cache                                       │  │   │   │
│  │  │   └──────────────────────────────────────────────────────┘  │   │   │
│  │  │                                                              │   │   │
│  │  │   Endpoints REST:                                          │   │   │
│  │  │   POST /kie-server/services/rest/server/containers/       │  │   │   │
│  │  │       {containerName}/dmn                                   │  │   │   │
│  │  │                                                              │  │   │   │
│  │  │   HA: 3 répliques (min)                                    │  │   │   │
│  │  └─────────────────────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    COUCHE STOCKAGE                                  │   │
│  │  ┌──────────────────┐  ┌──────────────────┐                      │   │
│  │  │  PostgreSQL      │  │    Git            │                      │   │
│  │  │  (Runtime state) │  │  (Versioning)     │                      │   │
│  │  │                  │  │                   │                      │   │
│  │  │  - Sessions      │  │  - Rules DRL      │                      │   │
│  │  │  - Stats         │  │  - DMN files      │                      │   │
│  │  │  - Audit         │  │  - Tests          │                      │   │
│  │  └──────────────────┘  └──────────────────┘                      │   │
│  │                                                                      │   │
│  │  ┌──────────────────┐  ┌──────────────────┐                      │   │
│  │  │  HashiCorp Vault │  │  Blockchain       │                      │   │
│  │  │  (Secrets)      │  │  (Signatures)     │                      │   │
│  │  │                  │  │                    │                      │   │
│  │  │  - API Keys     │  │  - Rule signatures│                      │   │
│  │  │  - Certs        │  │  - Version hashes │                      │   │
│  │  └──────────────────┘  └──────────────────┘                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4.2 Flux de Déploiement des Règles

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    FLUX DÉPLOIEMENT RÈGLES                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. DÉVELOPPEMENT                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐               │   │
│  │  │ Éditeur │  │  Test   │  │  Review │  │ Package │               │   │
│  │  │  règles │  │ unitaire│  │ Manager │  │  KJar   │               │   │
│  │  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘               │   │
│  │       │             │             │             │                    │   │
│  │       └─────────────┴─────────────┴─────────────┘                    │   │
│  │                              │                                         │   │
│  └──────────────────────────────┼────────────────────────────────────────┘   │
│                                 ▼                                           │
│  2. VALIDATION                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  ┌─────────────────────────────────────────────────────────────┐   │   │
│  │  │  GOUVERNANCE RÈGLES                                          │   │   │
│  │  │                                                               │   │   │
│  │  │  ┌───────────────────────────────────────────────────────┐  │   │   │
│  │  │  │ Étape 1: Validation technique                         │  │   │   │
│  │  │  │   - Tests d'intégration passent                       │  │   │   │
│  │  │  │   - Analyse impact performance                        │  │   │   │
│  │  │  │   - Review sécurité                                   │  │   │   │
│  │  │  └───────────────────────────────────────────────────────┘  │   │   │
│  │  │                           │                                   │   │   │
│  │  │                           ▼                                   │   │   │
│  │  │  ┌───────────────────────────────────────────────────────┐  │   │   │
│  │  │  │ Étape 2: Approbation gouvernance                      │  │   │   │
│  │  │  │   - Comité règles (3/5 signatures)                    │  │   │   │
│  │  │  │   - DSI, RSSI, Métier                                  │  │   │   │
│  │  │  └───────────────────────────────────────────────────────┘  │   │   │
│  │  │                           │                                   │   │   │
│  │  │                           ▼                                   │   │   │
│  │  │  ┌───────────────────────────────────────────────────────┐  │   │   │
│  │  │  │ Étape 3: Signature cryptographique                   │  │   │   │
│  │  │  │   - Signature HSM de la nouvelle version             │  │   │   │
│  │  │  │   - Publication hash blockchain                       │  │   │   │
│  │  │  │   - Horodatage TSA                                    │  │   │   │
│  │  │  └───────────────────────────────────────────────────────┘  │   │   │
│  │  │                                                               │   │   │
│  │  └─────────────────────────────────────────────────────────────┘   │   │
│  └──────────────────────────────┼────────────────────────────────────────┘   │
│                                 ▼                                           │
│  3. DÉPLOIEMENT                                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  ┌─────────────────────────────────────────────────────────────┐   │   │
│  │  │  Déploiement progressif (Canary)                           │   │   │
│  │  │                                                               │   │   │
│  │  │  1. 1% trafic ──▶ Monitoring ──▶ OK                       │   │   │
│  │  │  2. 10% trafic ──▶ Monitoring ──▶ OK                      │   │   │
│  │  │  3. 50% trafic ──▶ Monitoring ──▶ OK                      │   │   │
│  │  │  4. 100% trafic ──▶ OK                                     │   │   │
│  │  │                                                               │   │   │
│  │  │  Rollback automatique si anomalie                          │   │   │
│  │  └─────────────────────────────────────────────────────────────┘   │   │
│  └──────────────────────────────┼────────────────────────────────────────┘   │
│                                 ▼                                           │
│  4. PRODUCTION                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  ┌─────────────────────────────────────────────────────────────┐   │   │
│  │  │  Version active + Historique                                │   │   │
│  │  │                                                               │   │   │
│  │  │  Version: 2.0.0 | Status: ACTIVE | Date: 2026-02-23         │   │   │
│  │  │  Signature: RSA-PSS(sha256, key_AUTORITÉ_RÈGLES)          │   │   │
│  │  │  Hash blockchain: 0xa1b2c3d4...                            │   │   │
│  │  │                                                               │   │   │
│  │  └─────────────────────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Modèle de Données

### 5.1 Structure d'Entrée (Facts)

```java
// Drools Facts - RequestContext
public class RequestContext implements Serializable {
    
    // Contexte utilisateur
    private String agentId;
    private String agentOrg;
    private String missionId;
    private String missionType;
    private List<String> scopes;
    private PerimeterType perimeterType;
    private List<Integer> allowedDepartments;
    
    // Métriques temps réel
    private int nbRequetes1h;
    private int nbRequetes24h;
    private int resultatsDerniereRequete;
    
    // Requête courante
    private QueryType queryType;
    private String justification;
    private String searchTerm;
    private ExportFormat exportFormat;
    private int resultLimit;
    
    // Contexte temporel
    private LocalDateTime requestTime;
    private boolean isWithinMissionHours;
    
    // Géographie
    private String accountDepartment;
    private String requestRegion;
}
```

### 5.2 Structure de Sortie (Results)

```java
// Résultat d'évaluation
public class RuleEvaluationResult implements Serializable {
    
    private String requestId;
    private String ruleId;
    private String ruleVersion;
    private Decision decision;  // ACCEPT, REJECT, WARNING, APPROVAL_REQUIRED
    private String errorCode;
    private String message;
    private String ruleHash;
    private LocalDateTime evaluatedAt;
    
    // Preuve
    private String conditionEvaluated;
    private String actionExecuted;
}
```

---

## 6. Intégration API Gateway

### 6.1 Configuration Kong

```yaml
# drools-plugin.yaml
apiVersion: configuration.konghq.com/v1
kind: KongPlugin
metadata:
  name: crue-validation
plugin: proxy-cache-advanced
config:
  response_code:
    - 200
  request_method:
    - POST
  cache_ttl: 0  # Pas de cache pour CRUE
  strategy: redis
  redis_host: redis.rnbc.internal
  redis_port: 6379

---
# Drools external service
apiVersion: v1
kind: Service
metadata:
  name: drools-engine
spec:
  ports:
    - port: 8080
      targetPort: 8080
---
# Route vers CRUE
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: crue-ingress
  annotations:
    konghq.com/plugins: crue-validation
spec:
  rules:
    - host: crue.rnbc.internal
      http:
        paths:
          - path: /validate
            pathType: Exact
            backend:
              service:
                name: drools-engine
                port:
                  number: 8080
```

### 6.2 Appels depuis Kong

```bash
# Exemple appel validation CRUE
curl -X POST https://crue.rnbc.internal/validate \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "agentId": "AGENT_4571",
    "missionId": "MIS_2026_0234",
    "queryType": "SEARCH_BY_NAME",
    "justification": "Enquête judiciaire",
    "nbRequetes1h": 45,
    "resultLimit": 50
  }'

# Réponse
{
  "requestId": "req_20260223143021",
  "decision": "REJECT",
  "errorCode": "VOLUME_EXCEEDED",
  "message": "Quota de consultation dépassé (50/h)",
  "ruleId": "CRUE-001",
  "ruleVersion": "1.2.0"
}
```

---

## 7. Métriques et Monitoring

### 7.1 Dashboard Grafana

| Métrique | Description | Seuil Alerte |
|----------|-------------|--------------|
| `crue_rules_evaluated_total` | Nombre de règles évaluées | N/A |
| `crue_decision_reject_total` | Rejets par règle | > 10% |
| `crue_latency_seconds` | Latence évaluation | > 500ms |
| `crue_cache_hit_rate` | Taux cache | < 80% |
| `crue_version_active` | Version active | N/A |

### 7.2 Alerting

```yaml
groups:
- name: crue-alerts
  rules:
  - alert: HighRejectionRate
    expr: rate(crue_decision_reject_total[5m]) > 0.1
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Taux de rejet CRUE élevé"
      
  - alert: CRUELatencyHigh
    expr: crue_latency_seconds{quantile="0.95"} > 0.5
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "Latence CRUE élevée"
```

---

## 8. Checklist Implémentation

```
□ Composant                  Statut      Date
─────────────────────────────────────────────────────
□ Installation Drools        [ ]         _________
□ Définition règles v1       [ ]         _________
□ Signature cryptographique  [ ]         _________
□ Publication blockchain    [ ]         _________
□ Intégration Kong          [ ]         _________
□ Tests unitaires           [ ]         _________
□ Tests intégration         [ ]         _________
□ Tests performance         [ ]         _________
□ Publication production    [ ]         _________
□ Monitoring configuré      [ ]         _________
□ Documentation             [ ]         _________
□ Formation équipe           [ ]         _________
□ Go-Live                   [ ]         _________
```

---

*Document Spécification CRUE - Version 1.0*
*Date: 2026-02-23*
