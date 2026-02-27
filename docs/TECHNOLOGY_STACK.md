# 🛠 Stack Technologique Recommandée

## Registre National des Comptes Bancaires - Architecture Zero-Trust

---

## 1. Vue d'Ensemble de la Stack

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    STACK TECHNOLOGIQUE - COUCHES                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  COUCHE PRÉSENTATION                                                │   │
│  │  ├─ Portails Web (React/Angular)                                    │   │
│  │  ├─ API Explorer (Swagger/OpenAPI)                                 │   │
│  │  └─ Dashboards (Grafana)                                           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                              │
│                              ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  COUCHE IDENTITÉ & AUTHENTIFICATION                                │   │
│  │  ├─ Identity Provider: Keycloak / Azure AD B2C                    │   │
│  │  ├─ Tokens: JWT with RSA256                                        │   │
│  │  ├─ Hardware: YubiKey 5 / Thales Luna                             │   │
│  │  └─ MFA: FIDO2/WebAuthn                                            │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                              │
│                              ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  COUCHE ACCÈS & PROTECTION                                        │   │
│  │  ├─ API Gateway: Kong Enterprise / Apigee                         │   │
│  │  ├─ WAF: ModSecurity / AWS WAF                                    │   │
│  │  ├─ mTLS: HashiCorp Vault (PKI)                                   │   │
│  │  └─ Rate Limiting: Kong rate limiter                              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                              │
│                              ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  COUCHE CONTRÔLE & AUTOMATISATION                                 │   │
│  │  ├─ Rules Engine: Drools / OpenL Tablets                          │   │
│  │  ├─ PAM: CyberArk / BeyondTrust                                   │   │
│  │  ├─ SOAR: Splunk SOAR / Palo Alto XSOAR                          │   │
│  │  └─ Orchestration: Kubernetes / Docker                           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                              │
│                              ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  COUCHE DONNÉES                                                    │   │
│  │  ├─ Database: PostgreSQL (主) + Oracle (legacy)                  │   │
│  │  ├─ Secrets: HashiCorp Vault                                      │   │
│  │  ├─ Cache: Redis Cluster                                           │   │
│  │  └─ Search: Elasticsearch                                          │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                              │
│                              ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  COUCHE ÉVÉNEMENTS & MESSAGERIE                                   │   │
│  │  ├─ Event Bus: Apache Kafka                                       │   │
│  │  ├─ Streaming: Apache Flink                                       │   │
│  │  └─ Queue: RabbitMQ                                                │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                              │
│                              ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  COUCHE OBSERVABILITÉ                                              │   │
│  │  ├─ Logging: ELK Stack / Splunk                                   │   │
│  │  ├─ Metrics: Prometheus + Grafana                                 │   │
│  │  ├─ Tracing: Jaeger / Zipkin                                      │   │
│  │  └─ SIEM: Splunk Enterprise / QRadar                              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                              │
│                              ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  COUCHE SÉCURITÉ CRYPTOGRAPHIQUE                                   │   │
│  │  ├─ HSM: Thales Luna HSM                                           │   │
│  │  ├─ Signing: RSA-PSS / ECDSA                                       │   │
│  │  ├─ Blockchain: Hyperledger Fabric (consortium)                  │   │
│  │  └─ Timestamping: TSA qualifiée                                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                              │
│                              ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  COUCHE INFRASTRUCTURE                                             │   │
│  │  ├─ Cloud: AWS / Azure / OVH Cloud (SOVEREIGN)                   │   │
│  │  ├─ Container: Kubernetes (EKS/AKS)                               │   │
│  │  ├─ Network: VPC with private subnets                             │   │
│  │  └─ CDN: CloudFlare / AWS CloudFront                              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Détail par Composant

### 2.1 Identity & Access Management (IAM)

| Composant | Solution Recommandée | Alternatives | Justification |
|-----------|---------------------|--------------|----------------|
| **Identity Provider** | Keycloak (Open Source) | Azure AD B2C, Auth0 | Contrôle total, FIDO2 natif, sovereignty |
| **MFA Hardware** | YubiKey 5 Series | Thales IDPrime, Feitian | Standard FIDO2, durabilité |
| **Protocols** | SAML 2.0 + OIDC | OAuth 2.0 | Interopérabilité multi-organismes |
| **Session Management** | Redis + JWT | In-memory | Haute disponibilité, horizontal scaling |

**Configuration Recommandée:**

```yaml
identity_provider:
  provider: keycloak
  version: "24.0"
  deployment: cluster
  database: postgresql
  
authentication:
  methods:
    - type: fido2
      mandatory: true
    - type: certificate
      mandatory: true
    - type: password
      mandatory: false
      # Interdit seul, désactivé par défaut
      
  device_binding:
    enabled: true
    attestation: required
    
  context_validation:
    ip_whitelist: true
    geolocation_check: true
    time_window: mission_hours
    anomaly_detection: true
```

### 2.2 API Gateway

| Composant | Solution Recommandée | Alternatives | Justification |
|-----------|---------------------|--------------|----------------|
| **API Gateway** | Kong Enterprise | AWS API Gateway, Apigee | Plugins richesse, mTLS, rate limiting |
| **WAF** | ModSecurity + OWASP | AWS WAF, CloudFlare | Règles CRS complètes |
| **Rate Limiting** | Kong Plugin | AWS API Gateway native | Granularité fine |

**Configuration:**

```yaml
api_gateway:
  kong:
    version: "3.4"
    deployment: kubernetes_ingress
    
  plugins:
    - jwt
    - rate-limiting
    - request-transformer
    - response-transformer
    - correlation-id
    - logging
    
  security:
    tls_version: "1.3"
    mTLS: mandatory
    jwt_validation: strict
    
  rate_limiting:
    window: 1h
    limits:
      default: 50
      violation_alert: 45
      hard_block: 60
```

### 2.3 Privileged Access Management (PAM)

| Composant | Solution Recommandée | Alternatives | Justification |
|-----------|---------------------|--------------|----------------|
| **PAM** | CyberArk Core | BeyondTrust, Thycotic | Leader marché, intégration HSM |
| **Bastion** | AWS EC2 Bastion / Azure Bastion | Custom jump-host | Sécurisé, audit trail |
| **Session Recording** | CyberArk PSM | Devo, Relic | Intégration native |

**Configuration:**

```yaml
pam:
  cyberark:
    version: "14.0"
    deployment: centralized
    
  just_in_time:
    enabled: true
    max_duration: 4h
    approval_workflow: auto
    
  session:
    isolation: mandatory
    recording: mandatory
    keyboard_encryption: aes-256
    
  vault:
    primary: hardware_hsm
    replication: 3_sites
```

### 2.4 Deterministic Rules Engine (CRUE)

| Composant | Solution Recommandée | Alternatives | Justification |
|-----------|---------------------|--------------|----------------|
| **Rules Engine** | Drools Business Central | OpenL Tablets, Camunda | Maturité, performance |
| **Storage** | Git + Database | PostgreSQL | Versioning, audit |

**Architecture:**

```
┌─────────────────────────────────────────────────────────────────┐
│              MOTEUR DE RÈGLES - ARCHITECTURE                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌─────────────────────────────────────────────────────────┐    │
│   │            DROOLS BUSINESS CENTRAL                       │    │
│   │  ┌───────────────┐  ┌───────────────┐                   │    │
│   │  │  Modélisation │  │    Tests      │                   │    │
│   │  │   Règles      │  │   Unitaires   │                   │    │
│   │  └───────────────┘  └───────────────┘                   │    │
│   └─────────────────────────┬───────────────────────────────┘    │
│                             │                                      │
│                             ▼                                      │
│   ┌─────────────────────────────────────────────────────────┐    │
│   │              DROOLS KIE SERVER (API)                     │    │
│   │                                                          │    │
│   │   Endpoints:                                            │    │
│   │   POST /kie-server/services/rest/server/containers/     │    │
│   │          {decision}/dmn                                │    │
│   │                                                          │    │
│   └─────────────────────────┬───────────────────────────────┘    │
│                             │                                      │
│                             ▼                                      │
│   ┌─────────────────────────────────────────────────────────┐    │
│   │              INTÉGRATION API GATEWAY                     │    │
│   │   Kong → Validate Rules → Allow/Block                   │    │
│   └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│   VERSIONNAGE & SÉCURITÉ:                                       │
│   - Git pour le storage des règles                             │
│   - Signature numérique chaque version                         │
│   - Publication sur blockchain consortium                      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 2.5 Data Layer

| Composant | Solution Recommandée | Alternatives | Justification |
|-----------|---------------------|--------------|----------------|
| **Primary Database** | PostgreSQL 16 | Oracle Exadata, CockroachDB | ACID, performance, coût |
| **Secrets Management** | HashiCorp Vault | AWS Secrets Manager | Écosystème complet |
| **Cache** | Redis Cluster | Memcached | Persistence, clustering |
| **Search** | Elasticsearch | OpenSearch | Analytics intégré |

**Configuration Base de Données:**

```sql
-- Exemple: Politique de sécurité PostgreSQL

-- Rôle par périmètre
CREATE ROLE fiscal_readonly;
CREATE ROLE justice_read;
CREATE ROLE police_readonly;

-- Politique RLS (Row Level Security)
CREATE POLICY "fiscal_policy" ON accounts
    FOR SELECT
    TO fiscal_readonly
    USING (
        department IN (
            SELECT array_dept 
            FROM agent_perimeters 
            WHERE agent_id = current_setting('app.current_user')
        )
        AND justification IS NOT NULL
    );

-- Interdiction SELECT *
ALTER TABLE accounts ENABLE ROW LEVEL SECURITY;
DROP POLICY "allow_all_select" ON accounts;

-- Audit automatique
CREATE EXTENSION pgaudit;
ALTER SYSTEM SET pgaudit.log = 'all';
```

### 2.6 Event-Driven Architecture

| Composant | Solution Recommandée | Alternatives | Justification |
|-----------|---------------------|--------------|----------------|
| **Event Bus** | Apache Kafka | RabbitMQ, Pulsar | Throughput, rétention |
| **Schema Registry** | Confluent Schema Registry | Karapace | Governance |
| **Stream Processing** | Apache Flink | Kafka Streams | Real-time |

**Configuration Kafka:**

```yaml
kafka:
  version: "3.6"
  deployment: kraft_mode
  
  topics:
    - name: rnbc.events.auth
      partitions: 12
      replication: 3
      retention: 7years
      
    - name: rnbc.events.query
      partitions: 24
      replication: 3
      retention: 7years
      
    - name: rnbc.events.security
      partitions: 6
      replication: 3
      retention: 10years
      
  security:
    sasl: SCRAM-SHA-512
    encryption: TLS_1.3
    acl: enabled
```

### 2.7 Observability

| Composant | Solution Recommandée | Alternatives | Justification |
|-----------|---------------------|--------------|----------------|
| **SIEM** | Splunk Enterprise | QRadar, Elastic | Flexibilité, ML intégré |
| **Logging** | ELK Stack / Splunk | Loki, Graylog | Intégration SIEM |
| **Metrics** | Prometheus + Grafana | DataDog | Coût, richesse visuelle |
| **Tracing** | Jaeger | Zipkin | Distributed tracing |

### 2.8 Cryptographic Security

| Composant | Solution Recommandée | Alternatives | Justification |
|-----------|---------------------|--------------|----------------|
| **HSM** | Thales Luna Network 7 | AWS CloudHSM | Certification eIDAS |
| **Signing** | RSA-PSS 4096 | ECDSA P-384 | Performance/sécurité |
| **Blockchain** | Hyperledger Fabric | Quorum, Corda | Consortium, privacy |
| **Timestamping** | TSA DigiCert | FreeTSA | Qualification eIDAS |

---

## 3. Matrice de Compatibilité

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    MATRICE DE COMPATIBILITÉ                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Composant          Version     Dépendances                                │
│  ─────────────────────────────────────────────────────────────────────────  │
│                                                                             │
│  Kubernetes          1.28+       CNI: Calico, Service Mesh: Istio         │
│  ─────────────────────────────────────────────────────────────────────────  │
│  Keycloak           24.0        PostgreSQL 15+, Java 17+                   │
│  ─────────────────────────────────────────────────────────────────────────  │
│  Kong Gateway       3.4         PostgreSQL 15+, Nginx 1.25+                │
│  ─────────────────────────────────────────────────────────────────────────  │
│  Kafka              3.6         Zookeeper (or KRaft), Java 17+            │
│  ─────────────────────────────────────────────────────────────────────────  │
│  PostgreSQL         16          HBA auth, SSL/TLS                          │
│  ─────────────────────────────────────────────────────────────────────────  │
│  HashiCorp Vault    1.15        PostgreSQL 15+, Consul (optional)          │
│  ─────────────────────────────────────────────────────────────────────────  │
│  Drools             8.45        Java 17+, Maven 3.9+                      │
│  ─────────────────────────────────────────────────────────────────────────  │
│  Elasticsearch      8.11        JDK 17+                                    │
│  ─────────────────────────────────────────────────────────────────────────  │
│  Splunk             9.1+        Linux/Windows                              │
│  ─────────────────────────────────────────────────────────────────────────  │
│  CyberArk          14.0        Windows Server 2019+, SQL Server           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Recommandations Détaillées

### 4.1 Choix Cloud vs On-Premise

| Critère | Cloud Public | Cloud Sovereign | On-Premise | Hybride |
|---------|-------------|-----------------|------------|---------|
| **Contrôle données** | ✗ | ✓✓ | ✓✓✓ | ✓✓ |
| **Coût** | ✓✓ | ✓ | ✗ | ✓ |
| **Évolutivité** | ✓✓ | ✓✓ | ✗ | ✓✓ |
| **Souveraineté** | ✗ | ✓✓ | ✓✓✓ | ✓✓ |
| **Conformité** | ✗ | ✓✓ | ✓✓✓ | ✓✓ |

**Recommandation:** Architecture hybride avec:
- Données sensibles: On-premise ou cloud sovereign (OVH, Scaleway)
- Services managés: Cloud sovereign (Azure France, AWS eu-west-3)
- DR: Site secondaire géographique

### 4.2 Standards et Certifications Requis

| Certification | Niveau Requis | Échéance |
|---------------|---------------|----------|
| ISO 27001 | Mandatory | Phase 2 |
| eIDAS (TSM) | Mandatory | Phase 3 |
| SecNumCloud | Mandatory | Phase 3 |
| HDS (si santé) | Si applicable | Phase 2 |

### 4.3 Roadmap d'Implémentation

```
Phase 1 (M1-M6):
├── Keycloak + FIDO2 ──────────▶ [Obligatoire]
├── Kong API Gateway ──────────▶ [Obligatoire]
├── PostgreSQL + Vault ──────────▶ [Obligatoire]
└── ELK Stack ──────────────────▶ [Obligatoire]

Phase 2 (M7-M12):
├── CyberArk PAM ──────────────▶ [Critique]
├── Drools Rules Engine ───────▶ [Critique]
├── Kafka Event Bus ───────────▶ [Critique]
└── Splunk SIEM ────────────────▶ [Élevé]

Phase 3 (M13-M18):
├── ML Platform ───────────────▶ [Élevé]
├── SOAR Platform ─────────────▶ [Élevé]
├── Hyperledger Fabric ────────▶ [Innovation]
└── Attestation Service ────────▶ [Innovation]
```

---

## 5. Coûts de Licence (Estimation Annuelle)

| Solution | Type | Coût Estimé (k€/an) |
|----------|------|---------------------|
| Keycloak | Open Source | 0 (support optionnel: 100) |
| Kong Enterprise | Licence | 150-300 |
| CyberArk Core | Licence | 400-600 |
| Splunk Enterprise | Licence | 300-500 |
| HashiCorp Vault | Licence | 100-200 |
| Kafka (Confluent) | Licence | 100-200 |
| Drools (Red Hat) | Licence | 50-100 |
| Thales Luna HSM | Achat | 150-300 (amortissement) |
| **Total licences** | | **1250-2300** |

---

## 6. Équipe Requise

### 6.1 Equipe Architecture & Implémentation

| Rôle | Nombre | Profil |
|------|--------|--------|
| Architecte Sécurité | 1 | Expert Zero-Trust, IAM |
| Architecte Cloud/Infrastructure | 1 | Kubernetes, Cloud |
| Développeur Full-Stack | 2 | API, Frontend |
| Ingénieur IAM | 1 | Keycloak, FIDO2 |
| Ingénieur PAM | 1 | CyberArk |
| Ingénieur Data | 1 | PostgreSQL, Kafka |
| Ingénieur DevOps | 2 | K8s, CI/CD |
| Expert Cryptographie | 1 (externe) | HSM, PKI |

### 6.2 Equipe Run

| Rôle | Nombre | Disponibilité |
|------|--------|----------------|
| DevOps / SRE | 2 | 24/7 |
| Support N2/N3 | 3 | 8x5 |
| Analyste SIEM | 1 | 24/7 (astreinte) |

---

*Document Stack Technologique - Version 1.0*
*Date: 2026-02-23*
