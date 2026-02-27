# 🛡 R-SRP Formal Threat Model

## Version: 1.0  
## Date: 2026-02-24  
## Classification: Internal

---

## 0. Production-Hardening Addendum (2026-02-27)

- Frozen production crypto baseline:
  - `ML-KEM-768`
  - `ML-DSA-65`
- Production feature gate now maps to:
  - `production = ["real-crypto", "kyber768", "dilithium3"]`
- Hybrid mode is mandatory in production:
  - runtime rejects disabling hybrid requirements
- In production-hardening:
  - debug/trace logging levels are rejected at startup
  - mock backend use is blocked in release builds

---

## 1. Executive Summary

This document provides a comprehensive threat model for the R-SRP (Risk-Based Security Policy Engine) system. The analysis uses the **STRIDE** methodology to identify potential threats and provides CVSS-based risk scoring for each identified vulnerability.

### Scope
- Core R-SRP Engine
- CRUE DSL Parser
- Crypto Core Module
- Immutable Logging
- API Service

### Out of Scope
- Third-party integrations (future)
- Infrastructure (covered by cloud provider)
- Physical security

---

## 2. System Overview

### 2.1 Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                            R-SRP SYSTEM                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐          │
│  │   CLIENTS    │────▶│ API SERVICE  │────▶│CRUE ENGINE  │          │
│  │  (Untrusted)  │     │  (DMZ)       │     │  (Trusted)   │          │
│  └──────────────┘     └──────┬───────┘     └──────┬───────┘          │
│                              │                     │                   │
│                              ▼                     ▼                   │
│                      ┌──────────────┐     ┌──────────────┐          │
│                      │   IDENTITY   │     │   CRUE DSL   │          │
│                      │    LAYER     │     │   PARSER     │          │
│                      │  (Trusted)   │     │  (Trusted)   │          │
│                      └──────┬───────┘     └──────┬───────┘          │
│                             │                     │                   │
│                             ▼                     ▼                   │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │                    TRUST BOUNDARY                            │    │
│  │         (Enforced by mTLS + RBAC + Validation)             │    │
│  └──────────────────────────────────────────────────────────────┘    │
│                              │                                        │
│                              ▼                                        │
│                      ┌──────────────┐                                │
│                      │CRYPTO CORE   │                                │
│                      │ (Critical)    │                                │
│                      │ (HSM)        │                                │
│                      └──────┬───────┘                                │
│                             │                                         │
│                             ▼                                         │
│                      ┌──────────────┐                                │
│                      │ IMMUTABLE    │                                │
│                      │   LOGGING    │                                │
│                      │(WORM Storage)│                                │
│                      └──────────────┘                                │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Trust Boundaries

| Boundary | Type | Description | Enforcement |
|----------|------|-------------|-------------|
| External → API | **Untrusted** | Internet to API | TLS + Auth |
| API → Internal | **DMZ** | API to Services | mTLS |
| Services → Core | **Trusted** | Engine to Crypto | RBAC |
| Core → Storage | **Enforced** | Keys + Logs | Validation |
| Storage | **Never Trusted** | All storage | Immutability |

---

## 3. Data Flow Diagrams

### 3.1 Primary Data Flows

```
┌─────────┐     ┌─────────┐     ┌─────────┐     ┌─────────┐     ┌─────────┐
│ Request │────▶│ AuthN   │────▶│ Parser  │────▶│ Engine  │────▶│ Decision│
│ Ingress │     │ Check   │     │ (CRUE)  │     │ Eval    │     │ Output  │
└─────────┘     └────┬────┘     └────┬────┘     └────┬────┘     └────┬────┘
                    │               │               │               │
                    ▼               ▼               ▼               ▼
              ┌─────────┐     ┌─────────┐     ┌─────────┐     ┌─────────┐
              │  JWT    │     │  AST    │     │  Hash   │     │  Audit  │
              │ Verify  │     │ Build   │     │ Compute │     │  Log    │
              └─────────┘     └─────────┘     └─────────┘     └─────────┘
```

### 3.2 Key Data Elements

| Element | Sensitivity | Classification |
|---------|-------------|----------------|
| User Credentials | High | PII |
| JWT Tokens | High | Auth |
| Signing Keys | Critical | Crypto |
| Policy Rules | Medium | Config |
| Audit Logs | High | Compliance |
| Decision Results | Medium | Business |

---

## 4. Attack Surface Map

### 4.1 Entry Points

| ID | Entry Point | Protocol | Authentication | Network | Notes |
|----|-------------|----------|----------------|---------|-------|
| EP-01 | API Gateway | HTTPS | JWT/API Key | External | Main entry |
| EP-02 | Health Check | HTTP | **Internal Only** | Private | LB restriction required |
| EP-03 | Metrics Endpoint | HTTP | **Internal Only** | Private | IP allowlist required |
| EP-04 | Admin Interface | HTTPS | **mTLS** | Internal | Strict auth |

### 4.2 Exit Points

| ID | Exit Point | Destination | Data |
|----|------------|-------------|------|
| EX-01 | SOC Webhook | External | Alerts |
| EX-02 | TSA Server | External | Timestamps |
| EX-03 | HSM | Hardware | Keys |

---

## 5. STRIDE Analysis

### 5.1 STRIDE Matrix

| Component | Spoofing | Tampering | Repudiation | Information Disclosure | Denial of Service | Elevation of Privilege |
|-----------|----------|-----------|-------------|------------------------|-------------------|------------------------|
| API Service | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| CRUE Parser | - | ✅ | - | ✅ | ✅ | ✅ |
| Crypto Core | - | ✅ | ✅ | ✅ | - | ✅ |
| Immutable Log | - | ✅ | ✅ | - | ✅ | - |
| Identity Layer | ✅ | - | ✅ | ✅ | - | ✅ |

### 5.2 Detailed Threat Analysis

#### API Service Threats

| ID | Threat | STRIDE | CVSS | Severity | Mitigation |
|----|--------|--------|------|----------|-----------|
| T-001 | JWT forging | Spoofing | 9.1 | Critical | Signature validation, short expiry |
| T-002 | Request tampering | Tam.5pering | 7 | High | TLS + HMAC |
| T-003 | Log deletion | Repudiation | 6.8 | Medium | Immutable storage |
| T-004 | Config exposure | Info Disclosure | 8.2 | High | Encryption at rest |
| T-005 | DoS via requests | DoS | 7.2 | High | Rate limiting |
| T-006 | Privilege escalation | EoP | 8.8 | Critical | RBAC + validation |

#### CRUE Parser Threats

| ID | Threat | STRIDE | CVSS | Severity | Mitigation |
|----|--------|--------|------|----------|-----------|
| T-010 | Malformed rule injection | Tampering | 7.8 | High | Schema validation |
| T-011 | Regex DoS (ReDoS) | DoS | 8.5 | Critical | Timeout + limits |
| T-012 | Logic bypass | EoP | 8.1 | High | Sandboxed execution |
| T-013 | Rule extraction | Info Disclosure | 6.5 | Medium | Encryption |

#### Crypto Core Threats

| ID | Threat | STRIDE | CVSS | Severity | Mitigation |
|----|--------|--------|------|----------|-----------|
| T-020 | Weak key generation | Tampering | 9.3 | Critical | OsRng + FIPS |
| T-021 | Key exposure | Info Disclosure | 9.8 | Critical | Zeroize + HSM |
| T-022 | Signature forgery | Spoofing | 8.9 | Critical | Proper validation |
| T-023 | Non-repudiation fail | Repudiation | 7.0 | High | TSA anchoring |

#### Immutable Logging Threats

| ID | Threat | STRIDE | CVSS | Severity | Mitigation |
|----|--------|--------|------|----------|-----------|
| T-030 | Log tampering | Tampering | 8.3 | High | Hash chain |
| T-031 | Fork attack | Tampering | 6.8 | Medium | TSA anchoring |
| T-032 | Log deletion | Repudiation | 7.5 | High | WORM storage |
| T-033 | Chain gap | Repudiation | 5.5 | Medium | Continuous anchoring |

---

## 6. CVSS Scoring Summary

### Critical (≥9.0)
| ID | Threat | Score | Vector |
|----|--------|-------|--------|
| T-001 | JWT Forgery | 9.1 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N |
| T-020 | Weak Key Gen | 9.3 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| T-021 | Key Exposure | 9.8 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| T-006 | Privilege Escalation | 8.8 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |

### High (7.0-8.9)
| ID | Threat | Score |
|----|--------|-------|
| T-011 | ReDoS | 8.5 |
| T-030 | Log Tampering | 8.3 |
| T-010 | Rule Injection | 7.8 |
| T-002 | Request Tampering | 7.5 |
| T-004 | Config Exposure | 8.2 |
| T-005 | DoS | 7.2 |
| T-012 | Logic Bypass | 8.1 |
| T-022 | Sig Forgery | 8.9 |

### Medium (4.0-6.9)
| ID | Threat | Score |
|----|--------|-------|
| T-003 | Log Deletion | 6.8 |
| T-031 | Fork Attack | 6.8 |
| T-033 | Chain Gap | 5.5 |
| T-013 | Rule Extraction | 6.5 |

---

## 7. Mitigation Mapping

| Threat ID | Mitigation Required | Priority | Status |
|-----------|---------------------|----------|--------|
| T-001 | JWT validation, short expiry | P0 | ✅ |
| T-020 | OsRng + entropy check | P0 | ✅ |
| T-021 | Zeroize + HSM | P0 | ✅ |
| T-006 | RBAC + input validation | P0 | ✅ |
| T-011 | Regex timeout + limits | P0 | ✅ |
| T-004 | Encryption at rest | P1 | ✅ |
| T-005 | Rate limiting | P1 | ✅ |
| T-030 | Hash chain verification | P1 | ✅ |
| T-031 | TSA anchoring | P1 | ✅ |
| T-012 | WASM sandbox | P2 | 🔄 |
| T-013 | Rule encryption | P2 | 🔄 |

---

## 8. Risk Acceptance

| Threat | Residual Risk | Accepted By | Date |
|--------|---------------|-------------|------|
| T-031 (Fork Attack) | Low | Security Team | 2026-02-24 |
| T-033 (Chain Gap) | Low | Security Team | 2026-02-24 |

---

---

## 10. Assumptions & Constraints

### System Assumptions
| ID | Assumption | Risk if Violated |
|----|------------|------------------|
| A-01 | System runs on isolated network | External attack |
| A-02 | HSM is physically secured | Key compromise |
| A-03 | Operators are trusted | Insider threat |
| A-04 | TSA server is available | Non-repudiation failure |
| A-05 | Logs are stored immutably | Audit evidence loss |
| A-06 | Keys rotated annually | Cryptographic weakness |

### Constraints
| ID | Constraint | Impact |
|----|------------|--------|
| C-01 | No cloud HSM integration | Manual key management |
| C-02 | Single-region deployment | DR limitations |

---

## 11. Abuse Cases

| ID | Abuse Case | Threat IDs | Impact | Severity |
|----|------------|------------|--------|----------|
| AB-01 | Attacker obtains JWT via phishing | T-001 | Account takeover | Critical |
| AB-02 | Insider modifies policy rules | T-010, T-012 | Policy bypass | Critical |
| AB-03 | Malicious actor steals signing keys | T-021 | Signature forgery | Critical |
| AB-04 | Attacker deletes audit logs | T-030, T-032 | Evidence destruction | High |
| AB-05 | DoS attack on API | T-005, T-011 | Service unavailable | High |
| AB-06 | Information disclosure via metrics | EP-03 | Reconnaissance | Medium |
| AB-07 | Fork attack on log chain | T-031 | Timestamp fraud | Medium |

---

## 12. STRIDE → ISO Annex A Mapping

| STRIDE | ISO Annex A Control | R-SRP Implementation |
|--------|---------------------|----------------------|
| Spoofing | A.9.4.2 Secure logon | JWT + mTLS |
| Tampering | A.12.4.2 Protection of log info | Hash chain + TSA |
| Repudiation | A.12.4.3 Event logging | Immutable logs |
| Info Disclosure | A.10.1.1 Cryptographic controls | Encryption at rest |
| DoS | A.13.1.3 DoS protection | Rate limiting |
| EoP | A.9.4.3 Password management | RBAC validation |

---

## 13. Risk Heatmap

```
Impact
  9.0 ┌─────┬─────┬─────┬─────┬─────┐
      │ C   │     │     │     │     │
  7.0 ┼─────┼─────┼─H──┼─────┼─────┤
      │     │     │    │     │     │
  5.0 ┼─────┼─────┼─────┼─M──┼─────┤
      │     │     │    │    │     │
  3.0 ┼─────┼─────┼─────┼─────┼─L──┤
      └─────┴─────┴─────┴─────┴─────┘
         1.0   3.0   5.0   7.0   9.0
                    Likelihood
```

| Cell | Threats |
|------|---------|
| **Critical (H×H)** | T-001, T-020, T-021 |
| **High (H×M, M×H)** | T-002, T-004, T-005, T-006, T-010, T-011, T-012, T-022, T-030, T-032 |
| **Medium (M×M)** | T-003, T-013, T-031, T-033 |

---

## 14. Threat Review Sign-Off

### Formal Approval Required

| Role | Name | Date | Signature |
|------|------|------|-----------|
| CISO | _________________ | _________ | __________ |
| Security Lead | _________________ | _________ | __________ |
| Architect | _________________ | _________ | __________ |
| Compliance | _________________ | _________ | __________ |

### Review Checklist
- [ ] All threats reviewed and categorized
- [ ] Mitigations implemented or planned
- [ ] Residual risks accepted by stakeholders
- [ ] ISO Annex A mapping validated
- [ ] Abuse cases documented
- [ ] Risk heatmap reviewed

### Next Review Date: ____________

---

## 9. Review & Updates

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-02-24 | R-SRP Team | Initial threat model |

---

*This threat model shall be reviewed quarterly or after significant architecture changes.*
