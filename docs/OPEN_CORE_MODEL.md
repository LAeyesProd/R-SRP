# RSRP Open Core Model

*Publisher: Rsrp Systems | Author: Aymeric Le Cloitre-Maternat (ALM)*

## Overview

RSRP follows the **Open Core** business model, providing a solid foundation of open-source capabilities while monetizing enterprise-grade features.

---

## 🟢 Community Edition (Apache 2.0 / MIT)

**Goal**: Adoption + credibility + ecosystem growth

### Included Packages

| Package | Crate(s) | Description |
|---------|----------|-------------|
| **Rsrp.ProofEngine** | `crue-engine` + `crue-dsl` | Deterministic decision engine, policy evaluation, proof generation |
| **Rsrp.ImmutableLedger** | `immutable-logging` | Append-only ledger, Merkle trees, proof verification |
| **Rsrp.Security.Core** | `pqcrypto` + `crypto-core` | Signature abstraction, key management, PQ abstraction |
| **Rsrp.AspNetCore** | (NuGet) | ASP.NET Core integration, middleware, DI helpers |

### Features

✅ Deterministic rule execution  
✅ Cryptographic proof generation  
✅ Immutable hash chaining  
✅ Basic Ed25519 signatures  
✅ SHA-256 / BLAKE3 hashing  
✅ Merkle tree verification  
✅ JSON export  
✅ Basic documentation  
✅ Community support (GitHub)  

### Limitations

❌ No HSM integration  
❌ No post-quantum (PQ) algorithms by default  
❌ No advanced key lifecycle  
❌ No mTLS mesh  
❌ No deployment templates  
❌ No SLA  

### Target Users

- Startups building critical systems
- Open-source projects requiring audit trails
- Developers evaluating the technology
- Academic research

---

## 🔵 Enterprise Edition (Commercial License)

**Goal**: Revenue + enterprise adoption

### Additional Packages

| Package | Description | Pricing |
|---------|-------------|---------|
| **Rsrp.Enterprise.HSM** | PKCS#11, Thales Luna, AWS CloudHSM | Per-seat + infrastructure |
| **Rsrp.Enterprise.Vault** | HashiCorp Vault integration | Subscription |
| **Rsrp.Enterprise.Auditor** | Real-time compliance dashboard | Annual license |

### Features

✅ Full HSM support (PKCS#11)  
✅ Thales Luna Network HSM  
✅ AWS CloudHSM / Azure Key Vault  
✅ Advanced key lifecycle management  
✅ Vault integration  
✅ mTLS service mesh  
✅ Deployment templates (Terraform)  
✅ Kubernetes manifests  
✅ 24/7 SLA support  
✅ Certification assistance (ISO 27001, SOC 2)  
✅ Dedicated support channels  
✅ Custom development  

### Target Users

- Financial institutions
- Healthcare organizations
- Government agencies (non-classified)
- Large enterprises

### Pricing Model

```
Base Platform License: €50,000/year
Per-server: €5,000/year
HSM integration: €20,000/year
SLA (99.99%): +€15,000/year
```

---

## 🟣 Sovereign Edition (Private)

**Goal**: Classified/regulated environments

### Packages

| Package | Description |
|---------|-------------|
| **Rsrp.Sovereign.AirGapped** | Air-gapped deployment |
| **Rsrp.Sovereign.SecNumCloud** | SecNumCloud ready |
| **Rsrp.Sovereign.FIPS** | FIPS 140-2/3 validated module |
| **Rsrp.Sovereign.TPM** | TPM 2.0 attestation |

### Features

✅ Air-gapped deployment scripts  
✅ SecNumCloud (France) compliance  
✅ FIPS 140-2/3 validated crypto module  
✅ TPM 2.0 / Intel SGX attestation  
✅ Classified environment support  
✅ Custom certification support  
✅ Direct engineering support  
✅ On-premise deployment  

### Target Users

- Government agencies (classified)
- Defense contractors
- Intelligence services
- Critical national infrastructure

### Contact

```
Sovereign Sales: sovereign@rsrp.io
Direct Line: +33 1 XX XX XX XX
```

---

## Revenue Model

### Year 1-2: Community Growth

```
Objective: 2,000-5,000 downloads
         1-2 enterprise POC
         0 revenue
```

### Year 3: Early Enterprise

```
Objective: 5+ enterprise deals
         €200K-500K ARR
         First pilot programs
```

### Year 4-5: Scale

```
Objective: 20+ enterprise accounts
         €2-5M ARR
         Sovereign deals in negotiation
```

---

## Ecosystem Strategy

### Partners

| Partner Type | Examples | Value |
|--------------|----------|-------|
| SI/Integrators | Atos, Capgemini, Thales | Implementation |
| Cloud Providers | AWS, Azure, OVH | Marketplace listings |
| Security Vendors | CrowdStrike, Splunk | Integration |
| Standards Bodies | NIST, ANSSI | Certification |

### Developer Ecosystem

- **Discord**: Community discussion
- **GitHub**: Open-source contributions
- **npm/Crates.io**: Package distribution
- **Documentation**: Comprehensive guides
- **Training**: Online courses (planned)

---

## Comparison Matrix

| Feature | Community | Enterprise | Sovereign |
|---------|-----------|------------|----------|
| Decision Engine | ✅ | ✅ | ✅ |
| Immutable Ledger | ✅ | ✅ | ✅ |
| Basic Signatures | ✅ | ✅ | ✅ |
| PQ Signatures | ⚠️ Optional | ✅ | ✅ |
| HSM Support | ❌ | ✅ | ✅ |
| mTLS Mesh | ❌ | ✅ | ✅ |
| Air-Gapped | ❌ | ❌ | ✅ |
| FIPS Validated | ❌ | ⚠️ 140-2 | ✅ 140-3 |
| SecNumCloud | ❌ | ❌ | ✅ |
| SLA | ❌ | 24/7 | 24/7 + On-site |
| Support | Community | Dedicated | Engineering |

Legend: ✅ Full | ⚠️ Partial | ❌ Not included

---

## Migration Path

```
Community → Enterprise → Sovereign
    │            │            │
    │            │            │
  Free        €50K+       Contact
  GitHub      /year       Sales
  Issues      Slack       Direct
```

### Upgrading

1. **Community → Enterprise**
   - Contact sales
   - Sign license
   - Get access to private repos
   - Deployment assistance

2. **Enterprise → Sovereign**
   - Security clearance required
   - Custom contract
   - On-site deployment

---

## Brand Guidelines

### Colors

- **Community**: Green accent (`#10B981`)
- **Enterprise**: Blue accent (`#3B82F6`)
- **Sovereign**: Purple accent (`#8B5CF6`)

### Logo Usage

```
Community Edition:     RSRP Community
Enterprise Edition:    RSRP Enterprise
Sovereign Edition:    RSRP Sovereign
```

### Taglines

- Community: "Proof Infrastructure for Everyone"
- Enterprise: "Enterprise-Grade Decision Provenance"
- Sovereign: "For Classified Environments"

---

## Legal

### Community License

```
Apache 2.0 License
Copyright © 2024 RSRP
```

### Enterprise License

```
Commercial Proprietary License
Contact: enterprise@rsrp.io
```

### Sovereign License

```
Classified Distribution Agreement
Contact: sovereign@rsrp.io
```

---

## Getting Started

### Community

```bash
# Rust
cargo add crue-engine
cargo add immutable-logging

# .NET
dotnet add package Rsrp.ProofEngine
dotnet add package Rsrp.ImmutableLedger
```

### Enterprise

```
1. Contact: enterprise@rsrp.io
2. Schedule demo
3. Proof of concept
4. Pilot program
5. Production deployment
```

### Sovereign

```
1. Contact: sovereign@rsrp.io
2. Security clearance
3. Custom negotiation
4. On-site deployment
5. Ongoing support
```

---

## Summary

RSRP's open core model provides:
- **Free entry point** for adoption
- **Clear upgrade path** for enterprises
- **Specialized offering** for sovereign environments
- **Sustainable revenue** through enterprise licensing
- **Trust building** through transparency
