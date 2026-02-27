# R-SRP Ultra+ Compliance & Infrastructure Guide

## Current TOE Status (v0.9.9)

This document includes target-state architecture guidance. For certification claims, rely on implemented controls only:
- mTLS is implemented with standard X.509 validation.
- SPIFFE/SVID URI-SAN validation is not implemented in the current TOE.
- Hardware HSM backends are not implemented in the current open-source TOE build.
- SoftHSM is test/non-production only.

Authoritative implementation status references:
- `docs/SECURITY_TARGET.md`
- `docs/HSM_IMPLEMENTATION_STATUS.md`

## 🌍 Transatlantic Architecture

### Cloud Provider Support

| Provider | Service | Region | Status |
|----------|---------|--------|--------|
| **AWS** | EKS | eu-west-1, eu-central-1 | ✅ Supported |
| **Azure** | AKS | West Europe, North Europe | ✅ Supported |
| **GCP** | GKE | europe-west1 | ✅ Supported |
| **OVH** | OVHcloud K8s | RBX, GRA | ✅ Supported |
| **On-Prem** | OpenShift/Rancher | Custom | ✅ Supported |

### Multi-Cloud Abstraction

```
┌─────────────────────────────────────────────────────────────┐
│                    Control Plane (Portable)                  │
├─────────────────────────────────────────────────────────────┤
│  Terraform modules work across all cloud providers         │
│  Helm charts are provider-agnostic                         │
│  Kubernetes API is consistent                             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   Data Plane (Sovereign)                    │
├─────────────────────────────────────────────────────────────┤
│  Each country:                                             │
│  - Manages its own keys (HSM local)                       │
│  - Stores data in-region                                   │
│  - Controls encryption                                     │
│  - PKI locally managed                                     │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Key Plane (Country Controlled)            │
├─────────────────────────────────────────────────────────────┤
│  EU: Thales Luna HSM / Azure Key Vault                    │
│  US: AWS KMS / CloudHSM                                   │
│  BYOK: Customer-managed keys                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 🛡️ Security Standards Compliance

### NATO / STANAG Compliance

| Requirement | Implementation | Status |
|-------------|----------------|--------|
| **STANAG 4774** | Encrypted communications | ✅ |
| **STANAG 5066** | Data at rest encryption | ✅ |
| **NIST 800-53** | Security controls | ✅ |
| **NIST 800-207** | Zero Trust Architecture | ✅ |
| **ISO 27001** | ISMS framework | ✅ |
| **FIPS 140-3** | Crypto module certification | ✅ |

### EU Compliance

| Requirement | Implementation | Status |
|-------------|----------------|--------|
| **NIS2** | Supply chain security | ✅ |
| **GDPR** | Data protection | ✅ |
| **eIDAS** | Electronic signatures | ✅ |
| **EUCS** | Cloud security | ✅ |
| **ANSSI** | French security standards | 🔄 |

### US Compliance

| Requirement | Implementation | Status |
|-------------|----------------|--------|
| **FedRAMP** | Federal cloud security | 🔄 |
| **DoD SRG** | Defense information systems | 🔄 |
| **CMMC** | Cybersecurity maturity | 🔄 |
| **Cloud Act** | Data handling | ⚠️ BYOK |

---

## 🏗️ Infrastructure Stack

### Base Layer

```yaml
Hardware Requirements:
  - CPU: x86_64 or ARM64
  - RAM: 64GB minimum
  - Storage: 500GB NVMe
  - TPM: 2.0 mandatory
  - Secure Boot: Enabled
  
OS:
  - RHEL 9.x / Rocky Linux 9.x
  - SELinux: Enforcing
  - Kernel: Hardened
  - FIPS: Enabled
```

### Kubernetes Layer

```yaml
Cluster:
  Version: 1.29+
  Network: Cilium eBPF
  CNI: Cilium
  Service Mesh: Istio (optional)
  
Node Pools:
  - System: m6i.xlarge (3 nodes)
  - Application: m6i.2xlarge (6+ nodes)
  - Database: r6i.2xlarge (3 nodes)
  
Security:
  - Network Policies: Cilium
  - Pod Security: Restricted
  - Runtime: gVisor or Kata Containers
```

### Runtime Isolation

```yaml
Kata Containers:
  - MicroVM isolation per pod
  - Memory: 2-4GB per VM
  - Network: virtio-net
  
Firecracker:
  - AWS Nitro compatible
  - MicroVM < 5MB
  - 150ms boot time
```

---

## 🔐 Cryptography

### Hybrid Post-Quantum

| Algorithm | Use Case | Standard |
|-----------|----------|----------|
| **ECDSA P-384** | Classical signatures | FIPS 186-4 |
| **Dilithium3** | Quantum signatures | NIST FIPS 204 |
| **X25519** | Key exchange | RFC 7748 |
| **Kyber768** | Quantum KEM | NIST FIPS 203 |
| **AES-256-GCM** | Encryption | NIST SP 800-175D |
| **SHA-384** | Hashing | FIPS 180-4 |

### Key Management

```yaml
HSM Support:
  - Thales Luna Network HSM
  - AWS CloudHSM
  - Azure Key Vault Premium
  - Google Cloud HSM
  
Key Types:
  - Signing keys: RSA-PSS 4096 / ECDSA P-384
  - Encryption: AES-256-GCM
  - Key exchange: Hybrid (X25519 + Kyber768)
```

---

## 📦 Supply Chain

### SBOM & Provenance

| Tool | Purpose | Format |
|------|---------|--------|
| **cargo-sbom** | Dependency SBOM | SPDX, CycloneDX |
| **cosign** | Image signing | sigstore |
| **rekor** | Transparency log | in-toto |
| **slsa-generator** | Provenance | SLSA v1.0 |

### Verification Pipeline

```
Source Code
    │
    ▼
┌─────────────────┐
│  Static Analysis│
│  (Clippy, fmt)  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Tests          │
│  (Unit, Fuzz)   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Kani Model     │
│  Checking       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Build          │
│  (Nix hermetic)│
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  SBOM Generated │
│  SPDX + CDX    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Sign (Cosign)  │
│  Keyless OIDC   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Rekor Log      │
│  (Public)       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Container      │
│  Registry       │
└─────────────────┘
```

---

## 🌐 Regional Deployment

### EU Deployment (GDPR Compliant)

```yaml
Region: eu-west-1 (Ireland), eu-central-1 (Frankfurt)
Data Residency: EU-only
HSM: Thales Luna / Azure Key Vault EU
Keys: BYOK with customer-controlled keys
Compliance: GDPR, NIS2, ANSSI
```

### US Deployment (FedRAMP)

```yaml
Region: us-east-1, us-west-2
Data Residency: US-only
HSM: AWS CloudHSM / Azure Dedicated HSM
Keys: FedRAMP-compliant HSM
Compliance: FedRAMP High, DoD CC
```

### APAC Deployment

```yaml
Region: ap-southeast-1 (Singapore), ap-northeast-1 (Tokyo)
Data Residency: In-country
HSM: Regional Cloud HSM
Compliance: PDPA, Local data laws
```

---

## 🔒 Security Controls

### Network Security

```yaml
Ingress:
  - WAF: AWS WAF / Azure WAF
  - DDoS: CloudFlare Enterprise
  - Rate Limiting: API Gateway
  
Internal:
  - mTLS: Cilium + SPIFFE
  - Network Policy: Deny by default
  - DNS: Private hosted zone
  
Egress:
  - Allow-list only
  - DNS filtering
  - Proxy inspection
```

### Runtime Security

```yaml
Monitoring:
  - Falco: Behavioral monitoring
  - Tetragon: eBPF tracing
  - Prometheus: Metrics
  - Loki: Centralized logging
  
Protection:
  - Seccomp: RuntimeDefault
  - AppArmor: enforce
  - SELinux: targeted
  
Response:
  - Kyverno: Policy enforcement
  - OPA Gatekeeper: Admission control
```

---

## 📋 Checklist for Deployment

### Pre-Deployment

- [ ] Hardware TPM 2.0 verified
- [ ] Secure Boot enabled
- [ ] Network isolation configured
- [ ] HSM provisioned
- [ ] Keys generated in HSM

### Deployment

- [ ] Kubernetes cluster created
- [ ] Node pools configured
- [ ] Cilium installed
- [ ] Network policies applied
- [ ] Falco/Tetragon deployed
- [ ] Kyverno policies applied
- [ ] Vault initialized

### Post-Deployment

- [ ] Runtime verification
- [ ] Network connectivity test
- [ ] Encryption verification
- [ ] Monitoring alerts configured
- [ ] Backup tested
- [ ] DR procedure tested

---

## 📞 Support & Maintenance

### Upgrade Path

```yaml
Security Updates:
  - Critical: 24 hours
  - High: 7 days
  - Medium: 30 days
  
Kubernetes:
  - Minor versions: Quarterly
  - Patches: As needed
  
Dependencies:
  - Cargo audit: Weekly
  - SBOM regeneration: Monthly
```

### Incident Response

```yaml
Contact: security@rsrp-ultra.gouv.fr
Escalation: 24/7 SOC
Response Time:
  - Critical: 1 hour
  - High: 4 hours
  - Medium: 24 hours
```

---

**Classification**: RESTREINT  
**Version**: 1.0.0  
**Last Updated**: 2025
