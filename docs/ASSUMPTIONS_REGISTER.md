# R-SRP Assumptions Register

Version: 0.9.9  
Date: 2026-02-27  
Owner: Security Engineering

## 1. Purpose

This register makes implicit assumptions explicit for external audit and certification review.

Each assumption includes:
- why it exists,
- what breaks if it fails,
- required compensating controls/evidence.

## 2. Assumptions

| ID | Assumption | If False | Required Controls / Evidence |
|---|---|---|---|
| A-001 | Production uses approved entropy sources and allowed crypto profile only. | Weak/invalid key generation path can be introduced. | `docs/ENTROPY_BOUNDARY.md`, production gate logs, runtime startup logs |
| A-002 | Key custody (HSM/KMS/operator workflow) is enforced operationally outside crate logic. | Unauthorized signing or key misuse becomes possible. | `docs/KEY_LIFECYCLE_POLICY.md`, key ceremony records, revocation logs |
| A-003 | CI runners, branch protections, and release credentials remain controlled. | Artifact substitution / supply-chain compromise risk increases. | signed provenance, SBOM, `production-gate.yml`, `signing.yml` evidence |
| A-004 | Append-only audit storage and WAL persistence are deployed as designed. | Loss of audit continuity / replay tamper risk. | immutable-log WAL config, chain verification outputs, backup/restore runbook |
| A-005 | External TSA/HSM trust anchors are managed by deployment security policy. | Timestamp/signature trust can be undermined externally. | trust-store governance records, rotation evidence, incident runbook |
| A-006 | API is deployed behind expected network controls (mTLS/ingress policy/WAF as required). | Exposure to abuse/fingerprinting and DoS increases. | deployment manifests, network policy config, monitoring evidence |
| A-007 | Production hosts keep a trusted, monitored UTC time source (NTP/PTP) and alert on drift. | Time-based RBAC and audit timestamps can be manipulated by clock drift or tampering. | time-sync policy, drift alerts, host monitoring evidence |

## 3. Hostile-Host Model (Container/VM Compromise)

Assumption:
- Host compromise is out-of-scope for cryptographic correctness claims, but in-scope for operational resilience.

Required controls for this model:
- rapid key revocation and rotation process,
- immutable evidence export off-host,
- startup integrity checks for production profile,
- incident runbook demonstrating trust re-establishment.

## 4. Governance Rule

Any new production feature that introduces a trust dependency must:
1. add/modify an assumption entry here,
2. add traceability row in `docs/TRACEABILITY_MATRIX.md`,
3. update `docs/SECURITY_TARGET.md` and (if needed) `docs/THREAT_MODEL_STRIDE.md`.
