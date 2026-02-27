# R-SRP Incident Response Plan

Version: 0.9.9  
Date: 2026-02-27  
Owner: Security Operations

## 1. Scope

This plan defines incident response for:
- cryptographic compromise suspicion,
- signing key misuse or leakage,
- supply-chain compromise,
- integrity failure in immutable logging/proof verification,
- production service abuse affecting security controls.

## 2. Reporting Channels

- Security mailbox: `security@rsrp.io`
- Internal urgent escalation: on-call security lead (24/7 rota)
- Public vulnerability disclosure entrypoint: `SECURITY.md`

For regulated deployments, operator runbooks must include local authority notification path (for example CERT-FR/ANSSI contact chain) according to contract and jurisdiction.

## 3. Severity Model and SLA

| Severity | Example | Triage SLA | Containment SLA | Communication SLA |
|---|---|---|---|---|
| Critical | active key compromise, forged signature accepted, supply-chain artifact substitution | 1 hour | 24 hours | 24 hours |
| High | exploitable auth bypass, severe confidentiality/integrity weakness | 4 hours | 72 hours | 72 hours |
| Medium | hardening gap without active exploitation | 24 hours | 30 days | 30 days |
| Low | documentation/process issue with no immediate exploitation path | 5 business days | planned cycle | planned cycle |

## 4. Incident Lifecycle

1. Detection and intake:
   - create incident ID and preserve initial evidence.
2. Triage:
   - classify severity and impacted components.
3. Containment:
   - fail-closed measures first (disable risky path, revoke compromised key IDs, block unsafe rollout).
4. Eradication and recovery:
   - patch root cause, rotate credentials/keys, replay integrity checks.
5. Validation:
   - rerun security gates and targeted regression suite.
6. Closure:
   - issue post-incident report with corrective/preventive actions.

## 5. Mandatory Technical Actions by Incident Type

- Key compromise:
  - revoke affected key IDs immediately,
  - rotate keys and record immutable audit evidence,
  - re-sign impacted artifacts/publications as required.
- Supply-chain compromise suspicion:
  - halt release pipeline,
  - regenerate SBOM/provenance/signatures from trusted clean environment,
  - compare digests with archived manifests.
- Ledger integrity alert:
  - stop publication,
  - verify chain and compact proofs from trusted snapshot,
  - perform WAL continuity and off-host evidence verification.

## 6. Evidence and Audit Trail

Each incident record must include:
- incident ID, severity, timestamps, owner,
- affected versions/commits/artifacts,
- containment and remediation actions,
- proof of verification (tests, CI run IDs, manifests, signatures),
- closure approval.

## 7. Communication Rules

- Do not disclose sensitive exploit details before containment.
- Publish coordinated disclosure after fix readiness and impact assessment.
- Maintain a changelog entry linking impacted versions and remediation release.

## 8. Governance

This plan is release-blocking for certification bundle completeness and must stay aligned with:
- `docs/SECURITY_TARGET.md`
- `docs/CERTIFICATION_BUNDLE.md`
- `docs/DEPENDENCY_RISK_ASSESSMENT.md`
- `SECURITY.md`
