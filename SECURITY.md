# Security Policy

## Supported Versions

Pre-1.0 release line currently maintained:

- `0.9.x` (active)

## Reporting a Vulnerability

Please report vulnerabilities privately before any public disclosure.

1. Open a **private security advisory** on GitHub (preferred).
2. Include:
   - affected crate/module and version,
   - impact assessment,
   - reproduction steps or PoC,
   - suggested fix (if available).
3. If advisory flow is unavailable, contact maintainers through repository contacts and request private handling.

## Disclosure Process

- We acknowledge receipt as quickly as possible.
- We triage severity and affected scope.
- We prepare and test a fix.
- We publish patched versions and release notes.
- We credit reporters unless anonymity is requested.

## Scope Notes

This project contains cryptographic and verification components. Please prioritize reports related to:

- signature verification bypass,
- KEM/key exchange misuse,
- deterministic serialization ambiguity,
- ledger immutability/integrity bypass,
- secret exposure in API or memory handling.

## Security Artifacts

- Formal STRIDE threat model: `docs/THREAT_MODEL_STRIDE.md`
- Pre-audit technical status: `docs/PRE_AUDIT_AUTOMATIQUE_2026-02-27.md`
- Security hardening notes: `docs/SECURITY_HARDENING_v0.9.4.md`
- Signed SBOM workflow: `.github/workflows/sbom.yml`
