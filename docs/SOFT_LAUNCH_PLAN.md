# RSRP Soft Launch Plan

*Publisher: Rsrp Systems | Author: Aymeric Le Cloitre-Maternat (ALM)*

---

## 🎯 Objectives

**Not:**
- ❌ Buzz marketing
- ❌ Aggressive LinkedIn posts
- ❌ Press releases

**Real goals:**
- ✅ Test public stability
- ✅ Observe real usage
- ✅ Fix API before traction
- ✅ Measure organic interest
- ✅ Build silent credibility

---

## 🧱 PHASE 1 — Controlled Pre-Release (2–3 weeks)

### Version

**Publish:** `v0.9.0-preview`

**NOT:** `v1.0.0`

This signals: "Stable but evolving."

### Install Commands

```bash
# All-in-one (recommended - future)
# Not yet available for Rust

# Individual crates (Rust)
cargo add crue-engine
cargo add immutable-logging
cargo add crypto-core
cargo add pqcrypto
```

### Crates.io Settings

**Note:** This project uses Rust, not .NET. Packages are published to **crates.io**, not NuGet.

- ✅ Public listing
- ❌ No big announcement
- Minimalist release notes
- Clean Git tag

### README Content

**NOT:**
- Grand sovereign speeches
- Defense rhetoric
- Certification claims

**JUST:**

```
# Rsrp.ProofEngine

Deterministic Proof Engine for .NET
```

Simple. Honest. Technical.

---

## 🔍 PHASE 2 — Silent Observation (30 days)

### What to Monitor

| Metric | Target |
|--------|--------|
| Downloads/day | 10-50 |
| Issues opened | < 5 |
| External integrations | 0-2 |
| Stars | Organic only |

### What NOT to Do

- ❌ Don't force engagement
- ❌ Don't seed discussions
- ❌ Don't boost metrics
- ❌ Don't announce on social media

**If it grows naturally → Good signal.**

---

## 🛠 PHASE 3 — API Stabilization

During soft launch:

1. **Fix API friction**
   - Simplify instantiation
   - Improve error messages
   - Reduce cognitive load

2. **Performance optimization**
   - Benchmark critical paths
   - Reduce allocations
   - Optimize hot paths

3. **Documentation polish**
   - Fix unclear sections
   - Add missing examples
   - Improve "Getting Started"

### Goal: `v1.0.0` - Truly Stable

---

## 📊 KPIs to Measure

### Technical KPIs

| Metric | Target |
|--------|--------|
| Average integration time | < 30 min |
| Critical issues | 0 |
| Crypto bugs | 0 |
| DI/ASP.NET issues | < 3 |

### Market KPIs

| Metric | Target |
|--------|--------|
| Unique downloads | 500-2000 |
| Forks | 10-50 |
| GitHub mentions | Organic |
| Stars | Natural |

---

## 📋 Launch Checklist

### Pre-Launch

- [ ] Set version to `v0.9.0-preview`
- [ ] Clean up git tags
- [ ] Verify crates.io listing
- [ ] Test clean install
- [ ] Verify minimal README
- [ ] Remove all "sovereign" rhetoric

### Post-Launch (Day 1-7)

- [ ] Monitor download metrics
- [ ] Check error logs
- [ ] Review any issues
- [ ] Fix critical bugs only

### Post-Launch (Day 8-30)

- [ ] Analyze usage patterns
- [ ] Collect feedback
- [ ] Plan API fixes for v0.9.1
- [ ] Document friction points

---

## 🚀 Communication Style

### What to Say

```markdown
# Rsrp.ProofEngine

Deterministic Proof Engine for .NET

A lightweight decision engine with cryptographic proof generation.
```

### What NOT to Say

```markdown
# ❌ DON'T

"First sovereign proof infrastructure"
"Government-grade security"
"Classified-ready technology"
"Revolutionary zero-trust platform"
```

---

## 📈 Success Criteria

| Phase | Milestone |
|-------|-----------|
| Phase 1 | v0.9.0-preview published |
| Phase 2 | 30 days without major incidents |
| Phase 3 | API stabilized, ready for v1.0 |

---

## 🔐 Important Notes

1. **No certification claims** - Don't mention FIPS, SecNumCloud, etc. in public docs
2. **No sovereign rhetoric** - Keep it technical, not political
3. **No enterprise features in preview** - HSM, Vault, mTLS come later
4. **Focus on developers** - They're the target audience

---

## 📞 Contact

- **GitHub Issues**: For bugs and feature requests
- **Discussions**: For technical questions
- **Email**: Will be added after entity creation

---

*Rsrp Systems — Building proof infrastructure, one commit at a time.*
