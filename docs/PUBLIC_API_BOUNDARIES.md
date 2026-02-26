# RSRP Public API Boundaries

*Publisher: Rsrp Systems | Author: Aymeric Le Cloitre-Maternat (ALM)*

This document defines the public API surface for each package, specifying what is exposed to consumers and what remains internal.

## Design Principles

1. **Minimal Public API** — Only expose what's necessary for integration
2. **Implementation Hiding** — Internal details are opaque
3. **Semantic Versioning** — Public API changes = version bump
4. **Deprecation Policy** — 2 minor versions notice before removal

---

## Package 1: Rsrp.ProofEngine

### ✅ Public API (Exposed)

```rust
// Core trait - main entry point
pub trait IProofEngine {
    /// Evaluate a policy against input
    fn evaluate(&self, policy: &Policy, input: &EvaluationInput) -> Result<DecisionResult>;
    
    /// Get policy by ID
    fn get_policy(&self, id: &PolicyId) -> Result<Policy>;
}

/// Decision result with proof generation
pub trait IDecisionResult {
    /// The decision (Allow/Deny/Challenge)
    fn decision(&self) -> Decision;
    
    /// Generate cryptographic proof
    fn generate_proof(&self) -> Result<Proof>;
    
    /// Serialize to JSON
    fn to_json(&self) -> String;
}

/// Verifiable proof object
pub trait IProof {
    /// Verify proof validity
    fn verify(&self) -> bool;
    
    /// Get canonical hash
    fn hash(&self) -> &str;
    
    /// Get signature (if applicable)
    fn signature(&self) -> Option<&Signature>;
}

/// Policy definition
pub trait IPolicy {
    fn id(&self) -> &PolicyId;
    fn version(&self) -> u32;
    fn rules(&self) -> &[Rule];
    fn hash(&self) -> &str;
}

/// Evaluation context
pub struct EvaluationInput {
    pub agent_id: String,
    pub agent_org: String,
    pub action: String,
    pub resource: String,
    pub context: HashMap<String, String>,
}
```

### ❌ Internal (NOT Exposed)

- `crue_engine::engine::Engine` (internal implementation)
- `crue_engine::context::ContextBuilder`
- `crue_dsl::parser::Parser` (internal DSL)
- `crue_dsl::compiler::Compiler`
- Decision evaluation internals
- Rule matching algorithms
- Cached policy state

---

## Package 2: Rsrp.ImmutableLedger

### ✅ Public API (Exposed)

```rust
/// Immutable ledger interface
pub trait IImmutableLedger {
    /// Append new entry
    async fn append(&self, entry: LogEntry) -> Result<LogEntry>;
    
    /// Verify ledger integrity
    async fn verify(&self) -> Result<bool>;
    
    /// Get Merkle root for hour
    async fn get_merkle_root(&self, hour: DateTime) -> Result<MerkleRoot>;
    
    /// Export ledger
    fn export(&self, format: ExportFormat) -> Result<String>;
}

/// Log entry structure
pub struct LogEntry {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub entry_type: EntryType,
    pub payload: Vec<u8>,
    pub previous_hash: String,
    pub hash: String,
}

/// Proof of inclusion
pub trait IProof {
    /// Verify proof
    fn verify(&self) -> bool;
    
    /// Get canonical JSON
    fn to_canonical_hash(&self) -> String;
}

/// Export formats
pub enum ExportFormat {
    Json,
    JsonCanonical,
    Cbor,
}
```

### ❌ Internal (NOT Exposed)

- `immutable_logging::chain::LogChain`
- `immutable_logging::merkle_service::MerkleService`
- `immutable_logging::publication::PublicationService`
- Hash computation details
- Tree node structures
- Internal caching

---

## Package 3: Rsrp.Security.Core

### ✅ Public API (Exposed)

```rust
/// Signature provider
pub trait ISignatureProvider {
    fn sign(&self, message: &[u8], key: &PrivateKey) -> Result<Signature>;
    fn verify(&self, message: &[u8], sig: &Signature, key: &PublicKey) -> bool;
    fn algorithm(&self) -> Algorithm;
}

/// Key manager interface
pub trait IKeyManager {
    fn generate_key(&self, algorithm: Algorithm) -> Result<KeyPair>;
    fn import_key(&self, key: &[u8], key_type: KeyType) -> Result<KeyHandle>;
    fn export_public_key(&self, handle: &KeyHandle) -> Result<Vec<u8>>;
}

/// Post-quantum provider
pub trait IPqcProvider {
    fn hybrid_sign(&self, message: &[u8], classical: &PrivateKey, pq: &PrivateKey) 
        -> Result<HybridSignature>;
    fn hybrid_verify(&self, message: &[u8], sig: &HybridSignature) -> bool;
}

/// Hash provider
pub trait IHashProvider {
    fn hash(&self, data: &[u8]) -> Vec<u8>;
    fn algorithm(&self) -> HashAlgorithm;
}

/// Key pair
pub struct KeyPair {
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
}

/// Key handle (references key in HSM/Vault)
pub struct KeyHandle(String);
```

### ❌ Internal (NOT Exposed)

- `crypto_core::hsm::Pkcs11Session`
- `crypto_core::hsm::HsmConnection`
- `crypto_core::hsm::LunaHsmProvider`
- Raw cryptographic operations
- Memory zeroing implementation
- Key serialization (internal)
- PKCS#11 function pointers

---

## Package 4: Rsrp.AspNetCore

### ✅ Public API (Exposed)

```csharp
// Service collection extensions
public static class RsrpServiceCollectionExtensions
{
    public static IServiceCollection AddRsrpProofEngine(
        this IServiceCollection services, 
        Action<ProofEngineOptions> configure);
    
    public static IServiceCollection AddRsrpImmutableLedger(
        this IServiceCollection services,
        Action<LedgerOptions> configure);
}

// Middleware
public class ProofInjectionMiddleware
{
    public Task InvokeAsync(HttpContext context);
}

public class DecisionVerificationMiddleware  
{
    public Task InvokeAsync(HttpContext context);
}

// Attributes
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class RsrpProofAttribute : Attribute, IAsyncActionFilter
{
}

[AttributeUsage(AttributeTargets.Method)]
public class RequireProofAttribute : Attribute
{
}

// Options
public class ProofEngineOptions
{
    public bool EnableImmutableLedger { get; set; }
    public HashAlgorithm HashAlgorithm { get; set; }
    public SignatureAlgorithm SignatureAlgorithm { get; set; }
}
```

### ❌ Internal (NOT Exposed)

- Internal service implementations
- Filter internals
- Configuration parsing

---

## Enterprise Packages (Private)

### Rsrp.Enterprise.HSM

**Entire package is private** — not for public release.

```rust
// PKCS#11 integration
pub mod pkcs11 {
    pub struct Pkcs11Provider { /* ... */ }
    pub struct SlotList { /* ... */ }
    pub struct Session { /* ... */ }
}

// HSM connectors
pub mod hsm {
    pub struct LunaHsmProvider { /* ... */ }
    pub struct CloudHsmProvider { /* ... */ }
    pub struct ThalesProvider { /* ... */ }
}
```

### Rsrp.Sovereign.Deployment

**Entire package is private** — deployment templates.

---

## API Stability Promise

| API Type | Stability | Version Bump |
|----------|-----------|--------------|
| Public trait methods | Stable | Minor |
| Public struct fields | Stable | Minor |
| Public enums | Stable | Minor |
| Internal items | Unstable | Patch |
| Security fixes | Immediate | Patch |

---

## Migration Guide

When refactoring internal code:

1. **Keep internals private** — Don't expose for convenience
2. **Use sealed traits** — Prevent external implementation
3. **Version bumps** — Increment for any public API change
4. **Deprecation notices** — 2 minor versions before removal

### Example: Adding New Method

```rust
// Old public API
pub trait IProofEngine {
    fn evaluate(&self, policy: &Policy, input: &EvaluationInput) -> Result<DecisionResult>;
}

// New version - Add method (minor version bump to 1.1.0)
pub trait IProofEngine {
    fn evaluate(&self, policy: &Policy, input: &EvaluationInput) -> Result<DecisionResult>;
    fn validate_policy(&self, policy: &Policy) -> Result<bool>;  // NEW
}
```

---

## Testing Public API

All public APIs must have:
- Unit tests for happy path
- Unit tests for error cases
- Integration tests for cross-package usage
- Documentation examples that compile

---

## Documentation Requirements

For each public API item:

```rust
/// Evaluates a policy against input and returns a decision result.
/// 
/// # Arguments
/// * `policy` - The policy to evaluate
/// * `input` - The evaluation context
/// 
/// # Returns
/// `Ok(DecisionResult)` if evaluation succeeded
/// 
/// # Errors
/// Returns `Err(Error::InvalidPolicy)` if policy is malformed
/// 
/// # Example
/// ```rust
/// let engine = ProofEngine::new();
/// let result = engine.evaluate(&policy, &input)?;
/// ```
pub fn evaluate(&self, policy: &Policy, input: &EvaluationInput) -> Result<DecisionResult>;
```

---

## Summary Table

| Package | Public Types | Internal Types | Lines of Public API |
|---------|--------------|----------------|---------------------|
| ProofEngine | ~15 | ~50 | ~200 |
| ImmutableLedger | ~10 | ~30 | ~150 |
| Security.Core | ~20 | ~40 | ~300 |
| AspNetCore | ~25 | ~10 | ~400 |

---

## Version Compatibility

| Package | .NET Version | Rust Version | Status |
|---------|--------------|---------------|--------|
| Rsrp.ProofEngine | .NET 6+ | Rust 1.70+ | ✅ Stable |
| Rsrp.ImmutableLedger | .NET 6+ | Rust 1.70+ | ✅ Stable |
| Rsrp.Security.Core | .NET 6+ | Rust 1.70+ | ✅ Stable |
| Rsrp.AspNetCore | .NET 7+ | N/A | ✅ Stable |
