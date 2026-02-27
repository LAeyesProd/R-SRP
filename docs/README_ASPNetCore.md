# Rsrp.AspNetCore

ASP.NET Core integration for automatic proof injection and decision verification.

*Publisher: Rsrp Systems | Author: Aymeric Le Cloitre-Maternat (ALM)*

## Overview

Rsrp.AspNetCore provides seamless integration with ASP.NET Core applications:
- **Middleware for automatic proof injection**
- **Action filters for decision proofing**
- **HTTP header verification**
- **Dependency injection helpers**

## Quick Start

```bash
dotnet add package Rsrp.AspNetCore
```

```csharp
// Program.cs
builder.Services.AddRsrpProofEngine(options =>
{
    options.EnableImmutableLedger();
    options.UseEd25519();
});

var app = builder.Build();

// Enable automatic proof injection
app.UseRsrpProofInjection();

// Enable decision verification
app.UseRsrpDecisionVerification();
```

## Middleware

### Proof Injection Middleware

Automatically adds proof headers to every response:

```csharp
app.UseRsrpProofInjection();
```

Response headers:
```
X-RSRP-Proof-Hash: abcd1234...
X-RSRP-Timestamp: 2024-01-15T10:30:00Z
X-RSRP-Signature: MEQCIQ...
```

### Decision Verification Middleware

Verifies incoming proof headers:

```csharp
app.UseRsrpDecisionVerification(options =>
{
    options.RequireProof = true;
    options.AcceptedAlgorithms = new[] { "Ed25519", "Dilithium2" };
});
```

## Action Filters

### ProofActionFilter

Automatically generates proof for controller actions:

```csharp
[ApiController]
public class AccountsController : ControllerBase
{
    [HttpGet("{id}")]
    [RsrpProof]
    public async Task<ActionResult<Account>> GetAccount(string id)
    {
        // Decision is automatically proofed
        return await _service.GetAccountAsync(id);
    }
}
```

### RequireProof Attribute

Requires valid proof in request:

```csharp
[HttpPost]
[RequireProof]
public async Task<IActionResult> Transfer([FromBody] TransferRequest request)
{
    // Request is verified before action executes
    await _service.TransferAsync(request);
    return Ok();
}
```

## Dependency Injection

### Register Services

```csharp
// In Program.cs
builder.Services.AddRsrpProofEngine();
builder.Services.AddRsrpImmutableLedger();
builder.Services.AddRsrpSecurityCore();
```

### Configuration

```json
{
  "Rsrp": {
    "ProofEngine": {
      "Enabled": true,
      "HashAlgorithm": "SHA256",
      "SignatureAlgorithm": "Ed25519"
    },
    "Ledger": {
      "Enabled": true,
      "ExportInterval": "Hourly"
    }
  }
}
```

## HTTP Decision Verification

### Client-Side

```csharp
var client = new HttpClient();
client.DefaultRequestHeaders.Add("X-RSRP-Proof", proof);
client.DefaultRequestHeaders.Add("X-RSRP-Signature", signature);

var response = await client.GetAsync("https://api.example.com/data");
```

### Server-Side Verification

```csharp
[HttpGet]
public async Task<IActionResult> GetData([FromHeader(Name = "X-RSRP-Proof")] string proof)
{
    var verifier = HttpContext.RequestServices.GetRequiredService<IProofVerifier>();
    
    if (!await verifier.VerifyAsync(proof))
    {
        return Unauthorized("Invalid proof");
    }
    
    return Ok(_data);
}
```

## Health Checks

```csharp
builder.Services.AddHealthChecks()
    .AddRsrpLedger();
```

## Example: Complete Integration

```csharp
// Program.cs
var builder = WebApplication.CreateBuilder(args);

// Add RSRP services
builder.Services.AddRsrpProofEngine(options =>
{
    options.UseEd25519();
    options.EnableImmutableLedger();
});

builder.Services.AddRsrpImmutableLedger();

// Add controllers with proof
builder.Services.AddControllers(options =>
{
    options.Filters.Add<RsrpProofActionFilter>();
});

var app = builder.Build();

// Enable middleware
app.UseRsrpProofInjection();
app.UseRsrpDecisionVerification();

app.MapControllers();

app.Run();
```

```csharp
// Controller
[ApiController]
[Route("api/[controller]")]
public class TransactionsController : ControllerBase
{
    private readonly IProofEngine _engine;
    private readonly ILedger _ledger;

    [HttpPost]
    public async Task<IActionResult> CreateTransaction([FromBody] TransactionRequest request)
    {
        // Evaluate policy
        var decision = await _engine.EvaluateAsync(Policy, request);
        
        // Generate proof
        var proof = decision.GenerateProof();
        
        // Record in ledger
        await _ledger.AppendAsync(proof);
        
        return decision.Approved ? Ok(proof) : Forbid();
    }
}
```

## Options

### ProofEngineOptions

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| Enabled | bool | true | Enable proof engine |
| HashAlgorithm | HashAlgorithm | Sha256 | Hash algorithm |
| SignatureAlgorithm | SignatureAlgorithm | Ed25519 | Signing algorithm |
| EnableImmutableLedger | bool | false | Enable ledger recording |

### DecisionVerificationOptions

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| RequireProof | bool | false | Require proof in requests |
| AcceptedAlgorithms | string[] | All | Accepted signature algorithms |
| HeaderName | string | X-RSRP-Proof | Proof header name |

## Installation

```bash
# Core ASP.NET integration
dotnet add package Rsrp.AspNetCore

# With all features
dotnet add package Rsrp.AspNetCore.All
```

## Documentation

- [Middleware Guide](https://docs.rsrp.io/aspnet/middleware)
- [Filter Reference](https://docs.rsrp.io/aspnet/filters)
- [Configuration](https://docs.rsrp.io/aspnet/config)

## License

Apache 2.0

---

**Rsrp.AspNetCore** — Proof infrastructure for ASP.NET Core applications.
