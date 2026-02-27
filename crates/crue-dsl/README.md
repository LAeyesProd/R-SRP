# rsrp-policy-dsl

Compiled policy DSL for deterministic rule evaluation.

Crates.io package: `rsrp-policy-dsl`  
Rust import path: `crue_dsl`

## Quick Start

```rust
use crue_dsl::compiler::Compiler;
use crue_dsl::parser;

let src = r#"
RULE CRUE_001 VERSION 1.0.0 SIGNED
WHEN true
THEN LOG
"#;

let ast = parser::parse(src).expect("parse");
let bytecode = Compiler::compile(&ast).expect("compile");

assert!(!bytecode.instructions.is_empty());
```

## Scope

- CRUE rule parsing
- AST representation
- Deterministic bytecode compilation
- Rule signature metadata helpers

