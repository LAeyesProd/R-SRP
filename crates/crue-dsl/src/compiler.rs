//! CRUE DSL Compiler
//! 
//! Compiles AST to bytecode for deterministic execution

use crate::ast::*;
use crate::error::{DslError, Result};
use sha2::{Sha256, Digest};

/// Bytecode opcodes for the CRUE VM
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    /// Load field onto stack
    LoadField = 0x01,
    /// Load constant
    LoadConst = 0x02,
    /// Load true
    LoadTrue = 0x03,
    /// Load false
    LoadFalse = 0x04,
    /// Greater than
    Gt = 0x10,
    /// Less than
    Lt = 0x11,
    /// Greater than or equal
    Gte = 0x12,
    /// Less than or equal
    Lte = 0x13,
    /// Equal
    Eq = 0x14,
    /// Not equal
    Neq = 0x15,
    /// Logical AND
    And = 0x20,
    /// Logical OR
    Or = 0x21,
    /// Logical NOT
    Not = 0x22,
    /// Jump if false
    JmpF = 0x30,
    /// Jump unconditional
    Jmp = 0x31,
    /// Return
    Ret = 0xFF,
}

/// Compiled bytecode with metadata
pub struct Bytecode {
    pub instructions: Vec<u8>,
    pub constants: Vec<Constant>,
    pub fields: Vec<String>,
}

/// Constant pool entry
#[derive(Debug, Clone)]
pub enum Constant {
    Number(i64),
    String(String),
    Boolean(bool),
}

/// CRUE DSL Compiler
pub struct Compiler;
impl Compiler {
    /// Compile AST to bytecode
    pub fn compile(ast: &RuleAst) -> Result<Bytecode> {
        let mut compiler = CompilerState::new();
        compiler.compile_expression(&ast.when_clause)?;
        compiler.emit(Opcode::Ret);
        
        Ok(Bytecode {
            instructions: compiler.instructions,
            constants: compiler.constants,
            fields: compiler.fields,
        })
    }
    
    /// Compute source hash
    pub fn compute_source_hash(source: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(source.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

struct CompilerState {
    instructions: Vec<u8>,
    constants: Vec<Constant>,
    fields: Vec<String>,
}

impl CompilerState {
    fn new() -> Self {
        CompilerState {
            instructions: Vec::new(),
            constants: Vec::new(),
            fields: Vec::new(),
        }
    }
    
    fn emit(&mut self, opcode: Opcode) {
        self.instructions.push(opcode as u8);
    }
    
    fn emit_u16(&mut self, value: u16) {
        self.instructions.extend_from_slice(&value.to_be_bytes());
    }
    
    fn emit_u32(&mut self, value: u32) {
        self.instructions.extend_from_slice(&value.to_be_bytes());
    }
    
    fn add_constant(&mut self, constant: Constant) -> u32 {
        let index = self.constants.len() as u32;
        self.constants.push(constant);
        index
    }
    
    fn add_field(&mut self, field: &str) -> u16 {
        if let Some(idx) = self.fields.iter().position(|f| f == field) {
            return idx as u16;
        }
        let index = self.fields.len() as u16;
        self.fields.push(field.to_string());
        index
    }
    
    fn compile_expression(&mut self, expr: &Expression) -> Result<()> {
        match expr {
            Expression::True => {
                self.emit(Opcode::LoadTrue);
            }
            Expression::False => {
                self.emit(Opcode::LoadFalse);
            }
            Expression::Value(Value::Number(n)) => {
                let idx = self.add_constant(Constant::Number(*n));
                self.emit(Opcode::LoadConst);
                self.emit_u32(idx);
            }
            Expression::Value(Value::String(s)) => {
                let idx = self.add_constant(Constant::String(s.clone()));
                self.emit(Opcode::LoadConst);
                self.emit_u32(idx);
            }
            Expression::Value(Value::Boolean(b)) => {
                if *b {
                    self.emit(Opcode::LoadTrue);
                } else {
                    self.emit(Opcode::LoadFalse);
                }
            }
            Expression::Value(Value::Float(_)) => {
                return Err(DslError::BytecodeError("Float not supported".to_string()));
            }
            Expression::Field(path) => {
                let field_idx = self.add_field(path);
                self.emit(Opcode::LoadField);
                self.emit_u16(field_idx);
            }
            Expression::Gt(e1, e2) => {
                self.compile_expression(e1)?;
                self.compile_expression(e2)?;
                self.emit(Opcode::Gt);
            }
            Expression::Lt(e1, e2) => {
                self.compile_expression(e1)?;
                self.compile_expression(e2)?;
                self.emit(Opcode::Lt);
            }
            Expression::Gte(e1, e2) => {
                self.compile_expression(e1)?;
                self.compile_expression(e2)?;
                self.emit(Opcode::Gte);
            }
            Expression::Lte(e1, e2) => {
                self.compile_expression(e1)?;
                self.compile_expression(e2)?;
                self.emit(Opcode::Lte);
            }
            Expression::Eq(e1, e2) => {
                self.compile_expression(e1)?;
                self.compile_expression(e2)?;
                self.emit(Opcode::Eq);
            }
            Expression::Neq(e1, e2) => {
                self.compile_expression(e1)?;
                self.compile_expression(e2)?;
                self.emit(Opcode::Neq);
            }
            Expression::And(e1, e2) => {
                self.compile_expression(e1)?;
                self.compile_expression(e2)?;
                self.emit(Opcode::And);
            }
            Expression::Or(e1, e2) => {
                self.compile_expression(e1)?;
                self.compile_expression(e2)?;
                self.emit(Opcode::Or);
            }
            Expression::Not(e) => {
                self.compile_expression(e)?;
                self.emit(Opcode::Not);
            }
            Expression::In(_, _) => {
                return Err(DslError::BytecodeError("IN operator not yet implemented".to_string()));
            }
            Expression::Between(_, _, _) => {
                return Err(DslError::BytecodeError("BETWEEN operator not yet implemented".to_string()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_compile_simple_expression() {
        let expr = Expression::Gt(
            Box::new(Expression::field("agent.requests_last_hour")),
            Box::new(Expression::number(50)),
        );
        
        let bytecode = Compiler::compile(&RuleAst {
            id: "CRUE_001".to_string(),
            version: "1.0.0".to_string(),
            signed: false,
            when_clause: expr,
            then_clause: vec![],
            metadata: MetadataNode {
                name: "Test".to_string(),
                description: "Test rule".to_string(),
                severity: "HIGH".to_string(),
                category: "TEST".to_string(),
                author: "system".to_string(),
                created_at: "2026-01-01".to_string(),
                validated_by: None,
            },
        }).unwrap();
        
        assert!(!bytecode.instructions.is_empty());
    }
    
    #[test]
    fn test_source_hash() {
        let source = r#"RULE CRUE_001 VERSION 1.0 WHEN agent.requests_last_hour >= 50 THEN BLOCK"#;
        let hash = Compiler::compute_source_hash(source);
        assert_eq!(hash.len(), 64); // SHA-256 hex
    }
}
