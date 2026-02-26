//! CRUE Engine Error Module

use thiserror::Error;

#[derive(Error, Debug)]
pub enum EngineError {
    #[error("Rule not found: {0}")]
    RuleNotFound(String),
    
    #[error("Field not found: {0}")]
    FieldNotFound(String),
    
    #[error("Invalid operator: {0}")]
    InvalidOperator(String),

    #[error("Invalid action: {0}")]
    InvalidAction(String),
    
    #[error("Type mismatch for field: {0}")]
    TypeMismatch(String),
    
    #[error("Evaluation error: {0}")]
    EvaluationError(String),
    
    #[error("Rule compilation error: {0}")]
    CompilationError(String),
    
    #[error("Rule signature invalid: {0}")]
    InvalidSignature(String),
}
