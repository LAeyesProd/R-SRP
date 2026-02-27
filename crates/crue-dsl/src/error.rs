//! CRUE DSL Error Types

use thiserror::Error;

/// DSL Error types
#[derive(Error, Debug)]
pub enum DslError {
    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Compilation error: {0}")]
    CompilationError(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Signature error: {0}")]
    SignatureError(String),

    #[error("Version error: {0}")]
    VersionError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Invalid rule: {0}")]
    InvalidRule(String),

    #[error("Bytecode error: {0}")]
    BytecodeError(String),
}

impl serde::Serialize for DslError {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

/// Result type alias
pub type Result<T> = std::result::Result<T, DslError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_serialization() {
        let error = DslError::ParseError("Invalid token".to_string());
        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("Parse error"));
    }
}
