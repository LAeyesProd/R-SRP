//! CRUE DSL - Domain Specific Language for Zero-Trust Rules
//! 
//! This module provides a compiled DSL for defining access control rules
//! that are signed, versioned, and cannot be bypassed at runtime.
//!
//! ## DSL Syntax Example
//!
//! ```crue
//! RULE CRUE_001 VERSION 1.2.0 SIGNED
//! WHEN
//!     agent.requests_last_hour >= 50
//! THEN
//!     BLOCK WITH CODE "VOLUME_EXCEEDED"
//!     ALERT SOC
//! ```

pub mod ast;
pub mod parser;
pub mod compiler;
pub mod signature;
pub mod error;

use serde::{Deserialize, Serialize};

/// CRUE Rule identifier following the specification
pub const RULE_PREFIX: &str = "CRUE";
pub const RULE_VERSION: &str = "1.0.0";

/// Rule severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    /// Critical - Immediate block
    Critical,
    /// High - Block with alert
    High,
    /// Medium - Warning
    Medium,
    /// Low - Log only
    Low,
}

impl Default for Severity {
    fn default() -> Self {
        Severity::High
    }
}

/// Rule action types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Action {
    /// Block the request
    Block {
        #[serde(rename = "code")]
        error_code: String,
        #[serde(rename = "message")]
        error_message: Option<String>,
    },
    /// Allow with warning
    Warn {
        #[serde(rename = "code")]
        warning_code: String,
    },
    /// Require approval from supervisor
    RequireApproval {
        #[serde(rename = "code")]
        approval_code: String,
        #[serde(rename = "timeout_minutes")]
        timeout: u32,
    },
    /// Log the event
    Log,
    /// Alert SOC team
    AlertSoc,
}

impl Default for Action {
    fn default() -> Self {
        Action::Block {
            error_code: "UNKNOWN_ERROR".to_string(),
            error_message: None,
        }
    }
}

/// Compiled rule binary representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledRule {
    /// Rule ID (e.g., "CRUE_001")
    pub id: String,
    /// Semantic version
    pub version: String,
    /// SHA-256 hash of the rule source
    pub source_hash: String,
    /// Cryptographic signature (RSA-PSS)
    pub signature: Vec<u8>,
    /// Signer key ID
    pub signer_key_id: String,
    /// Compiled bytecode
    pub bytecode: Vec<u8>,
    /// Timestamp of compilation
    pub compiled_at: i64,
    /// Validity period
    pub valid_from: Option<i64>,
    pub valid_until: Option<i64>,
}

/// DSL source code representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSource {
    /// Rule ID
    pub id: String,
    /// Version
    pub version: String,
    /// WHEN conditions (AST)
    pub conditions: ast::Expression,
    /// THEN actions
    pub actions: Vec<Action>,
    /// Optional metadata
    pub metadata: RuleMetadata,
}

/// Rule metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMetadata {
    /// Human-readable name
    pub name: String,
    /// Description
    pub description: String,
    /// Severity level
    pub severity: Severity,
    /// Category
    pub category: String,
    /// Author
    pub author: String,
    /// Creation date
    pub created_at: String,
    /// Validated by
    pub validated_by: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_serialization() {
        let action = Action::Block {
            error_code: "VOLUME_EXCEEDED".to_string(),
            error_message: Some("Quota dépassé".to_string()),
        };
        
        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains("VOLUME_EXCEEDED"));
    }

    #[test]
    fn test_severity_default() {
        let severity: Severity = serde_json::from_str("\"HIGH\"").unwrap();
        assert_eq!(severity, Severity::High);
    }
}
