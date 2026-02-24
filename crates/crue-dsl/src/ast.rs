//! CRUE DSL Abstract Syntax Tree
//! 
//! Defines the AST nodes for parsed CRUE rules

use serde::{Deserialize, Serialize};

/// AST Root node for a CRUE rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleAst {
    pub id: String,
    pub version: String,
    pub signed: bool,
    pub when_clause: Expression,
    pub then_clause: Vec<ActionNode>,
    pub metadata: MetadataNode,
}

/// Metadata in the rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataNode {
    pub name: String,
    pub description: String,
    pub severity: String,
    pub category: String,
    pub author: String,
    pub created_at: String,
    pub validated_by: Option<String>,
}

/// Actions available in THEN clause
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "UPPERCASE")]
pub enum ActionNode {
    Block {
        code: String,
        message: Option<String>,
    },
    Warn {
        code: String,
    },
    RequireApproval {
        code: String,
        timeout_minutes: u32,
    },
    Log,
    AlertSoc,
}

/// Expression AST node
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", content = "args", rename_all = "snake_case")]
pub enum Expression {
    /// Boolean literals
    True,
    False,
    
    /// Numeric comparison: >, <, >=, <=, ==, !=
    Gt(Box<Expression>, Box<Expression>),
    Lt(Box<Expression>, Box<Expression>),
    Gte(Box<Expression>, Box<Expression>),
    Lte(Box<Expression>, Box<Expression>),
    Eq(Box<Expression>, Box<Expression>),
    Neq(Box<Expression>, Box<Expression>),
    
    /// Logical operators
    And(Box<Expression>, Box<Expression>),
    Or(Box<Expression>, Box<Expression>),
    Not(Box<Expression>),
    
    /// Field access (e.g., agent.requests_last_hour)
    Field(String),
    
    /// Value access
    Value(Value),
    
    /// IN operator for set membership
    In(Box<Expression>, Vec<Value>),
    
    /// BETWEEN operator
    Between(Box<Expression>, Box<Expression>, Box<Expression>),
}

/// Value types in expressions
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Value {
    Number(i64),
    Float(f64),
    String(String),
    Boolean(bool),
}

/// Field path for context access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldPath {
    /// Root object (agent, request, session, context)
    pub root: String,
    /// Field name
    pub field: String,
    /// Optional nested field
    pub nested: Option<String>,
}

impl FieldPath {
    /// Parse a field path string like "agent.requests_last_hour"
    pub fn parse(path: &str) -> Result<Self, crate::error::DslError> {
        let parts: Vec<&str> = path.split('.').collect();
        
        if parts.len() < 2 {
            return Err(crate::error::DslError::ParseError(
                format!("Invalid field path: {}", path)
            ));
        }
        
        Ok(FieldPath {
            root: parts[0].to_string(),
            field: parts[1].to_string(),
            nested: parts.get(2).map(|s| s.to_string()),
        })
    }
}

impl Expression {
    /// Create a field access expression
    pub fn field(path: &str) -> Self {
        Expression::Field(path.to_string())
    }
    
    /// Create a numeric literal
    pub fn number(n: i64) -> Self {
        Expression::Value(Value::Number(n))
    }
    
    /// Create a string literal
    pub fn string(s: &str) -> Self {
        Expression::Value(Value::String(s.to_string()))
    }
    
    /// Create a boolean literal
    pub fn boolean(b: bool) -> Self {
        if b { Expression::True } else { Expression::False }
    }
    
    /// Check if expression is statically true
    pub fn is_static_true(&self) -> bool {
        matches!(self, Expression::True)
    }
    
    /// Get all referenced fields in this expression
    pub fn referenced_fields(&self) -> Vec<String> {
        match self {
            Expression::True | Expression::False => vec![],
            Expression::Gt(e1, e2) | Expression::Lt(e1, e2) 
            | Expression::Gte(e1, e2) | Expression::Lte(e1, e2)
            | Expression::Eq(e1, e2) | Expression::Neq(e1, e2)
            | Expression::And(e1, e2) | Expression::Or(e1, e2) => {
                let mut fields = e1.referenced_fields();
                fields.extend(e2.referenced_fields());
                fields
            }
            Expression::Not(e) => e.referenced_fields(),
            Expression::Field(path) => vec![path.clone()],
            Expression::Value(_) => vec![],
            Expression::In(e, values) => {
                let mut fields = e.referenced_fields();
                for _ in values {
                    // Values don't contain fields
                }
                fields
            }
            Expression::Between(e1, e2, e3) => {
                let mut fields = e1.referenced_fields();
                fields.extend(e2.referenced_fields());
                fields.extend(e3.referenced_fields());
                fields
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_field_path_parse() {
        let path = FieldPath::parse("agent.requests_last_hour").unwrap();
        assert_eq!(path.root, "agent");
        assert_eq!(path.field, "requests_last_hour");
    }
    
    #[test]
    fn test_expression_referenced_fields() {
        let expr = Expression::Gt(
            Box::new(Expression::field("agent.requests_last_hour")),
            Box::new(Expression::number(50)),
        );
        
        let fields = expr.referenced_fields();
        assert!(fields.contains(&"agent.requests_last_hour".to_string()));
    }
}
