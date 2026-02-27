//! CRUE DSL Parser
//!
//! Parses CRUE DSL source code into an AST

use crate::ast::*;
use crate::error::{DslError, Result};

const MAX_TOKEN_COUNT: usize = 10_000;
const MAX_PARSE_DEPTH: usize = 128;

/// CRUE DSL Parser
pub struct Parser {
    tokens: Vec<Token>,
    position: usize,
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Rule,
    Version,
    Signed,
    When,
    Then,
    Block,
    Warn,
    Alert,
    Log,
    Require,
    Approval,
    With,
    Code,
    And,
    Or,
    Not,
    In,
    Between,
    Gt,
    Lt,
    Gte,
    Lte,
    Eq,
    Neq,
    Identifier(String),
    Number(i64),
    InvalidNumber(String),
    String(String),
    Dot,
    ParenOpen,
    ParenClose,
    BracketOpen,
    BracketClose,
    Comma,
    Eof,
}

impl Parser {
    /// Create a new parser with source code
    pub fn new(source: &str) -> Result<Self> {
        let tokens = Self::tokenize(source)?;
        Ok(Parser {
            tokens,
            position: 0,
        })
    }

    /// Tokenize source code
    fn tokenize(source: &str) -> Result<Vec<Token>> {
        let mut tokens = Vec::new();
        let mut chars = source.chars().peekable();

        while let Some(c) = chars.next() {
            // Skip whitespace
            if c.is_whitespace() {
                continue;
            }

            // Comments
            if c == '/' && chars.peek() == Some(&'/') {
                for c in chars.by_ref() {
                    if c == '\n' {
                        break;
                    }
                }
                continue;
            }

            // Identifiers and keywords
            if c.is_alphabetic() || c == '_' {
                let mut ident = String::new();
                ident.push(c);
                while let Some(&c) = chars.peek() {
                    if c.is_alphanumeric() || c == '_' {
                        if let Some(next_char) = chars.next() {
                            ident.push(next_char);
                        }
                    } else {
                        break;
                    }
                }

                let kw = ident.to_uppercase();
                tokens.push(match kw.as_str() {
                    "RULE" => Token::Rule,
                    "VERSION" => Token::Version,
                    "SIGNED" => Token::Signed,
                    "WHEN" => Token::When,
                    "THEN" => Token::Then,
                    "BLOCK" => Token::Block,
                    "WARN" => Token::Warn,
                    "ALERT" => Token::Alert,
                    "LOG" => Token::Log,
                    "REQUIRE" => Token::Require,
                    "APPROVAL" => Token::Approval,
                    "WITH" => Token::With,
                    "CODE" => Token::Code,
                    "AND" => Token::And,
                    "OR" => Token::Or,
                    "NOT" => Token::Not,
                    "IN" => Token::In,
                    "BETWEEN" => Token::Between,
                    "TRUE" => Token::Identifier("true".to_string()),
                    "FALSE" => Token::Identifier("false".to_string()),
                    _ => Token::Identifier(ident),
                });
                Self::ensure_token_budget(tokens.len())?;
                continue;
            }

            // Numbers
            if c.is_ascii_digit() {
                let mut num = String::new();
                num.push(c);
                while let Some(&c) = chars.peek() {
                    if c.is_ascii_digit() {
                        if let Some(next_char) = chars.next() {
                            num.push(next_char);
                        }
                    } else {
                        break;
                    }
                }
                match num.parse::<i64>() {
                    Ok(v) => tokens.push(Token::Number(v)),
                    Err(_) => tokens.push(Token::InvalidNumber(num)),
                }
                Self::ensure_token_budget(tokens.len())?;
                continue;
            }

            // Strings
            if c == '"' {
                let mut s = String::new();
                while let Some(c) = chars.next() {
                    if c == '"' {
                        break;
                    }
                    if c == '\\' {
                        if let Some(ec) = chars.next() {
                            s.push(ec);
                        }
                    } else {
                        s.push(c);
                    }
                }
                tokens.push(Token::String(s));
                Self::ensure_token_budget(tokens.len())?;
                continue;
            }

            // Operators
            match c {
                '.' => tokens.push(Token::Dot),
                '(' => tokens.push(Token::ParenOpen),
                ')' => tokens.push(Token::ParenClose),
                '[' => tokens.push(Token::BracketOpen),
                ']' => tokens.push(Token::BracketClose),
                ',' => tokens.push(Token::Comma),
                '>' => {
                    if chars.peek() == Some(&'=') {
                        chars.next();
                        tokens.push(Token::Gte);
                    } else {
                        tokens.push(Token::Gt);
                    }
                }
                '<' => {
                    if chars.peek() == Some(&'=') {
                        chars.next();
                        tokens.push(Token::Lte);
                    } else {
                        tokens.push(Token::Lt);
                    }
                }
                '=' => {
                    if chars.peek() == Some(&'=') {
                        chars.next();
                        tokens.push(Token::Eq);
                    }
                }
                '!' => {
                    if chars.peek() == Some(&'=') {
                        chars.next();
                        tokens.push(Token::Neq);
                    }
                }
                _ => {}
            }
            Self::ensure_token_budget(tokens.len())?;
        }

        tokens.push(Token::Eof);
        Self::ensure_token_budget(tokens.len())?;
        Ok(tokens)
    }

    fn ensure_token_budget(token_count: usize) -> Result<()> {
        if token_count > MAX_TOKEN_COUNT {
            return Err(DslError::RuleTooComplex(format!(
                "token count exceeds limit ({MAX_TOKEN_COUNT})"
            )));
        }
        Ok(())
    }

    fn ensure_depth(depth: usize) -> Result<()> {
        if depth > MAX_PARSE_DEPTH {
            return Err(DslError::RuleTooComplex(format!(
                "expression depth exceeds limit ({MAX_PARSE_DEPTH})"
            )));
        }
        Ok(())
    }

    /// Parse the source into an AST
    pub fn parse(&mut self) -> Result<RuleAst> {
        self.parse_rule()
    }

    /// Parse RULE declaration
    fn parse_rule(&mut self) -> Result<RuleAst> {
        self.expect(Token::Rule)?;

        let id = match self.next() {
            Token::Identifier(id) => id,
            _ => return Err(self.error("Expected rule ID")),
        };

        self.expect(Token::Version)?;
        let version = match self.next() {
            Token::Number(n) => n.to_string(),
            Token::Identifier(s) => s,
            Token::InvalidNumber(raw) => {
                return Err(self.error(&format!("Invalid numeric literal: {}", raw)))
            }
            _ => return Err(self.error("Expected version")),
        };

        // Handle version format like "1.2.0"
        if let Token::Dot = self.peek() {
            self.next(); // consume dot
            if let Token::Number(n) = self.next() {
                let _ = self.peek();
                if let Token::Dot = self.peek() {
                    self.next();
                    if let Token::Number(n2) = self.next() {
                        return Ok(RuleAst {
                            id,
                            version: format!("{}.{}.{}", version, n, n2),
                            signed: self.match_token(Token::Signed),
                            when_clause: {
                                self.expect(Token::When)?;
                                self.parse_expression()?
                            },
                            then_clause: {
                                self.expect(Token::Then)?;
                                self.parse_actions()?
                            },
                            metadata: self.parse_metadata()?,
                        });
                    }
                }
                return Ok(RuleAst {
                    id,
                    version: format!("{}.{}", version, n),
                    signed: self.match_token(Token::Signed),
                    when_clause: {
                        self.expect(Token::When)?;
                        self.parse_expression()?
                    },
                    then_clause: {
                        self.expect(Token::Then)?;
                        self.parse_actions()?
                    },
                    metadata: self.parse_metadata()?,
                });
            }
        }

        let signed = self.match_token(Token::Signed);

        self.expect(Token::When)?;
        let when_clause = self.parse_expression()?;

        self.expect(Token::Then)?;
        let then_clause = self.parse_actions()?;

        let metadata = self.parse_metadata()?;

        Ok(RuleAst {
            id,
            version,
            signed,
            when_clause,
            then_clause,
            metadata,
        })
    }

    /// Parse metadata section
    fn parse_metadata(&mut self) -> Result<MetadataNode> {
        // For now, return default metadata
        Ok(MetadataNode {
            name: "Unknown".to_string(),
            description: "CRUE rule".to_string(),
            severity: "HIGH".to_string(),
            category: "ACCESS_CONTROL".to_string(),
            author: "system".to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            validated_by: None,
        })
    }

    /// Parse expressions (recursive descent)
    fn parse_expression(&mut self) -> Result<Expression> {
        self.parse_or_expr(0)
    }

    /// Parse OR expressions
    fn parse_or_expr(&mut self, depth: usize) -> Result<Expression> {
        Self::ensure_depth(depth)?;
        let mut left = self.parse_and_expr(depth + 1)?;

        while self.match_token(Token::Or) {
            let right = self.parse_and_expr(depth + 1)?;
            left = Expression::Or(Box::new(left), Box::new(right));
        }

        Ok(left)
    }

    /// Parse AND expressions
    fn parse_and_expr(&mut self, depth: usize) -> Result<Expression> {
        Self::ensure_depth(depth)?;
        let mut left = self.parse_not_expr(depth + 1)?;

        while self.match_token(Token::And) {
            let right = self.parse_not_expr(depth + 1)?;
            left = Expression::And(Box::new(left), Box::new(right));
        }

        Ok(left)
    }

    /// Parse NOT expressions
    fn parse_not_expr(&mut self, depth: usize) -> Result<Expression> {
        Self::ensure_depth(depth)?;
        if self.match_token(Token::Not) {
            let expr = self.parse_not_expr(depth + 1)?;
            return Ok(Expression::Not(Box::new(expr)));
        }
        self.parse_comparison_expr(depth + 1)
    }

    /// Parse comparison expressions
    fn parse_comparison_expr(&mut self, depth: usize) -> Result<Expression> {
        Self::ensure_depth(depth)?;
        let left = self.parse_primary_expr(depth + 1)?;

        // Check for comparison operators
        if let Token::Gt = self.peek() {
            self.next();
            let right = self.parse_primary_expr(depth + 1)?;
            return Ok(Expression::Gt(Box::new(left), Box::new(right)));
        }
        if let Token::Lt = self.peek() {
            self.next();
            let right = self.parse_primary_expr(depth + 1)?;
            return Ok(Expression::Lt(Box::new(left), Box::new(right)));
        }
        if let Token::Gte = self.peek() {
            self.next();
            let right = self.parse_primary_expr(depth + 1)?;
            return Ok(Expression::Gte(Box::new(left), Box::new(right)));
        }
        if let Token::Lte = self.peek() {
            self.next();
            let right = self.parse_primary_expr(depth + 1)?;
            return Ok(Expression::Lte(Box::new(left), Box::new(right)));
        }
        if let Token::Eq = self.peek() {
            self.next();
            let right = self.parse_primary_expr(depth + 1)?;
            return Ok(Expression::Eq(Box::new(left), Box::new(right)));
        }
        if let Token::Neq = self.peek() {
            self.next();
            let right = self.parse_primary_expr(depth + 1)?;
            return Ok(Expression::Neq(Box::new(left), Box::new(right)));
        }

        Ok(left)
    }

    /// Parse primary expressions
    fn parse_primary_expr(&mut self, depth: usize) -> Result<Expression> {
        Self::ensure_depth(depth)?;
        let token = self.next();

        match token {
            Token::Identifier(id) => {
                // Check if it's a field path
                if let Token::Dot = self.peek() {
                    self.next();
                    if let Token::Identifier(field) = self.next() {
                        return Ok(Expression::Field(format!("{}.{}", id, field)));
                    }
                }

                // Check for true/false
                if id == "true" {
                    return Ok(Expression::True);
                }
                if id == "false" {
                    return Ok(Expression::False);
                }

                // It's just a field
                Ok(Expression::Field(id))
            }
            Token::Number(n) => Ok(Expression::Value(Value::Number(n))),
            Token::InvalidNumber(raw) => {
                Err(self.error(&format!("Invalid numeric literal: {}", raw)))
            }
            Token::String(s) => Ok(Expression::Value(Value::String(s))),
            Token::ParenOpen => {
                let expr = self.parse_or_expr(depth + 1)?;
                self.expect(Token::ParenClose)?;
                Ok(expr)
            }
            _ => Err(self.error("Unexpected token in expression")),
        }
    }

    /// Parse THEN actions
    fn parse_actions(&mut self) -> Result<Vec<ActionNode>> {
        let mut actions = Vec::new();

        while let Token::Block = self.peek() {
            self.next();
            self.expect(Token::With)?;
            self.expect(Token::Code)?;
            let code = match self.next() {
                Token::String(s) => s,
                Token::Identifier(id) => id,
                _ => return Err(self.error("Expected code string")),
            };

            let message = if self.match_token(Token::Identifier("message".to_string())) {
                self.expect(Token::String(String::new()))?;
                Some(String::new())
            } else {
                None
            };

            actions.push(ActionNode::Block { code, message });

            // Check for ALERT SOC
            if self.match_token(Token::Alert) {
                self.expect(Token::Identifier("SOC".to_string()))?;
                actions.push(ActionNode::AlertSoc);
            }
        }

        Ok(actions)
    }

    // Helper methods

    fn peek(&self) -> Token {
        self.tokens
            .get(self.position)
            .cloned()
            .unwrap_or(Token::Eof)
    }

    fn next(&mut self) -> Token {
        let token = self.peek();
        self.position += 1;
        token
    }

    fn expect(&mut self, expected: Token) -> Result<()> {
        let token = self.next();
        if token == expected {
            Ok(())
        } else {
            Err(self.error(&format!("Expected {:?}, got {:?}", expected, token)))
        }
    }

    fn match_token(&mut self, expected: Token) -> bool {
        if self.peek() == expected {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn error(&self, msg: &str) -> DslError {
        DslError::ParseError(msg.to_string())
    }
}

/// Parse CRUE DSL source code
pub fn parse(source: &str) -> Result<RuleAst> {
    let mut parser = Parser::new(source)?;
    parser.parse()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tokenize() {
        let tokens = Parser::tokenize("RULE CRUE_001 VERSION 1.0").unwrap();
        assert!(tokens.contains(&Token::Rule));
        assert!(tokens.contains(&Token::Identifier("CRUE_001".to_string())));
    }

    #[test]
    fn test_parse_simple_rule() {
        let source = r#"
            RULE CRUE_001 VERSION 1.0
            WHEN
                agent.requests_last_hour >= 50
            THEN
                BLOCK WITH CODE "VOLUME_EXCEEDED"
        "#;

        let ast = parse(source).unwrap();
        assert_eq!(ast.id, "CRUE_001");
    }
}
