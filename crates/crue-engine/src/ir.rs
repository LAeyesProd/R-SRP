//! Typed rule IR for compiled-policy execution paths.

use crate::decision::Decision;
use crate::error::EngineError;
use crue_dsl::ast::ActionNode;
use crue_dsl::compiler::{
    ActionDecision as DslActionDecision, ActionInstruction as DslActionInstruction,
};
use serde::{Deserialize, Serialize};

/// Typed comparison operators for deterministic rule evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operator {
    Eq,
    Ne,
    Gt,
    Lt,
    Gte,
    Lte,
}

impl Operator {
    pub fn parse(op: &str) -> Result<Self, EngineError> {
        match op {
            "==" => Ok(Self::Eq),
            "!=" => Ok(Self::Ne),
            ">" => Ok(Self::Gt),
            "<" => Ok(Self::Lt),
            ">=" => Ok(Self::Gte),
            "<=" => Ok(Self::Lte),
            _ => Err(EngineError::InvalidOperator(op.to_string())),
        }
    }
}

/// Typed legacy action kind to avoid stringly dispatch in the engine runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionKind {
    Block,
    Warn,
    RequireApproval,
    Log,
}

impl ActionKind {
    pub fn parse(action: &str) -> Result<Self, EngineError> {
        match action {
            "BLOCK" => Ok(Self::Block),
            "WARN" => Ok(Self::Warn),
            "REQUIRE_APPROVAL" => Ok(Self::RequireApproval),
            "LOG" => Ok(Self::Log),
            _ => Err(EngineError::InvalidAction(action.to_string())),
        }
    }
}

/// Typed action/effect emitted by a compiled rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleEffect {
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

/// Explicit action VM instructions for compiled rule effects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionInstruction {
    SetDecision(Decision),
    SetErrorCode(String),
    SetMessage(String),
    SetApprovalTimeout(u32),
    SetAlertSoc(bool),
    Halt,
}

impl TryFrom<ActionNode> for RuleEffect {
    type Error = EngineError;

    fn try_from(value: ActionNode) -> Result<Self, Self::Error> {
        Ok(match value {
            ActionNode::Block { code, message } => Self::Block { code, message },
            ActionNode::Warn { code } => Self::Warn { code },
            ActionNode::RequireApproval {
                code,
                timeout_minutes,
            } => Self::RequireApproval {
                code,
                timeout_minutes,
            },
            ActionNode::Log => Self::Log,
            ActionNode::AlertSoc => Self::AlertSoc,
        })
    }
}

impl TryFrom<DslActionInstruction> for ActionInstruction {
    type Error = EngineError;

    fn try_from(value: DslActionInstruction) -> Result<Self, Self::Error> {
        Ok(match value {
            DslActionInstruction::SetDecision(d) => Self::SetDecision(match d {
                DslActionDecision::Allow => Decision::Allow,
                DslActionDecision::Block => Decision::Block,
                DslActionDecision::Warn => Decision::Warn,
                DslActionDecision::ApprovalRequired => Decision::ApprovalRequired,
            }),
            DslActionInstruction::SetErrorCode(code) => Self::SetErrorCode(code),
            DslActionInstruction::SetMessage(msg) => Self::SetMessage(msg),
            DslActionInstruction::SetApprovalTimeout(timeout) => Self::SetApprovalTimeout(timeout),
            DslActionInstruction::SetAlertSoc(v) => Self::SetAlertSoc(v),
            DslActionInstruction::Halt => Self::Halt,
        })
    }
}

impl RuleEffect {
    pub fn is_alert_only(&self) -> bool {
        matches!(self, Self::AlertSoc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operator_parse() {
        assert_eq!(Operator::parse(">=").unwrap(), Operator::Gte);
        assert!(Operator::parse("contains").is_err());
    }

    #[test]
    fn test_action_node_to_rule_effect() {
        let effect = RuleEffect::try_from(ActionNode::RequireApproval {
            code: "APPROVAL".to_string(),
            timeout_minutes: 15,
        })
        .unwrap();

        assert_eq!(
            effect,
            RuleEffect::RequireApproval {
                code: "APPROVAL".to_string(),
                timeout_minutes: 15,
            }
        );
    }

    #[test]
    fn test_action_kind_parse() {
        assert_eq!(ActionKind::parse("BLOCK").unwrap(), ActionKind::Block);
        assert!(ActionKind::parse("DROP_TABLE").is_err());
    }

    #[test]
    fn test_action_instruction_roundtrip_serde() {
        let insn = ActionInstruction::SetDecision(Decision::Block);
        let json = serde_json::to_string(&insn).unwrap();
        let decoded: ActionInstruction = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, insn);
    }

    #[test]
    fn test_dsl_action_instruction_to_engine_action_instruction() {
        let dsl = DslActionInstruction::SetDecision(DslActionDecision::Block);
        let engine = ActionInstruction::try_from(dsl).unwrap();
        assert_eq!(engine, ActionInstruction::SetDecision(Decision::Block));
    }
}
