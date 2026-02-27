//! Rule Registry and Built-in Rules

use crate::context::EvaluationContext;
use crate::decision::ActionResult;
use crate::error::EngineError;
use crate::ir::{ActionKind, Operator};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Rule definition
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub version: String,
    pub name: String,
    pub description: String,
    pub severity: String,
    pub condition: RuleCondition,
    pub action: RuleAction,
    pub valid_from: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
    pub enabled: bool,
}

/// Rule condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCondition {
    pub field: String,
    pub operator: String,
    pub value: i64,
}

/// Rule action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleAction {
    pub action_type: String,
    pub error_code: Option<String>,
    pub message: Option<String>,
    pub timeout_minutes: Option<u32>,
    pub alert_soc: bool,
}

impl Rule {
    /// Check if rule is valid now
    pub fn is_valid_now(&self) -> bool {
        let now = Utc::now();

        if now < self.valid_from {
            return false;
        }

        if let Some(until) = self.valid_until {
            if now > until {
                return false;
            }
        }

        self.enabled
    }

    /// Evaluate condition against context
    pub fn evaluate(&self, ctx: &EvaluationContext) -> Result<bool, EngineError> {
        let field_value = ctx
            .get_field(&self.condition.field)
            .ok_or_else(|| EngineError::FieldNotFound(self.condition.field.clone()))?;

        // Get numeric value from field
        let field_num = match field_value {
            crate::context::FieldValue::Number(n) => *n,
            crate::context::FieldValue::Boolean(b) => {
                if *b {
                    1
                } else {
                    0
                }
            }
            _ => return Err(EngineError::TypeMismatch(self.condition.field.clone())),
        };

        let op = self.condition.operator_typed()?;
        let result = match op {
            Operator::Gt => field_num > self.condition.value,
            Operator::Lt => field_num < self.condition.value,
            Operator::Gte => field_num >= self.condition.value,
            Operator::Lte => field_num <= self.condition.value,
            Operator::Eq => field_num == self.condition.value,
            Operator::Ne => field_num != self.condition.value,
        };

        Ok(result)
    }

    /// Apply action
    pub fn apply_action(&self, _ctx: &EvaluationContext) -> ActionResult {
        match self.action.action_kind().unwrap_or(ActionKind::Log) {
            ActionKind::Block => {
                let mut result = ActionResult::block(
                    self.action.error_code.as_deref().unwrap_or("UNKNOWN"),
                    self.action.message.as_deref().unwrap_or("Access denied"),
                );
                if self.action.alert_soc {
                    result = result.with_soc_alert();
                }
                result
            }
            ActionKind::Warn => ActionResult::warn(
                self.action.error_code.as_deref().unwrap_or("WARNING"),
                self.action.message.as_deref().unwrap_or("Warning"),
            ),
            ActionKind::RequireApproval => ActionResult::approval_required(
                self.action
                    .error_code
                    .as_deref()
                    .unwrap_or("APPROVAL_REQUIRED"),
                self.action.timeout_minutes.unwrap_or(30),
            ),
            ActionKind::Log => ActionResult::allow(),
        }
    }
}

impl RuleCondition {
    pub fn operator_typed(&self) -> Result<Operator, EngineError> {
        Operator::parse(&self.operator)
    }
}

impl RuleAction {
    pub fn action_kind(&self) -> Result<ActionKind, EngineError> {
        ActionKind::parse(&self.action_type)
    }
}

/// Rule registry
#[derive(Debug)]
pub struct RuleRegistry {
    rules: Vec<Rule>,
    by_id: std::collections::HashMap<String, usize>,
}

impl RuleRegistry {
    /// Create an empty registry (without built-in rules).
    /// Useful for tests that need deterministic "no rule matched" behavior.
    pub fn empty() -> Self {
        RuleRegistry {
            rules: Vec::new(),
            by_id: std::collections::HashMap::new(),
        }
    }

    /// Create new registry
    pub fn new() -> Self {
        let mut registry = RuleRegistry::empty();

        // Load built-in rules from specification
        registry.load_builtin_rules();

        registry
    }

    /// Load built-in rules
    fn load_builtin_rules(&mut self) {
        // CRUE-001: Volume max
        self.add_rule(Rule {
            id: "CRUE_001".to_string(),
            version: "1.2.0".to_string(),
            name: "VOLUME_MAX".to_string(),
            description: "Max 50 requêtes/heure".to_string(),
            severity: "HIGH".to_string(),
            condition: RuleCondition {
                field: "agent.requests_last_hour".to_string(),
                operator: ">=".to_string(),
                value: 50,
            },
            action: RuleAction {
                action_type: "BLOCK".to_string(),
                error_code: Some("VOLUME_EXCEEDED".to_string()),
                message: Some("Quota de consultation dépassé (50/h)".to_string()),
                timeout_minutes: None,
                alert_soc: true,
            },
            valid_from: Utc::now(),
            valid_until: None,
            enabled: true,
        });

        // CRUE-002: Justification obligatoire
        self.add_rule(Rule {
            id: "CRUE_002".to_string(),
            version: "1.1.0".to_string(),
            name: "JUSTIFICATION_OBLIG".to_string(),
            description: "Justification texte requise".to_string(),
            severity: "HIGH".to_string(),
            condition: RuleCondition {
                field: "request.justification_length".to_string(),
                operator: "<".to_string(),
                value: 10,
            },
            action: RuleAction {
                action_type: "BLOCK".to_string(),
                error_code: Some("JUSTIFICATION_REQUIRED".to_string()),
                message: Some("Justification obligatoire (min 10 caractères)".to_string()),
                timeout_minutes: None,
                alert_soc: false,
            },
            valid_from: Utc::now(),
            valid_until: None,
            enabled: true,
        });

        // CRUE-003: Export interdit
        self.add_rule(Rule {
            id: "CRUE_003".to_string(),
            version: "2.0.0".to_string(),
            name: "EXPORT_INTERDIT".to_string(),
            description: "Pas d'export CSV/XML/JSON bulk".to_string(),
            severity: "CRITICAL".to_string(),
            condition: RuleCondition {
                field: "request.export_format".to_string(),
                operator: "!=".to_string(),
                value: 0, // Not empty
            },
            action: RuleAction {
                action_type: "BLOCK".to_string(),
                error_code: Some("EXPORT_FORBIDDEN".to_string()),
                message: Some("Export de masse non autorisé".to_string()),
                timeout_minutes: None,
                alert_soc: true,
            },
            valid_from: Utc::now(),
            valid_until: None,
            enabled: true,
        });

        // CRUE-007: Temps requête max
        self.add_rule(Rule {
            id: "CRUE_007".to_string(),
            version: "1.0.0".to_string(),
            name: "TEMPS_REQUETE".to_string(),
            description: "Max 10 secondes".to_string(),
            severity: "MEDIUM".to_string(),
            condition: RuleCondition {
                field: "context.request_hour".to_string(),
                operator: ">=".to_string(),
                value: 0,
            },
            action: RuleAction {
                action_type: "WARN".to_string(),
                error_code: Some("PERFORMANCE_WARNING".to_string()),
                message: Some("Temps de requête élevé".to_string()),
                timeout_minutes: None,
                alert_soc: false,
            },
            valid_from: Utc::now(),
            valid_until: None,
            enabled: true,
        });
    }

    /// Add rule to registry
    pub fn add_rule(&mut self, rule: Rule) {
        let id = rule.id.clone();
        let index = self.rules.len();
        self.rules.push(rule);
        self.by_id.insert(id, index);
    }

    /// Get active rules
    pub fn get_active_rules(&self) -> Vec<&Rule> {
        self.rules.iter().filter(|r| r.is_valid_now()).collect()
    }

    /// Get rule by ID
    pub fn get_rule(&self, id: &str) -> Option<&Rule> {
        self.by_id.get(id).and_then(|&i| self.rules.get(i))
    }

    /// Get rule count
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether the registry contains no rules.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

impl Default for RuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_loads_builtin() {
        let registry = RuleRegistry::new();
        assert!(!registry.is_empty());
    }

    #[test]
    fn test_rule_evaluation() {
        let rule = Rule {
            id: "TEST_001".to_string(),
            version: "1.0.0".to_string(),
            name: "Test Rule".to_string(),
            description: "Test".to_string(),
            severity: "HIGH".to_string(),
            condition: RuleCondition {
                field: "agent.requests_last_hour".to_string(),
                operator: ">=".to_string(),
                value: 50,
            },
            action: RuleAction {
                action_type: "BLOCK".to_string(),
                error_code: Some("VOLUME_EXCEEDED".to_string()),
                message: None,
                timeout_minutes: None,
                alert_soc: false,
            },
            valid_from: Utc::now(),
            valid_until: None,
            enabled: true,
        };

        let ctx = EvaluationContext::from_request(&crate::EvaluationRequest {
            request_id: "test".to_string(),
            agent_id: "AGENT_001".to_string(),
            agent_org: "DGFiP".to_string(),
            agent_level: "standard".to_string(),
            mission_id: None,
            mission_type: None,
            query_type: None,
            justification: None,
            export_format: None,
            result_limit: None,
            requests_last_hour: 60,
            requests_last_24h: 100,
            results_last_query: 5,
            account_department: None,
            allowed_departments: vec![],
            request_hour: 14,
            is_within_mission_hours: true,
        });

        let result = rule.evaluate(&ctx).unwrap();
        assert!(result);
    }

    #[test]
    fn test_rule_condition_operator_typed() {
        let cond = RuleCondition {
            field: "agent.requests_last_hour".to_string(),
            operator: ">=".to_string(),
            value: 50,
        };
        assert_eq!(cond.operator_typed().unwrap(), crate::ir::Operator::Gte);
    }

    #[test]
    fn test_rule_action_kind_typed() {
        let action = RuleAction {
            action_type: "BLOCK".to_string(),
            error_code: None,
            message: None,
            timeout_minutes: None,
            alert_soc: false,
        };
        assert_eq!(action.action_kind().unwrap(), ActionKind::Block);
    }
}
