//! Decision Types

use serde::{Deserialize, Serialize};

/// Access decision
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum Decision {
    /// Allow access
    #[default]
    Allow,
    /// Block access
    Block,
    /// Allow with warning
    Warn,
    /// Require approval
    ApprovalRequired,
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Decision::Allow => write!(f, "ALLOW"),
            Decision::Block => write!(f, "BLOCK"),
            Decision::Warn => write!(f, "WARN"),
            Decision::ApprovalRequired => write!(f, "APPROVAL_REQUIRED"),
        }
    }
}

/// Action result from rule
#[derive(Debug, Clone)]
pub struct ActionResult {
    pub decision: Decision,
    pub error_code: Option<String>,
    pub message: Option<String>,
    pub alert_soc: bool,
}

impl ActionResult {
    /// Create block result
    pub fn block(code: &str, message: &str) -> Self {
        ActionResult {
            decision: Decision::Block,
            error_code: Some(code.to_string()),
            message: Some(message.to_string()),
            alert_soc: false,
        }
    }

    /// Create warning result
    pub fn warn(code: &str, message: &str) -> Self {
        ActionResult {
            decision: Decision::Warn,
            error_code: Some(code.to_string()),
            message: Some(message.to_string()),
            alert_soc: false,
        }
    }

    /// Create approval required result
    pub fn approval_required(code: &str, timeout_minutes: u32) -> Self {
        ActionResult {
            decision: Decision::ApprovalRequired,
            error_code: Some(code.to_string()),
            message: Some(format!(
                "Approval required within {} minutes",
                timeout_minutes
            )),
            alert_soc: false,
        }
    }

    /// Create allow result
    pub fn allow() -> Self {
        ActionResult {
            decision: Decision::Allow,
            error_code: None,
            message: None,
            alert_soc: false,
        }
    }

    /// Add SOC alert
    pub fn with_soc_alert(mut self) -> Self {
        self.alert_soc = true;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decision_display() {
        assert_eq!(format!("{}", Decision::Allow), "ALLOW");
        assert_eq!(format!("{}", Decision::Block), "BLOCK");
    }

    #[test]
    fn test_action_result() {
        let result = ActionResult::block("VOLUME_EXCEEDED", "Quota dépassé");
        assert_eq!(result.decision, Decision::Block);
        assert_eq!(result.error_code, Some("VOLUME_EXCEEDED".to_string()));
    }
}
