//! CRUE Engine Core

use crate::{EvaluationRequest, EvaluationResult, decision::Decision, error::EngineError};
use crate::context::EvaluationContext;
use crate::rules::RuleRegistry;
use std::time::Instant;
use tracing::{info, warn, error};

/// CRUE Engine - main rule evaluation engine
pub struct CrueEngine {
    rule_registry: RuleRegistry,
    strict_mode: bool,
}

impl CrueEngine {
    /// Create new CRUE engine
    pub fn new() -> Self {
        CrueEngine {
            rule_registry: RuleRegistry::new(),
            strict_mode: true,
        }
    }
    
    /// Load rules from registry
    pub fn load_rules(&mut self, registry: RuleRegistry) {
        self.rule_registry = registry;
    }
    
    /// Evaluate request against all rules
    pub fn evaluate(&self, request: &EvaluationRequest) -> EvaluationResult {
        let start = Instant::now();
        
        info!("Evaluating request: {}", request.request_id);
        
        // Create evaluation context
        let ctx = EvaluationContext::from_request(request);
        
        // Get active rules
        let rules = self.rule_registry.get_active_rules();
        
        // Evaluate each rule in order (first-match-wins)
        for rule in rules {
            // Check rule validity period
            if !rule.is_valid_now() {
                continue;
            }
            
            // Evaluate conditions
            match rule.evaluate(&ctx) {
                Ok(true) => {
                    // Rule matched - apply action
                    let result = rule.apply_action(&ctx);
                    
                    let evaluation_time = start.elapsed().as_millis() as u64;
                    
                    info!(
                        "Request {}: {} by rule {} ({}ms)",
                        request.request_id,
                        format!("{:?}", result.decision),
                        rule.id,
                        evaluation_time
                    );
                    
                    return EvaluationResult {
                        request_id: request.request_id.clone(),
                        decision: result.decision,
                        error_code: result.error_code,
                        message: result.message,
                        rule_id: Some(rule.id.clone()),
                        rule_version: Some(rule.version.clone()),
                        evaluated_at: chrono::Utc::now().to_rfc3339(),
                        evaluation_time_ms: evaluation_time,
                    };
                }
                Ok(false) => {
                    // Rule didn't match, continue to next
                }
                Err(e) => {
                    // Error evaluating rule
                    if self.strict_mode {
                        error!("Error evaluating rule {}: {}", rule.id, e);
                        // In strict mode, block on error
                        return EvaluationResult {
                            request_id: request.request_id.clone(),
                            decision: Decision::Block,
                            error_code: Some("ENGINE_ERROR".to_string()),
                            message: Some(format!("Rule evaluation error: {}", e)),
                            rule_id: Some(rule.id.clone()),
                            rule_version: Some(rule.version.clone()),
                            evaluated_at: chrono::Utc::now().to_rfc3339(),
                            evaluation_time_ms: start.elapsed().as_millis() as u64,
                        };
                    } else {
                        warn!("Non-strict mode: continuing after error in rule {}", rule.id);
                    }
                }
            }
        }
        
        // No rules matched - allow by default
        EvaluationResult {
            request_id: request.request_id.clone(),
            decision: Decision::Allow,
            evaluated_at: chrono::Utc::now().to_rfc3339(),
            evaluation_time_ms: start.elapsed().as_millis() as u64,
            ..Default::default()
        }
    }
    
    /// Set strict mode
    pub fn set_strict_mode(&mut self, strict: bool) {
        self.strict_mode = strict;
    }
    
    /// Get rule count
    pub fn rule_count(&self) -> usize {
        self.rule_registry.len()
    }
}

impl Default for CrueEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_engine_default() {
        let engine = CrueEngine::new();
        assert_eq!(engine.rule_count(), 0);
    }
    
    #[test]
    fn test_evaluate_default_allow() {
        let engine = CrueEngine::new();
        
        let request = EvaluationRequest {
            request_id: "test_001".to_string(),
            agent_id: "AGENT_001".to_string(),
            agent_org: "DGFiP".to_string(),
            agent_level: "standard".to_string(),
            mission_id: None,
            mission_type: None,
            query_type: None,
            justification: None,
            export_format: None,
            result_limit: None,
            requests_last_hour: 0,
            requests_last_24h: 0,
            results_last_query: 0,
            account_department: None,
            allowed_departments: vec![],
            request_hour: 12,
            is_within_mission_hours: true,
        };
        
        let result = engine.evaluate(&request);
        assert_eq!(result.decision, Decision::Allow);
    }
}
