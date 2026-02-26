//! Evaluation Context - Runtime context for rule evaluation

use crate::EvaluationRequest;
use std::collections::HashMap;

/// Evaluation context - provides field values for rule evaluation
pub struct EvaluationContext {
    /// Field values keyed by field path (e.g., "agent.requests_last_hour")
    fields: HashMap<String, FieldValue>,
}

impl EvaluationContext {
    /// Create context from evaluation request
    pub fn from_request(request: &EvaluationRequest) -> Self {
        let mut ctx = EvaluationContext {
            fields: HashMap::new(),
        };
        
        // Agent fields
        ctx.set_field("agent.id", FieldValue::String(request.agent_id.clone()));
        ctx.set_field("agent.org", FieldValue::String(request.agent_org.clone()));
        ctx.set_field("agent.level", FieldValue::String(request.agent_level.clone()));
        ctx.set_field("agent.requests_last_hour", FieldValue::Number(request.requests_last_hour as i64));
        ctx.set_field("agent.requests_last_24h", FieldValue::Number(request.requests_last_24h as i64));
        
        // Mission fields
        if let Some(mission_id) = &request.mission_id {
            ctx.set_field("mission.id", FieldValue::String(mission_id.clone()));
        }
        if let Some(mission_type) = &request.mission_type {
            ctx.set_field("mission.type", FieldValue::String(mission_type.clone()));
        }
        
        // Request fields
        if let Some(query_type) = &request.query_type {
            ctx.set_field("request.query_type", FieldValue::String(query_type.clone()));
        }
        if let Some(justification) = &request.justification {
            ctx.set_field("request.justification", FieldValue::String(justification.clone()));
            ctx.set_field("request.justification_length", FieldValue::Number(justification.len() as i64));
        }
        if let Some(export_format) = &request.export_format {
            ctx.set_field("request.export_format", FieldValue::String(export_format.clone()));
        }
        if let Some(limit) = request.result_limit {
            ctx.set_field("request.result_limit", FieldValue::Number(limit as i64));
        }
        
        // Results
        ctx.set_field("request.results_last_query", FieldValue::Number(request.results_last_query as i64));
        
        // Geographic
        if let Some(dept) = &request.account_department {
            ctx.set_field("account.department", FieldValue::String(dept.clone()));
        }
        
        // Allowed departments
        for (i, dept) in request.allowed_departments.iter().enumerate() {
            ctx.set_field(
                &format!("agent.allowed_departments[{}]", i),
                FieldValue::Number(*dept as i64),
            );
        }
        
        // Time
        ctx.set_field("context.request_hour", FieldValue::Number(request.request_hour as i64));
        ctx.set_field("context.is_within_mission_hours", FieldValue::Boolean(request.is_within_mission_hours));
        
        ctx
    }
    
    /// Get field value
    pub fn get_field(&self, path: &str) -> Option<&FieldValue> {
        self.fields.get(path)
    }
    
    /// Set field value
    pub fn set_field(&mut self, path: &str, value: FieldValue) {
        self.fields.insert(path.to_string(), value);
    }
    
    /// Get all fields
    pub fn fields(&self) -> &HashMap<String, FieldValue> {
        &self.fields
    }
}

/// Field value types
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum FieldValue {
    Number(i64),
    Float(f64),
    String(String),
    Boolean(bool),
}

impl FieldValue {
    /// Compare using operator
    pub fn compare(&self, op: &str, other: &FieldValue) -> bool {
        match (self, other) {
            (FieldValue::Number(a), FieldValue::Number(b)) => {
                match op {
                    ">" => a > b,
                    "<" => a < b,
                    ">=" => a >= b,
                    "<=" => a <= b,
                    "==" => a == b,
                    "!=" => a != b,
                    _ => false,
                }
            }
            (FieldValue::String(a), FieldValue::String(b)) => {
                match op {
                    "==" => a == b,
                    "!=" => a != b,
                    _ => false,
                }
            }
            (FieldValue::Boolean(a), FieldValue::Boolean(b)) => {
                match op {
                    "==" => a == b,
                    "!=" => a != b,
                    _ => false,
                }
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_context_creation() {
        let request = EvaluationRequest {
            request_id: "test".to_string(),
            agent_id: "AGENT_001".to_string(),
            agent_org: "DGFiP".to_string(),
            agent_level: "standard".to_string(),
            mission_id: Some("MIS_001".to_string()),
            mission_type: None,
            query_type: None,
            justification: None,
            export_format: None,
            result_limit: None,
            requests_last_hour: 10,
            requests_last_24h: 100,
            results_last_query: 5,
            account_department: None,
            allowed_departments: vec![],
            request_hour: 14,
            is_within_mission_hours: true,
        };
        
        let ctx = EvaluationContext::from_request(&request);
        
        assert_eq!(
            ctx.get_field("agent.id"),
            Some(&FieldValue::String("AGENT_001".to_string()))
        );
        assert_eq!(
            ctx.get_field("agent.requests_last_hour"),
            Some(&FieldValue::Number(10))
        );
    }
    
    #[test]
    fn test_field_comparison() {
        assert!(FieldValue::Number(10).compare(">", &FieldValue::Number(5)));
        assert!(FieldValue::Number(10).compare(">=", &FieldValue::Number(10)));
        assert!(FieldValue::String("test".to_string()).compare("==", &FieldValue::String("test".to_string())));
    }
}
