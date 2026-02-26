//! Incident Response Module
//! 
//! Provides structured incident response capabilities for R-SRP including:
//! - Incident detection and classification
//! - Automated response playbooks
//! - SOC integration hooks
//! - Runbook automation
//! - Alerting and escalation

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// Incident severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Incident status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum IncidentStatus {
    Open,
    Investigating,
    Contained,
    Eradicated,
    Recovering,
    Closed,
    FalsePositive,
}

/// Incident type classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IncidentType {
    SecurityBreach,
    DenialOfService,
    Malware,
    UnauthorizedAccess,
    DataExfiltration,
    SystemFailure,
    PerformanceDegradation,
    AnomalyDetection,
    ConfigurationDrift,
    ComplianceViolation,
}

/// Incident record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    /// Unique incident ID
    pub id: String,
    /// Incident type
    pub incident_type: IncidentType,
    /// Severity level
    pub severity: Severity,
    /// Current status
    pub status: IncidentStatus,
    /// Detection timestamp
    pub detected_at: DateTime<Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
    /// Title/description
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Affected systems
    pub affected_systems: Vec<String>,
    /// Assigned responder
    pub assigned_to: Option<String>,
    /// Timeline of events
    pub timeline: Vec<IncidentEvent>,
    /// Related artifacts
    pub artifacts: Vec<Artifact>,
    /// Playbook executed
    pub playbook_executed: Option<String>,
    /// Resolution notes
    pub resolution: Option<String>,
}

/// Single event in incident timeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub description: String,
    pub actor: Option<String>,
}

/// Evidence artifact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub artifact_type: String,
    pub location: String,
    pub hash: Option<String>,
    pub collected_at: DateTime<Utc>,
}

/// Playbook definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Playbook {
    pub id: String,
    pub name: String,
    pub description: String,
    pub triggered_by: Vec<IncidentType>,
    pub severity_threshold: Severity,
    pub steps: Vec<PlaybookStep>,
}

/// Playbook step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookStep {
    pub step_id: u32,
    pub action: String,
    pub description: String,
    pub automated: bool,
    pub estimated_duration_secs: u32,
}

/// Incident service
pub struct IncidentService {
    /// Active incidents
    incidents: Vec<Incident>,
    /// Available playbooks
    playbooks: Vec<Playbook>,
    /// SOC webhook URL
    soc_webhook: Option<String>,
}

impl IncidentService {
    /// Create new incident service
    pub fn new() -> Self {
        let mut service = IncidentService {
            incidents: Vec::new(),
            playbooks: Vec::new(),
            soc_webhook: None,
        };
        
        // Load default playbooks
        service.init_default_playbooks();
        service
    }
    
    /// Initialize default incident response playbooks
    fn init_default_playbooks(&mut self) {
        self.playbooks = vec![
            Playbook {
                id: "PB-001".to_string(),
                name: "Security Breach Response".to_string(),
                description: "Automated response for security breaches".to_string(),
                triggered_by: vec![
                    IncidentType::SecurityBreach,
                    IncidentType::UnauthorizedAccess,
                ],
                severity_threshold: Severity::High,
                steps: vec![
                    PlaybookStep {
                        step_id: 1,
                        action: "isolate".to_string(),
                        description: "Isolate affected systems".to_string(),
                        automated: true,
                        estimated_duration_secs: 60,
                    },
                    PlaybookStep {
                        step_id: 2,
                        action: "alert_soc".to_string(),
                        description: "Alert SOC team".to_string(),
                        automated: true,
                        estimated_duration_secs: 30,
                    },
                    PlaybookStep {
                        step_id: 3,
                        action: "collect_evidence".to_string(),
                        description: "Collect forensic evidence".to_string(),
                        automated: true,
                        estimated_duration_secs: 300,
                    },
                    PlaybookStep {
                        step_id: 4,
                        action: "notify_stakeholders".to_string(),
                        description: "Notify stakeholders".to_string(),
                        automated: false,
                        estimated_duration_secs: 0,
                    },
                ],
            },
            Playbook {
                id: "PB-002".to_string(),
                name: "DoS Attack Response".to_string(),
                description: "Response playbook for denial of service".to_string(),
                triggered_by: vec![IncidentType::DenialOfService],
                severity_threshold: Severity::Medium,
                steps: vec![
                    PlaybookStep {
                        step_id: 1,
                        action: "enable_rate_limiting".to_string(),
                        description: "Enable aggressive rate limiting".to_string(),
                        automated: true,
                        estimated_duration_secs: 30,
                    },
                    PlaybookStep {
                        step_id: 2,
                        action: "block_ips".to_string(),
                        description: "Block malicious IPs".to_string(),
                        automated: true,
                        estimated_duration_secs: 60,
                    },
                    PlaybookStep {
                        step_id: 3,
                        action: "scale_infrastructure".to_string(),
                        description: "Scale infrastructure".to_string(),
                        automated: true,
                        estimated_duration_secs: 120,
                    },
                ],
            },
            Playbook {
                id: "PB-003".to_string(),
                name: "Anomaly Investigation".to_string(),
                description: "Investigate detected anomalies".to_string(),
                triggered_by: vec![IncidentType::AnomalyDetection],
                severity_threshold: Severity::Low,
                steps: vec![
                    PlaybookStep {
                        step_id: 1,
                        action: "log_enrichment".to_string(),
                        description: "Enrich logs with context".to_string(),
                        automated: true,
                        estimated_duration_secs: 30,
                    },
                    PlaybookStep {
                        step_id: 2,
                        action: "analyze_patterns".to_string(),
                        description: "Analyze behavioral patterns".to_string(),
                        automated: true,
                        estimated_duration_secs: 120,
                    },
                    PlaybookStep {
                        step_id: 3,
                        action: "human_review".to_string(),
                        description: "Queue for human review".to_string(),
                        automated: false,
                        estimated_duration_secs: 0,
                    },
                ],
            },
        ];
    }
    
    /// Configure SOC webhook
    pub fn set_soc_webhook(&mut self, url: String) {
        self.soc_webhook = Some(url);
    }
    
    /// Create new incident
    pub fn create_incident(
        &mut self,
        incident_type: IncidentType,
        severity: Severity,
        title: String,
        description: String,
        affected_systems: Vec<String>,
    ) -> Incident {
        let incident = Incident {
            id: format!("INC-{}", uuid::Uuid::new_v4()),
            incident_type,
            severity: severity.clone(),
            status: IncidentStatus::Open,
            detected_at: Utc::now(),
            updated_at: Utc::now(),
            title,
            description,
            affected_systems,
            assigned_to: None,
            timeline: vec![IncidentEvent {
                timestamp: Utc::now(),
                event_type: "CREATED".to_string(),
                description: "Incident created".to_string(),
                actor: Some("system".to_string()),
            }],
            artifacts: Vec::new(),
            playbook_executed: None,
            resolution: None,
        };
        
        self.incidents.push(incident.clone());
        
        // Auto-trigger playbook if available
        self.trigger_playbook(&incident);
        
        // Alert SOC if configured
        if let Some(ref webhook) = self.soc_webhook {
            self.send_soc_alert(&incident, webhook);
        }
        
        incident
    }
    
    /// Trigger appropriate playbook
    fn trigger_playbook(&mut self, incident: &Incident) {
        // Find matching playbook
        if let Some(playbook) = self.playbooks.iter().find(|pb| {
            pb.triggered_by.contains(&incident.incident_type) 
            && self.severity_meets_threshold(&incident.severity, &pb.severity_threshold)
        }) {
            // Execute playbook (simulated)
            tracing::info!(
                "Triggering playbook {} for incident {}",
                playbook.id,
                incident.id
            );
            
            // Update incident
            if let Some(inc) = self.incidents.iter_mut().find(|i| i.id == incident.id) {
                inc.playbook_executed = Some(playbook.id.clone());
                inc.status = IncidentStatus::Investigating;
                inc.timeline.push(IncidentEvent {
                    timestamp: Utc::now(),
                    event_type: "PLAYBOOK_TRIGGERED".to_string(),
                    description: format!("Playbook '{}' triggered", playbook.name),
                    actor: Some("system".to_string()),
                });
            }
        }
    }
    
    /// Check if severity meets threshold
    fn severity_meets_threshold(&self, severity: &Severity, threshold: &Severity) -> bool {
        let severity_order = |s: &Severity| match s {
            Severity::Critical => 5,
            Severity::High => 4,
            Severity::Medium => 3,
            Severity::Low => 2,
            Severity::Info => 1,
        };
        
        severity_order(severity) >= severity_order(threshold)
    }
    
    /// Send alert to SOC
    fn send_soc_alert(&self, incident: &Incident, webhook: &str) {
        // In production, this would make an HTTP POST to the SOC
        tracing::warn!(
            "SOC ALERT: {} - {} [{:?}] - {}",
            webhook,
            incident.id,
            incident.severity,
            incident.title
        );
    }
    
    /// Update incident status
    pub fn update_status(&mut self, incident_id: &str, status: IncidentStatus) -> Option<&Incident> {
        if let Some(inc) = self.incidents.iter_mut().find(|i| i.id == incident_id) {
            inc.status = status.clone();
            inc.updated_at = Utc::now();
            inc.timeline.push(IncidentEvent {
                timestamp: Utc::now(),
                event_type: "STATUS_CHANGED".to_string(),
                description: format!("Status changed to {:?}", status),
                actor: Some("system".to_string()),
            });
        }
        self.incidents.iter().find(|i| i.id == incident_id)
    }
    
    /// Get active incidents
    pub fn get_active_incidents(&self) -> Vec<&Incident> {
        self.incidents
            .iter()
            .filter(|i| i.status != IncidentStatus::Closed && i.status != IncidentStatus::FalsePositive)
            .collect()
    }
    
    /// Resolve incident
    pub fn resolve_incident(&mut self, incident_id: &str, resolution: String) -> Option<&Incident> {
        if let Some(inc) = self.incidents.iter_mut().find(|i| i.id == incident_id) {
            inc.status = IncidentStatus::Closed;
            inc.resolution = Some(resolution);
            inc.updated_at = Utc::now();
            inc.timeline.push(IncidentEvent {
                timestamp: Utc::now(),
                event_type: "RESOLVED".to_string(),
                description: "Incident resolved".to_string(),
                actor: Some("system".to_string()),
            });
        }
        self.incidents.iter().find(|i| i.id == incident_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_create_incident() {
        let mut service = IncidentService::new();
        
        let incident = service.create_incident(
            IncidentType::AnomalyDetection,
            Severity::Medium,
            "Test Incident".to_string(),
            "Test description".to_string(),
            vec!["server-1".to_string()],
        );
        
        assert_eq!(incident.status, IncidentStatus::Open);
    }
    
    #[test]
    fn test_severity_threshold() {
        let service = IncidentService::new();
        
        assert!(service.severity_meets_threshold(&Severity::Critical, &Severity::Low));
        assert!(service.severity_meets_threshold(&Severity::High, &Severity::High));
        assert!(!service.severity_meets_threshold(&Severity::Low, &Severity::High));
    }
}
