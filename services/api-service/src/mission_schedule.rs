//! Mission schedule store used for temporal RBAC checks.

use chrono::{DateTime, Datelike, Timelike, Utc};
use serde::Deserialize;
use std::{collections::HashMap, path::Path};

#[derive(Debug, Clone, Deserialize)]
struct MissionScheduleFile {
    missions: Vec<MissionScheduleEntry>,
}

#[derive(Debug, Clone, Deserialize)]
struct MissionScheduleEntry {
    mission_id: String,
    // Monday=1 ... Sunday=7 (ISO weekday index)
    allowed_weekdays: Vec<u8>,
    // UTC hour, inclusive start and exclusive end.
    start_hour: u8,
    end_hour: u8,
}

#[derive(Debug, Clone, Default)]
pub struct MissionScheduleStore {
    missions: HashMap<String, MissionScheduleEntry>,
}

impl MissionScheduleStore {
    pub fn from_env() -> Result<Self, String> {
        let path = std::env::var("MISSION_SCHEDULE_PATH").unwrap_or_default();
        if path.trim().is_empty() {
            tracing::warn!(
                "MISSION_SCHEDULE_PATH not configured. Temporal RBAC is fail-closed (all requests denied)."
            );
            return Ok(Self::default());
        }
        Self::from_file(Path::new(path.trim()))
    }

    pub fn from_file(path: &Path) -> Result<Self, String> {
        let raw = std::fs::read(path)
            .map_err(|e| format!("Failed to read mission schedule {}: {}", path.display(), e))?;
        let parsed: MissionScheduleFile = serde_json::from_slice(&raw)
            .map_err(|e| format!("Invalid mission schedule JSON {}: {}", path.display(), e))?;

        let mut missions = HashMap::new();
        for entry in parsed.missions {
            if entry.mission_id.trim().is_empty() {
                return Err("Mission schedule contains empty mission_id".to_string());
            }
            if entry.allowed_weekdays.is_empty() {
                return Err(format!(
                    "Mission {} has empty allowed_weekdays",
                    entry.mission_id
                ));
            }
            if entry.allowed_weekdays.iter().any(|d| *d < 1 || *d > 7) {
                return Err(format!(
                    "Mission {} has invalid weekday values (expected 1..7)",
                    entry.mission_id
                ));
            }
            if entry.start_hour > 23 || entry.end_hour > 24 || entry.start_hour >= entry.end_hour {
                return Err(format!(
                    "Mission {} has invalid hour range {}..{}",
                    entry.mission_id, entry.start_hour, entry.end_hour
                ));
            }
            missions.insert(entry.mission_id.clone(), entry);
        }
        Ok(Self { missions })
    }

    pub fn is_within_mission_hours(
        &self,
        mission_id: Option<&str>,
        now_utc: DateTime<Utc>,
    ) -> bool {
        let mission_id = match mission_id {
            Some(v) if !v.trim().is_empty() => v,
            _ => return false,
        };
        let schedule = match self.missions.get(mission_id) {
            Some(s) => s,
            None => return false,
        };

        let weekday = now_utc.weekday().number_from_monday() as u8;
        if !schedule.allowed_weekdays.contains(&weekday) {
            return false;
        }
        let hour = now_utc.hour() as u8;
        hour >= schedule.start_hour && hour < schedule.end_hour
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    #[test]
    fn test_schedule_allows_in_range() {
        let json = r#"{
            "missions":[{"mission_id":"MIS_001","allowed_weekdays":[1,2,3,4,5],"start_hour":8,"end_hour":18}]
        }"#;
        let file: MissionScheduleFile = serde_json::from_str(json).unwrap();
        let store = MissionScheduleStore {
            missions: file
                .missions
                .into_iter()
                .map(|m| (m.mission_id.clone(), m))
                .collect(),
        };
        let ts = Utc.with_ymd_and_hms(2026, 3, 2, 10, 0, 0).unwrap(); // Monday
        assert!(store.is_within_mission_hours(Some("MIS_001"), ts));
    }

    #[test]
    fn test_schedule_rejects_out_of_range_or_missing() {
        let json = r#"{
            "missions":[{"mission_id":"MIS_001","allowed_weekdays":[1,2,3,4,5],"start_hour":8,"end_hour":18}]
        }"#;
        let file: MissionScheduleFile = serde_json::from_str(json).unwrap();
        let store = MissionScheduleStore {
            missions: file
                .missions
                .into_iter()
                .map(|m| (m.mission_id.clone(), m))
                .collect(),
        };
        let late = Utc.with_ymd_and_hms(2026, 3, 2, 21, 0, 0).unwrap(); // Monday
        assert!(!store.is_within_mission_hours(Some("MIS_001"), late));
        assert!(!store.is_within_mission_hours(Some("UNKNOWN"), late));
        assert!(!store.is_within_mission_hours(None, late));
    }
}
