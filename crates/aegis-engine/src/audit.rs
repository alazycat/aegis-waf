use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_version: u8,
    pub ts: String,
    pub request_id: String,
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub decision: String,
    pub status: u16,
    pub rule_id: Option<u32>,
    pub rule_msg: Option<String>,
    pub rule_data: Option<String>,
    pub severity: Option<String>,
    pub tags: Vec<String>,
    pub matched_rules: Vec<MatchedRule>,
    pub error: Option<String>,
    pub upstream: UpstreamInfo,
    pub latency_ms: u64,
    pub request_bytes: u64,
    pub rules_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchedRule {
    pub id: u32,
    pub msg: Option<String>,
    pub logdata: Option<String>,
    pub severity: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamInfo {
    pub status: Option<u16>,
    pub latency_ms: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> AuditEvent {
        AuditEvent {
            event_version: 1,
            ts: "2026-10-23T12:00:00.123Z".to_string(),
            request_id: "0b6f7d2e-6f0a-4e2a-9c1a-2f4b6d8e0a11".to_string(),
            client_ip: "203.0.113.10".to_string(),
            method: "GET".to_string(),
            path: "/login".to_string(),
            query: None,
            decision: "block".to_string(),
            status: 403,
            rule_id: Some(942100),
            rule_msg: Some("SQL Injection Attack Detected".to_string()),
            rule_data: None,
            severity: Some("CRITICAL".to_string()),
            tags: vec!["attack-sqli".to_string()],
            matched_rules: vec![MatchedRule {
                id: 942100,
                msg: Some("SQL Injection Attack Detected".to_string()),
                logdata: Some("Matched Data: x found within ARGS:q".to_string()),
                severity: Some("CRITICAL".to_string()),
                tags: vec!["attack-sqli".to_string()],
            }],
            error: None,
            upstream: UpstreamInfo {
                status: None,
                latency_ms: None,
            },
            latency_ms: 2,
            request_bytes: 128,
            rules_version: 4,
        }
    }

    #[test]
    fn serializes_expected_field_names() {
        let json = serde_json::to_value(event()).unwrap();
        assert_eq!(json["event_version"], 1);
        assert_eq!(json["decision"], "block");
        assert_eq!(json["matched_rules"][0]["id"], 942100);
        assert_eq!(json["upstream"]["status"], serde_json::Value::Null);
    }

    #[test]
    fn round_trips_through_json() {
        let original = event();
        let text = serde_json::to_string(&original).unwrap();
        let restored: AuditEvent = serde_json::from_str(&text).unwrap();
        assert_eq!(original, restored);
    }
}
