use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use aegis_engine::audit::{AuditEvent, MatchedRule, UpstreamInfo};
use aegis_engine::{Decision, RuleMatch};
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::mpsc;

use crate::config::{AuditConfig, AuditMode, AuditSink};

#[derive(Clone)]
pub struct AuditHandle {
    tx: mpsc::Sender<AuditEvent>,
    dropped: Arc<AtomicU64>,
}

impl AuditHandle {
    pub fn channel(capacity: usize) -> (Self, mpsc::Receiver<AuditEvent>) {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        (
            Self {
                tx,
                dropped: Arc::new(AtomicU64::new(0)),
            },
            rx,
        )
    }

    pub fn try_send(&self, event: AuditEvent) {
        if self.tx.try_send(event).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

pub fn should_write(
    mode: AuditMode,
    decision: &Decision,
    matched: &[RuleMatch],
    status: u16,
    upstream_status: Option<u16>,
    error: Option<&str>,
) -> bool {
    match mode {
        AuditMode::All => true,
        AuditMode::BlockedOnly => {
            decision.is_decisive()
                || error.is_some()
                || (status >= 400 && upstream_status.is_none())
                || matched.iter().any(|rule| rule.log)
        }
    }
}

pub struct EventInput<'a> {
    pub request_id: &'a str,
    pub client_ip: std::net::IpAddr,
    pub method: &'a str,
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub decision: &'a Decision,
    pub matched: &'a [RuleMatch],
    pub status: u16,
    pub upstream_status: Option<u16>,
    pub upstream_latency_ms: Option<u64>,
    pub error: Option<String>,
    pub latency_ms: u64,
    pub request_bytes: u64,
    pub rules_version: u64,
    pub include_query: bool,
    pub matched_limit: usize,
}

pub fn build_event(input: EventInput<'_>) -> AuditEvent {
    let decision_label = match input.decision {
        Decision::Pass if input.error.is_some() => "error",
        Decision::Pass if input.status >= 400 && input.upstream_status.is_none() => "block",
        Decision::Pass => "pass",
        Decision::Block { .. } => "block",
        Decision::Allow { .. } => "allow",
    };
    let rule_id = match input.decision {
        Decision::Pass => None,
        Decision::Block { rule_id, .. } => Some(*rule_id),
        Decision::Allow { rule_id } => Some(*rule_id),
    };
    let rule_msg = match input.decision {
        Decision::Block { msg, .. } => msg.clone(),
        _ => None,
    };
    let decision_rule = rule_id.and_then(|id| input.matched.iter().find(|rule| rule.id == id));
    let rule_data = decision_rule.and_then(|rule| rule.logdata.clone());
    let severity = decision_rule.and_then(|rule| rule.severity.clone());
    let tags = decision_rule
        .map(|rule| rule.tags.clone())
        .unwrap_or_default();
    let matched_rules: Vec<MatchedRule> = input
        .matched
        .iter()
        .take(input.matched_limit)
        .map(|rule| MatchedRule {
            id: rule.id,
            msg: rule.msg.clone(),
            logdata: rule.logdata.clone(),
            severity: rule.severity.clone(),
            tags: rule.tags.clone(),
        })
        .collect();

    AuditEvent {
        event_version: 1,
        ts: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        request_id: input.request_id.to_string(),
        client_ip: input.client_ip.to_string(),
        method: input.method.to_string(),
        path: input.path.to_string(),
        query: if input.include_query {
            input.query.map(str::to_string)
        } else {
            None
        },
        decision: decision_label.to_string(),
        status: input.status,
        rule_id,
        rule_msg,
        rule_data,
        severity,
        tags,
        matched_rules,
        error: input.error,
        upstream: UpstreamInfo {
            status: input.upstream_status,
            latency_ms: input.upstream_latency_ms,
        },
        latency_ms: input.latency_ms,
        request_bytes: input.request_bytes,
        rules_version: input.rules_version,
    }
}

pub async fn run(config: AuditConfig, mut receiver: mpsc::Receiver<AuditEvent>) {
    match config.sink {
        AuditSink::None => while receiver.recv().await.is_some() {},
        AuditSink::Stdout => {
            while let Some(event) = receiver.recv().await {
                match serde_json::to_string(&event) {
                    Ok(line) => println!("{line}"),
                    Err(error) => tracing::error!(%error, "failed to serialize audit event"),
                }
            }
        }
        AuditSink::File => {
            let path = match config.path.as_deref() {
                Some(path) => PathBuf::from(path),
                None => {
                    tracing::error!("audit.path missing; audit disabled");
                    while receiver.recv().await.is_some() {}
                    return;
                }
            };
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    if let Err(error) = tokio::fs::create_dir_all(parent).await {
                        tracing::error!(%error, "failed to create audit directory");
                    }
                }
            }
            match tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .await
            {
                Ok(file) => {
                    let mut writer = BufWriter::new(file);
                    while let Some(event) = receiver.recv().await {
                        match serde_json::to_vec(&event) {
                            Ok(mut line) => {
                                line.push(b'\n');
                                if writer.write_all(&line).await.is_err()
                                    || writer.flush().await.is_err()
                                {
                                    tracing::error!("failed to write audit event");
                                }
                            }
                            Err(error) => {
                                tracing::error!(%error, "failed to serialize audit event")
                            }
                        }
                    }
                }
                Err(error) => {
                    tracing::error!(%error, "failed to open audit file");
                    while receiver.recv().await.is_some() {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use aegis_engine::audit::{AuditEvent, MatchedRule, UpstreamInfo};
    use aegis_engine::{Decision, RuleMatch};

    use super::*;

    fn rule_match() -> RuleMatch {
        RuleMatch {
            id: 1001,
            msg: Some("blocked".to_string()),
            severity: Some("CRITICAL".to_string()),
            tags: vec!["attack".to_string()],
            logdata: Some("data".to_string()),
            log: true,
        }
    }

    #[test]
    fn blocked_only_filters_successful_pass_requests() {
        assert!(!should_write(
            AuditMode::BlockedOnly,
            &Decision::Pass,
            &[],
            200,
            None,
            None
        ));
        assert!(should_write(
            AuditMode::BlockedOnly,
            &Decision::Block {
                status: 403,
                rule_id: 1,
                msg: None
            },
            &[rule_match()],
            403,
            None,
            None
        ));
        assert!(should_write(
            AuditMode::BlockedOnly,
            &Decision::Pass,
            &[rule_match()],
            200,
            None,
            None
        ));
        assert!(should_write(
            AuditMode::BlockedOnly,
            &Decision::Pass,
            &[],
            413,
            None,
            None
        ));
        assert!(!should_write(
            AuditMode::BlockedOnly,
            &Decision::Pass,
            &[],
            404,
            Some(404),
            None
        ));
    }

    #[test]
    fn all_mode_writes_every_request() {
        assert!(should_write(
            AuditMode::All,
            &Decision::Pass,
            &[],
            200,
            None,
            None
        ));
    }

    #[test]
    fn builds_event_with_decision_metadata_and_redacted_query() {
        let matched = [rule_match()];
        let decision = Decision::Block {
            status: 403,
            rule_id: 1001,
            msg: Some("blocked".to_string()),
        };
        let event = build_event(EventInput {
            request_id: "req-1",
            client_ip: "203.0.113.10".parse().unwrap(),
            method: "GET",
            path: "/login",
            query: Some("q=secret"),
            decision: &decision,
            matched: &matched,
            status: 403,
            upstream_status: None,
            upstream_latency_ms: None,
            error: None,
            latency_ms: 2,
            request_bytes: 128,
            rules_version: 3,
            include_query: false,
            matched_limit: 16,
        });
        assert_eq!(event.decision, "block");
        assert_eq!(event.rule_id, Some(1001));
        assert_eq!(event.rule_data.as_deref(), Some("data"));
        assert_eq!(event.query, None);
        assert_eq!(event.matched_rules[0].id, 1001);
    }

    #[tokio::test]
    async fn dropped_counter_increments_when_queue_is_full() {
        let (handle, mut receiver) = AuditHandle::channel(1);
        let event = || AuditEvent {
            event_version: 1,
            ts: "2026-10-23T12:00:00.000Z".to_string(),
            request_id: "req".to_string(),
            client_ip: "127.0.0.1".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            query: None,
            decision: "pass".to_string(),
            status: 200,
            rule_id: None,
            rule_msg: None,
            rule_data: None,
            severity: None,
            tags: Vec::new(),
            matched_rules: Vec::<MatchedRule>::new(),
            error: None,
            upstream: UpstreamInfo {
                status: None,
                latency_ms: None,
            },
            latency_ms: 1,
            request_bytes: 1,
            rules_version: 1,
        };
        handle.try_send(event());
        handle.try_send(event());
        handle.try_send(event());
        assert!(handle.dropped() >= 1);
        assert!(receiver.recv().await.is_some());
    }
}
