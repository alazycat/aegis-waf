#![forbid(unsafe_code)]

pub mod audit_sink;
pub mod config;
pub mod proxy;
pub mod rules;
pub mod state;

use std::sync::Arc;

pub use config::{resolve_rule_files, Config, ConfigError};

pub async fn run(config: Config) -> anyhow::Result<()> {
    let rule_files = config.validate()?;
    let rules = Arc::new(rules::RulesManager::load_initial(
        &rule_files,
        config.rules.lenient,
    )?);
    let (audit, audit_receiver) = audit_sink::AuditHandle::channel(config.audit.queue_capacity);
    tokio::spawn(audit_sink::run(config.audit.clone(), audit_receiver));
    let listener = tokio::net::TcpListener::bind(&config.listen).await?;
    let state = Arc::new(state::AppState::new(config, rules, audit)?);
    tracing::info!("aegis-proxy listening on {}", listener.local_addr()?);
    proxy::serve_on(listener, state).await
}
