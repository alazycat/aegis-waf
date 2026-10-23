#![forbid(unsafe_code)]

pub mod admin;
pub mod audit_sink;
pub mod config;
pub mod proxy;
pub mod rules;
pub mod signal;
pub mod state;

use std::sync::Arc;
use std::time::Duration;

pub use config::{resolve_rule_files, Config, ConfigError};

pub async fn run(config: Config) -> anyhow::Result<()> {
    let rule_files = config.validate()?;
    let rules = Arc::new(rules::RulesManager::load_initial(
        &rule_files,
        config.rules.lenient,
    )?);
    let (audit, audit_receiver) = audit_sink::AuditHandle::channel(config.audit.queue_capacity);
    tokio::spawn(audit_sink::run(config.audit.clone(), audit_receiver));

    let data_listener = tokio::net::TcpListener::bind(&config.listen).await?;
    let admin_listener = tokio::net::TcpListener::bind(&config.admin.listen).await?;
    let data_addr = data_listener.local_addr()?;
    let admin_addr = admin_listener.local_addr()?;
    let state = Arc::new(state::AppState::new(config, rules, audit)?);
    tracing::info!(%data_addr, %admin_addr, "aegis-proxy started");

    let (shutdown_sender, shutdown_receiver) = tokio::sync::watch::channel(false);
    let data_task = tokio::spawn(proxy::serve_on_with_shutdown(
        data_listener,
        state.clone(),
        shutdown_receiver,
    ));
    let admin_task = tokio::spawn(admin::serve_on(admin_listener, state.clone()));

    #[cfg(unix)]
    tokio::spawn(signal::sighup_loop(state));

    signal::shutdown_signal().await;
    let _ = shutdown_sender.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(12), data_task).await;
    admin_task.abort();
    Ok(())
}
