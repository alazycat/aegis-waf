#![forbid(unsafe_code)]

pub mod config;
pub mod proxy;
pub mod state;

use std::sync::Arc;

pub use config::{Config, ConfigError};

pub async fn run(config: Config) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(&config.listen).await?;
    let state = Arc::new(state::AppState::new(config)?);
    tracing::info!("aegis-proxy listening on {}", listener.local_addr()?);
    proxy::serve_on(listener, state).await
}
