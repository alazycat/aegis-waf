#![forbid(unsafe_code)]

pub mod config;

pub use config::{Config, ConfigError};

pub async fn run(_config: Config) -> anyhow::Result<()> {
    anyhow::bail!("server not implemented yet")
}
