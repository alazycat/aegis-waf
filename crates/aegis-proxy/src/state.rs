use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::Full;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

use crate::audit_sink::AuditHandle;
use crate::config::Config;
use crate::rules::RulesManager;

pub type ProxyClient = Client<HttpConnector, Full<Bytes>>;

pub struct AppState {
    pub config: Config,
    pub client: ProxyClient,
    pub rules: Arc<RulesManager>,
    pub audit: AuditHandle,
    pub started_at: Instant,
}

impl AppState {
    pub fn new(
        config: Config,
        rules: Arc<RulesManager>,
        audit: AuditHandle,
    ) -> anyhow::Result<Self> {
        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(Duration::from_millis(
            config.upstream.connect_timeout_ms,
        )));
        connector.enforce_http(true);
        let client: ProxyClient = Client::builder(TokioExecutor::new()).build(connector);
        Ok(Self {
            config,
            client,
            rules,
            audit,
            started_at: Instant::now(),
        })
    }
}
