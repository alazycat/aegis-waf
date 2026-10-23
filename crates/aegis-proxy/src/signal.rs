#[cfg(unix)]
use std::sync::Arc;

#[cfg(unix)]
use crate::state::AppState;

pub async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[cfg(unix)]
pub async fn sighup_loop(state: Arc<AppState>) {
    use tokio::signal::unix::{signal, SignalKind};

    let Ok(mut hangup) = signal(SignalKind::hangup()) else {
        tracing::error!("failed to install SIGHUP handler");
        return;
    };
    while hangup.recv().await.is_some() {
        match state.rules.reload().await {
            Ok(rules) => tracing::info!(version = rules.version, "rules reloaded on SIGHUP"),
            Err(error) => tracing::error!(%error, "SIGHUP rule reload failed"),
        }
    }
}
