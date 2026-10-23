use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use hyper::body::Incoming;
use hyper::header::{AUTHORIZATION, CONTENT_TYPE};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::json;
use tokio::net::TcpListener;

use crate::proxy::{full_body, ProxyBody};
use crate::state::AppState;

pub async fn serve_on(listener: TcpListener, state: Arc<AppState>) -> anyhow::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |request| handle(request, state.clone()));
            if let Err(error) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                tracing::debug!(%peer, %error, "admin connection closed");
            }
        });
    }
}

async fn handle(
    request: Request<Incoming>,
    state: Arc<AppState>,
) -> Result<Response<ProxyBody>, Infallible> {
    if !authorized(&request, &state) {
        return Ok(json_response(
            StatusCode::UNAUTHORIZED,
            json!({"error": "unauthorized"}),
        ));
    }
    match (request.method(), request.uri().path()) {
        (&Method::GET, "/healthz") => Ok(json_response(StatusCode::OK, json!({"status": "ok"}))),
        (&Method::GET, "/readyz") => Ok(json_response(StatusCode::OK, json!({"status": "ready"}))),
        (&Method::GET, "/status") => {
            let rules = state.rules.snapshot();
            Ok(json_response(
                StatusCode::OK,
                json!({
                    "version": env!("CARGO_PKG_VERSION"),
                    "uptime_seconds": state.started_at.elapsed().as_secs(),
                    "rules": {
                        "version": rules.version,
                        "count": rules.rule_count,
                        "files": state.rules.files().iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
                        "loaded_at": state.rules.loaded_at(),
                    },
                    "audit": {"dropped": state.audit.dropped()},
                    "ready": true,
                }),
            ))
        }
        (&Method::GET, "/rules") => {
            let rules = state.rules.snapshot();
            Ok(json_response(
                StatusCode::OK,
                json!({
                    "version": rules.version,
                    "count": rules.rule_count,
                    "files": state.rules.files().iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
                    "loaded_at": state.rules.loaded_at(),
                }),
            ))
        }
        (&Method::POST, "/rules/reload") => match state.rules.reload().await {
            Ok(rules) => Ok(json_response(
                StatusCode::OK,
                json!({
                    "rules_version": rules.version,
                    "count": rules.rule_count,
                    "loaded_at": state.rules.loaded_at(),
                }),
            )),
            Err(error) => Ok(json_response(
                StatusCode::BAD_REQUEST,
                json!({"error": error.to_string()}),
            )),
        },
        _ => Ok(json_response(
            StatusCode::NOT_FOUND,
            json!({"error": "not found"}),
        )),
    }
}

fn authorized(request: &Request<Incoming>, state: &AppState) -> bool {
    match state.config.admin.token.as_deref() {
        None => true,
        Some(token) => request
            .headers()
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(|value| {
                value
                    .strip_prefix("Bearer ")
                    .map(|provided| provided == token)
                    .unwrap_or(false)
            })
            .unwrap_or(false),
    }
}

fn json_response(status: StatusCode, value: serde_json::Value) -> Response<ProxyBody> {
    let body = serde_json::to_vec(&value).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(full_body(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(full_body("{}")))
}
