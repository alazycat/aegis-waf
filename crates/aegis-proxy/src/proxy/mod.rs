use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::CONTENT_LENGTH;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Version};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tracing::{debug, warn};

use aegis_engine::{
    evaluate_phase, CompiledRules, Decision, Evaluation, EvaluationState, Phase, RequestView,
};
use uuid::Uuid;

use crate::audit_sink;
use crate::state::AppState;

pub mod forward;
pub mod limits;

pub type ProxyBody = BoxBody<Bytes, hyper::Error>;

pub fn full_body(bytes: impl Into<Bytes>) -> ProxyBody {
    Full::new(bytes.into())
        .map_err(|error: Infallible| match error {})
        .boxed()
}

pub fn text_response(status: StatusCode, message: &'static str) -> Response<ProxyBody> {
    match Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(full_body(message))
    {
        Ok(response) => response,
        Err(_) => {
            let mut response = Response::new(full_body("internal error\n"));
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            response
        }
    }
}

fn header_bytes(headers: &hyper::HeaderMap) -> usize {
    headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len() + 4)
        .sum()
}

fn content_length(headers: &hyper::HeaderMap) -> Option<u64> {
    headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
}

fn blocked_status(status: u16) -> StatusCode {
    StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN)
}

pub async fn serve_on(listener: TcpListener, state: Arc<AppState>) -> anyhow::Result<()> {
    let (shutdown_sender, shutdown_receiver) = tokio::sync::watch::channel(false);
    let result = serve_on_with_shutdown(listener, state, shutdown_receiver).await;
    drop(shutdown_sender);
    result
}

pub async fn serve_on_with_shutdown(
    listener: TcpListener,
    state: Arc<AppState>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                let header_timeout =
                    Duration::from_millis(state.config.limits.header_read_timeout_ms);
                let state = state.clone();
                connections.spawn(async move {
                    let io = TokioIo::new(stream);
                    let service = service_fn(move |request| handle(request, state.clone(), peer));
                    let mut builder = hyper::server::conn::http1::Builder::new();
                    builder.timer(TokioTimer::new());
                    builder.header_read_timeout(header_timeout);
                    if let Err(error) = builder.serve_connection(io, service).await {
                        debug!(%peer, %error, "connection closed");
                    }
                });
            }
        }
    }
    let drain = async { while connections.join_next().await.is_some() {} };
    let _ = tokio::time::timeout(Duration::from_secs(10), drain).await;
    connections.abort_all();
    Ok(())
}

struct Outcome {
    response: Response<ProxyBody>,
    status: StatusCode,
    upstream_status: Option<u16>,
    upstream_latency_ms: Option<u64>,
    error: Option<String>,
    request_body_bytes: usize,
}

fn local(status: StatusCode, message: &'static str) -> Outcome {
    Outcome {
        response: text_response(status, message),
        status,
        upstream_status: None,
        upstream_latency_ms: None,
        error: None,
        request_body_bytes: 0,
    }
}

fn blocked(status: u16, body_bytes: usize) -> Outcome {
    let status = blocked_status(status);
    Outcome {
        response: text_response(status, "request blocked\n"),
        status,
        upstream_status: None,
        upstream_latency_ms: None,
        error: None,
        request_body_bytes: body_bytes,
    }
}

fn estimate_request_bytes(parts: &http::request::Parts) -> u64 {
    let headers: usize = parts
        .headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len() + 4)
        .sum();
    (parts.method.as_str().len() + parts.uri.to_string().len() + 12 + headers) as u64
}

async fn process(
    state: &AppState,
    rules: &CompiledRules,
    parts: &http::request::Parts,
    incoming: Incoming,
    peer: SocketAddr,
    evaluation: &mut EvaluationState,
) -> Outcome {
    let uri_len = parts
        .uri
        .path_and_query()
        .map(|value| value.as_str().len())
        .unwrap_or(0);
    if uri_len > state.config.limits.max_uri_bytes {
        return local(StatusCode::URI_TOO_LONG, "URI too long\n");
    }
    if header_bytes(&parts.headers) > state.config.limits.max_header_bytes {
        return local(
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            "request headers too large\n",
        );
    }

    evaluate_phase(evaluation, rules, Phase::Phase1);
    if let Decision::Block { status, .. } = evaluation.decision() {
        return blocked(*status, 0);
    }
    let skip_phase_two = matches!(evaluation.decision(), Decision::Allow { .. });

    if let Some(length) = content_length(&parts.headers) {
        if length > state.config.limits.max_body_bytes as u64 {
            return local(StatusCode::PAYLOAD_TOO_LARGE, "request body too large\n");
        }
    }

    let body = match limits::read_body_limited(
        incoming,
        state.config.limits.max_body_bytes,
        Duration::from_millis(state.config.limits.body_read_timeout_ms),
    )
    .await
    {
        Ok(body) => body,
        Err(limits::BodyError::TooLarge) => {
            return local(StatusCode::PAYLOAD_TOO_LARGE, "request body too large\n");
        }
        Err(limits::BodyError::Timeout) => {
            return local(StatusCode::REQUEST_TIMEOUT, "request body read timeout\n");
        }
        Err(limits::BodyError::Hyper(error)) => {
            warn!(%peer, %error, "failed to read request body");
            return local(StatusCode::BAD_REQUEST, "invalid request body\n");
        }
    };
    let body_len = body.len();

    if !skip_phase_two {
        evaluation.set_body(&body);
        evaluate_phase(evaluation, rules, Phase::Phase2);
        if let Decision::Block { status, .. } = evaluation.decision() {
            return blocked(*status, body_len);
        }
    }

    let upstream_started = Instant::now();
    let (response_parts, response_body) =
        match forward::forward(state, parts, body, peer.ip()).await {
            Ok(pair) => pair,
            Err(forward::ForwardError::Timeout) => {
                return Outcome {
                    response: text_response(StatusCode::GATEWAY_TIMEOUT, "upstream timeout\n"),
                    status: StatusCode::GATEWAY_TIMEOUT,
                    upstream_status: None,
                    upstream_latency_ms: Some(upstream_started.elapsed().as_millis() as u64),
                    error: Some("upstream_timeout".to_string()),
                    request_body_bytes: body_len,
                };
            }
            Err(forward::ForwardError::Upstream(message)) => {
                warn!(%peer, %message, "upstream request failed");
                return Outcome {
                    response: text_response(StatusCode::BAD_GATEWAY, "upstream error\n"),
                    status: StatusCode::BAD_GATEWAY,
                    upstream_status: None,
                    upstream_latency_ms: Some(upstream_started.elapsed().as_millis() as u64),
                    error: Some(format!("upstream_error: {message}")),
                    request_body_bytes: body_len,
                };
            }
        };

    let upstream_status = response_parts.status.as_u16();
    let upstream_latency = Some(upstream_started.elapsed().as_millis() as u64);

    let inspect_response = !rules.phase3.is_empty() || !rules.phase4.is_empty();
    if inspect_response {
        evaluation.set_response_headers(upstream_status, &response_parts.headers);
        evaluate_phase(evaluation, rules, Phase::Phase3);
        if let Decision::Block { status, .. } = evaluation.decision() {
            return blocked_with_upstream(
                *status,
                body_len,
                Some(upstream_status),
                upstream_latency,
            );
        }
    }

    let inspect_body = !rules.phase4.is_empty()
        && content_length(&response_parts.headers)
            .map(|length| length <= state.config.limits.max_response_body_bytes as u64)
            .unwrap_or(false);

    if inspect_body {
        let response_body = match limits::read_body_limited(
            response_body,
            state.config.limits.max_response_body_bytes,
            Duration::from_millis(state.config.limits.body_read_timeout_ms),
        )
        .await
        {
            Ok(body) => body,
            Err(limits::BodyError::TooLarge) => {
                return local_after_upstream(
                    StatusCode::BAD_GATEWAY,
                    "upstream body too large\n",
                    body_len,
                    upstream_status,
                    upstream_latency,
                    "upstream_body_too_large",
                );
            }
            Err(limits::BodyError::Timeout) => {
                return local_after_upstream(
                    StatusCode::GATEWAY_TIMEOUT,
                    "upstream body timeout\n",
                    body_len,
                    upstream_status,
                    upstream_latency,
                    "upstream_body_timeout",
                );
            }
            Err(limits::BodyError::Hyper(error)) => {
                warn!(%peer, %error, "failed to read upstream body");
                return local_after_upstream(
                    StatusCode::BAD_GATEWAY,
                    "upstream body error\n",
                    body_len,
                    upstream_status,
                    upstream_latency,
                    "upstream_body_error",
                );
            }
        };
        evaluation.set_response_body(&response_body);
        evaluate_phase(evaluation, rules, Phase::Phase4);
        if let Decision::Block { status, .. } = evaluation.decision() {
            return blocked_with_upstream(
                *status,
                body_len,
                Some(upstream_status),
                upstream_latency,
            );
        }
        if !rules.phase5.is_empty() {
            evaluate_phase(evaluation, rules, Phase::Phase5);
        }
        let downstream_status = response_parts.status;
        Outcome {
            response: build_response(response_parts, full_body(response_body)),
            status: downstream_status,
            upstream_status: Some(upstream_status),
            upstream_latency_ms: upstream_latency,
            error: None,
            request_body_bytes: body_len,
        }
    } else {
        if !rules.phase5.is_empty() {
            evaluate_phase(evaluation, rules, Phase::Phase5);
        }
        let downstream_status = response_parts.status;
        Outcome {
            response: build_response(response_parts, response_body.boxed()),
            status: downstream_status,
            upstream_status: Some(upstream_status),
            upstream_latency_ms: upstream_latency,
            error: None,
            request_body_bytes: body_len,
        }
    }
}

fn blocked_with_upstream(
    status: u16,
    request_body_bytes: usize,
    upstream_status: Option<u16>,
    upstream_latency_ms: Option<u64>,
) -> Outcome {
    let status = blocked_status(status);
    Outcome {
        response: text_response(status, "response blocked\n"),
        status,
        upstream_status,
        upstream_latency_ms,
        error: None,
        request_body_bytes,
    }
}

fn local_after_upstream(
    status: StatusCode,
    message: &'static str,
    request_body_bytes: usize,
    upstream_status: u16,
    upstream_latency_ms: Option<u64>,
    error: &str,
) -> Outcome {
    Outcome {
        response: text_response(status, message),
        status,
        upstream_status: Some(upstream_status),
        upstream_latency_ms,
        error: Some(error.to_string()),
        request_body_bytes,
    }
}

fn build_response(parts: http::response::Parts, body: ProxyBody) -> Response<ProxyBody> {
    let status = parts.status;
    let mut response = Response::builder()
        .status(status)
        .version(Version::HTTP_11)
        .body(body)
        .unwrap_or_else(|_| text_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error\n"));
    *response.headers_mut() = parts.headers;
    response
}

#[allow(clippy::too_many_arguments)]
fn emit_audit(
    state: &AppState,
    request_id: &str,
    peer: SocketAddr,
    started: Instant,
    method: &str,
    path: &str,
    query: Option<&str>,
    request_bytes: u64,
    rules_version: u64,
    evaluation: &Evaluation,
    outcome: &Outcome,
) {
    if evaluation.suppress_audit {
        return;
    }
    if !audit_sink::should_write(
        state.config.audit.mode,
        &evaluation.decision,
        &evaluation.matched,
        outcome.status.as_u16(),
        outcome.upstream_status,
        outcome.error.as_deref(),
    ) {
        return;
    }
    let event = audit_sink::build_event(audit_sink::EventInput {
        request_id,
        client_ip: peer.ip(),
        method,
        path,
        query,
        decision: &evaluation.decision,
        matched: &evaluation.matched,
        status: outcome.status.as_u16(),
        upstream_status: outcome.upstream_status,
        upstream_latency_ms: outcome.upstream_latency_ms,
        error: outcome.error.clone(),
        latency_ms: started.elapsed().as_millis() as u64,
        request_bytes,
        rules_version,
        include_query: state.config.audit.include_query,
        matched_limit: state.config.audit.matched_rules_limit,
    });
    state.audit.try_send(event);
}

async fn handle(
    request: Request<Incoming>,
    state: Arc<AppState>,
    peer: SocketAddr,
) -> Result<Response<ProxyBody>, Infallible> {
    let started = Instant::now();
    let request_id = Uuid::new_v4().to_string();
    let (parts, incoming) = request.into_parts();
    let method = parts.method.as_str().to_string();
    let path = parts.uri.path().to_string();
    let query = parts.uri.query().map(str::to_string);
    let uri_string = parts
        .uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/")
        .to_string();
    let rules = state.rules.snapshot();
    let rules_version = rules.version;
    let protocol = match parts.version {
        hyper::Version::HTTP_10 => "HTTP/1.0",
        _ => "HTTP/1.1",
    };

    let mut evaluation = {
        let view = RequestView {
            method: &method,
            uri: &uri_string,
            path: &path,
            query: query.as_deref(),
            protocol,
            headers: &parts.headers,
            body: &[],
            remote_addr: peer.ip(),
        };
        EvaluationState::new_with_store(&view, state.collections.clone())
    };

    let outcome = process(&state, &rules, &parts, incoming, peer, &mut evaluation).await;
    let request_bytes = estimate_request_bytes(&parts) + outcome.request_body_bytes as u64;
    let evaluation = evaluation.finish(started);
    emit_audit(
        &state,
        &request_id,
        peer,
        started,
        &method,
        &path,
        query.as_deref(),
        request_bytes,
        rules_version,
        &evaluation,
        &outcome,
    );
    Ok(outcome.response)
}
