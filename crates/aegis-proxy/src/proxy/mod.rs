use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::CONTENT_LENGTH;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tracing::{debug, warn};

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

pub async fn serve_on(listener: TcpListener, state: Arc<AppState>) -> anyhow::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let header_timeout = Duration::from_millis(state.config.limits.header_read_timeout_ms);
        let state = state.clone();
        tokio::spawn(async move {
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

async fn handle(
    request: Request<Incoming>,
    state: Arc<AppState>,
    peer: SocketAddr,
) -> Result<Response<ProxyBody>, Infallible> {
    let (parts, incoming) = request.into_parts();

    let uri_len = parts
        .uri
        .path_and_query()
        .map(|value| value.as_str().len())
        .unwrap_or(0);
    if uri_len > state.config.limits.max_uri_bytes {
        return Ok(text_response(StatusCode::URI_TOO_LONG, "URI too long\n"));
    }
    if header_bytes(&parts.headers) > state.config.limits.max_header_bytes {
        return Ok(text_response(
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            "request headers too large\n",
        ));
    }
    if let Some(length) = content_length(&parts.headers) {
        if length > state.config.limits.max_body_bytes as u64 {
            return Ok(text_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body too large\n",
            ));
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
            return Ok(text_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body too large\n",
            ));
        }
        Err(limits::BodyError::Timeout) => {
            return Ok(text_response(
                StatusCode::REQUEST_TIMEOUT,
                "request body read timeout\n",
            ));
        }
        Err(limits::BodyError::Hyper(error)) => {
            warn!(%peer, %error, "failed to read request body");
            return Ok(text_response(
                StatusCode::BAD_REQUEST,
                "invalid request body\n",
            ));
        }
    };

    match forward::forward(&state, &parts, body, peer.ip()).await {
        Ok(response) => Ok(response),
        Err(forward::ForwardError::Timeout) => Ok(text_response(
            StatusCode::GATEWAY_TIMEOUT,
            "upstream timeout\n",
        )),
        Err(forward::ForwardError::Upstream(error)) => {
            warn!(%peer, %error, "upstream request failed");
            Ok(text_response(StatusCode::BAD_GATEWAY, "upstream error\n"))
        }
    }
}
