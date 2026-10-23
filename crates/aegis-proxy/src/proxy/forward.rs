use std::net::IpAddr;

use bytes::Bytes;
use http::request::Parts;
use http::{HeaderName, HeaderValue, Uri, Version};
use http_body_util::{BodyExt, Full};
use hyper::header::HOST;
use hyper::{Request, Response};

use crate::config::HostHeader;
use crate::proxy::ProxyBody;
use crate::state::AppState;

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

#[derive(Debug)]
pub enum ForwardError {
    Timeout,
    Upstream(String),
}

pub async fn forward(
    state: &AppState,
    parts: &Parts,
    body: Bytes,
    peer_ip: IpAddr,
) -> Result<Response<ProxyBody>, ForwardError> {
    let base: Uri = state
        .config
        .upstream
        .url
        .parse()
        .map_err(|error: http::uri::InvalidUri| ForwardError::Upstream(error.to_string()))?;
    let authority = base
        .authority()
        .ok_or_else(|| ForwardError::Upstream("upstream URL has no authority".to_string()))?
        .clone();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let uri: Uri = format!(
        "{}://{}{}",
        base.scheme_str().unwrap_or("http"),
        authority.as_str(),
        path_and_query
    )
    .parse()
    .map_err(|error: http::uri::InvalidUri| ForwardError::Upstream(error.to_string()))?;

    let mut headers = parts.headers.clone();
    for name in HOP_BY_HOP {
        headers.remove(*name);
    }
    if state.config.upstream.host_header == HostHeader::Rewrite {
        headers.insert(
            HOST,
            HeaderValue::from_str(authority.as_str())
                .map_err(|error| ForwardError::Upstream(error.to_string()))?,
        );
    }
    let forwarded_for = match headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
    {
        Some(existing) => format!("{existing}, {peer_ip}"),
        None => peer_ip.to_string(),
    };
    headers.insert(
        HeaderName::from_static("x-forwarded-for"),
        HeaderValue::from_str(&forwarded_for)
            .map_err(|error| ForwardError::Upstream(error.to_string()))?,
    );
    headers.insert(
        HeaderName::from_static("x-forwarded-proto"),
        HeaderValue::from_static("http"),
    );
    if let Some(host) = parts.headers.get(HOST) {
        headers.insert(HeaderName::from_static("x-forwarded-host"), host.clone());
    }

    let mut request = Request::builder()
        .method(parts.method.clone())
        .uri(uri)
        .version(Version::HTTP_11)
        .body(Full::new(body))
        .map_err(|error| ForwardError::Upstream(error.to_string()))?;
    *request.headers_mut() = headers;

    let timeout = std::time::Duration::from_millis(state.config.upstream.total_timeout_ms);
    let response = match tokio::time::timeout(timeout, state.client.request(request)).await {
        Err(_) => return Err(ForwardError::Timeout),
        Ok(Err(error)) => return Err(ForwardError::Upstream(error.to_string())),
        Ok(Ok(response)) => response,
    };

    let (mut response_parts, response_body) = response.into_parts();
    for name in HOP_BY_HOP {
        response_parts.headers.remove(*name);
    }
    let mut response = Response::builder()
        .status(response_parts.status)
        .version(Version::HTTP_11)
        .body(response_body.boxed())
        .map_err(|error| ForwardError::Upstream(error.to_string()))?;
    *response.headers_mut() = response_parts.headers;
    Ok(response)
}
