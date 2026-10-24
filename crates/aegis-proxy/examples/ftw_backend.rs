use std::collections::HashMap;
use std::convert::Infallible;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{HeaderName, HeaderValue, CONTENT_TYPE};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use tokio::net::TcpListener;

type Body = BoxBody<Bytes, Infallible>;

#[derive(Debug, Deserialize)]
struct Reflect {
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    headers: HashMap<String, String>,
}

fn full(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into())
        .map_err(|error: Infallible| match error {})
        .boxed()
}

fn text(status: StatusCode, message: &'static str) -> Response<Body> {
    let mut response = Response::new(full(message));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

async fn handle(request: Request<Incoming>) -> Result<Response<Body>, Infallible> {
    let path = request.uri().path().to_string();
    if let Some(code) = path
        .strip_prefix("/status/")
        .and_then(|value| value.parse::<u16>().ok())
    {
        let status = StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_REQUEST);
        return Ok(text(status, ""));
    }
    if path == "/reflect" {
        let Ok(collected) = request.into_body().collect().await else {
            return Ok(text(StatusCode::BAD_REQUEST, "invalid body"));
        };
        let bytes = collected.to_bytes();
        let Ok(reflect) = serde_json::from_slice::<Reflect>(&bytes) else {
            return Ok(text(StatusCode::BAD_REQUEST, "invalid json"));
        };
        let status = reflect
            .status
            .and_then(|code| StatusCode::from_u16(code).ok())
            .unwrap_or(StatusCode::OK);
        let mut response = Response::new(full(reflect.body.unwrap_or_default()));
        *response.status_mut() = status;
        for (name, value) in reflect.headers {
            let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
                continue;
            };
            let Ok(value) = HeaderValue::from_str(&value) else {
                continue;
            };
            response.headers_mut().insert(name, value);
        }
        return Ok(response);
    }
    Ok(Response::new(full(Bytes::new())))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let port = std::env::var("FTW_BACKEND_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(18081);
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!("ftw backend listening on 127.0.0.1:{port}");
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(handle);
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });
    }
}
