use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{HeaderValue, HOST};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;

struct Upstream {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
}

async fn start_upstream() -> Upstream {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_for_server = hits.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let hits = hits_for_server.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let service = service_fn(move |req: Request<Incoming>| {
                    let hits = hits.clone();
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        let method = req.method().to_string();
                        let path = req.uri().path().to_string();
                        let body = req.into_body().collect().await.unwrap().to_bytes();
                        let text = format!(
                            "method={method}\npath={path}\nbody={}",
                            String::from_utf8_lossy(&body)
                        );
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(text))))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
            });
        }
    });
    Upstream { addr, hits }
}

async fn start_proxy(upstream: SocketAddr) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("rules.conf"), "").unwrap();
    let config = aegis_proxy::Config {
        listen: "127.0.0.1:0".to_string(),
        upstream: aegis_proxy::config::UpstreamConfig {
            url: format!("http://{upstream}"),
            host_header: aegis_proxy::config::HostHeader::Preserve,
            connect_timeout_ms: 3000,
            total_timeout_ms: 30000,
        },
        admin: aegis_proxy::config::AdminConfig {
            listen: "127.0.0.1:0".to_string(),
            token: None,
        },
        rules: aegis_proxy::config::RulesConfig {
            files: vec![dir.path().join("rules.conf").display().to_string()],
            lenient: false,
        },
        limits: aegis_proxy::config::LimitsConfig {
            max_header_bytes: 65536,
            max_uri_bytes: 8192,
            max_body_bytes: 1024,
            header_read_timeout_ms: 10000,
            body_read_timeout_ms: 15000,
        },
        on_error: aegis_proxy::config::OnError::Block,
        audit: aegis_proxy::config::AuditConfig {
            sink: aegis_proxy::config::AuditSink::None,
            path: None,
            mode: aegis_proxy::config::AuditMode::BlockedOnly,
            queue_capacity: 8192,
            include_query: false,
            matched_rules_limit: 16,
        },
    };
    let rules = Arc::new(
        aegis_proxy::rules::RulesManager::load_initial(&[dir.path().join("rules.conf")], false)
            .unwrap(),
    );
    let (audit, _audit_receiver) = aegis_proxy::audit_sink::AuditHandle::channel(64);
    let state = Arc::new(aegis_proxy::state::AppState::new(config, rules, audit).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = aegis_proxy::proxy::serve_on(listener, state).await;
    });
    std::mem::forget(dir);
    (addr, handle)
}

async fn send(addr: SocketAddr, request: Request<Full<Bytes>>) -> (StatusCode, String) {
    let (mut parts, body) = request.into_parts();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/")
        .to_string();
    let host = parts
        .uri
        .authority()
        .map(|authority| authority.to_string())
        .unwrap_or_else(|| "example.test".to_string());
    if !parts.headers.contains_key(HOST) {
        parts
            .headers
            .insert(HOST, HeaderValue::from_bytes(host.as_bytes()).unwrap());
    }
    parts.uri = format!("http://{addr}{path_and_query}").parse().unwrap();
    let request = Request::from_parts(parts, body);

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build_http();
    let response = client.request(request).await.unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn forwards_get_request() {
    let upstream = start_upstream().await;
    let (addr, handle) = start_proxy(upstream.addr).await;
    let request = Request::builder()
        .uri("http://example.test/hello?x=1")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (status, body) = send(addr, request).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("method=GET"));
    assert!(body.contains("path=/hello"));
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 1);
    handle.abort();
}

#[tokio::test]
async fn forwards_post_body() {
    let upstream = start_upstream().await;
    let (addr, handle) = start_proxy(upstream.addr).await;
    let request = Request::builder()
        .method("POST")
        .uri("http://example.test/submit")
        .body(Full::new(Bytes::from_static(b"payload")))
        .unwrap();
    let (status, body) = send(addr, request).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("body=payload"));
    handle.abort();
}

#[tokio::test]
async fn rejects_body_over_limit_without_calling_upstream() {
    let upstream = start_upstream().await;
    let (addr, handle) = start_proxy(upstream.addr).await;
    let request = Request::builder()
        .method("POST")
        .uri("http://example.test/upload")
        .body(Full::new(Bytes::from(vec![b'a'; 2048])))
        .unwrap();
    let (status, _) = send(addr, request).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 0);
    handle.abort();
}

#[tokio::test]
async fn rejects_uri_over_limit() {
    let upstream = start_upstream().await;
    let (addr, handle) = start_proxy(upstream.addr).await;
    let long_path = format!("/{}", "a".repeat(9000));
    let request = Request::builder()
        .uri(format!("http://example.test{long_path}"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (status, _) = send(addr, request).await;
    assert_eq!(status, StatusCode::URI_TOO_LONG);
    handle.abort();
}
