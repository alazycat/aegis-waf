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

struct Harness {
    proxy: SocketAddr,
    hits: Arc<AtomicUsize>,
    _dir: tempfile::TempDir,
    handle: tokio::task::JoinHandle<()>,
}

async fn harness(
    rules: &str,
    upstream_status: StatusCode,
    upstream_body: &'static [u8],
    max_response_body_bytes: usize,
) -> Harness {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_for_server = hits.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let hits = hits_for_server.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let service = service_fn(move |_request: Request<Incoming>| {
                    let hits = hits.clone();
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(upstream_status)
                                .header("content-type", "text/plain")
                                .body(Full::new(Bytes::from_static(upstream_body)))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
            });
        }
    });

    let dir = tempfile::tempdir().unwrap();
    let rules_path = dir.path().join("rules.conf");
    std::fs::write(&rules_path, rules).unwrap();
    let config = aegis_proxy::Config {
        listen: "127.0.0.1:0".to_string(),
        upstream: aegis_proxy::config::UpstreamConfig {
            url: format!("http://{upstream_addr}"),
            host_header: aegis_proxy::config::HostHeader::Preserve,
            connect_timeout_ms: 3000,
            total_timeout_ms: 30000,
        },
        admin: aegis_proxy::config::AdminConfig {
            listen: "127.0.0.1:0".to_string(),
            token: None,
        },
        rules: aegis_proxy::config::RulesConfig {
            files: vec![rules_path.display().to_string()],
            lenient: false,
        },
        limits: aegis_proxy::config::LimitsConfig {
            max_header_bytes: 65536,
            max_uri_bytes: 8192,
            max_body_bytes: 1024,
            max_response_body_bytes,
            header_read_timeout_ms: 10000,
            body_read_timeout_ms: 15000,
        },
        on_error: aegis_proxy::config::OnError::Block,
        audit: aegis_proxy::config::AuditConfig {
            sink: aegis_proxy::config::AuditSink::None,
            path: None,
            mode: aegis_proxy::config::AuditMode::BlockedOnly,
            queue_capacity: 1024,
            include_query: false,
            matched_rules_limit: 16,
        },
    };
    let rules =
        Arc::new(aegis_proxy::rules::RulesManager::load_initial(&[rules_path], false).unwrap());
    let (audit, _audit_receiver) = aegis_proxy::audit_sink::AuditHandle::channel(64);
    let state = Arc::new(aegis_proxy::state::AppState::new(config, rules, audit).unwrap());
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = proxy_listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = aegis_proxy::proxy::serve_on(proxy_listener, state).await;
    });
    Harness {
        proxy,
        hits,
        _dir: dir,
        handle,
    }
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

fn get(uri: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .uri(uri)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

#[tokio::test]
async fn phase_three_blocks_response_by_status() {
    let harness = harness(
        r#"SecRule RESPONSE_STATUS "@eq 200" "id:1,phase:3,deny,status:451""#,
        StatusCode::OK,
        b"upstream body",
        1048576,
    )
    .await;
    let (status, _) = send(harness.proxy, get("http://example.test/")).await;
    assert_eq!(status, StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
    assert_eq!(harness.hits.load(Ordering::SeqCst), 1);
    harness.handle.abort();
}

#[tokio::test]
async fn phase_four_blocks_response_body() {
    let harness = harness(
        r#"SecRule RESPONSE_BODY "@contains secret" "id:2,phase:4,deny,status:403""#,
        StatusCode::OK,
        b"a secret response",
        1048576,
    )
    .await;
    let (status, _) = send(harness.proxy, get("http://example.test/")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(harness.hits.load(Ordering::SeqCst), 1);
    harness.handle.abort();
}

#[tokio::test]
async fn phase_four_allows_safe_response() {
    let harness = harness(
        r#"SecRule RESPONSE_BODY "@contains missing" "id:2,phase:4,deny,status:403""#,
        StatusCode::OK,
        b"safe response",
        1048576,
    )
    .await;
    let (status, body) = send(harness.proxy, get("http://example.test/")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "safe response");
    assert_eq!(harness.hits.load(Ordering::SeqCst), 1);
    harness.handle.abort();
}

#[tokio::test]
async fn phase_four_is_skipped_when_response_exceeds_limit() {
    let harness = harness(
        r#"SecRule RESPONSE_BODY "@contains 789" "id:2,phase:4,deny,status:403""#,
        StatusCode::OK,
        b"0123456789",
        4,
    )
    .await;
    let (status, body) = send(harness.proxy, get("http://example.test/")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "0123456789");
    assert_eq!(harness.hits.load(Ordering::SeqCst), 1);
    harness.handle.abort();
}
