use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::AUTHORIZATION;
use hyper::Request;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tokio::net::TcpListener;

struct AdminHarness {
    addr: SocketAddr,
    rules_path: PathBuf,
    _dir: tempfile::TempDir,
    handle: tokio::task::JoinHandle<()>,
}

async fn start_admin(token: Option<&str>) -> AdminHarness {
    let dir = tempfile::tempdir().unwrap();
    let rules_path = dir.path().join("rules.conf");
    std::fs::write(&rules_path, r#"SecRule ARGS "@rx a" "id:1,phase:1,pass""#).unwrap();
    let config = aegis_proxy::Config {
        listen: "127.0.0.1:0".to_string(),
        upstream: aegis_proxy::config::UpstreamConfig {
            url: "http://127.0.0.1:3000".to_string(),
            host_header: aegis_proxy::config::HostHeader::Preserve,
            connect_timeout_ms: 3000,
            total_timeout_ms: 30000,
        },
        admin: aegis_proxy::config::AdminConfig {
            listen: "127.0.0.1:0".to_string(),
            token: token.map(str::to_string),
        },
        rules: aegis_proxy::config::RulesConfig {
            files: vec![rules_path.display().to_string()],
            lenient: false,
        },
        limits: aegis_proxy::config::LimitsConfig {
            max_header_bytes: 65536,
            max_uri_bytes: 8192,
            max_body_bytes: 1048576,
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
    let rules = Arc::new(
        aegis_proxy::rules::RulesManager::load_initial(std::slice::from_ref(&rules_path), false)
            .unwrap(),
    );
    let (audit, _audit_receiver) = aegis_proxy::audit_sink::AuditHandle::channel(16);
    let state = Arc::new(aegis_proxy::state::AppState::new(config, rules, audit).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = aegis_proxy::admin::serve_on(listener, state).await;
    });
    AdminHarness {
        addr,
        rules_path,
        _dir: dir,
        handle,
    }
}

async fn request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    token: Option<&str>,
) -> (hyper::StatusCode, String) {
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build_http();
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://{addr}{path}"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    if let Some(token) = token {
        builder
            .headers_mut()
            .insert(AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
    }
    let response = client.request(builder).await.unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn health_and_status_endpoints_work() {
    let harness = start_admin(None).await;
    let (status, body) = request(harness.addr, "GET", "/healthz", None).await;
    assert_eq!(status, hyper::StatusCode::OK);
    assert!(body.contains("\"status\":\"ok\""));

    let (status, body) = request(harness.addr, "GET", "/rules", None).await;
    assert_eq!(status, hyper::StatusCode::OK);
    assert!(body.contains("\"version\":1"));
    assert!(body.contains("\"count\":1"));
    harness.handle.abort();
}

#[tokio::test]
async fn reload_endpoint_swaps_rules_and_reports_errors() {
    let harness = start_admin(None).await;
    std::fs::write(
        &harness.rules_path,
        r#"
SecRule ARGS "@rx a" "id:1,phase:1,pass"
SecRule ARGS "@rx b" "id:2,phase:1,pass"
"#,
    )
    .unwrap();
    let (status, body) = request(harness.addr, "POST", "/rules/reload", None).await;
    assert_eq!(status, hyper::StatusCode::OK);
    assert!(body.contains("\"rules_version\":2"));
    assert!(body.contains("\"count\":2"));

    std::fs::write(
        &harness.rules_path,
        "SecRule ARGS \"@rx (\" \"id:3,deny\"\n",
    )
    .unwrap();
    let (status, body) = request(harness.addr, "POST", "/rules/reload", None).await;
    assert_eq!(status, hyper::StatusCode::BAD_REQUEST);
    assert!(body.contains("invalid regex"));

    let (_, body) = request(harness.addr, "GET", "/rules", None).await;
    assert!(body.contains("\"version\":2"));
    assert!(body.contains("\"count\":2"));
    harness.handle.abort();
}

#[tokio::test]
async fn token_is_required_when_configured() {
    let harness = start_admin(Some("secret")).await;
    let (status, _) = request(harness.addr, "GET", "/healthz", None).await;
    assert_eq!(status, hyper::StatusCode::UNAUTHORIZED);
    let (status, _) = request(harness.addr, "GET", "/healthz", Some("secret")).await;
    assert_eq!(status, hyper::StatusCode::OK);
    let (status, _) = request(harness.addr, "GET", "/healthz", Some("wrong")).await;
    assert_eq!(status, hyper::StatusCode::UNAUTHORIZED);
    harness.handle.abort();
}
