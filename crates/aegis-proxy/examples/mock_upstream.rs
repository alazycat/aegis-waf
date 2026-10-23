use std::convert::Infallible;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:13000".to_string());
    let listener = TcpListener::bind(&addr).await?;
    println!("mock upstream listening on {}", listener.local_addr()?);

    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(|_request: Request<Incoming>| async {
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });
    }
}
