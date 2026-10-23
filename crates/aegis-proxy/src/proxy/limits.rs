use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http_body_util::BodyExt;
use hyper::body::Incoming;

#[derive(Debug)]
pub enum BodyError {
    TooLarge,
    Timeout,
    Hyper(hyper::Error),
}

pub async fn read_body_limited(
    mut body: Incoming,
    limit: usize,
    timeout: Duration,
) -> Result<Bytes, BodyError> {
    let read = async {
        let mut buffer = BytesMut::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(BodyError::Hyper)?;
            if let Ok(data) = frame.into_data() {
                if buffer.len() + data.len() > limit {
                    return Err(BodyError::TooLarge);
                }
                buffer.extend_from_slice(&data);
            }
        }
        Ok(buffer.freeze())
    };
    match tokio::time::timeout(timeout, read).await {
        Ok(result) => result,
        Err(_) => Err(BodyError::Timeout),
    }
}
