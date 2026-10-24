use std::time::Duration;

use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use http_body_util::{BodyExt, BodyStream, StreamBody};
use hyper::body::Incoming;

use crate::proxy::ProxyBody;

#[derive(Debug)]
pub enum BodyError {
    TooLarge { prefix: Bytes, rest: Incoming },
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
        loop {
            let frame = match body.frame().await {
                Some(frame) => frame.map_err(BodyError::Hyper)?,
                None => break,
            };
            if let Ok(data) = frame.into_data() {
                if buffer.len() + data.len() > limit {
                    buffer.extend_from_slice(&data);
                    return Err(BodyError::TooLarge {
                        prefix: buffer.freeze(),
                        rest: body,
                    });
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

pub fn prefix_body(prefix: Bytes, rest: Incoming) -> ProxyBody {
    let first = futures_util::stream::once(async move {
        Ok::<_, hyper::Error>(hyper::body::Frame::data(prefix))
    });
    let stream = first.chain(BodyStream::new(rest));
    BodyExt::boxed(StreamBody::new(stream))
}
