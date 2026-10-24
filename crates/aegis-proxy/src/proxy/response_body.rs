use std::io::Read;

use bytes::Bytes;
use hyper::header::{CONTENT_ENCODING, CONTENT_TYPE};
use hyper::HeaderMap;

pub enum DecodedBody {
    Decoded(Bytes),
    TooLarge,
    Unsupported,
}

pub fn is_event_stream(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .trim_start()
                .to_ascii_lowercase()
                .starts_with("text/event-stream")
        })
        .unwrap_or(false)
}

pub fn decode_body(body: &Bytes, headers: &HeaderMap, limit: usize) -> DecodedBody {
    let mut encodings = Vec::new();
    for value in headers.get_all(CONTENT_ENCODING).iter() {
        let Ok(value) = value.to_str() else {
            return DecodedBody::Unsupported;
        };
        for part in value.split(',') {
            let part = part.trim();
            if !part.is_empty() {
                encodings.push(part.to_ascii_lowercase());
            }
        }
    }
    if encodings.is_empty()
        || encodings
            .iter()
            .all(|encoding| encoding.as_str() == "identity")
    {
        return DecodedBody::Decoded(body.clone());
    }

    let mut current = body.clone();
    for encoding in encodings.iter().rev() {
        match decode_one(&current, encoding, limit) {
            Ok(next) => current = next,
            Err(DecodeError::TooLarge) => return DecodedBody::TooLarge,
            Err(DecodeError::Unsupported) | Err(DecodeError::Malformed) => {
                return DecodedBody::Unsupported;
            }
        }
    }
    DecodedBody::Decoded(current)
}

enum DecodeError {
    TooLarge,
    Unsupported,
    Malformed,
}

fn decode_one(body: &Bytes, encoding: &str, limit: usize) -> Result<Bytes, DecodeError> {
    let reader: Box<dyn Read> = match encoding {
        "gzip" | "x-gzip" => Box::new(flate2::read::MultiGzDecoder::new(body.as_ref())),
        "deflate" => Box::new(flate2::read::ZlibDecoder::new(body.as_ref())),
        "br" => Box::new(brotli::Decompressor::new(body.as_ref(), 4096)),
        _ => return Err(DecodeError::Unsupported),
    };
    let mut output = Vec::new();
    let mut limited = reader.take(limit as u64 + 1);
    limited
        .read_to_end(&mut output)
        .map_err(|_| DecodeError::Malformed)?;
    if output.len() > limit {
        Err(DecodeError::TooLarge)
    } else {
        Ok(Bytes::from(output))
    }
}
