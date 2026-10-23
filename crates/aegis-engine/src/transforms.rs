use std::borrow::Cow;

use base64::Engine as _;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transform {
    Lowercase,
    UrlDecode,
    UrlDecodeUni,
    HtmlEntityDecode,
    Trim,
    TrimLeft,
    TrimRight,
    CompressWhitespace,
    RemoveNulls,
    NormalizePath,
    Base64Decode,
}

impl Transform {
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "lowercase" => Some(Self::Lowercase),
            "urldecode" => Some(Self::UrlDecode),
            "urldecodeuni" => Some(Self::UrlDecodeUni),
            "htmlentitydecode" => Some(Self::HtmlEntityDecode),
            "trim" => Some(Self::Trim),
            "trimleft" => Some(Self::TrimLeft),
            "trimright" => Some(Self::TrimRight),
            "compresswhitespace" => Some(Self::CompressWhitespace),
            "removenulls" => Some(Self::RemoveNulls),
            "normalizepath" => Some(Self::NormalizePath),
            "base64decode" => Some(Self::Base64Decode),
            _ => None,
        }
    }

    pub fn apply<'a>(&self, input: &'a str) -> Cow<'a, str> {
        match self {
            Self::Lowercase => {
                if input.bytes().any(|byte| byte.is_ascii_uppercase()) {
                    Cow::Owned(input.to_ascii_lowercase())
                } else {
                    Cow::Borrowed(input)
                }
            }
            Self::UrlDecode => url_decode(input, false),
            Self::UrlDecodeUni => url_decode(input, true),
            Self::HtmlEntityDecode => html_escape::decode_html_entities(input),
            Self::Trim => {
                let value = input.trim_matches(|ch: char| ch.is_ascii_whitespace());
                borrowed_if_unchanged(input, value)
            }
            Self::TrimLeft => {
                let value = input.trim_start_matches(|ch: char| ch.is_ascii_whitespace());
                borrowed_if_unchanged(input, value)
            }
            Self::TrimRight => {
                let value = input.trim_end_matches(|ch: char| ch.is_ascii_whitespace());
                borrowed_if_unchanged(input, value)
            }
            Self::CompressWhitespace => compress_whitespace(input),
            Self::RemoveNulls => {
                if input.contains('\0') {
                    Cow::Owned(input.chars().filter(|ch| *ch != '\0').collect())
                } else {
                    Cow::Borrowed(input)
                }
            }
            Self::NormalizePath => normalize_path(input),
            Self::Base64Decode => {
                match base64::engine::general_purpose::STANDARD.decode(input.as_bytes()) {
                    Ok(bytes) => Cow::Owned(String::from_utf8_lossy(&bytes).into_owned()),
                    Err(_) => Cow::Borrowed(input),
                }
            }
        }
    }
}

fn borrowed_if_unchanged<'a>(original: &'a str, value: &'a str) -> Cow<'a, str> {
    if original.len() == value.len() && original.as_ptr() == value.as_ptr() {
        Cow::Borrowed(original)
    } else {
        Cow::Borrowed(value)
    }
}

fn compress_whitespace(input: &str) -> Cow<'_, str> {
    let mut output = String::with_capacity(input.len());
    let mut previous_space = false;
    let mut changed = false;
    for ch in input.chars() {
        if ch.is_ascii_whitespace() {
            if !previous_space {
                output.push(' ');
                previous_space = true;
            } else {
                changed = true;
            }
        } else {
            output.push(ch);
            previous_space = false;
        }
    }
    if changed || output != input {
        Cow::Owned(output)
    } else {
        Cow::Borrowed(input)
    }
}

fn url_decode(input: &str, uni: bool) -> Cow<'_, str> {
    if !input.contains('%') && !input.contains('+') {
        return Cow::Borrowed(input);
    }
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                output.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                if uni && bytes[index + 1] == b'u' && index + 6 <= bytes.len() {
                    let code = match (
                        hex_nibble(bytes[index + 2]),
                        hex_nibble(bytes[index + 3]),
                        hex_nibble(bytes[index + 4]),
                        hex_nibble(bytes[index + 5]),
                    ) {
                        (Some(a), Some(b), Some(c), Some(d)) => Some(
                            ((a as u32) << 12) | ((b as u32) << 8) | ((c as u32) << 4) | (d as u32),
                        ),
                        _ => None,
                    };
                    if let Some(ch) = code.and_then(char::from_u32) {
                        let mut buffer = [0u8; 4];
                        output.extend_from_slice(ch.encode_utf8(&mut buffer).as_bytes());
                        index += 6;
                    } else {
                        output.push(b'%');
                        index += 1;
                    }
                } else if let (Some(high), Some(low)) =
                    (hex_nibble(bytes[index + 1]), hex_nibble(bytes[index + 2]))
                {
                    output.push(high * 16 + low);
                    index += 3;
                } else {
                    output.push(b'%');
                    index += 1;
                }
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }
    Cow::Owned(String::from_utf8_lossy(&output).into_owned())
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn normalize_path(input: &str) -> Cow<'_, str> {
    if !input.contains('\\')
        && !input.contains("//")
        && !input.contains("/./")
        && !input.contains("/../")
        && !input.ends_with("/.")
        && !input.ends_with("/..")
    {
        return Cow::Borrowed(input);
    }
    let absolute = input.starts_with('/') || input.starts_with('\\');
    let mut segments: Vec<&str> = Vec::new();
    for segment in input.split(['/', '\\']) {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            value => segments.push(value),
        }
    }
    let mut output = String::new();
    if absolute {
        output.push('/');
    }
    output.push_str(&segments.join("/"));
    if output.is_empty() {
        output.push('/');
    }
    Cow::Owned(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lowercase_and_trim() {
        assert_eq!(Transform::Lowercase.apply("AbC"), "abc");
        assert_eq!(Transform::Trim.apply("  a b  "), "a b");
        assert_eq!(Transform::TrimLeft.apply("  a "), "a ");
        assert_eq!(Transform::TrimRight.apply(" a  "), " a");
    }

    #[test]
    fn url_decode_variants() {
        assert_eq!(Transform::UrlDecode.apply("a%20b+c"), "a b c");
        assert_eq!(Transform::UrlDecodeUni.apply("%u0041%u4E2D"), "A中");
        assert_eq!(Transform::UrlDecode.apply("%zz"), "%zz");
        assert_eq!(Transform::UrlDecode.apply("%Aé"), "%Aé");
    }

    #[test]
    fn html_entities_and_nulls() {
        assert_eq!(
            Transform::HtmlEntityDecode.apply("&lt;script&gt;"),
            "<script>"
        );
        assert_eq!(Transform::RemoveNulls.apply("a\0b"), "ab");
    }

    #[test]
    fn path_normalization() {
        assert_eq!(Transform::NormalizePath.apply("/a//b/../c/./d"), "/a/c/d");
        assert_eq!(Transform::NormalizePath.apply("/../../x"), "/x");
        assert_eq!(Transform::NormalizePath.apply("a\\b"), "a/b");
    }

    #[test]
    fn whitespace_compression() {
        assert_eq!(Transform::CompressWhitespace.apply("a \t\n b"), "a b");
    }

    #[test]
    fn base64_decode_keeps_invalid_input() {
        assert_eq!(Transform::Base64Decode.apply("aGVsbG8="), "hello");
        assert_eq!(Transform::Base64Decode.apply("!!!"), "!!!");
    }
}
