use std::borrow::Cow;

use base64::Engine as _;
use sha1::{Digest, Sha1};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Transform {
    Lowercase,
    UrlDecode,
    UrlDecodeUni,
    HtmlEntityDecode,
    JsDecode,
    CssDecode,
    CmdLine,
    Utf8ToUnicode,
    EscapeSeqDecode,
    Trim,
    TrimLeft,
    TrimRight,
    CompressWhitespace,
    RemoveWhitespace,
    RemoveNulls,
    ReplaceComments,
    RemoveCommentsChar,
    NormalizePath,
    NormalizePathWin,
    Length,
    Sha1,
    HexEncode,
    Base64Decode,
}

impl Transform {
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "lowercase" => Some(Self::Lowercase),
            "urldecode" => Some(Self::UrlDecode),
            "urldecodeuni" => Some(Self::UrlDecodeUni),
            "htmlentitydecode" => Some(Self::HtmlEntityDecode),
            "jsdecode" => Some(Self::JsDecode),
            "cssdecode" => Some(Self::CssDecode),
            "cmdline" => Some(Self::CmdLine),
            "utf8tounicode" => Some(Self::Utf8ToUnicode),
            "escapeseqdecode" => Some(Self::EscapeSeqDecode),
            "trim" => Some(Self::Trim),
            "trimleft" => Some(Self::TrimLeft),
            "trimright" => Some(Self::TrimRight),
            "compresswhitespace" => Some(Self::CompressWhitespace),
            "removewhitespace" => Some(Self::RemoveWhitespace),
            "removenulls" => Some(Self::RemoveNulls),
            "replacecomments" => Some(Self::ReplaceComments),
            "removecommentschar" => Some(Self::RemoveCommentsChar),
            "normalizepath" => Some(Self::NormalizePath),
            "normalizepathwin" => Some(Self::NormalizePathWin),
            "length" => Some(Self::Length),
            "sha1" => Some(Self::Sha1),
            "hexencode" => Some(Self::HexEncode),
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
            Self::JsDecode => js_decode(input),
            Self::CssDecode => css_decode(input),
            Self::CmdLine => cmd_line(input),
            Self::Utf8ToUnicode => utf8_to_unicode(input),
            Self::EscapeSeqDecode => js_decode(input),
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
            Self::RemoveWhitespace => {
                if input.chars().any(char::is_whitespace) {
                    Cow::Owned(input.chars().filter(|ch| !ch.is_whitespace()).collect())
                } else {
                    Cow::Borrowed(input)
                }
            }
            Self::RemoveNulls => {
                if input.contains('\0') {
                    Cow::Owned(input.chars().filter(|ch| *ch != '\0').collect())
                } else {
                    Cow::Borrowed(input)
                }
            }
            Self::ReplaceComments => replace_comments(input),
            Self::RemoveCommentsChar => remove_comment_chars(input),
            Self::NormalizePath | Self::NormalizePathWin => normalize_path(input),
            Self::Length => Cow::Owned(input.chars().count().to_string()),
            Self::Sha1 => Cow::Owned(hex_encode(&Sha1::digest(input.as_bytes()))),
            Self::HexEncode => Cow::Owned(hex_encode(input.as_bytes())),
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

fn js_decode(input: &str) -> Cow<'_, str> {
    if !input.contains('\\') {
        return Cow::Borrowed(input);
    }
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'\\' || index + 1 >= bytes.len() {
            output.push(bytes[index]);
            index += 1;
            continue;
        }
        let next = bytes[index + 1];
        match next {
            b'x' if index + 3 < bytes.len() => {
                if let (Some(high), Some(low)) =
                    (hex_nibble(bytes[index + 2]), hex_nibble(bytes[index + 3]))
                {
                    output.push(high * 16 + low);
                    index += 4;
                } else {
                    output.push(b'\\');
                    index += 1;
                }
            }
            b'u' if index + 5 < bytes.len() => {
                let mut code = 0u32;
                let mut valid = true;
                for offset in 0..4 {
                    match hex_nibble(bytes[index + 2 + offset]) {
                        Some(value) => code = (code << 4) | value as u32,
                        None => {
                            valid = false;
                            break;
                        }
                    }
                }
                if valid {
                    if let Some(ch) = char::from_u32(code) {
                        let mut buffer = [0u8; 4];
                        output.extend_from_slice(ch.encode_utf8(&mut buffer).as_bytes());
                        index += 6;
                    } else {
                        output.push(b'\\');
                        index += 1;
                    }
                } else {
                    output.push(b'\\');
                    index += 1;
                }
            }
            b'0' => {
                output.push(0);
                index += 2;
            }
            b'n' => {
                output.push(b'\n');
                index += 2;
            }
            b'r' => {
                output.push(b'\r');
                index += 2;
            }
            b't' => {
                output.push(b'\t');
                index += 2;
            }
            b'b' => {
                output.push(8);
                index += 2;
            }
            b'f' => {
                output.push(12);
                index += 2;
            }
            b'v' => {
                output.push(11);
                index += 2;
            }
            b'\\' | b'\'' | b'"' | b'/' => {
                output.push(next);
                index += 2;
            }
            b'\n' => {
                index += 2;
            }
            b'\r' if index + 2 < bytes.len() && bytes[index + 2] == b'\n' => {
                index += 3;
            }
            _ => {
                output.push(next);
                index += 2;
            }
        }
    }
    Cow::Owned(String::from_utf8_lossy(&output).into_owned())
}

fn css_decode(input: &str) -> Cow<'_, str> {
    if !input.contains('\\') {
        return Cow::Borrowed(input);
    }
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'\\' || index + 1 >= bytes.len() {
            output.push(bytes[index]);
            index += 1;
            continue;
        }
        let mut cursor = index + 1;
        let mut code = 0u32;
        let mut digits = 0;
        while digits < 6 && cursor < bytes.len() {
            match hex_nibble(bytes[cursor]) {
                Some(value) => {
                    code = (code << 4) | value as u32;
                    digits += 1;
                    cursor += 1;
                }
                None => break,
            }
        }
        if digits > 0 {
            if let Some(ch) = char::from_u32(code) {
                let mut buffer = [0u8; 4];
                output.extend_from_slice(ch.encode_utf8(&mut buffer).as_bytes());
            }
            if cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            index = cursor;
        } else {
            output.push(bytes[index + 1]);
            index += 2;
        }
    }
    Cow::Owned(String::from_utf8_lossy(&output).into_owned())
}

fn cmd_line(input: &str) -> Cow<'_, str> {
    let needs_normalization = input.chars().any(|ch| {
        ch.is_ascii_uppercase()
            || ch.is_whitespace()
            || matches!(ch, '\\' | '"' | '\'' | '^' | ',' | ';')
    });
    if !needs_normalization {
        return Cow::Borrowed(input);
    }
    let mut output = String::with_capacity(input.len());
    let mut pending_space = false;
    for ch in input.chars() {
        if matches!(ch, '\\' | '"' | '\'' | '^') {
            continue;
        }
        let ch = match ch {
            ',' | ';' => ' ',
            other => other,
        };
        if ch.is_whitespace() {
            pending_space = true;
            continue;
        }
        if pending_space {
            if ch != '/' && ch != '(' && !output.is_empty() {
                output.push(' ');
            }
            pending_space = false;
        }
        output.push(ch.to_ascii_lowercase());
    }
    Cow::Owned(output)
}

fn utf8_to_unicode(input: &str) -> Cow<'_, str> {
    if input.is_ascii() {
        return Cow::Borrowed(input);
    }
    use std::fmt::Write as _;
    let mut output = String::with_capacity(input.len() * 2);
    for ch in input.chars() {
        let code = ch as u32;
        if code < 0x80 {
            output.push(ch);
        } else if code <= 0xFFFF {
            let _ = write!(output, "%u{code:04X}");
        } else {
            let value = code - 0x10000;
            let high = 0xD800 + (value >> 10);
            let low = 0xDC00 + (value & 0x3FF);
            let _ = write!(output, "%u{high:04X}%u{low:04X}");
        }
    }
    Cow::Owned(output)
}

fn replace_comments(input: &str) -> Cow<'_, str> {
    if !input.contains("/*") {
        return Cow::Borrowed(input);
    }
    let mut output = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find("/*") {
        output.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        if let Some(end) = after.find("*/") {
            output.push(' ');
            rest = &after[end + 2..];
        } else {
            output.push(' ');
            rest = "";
            break;
        }
    }
    output.push_str(rest);
    Cow::Owned(output)
}

fn remove_comment_chars(input: &str) -> Cow<'_, str> {
    if !input.contains(['/', '*', '-', '#']) {
        return Cow::Borrowed(input);
    }
    Cow::Owned(
        input
            .replace("/*", "")
            .replace("*/", "")
            .replace("--", "")
            .replace('#', ""),
    )
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
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
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #[test]
        fn url_decode_never_panics(input in ".*") {
            let _ = Transform::UrlDecode.apply(&input);
            let _ = Transform::UrlDecodeUni.apply(&input);
        }

        #[test]
        fn normalize_path_idempotent(input in ".*") {
            let once = Transform::NormalizePath.apply(&input).into_owned();
            let twice = Transform::NormalizePath.apply(&once).into_owned();
            prop_assert_eq!(once, twice);
        }
    }

    #[test]
    fn cmd_line_matches_modsecurity() {
        assert_eq!(
            Transform::CmdLine.apply("for %variable in (set) do command"),
            "for %variable in(set) do command"
        );
        assert_eq!(
            Transform::CmdLine.apply(r#""C:\Windows\CMD.EXE" /C DIR"#),
            "c:windowscmd.exe/c dir"
        );
        assert_eq!(Transform::CmdLine.apply("a , b ; c\t\td"), "a b c d");
    }

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

    #[test]
    fn decode_obfuscated_script() {
        assert_eq!(Transform::JsDecode.apply(r"\x3cscript\x3e"), "<script>");
        assert_eq!(Transform::JsDecode.apply(r"A"), "A");
        assert_eq!(Transform::CssDecode.apply(r"\3c script"), "<script");
        assert_eq!(Transform::EscapeSeqDecode.apply(r"a\tb\n"), "a\tb\n");
    }

    #[test]
    fn normalize_command_line_and_comments() {
        assert_eq!(
            Transform::CmdLine.apply(r#"c^m\d /c "whoami""#),
            "cmd/c whoami"
        );
        assert_eq!(Transform::RemoveWhitespace.apply("a b\tc"), "abc");
        assert_eq!(Transform::ReplaceComments.apply("a/*x*/b"), "a b");
        assert_eq!(Transform::ReplaceComments.apply("a/*x"), "a ");
        assert_eq!(Transform::RemoveCommentsChar.apply("a/*b*/--c#d"), "abcd");
    }

    #[test]
    fn length_sha1_and_hex_encode() {
        assert_eq!(Transform::Length.apply("abc"), "3");
        assert_eq!(
            Transform::Sha1.apply("abc"),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(Transform::HexEncode.apply("ab"), "6162");
        assert_eq!(Transform::Utf8ToUnicode.apply("abc"), "abc");
        assert_eq!(Transform::Utf8ToUnicode.apply("é中"), "%u00E9%u4E2D");
        assert_eq!(Transform::Utf8ToUnicode.apply("😀"), "%uD83D%uDE00");
    }
}
