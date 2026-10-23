#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogicalLine {
    pub text: String,
    pub line: usize,
}

pub fn split_logical_lines(input: &str) -> Vec<LogicalLine> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut start_line = 0usize;
    let mut in_single = false;
    let mut in_double = false;

    for (index, raw) in input.lines().enumerate() {
        let line_number = index + 1;
        let line = strip_comment(raw, &mut in_single, &mut in_double);
        let trimmed_end = line.trim_end();
        let continuation = ends_with_unescaped_backslash(trimmed_end);
        let segment = if continuation {
            &trimmed_end[..trimmed_end.len() - 1]
        } else {
            trimmed_end
        };
        if current.is_empty() {
            start_line = line_number;
        } else if !segment.trim().is_empty() {
            current.push(' ');
        }
        current.push_str(segment.trim());
        if !continuation {
            let text = current.trim().to_string();
            if !text.is_empty() {
                result.push(LogicalLine {
                    text,
                    line: start_line,
                });
            }
            current.clear();
            start_line = 0;
        }
    }

    let text = current.trim().to_string();
    if !text.is_empty() {
        result.push(LogicalLine {
            text,
            line: start_line,
        });
    }
    result
}

fn strip_comment<'a>(line: &'a str, in_single: &mut bool, in_double: &mut bool) -> &'a str {
    let bytes = line.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if *in_single {
            if byte == b'\\' {
                index += 2;
                continue;
            }
            if byte == b'\'' {
                *in_single = false;
            }
        } else if *in_double {
            if byte == b'\\' {
                index += 2;
                continue;
            }
            if byte == b'"' {
                *in_double = false;
            }
        } else if byte == b'\'' {
            *in_single = true;
        } else if byte == b'"' {
            *in_double = true;
        } else if byte == b'#' {
            return &line[..index];
        }
        index += 1;
    }
    line
}

fn ends_with_unescaped_backslash(text: &str) -> bool {
    let count = text
        .as_bytes()
        .iter()
        .rev()
        .take_while(|byte| **byte == b'\\')
        .count();
    count % 2 == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_backslash_continuations() {
        let input = "SecRule ARGS \"@rx foo\" \\\n    \"id:1,deny\"\n";
        let lines = split_logical_lines(input);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].text, "SecRule ARGS \"@rx foo\" \"id:1,deny\"");
        assert_eq!(lines[0].line, 1);
    }

    #[test]
    fn strips_comments_and_blank_lines() {
        let input = "\n# comment\nSecMarker START # trailing\n\n";
        let lines = split_logical_lines(input);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].text, "SecMarker START");
        assert_eq!(lines[0].line, 3);
    }

    #[test]
    fn keeps_hash_inside_quotes() {
        let input = "SecRule ARGS \"@rx a#b\" \"id:1,deny\"\n";
        let lines = split_logical_lines(input);
        assert_eq!(lines[0].text, "SecRule ARGS \"@rx a#b\" \"id:1,deny\"");
    }

    #[test]
    fn tracks_line_number_after_comments_and_blanks() {
        let input = "# a\n\nSecRule ARGS \"@rx x\" \"id:1,deny\"\n";
        let lines = split_logical_lines(input);
        assert_eq!(lines[0].line, 3);
    }
}
