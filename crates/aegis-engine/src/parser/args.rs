#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawArg {
    pub value: String,
    pub column: usize,
}

pub fn split_args(input: &str) -> Result<Vec<RawArg>, String> {
    let mut args = Vec::new();
    let mut chars = input.char_indices().peekable();

    while let Some(&(start, first)) = chars.peek() {
        if first.is_whitespace() {
            chars.next();
            continue;
        }
        let mut value = String::new();
        let mut quote: Option<char> = None;
        while let Some(&(_, ch)) = chars.peek() {
            if let Some(delimiter) = quote {
                chars.next();
                if ch == '\\' {
                    match chars.peek() {
                        Some(&(_, escaped)) if escaped == delimiter || escaped == '\\' => {
                            value.push(escaped);
                            chars.next();
                        }
                        _ => value.push('\\'),
                    }
                } else if ch == delimiter {
                    quote = None;
                } else {
                    value.push(ch);
                }
            } else if ch == '"' || ch == '\'' {
                quote = Some(ch);
                chars.next();
            } else if ch.is_whitespace() {
                break;
            } else {
                value.push(ch);
                chars.next();
            }
        }
        if quote.is_some() {
            return Err(format!("unterminated quote at column {}", start + 1));
        }
        args.push(RawArg {
            value,
            column: start + 1,
        });
    }
    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_quoted_arguments_and_preserves_columns() {
        let args = split_args(r#"ARGS "@rx a b" "id:1,msg:'x,y'""#).unwrap();
        assert_eq!(args.len(), 3);
        assert_eq!(args[0].value, "ARGS");
        assert_eq!(args[1].value, "@rx a b");
        assert_eq!(args[2].value, "id:1,msg:'x,y'");
        assert_eq!(args[0].column, 1);
        assert_eq!(args[1].column, 6);
    }

    #[test]
    fn unescapes_backslashes_inside_quotes() {
        let args = split_args(r#""a\"b""#).unwrap();
        assert_eq!(args[0].value, "a\"b");
    }

    #[test]
    fn preserves_regex_backslashes_inside_quotes() {
        let args = split_args(r#"ARGS "@rx \s+foo" "id:1""#).unwrap();
        assert_eq!(args[1].value, r"@rx \s+foo");
    }

    #[test]
    fn rejects_unterminated_quotes() {
        assert!(split_args("\"abc").is_err());
    }
}
