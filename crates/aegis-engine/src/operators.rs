use std::net::IpAddr;

use ipnet::IpNet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NumberArg {
    Literal(i64),
    Template(String),
}

impl NumberArg {
    fn resolve<F: Fn(&str) -> String>(&self, expand: &F) -> Option<i64> {
        match self {
            Self::Literal(value) => Some(*value),
            Self::Template(template) => expand(template).trim().parse::<i64>().ok(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum CompiledOperator {
    Rx(regex::Regex),
    Eq(String),
    Contains(String),
    BeginsWith(String),
    EndsWith(String),
    Pm(Vec<String>),
    IpMatch(Vec<IpNet>),
    Within(String),
    Gt(NumberArg),
    Ge(NumberArg),
    Lt(NumberArg),
    Le(NumberArg),
    DetectSqli,
    DetectXss,
    Unconditional,
    ByteRange(Vec<(u8, u8)>),
    ValidateUtf8Encoding,
    ValidateUrlEncoding,
}

impl CompiledOperator {
    pub fn matches(&self, input: &str) -> bool {
        self.matches_with(input, &|_| String::new())
    }

    pub fn matches_with<F: Fn(&str) -> String>(&self, input: &str, expand: &F) -> bool {
        match self {
            Self::Rx(regex) => regex.is_match(input),
            Self::Eq(expected) => input == expected,
            Self::Contains(needle) => input.contains(needle),
            Self::BeginsWith(prefix) => input.starts_with(prefix),
            Self::EndsWith(suffix) => input.ends_with(suffix),
            Self::Pm(phrases) => {
                let haystack = input.to_ascii_lowercase();
                phrases.iter().any(|phrase| haystack.contains(phrase))
            }
            Self::IpMatch(networks) => input
                .parse::<IpAddr>()
                .map(|address| networks.iter().any(|network| network.contains(&address)))
                .unwrap_or(false),
            Self::Within(haystack) => haystack.contains(input),
            Self::Gt(value) => {
                compare_numbers(input, value, expand, |number, limit| number > limit)
            }
            Self::Ge(value) => {
                compare_numbers(input, value, expand, |number, limit| number >= limit)
            }
            Self::Lt(value) => {
                compare_numbers(input, value, expand, |number, limit| number < limit)
            }
            Self::Le(value) => {
                compare_numbers(input, value, expand, |number, limit| number <= limit)
            }
            Self::DetectSqli => libinjectionrs::detect_sqli(input.as_bytes()).is_injection(),
            Self::DetectXss => libinjectionrs::detect_xss(input.as_bytes()).is_injection(),
            Self::Unconditional => true,
            Self::ByteRange(ranges) => !input.as_bytes().iter().all(|byte| {
                ranges
                    .iter()
                    .any(|(start, end)| *start <= *byte && *byte <= *end)
            }),
            Self::ValidateUtf8Encoding => input.contains('\u{FFFD}'),
            Self::ValidateUrlEncoding => invalid_url_encoding(input),
        }
    }
}

fn invalid_url_encoding(input: &str) -> bool {
    let bytes = input.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return true;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    false
}

fn parse_number(input: &str) -> Option<i64> {
    input.trim().parse::<i64>().ok()
}

fn compare_numbers<F: Fn(&str) -> String>(
    input: &str,
    limit: &NumberArg,
    expand: &F,
    compare: impl Fn(i64, i64) -> bool,
) -> bool {
    match (parse_number(input), limit.resolve(expand)) {
        (Some(number), Some(limit)) => compare(number, limit),
        _ => false,
    }
}

pub fn parse_ip_match(argument: &str) -> Result<Vec<IpNet>, String> {
    argument
        .split(',')
        .map(|item| {
            let item = item.trim();
            if let Ok(network) = item.parse::<IpNet>() {
                Ok(network)
            } else if let Ok(address) = item.parse::<IpAddr>() {
                let prefix = if address.is_ipv4() { 32 } else { 128 };
                Ok(IpNet::new(address, prefix).map_err(|error| error.to_string())?)
            } else {
                Err(format!("invalid IP or CIDR: {item}"))
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_operators_match() {
        assert!(CompiledOperator::Eq("a".into()).matches("a"));
        assert!(CompiledOperator::Contains("bc".into()).matches("abcd"));
        assert!(CompiledOperator::BeginsWith("ab".into()).matches("abcd"));
        assert!(CompiledOperator::EndsWith("cd".into()).matches("abcd"));
        assert!(CompiledOperator::Within("abcd".into()).matches("bc"));
        assert!(CompiledOperator::Pm(vec!["x".into(), "bc".into()]).matches("abcd"));
    }

    #[test]
    fn pm_is_case_insensitive() {
        assert!(CompiledOperator::Pm(vec!["sqlmap".into()]).matches("SQLMAP/1.0"));
        assert!(CompiledOperator::Pm(vec!["bc".into()]).matches("ABCD"));
    }

    #[test]
    fn ip_match_supports_cidr_and_single_addresses() {
        let networks = parse_ip_match("10.0.0.0/8, 192.168.1.5, 2001:db8::/32").unwrap();
        assert!(CompiledOperator::IpMatch(networks.clone()).matches("10.1.2.3"));
        assert!(CompiledOperator::IpMatch(networks.clone()).matches("192.168.1.5"));
        assert!(CompiledOperator::IpMatch(networks).matches("2001:db8::1"));
    }

    #[test]
    fn numeric_operators_handle_invalid_input() {
        assert!(CompiledOperator::Gt(NumberArg::Literal(5)).matches("6"));
        assert!(!CompiledOperator::Gt(NumberArg::Literal(5)).matches("abc"));
    }

    #[test]
    fn libinjection_operators_detect_attacks() {
        assert!(CompiledOperator::DetectSqli.matches("1' OR '1'='1"));
        assert!(!CompiledOperator::DetectSqli.matches("hello world"));
        assert!(CompiledOperator::DetectXss.matches("<script>alert(1)</script>"));
        assert!(!CompiledOperator::DetectXss.matches("hello world"));
    }

    #[test]
    fn byte_range_matches_invalid_bytes() {
        let printable = CompiledOperator::ByteRange(vec![(32, 126)]);
        assert!(!printable.matches("hello"));
        assert!(printable.matches("hel\0lo"));
        assert!(CompiledOperator::Unconditional.matches(""));
        assert!(CompiledOperator::Unconditional.matches("anything"));
    }

    #[test]
    fn validation_operators_match_invalid_input() {
        assert!(!CompiledOperator::ValidateUtf8Encoding.matches("hello"));
        assert!(CompiledOperator::ValidateUtf8Encoding.matches("hel\u{FFFD}lo"));
        assert!(!CompiledOperator::ValidateUrlEncoding.matches("a%20b"));
        assert!(CompiledOperator::ValidateUrlEncoding.matches("a%2"));
        assert!(CompiledOperator::ValidateUrlEncoding.matches("a%zz"));
    }
}
