use std::cell::RefCell;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use http::HeaderMap;

use crate::model::{PrefilterScope, Variable};

use super::tx::TxStore;

#[derive(Debug, Clone, Copy)]
pub struct RequestView<'a> {
    pub method: &'a str,
    pub uri: &'a str,
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub headers: &'a HeaderMap,
    pub body: &'a [u8],
    pub remote_addr: IpAddr,
}

#[derive(Debug, Clone)]
pub struct RequestContext {
    method: String,
    uri: String,
    path: String,
    query: Option<String>,
    headers: Vec<(String, String)>,
    query_pairs: Vec<(String, String)>,
    body_pairs: Vec<(String, String)>,
    cookies: Vec<(String, String)>,
    remote_addr: IpAddr,
    body_text: String,
    tx: TxStore,
    cache: RefCell<HashMap<Variable, Arc<Vec<String>>>>,
}

impl RequestContext {
    pub fn new(view: &RequestView<'_>) -> Self {
        let headers: Vec<(String, String)> = view
            .headers
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_ascii_lowercase(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect();
        let query_pairs = view
            .query
            .map(|query| {
                form_urlencoded::parse(query.as_bytes())
                    .map(|(name, value)| (name.into_owned(), value.into_owned()))
                    .collect()
            })
            .unwrap_or_default();
        let cookies = headers
            .iter()
            .filter(|(name, _)| name == "cookie")
            .flat_map(|(_, value)| parse_cookies(value))
            .collect();

        Self {
            method: view.method.to_string(),
            uri: view.uri.to_string(),
            path: view.path.to_string(),
            query: view.query.map(str::to_string),
            headers,
            query_pairs,
            body_pairs: Vec::new(),
            cookies,
            remote_addr: view.remote_addr,
            body_text: String::new(),
            tx: TxStore::default(),
            cache: RefCell::new(HashMap::new()),
        }
    }

    pub fn set_body(&mut self, body: &[u8]) {
        self.body_text = String::from_utf8_lossy(body).into_owned();
        let is_form = self
            .headers
            .iter()
            .find(|(name, _)| name == "content-type")
            .map(|(_, value)| {
                value
                    .to_ascii_lowercase()
                    .starts_with("application/x-www-form-urlencoded")
            })
            .unwrap_or(false);
        self.body_pairs = if is_form {
            form_urlencoded::parse(body)
                .map(|(name, value)| (name.into_owned(), value.into_owned()))
                .collect()
        } else {
            Vec::new()
        };
        self.cache.borrow_mut().clear();
    }

    pub fn tx(&self) -> &TxStore {
        &self.tx
    }

    pub fn tx_mut(&mut self) -> &mut TxStore {
        &mut self.tx
    }

    pub fn extract(&self, variable: &Variable) -> Arc<Vec<String>> {
        let cacheable = !matches!(variable, Variable::Tx(_));
        if cacheable {
            if let Some(values) = self.cache.borrow().get(variable) {
                return values.clone();
            }
        }
        let values = Arc::new(self.compute(variable));
        if cacheable {
            self.cache
                .borrow_mut()
                .insert(variable.clone(), values.clone());
        }
        values
    }

    fn compute(&self, variable: &Variable) -> Vec<String> {
        match variable {
            Variable::RequestUri => vec![self.uri.clone()],
            Variable::RequestMethod => vec![self.method.clone()],
            Variable::QueryString => vec![self.query.clone().unwrap_or_default()],
            Variable::RequestFilename => vec![self.path.clone()],
            Variable::RequestHeaders(None) => self
                .headers
                .iter()
                .map(|(_, value)| value.clone())
                .collect(),
            Variable::RequestHeaders(Some(name)) => {
                let name = name.to_ascii_lowercase();
                self.headers
                    .iter()
                    .filter(|(header, _)| *header == name)
                    .map(|(_, value)| value.clone())
                    .collect()
            }
            Variable::Args => self
                .query_pairs
                .iter()
                .chain(self.body_pairs.iter())
                .map(|(_, value)| value.clone())
                .collect(),
            Variable::ArgsGet => self
                .query_pairs
                .iter()
                .map(|(_, value)| value.clone())
                .collect(),
            Variable::ArgsPost => self
                .body_pairs
                .iter()
                .map(|(_, value)| value.clone())
                .collect(),
            Variable::ArgsNames => self
                .query_pairs
                .iter()
                .chain(self.body_pairs.iter())
                .map(|(name, _)| name.clone())
                .collect(),
            Variable::RequestCookies(None) => self
                .cookies
                .iter()
                .map(|(_, value)| value.clone())
                .collect(),
            Variable::RequestCookies(Some(name)) => self
                .cookies
                .iter()
                .filter(|(cookie, _)| cookie.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.clone())
                .collect(),
            Variable::RequestBody => vec![self.body_text.clone()],
            Variable::RemoteAddr => vec![self.remote_addr.to_string()],
            Variable::Tx(None) => self.tx.values().map(str::to_string).collect(),
            Variable::Tx(Some(name)) => self
                .tx
                .get(name)
                .map(|value| vec![value.to_string()])
                .unwrap_or_default(),
        }
    }

    pub fn for_each_prefilter_value<F: FnMut(&str)>(&self, scope: PrefilterScope, mut f: F) {
        if scope.request_line {
            f(&self.method);
            f(&self.uri);
            f(&self.path);
            if let Some(query) = &self.query {
                f(query);
            }
        }
        if scope.headers {
            for (name, value) in &self.headers {
                f(name);
                f(value);
            }
        }
        if scope.cookies {
            for (name, value) in &self.cookies {
                f(name);
                f(value);
            }
        }
        if scope.query {
            for (name, value) in &self.query_pairs {
                f(name);
                f(value);
            }
        }
        if scope.body {
            f(&self.body_text);
            for (name, value) in &self.body_pairs {
                f(name);
                f(value);
            }
        }
    }
}

fn parse_cookies(value: &str) -> Vec<(String, String)> {
    value
        .split(';')
        .filter_map(|item| {
            let item = item.trim();
            let (name, value) = item.split_once('=')?;
            Some((name.trim().to_string(), value.trim().to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue};

    use super::*;
    use crate::model::Variable;

    fn header_map(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(
                http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        headers
    }

    fn context(headers: &HeaderMap) -> RequestContext {
        let view = RequestView {
            method: "POST",
            uri: "/search?q=%3Cscript%3E&page=2",
            path: "/search",
            query: Some("q=%3Cscript%3E&page=2"),
            headers,
            body: b"",
            remote_addr: "203.0.113.7".parse().unwrap(),
        };
        RequestContext::new(&view)
    }

    fn extract(context: &RequestContext, variable: Variable) -> Vec<String> {
        context.extract(&variable).iter().cloned().collect()
    }

    #[test]
    fn extracts_query_arguments_and_names() {
        let headers = header_map(&[]);
        let context = context(&headers);
        assert_eq!(extract(&context, Variable::ArgsGet), vec!["<script>", "2"]);
        assert_eq!(extract(&context, Variable::Args), vec!["<script>", "2"]);
        let mut names = extract(&context, Variable::ArgsNames);
        names.sort();
        assert_eq!(names, vec!["page", "q"]);
    }

    #[test]
    fn extracts_form_body_only_for_urlencoded() {
        let headers = header_map(&[("content-type", "application/x-www-form-urlencoded")]);
        let mut context = context(&headers);
        context.set_body(b"user=admin&token=a%20b");
        assert_eq!(extract(&context, Variable::ArgsPost), vec!["admin", "a b"]);
        assert_eq!(
            extract(&context, Variable::Args),
            vec!["<script>", "2", "admin", "a b"]
        );
    }

    #[test]
    fn does_not_parse_multipart_body() {
        let headers = header_map(&[("content-type", "multipart/form-data; boundary=x")]);
        let mut context = context(&headers);
        context.set_body(b"user=admin");
        assert!(extract(&context, Variable::ArgsPost).is_empty());
        assert_eq!(extract(&context, Variable::RequestBody), vec!["user=admin"]);
    }

    #[test]
    fn extracts_headers_case_insensitively_with_duplicates() {
        let headers = header_map(&[("X-Test", "one"), ("x-test", "two")]);
        let context = context(&headers);
        assert_eq!(
            extract(&context, Variable::RequestHeaders(Some("X-TEST".into()))),
            vec!["one", "two"]
        );
        let all = extract(&context, Variable::RequestHeaders(None));
        assert!(all.contains(&"one".to_string()));
        assert!(all.contains(&"two".to_string()));
    }

    #[test]
    fn extracts_cookies() {
        let headers = header_map(&[("cookie", "session=abc; theme=dark")]);
        let context = context(&headers);
        assert_eq!(
            extract(&context, Variable::RequestCookies(Some("session".into()))),
            vec!["abc"]
        );
        assert_eq!(
            extract(&context, Variable::RequestCookies(None)),
            vec!["abc", "dark"]
        );
    }

    #[test]
    fn extracts_request_metadata_and_tx() {
        let headers = header_map(&[]);
        let mut context = context(&headers);
        assert_eq!(extract(&context, Variable::RequestMethod), vec!["POST"]);
        assert_eq!(
            extract(&context, Variable::RequestUri),
            vec!["/search?q=%3Cscript%3E&page=2"]
        );
        assert_eq!(
            extract(&context, Variable::RequestFilename),
            vec!["/search"]
        );
        assert_eq!(
            extract(&context, Variable::QueryString),
            vec!["q=%3Cscript%3E&page=2"]
        );
        assert_eq!(extract(&context, Variable::RemoteAddr), vec!["203.0.113.7"]);
        context.tx_mut().set("score", "9".to_string());
        assert_eq!(
            extract(&context, Variable::Tx(Some("SCORE".into()))),
            vec!["9"]
        );
        assert_eq!(extract(&context, Variable::Tx(None)), vec!["9"]);
    }

    #[test]
    fn extracts_lossy_request_body() {
        let headers = header_map(&[]);
        let mut context = context(&headers);
        context.set_body(&[0x66, 0x6f, 0x80, 0x6f]);
        assert_eq!(
            extract(&context, Variable::RequestBody),
            vec!["fo\u{fffd}o"]
        );
    }

    #[test]
    fn caches_non_tx_extractions_and_clears_on_body_change() {
        let headers = header_map(&[]);
        let mut context = context(&headers);
        let first = context.extract(&Variable::ArgsGet);
        let second = context.extract(&Variable::ArgsGet);
        assert!(Arc::ptr_eq(&first, &second));

        context.set_body(b"q=body");
        let after = context.extract(&Variable::ArgsGet);
        assert!(!Arc::ptr_eq(&first, &after));
    }
}
