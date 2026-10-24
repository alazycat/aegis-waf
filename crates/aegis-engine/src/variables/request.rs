use std::cell::RefCell;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use http::HeaderMap;

use crate::collections::{MemoryCollectionStore, SharedCollectionStore};
use crate::model::{PrefilterScope, Selector, Variable};

use super::tx::TxStore;

#[derive(Debug, Clone, Copy)]
pub struct RequestView<'a> {
    pub method: &'a str,
    pub uri: &'a str,
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub protocol: &'a str,
    pub headers: &'a HeaderMap,
    pub body: &'a [u8],
    pub remote_addr: IpAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariableEntry {
    pub name: String,
    pub key: Option<String>,
    pub value: String,
}

impl VariableEntry {
    fn scalar(variable: &Variable, value: String) -> Self {
        Self {
            name: variable.display_name(),
            key: None,
            value,
        }
    }

    fn item(prefix: &str, key: &str, value: String) -> Self {
        Self {
            name: format!("{prefix}:{key}"),
            key: Some(key.to_string()),
            value,
        }
    }
}

#[derive(Debug, Clone)]
struct MultipartPart {
    name: String,
    filename: Option<String>,
    data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RequestContext {
    method: String,
    uri: String,
    path: String,
    query: Option<String>,
    protocol: String,
    headers: Vec<(String, String)>,
    query_pairs: Vec<(String, String)>,
    body_pairs: Vec<(String, String)>,
    cookies: Vec<(String, String)>,
    remote_addr: IpAddr,
    body_text: String,
    body_len: usize,
    xml_values: Vec<String>,
    multipart_parts: Vec<MultipartPart>,
    response_status: Option<u16>,
    response_headers: Vec<(String, String)>,
    response_body_text: String,
    response_body_len: usize,
    response_content_type: Option<String>,
    tx: TxStore,
    collections: SharedCollectionStore,
    collection_keys: HashMap<String, String>,
    cache: RefCell<HashMap<Variable, Arc<Vec<VariableEntry>>>>,
}

impl RequestContext {
    pub fn new(view: &RequestView<'_>) -> Self {
        Self::new_with_store(view, Arc::new(MemoryCollectionStore::new()))
    }

    pub fn new_with_store(view: &RequestView<'_>, collections: SharedCollectionStore) -> Self {
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
            protocol: view.protocol.to_string(),
            headers,
            query_pairs,
            body_pairs: Vec::new(),
            cookies,
            remote_addr: view.remote_addr,
            body_text: String::new(),
            body_len: 0,
            xml_values: Vec::new(),
            multipart_parts: Vec::new(),
            response_status: None,
            response_headers: Vec::new(),
            response_body_text: String::new(),
            response_body_len: 0,
            response_content_type: None,
            tx: TxStore::default(),
            collections,
            collection_keys: HashMap::new(),
            cache: RefCell::new(HashMap::new()),
        }
    }

    pub fn set_collection_key(&mut self, collection: &str, key: String) {
        self.collection_keys
            .insert(collection.to_ascii_lowercase(), key);
        self.cache.borrow_mut().clear();
    }

    pub fn collection_key(&self, collection: &str) -> Option<&str> {
        self.collection_keys
            .get(&collection.to_ascii_lowercase())
            .map(String::as_str)
    }

    pub fn collection_get(&self, collection: &str, name: &str) -> Option<String> {
        let collection = collection.to_ascii_lowercase();
        let key = self.collection_key(&collection)?;
        self.collections.get(&collection, key, name)
    }

    pub fn collection_set(&mut self, collection: &str, name: &str, value: String) {
        let collection = collection.to_ascii_lowercase();
        let Some(key) = self.collection_key(&collection).map(str::to_string) else {
            return;
        };
        self.collections.set(&collection, &key, name, value);
        self.cache.borrow_mut().clear();
    }

    pub fn collection_remove(&mut self, collection: &str, name: &str) {
        let collection = collection.to_ascii_lowercase();
        let Some(key) = self.collection_key(&collection).map(str::to_string) else {
            return;
        };
        self.collections.remove(&collection, &key, name);
        self.cache.borrow_mut().clear();
    }

    pub fn collection_entries(&self, collection: &str) -> Vec<(String, String)> {
        let collection = collection.to_ascii_lowercase();
        let Some(key) = self.collection_key(&collection) else {
            return Vec::new();
        };
        self.collections.entries(&collection, key)
    }

    pub fn set_body(&mut self, body: &[u8]) {
        self.body_len = body.len();
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
        self.xml_values = if self
            .headers
            .iter()
            .find(|(name, _)| name == "content-type")
            .map(|(_, value)| value.to_ascii_lowercase().contains("xml"))
            .unwrap_or(false)
        {
            extract_xml_values(&self.body_text)
        } else {
            Vec::new()
        };
        self.multipart_parts = multipart_boundary(&self.headers)
            .map(|boundary| parse_multipart(body, &boundary))
            .unwrap_or_default();
        self.cache.borrow_mut().clear();
    }

    pub fn set_response_headers(&mut self, status: u16, headers: &HeaderMap) {
        self.response_status = Some(status);
        self.response_headers = headers
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_ascii_lowercase(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect();
        self.response_content_type = headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        self.cache.borrow_mut().clear();
    }

    pub fn set_response_body(&mut self, body: &[u8]) {
        self.response_body_len = body.len();
        self.response_body_text = String::from_utf8_lossy(body).into_owned();
        self.cache.borrow_mut().clear();
    }

    pub fn remote_addr(&self) -> IpAddr {
        self.remote_addr
    }

    pub fn tx(&self) -> &TxStore {
        &self.tx
    }

    pub fn tx_mut(&mut self) -> &mut TxStore {
        &mut self.tx
    }

    pub fn extract(&self, variable: &Variable) -> Arc<Vec<VariableEntry>> {
        let cacheable = !matches!(
            variable,
            Variable::Tx(_)
                | Variable::MatchedVar
                | Variable::MatchedVarName
                | Variable::MatchedVars(_)
                | Variable::Ip(_)
                | Variable::Session(_)
                | Variable::User(_)
                | Variable::Global(_)
        );
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

    fn compute(&self, variable: &Variable) -> Vec<VariableEntry> {
        match variable {
            Variable::RequestUri | Variable::RequestUriRaw => {
                vec![VariableEntry::scalar(variable, self.uri.clone())]
            }
            Variable::RequestLine => vec![VariableEntry::scalar(
                variable,
                format!("{} {} {}", self.method, self.uri, self.protocol),
            )],
            Variable::RequestProtocol => {
                vec![VariableEntry::scalar(variable, self.protocol.clone())]
            }
            Variable::RequestBasename => vec![VariableEntry::scalar(
                variable,
                self.path
                    .rsplit('/')
                    .find(|segment| !segment.is_empty())
                    .unwrap_or("")
                    .to_string(),
            )],
            Variable::RequestMethod => vec![VariableEntry::scalar(variable, self.method.clone())],
            Variable::QueryString => vec![VariableEntry::scalar(
                variable,
                self.query.clone().unwrap_or_default(),
            )],
            Variable::RequestFilename => vec![VariableEntry::scalar(variable, self.path.clone())],
            Variable::RequestHeaders(selector) => self
                .headers
                .iter()
                .filter(|(name, _)| name_matches(selector, name))
                .map(|(name, value)| VariableEntry::item("REQUEST_HEADERS", name, value.clone()))
                .collect(),
            Variable::RequestHeadersNames => unique_names(&self.headers)
                .into_iter()
                .map(|name| VariableEntry::item("REQUEST_HEADERS_NAMES", &name, name.clone()))
                .collect(),
            Variable::Args(selector) => self
                .query_pairs
                .iter()
                .chain(self.body_pairs.iter())
                .filter(|(name, _)| name_matches(selector, name))
                .map(|(name, value)| VariableEntry::item("ARGS", name, value.clone()))
                .collect(),
            Variable::ArgsGet(selector) => self
                .query_pairs
                .iter()
                .filter(|(name, _)| name_matches(selector, name))
                .map(|(name, value)| VariableEntry::item("ARGS_GET", name, value.clone()))
                .collect(),
            Variable::ArgsPost(selector) => self
                .body_pairs
                .iter()
                .filter(|(name, _)| name_matches(selector, name))
                .map(|(name, value)| VariableEntry::item("ARGS_POST", name, value.clone()))
                .collect(),
            Variable::ArgsNames => self
                .query_pairs
                .iter()
                .chain(self.body_pairs.iter())
                .map(|(name, _)| VariableEntry::item("ARGS_NAMES", name, name.clone()))
                .collect(),
            Variable::RequestCookies(selector) => self
                .cookies
                .iter()
                .filter(|(name, _)| name_matches(selector, name))
                .map(|(name, value)| VariableEntry::item("REQUEST_COOKIES", name, value.clone()))
                .collect(),
            Variable::RequestCookiesNames => unique_names(&self.cookies)
                .into_iter()
                .map(|name| VariableEntry::item("REQUEST_COOKIES_NAMES", &name, name.clone()))
                .collect(),
            Variable::RequestBody => vec![VariableEntry::scalar(variable, self.body_text.clone())],
            Variable::RequestBodyLength => {
                vec![VariableEntry::scalar(variable, self.body_len.to_string())]
            }
            Variable::Files => self
                .multipart_parts
                .iter()
                .filter(|part| part.filename.is_some())
                .map(|part| {
                    VariableEntry::item(
                        "FILES",
                        &part.name,
                        String::from_utf8_lossy(&part.data).into_owned(),
                    )
                })
                .collect(),
            Variable::FilesNames => self
                .multipart_parts
                .iter()
                .filter(|part| part.filename.is_some())
                .map(|part| VariableEntry::item("FILES_NAMES", &part.name, part.name.clone()))
                .collect(),
            Variable::FilesSizes => self
                .multipart_parts
                .iter()
                .filter(|part| part.filename.is_some())
                .map(|part| {
                    VariableEntry::item("FILES_SIZES", &part.name, part.data.len().to_string())
                })
                .collect(),
            Variable::FilesCombinedSize => vec![VariableEntry::scalar(
                variable,
                self.multipart_parts
                    .iter()
                    .filter(|part| part.filename.is_some())
                    .map(|part| part.data.len())
                    .sum::<usize>()
                    .to_string(),
            )],
            Variable::FilesTmpnames => Vec::new(),
            Variable::Ip(selector) => collection_entries(self, "ip", "IP", selector),
            Variable::Session(selector) => collection_entries(self, "session", "SESSION", selector),
            Variable::User(selector) => collection_entries(self, "user", "USER", selector),
            Variable::Global(selector) => collection_entries(self, "global", "GLOBAL", selector),
            Variable::RemoteAddr => {
                vec![VariableEntry::scalar(
                    variable,
                    self.remote_addr.to_string(),
                )]
            }
            Variable::MatchedVar => self
                .tx
                .get("matched_var")
                .map(|value| vec![VariableEntry::scalar(variable, value.to_string())])
                .unwrap_or_default(),
            Variable::MatchedVarName => self
                .tx
                .get("matched_var_name")
                .map(|value| vec![VariableEntry::scalar(variable, value.to_string())])
                .unwrap_or_default(),
            Variable::MatchedVars(_) => self
                .tx
                .get("matched_var_name")
                .map(|value| vec![VariableEntry::scalar(variable, value.to_string())])
                .unwrap_or_default(),
            Variable::Xml(_) => self
                .xml_values
                .iter()
                .map(|value| VariableEntry::scalar(variable, value.clone()))
                .collect(),
            Variable::ResponseStatus => self
                .response_status
                .map(|status| vec![VariableEntry::scalar(variable, status.to_string())])
                .unwrap_or_default(),
            Variable::ResponseHeaders(selector) => self
                .response_headers
                .iter()
                .filter(|(name, _)| name_matches(selector, name))
                .map(|(name, value)| VariableEntry::item("RESPONSE_HEADERS", name, value.clone()))
                .collect(),
            Variable::ResponseHeadersNames => unique_names(&self.response_headers)
                .into_iter()
                .map(|name| VariableEntry::item("RESPONSE_HEADERS_NAMES", &name, name.clone()))
                .collect(),
            Variable::ResponseBody => vec![VariableEntry::scalar(
                variable,
                self.response_body_text.clone(),
            )],
            Variable::ResponseBodyLength => vec![VariableEntry::scalar(
                variable,
                self.response_body_len.to_string(),
            )],
            Variable::ResponseContentType => self
                .response_content_type
                .clone()
                .map(|value| vec![VariableEntry::scalar(variable, value)])
                .unwrap_or_default(),
            Variable::Tx(selector) => self
                .tx
                .iter()
                .filter(|(name, _)| name_matches(selector, name))
                .map(|(name, value)| VariableEntry::item("TX", name, value.to_string()))
                .collect(),
        }
    }

    pub fn for_each_prefilter_value<F: FnMut(&str)>(&self, scope: PrefilterScope, mut f: F) {
        if scope.request_line {
            f(&self.method);
            f(&self.uri);
            f(&self.path);
            f(&self.protocol);
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

fn collection_entries(
    context: &RequestContext,
    collection: &str,
    prefix: &str,
    selector: &Option<Selector>,
) -> Vec<VariableEntry> {
    context
        .collection_entries(collection)
        .into_iter()
        .filter(|(name, _)| name_matches(selector, name))
        .map(|(name, value)| VariableEntry::item(prefix, &name, value))
        .collect()
}

fn name_matches(selector: &Option<Selector>, name: &str) -> bool {
    selector
        .as_ref()
        .map(|selector| selector.matches(name))
        .unwrap_or(true)
}

fn unique_names(pairs: &[(String, String)]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    pairs
        .iter()
        .filter_map(|(name, _)| {
            if seen.insert(name.clone()) {
                Some(name.clone())
            } else {
                None
            }
        })
        .collect()
}

fn multipart_boundary(headers: &[(String, String)]) -> Option<String> {
    let content_type = headers
        .iter()
        .find(|(name, _)| name == "content-type")
        .map(|(_, value)| value)?;
    if !content_type
        .to_ascii_lowercase()
        .starts_with("multipart/form-data")
    {
        return None;
    }
    content_type
        .split(';')
        .skip(1)
        .find_map(|part| {
            let part = part.trim();
            part.strip_prefix("boundary=")
                .map(|value| value.trim_matches('"').to_string())
        })
        .filter(|boundary| !boundary.is_empty())
}

fn parse_multipart(body: &[u8], boundary: &str) -> Vec<MultipartPart> {
    let delimiter = format!("--{boundary}").into_bytes();
    let next_delimiter = format!("\r\n--{boundary}").into_bytes();
    let mut parts = Vec::new();
    let mut position = 0usize;

    while let Some(start) = find_subslice(&body[position..], &delimiter) {
        let mut cursor = position + start + delimiter.len();
        if body.get(cursor..cursor + 2) == Some(b"--") {
            break;
        }
        if body.get(cursor..cursor + 2) == Some(b"\r\n") {
            cursor += 2;
        } else if body.get(cursor..cursor + 1) == Some(b"\n") {
            cursor += 1;
        }
        let Some(header_end) = find_subslice(&body[cursor..], b"\r\n\r\n") else {
            break;
        };
        let headers_text = String::from_utf8_lossy(&body[cursor..cursor + header_end]);
        let data_start = cursor + header_end + 4;
        let Some(next) = find_subslice(&body[data_start..], &next_delimiter) else {
            break;
        };
        let data_end = data_start + next;
        if let Some((name, filename)) = parse_part_disposition(&headers_text) {
            parts.push(MultipartPart {
                name,
                filename,
                data: body[data_start..data_end].to_vec(),
            });
        }
        position = data_end + 2;
    }
    parts
}

fn parse_part_disposition(headers: &str) -> Option<(String, Option<String>)> {
    let disposition = headers.lines().find(|line| {
        line.to_ascii_lowercase()
            .starts_with("content-disposition:")
    })?;
    let mut name = None;
    let mut filename = None;
    for part in disposition.split(';').skip(1) {
        let part = part.trim();
        if let Some(value) = part.strip_prefix("name=") {
            name = Some(value.trim_matches('"').to_string());
        } else if let Some(value) = part.strip_prefix("filename=") {
            filename = Some(value.trim_matches('"').to_string());
        }
    }
    name.map(|name| (name, filename))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn extract_xml_values(text: &str) -> Vec<String> {
    let Ok(document) = roxmltree::Document::parse(text) else {
        return Vec::new();
    };
    let mut values = Vec::new();
    for node in document.descendants() {
        for child in node.children() {
            if child.is_text() {
                if let Some(text) = child.text() {
                    let text = text.trim();
                    if !text.is_empty() {
                        values.push(text.to_string());
                    }
                }
            }
        }
        for attribute in node.attributes() {
            values.push(attribute.value().to_string());
        }
    }
    values
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
            protocol: "HTTP/1.1",
            headers,
            body: b"",
            remote_addr: "203.0.113.7".parse().unwrap(),
        };
        RequestContext::new(&view)
    }

    fn extract(context: &RequestContext, variable: Variable) -> Vec<String> {
        context
            .extract(&variable)
            .iter()
            .map(|entry| entry.value.clone())
            .collect()
    }

    #[test]
    fn entries_carry_precise_names_and_keys() {
        let headers = header_map(&[]);
        let context = context(&headers);
        let entries = context.extract(&Variable::Args(None));
        assert_eq!(entries[0].name, "ARGS:q");
        assert_eq!(entries[0].key.as_deref(), Some("q"));
        let names = context.extract(&Variable::ArgsNames);
        assert_eq!(names[0].name, "ARGS_NAMES:q");
        assert_eq!(names[0].value, "q");
    }

    #[test]
    fn extracts_query_arguments_and_names() {
        let headers = header_map(&[]);
        let context = context(&headers);
        assert_eq!(
            extract(&context, Variable::ArgsGet(None)),
            vec!["<script>", "2"]
        );
        assert_eq!(
            extract(&context, Variable::Args(None)),
            vec!["<script>", "2"]
        );
        let mut names = extract(&context, Variable::ArgsNames);
        names.sort();
        assert_eq!(names, vec!["page", "q"]);
    }

    #[test]
    fn extracts_form_body_only_for_urlencoded() {
        let headers = header_map(&[("content-type", "application/x-www-form-urlencoded")]);
        let mut context = context(&headers);
        context.set_body(b"user=admin&token=a%20b");
        assert_eq!(
            extract(&context, Variable::ArgsPost(None)),
            vec!["admin", "a b"]
        );
        assert_eq!(
            extract(&context, Variable::Args(None)),
            vec!["<script>", "2", "admin", "a b"]
        );
    }

    #[test]
    fn does_not_parse_multipart_body() {
        let headers = header_map(&[("content-type", "multipart/form-data; boundary=x")]);
        let mut context = context(&headers);
        context.set_body(b"user=admin");
        assert!(extract(&context, Variable::ArgsPost(None)).is_empty());
        assert_eq!(extract(&context, Variable::RequestBody), vec!["user=admin"]);
    }

    #[test]
    fn extracts_headers_case_insensitively_with_duplicates() {
        let headers = header_map(&[("X-Test", "one"), ("x-test", "two")]);
        let context = context(&headers);
        assert_eq!(
            extract(
                &context,
                Variable::RequestHeaders(Some(Selector::Literal("X-TEST".into())))
            ),
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
            extract(
                &context,
                Variable::RequestCookies(Some(Selector::Literal("session".into())))
            ),
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
            extract(
                &context,
                Variable::Tx(Some(Selector::Literal("SCORE".into())))
            ),
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
    fn extracts_extended_request_metadata() {
        let headers = header_map(&[
            ("x-a", "1"),
            ("x-b", "2"),
            ("cookie", "session=abc; theme=dark"),
        ]);
        let mut context = context(&headers);
        assert_eq!(
            extract(&context, Variable::RequestUriRaw),
            vec!["/search?q=%3Cscript%3E&page=2"]
        );
        assert_eq!(
            extract(&context, Variable::RequestLine),
            vec!["POST /search?q=%3Cscript%3E&page=2 HTTP/1.1"]
        );
        assert_eq!(
            extract(&context, Variable::RequestProtocol),
            vec!["HTTP/1.1"]
        );
        assert_eq!(extract(&context, Variable::RequestBasename), vec!["search"]);
        let header_names = extract(&context, Variable::RequestHeadersNames);
        assert!(header_names.contains(&"x-a".to_string()));
        assert!(header_names.contains(&"x-b".to_string()));
        assert_eq!(
            extract(&context, Variable::RequestCookiesNames),
            vec!["session", "theme"]
        );
        assert_eq!(extract(&context, Variable::RequestBodyLength), vec!["0"]);
        context.set_body(b"abc");
        assert_eq!(extract(&context, Variable::RequestBodyLength), vec!["3"]);
    }

    #[test]
    fn extracts_args_selectors() {
        let headers = header_map(&[("content-type", "application/x-www-form-urlencoded")]);
        let mut context = context(&headers);
        context.set_body(b"q=body&x=1");
        assert_eq!(
            extract(
                &context,
                Variable::ArgsGet(Some(Selector::Literal("q".into())))
            ),
            vec!["<script>"]
        );
        assert_eq!(
            extract(
                &context,
                Variable::ArgsPost(Some(Selector::Literal("x".into())))
            ),
            vec!["1"]
        );
        assert_eq!(
            extract(
                &context,
                Variable::Args(Some(Selector::Literal("x".into())))
            ),
            vec!["1"]
        );
    }

    #[test]
    fn extracts_xml_values() {
        let headers = header_map(&[("content-type", "application/xml")]);
        let mut context = context(&headers);
        context.set_body(b"<root><a>attack</a><b x=\"y\"/></root>");
        let values = extract(
            &context,
            Variable::Xml(Some(Selector::Literal("/*".into()))),
        );
        assert!(values.contains(&"attack".to_string()));
        assert!(values.contains(&"y".to_string()));
    }

    #[test]
    fn extracts_response_variables() {
        let headers = header_map(&[("content-type", "text/html"), ("x-test", "one")]);
        let mut context = context(&headers);
        context.set_response_headers(404, &headers);
        assert_eq!(extract(&context, Variable::ResponseStatus), vec!["404"]);
        assert_eq!(
            extract(&context, Variable::ResponseContentType),
            vec!["text/html"]
        );
        assert_eq!(
            extract(
                &context,
                Variable::ResponseHeaders(Some(Selector::Literal("X-Test".into())))
            ),
            vec!["one"]
        );
        let mut response_header_names = extract(&context, Variable::ResponseHeadersNames);
        response_header_names.sort();
        assert_eq!(response_header_names, vec!["content-type", "x-test"]);
        context.set_response_body(b"not found");
        assert_eq!(extract(&context, Variable::ResponseBody), vec!["not found"]);
        assert_eq!(extract(&context, Variable::ResponseBodyLength), vec!["9"]);
    }

    #[test]
    fn extracts_multipart_files() {
        let headers = header_map(&[("content-type", "multipart/form-data; boundary=X")]);
        let mut context = context(&headers);
        let body = b"--X\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nfile-content\r\n--X\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\nvalue\r\n--X--\r\n";
        context.set_body(body);
        assert_eq!(extract(&context, Variable::Files), vec!["file-content"]);
        assert_eq!(extract(&context, Variable::FilesNames), vec!["file"]);
        assert_eq!(extract(&context, Variable::FilesSizes), vec!["12"]);
        assert_eq!(extract(&context, Variable::FilesCombinedSize), vec!["12"]);
        assert!(extract(&context, Variable::FilesTmpnames).is_empty());
    }

    #[test]
    fn caches_non_tx_extractions_and_clears_on_body_change() {
        let headers = header_map(&[]);
        let mut context = context(&headers);
        let first = context.extract(&Variable::ArgsGet(None));
        let second = context.extract(&Variable::ArgsGet(None));
        assert!(Arc::ptr_eq(&first, &second));

        context.set_body(b"q=body");
        let after = context.extract(&Variable::ArgsGet(None));
        assert!(!Arc::ptr_eq(&first, &after));
    }
}
