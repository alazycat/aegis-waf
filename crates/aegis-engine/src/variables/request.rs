use std::cell::RefCell;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use http::HeaderMap;

use crate::collections::{MemoryCollectionStore, SharedCollectionStore};
use crate::model::{BodyProcessor, PrefilterScope, Selector, Variable};

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
    pub unique_id: &'a str,
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
    headers: Vec<String>,
    data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseLimits {
    pub max_args: usize,
    pub max_multipart_parts: usize,
    pub max_multipart_part_headers: usize,
    pub max_xml_depth: usize,
    pub max_xml_values: usize,
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            max_args: 10_000,
            max_multipart_parts: 1_000,
            max_multipart_part_headers: 64,
            max_xml_depth: 64,
            max_xml_values: 10_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BodyParseError {
    #[error("too many request arguments")]
    TooManyArgs,
    #[error("too many multipart parts")]
    TooManyMultipartParts,
    #[error("too many multipart part headers")]
    TooManyMultipartHeaders,
    #[error("xml nesting too deep")]
    XmlTooDeep,
    #[error("too many xml values")]
    TooManyXmlValues,
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
    unique_id: String,
    body_text: String,
    body_len: usize,
    body_available: bool,
    body_processor: BodyProcessor,
    body_processor_override: Option<BodyProcessor>,
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
    matched_entries: Vec<VariableEntry>,
    parse_limits: ParseLimits,
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
            path: decode_path(view.path),
            query: view.query.map(str::to_string),
            protocol: view.protocol.to_string(),
            headers,
            query_pairs,
            body_pairs: Vec::new(),
            cookies,
            remote_addr: view.remote_addr,
            unique_id: view.unique_id.to_string(),
            body_text: String::new(),
            body_len: 0,
            body_available: false,
            body_processor: BodyProcessor::None,
            body_processor_override: None,
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
            matched_entries: Vec::new(),
            parse_limits: ParseLimits::default(),
            cache: RefCell::new(HashMap::new()),
        }
    }

    pub fn record_match(&mut self, name: &str, key: Option<&str>, value: &str) {
        self.matched_entries.push(VariableEntry {
            name: name.to_string(),
            key: key.map(str::to_string),
            value: value.to_string(),
        });
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

    pub fn set_parse_limits(&mut self, limits: ParseLimits) {
        self.parse_limits = limits;
    }

    pub fn set_body(&mut self, body: &[u8]) -> Result<(), BodyParseError> {
        self.body_len = body.len();
        self.body_text = String::from_utf8_lossy(body).into_owned();
        self.body_processor = self
            .body_processor_override
            .unwrap_or_else(|| derive_body_processor(&self.headers));
        self.body_available = !matches!(self.body_processor, BodyProcessor::Xml);
        self.body_pairs = Vec::new();
        self.multipart_parts = Vec::new();
        self.xml_values = Vec::new();
        self.cache.borrow_mut().clear();

        let result = match self.body_processor {
            BodyProcessor::UrlEncoded => {
                let mut pairs = Vec::new();
                for (name, value) in form_urlencoded::parse(body) {
                    if pairs.len() >= self.parse_limits.max_args {
                        return Err(BodyParseError::TooManyArgs);
                    }
                    pairs.push((name.into_owned(), value.into_owned()));
                }
                self.body_pairs = pairs;
                Ok(())
            }
            BodyProcessor::Multipart => {
                if let Some(boundary) = multipart_boundary(&self.headers) {
                    let parts = parse_multipart(body, &boundary, &self.parse_limits)?;
                    let mut body_pairs = Vec::new();
                    for part in &parts {
                        if part.filename.is_none() {
                            if body_pairs.len() >= self.parse_limits.max_args {
                                return Err(BodyParseError::TooManyArgs);
                            }
                            body_pairs.push((
                                part.name.clone(),
                                String::from_utf8_lossy(&part.data).into_owned(),
                            ));
                        }
                    }
                    self.multipart_parts = parts;
                    self.body_pairs = body_pairs;
                }
                Ok(())
            }
            BodyProcessor::Xml => {
                self.xml_values = extract_xml_values(&self.body_text, &self.parse_limits)?;
                Ok(())
            }
            BodyProcessor::Json | BodyProcessor::None => Ok(()),
        };
        self.cache.borrow_mut().clear();
        result
    }

    pub fn set_body_processor_override(&mut self, processor: BodyProcessor) {
        self.body_processor_override = Some(processor);
    }

    pub fn body_processor(&self) -> BodyProcessor {
        self.body_processor
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

    pub fn expand_macros(&self, template: &str) -> String {
        let remote_addr = self.remote_addr.to_string();
        let mut output = String::with_capacity(template.len());
        let mut rest = template;
        while let Some(start) = rest.find("%{") {
            output.push_str(&rest[..start]);
            let after = &rest[start + 2..];
            let Some(end) = after.find('}') else {
                output.push_str(&rest[start..]);
                return output;
            };
            let name = after[..end].trim().to_ascii_lowercase();
            if let Some(tx_name) = name.strip_prefix("tx.") {
                if let Some(value) = self.tx.get(tx_name) {
                    output.push_str(value);
                }
            } else if let Some(header) = name.strip_prefix("request_headers.") {
                if let Some((_, value)) = self
                    .headers
                    .iter()
                    .find(|(header_name, _)| header_name.eq_ignore_ascii_case(header))
                {
                    output.push_str(value);
                }
            } else if let Some(cookie) = name.strip_prefix("request_cookies.") {
                if let Some((_, value)) = self
                    .cookies
                    .iter()
                    .find(|(cookie_name, _)| cookie_name.eq_ignore_ascii_case(cookie))
                {
                    output.push_str(value);
                }
            } else {
                let value = match name.as_str() {
                    "remote_addr" => Some(remote_addr.as_str()),
                    "request_method" => Some(self.method.as_str()),
                    "request_uri" | "request_uri_raw" => Some(self.uri.as_str()),
                    "request_filename" => Some(self.path.as_str()),
                    "request_basename" => Some(
                        self.path
                            .rsplit('/')
                            .find(|segment| !segment.is_empty())
                            .unwrap_or(""),
                    ),
                    "query_string" => self.query.as_deref(),
                    "request_protocol" => Some(self.protocol.as_str()),
                    "request_body" if self.body_available => Some(self.body_text.as_str()),
                    "matched_var" | "matched_var_name" => self.tx.get(&name),
                    _ => None,
                };
                if let Some(value) = value {
                    output.push_str(value);
                }
            }
            rest = &after[end + 1..];
        }
        output.push_str(rest);
        output
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
                | Variable::Count(_)
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
            Variable::ArgsNames(selector) => self
                .query_pairs
                .iter()
                .chain(self.body_pairs.iter())
                .filter(|(name, _)| name_matches(selector, name))
                .map(|(name, _)| VariableEntry::item("ARGS_NAMES", name, name.clone()))
                .collect(),
            Variable::ArgsGetNames => self
                .query_pairs
                .iter()
                .map(|(name, _)| VariableEntry::item("ARGS_GET_NAMES", name, name.clone()))
                .collect(),
            Variable::ArgsCombinedSize => vec![VariableEntry::scalar(
                variable,
                self.query_pairs
                    .iter()
                    .chain(self.body_pairs.iter())
                    .map(|(name, value)| name.len() + value.len())
                    .sum::<usize>()
                    .to_string(),
            )],
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
            Variable::RequestBody => {
                if self.body_available {
                    vec![VariableEntry::scalar(variable, self.body_text.clone())]
                } else {
                    Vec::new()
                }
            }
            Variable::RequestBodyLength => {
                vec![VariableEntry::scalar(variable, self.body_len.to_string())]
            }
            Variable::MultipartPartHeaders(selector) => self
                .multipart_parts
                .iter()
                .filter(|part| name_matches(selector, &part.name))
                .flat_map(|part| {
                    part.headers.iter().map(move |header| {
                        VariableEntry::item("MULTIPART_PART_HEADERS", &part.name, header.clone())
                    })
                })
                .collect(),
            Variable::ReqbodyProcessor => {
                let name = self.body_processor.name();
                if name.is_empty() {
                    Vec::new()
                } else {
                    vec![VariableEntry::scalar(variable, name.to_string())]
                }
            }
            Variable::Files => self
                .multipart_parts
                .iter()
                .filter(|part| part.filename.is_some())
                .map(|part| VariableEntry::item("FILES", &part.name, part.name.clone()))
                .collect(),
            Variable::FilesNames => self
                .multipart_parts
                .iter()
                .filter_map(|part| part.filename.as_ref())
                .map(|filename| VariableEntry::item("FILES_NAMES", filename, filename.clone()))
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
            Variable::UniqueId => vec![VariableEntry::scalar(variable, self.unique_id.clone())],
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
            Variable::MatchedVars(selector) => self
                .matched_entries
                .iter()
                .filter(|entry| name_matches(selector, &entry.name))
                .cloned()
                .collect(),
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
                .filter(|(name, _)| tx_name_matches(selector, name))
                .map(|(name, value)| VariableEntry::item("TX", name, value.to_string()))
                .collect(),
            Variable::Count(inner) => {
                let count = self.extract(inner).len();
                vec![VariableEntry {
                    name: variable.display_name(),
                    key: None,
                    value: count.to_string(),
                }]
            }
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

fn tx_name_matches(selector: &Option<Selector>, name: &str) -> bool {
    match selector {
        None => true,
        Some(Selector::Literal(value)) => name.eq_ignore_ascii_case(value),
        Some(Selector::Regex(regex)) => regex.is_match_ignore_case(name),
    }
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

fn derive_body_processor(headers: &[(String, String)]) -> BodyProcessor {
    let Some(content_type) = headers
        .iter()
        .find(|(name, _)| name == "content-type")
        .map(|(_, value)| value.to_ascii_lowercase())
    else {
        return BodyProcessor::None;
    };
    if content_type.starts_with("application/x-www-form-urlencoded") {
        BodyProcessor::UrlEncoded
    } else if content_type.starts_with("multipart/form-data") {
        BodyProcessor::Multipart
    } else if content_type.starts_with("application/json") || content_type.contains("+json") {
        BodyProcessor::Json
    } else if content_type.starts_with("application/xml")
        || content_type.starts_with("text/xml")
        || content_type.contains("+xml")
    {
        BodyProcessor::Xml
    } else {
        BodyProcessor::None
    }
}

fn decode_path(path: &str) -> String {
    if !path.contains('%') {
        return path.to_string();
    }
    let bytes = path.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
            {
                output.push(high * 16 + low);
                index += 3;
                continue;
            }
        }
        output.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
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

fn parse_multipart(
    body: &[u8],
    boundary: &str,
    limits: &ParseLimits,
) -> Result<Vec<MultipartPart>, BodyParseError> {
    let delimiter = format!("--{boundary}").into_bytes();
    let next_delimiter = format!("\r\n--{boundary}").into_bytes();
    let mut parts = Vec::new();
    let mut part_count = 0usize;
    let mut position = 0usize;

    while let Some(start) = find_subslice(&body[position..], &delimiter) {
        let mut cursor = position + start + delimiter.len();
        if body.get(cursor..cursor + 2) == Some(b"--") {
            break;
        }
        part_count += 1;
        if part_count > limits.max_multipart_parts {
            return Err(BodyParseError::TooManyMultipartParts);
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
        let headers: Vec<String> = headers_text
            .lines()
            .map(str::trim_end)
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect();
        if headers.len() > limits.max_multipart_part_headers {
            return Err(BodyParseError::TooManyMultipartHeaders);
        }
        let data_start = cursor + header_end + 4;
        let Some(next) = find_subslice(&body[data_start..], &next_delimiter) else {
            break;
        };
        let data_end = data_start + next;
        if let Some((name, filename)) = parse_part_disposition(&headers_text) {
            parts.push(MultipartPart {
                name,
                filename,
                headers,
                data: body[data_start..data_end].to_vec(),
            });
        }
        position = data_end + 2;
    }
    Ok(parts)
}

fn parse_part_disposition(headers: &str) -> Option<(String, Option<String>)> {
    let disposition = headers.lines().find(|line| {
        line.to_ascii_lowercase()
            .starts_with("content-disposition:")
    })?;
    let rest = disposition.split_once(':')?.1;
    let mut name = None;
    let mut filename = None;
    for part in split_quoted(rest, ';') {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = unquote_param(value.trim());
        match key.as_str() {
            "name" => name = Some(value),
            "filename" => filename = Some(value),
            _ => {}
        }
    }
    name.map(|name| (name, filename))
}

fn split_quoted(input: &str, delimiter: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quote: Option<char> = None;
    for (index, ch) in input.char_indices() {
        match quote {
            Some(open) if ch == open => quote = None,
            Some(_) => {}
            None if ch == '"' || ch == '\'' => quote = Some(ch),
            None if ch == delimiter => {
                parts.push(&input[start..index]);
                start = index + ch.len_utf8();
            }
            None => {}
        }
    }
    parts.push(&input[start..]);
    parts
}

fn unquote_param(value: &str) -> String {
    let value = value.trim();
    let quoted = value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')));
    if !quoted {
        return value.to_string();
    }
    value[1..value.len() - 1].to_string()
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn extract_xml_values(text: &str, limits: &ParseLimits) -> Result<Vec<String>, BodyParseError> {
    let Ok(document) = roxmltree::Document::parse(text) else {
        return Ok(Vec::new());
    };
    let mut values = Vec::new();
    for node in document.descendants() {
        let depth = node.ancestors().filter(|node| node.is_element()).count();
        if depth > limits.max_xml_depth {
            return Err(BodyParseError::XmlTooDeep);
        }
        for child in node.children() {
            if child.is_text() {
                if let Some(text) = child.text() {
                    let text = text.trim();
                    if !text.is_empty() {
                        if values.len() >= limits.max_xml_values {
                            return Err(BodyParseError::TooManyXmlValues);
                        }
                        values.push(text.to_string());
                    }
                }
            }
        }
        for attribute in node.attributes() {
            if values.len() >= limits.max_xml_values {
                return Err(BodyParseError::TooManyXmlValues);
            }
            values.push(attribute.value().to_string());
        }
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue};

    use super::*;
    use crate::model::{RegexSelector, Variable};

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
            unique_id: "test-unique-id",
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
    fn extracts_unique_id() {
        let headers = header_map(&[]);
        let context = context(&headers);
        assert_eq!(
            extract(&context, Variable::UniqueId),
            vec!["test-unique-id"]
        );
    }

    #[test]
    fn args_names_selector_filters_names() {
        let headers = header_map(&[]);
        let context = context(&headers);
        let selector = Selector::Regex(RegexSelector::new("^q$").unwrap());
        assert_eq!(
            extract(&context, Variable::ArgsNames(Some(selector))),
            vec!["q"]
        );
    }

    #[test]
    fn regex_selector_filters_cookie_names() {
        let headers = header_map(&[("cookie", "_ga=1; session=abc; _gid=2")]);
        let context = context(&headers);
        let selector = Selector::Regex(RegexSelector::new("^_ga").unwrap());
        let entries = context.extract(&Variable::RequestCookies(Some(selector)));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key.as_deref(), Some("_ga"));
    }

    #[test]
    fn entries_carry_precise_names_and_keys() {
        let headers = header_map(&[]);
        let context = context(&headers);
        let entries = context.extract(&Variable::Args(None));
        assert_eq!(entries[0].name, "ARGS:q");
        assert_eq!(entries[0].key.as_deref(), Some("q"));
        let names = context.extract(&Variable::ArgsNames(None));
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
        let mut names = extract(&context, Variable::ArgsNames(None));
        names.sort();
        assert_eq!(names, vec!["page", "q"]);
    }

    #[test]
    fn extracts_args_get_names_and_combined_size() {
        let headers = header_map(&[("content-type", "application/x-www-form-urlencoded")]);
        let mut context = context(&headers);
        context.set_body(b"x=1").unwrap();
        assert_eq!(extract(&context, Variable::ArgsGetNames), vec!["q", "page"]);
        assert_eq!(extract(&context, Variable::ArgsCombinedSize), vec!["16"]);
    }

    #[test]
    fn extracts_form_body_only_for_urlencoded() {
        let headers = header_map(&[("content-type", "application/x-www-form-urlencoded")]);
        let mut context = context(&headers);
        context.set_body(b"user=admin&token=a%20b").unwrap();
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
        context.set_body(b"user=admin").unwrap();
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
        context.set_body(&[0x66, 0x6f, 0x80, 0x6f]).unwrap();
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
        context.set_body(b"abc").unwrap();
        assert_eq!(extract(&context, Variable::RequestBodyLength), vec!["3"]);
    }

    #[test]
    fn extracts_args_selectors() {
        let headers = header_map(&[("content-type", "application/x-www-form-urlencoded")]);
        let mut context = context(&headers);
        context.set_body(b"q=body&x=1").unwrap();
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
        context
            .set_body(b"<root><a>attack</a><b x=\"y\"/></root>")
            .unwrap();
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
        context.set_body(body).unwrap();
        assert_eq!(extract(&context, Variable::Files), vec!["file"]);
        assert_eq!(extract(&context, Variable::FilesNames), vec!["a.txt"]);
        assert_eq!(extract(&context, Variable::FilesSizes), vec!["12"]);
        assert_eq!(extract(&context, Variable::FilesCombinedSize), vec!["12"]);
        assert!(extract(&context, Variable::FilesTmpnames).is_empty());
    }

    #[test]
    fn extracts_multipart_part_headers_and_form_fields() {
        let headers = header_map(&[("content-type", "multipart/form-data; boundary=X")]);
        let mut context = context(&headers);
        let body = b"--X\r\nContent-Disposition: form-data; name=\"_charset_\"\r\nContent-Type: text/plain\r\n\r\nUTF-8\r\n--X\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n\r\nfile-content\r\n--X--\r\n";
        context.set_body(body).unwrap();
        let part_headers = context.extract(&Variable::MultipartPartHeaders(None));
        assert!(part_headers
            .iter()
            .any(|entry| entry.value.eq_ignore_ascii_case("content-type: text/plain")));
        assert_eq!(part_headers[0].key.as_deref(), Some("_charset_"));
        let charset = context.extract(&Variable::MultipartPartHeaders(Some(Selector::Literal(
            "_charset_".to_string(),
        ))));
        assert_eq!(charset.len(), 2);
        assert_eq!(extract(&context, Variable::ArgsPost(None)), vec!["UTF-8"]);
        assert_eq!(extract(&context, Variable::Files), vec!["file"]);
    }

    #[test]
    fn derives_request_body_processor() {
        let headers = header_map(&[("content-type", "application/json")]);
        let mut context = context(&headers);
        context.set_body(b"{\"a\":1}").unwrap();
        assert_eq!(context.body_processor(), BodyProcessor::Json);
        assert!(extract(&context, Variable::ArgsPost(None)).is_empty());
        assert_eq!(extract(&context, Variable::RequestBody), vec!["{\"a\":1}"]);
        assert_eq!(extract(&context, Variable::ReqbodyProcessor), vec!["JSON"]);
    }

    #[test]
    fn missing_content_type_does_not_parse_args() {
        let headers = header_map(&[]);
        let mut context = context(&headers);
        context.set_body(b"a=1&b=2").unwrap();
        assert_eq!(context.body_processor(), BodyProcessor::None);
        assert!(extract(&context, Variable::ArgsPost(None)).is_empty());
        assert_eq!(extract(&context, Variable::RequestBody), vec!["a=1&b=2"]);
    }

    #[test]
    fn caches_non_tx_extractions_and_clears_on_body_change() {
        let headers = header_map(&[]);
        let mut context = context(&headers);
        let first = context.extract(&Variable::ArgsGet(None));
        let second = context.extract(&Variable::ArgsGet(None));
        assert!(Arc::ptr_eq(&first, &second));

        context.set_body(b"q=body").unwrap();
        let after = context.extract(&Variable::ArgsGet(None));
        assert!(!Arc::ptr_eq(&first, &after));
    }

    #[test]
    fn multipart_disposition_params_respect_quotes() {
        let headers = header_map(&[("content-type", "multipart/form-data; boundary=X")]);
        let mut context = context(&headers);
        let body = b"--X\r\nContent-Disposition: form-data; name=\"fi;le\"; filename=\"te;st.txt\"\r\nContent-Type: text/plain\r\n\r\nvalue\r\n--X--\r\n";
        context.set_body(body).unwrap();
        assert_eq!(extract(&context, Variable::Files), vec!["fi;le"]);
        assert_eq!(extract(&context, Variable::FilesNames), vec!["te;st.txt"]);
    }

    #[test]
    fn tx_regex_selector_is_case_insensitive() {
        let headers = header_map(&[]);
        let mut context = context(&headers);
        context.tx_mut().set(
            "multipart_headers_content_types_1",
            "text/plain".to_string(),
        );
        let selector =
            Selector::Regex(RegexSelector::new("MULTIPART_HEADERS_CONTENT_TYPES_*").unwrap());
        assert_eq!(
            extract(&context, Variable::Tx(Some(selector))),
            vec!["text/plain"]
        );
    }

    #[test]
    fn expands_request_macros() {
        let headers = header_map(&[("Host", "localhost"), ("Referer", "http://x/")]);
        let context = context(&headers);
        assert_eq!(
            context.expand_macros("%{request_headers.host}"),
            "localhost"
        );
        assert_eq!(context.expand_macros("%{request_method}"), "POST");
        assert_eq!(context.expand_macros("%{request_filename}"), "/search");
        assert_eq!(context.expand_macros("%{remote_addr}"), "203.0.113.7");
    }

    #[test]
    fn request_filename_is_url_decoded() {
        let headers = header_map(&[]);
        let view = RequestView {
            method: "GET",
            uri: "/path/with/if%20exist%20StorageServer.port%20echo%20yay",
            path: "/path/with/if%20exist%20StorageServer.port%20echo%20yay",
            query: None,
            protocol: "HTTP/1.1",
            headers: &headers,
            body: b"",
            remote_addr: "203.0.113.7".parse().unwrap(),
            unique_id: "test-unique-id",
        };
        let context = RequestContext::new(&view);
        assert_eq!(
            extract(&context, Variable::RequestFilename),
            vec!["/path/with/if exist StorageServer.port echo yay"]
        );
        assert_eq!(
            extract(&context, Variable::RequestBasename),
            vec!["if exist StorageServer.port echo yay"]
        );
    }

    #[test]
    fn urlencoded_body_over_max_args_is_rejected() {
        let headers = header_map(&[("content-type", "application/x-www-form-urlencoded")]);
        let mut context = context(&headers);
        context.set_parse_limits(ParseLimits {
            max_args: 2,
            ..ParseLimits::default()
        });
        assert!(context.set_body(b"a=1&b=2").is_ok());
        assert_eq!(
            context.set_body(b"a=1&b=2&c=3"),
            Err(BodyParseError::TooManyArgs)
        );
    }

    #[test]
    fn multipart_part_count_limit_is_enforced() {
        let headers = header_map(&[("content-type", "multipart/form-data; boundary=X")]);
        let mut context = context(&headers);
        context.set_parse_limits(ParseLimits {
            max_multipart_parts: 1,
            ..ParseLimits::default()
        });
        let one_part = b"--X\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--X--\r\n";
        assert!(context.set_body(one_part).is_ok());
        let two_parts = b"--X\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--X\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\n2\r\n--X--\r\n";
        assert_eq!(
            context.set_body(two_parts),
            Err(BodyParseError::TooManyMultipartParts)
        );
    }

    #[test]
    fn multipart_header_count_limit_is_enforced() {
        let headers = header_map(&[("content-type", "multipart/form-data; boundary=X")]);
        let mut context = context(&headers);
        context.set_parse_limits(ParseLimits {
            max_multipart_part_headers: 2,
            ..ParseLimits::default()
        });
        let body = b"--X\r\nContent-Disposition: form-data; name=\"a\"\r\nContent-Type: text/plain\r\nX-Test: 1\r\n\r\nvalue\r\n--X--\r\n";
        assert_eq!(
            context.set_body(body),
            Err(BodyParseError::TooManyMultipartHeaders)
        );
    }

    #[test]
    fn xml_depth_limit_is_enforced() {
        let headers = header_map(&[("content-type", "application/xml")]);
        let mut context = context(&headers);
        context.set_parse_limits(ParseLimits {
            max_xml_depth: 2,
            ..ParseLimits::default()
        });
        assert_eq!(
            context.set_body(b"<a><b><c>x</c></b></a>"),
            Err(BodyParseError::XmlTooDeep)
        );
        context.set_parse_limits(ParseLimits {
            max_xml_depth: 3,
            ..ParseLimits::default()
        });
        assert!(context.set_body(b"<a><b><c>x</c></b></a>").is_ok());
    }

    #[test]
    fn xml_value_count_limit_is_enforced() {
        let headers = header_map(&[("content-type", "application/xml")]);
        let mut context = context(&headers);
        context.set_parse_limits(ParseLimits {
            max_xml_values: 1,
            ..ParseLimits::default()
        });
        assert_eq!(
            context.set_body(b"<a><b>1</b><b>2</b></a>"),
            Err(BodyParseError::TooManyXmlValues)
        );
        context.set_parse_limits(ParseLimits {
            max_xml_values: 2,
            ..ParseLimits::default()
        });
        assert!(context.set_body(b"<a><b>1</b><b>2</b></a>").is_ok());
    }

    #[test]
    fn json_body_ignores_parse_limits() {
        let headers = header_map(&[("content-type", "application/json")]);
        let mut context = context(&headers);
        context.set_parse_limits(ParseLimits {
            max_args: 1,
            ..ParseLimits::default()
        });
        assert!(context.set_body(b"{\"a\":1,\"b\":2}").is_ok());
    }
}
