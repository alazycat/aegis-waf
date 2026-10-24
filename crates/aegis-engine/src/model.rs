use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

pub use crate::operators::{CompiledOperator, NumberArg};
pub use crate::transforms::Transform;

#[derive(Debug, Clone)]
pub struct RegexSelector {
    pattern: String,
    regex: regex::Regex,
}

impl RegexSelector {
    pub fn new(pattern: &str) -> Result<Self, regex::Error> {
        Ok(Self {
            pattern: pattern.to_string(),
            regex: regex::Regex::new(pattern)?,
        })
    }

    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    pub fn is_match(&self, key: &str) -> bool {
        self.regex.is_match(key)
    }
}

impl PartialEq for RegexSelector {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern
    }
}

impl Eq for RegexSelector {}

impl std::hash::Hash for RegexSelector {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.pattern.hash(state);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Selector {
    Literal(String),
    Regex(RegexSelector),
}

impl Selector {
    pub fn matches(&self, key: &str) -> bool {
        match self {
            Self::Literal(value) => value.eq_ignore_ascii_case(key),
            Self::Regex(regex) => regex.is_match(key),
        }
    }

    pub fn as_display(&self) -> String {
        match self {
            Self::Literal(value) => value.clone(),
            Self::Regex(regex) => format!("/{}/", regex.pattern()),
        }
    }
}

fn selected(prefix: &str, selector: &Option<Selector>) -> String {
    match selector {
        Some(selector) => format!("{prefix}:{}", selector.as_display()),
        None => prefix.to_string(),
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PrefilterScope {
    pub request_line: bool,
    pub headers: bool,
    pub query: bool,
    pub body: bool,
    pub cookies: bool,
}

impl PrefilterScope {
    pub fn merge(self, other: Self) -> Self {
        Self {
            request_line: self.request_line || other.request_line,
            headers: self.headers || other.headers,
            query: self.query || other.query,
            body: self.body || other.body,
            cookies: self.cookies || other.cookies,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Prefilter {
    pub variants: Vec<PrefilterVariant>,
}

#[derive(Debug, Clone)]
pub struct PrefilterVariant {
    pub matcher: Option<Arc<aho_corasick::AhoCorasick>>,
    pub regex_set: Option<Arc<regex::RegexSet>>,
    pub ac_pattern_count: usize,
    pub regex_pattern_count: usize,
    pub scope: PrefilterScope,
    pub transforms: Vec<Transform>,
}

#[derive(Debug, Clone)]
pub struct RulePrefilter {
    pub variant: usize,
    pub ac_patterns: Vec<usize>,
    pub regex_pattern: Option<usize>,
}

#[derive(Debug, Clone, Default)]
pub struct PrefilterHits {
    pub ac: Vec<bool>,
    pub regex: Vec<bool>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PrefilterStats {
    pub total_groups: usize,
    pub prefiltered_groups: usize,
    pub ac_groups: usize,
    pub regex_groups: usize,
    pub total_rules: usize,
    pub prefiltered_rules: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Phase1,
    Phase2,
    Phase3,
    Phase4,
    Phase5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyProcessor {
    UrlEncoded,
    Multipart,
    Json,
    Xml,
    None,
}

impl BodyProcessor {
    pub fn parse_name(raw: &str) -> Option<Self> {
        match raw.to_ascii_lowercase().as_str() {
            "urlencoded" => Some(Self::UrlEncoded),
            "multipart" => Some(Self::Multipart),
            "json" => Some(Self::Json),
            "xml" => Some(Self::Xml),
            "none" => Some(Self::None),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::UrlEncoded => "URLENCODED",
            Self::Multipart => "MULTIPART",
            Self::Json => "JSON",
            Self::Xml => "XML",
            Self::None => "",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Variable {
    RequestUri,
    RequestUriRaw,
    RequestLine,
    RequestProtocol,
    RequestBasename,
    RequestMethod,
    QueryString,
    RequestFilename,
    RequestHeaders(Option<Selector>),
    RequestHeadersNames,
    Args(Option<Selector>),
    ArgsGet(Option<Selector>),
    ArgsPost(Option<Selector>),
    ArgsNames(Option<Selector>),
    ArgsGetNames,
    ArgsCombinedSize,
    RequestCookies(Option<Selector>),
    RequestCookiesNames,
    RequestBody,
    RequestBodyLength,
    MultipartPartHeaders(Option<Selector>),
    ReqbodyProcessor,
    Files,
    FilesNames,
    FilesSizes,
    FilesCombinedSize,
    FilesTmpnames,
    Ip(Option<Selector>),
    Session(Option<Selector>),
    User(Option<Selector>),
    Global(Option<Selector>),
    RemoteAddr,
    UniqueId,
    MatchedVar,
    MatchedVarName,
    MatchedVars(Option<Selector>),
    Xml(Option<Selector>),
    ResponseStatus,
    ResponseHeaders(Option<Selector>),
    ResponseHeadersNames,
    ResponseBody,
    ResponseBodyLength,
    ResponseContentType,
    Tx(Option<Selector>),
    Count(Box<Variable>),
}

impl Variable {
    pub fn display_name(&self) -> String {
        match self {
            Self::RequestUri => "REQUEST_URI".to_string(),
            Self::RequestUriRaw => "REQUEST_URI_RAW".to_string(),
            Self::RequestLine => "REQUEST_LINE".to_string(),
            Self::RequestProtocol => "REQUEST_PROTOCOL".to_string(),
            Self::RequestBasename => "REQUEST_BASENAME".to_string(),
            Self::RequestMethod => "REQUEST_METHOD".to_string(),
            Self::QueryString => "QUERY_STRING".to_string(),
            Self::RequestFilename => "REQUEST_FILENAME".to_string(),
            Self::RequestHeaders(selector) => selected("REQUEST_HEADERS", selector),
            Self::RequestHeadersNames => "REQUEST_HEADERS_NAMES".to_string(),
            Self::Args(selector) => selected("ARGS", selector),
            Self::ArgsGet(selector) => selected("ARGS_GET", selector),
            Self::ArgsPost(selector) => selected("ARGS_POST", selector),
            Self::ArgsNames(selector) => selected("ARGS_NAMES", selector),
            Self::ArgsGetNames => "ARGS_GET_NAMES".to_string(),
            Self::ArgsCombinedSize => "ARGS_COMBINED_SIZE".to_string(),
            Self::RequestCookies(selector) => selected("REQUEST_COOKIES", selector),
            Self::RequestCookiesNames => "REQUEST_COOKIES_NAMES".to_string(),
            Self::RequestBody => "REQUEST_BODY".to_string(),
            Self::RequestBodyLength => "REQUEST_BODY_LENGTH".to_string(),
            Self::MultipartPartHeaders(selector) => selected("MULTIPART_PART_HEADERS", selector),
            Self::ReqbodyProcessor => "REQBODY_PROCESSOR".to_string(),
            Self::Files => "FILES".to_string(),
            Self::FilesNames => "FILES_NAMES".to_string(),
            Self::FilesSizes => "FILES_SIZES".to_string(),
            Self::FilesCombinedSize => "FILES_COMBINED_SIZE".to_string(),
            Self::FilesTmpnames => "FILES_TMPNAMES".to_string(),
            Self::Ip(selector) => selected("IP", selector),
            Self::Session(selector) => selected("SESSION", selector),
            Self::User(selector) => selected("USER", selector),
            Self::Global(selector) => selected("GLOBAL", selector),
            Self::RemoteAddr => "REMOTE_ADDR".to_string(),
            Self::UniqueId => "UNIQUE_ID".to_string(),
            Self::MatchedVar => "MATCHED_VAR".to_string(),
            Self::MatchedVarName => "MATCHED_VAR_NAME".to_string(),
            Self::MatchedVars(selector) => selected("MATCHED_VARS", selector),
            Self::Xml(selector) => selected("XML", selector),
            Self::ResponseStatus => "RESPONSE_STATUS".to_string(),
            Self::ResponseHeaders(selector) => selected("RESPONSE_HEADERS", selector),
            Self::ResponseHeadersNames => "RESPONSE_HEADERS_NAMES".to_string(),
            Self::ResponseBody => "RESPONSE_BODY".to_string(),
            Self::ResponseBodyLength => "RESPONSE_BODY_LENGTH".to_string(),
            Self::ResponseContentType => "RESPONSE_CONTENT_TYPE".to_string(),
            Self::Tx(selector) => selected("TX", selector),
            Self::Count(inner) => format!("&{}", inner.display_name()),
        }
    }

    pub fn selector(&self) -> Option<&Selector> {
        match self {
            Self::RequestHeaders(selector)
            | Self::Args(selector)
            | Self::ArgsGet(selector)
            | Self::ArgsPost(selector)
            | Self::ArgsNames(selector)
            | Self::RequestCookies(selector)
            | Self::MultipartPartHeaders(selector)
            | Self::Ip(selector)
            | Self::Session(selector)
            | Self::User(selector)
            | Self::Global(selector)
            | Self::MatchedVars(selector)
            | Self::Xml(selector)
            | Self::ResponseHeaders(selector)
            | Self::Tx(selector) => selector.as_ref(),
            Self::Count(inner) => inner.selector(),
            _ => None,
        }
    }

    pub fn same_family(&self, other: &Self) -> bool {
        let left = self.unwrap_count();
        let right = other.unwrap_count();
        std::mem::discriminant(left) == std::mem::discriminant(right)
    }

    fn unwrap_count(&self) -> &Self {
        let mut current = self;
        while let Self::Count(inner) = current {
            current = inner;
        }
        current
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariableSpec {
    pub variable: Variable,
    pub negated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetVarOp {
    Assign(String),
    Add(String),
    Sub(String),
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetVarScope {
    Tx,
    Ip,
    Session,
    User,
    Global,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetVar {
    pub scope: SetVarScope,
    pub name: String,
    pub op: SetVarOp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disruptive {
    Deny { status: u16 },
    Allow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleEngineMode {
    On,
    Off,
    DetectionOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleIdRange {
    pub start: u32,
    pub end: u32,
}

impl RuleIdRange {
    pub fn contains(self, id: u32) -> bool {
        self.start <= id && id <= self.end
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CtlAction {
    AuditEngine(bool),
    RuleEngine(RuleEngineMode),
    RemoveRuleById(RuleIdRange),
    RemoveRuleByTag(String),
    RequestBodyProcessor(BodyProcessor),
    ForceRequestBodyVariable(bool),
    RemoveTargetById { id: u32, target: Variable },
    RemoveTargetByTag { tag: String, target: Variable },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledActions {
    pub disruptive: Option<Disruptive>,
    pub log: bool,
    pub msg: Option<String>,
    pub severity: Option<String>,
    pub tags: Vec<String>,
    pub setvars: Vec<SetVar>,
    pub logdata: Option<String>,
    pub chain: bool,
    pub capture: bool,
    pub multi_match: bool,
    pub skip_after: Option<String>,
    pub ctl: Vec<CtlAction>,
    pub init_collections: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub id: u32,
    pub phase: Phase,
    pub variables: Vec<VariableSpec>,
    pub operator: CompiledOperator,
    pub operator_negated: bool,
    pub transformations: Vec<Transform>,
    pub actions: CompiledActions,
    pub unconditional: bool,
    pub prefilter: Option<RulePrefilter>,
    pub sequence: usize,
    pub file: PathBuf,
    pub line: usize,
}

#[derive(Debug, Clone)]
pub enum RuleGroup {
    Single(Box<CompiledRule>),
    Chain(Vec<CompiledRule>),
}

#[derive(Debug, Clone)]
pub struct CompiledRules {
    pub version: u64,
    pub rule_count: usize,
    pub files: Vec<PathBuf>,
    pub phase1: Vec<RuleGroup>,
    pub phase2: Vec<RuleGroup>,
    pub phase3: Vec<RuleGroup>,
    pub phase4: Vec<RuleGroup>,
    pub phase5: Vec<RuleGroup>,
    pub markers: HashMap<String, usize>,
    pub prefilter: Option<Prefilter>,
}

impl CompiledRules {
    pub fn prefilter_stats(&self) -> PrefilterStats {
        let mut stats = PrefilterStats::default();
        for group in self
            .phase1
            .iter()
            .chain(self.phase2.iter())
            .chain(self.phase3.iter())
            .chain(self.phase4.iter())
            .chain(self.phase5.iter())
        {
            stats.total_groups += 1;
            let (first, rule_count) = match group {
                RuleGroup::Single(rule) => (rule.as_ref(), 1),
                RuleGroup::Chain(rules) => (&rules[0], rules.len()),
            };
            stats.total_rules += rule_count;
            if let Some(prefilter) = &first.prefilter {
                stats.prefiltered_groups += 1;
                stats.prefiltered_rules += rule_count;
                if !prefilter.ac_patterns.is_empty() {
                    stats.ac_groups += 1;
                }
                if prefilter.regex_pattern.is_some() {
                    stats.regex_groups += 1;
                }
            }
        }
        stats
    }
}
