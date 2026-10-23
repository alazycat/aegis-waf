use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

pub use crate::operators::CompiledOperator;
pub use crate::transforms::Transform;

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
    RequestHeaders(Option<String>),
    RequestHeadersNames,
    Args(Option<String>),
    ArgsGet(Option<String>),
    ArgsPost(Option<String>),
    ArgsNames,
    RequestCookies(Option<String>),
    RequestCookiesNames,
    RequestBody,
    RequestBodyLength,
    Files,
    FilesNames,
    FilesSizes,
    FilesCombinedSize,
    FilesTmpnames,
    Ip(Option<String>),
    Session(Option<String>),
    User(Option<String>),
    Global(Option<String>),
    RemoteAddr,
    MatchedVar,
    MatchedVarName,
    MatchedVars,
    Xml(Option<String>),
    ResponseStatus,
    ResponseHeaders(Option<String>),
    ResponseHeadersNames,
    ResponseBody,
    ResponseBodyLength,
    ResponseContentType,
    Tx(Option<String>),
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
            Self::RequestHeaders(None) => "REQUEST_HEADERS".to_string(),
            Self::RequestHeaders(Some(name)) => format!("REQUEST_HEADERS:{name}"),
            Self::RequestHeadersNames => "REQUEST_HEADERS_NAMES".to_string(),
            Self::Args(None) => "ARGS".to_string(),
            Self::Args(Some(name)) => format!("ARGS:{name}"),
            Self::ArgsGet(None) => "ARGS_GET".to_string(),
            Self::ArgsGet(Some(name)) => format!("ARGS_GET:{name}"),
            Self::ArgsPost(None) => "ARGS_POST".to_string(),
            Self::ArgsPost(Some(name)) => format!("ARGS_POST:{name}"),
            Self::ArgsNames => "ARGS_NAMES".to_string(),
            Self::RequestCookies(None) => "REQUEST_COOKIES".to_string(),
            Self::RequestCookies(Some(name)) => format!("REQUEST_COOKIES:{name}"),
            Self::RequestCookiesNames => "REQUEST_COOKIES_NAMES".to_string(),
            Self::RequestBody => "REQUEST_BODY".to_string(),
            Self::RequestBodyLength => "REQUEST_BODY_LENGTH".to_string(),
            Self::Files => "FILES".to_string(),
            Self::FilesNames => "FILES_NAMES".to_string(),
            Self::FilesSizes => "FILES_SIZES".to_string(),
            Self::FilesCombinedSize => "FILES_COMBINED_SIZE".to_string(),
            Self::FilesTmpnames => "FILES_TMPNAMES".to_string(),
            Self::Ip(None) => "IP".to_string(),
            Self::Ip(Some(name)) => format!("IP:{name}"),
            Self::Session(None) => "SESSION".to_string(),
            Self::Session(Some(name)) => format!("SESSION:{name}"),
            Self::User(None) => "USER".to_string(),
            Self::User(Some(name)) => format!("USER:{name}"),
            Self::Global(None) => "GLOBAL".to_string(),
            Self::Global(Some(name)) => format!("GLOBAL:{name}"),
            Self::RemoteAddr => "REMOTE_ADDR".to_string(),
            Self::MatchedVar => "MATCHED_VAR".to_string(),
            Self::MatchedVarName => "MATCHED_VAR_NAME".to_string(),
            Self::MatchedVars => "MATCHED_VARS".to_string(),
            Self::Xml(None) => "XML".to_string(),
            Self::Xml(Some(selector)) => format!("XML:{selector}"),
            Self::ResponseStatus => "RESPONSE_STATUS".to_string(),
            Self::ResponseHeaders(None) => "RESPONSE_HEADERS".to_string(),
            Self::ResponseHeaders(Some(name)) => format!("RESPONSE_HEADERS:{name}"),
            Self::ResponseHeadersNames => "RESPONSE_HEADERS_NAMES".to_string(),
            Self::ResponseBody => "RESPONSE_BODY".to_string(),
            Self::ResponseBodyLength => "RESPONSE_BODY_LENGTH".to_string(),
            Self::ResponseContentType => "RESPONSE_CONTENT_TYPE".to_string(),
            Self::Tx(None) => "TX".to_string(),
            Self::Tx(Some(name)) => format!("TX:{name}"),
        }
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CtlAction {
    AuditEngine(bool),
    RuleEngine(RuleEngineMode),
    RemoveRuleById(u32),
    RemoveRuleByTag(String),
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
