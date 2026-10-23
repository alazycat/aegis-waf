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
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Variable {
    RequestUri,
    RequestMethod,
    QueryString,
    RequestFilename,
    RequestHeaders(Option<String>),
    Args,
    ArgsGet,
    ArgsPost,
    ArgsNames,
    RequestCookies(Option<String>),
    RequestBody,
    RemoteAddr,
    Tx(Option<String>),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetVar {
    pub name: String,
    pub op: SetVarOp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disruptive {
    Deny { status: u16 },
    Allow,
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
    pub prefilter: Option<Prefilter>,
}

impl CompiledRules {
    pub fn prefilter_stats(&self) -> PrefilterStats {
        let mut stats = PrefilterStats::default();
        for group in self.phase1.iter().chain(self.phase2.iter()) {
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
