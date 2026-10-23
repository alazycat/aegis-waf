use std::path::PathBuf;

pub use crate::operators::CompiledOperator;
pub use crate::transforms::Transform;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Phase1,
    Phase2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
}
