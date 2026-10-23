use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::error::LoadError;
use crate::model::*;
use crate::operators::parse_ip_match;
use crate::parser::directive::{ActionAst, RuleAst};
use crate::parser::{Directive, LocatedDirective};

#[derive(Debug, Clone)]
pub struct LoadOptions {
    pub lenient: bool,
    pub version: u64,
}

impl Default for LoadOptions {
    fn default() -> Self {
        Self {
            lenient: false,
            version: 1,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct DefaultActions {
    phase: Option<Phase>,
    disruptive: Option<Disruptive>,
    disruptive_specified: bool,
    status: Option<u16>,
    log: Option<bool>,
    transforms: Vec<Transform>,
}

#[derive(Debug, Default)]
struct ParsedActions {
    id: Option<u32>,
    phase: Option<Phase>,
    disruptive: Option<Disruptive>,
    disruptive_specified: bool,
    block_requested: bool,
    status: Option<u16>,
    log: Option<bool>,
    msg: Option<String>,
    severity: Option<String>,
    tags: Vec<String>,
    transforms: Vec<Transform>,
    setvars: Vec<SetVar>,
    logdata: Option<String>,
    chain: bool,
}

impl ParsedActions {
    fn into_default_actions(self) -> DefaultActions {
        DefaultActions {
            phase: self.phase,
            disruptive: self.disruptive,
            disruptive_specified: self.disruptive_specified,
            status: self.status,
            log: self.log,
            transforms: self.transforms,
        }
    }
}

pub fn load_rules(files: &[PathBuf], options: &LoadOptions) -> Result<CompiledRules, LoadError> {
    let directives = crate::parser::parse_files(files)?;
    compile_directives(directives, files.to_vec(), options)
}

fn compile_error(file: &Path, line: usize, column: usize, message: String) -> LoadError {
    LoadError::Compile {
        file: file.to_path_buf(),
        line,
        column,
        message,
    }
}

fn compile_directives(
    directives: Vec<LocatedDirective>,
    files: Vec<PathBuf>,
    options: &LoadOptions,
) -> Result<CompiledRules, LoadError> {
    let mut defaults: HashMap<PathBuf, DefaultActions> = HashMap::new();
    let mut ids = HashSet::new();
    let mut phase1 = Vec::new();
    let mut phase2 = Vec::new();
    let mut chain: Vec<CompiledRule> = Vec::new();
    let mut chain_phase: Option<Phase> = None;
    let mut last_location: Option<(PathBuf, usize, usize)> = None;
    let mut rule_count = 0usize;

    for located in directives {
        let file = located.file;
        match located.directive {
            Directive::Rule(ast) => {
                let default = defaults.get(&file).cloned().unwrap_or_default();
                let Some(rule) = compile_rule(&file, &ast, &default, options)? else {
                    continue;
                };
                if !ids.insert(rule.id) {
                    return Err(compile_error(
                        &file,
                        ast.line,
                        ast.column,
                        format!("duplicate rule id {}", rule.id),
                    ));
                }
                rule_count += 1;
                last_location = Some((file.clone(), ast.line, ast.column));

                if rule.actions.chain && rule.actions.disruptive.is_some() {
                    return Err(compile_error(
                        &file,
                        ast.line,
                        ast.column,
                        "chain middle rules cannot contain disruptive actions".to_string(),
                    ));
                }
                if !chain.is_empty() && chain_phase != Some(rule.phase) {
                    return Err(compile_error(
                        &file,
                        ast.line,
                        ast.column,
                        "chain rules must share the same phase".to_string(),
                    ));
                }
                if rule.actions.chain {
                    if chain.is_empty() {
                        chain_phase = Some(rule.phase);
                    }
                    chain.push(rule);
                    continue;
                }
                if !chain.is_empty() {
                    chain.push(rule);
                    let group = RuleGroup::Chain(std::mem::take(&mut chain));
                    match chain_phase.take().unwrap_or(Phase::Phase2) {
                        Phase::Phase1 => phase1.push(group),
                        Phase::Phase2 => phase2.push(group),
                    }
                    continue;
                }
                match rule.phase {
                    Phase::Phase1 => phase1.push(RuleGroup::Single(Box::new(rule))),
                    Phase::Phase2 => phase2.push(RuleGroup::Single(Box::new(rule))),
                }
            }
            Directive::Action(ast) => {
                if !chain.is_empty() {
                    return Err(compile_error(
                        &file,
                        ast.line,
                        ast.column,
                        "SecAction cannot appear inside a chain".to_string(),
                    ));
                }
                let default = defaults.get(&file).cloned().unwrap_or_default();
                let Some(rule) = compile_action(&file, &ast, &default, options)? else {
                    continue;
                };
                if !ids.insert(rule.id) {
                    return Err(compile_error(
                        &file,
                        ast.line,
                        ast.column,
                        format!("duplicate rule id {}", rule.id),
                    ));
                }
                rule_count += 1;
                match rule.phase {
                    Phase::Phase1 => phase1.push(RuleGroup::Single(Box::new(rule))),
                    Phase::Phase2 => phase2.push(RuleGroup::Single(Box::new(rule))),
                }
            }
            Directive::DefaultAction(ast) => {
                if !chain.is_empty() {
                    return Err(compile_error(
                        &file,
                        ast.line,
                        ast.column,
                        "SecDefaultAction cannot appear inside a chain".to_string(),
                    ));
                }
                let Some(parsed) =
                    parse_actions(&file, ast.line, ast.column, &ast.actions, options)?
                else {
                    continue;
                };
                if parsed.id.is_some()
                    || parsed.msg.is_some()
                    || !parsed.tags.is_empty()
                    || !parsed.setvars.is_empty()
                    || parsed.logdata.is_some()
                    || parsed.chain
                    || parsed.block_requested
                {
                    return Err(compile_error(
                        &file,
                        ast.line,
                        ast.column,
                        "SecDefaultAction supports only phase, disruptive action, status, log/nolog, and t"
                            .to_string(),
                    ));
                }
                defaults.insert(file, parsed.into_default_actions());
            }
            Directive::Marker(_) => {}
            Directive::Unknown { name, line, column } => {
                if options.lenient {
                    tracing::warn!(
                        file = %file.display(),
                        line,
                        "ignoring unsupported directive {name}"
                    );
                } else {
                    return Err(compile_error(
                        &file,
                        line,
                        column,
                        format!("unsupported directive {name}"),
                    ));
                }
            }
            Directive::Include(_) => {
                return Err(compile_error(
                    &file,
                    1,
                    1,
                    "internal error: Include must be expanded by the parser".to_string(),
                ));
            }
        }
    }

    if let Some(rule) = chain.first() {
        let (file, line, column) =
            last_location.unwrap_or_else(|| (rule.file.clone(), rule.line, 1));
        return Err(compile_error(
            &file,
            line,
            column,
            "chain action on final rule (no following rule)".to_string(),
        ));
    }

    Ok(CompiledRules {
        version: options.version,
        rule_count,
        files,
        phase1,
        phase2,
    })
}

fn compile_rule(
    file: &Path,
    ast: &RuleAst,
    defaults: &DefaultActions,
    options: &LoadOptions,
) -> Result<Option<CompiledRule>, LoadError> {
    let Some(variables) = parse_variables(file, ast.line, ast.column, &ast.variables, options)?
    else {
        return Ok(None);
    };
    let (operator, operator_negated) = match parse_operator(&ast.operator) {
        Ok(value) => value,
        Err(message) => {
            if options.lenient {
                tracing::warn!(file = %file.display(), line = ast.line, "skipping rule: {message}");
                return Ok(None);
            }
            return Err(compile_error(file, ast.line, ast.column, message));
        }
    };
    let Some(parsed) = parse_actions(file, ast.line, ast.column, &ast.actions, options)? else {
        return Ok(None);
    };
    let Some(id) = parsed.id else {
        if options.lenient {
            tracing::warn!(file = %file.display(), line = ast.line, "skipping rule without id");
            return Ok(None);
        }
        return Err(compile_error(
            file,
            ast.line,
            ast.column,
            "rule id is required".to_string(),
        ));
    };
    let phase = match parsed.phase.or(defaults.phase) {
        Some(Phase::Phase1) => Phase::Phase1,
        Some(Phase::Phase2) => Phase::Phase2,
        None => Phase::Phase2,
    };
    let disruptive = resolve_disruptive(&parsed, defaults);
    let log = parsed.log.or(defaults.log).unwrap_or(false);
    let mut transformations = defaults.transforms.clone();
    transformations.extend(parsed.transforms);

    Ok(Some(CompiledRule {
        id,
        phase,
        variables,
        operator,
        operator_negated,
        transformations,
        actions: CompiledActions {
            disruptive,
            log,
            msg: parsed.msg,
            severity: parsed.severity,
            tags: parsed.tags,
            setvars: parsed.setvars,
            logdata: parsed.logdata,
            chain: parsed.chain,
        },
        unconditional: false,
        file: file.to_path_buf(),
        line: ast.line,
    }))
}

fn compile_action(
    file: &Path,
    ast: &ActionAst,
    defaults: &DefaultActions,
    options: &LoadOptions,
) -> Result<Option<CompiledRule>, LoadError> {
    let Some(parsed) = parse_actions(file, ast.line, ast.column, &ast.actions, options)? else {
        return Ok(None);
    };
    let Some(id) = parsed.id else {
        if options.lenient {
            tracing::warn!(file = %file.display(), line = ast.line, "skipping SecAction without id");
            return Ok(None);
        }
        return Err(compile_error(
            file,
            ast.line,
            ast.column,
            "SecAction id is required".to_string(),
        ));
    };
    if parsed.chain {
        return Err(compile_error(
            file,
            ast.line,
            ast.column,
            "SecAction cannot use chain".to_string(),
        ));
    }
    let phase = parsed.phase.or(defaults.phase).unwrap_or(Phase::Phase2);
    let disruptive = resolve_disruptive(&parsed, defaults);
    Ok(Some(CompiledRule {
        id,
        phase,
        variables: Vec::new(),
        operator: CompiledOperator::Eq(String::new()),
        operator_negated: false,
        transformations: Vec::new(),
        actions: CompiledActions {
            disruptive,
            log: parsed.log.or(defaults.log).unwrap_or(false),
            msg: parsed.msg,
            severity: parsed.severity,
            tags: parsed.tags,
            setvars: parsed.setvars,
            logdata: parsed.logdata,
            chain: false,
        },
        unconditional: true,
        file: file.to_path_buf(),
        line: ast.line,
    }))
}

fn resolve_disruptive(parsed: &ParsedActions, defaults: &DefaultActions) -> Option<Disruptive> {
    let action = if parsed.block_requested {
        if defaults.disruptive_specified {
            defaults.disruptive.clone()
        } else {
            Some(Disruptive::Deny { status: 403 })
        }
    } else if parsed.disruptive_specified {
        parsed.disruptive.clone()
    } else {
        defaults.disruptive.clone()
    };
    let status = parsed.status.or(defaults.status).unwrap_or(403);
    action.map(|action| match action {
        Disruptive::Deny { .. } => Disruptive::Deny { status },
        Disruptive::Allow => Disruptive::Allow,
    })
}

fn parse_variables(
    file: &Path,
    line: usize,
    column: usize,
    raw: &str,
    options: &LoadOptions,
) -> Result<Option<Vec<VariableSpec>>, LoadError> {
    let mut specs = Vec::new();
    for item in raw.split('|') {
        let item = item.trim();
        if item.is_empty() {
            return Err(compile_error(
                file,
                line,
                column,
                "empty variable".to_string(),
            ));
        }
        let (negated, item) = match item.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, item),
        };
        if item.starts_with('&') {
            if options.lenient {
                tracing::warn!(
                    file = %file.display(),
                    line,
                    "skipping rule: variable counts are unsupported"
                );
                return Ok(None);
            }
            return Err(compile_error(
                file,
                line,
                column,
                "variable counts (&VAR) are not supported".to_string(),
            ));
        }
        let (name, selector) = match item.split_once(':') {
            Some((name, selector)) => (name, Some(selector.to_string())),
            None => (item, None),
        };
        let variable = match name.to_ascii_uppercase().as_str() {
            "REQUEST_URI" if selector.is_none() => Variable::RequestUri,
            "REQUEST_METHOD" if selector.is_none() => Variable::RequestMethod,
            "QUERY_STRING" if selector.is_none() => Variable::QueryString,
            "REQUEST_FILENAME" if selector.is_none() => Variable::RequestFilename,
            "REQUEST_HEADERS" => Variable::RequestHeaders(selector),
            "ARGS" if selector.is_none() => Variable::Args,
            "ARGS_GET" if selector.is_none() => Variable::ArgsGet,
            "ARGS_POST" if selector.is_none() => Variable::ArgsPost,
            "ARGS_NAMES" if selector.is_none() => Variable::ArgsNames,
            "REQUEST_COOKIES" => Variable::RequestCookies(selector),
            "REQUEST_BODY" if selector.is_none() => Variable::RequestBody,
            "REMOTE_ADDR" if selector.is_none() => Variable::RemoteAddr,
            "TX" => Variable::Tx(selector.map(|value| value.to_ascii_lowercase())),
            _ => {
                if options.lenient {
                    tracing::warn!(
                        file = %file.display(),
                        line,
                        "skipping rule: unsupported variable {item}"
                    );
                    return Ok(None);
                }
                return Err(compile_error(
                    file,
                    line,
                    column,
                    format!("unsupported variable {item}"),
                ));
            }
        };
        specs.push(VariableSpec { variable, negated });
    }
    Ok(Some(specs))
}

fn parse_operator(raw: &str) -> Result<(CompiledOperator, bool), String> {
    let (negated, rest) = match raw.strip_prefix('!') {
        Some(rest) => (true, rest),
        None => (false, raw),
    };
    let rest = rest.trim();
    if rest.is_empty() {
        return Err("empty operator".to_string());
    }
    let (name, argument) = if let Some(after_at) = rest.strip_prefix('@') {
        match after_at.find(char::is_whitespace) {
            Some(index) => (
                after_at[..index].to_ascii_lowercase(),
                unquote(after_at[index..].trim()),
            ),
            None => (after_at.to_ascii_lowercase(), String::new()),
        }
    } else {
        ("rx".to_string(), rest.to_string())
    };
    let operator = match name.as_str() {
        "rx" => CompiledOperator::Rx(
            regex::Regex::new(&argument).map_err(|error| format!("invalid regex: {error}"))?,
        ),
        "eq" => CompiledOperator::Eq(argument),
        "contains" => CompiledOperator::Contains(argument),
        "beginswith" => CompiledOperator::BeginsWith(argument),
        "endswith" => CompiledOperator::EndsWith(argument),
        "pm" => CompiledOperator::Pm(
            argument
                .split_ascii_whitespace()
                .map(|value| value.to_string())
                .collect(),
        ),
        "ipmatch" => CompiledOperator::IpMatch(parse_ip_match(&argument)?),
        "within" => CompiledOperator::Within(argument),
        "gt" => CompiledOperator::Gt(parse_integer(&argument)?),
        "ge" => CompiledOperator::Ge(parse_integer(&argument)?),
        "lt" => CompiledOperator::Lt(parse_integer(&argument)?),
        "le" => CompiledOperator::Le(parse_integer(&argument)?),
        other => return Err(format!("unsupported operator @{other}")),
    };
    Ok((operator, negated))
}

fn parse_integer(raw: &str) -> Result<i64, String> {
    raw.trim()
        .parse::<i64>()
        .map_err(|error| format!("invalid integer {raw}: {error}"))
}

fn parse_actions(
    file: &Path,
    line: usize,
    column: usize,
    raw: &str,
    options: &LoadOptions,
) -> Result<Option<ParsedActions>, LoadError> {
    let mut parsed = ParsedActions::default();
    for item in split_actions(raw) {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let (key, value) = match item.split_once(':') {
            Some((key, value)) => (key.trim().to_ascii_lowercase(), Some(value.trim())),
            None => (item.to_ascii_lowercase(), None),
        };
        match key.as_str() {
            "id" => {
                let raw_id = value.ok_or_else(|| {
                    compile_error(file, line, column, "id requires a value".to_string())
                })?;
                parsed.id = Some(raw_id.parse::<u32>().map_err(|error| {
                    compile_error(file, line, column, format!("invalid rule id: {error}"))
                })?);
            }
            "phase" => {
                let raw_phase = value.ok_or_else(|| {
                    compile_error(file, line, column, "phase requires a value".to_string())
                })?;
                let phase = match raw_phase {
                    "1" => Phase::Phase1,
                    "2" => Phase::Phase2,
                    "3" | "4" | "5" => {
                        if options.lenient {
                            tracing::warn!(
                                file = %file.display(),
                                line,
                                "skipping rule: phase {raw_phase} is unsupported"
                            );
                            return Ok(None);
                        }
                        return Err(compile_error(
                            file,
                            line,
                            column,
                            format!("phase {raw_phase} is not supported"),
                        ));
                    }
                    other => {
                        return Err(compile_error(
                            file,
                            line,
                            column,
                            format!("invalid phase {other}"),
                        ));
                    }
                };
                parsed.phase = Some(phase);
            }
            "deny" => {
                if value.is_some() {
                    return Err(compile_error(
                        file,
                        line,
                        column,
                        format!("{key} does not accept a value"),
                    ));
                }
                if parsed.disruptive_specified {
                    return Err(compile_error(
                        file,
                        line,
                        column,
                        "multiple disruptive actions".to_string(),
                    ));
                }
                parsed.disruptive_specified = true;
                parsed.disruptive = Some(Disruptive::Deny { status: 403 });
            }
            "block" => {
                if value.is_some() {
                    return Err(compile_error(
                        file,
                        line,
                        column,
                        "block does not accept a value".to_string(),
                    ));
                }
                if parsed.disruptive_specified {
                    return Err(compile_error(
                        file,
                        line,
                        column,
                        "multiple disruptive actions".to_string(),
                    ));
                }
                parsed.disruptive_specified = true;
                parsed.block_requested = true;
            }
            "pass" => {
                if value.is_some() {
                    return Err(compile_error(
                        file,
                        line,
                        column,
                        "pass does not accept a value".to_string(),
                    ));
                }
                if parsed.disruptive_specified {
                    return Err(compile_error(
                        file,
                        line,
                        column,
                        "multiple disruptive actions".to_string(),
                    ));
                }
                parsed.disruptive_specified = true;
            }
            "allow" => {
                if value.is_some() {
                    return Err(compile_error(
                        file,
                        line,
                        column,
                        "allow does not accept a value".to_string(),
                    ));
                }
                if parsed.disruptive_specified {
                    return Err(compile_error(
                        file,
                        line,
                        column,
                        "multiple disruptive actions".to_string(),
                    ));
                }
                parsed.disruptive_specified = true;
                parsed.disruptive = Some(Disruptive::Allow);
            }
            "status" => {
                let raw_status = value.ok_or_else(|| {
                    compile_error(file, line, column, "status requires a value".to_string())
                })?;
                let status = raw_status.parse::<u16>().map_err(|error| {
                    compile_error(file, line, column, format!("invalid status: {error}"))
                })?;
                if !(100..=599).contains(&status) {
                    return Err(compile_error(
                        file,
                        line,
                        column,
                        format!("status {status} is outside 100..=599"),
                    ));
                }
                parsed.status = Some(status);
            }
            "log" => {
                if value.is_some() {
                    return Err(compile_error(
                        file,
                        line,
                        column,
                        "log does not accept a value".to_string(),
                    ));
                }
                parsed.log = Some(true);
            }
            "nolog" => {
                if value.is_some() {
                    return Err(compile_error(
                        file,
                        line,
                        column,
                        "nolog does not accept a value".to_string(),
                    ));
                }
                parsed.log = Some(false);
            }
            "msg" => {
                parsed.msg = Some(unquote(value.ok_or_else(|| {
                    compile_error(file, line, column, "msg requires a value".to_string())
                })?));
            }
            "severity" => {
                parsed.severity = Some(unquote(value.ok_or_else(|| {
                    compile_error(file, line, column, "severity requires a value".to_string())
                })?));
            }
            "tag" => {
                parsed.tags.push(unquote(value.ok_or_else(|| {
                    compile_error(file, line, column, "tag requires a value".to_string())
                })?));
            }
            "rev" | "ver" => {
                let _ = value.ok_or_else(|| {
                    compile_error(file, line, column, format!("{key} requires a value"))
                })?;
            }
            "logdata" => {
                parsed.logdata = Some(unquote(value.ok_or_else(|| {
                    compile_error(file, line, column, "logdata requires a value".to_string())
                })?));
            }
            "t" => {
                let raw_transform = value.ok_or_else(|| {
                    compile_error(file, line, column, "t requires a value".to_string())
                })?;
                match Transform::from_name(raw_transform) {
                    Some(transform) => parsed.transforms.push(transform),
                    None => {
                        if options.lenient {
                            tracing::warn!(
                                file = %file.display(),
                                line,
                                "ignoring unsupported transform {raw_transform}"
                            );
                        } else {
                            return Err(compile_error(
                                file,
                                line,
                                column,
                                format!("unsupported transform {raw_transform}"),
                            ));
                        }
                    }
                }
            }
            "chain" => {
                if value.is_some() {
                    return Err(compile_error(
                        file,
                        line,
                        column,
                        "chain does not accept a value".to_string(),
                    ));
                }
                parsed.chain = true;
            }
            "setvar" => {
                let raw_setvar = value.ok_or_else(|| {
                    compile_error(file, line, column, "setvar requires a value".to_string())
                })?;
                match parse_setvar(raw_setvar) {
                    Ok(setvar) => parsed.setvars.push(setvar),
                    Err(message) => {
                        if options.lenient {
                            tracing::warn!(
                                file = %file.display(),
                                line,
                                "ignoring setvar: {message}"
                            );
                        } else {
                            return Err(compile_error(file, line, column, message));
                        }
                    }
                }
            }
            other => {
                if options.lenient {
                    tracing::warn!(
                        file = %file.display(),
                        line,
                        "ignoring unknown action {other}"
                    );
                } else {
                    return Err(compile_error(
                        file,
                        line,
                        column,
                        format!("unknown action {other}"),
                    ));
                }
            }
        }
    }
    Ok(Some(parsed))
}

fn parse_setvar(raw: &str) -> Result<SetVar, String> {
    if let Some(target) = raw.strip_prefix('!') {
        let name = target
            .strip_prefix("tx.")
            .ok_or_else(|| "only tx. variables are supported by setvar".to_string())?;
        return Ok(SetVar {
            name: name.to_ascii_lowercase(),
            op: SetVarOp::Delete,
        });
    }
    let (target, value) = raw
        .split_once('=')
        .ok_or_else(|| "setvar requires name=value".to_string())?;
    let name = target
        .strip_prefix("tx.")
        .ok_or_else(|| "only tx. variables are supported by setvar".to_string())?
        .to_ascii_lowercase();
    let value = unquote(value);
    let op = if let Some(rest) = value.strip_prefix('+') {
        SetVarOp::Add(rest.to_string())
    } else if let Some(rest) = value.strip_prefix('-') {
        SetVarOp::Sub(rest.to_string())
    } else {
        SetVarOp::Assign(value)
    };
    Ok(SetVar { name, op })
}

fn split_actions(raw: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for ch in raw.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' && quote.is_some() {
            current.push(ch);
            escaped = true;
            continue;
        }
        if let Some(delimiter) = quote {
            current.push(ch);
            if ch == delimiter {
                quote = None;
            }
        } else if ch == '\'' || ch == '"' {
            current.push(ch);
            quote = Some(ch);
        } else if ch == ',' {
            let item = current.trim();
            if !item.is_empty() {
                items.push(item.to_string());
            }
            current.clear();
        } else {
            current.push(ch);
        }
    }
    let item = current.trim();
    if !item.is_empty() {
        items.push(item.to_string());
    }
    items
}

fn unquote(value: &str) -> String {
    let value = value.trim();
    let bytes = value.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'\'' || first == b'"') && first == last {
            let delimiter = first as char;
            let inner = &value[1..value.len() - 1];
            let mut output = String::with_capacity(inner.len());
            let mut chars = inner.chars().peekable();
            while let Some(ch) = chars.next() {
                if ch == '\\' {
                    match chars.peek() {
                        Some(&next) if next == delimiter || next == '\\' => {
                            output.push(next);
                            chars.next();
                        }
                        _ => output.push('\\'),
                    }
                } else {
                    output.push(ch);
                }
            }
            return output;
        }
    }
    value.to_string()
}
