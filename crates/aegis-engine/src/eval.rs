use std::collections::HashSet;
use std::time::{Duration, Instant};

use crate::collections::SharedCollectionStore;
use crate::error::EngineError;
use crate::model::{
    CompiledOperator, CompiledRule, CompiledRules, CtlAction, Disruptive, Phase, Prefilter,
    PrefilterHits, PrefilterVariant, RuleEngineMode, RuleGroup, SetVar, SetVarOp, SetVarScope,
    Variable, VariableSpec,
};
use crate::variables::request::{RequestContext, RequestView, VariableEntry};
use crate::variables::tx::expand_macros_with_remote;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Pass,
    Block {
        status: u16,
        rule_id: u32,
        msg: Option<String>,
    },
    Allow {
        rule_id: u32,
    },
}

impl Decision {
    pub fn is_decisive(&self) -> bool {
        !matches!(self, Self::Pass)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMatch {
    pub id: u32,
    pub msg: Option<String>,
    pub severity: Option<String>,
    pub tags: Vec<String>,
    pub logdata: Option<String>,
    pub log: bool,
}

#[derive(Debug, Clone)]
pub struct Evaluation {
    pub decision: Decision,
    pub matched: Vec<RuleMatch>,
    pub error: Option<EngineError>,
    pub latency: Duration,
    pub suppress_audit: bool,
}

#[derive(Debug, Clone)]
pub struct EvaluationState {
    context: RequestContext,
    decision: Decision,
    matched: Vec<RuleMatch>,
    audit_enabled: bool,
    enforce: bool,
    removed_rule_ids: HashSet<u32>,
    removed_tags: HashSet<String>,
    removed_targets_by_id: Vec<(u32, Variable)>,
    removed_targets_by_tag: Vec<(String, Variable)>,
    skip_until: Option<usize>,
}

impl EvaluationState {
    pub fn new(view: &RequestView<'_>) -> Self {
        Self::new_with_store(
            view,
            std::sync::Arc::new(crate::collections::MemoryCollectionStore::new()),
        )
    }

    pub fn new_with_store(view: &RequestView<'_>, collections: SharedCollectionStore) -> Self {
        Self {
            context: RequestContext::new_with_store(view, collections),
            decision: Decision::Pass,
            matched: Vec::new(),
            audit_enabled: true,
            enforce: true,
            removed_rule_ids: HashSet::new(),
            removed_tags: HashSet::new(),
            removed_targets_by_id: Vec::new(),
            removed_targets_by_tag: Vec::new(),
            skip_until: None,
        }
    }

    pub fn set_body(&mut self, body: &[u8]) {
        self.context.set_body(body);
    }

    pub fn set_response_headers(&mut self, status: u16, headers: &http::HeaderMap) {
        self.context.set_response_headers(status, headers);
    }

    pub fn set_response_body(&mut self, body: &[u8]) {
        self.context.set_response_body(body);
    }

    pub fn decision(&self) -> &Decision {
        &self.decision
    }

    pub fn matched(&self) -> &[RuleMatch] {
        &self.matched
    }

    pub fn evaluate_phase(&mut self, rules: &CompiledRules, phase: Phase) {
        if self.decision.is_decisive() {
            return;
        }
        self.skip_until = None;
        let groups = match phase {
            Phase::Phase1 => &rules.phase1,
            Phase::Phase2 => &rules.phase2,
            Phase::Phase3 => &rules.phase3,
            Phase::Phase4 => &rules.phase4,
            Phase::Phase5 => &rules.phase5,
        };
        let prefilter_hits = rules
            .prefilter
            .as_ref()
            .map(|prefilter| prefilter_hits(prefilter, &self.context));
        for group in groups {
            if self.decision.is_decisive() {
                break;
            }
            let first = first_rule(group);
            if let Some(limit) = self.skip_until {
                if first.sequence <= limit {
                    continue;
                }
                self.skip_until = None;
            }
            if self.removed_rule_ids.contains(&first.id)
                || first
                    .actions
                    .tags
                    .iter()
                    .any(|tag| self.removed_tags.contains(tag))
            {
                continue;
            }
            if let Some(hits) = &prefilter_hits {
                let first = first_rule(group);
                if let Some(rule_prefilter) = &first.prefilter {
                    let variant_hits = &hits[rule_prefilter.variant];
                    let matched = if !rule_prefilter.ac_patterns.is_empty() {
                        rule_prefilter
                            .ac_patterns
                            .iter()
                            .any(|id| variant_hits.ac.get(*id).copied().unwrap_or(false))
                    } else if let Some(index) = rule_prefilter.regex_pattern {
                        variant_hits.regex.get(index).copied().unwrap_or(false)
                    } else {
                        true
                    };
                    if !matched {
                        continue;
                    }
                }
            }
            match group {
                RuleGroup::Single(rule) => {
                    let hits = self.rule_hits(rule);
                    if !hits.is_empty() {
                        if rule.actions.multi_match {
                            for hit in &hits {
                                self.apply_hit_context(rule, hit);
                                self.apply_non_disruptive_actions(rule);
                            }
                            self.record_rule_match(rule);
                        } else {
                            self.apply_hit_context(rule, &hits[0]);
                            self.apply_non_disruptive(rule);
                        }
                        self.apply_disruptive(rule);
                        self.apply_skip_after(rules, rule);
                    }
                }
                RuleGroup::Chain(chain) => {
                    let mut all_match = true;
                    for rule in chain {
                        let hits = self.rule_hits(rule);
                        if hits.is_empty() {
                            all_match = false;
                            break;
                        }
                        if rule.actions.multi_match {
                            for hit in &hits {
                                self.apply_hit_context(rule, hit);
                                self.apply_non_disruptive_actions(rule);
                            }
                            self.record_rule_match(rule);
                        } else {
                            self.apply_hit_context(rule, &hits[0]);
                            self.apply_non_disruptive(rule);
                        }
                    }
                    if all_match {
                        for rule in chain {
                            self.apply_disruptive(rule);
                            if self.decision.is_decisive() {
                                break;
                            }
                        }
                        if let Some(rule) =
                            chain.iter().find(|rule| rule.actions.skip_after.is_some())
                        {
                            self.apply_skip_after(rules, rule);
                        }
                    }
                }
            }
        }
    }

    pub fn finish(self, started: Instant) -> Evaluation {
        Evaluation {
            decision: self.decision,
            matched: self.matched,
            error: None,
            latency: started.elapsed(),
            suppress_audit: !self.audit_enabled,
        }
    }

    fn rule_hits(&self, rule: &CompiledRule) -> Vec<RuleHit> {
        if rule.unconditional {
            return vec![RuleHit {
                value: String::new(),
                variable_name: String::new(),
                key: None,
                captures: Vec::new(),
            }];
        }
        let mut hits = Vec::new();
        for spec in rule.variables.iter().filter(|spec| !spec.negated) {
            let entries = self.context.extract(&spec.variable);
            for entry in entries.iter() {
                if self.entry_excluded(rule, spec, entry) {
                    continue;
                }
                let expand = |template: &str| self.expand_template(template);
                let matched_value;
                let matched = if rule.transformations.is_empty() {
                    matched_value = entry.value.clone();
                    rule.operator.matches_with(&entry.value, &expand)
                } else {
                    let mut current = entry.value.clone();
                    let mut next = String::new();
                    for transform in &rule.transformations {
                        let result = transform.apply(&current);
                        next.clear();
                        next.push_str(&result);
                        std::mem::swap(&mut current, &mut next);
                    }
                    matched_value = current.clone();
                    rule.operator.matches_with(&current, &expand)
                };
                let matched = if rule.operator_negated {
                    !matched
                } else {
                    matched
                };
                if matched {
                    let captures = if rule.actions.capture {
                        capture_values(&rule.operator, &matched_value, rule.operator_negated)
                    } else {
                        Vec::new()
                    };
                    hits.push(RuleHit {
                        value: matched_value,
                        variable_name: entry.name.clone(),
                        key: entry.key.clone(),
                        captures,
                    });
                    if !rule.actions.multi_match {
                        return hits;
                    }
                }
            }
        }
        hits
    }

    fn entry_excluded(
        &self,
        rule: &CompiledRule,
        spec: &VariableSpec,
        entry: &VariableEntry,
    ) -> bool {
        let negated = rule
            .variables
            .iter()
            .filter(|spec| spec.negated)
            .any(|negated| {
                negated.variable.same_family(&spec.variable)
                    && match negated.variable.selector() {
                        None => true,
                        Some(selector) => entry
                            .key
                            .as_deref()
                            .map(|key| selector.matches(key))
                            .unwrap_or(false),
                    }
            });
        if negated {
            return true;
        }
        self.removed_targets_by_id
            .iter()
            .filter(|(id, _)| *id == rule.id)
            .map(|(_, target)| target)
            .chain(
                self.removed_targets_by_tag
                    .iter()
                    .filter(|(tag, _)| rule.actions.tags.contains(tag))
                    .map(|(_, target)| target),
            )
            .any(|target| target_excluded(target, spec, entry))
    }

    fn apply_hit_context(&mut self, rule: &CompiledRule, hit: &RuleHit) {
        self.context
            .record_match(&hit.variable_name, hit.key.as_deref(), &hit.value);
        self.context.tx_mut().set("matched_var", hit.value.clone());
        self.context
            .tx_mut()
            .set("matched_var_name", hit.variable_name.clone());
        if rule.actions.capture {
            for index in 0..10 {
                let name = index.to_string();
                if let Some(value) = hit.captures.get(index) {
                    self.context.tx_mut().set(&name, value.clone());
                } else {
                    self.context.tx_mut().remove(&name);
                }
            }
        }
    }

    fn expand_template(&self, template: &str) -> String {
        let remote_addr = self.context.remote_addr().to_string();
        expand_macros_with_remote(template, self.context.tx(), Some(&remote_addr))
    }

    fn apply_non_disruptive(&mut self, rule: &CompiledRule) {
        self.apply_non_disruptive_actions(rule);
        self.record_rule_match(rule);
    }

    fn apply_non_disruptive_actions(&mut self, rule: &CompiledRule) {
        for (collection, template) in &rule.actions.init_collections {
            let key = self.expand_template(template);
            self.context.set_collection_key(collection, key);
        }
        for setvar in &rule.actions.setvars {
            self.apply_setvar(setvar);
        }
        for ctl in &rule.actions.ctl {
            self.apply_ctl(ctl);
        }
    }

    fn record_rule_match(&mut self, rule: &CompiledRule) {
        let msg = rule
            .actions
            .msg
            .as_ref()
            .map(|template| self.expand_template(template));
        let logdata = rule
            .actions
            .logdata
            .as_ref()
            .map(|template| self.expand_template(template));
        self.matched.push(RuleMatch {
            id: rule.id,
            msg,
            severity: rule.actions.severity.clone(),
            tags: rule.actions.tags.clone(),
            logdata,
            log: rule.actions.log,
        });
    }

    fn apply_skip_after(&mut self, rules: &CompiledRules, rule: &CompiledRule) {
        if let Some(label) = &rule.actions.skip_after {
            if let Some(sequence) = rules.markers.get(label) {
                self.skip_until = Some(*sequence);
            }
        }
    }

    fn apply_ctl(&mut self, ctl: &CtlAction) {
        match ctl {
            CtlAction::AuditEngine(enabled) => self.audit_enabled = *enabled,
            CtlAction::RuleEngine(mode) => {
                self.enforce = matches!(mode, RuleEngineMode::On);
            }
            CtlAction::RemoveRuleById(id) => {
                self.removed_rule_ids.insert(*id);
            }
            CtlAction::RemoveRuleByTag(tag) => {
                self.removed_tags.insert(tag.clone());
            }
            CtlAction::RequestBodyProcessor(processor) => {
                self.context.set_body_processor_override(*processor);
            }
            CtlAction::ForceRequestBodyVariable(_) => {}
            CtlAction::RemoveTargetById { id, target } => {
                self.removed_targets_by_id.push((*id, target.clone()));
            }
            CtlAction::RemoveTargetByTag { tag, target } => {
                self.removed_targets_by_tag
                    .push((tag.clone(), target.clone()));
            }
        }
    }

    fn apply_disruptive(&mut self, rule: &CompiledRule) {
        if !self.enforce {
            return;
        }
        match &rule.actions.disruptive {
            Some(Disruptive::Deny { status }) => {
                let msg = rule
                    .actions
                    .msg
                    .as_ref()
                    .map(|template| self.expand_template(template));
                self.decision = Decision::Block {
                    status: *status,
                    rule_id: rule.id,
                    msg,
                };
            }
            Some(Disruptive::Allow) => {
                self.decision = Decision::Allow { rule_id: rule.id };
            }
            None => {}
        }
    }

    fn apply_setvar(&mut self, setvar: &SetVar) {
        let collection = match setvar.scope {
            SetVarScope::Tx => {
                match &setvar.op {
                    SetVarOp::Assign(template) => {
                        let value = self.expand_template(template);
                        self.context.tx_mut().set(&setvar.name, value);
                    }
                    SetVarOp::Add(template) => {
                        let delta = macro_integer(template, &self.context);
                        let current = self
                            .context
                            .tx()
                            .get(&setvar.name)
                            .and_then(|value| value.parse::<i64>().ok())
                            .unwrap_or(0);
                        self.context
                            .tx_mut()
                            .set(&setvar.name, (current + delta).to_string());
                    }
                    SetVarOp::Sub(template) => {
                        let delta = macro_integer(template, &self.context);
                        let current = self
                            .context
                            .tx()
                            .get(&setvar.name)
                            .and_then(|value| value.parse::<i64>().ok())
                            .unwrap_or(0);
                        self.context
                            .tx_mut()
                            .set(&setvar.name, (current - delta).to_string());
                    }
                    SetVarOp::Delete => {
                        self.context.tx_mut().remove(&setvar.name);
                    }
                }
                return;
            }
            SetVarScope::Ip => "ip",
            SetVarScope::Session => "session",
            SetVarScope::User => "user",
            SetVarScope::Global => "global",
        };

        match &setvar.op {
            SetVarOp::Assign(template) => {
                let value = self.expand_template(template);
                self.context.collection_set(collection, &setvar.name, value);
            }
            SetVarOp::Add(template) => {
                let delta = macro_integer(template, &self.context);
                let current = self
                    .context
                    .collection_get(collection, &setvar.name)
                    .and_then(|value| value.parse::<i64>().ok())
                    .unwrap_or(0);
                self.context.collection_set(
                    collection,
                    &setvar.name,
                    (current + delta).to_string(),
                );
            }
            SetVarOp::Sub(template) => {
                let delta = macro_integer(template, &self.context);
                let current = self
                    .context
                    .collection_get(collection, &setvar.name)
                    .and_then(|value| value.parse::<i64>().ok())
                    .unwrap_or(0);
                self.context.collection_set(
                    collection,
                    &setvar.name,
                    (current - delta).to_string(),
                );
            }
            SetVarOp::Delete => {
                self.context.collection_remove(collection, &setvar.name);
            }
        }
    }
}

fn target_excluded(target: &Variable, spec: &VariableSpec, entry: &VariableEntry) -> bool {
    target.same_family(&spec.variable)
        && match target.selector() {
            None => true,
            Some(selector) => entry
                .key
                .as_deref()
                .map(|key| selector.matches(key))
                .unwrap_or(false),
        }
}

fn macro_integer(template: &str, context: &RequestContext) -> i64 {
    let remote_addr = context.remote_addr().to_string();
    expand_macros_with_remote(template, context.tx(), Some(&remote_addr))
        .trim()
        .parse::<i64>()
        .unwrap_or(0)
}

struct RuleHit {
    value: String,
    variable_name: String,
    key: Option<String>,
    captures: Vec<String>,
}

fn capture_values(operator: &CompiledOperator, value: &str, operator_negated: bool) -> Vec<String> {
    if operator_negated {
        return vec![value.to_string()];
    }
    match operator {
        CompiledOperator::Rx(regex) => match regex.captures(value) {
            Some(captures) => (0..captures.len())
                .map(|index| {
                    captures
                        .get(index)
                        .map(|matched| matched.as_str().to_string())
                        .unwrap_or_default()
                })
                .collect(),
            None => vec![value.to_string()],
        },
        _ => vec![value.to_string()],
    }
}

fn first_rule(group: &RuleGroup) -> &CompiledRule {
    match group {
        RuleGroup::Single(rule) => rule,
        RuleGroup::Chain(rules) => &rules[0],
    }
}

fn scan_variant(variant: &PrefilterVariant, context: &RequestContext) -> PrefilterHits {
    if variant.matcher.is_none() && variant.regex_set.is_none() {
        return PrefilterHits::default();
    }
    let mut hits = PrefilterHits {
        ac: vec![false; variant.ac_pattern_count],
        regex: vec![false; variant.regex_pattern_count],
    };
    context.for_each_prefilter_value(variant.scope, |value| {
        if value.is_empty() {
            return;
        }
        if variant.transforms.is_empty() {
            scan_value(variant, value, &mut hits);
        } else {
            let mut current = value.to_string();
            let mut next = String::new();
            for transform in &variant.transforms {
                let result = transform.apply(&current);
                next.clear();
                next.push_str(&result);
                std::mem::swap(&mut current, &mut next);
            }
            scan_value(variant, &current, &mut hits);
        }
    });
    hits
}

fn scan_value(variant: &PrefilterVariant, value: &str, hits: &mut PrefilterHits) {
    if let Some(matcher) = &variant.matcher {
        mark_matches(matcher, value, &mut hits.ac);
    }
    if let Some(regex_set) = &variant.regex_set {
        for index in regex_set.matches(value).iter() {
            if let Some(slot) = hits.regex.get_mut(index) {
                *slot = true;
            }
        }
    }
}

fn mark_matches(matcher: &aho_corasick::AhoCorasick, value: &str, hits: &mut [bool]) {
    for found in matcher.find_iter(value.as_bytes()) {
        if let Some(slot) = hits.get_mut(found.pattern().as_usize()) {
            *slot = true;
        }
    }
}

fn prefilter_hits(prefilter: &Prefilter, context: &RequestContext) -> Vec<PrefilterHits> {
    prefilter
        .variants
        .iter()
        .map(|variant| scan_variant(variant, context))
        .collect()
}

pub fn evaluate_phase(state: &mut EvaluationState, rules: &CompiledRules, phase: Phase) {
    state.evaluate_phase(rules, phase);
}

pub fn evaluate(rules: &CompiledRules, view: &RequestView<'_>) -> Evaluation {
    let started = Instant::now();
    let mut state = EvaluationState::new(view);
    state.evaluate_phase(rules, Phase::Phase1);
    if !state.decision().is_decisive() {
        state.set_body(view.body);
        state.evaluate_phase(rules, Phase::Phase2);
    }
    state.finish(started)
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;
    use std::fs;

    use http::{HeaderMap, HeaderValue};
    use tempfile::tempdir;

    use super::*;
    use crate::compile::{load_rules, LoadOptions};
    use crate::model::CompiledRules;
    use crate::variables::request::RequestView;

    fn load(text: &str) -> CompiledRules {
        let dir = tempdir().unwrap();
        let path = dir.path().join("rules.conf");
        fs::write(&path, text).unwrap();
        load_rules(
            &[path],
            &LoadOptions {
                lenient: false,
                version: 1,
            },
        )
        .unwrap()
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(
                http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        headers
    }

    fn eval(
        rules: &CompiledRules,
        method: &str,
        uri: &str,
        header_pairs: &[(&str, &str)],
        body: &[u8],
    ) -> Evaluation {
        let path = uri.split_once('?').map(|(path, _)| path).unwrap_or(uri);
        let query = uri.split_once('?').map(|(_, query)| query);
        let headers = headers(header_pairs);
        let view = RequestView {
            method,
            uri,
            path,
            query,
            protocol: "HTTP/1.1",
            headers: &headers,
            body,
            remote_addr: "127.0.0.1".parse().unwrap(),
            unique_id: "test-unique-id",
        };
        evaluate(rules, &view)
    }

    #[test]
    fn blocks_matching_query_argument() {
        let rules =
            load(r#"SecRule ARGS "@rx <script" "id:1001,phase:1,deny,status:403,msg:'xss'""#);
        let evaluation = eval(&rules, "GET", "/search?q=%3Cscript%3E", &[], b"");
        assert_eq!(
            evaluation.decision,
            Decision::Block {
                status: 403,
                rule_id: 1001,
                msg: Some("xss".to_string()),
            }
        );
        assert_eq!(evaluation.matched.len(), 1);
    }

    #[test]
    fn blocks_matching_post_body() {
        let rules = load(r#"SecRule ARGS_POST "@contains evil" "id:1002,phase:2,deny""#);
        let evaluation = eval(
            &rules,
            "POST",
            "/submit",
            &[("content-type", "application/x-www-form-urlencoded")],
            b"name=evil",
        );
        assert!(matches!(
            evaluation.decision,
            Decision::Block { rule_id: 1002, .. }
        ));
    }

    #[test]
    fn applies_transformations_before_matching() {
        let rules = load(
            r#"SecRule ARGS "@contains <script>" "id:1003,phase:1,deny,t:urlDecodeUni,t:lowercase""#,
        );
        let evaluation = eval(&rules, "GET", "/x?a=%u003CSCRIPT%u003E", &[], b"");
        assert!(matches!(
            evaluation.decision,
            Decision::Block { rule_id: 1003, .. }
        ));
    }

    #[test]
    fn chain_requires_all_rules_to_match() {
        let rules = load(
            r#"
SecRule REQUEST_METHOD "@eq POST" "id:2001,phase:1,chain"
SecRule REQUEST_HEADERS:User-Agent "@contains sqlmap" "id:2002,phase:1,deny,status:403"
"#,
        );
        let blocked = eval(
            &rules,
            "POST",
            "/login",
            &[("user-agent", "sqlmap/1.0")],
            b"",
        );
        assert!(matches!(
            blocked.decision,
            Decision::Block { rule_id: 2002, .. }
        ));
        let passed = eval(&rules, "POST", "/login", &[("user-agent", "curl/8")], b"");
        assert_eq!(passed.decision, Decision::Pass);
    }

    #[test]
    fn setvar_macros_and_anomaly_threshold_across_phases() {
        let rules = load(
            r#"
SecAction "id:3000,phase:1,pass,setvar:tx.score=0"
SecRule REQUEST_HEADERS:X-Score "@eq 1" "id:3001,phase:1,pass,setvar:tx.score=+5"
SecRule TX:SCORE "@ge 5" "id:3002,phase:2,deny,status:403,msg:'score=%{tx.score}'"
"#,
        );
        let evaluation = eval(&rules, "POST", "/x", &[("x-score", "1")], b"");
        assert_eq!(
            evaluation.decision,
            Decision::Block {
                status: 403,
                rule_id: 3002,
                msg: Some("score=5".to_string()),
            }
        );
        let second = evaluation
            .matched
            .iter()
            .find(|matched| matched.id == 3002)
            .unwrap();
        assert_eq!(second.msg.as_deref(), Some("score=5"));
    }

    #[test]
    fn negated_variables_exclude_items_by_name() {
        let rules = load(
            r#"SecRule REQUEST_HEADERS|!REQUEST_HEADERS:User-Agent "@contains evil" "id:4001,phase:1,deny""#,
        );
        let blocked = eval(
            &rules,
            "GET",
            "/",
            &[("user-agent", "safe"), ("x-other", "evil")],
            b"",
        );
        assert!(matches!(
            blocked.decision,
            Decision::Block { rule_id: 4001, .. }
        ));
        let excluded = eval(
            &rules,
            "GET",
            "/",
            &[("user-agent", "evil"), ("x-other", "safe")],
            b"",
        );
        assert_eq!(excluded.decision, Decision::Pass);
    }

    #[test]
    fn negated_operator_inverts_each_value() {
        let rules = load(r#"SecRule REQUEST_METHOD "!@eq GET" "id:4002,phase:1,deny""#);
        assert!(matches!(
            eval(&rules, "POST", "/", &[], b"").decision,
            Decision::Block { rule_id: 4002, .. }
        ));
        assert_eq!(eval(&rules, "GET", "/", &[], b"").decision, Decision::Pass);
    }

    #[test]
    fn allow_stops_remaining_rules() {
        let rules = load(
            r#"
SecRule REQUEST_HEADERS:X-Allow "@eq 1" "id:5001,phase:1,allow"
SecRule ARGS "@contains attack" "id:5002,phase:1,deny"
"#,
        );
        let evaluation = eval(&rules, "GET", "/?q=attack", &[("x-allow", "1")], b"");
        assert_eq!(evaluation.decision, Decision::Allow { rule_id: 5001 });
    }

    #[test]
    fn sec_action_runs_unconditionally() {
        let rules = load(
            r#"
SecAction "id:6001,phase:1,pass,setvar:tx.flag=on"
SecRule TX:FLAG "@eq on" "id:6002,phase:1,deny"
"#,
        );
        assert!(matches!(
            eval(&rules, "GET", "/", &[], b"").decision,
            Decision::Block { rule_id: 6002, .. }
        ));
    }

    #[test]
    fn first_disruptive_action_wins() {
        let rules = load(
            r#"
SecRule ARGS "@contains x" "id:7001,phase:1,deny,status:401"
SecRule ARGS "@contains x" "id:7002,phase:1,deny,status:402"
"#,
        );
        let evaluation = eval(&rules, "GET", "/?q=x", &[], b"");
        assert_eq!(
            evaluation.decision,
            Decision::Block {
                status: 401,
                rule_id: 7001,
                msg: None,
            }
        );
        assert_eq!(evaluation.matched.len(), 1);
    }

    #[test]
    fn chain_starter_block_only_applies_when_chain_matches() {
        let rules = load(
            r#"
SecRule REQUEST_HEADERS:X-A "@eq 1" "id:1,phase:1,chain,block"
SecRule REQUEST_HEADERS:X-B "@eq 1" "id:2,phase:1"
"#,
        );
        let failed = eval(&rules, "GET", "/", &[("x-a", "1")], b"");
        assert_eq!(failed.decision, Decision::Pass);
        let blocked = eval(&rules, "GET", "/", &[("x-a", "1"), ("x-b", "1")], b"");
        assert!(matches!(
            blocked.decision,
            Decision::Block { rule_id: 1, .. }
        ));
    }

    #[test]
    fn failed_chain_keeps_non_disruptive_setvar() {
        let rules = load(
            r#"
SecRule REQUEST_HEADERS:X-A "@eq 1" "id:1,phase:1,chain,setvar:tx.leak=1"
SecRule REQUEST_HEADERS:X-B "@eq 1" "id:2,phase:1"
SecRule TX:LEAK "@eq 1" "id:3,phase:1,deny,status:403"
"#,
        );
        let evaluation = eval(&rules, "GET", "/", &[("x-a", "1")], b"");
        assert!(matches!(
            evaluation.decision,
            Decision::Block { rule_id: 3, .. }
        ));
    }

    #[test]
    fn prefilter_uses_decoded_query_values() {
        let rules = load(r#"SecRule ARGS "@contains <script" "id:9001,phase:1,deny""#);
        let evaluation = eval(&rules, "GET", "/?q=%3Cscript%3E", &[], b"");
        assert!(matches!(
            evaluation.decision,
            Decision::Block { rule_id: 9001, .. }
        ));
    }

    #[test]
    fn prefilter_does_not_change_decisions() {
        let rules = load(
            r#"
SecRule ARGS "@contains needle" "id:9002,phase:1,deny"
SecRule REQUEST_METHOD "@eq GET" "id:9003,phase:1,pass"
"#,
        );
        let passed = eval(&rules, "GET", "/?q=hello", &[], b"");
        assert_eq!(passed.decision, Decision::Pass);
        let blocked = eval(&rules, "GET", "/?q=needle", &[], b"");
        assert!(matches!(
            blocked.decision,
            Decision::Block { rule_id: 9002, .. }
        ));
    }

    #[test]
    fn remote_addr_rules_are_not_prefiltered() {
        let rules = load(r#"SecRule REMOTE_ADDR "@contains 127.0.0" "id:9004,phase:1,deny""#);
        let evaluation = eval(&rules, "GET", "/", &[], b"");
        assert!(matches!(
            evaluation.decision,
            Decision::Block { rule_id: 9004, .. }
        ));
    }

    #[test]
    fn pm_rules_are_prefiltered_from_headers() {
        let rules =
            load(r#"SecRule REQUEST_HEADERS:User-Agent "@pm sqlmap nikto" "id:9005,phase:1,deny""#);
        let evaluation = eval(&rules, "GET", "/", &[("user-agent", "SQLMAP/1.0")], b"");
        assert!(matches!(
            evaluation.decision,
            Decision::Block { rule_id: 9005, .. }
        ));
    }

    #[test]
    fn pm_from_file_is_case_insensitive() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("bad.txt");
        std::fs::write(&data, "attack\n# comment\nscanner\n").unwrap();
        let rules_path = dir.path().join("rules.conf");
        std::fs::write(
            &rules_path,
            r#"SecRule ARGS "@pmFromFile bad.txt" "id:9006,phase:1,deny""#,
        )
        .unwrap();
        let rules = load_rules(
            &[rules_path],
            &LoadOptions {
                lenient: false,
                version: 1,
            },
        )
        .unwrap();
        let blocked = eval(&rules, "GET", "/?q=ATTACK", &[], b"");
        assert!(matches!(
            blocked.decision,
            Decision::Block { rule_id: 9006, .. }
        ));
        let passed = eval(&rules, "GET", "/?q=hello", &[], b"");
        assert_eq!(passed.decision, Decision::Pass);
    }

    #[test]
    fn regex_prefilter_uses_required_literal() {
        let rules = load(r#"SecRule ARGS "@rx needle-[0-9]+" "id:9101,phase:1,deny""#);
        let blocked = eval(&rules, "GET", "/?q=needle-42", &[], b"");
        assert!(matches!(
            blocked.decision,
            Decision::Block { rule_id: 9101, .. }
        ));
        let passed = eval(&rules, "GET", "/?q=hello", &[], b"");
        assert_eq!(passed.decision, Decision::Pass);
    }

    #[test]
    fn regex_suffix_literals_are_used() {
        let rules = load(r#"SecRule ARGS "@rx [0-9]+suffix" "id:9102,phase:1,deny""#);
        let blocked = eval(&rules, "GET", "/?q=42suffix", &[], b"");
        assert!(matches!(
            blocked.decision,
            Decision::Block { rule_id: 9102, .. }
        ));
    }

    #[test]
    fn case_insensitive_regex_matches_regardless_of_case() {
        let rules = load(r#"SecRule ARGS "@rx (?i)secret" "id:9103,phase:1,deny""#);
        let blocked = eval(&rules, "GET", "/?q=SECRET", &[], b"");
        assert!(matches!(
            blocked.decision,
            Decision::Block { rule_id: 9103, .. }
        ));
        let passed = eval(&rules, "GET", "/?q=hello", &[], b"");
        assert_eq!(passed.decision, Decision::Pass);
    }

    #[test]
    fn case_insensitive_regex_set_is_used_for_large_sets() {
        let mut text = String::new();
        for index in 0..8 {
            writeln!(
                text,
                "SecRule ARGS \"@rx (?i)secret{index}\" \"id:{},phase:1,pass\"",
                9100 + index
            )
            .unwrap();
        }
        let rules = load(&text);
        assert!(rules.prefilter_stats().regex_groups >= 1);
        let evaluation = eval(&rules, "GET", "/?q=SECRET3", &[], b"");
        assert_eq!(evaluation.decision, Decision::Pass);
        assert!(evaluation.matched.iter().any(|matched| matched.id == 9103));
    }

    #[test]
    fn case_insensitive_regex_with_transforms_matches() {
        let rules = load(r#"SecRule ARGS "@rx (?i)secret" "id:9106,phase:1,deny,t:lowercase""#);
        let blocked = eval(&rules, "GET", "/?q=SECRET", &[], b"");
        assert!(matches!(
            blocked.decision,
            Decision::Block { rule_id: 9106, .. }
        ));
    }

    #[test]
    fn regex_matching_empty_is_not_prefiltered() {
        let rules = load(r#"SecRule ARGS "@rx .*" "id:9107,phase:1,deny""#);
        let blocked = eval(&rules, "GET", "/?q=hello", &[], b"");
        assert!(matches!(
            blocked.decision,
            Decision::Block { rule_id: 9107, .. }
        ));
    }

    #[test]
    fn lowercase_transform_is_used_in_prefilter() {
        let rules = load(r#"SecRule ARGS "@rx needle-[0-9]+" "id:9104,phase:1,deny,t:lowercase""#);
        let blocked = eval(&rules, "GET", "/?q=NEEDLE-42", &[], b"");
        assert!(matches!(
            blocked.decision,
            Decision::Block { rule_id: 9104, .. }
        ));
    }

    #[test]
    fn url_decode_transform_is_used_in_prefilter() {
        let rules = load(
            r#"SecRule REQUEST_URI "@rx needle-[0-9]+" "id:9105,phase:1,deny,t:urlDecodeUni,t:lowercase""#,
        );
        let blocked = eval(&rules, "GET", "/?q=NEEDLE%2D42", &[], b"");
        assert!(matches!(
            blocked.decision,
            Decision::Block { rule_id: 9105, .. }
        ));
    }

    #[test]
    fn capture_exposes_regex_groups_to_later_rules() {
        let rules = load(
            r#"
SecRule ARGS "@rx secret-([0-9]+)" "id:9201,phase:1,pass,capture"
SecRule TX:1 "@eq 42" "id:9202,phase:1,deny,status:403"
"#,
        );
        let evaluation = eval(&rules, "GET", "/?q=secret-42", &[], b"");
        assert!(matches!(
            evaluation.decision,
            Decision::Block { rule_id: 9202, .. }
        ));
    }

    #[test]
    fn matched_var_and_macro_are_available_to_later_rules() {
        let rules = load(
            r#"
SecRule ARGS "@rx secret-([0-9]+)" "id:9203,phase:1,pass,capture"
SecRule MATCHED_VAR "@contains secret-42" "id:9204,phase:1,deny,status:403,msg:'matched=%{MATCHED_VAR}'"
"#,
        );
        let evaluation = eval(&rules, "GET", "/?q=secret-42", &[], b"");
        assert_eq!(
            evaluation.decision,
            Decision::Block {
                status: 403,
                rule_id: 9204,
                msg: Some("matched=secret-42".to_string()),
            }
        );
    }

    #[test]
    fn xml_variable_extracts_element_text() {
        let rules = load(r#"SecRule XML:/* "@contains attack" "id:9205,phase:2,deny""#);
        let headers = headers(&[("content-type", "application/xml")]);
        let view = RequestView {
            method: "POST",
            uri: "/xml",
            path: "/xml",
            query: None,
            protocol: "HTTP/1.1",
            headers: &headers,
            body: b"<root><a>attack</a></root>",
            remote_addr: "127.0.0.1".parse().unwrap(),
            unique_id: "test-unique-id",
        };
        let evaluation = evaluate(&rules, &view);
        assert!(matches!(
            evaluation.decision,
            Decision::Block { rule_id: 9205, .. }
        ));
    }

    #[test]
    fn ctl_removes_rule_by_id() {
        let rules = load(
            r#"
SecRule REQUEST_HEADERS:X-Skip "@eq 1" "id:1,phase:1,pass,ctl:ruleRemoveById=3"
SecRule ARGS "@contains attack" "id:3,phase:1,deny,status:403"
"#,
        );
        let skipped = eval(&rules, "GET", "/?q=attack", &[("x-skip", "1")], b"");
        assert_eq!(skipped.decision, Decision::Pass);
        let blocked = eval(&rules, "GET", "/?q=attack", &[], b"");
        assert!(matches!(
            blocked.decision,
            Decision::Block { rule_id: 3, .. }
        ));
    }

    #[test]
    fn ctl_removes_rule_by_tag() {
        let rules = load(
            r#"
SecRule REQUEST_HEADERS:X-Skip "@eq 1" "id:1,phase:1,pass,ctl:ruleRemoveByTag=blockme"
SecRule ARGS "@contains attack" "id:3,phase:1,deny,status:403,tag:'blockme'"
"#,
        );
        let skipped = eval(&rules, "GET", "/?q=attack", &[("x-skip", "1")], b"");
        assert_eq!(skipped.decision, Decision::Pass);
    }

    #[test]
    fn ctl_rule_engine_off_prevents_blocking() {
        let rules = load(
            r#"
SecRule REQUEST_HEADERS:X-Skip "@eq 1" "id:1,phase:1,pass,ctl:ruleEngine=Off"
SecRule ARGS "@contains attack" "id:3,phase:1,deny,status:403"
"#,
        );
        let evaluation = eval(&rules, "GET", "/?q=attack", &[("x-skip", "1")], b"");
        assert_eq!(evaluation.decision, Decision::Pass);
    }

    #[test]
    fn ctl_audit_engine_off_suppresses_audit() {
        let rules = load(r#"SecRule ARGS "@contains x" "id:1,phase:1,pass,ctl:auditEngine=Off""#);
        let evaluation = eval(&rules, "GET", "/?q=x", &[], b"");
        assert!(evaluation.suppress_audit);
    }

    #[test]
    fn phase_three_blocks_on_response_status() {
        let rules = load(r#"SecRule RESPONSE_STATUS "@eq 500" "id:9301,phase:3,deny,status:502""#);
        let request_headers = headers(&[]);
        let view = RequestView {
            method: "GET",
            uri: "/",
            path: "/",
            query: None,
            protocol: "HTTP/1.1",
            headers: &request_headers,
            body: b"",
            remote_addr: "127.0.0.1".parse().unwrap(),
            unique_id: "test-unique-id",
        };
        let mut state = EvaluationState::new(&view);
        state.evaluate_phase(&rules, Phase::Phase1);
        state.evaluate_phase(&rules, Phase::Phase2);
        assert_eq!(state.decision(), &Decision::Pass);
        let response_headers = headers(&[("content-type", "text/html")]);
        state.set_response_headers(500, &response_headers);
        state.evaluate_phase(&rules, Phase::Phase3);
        assert!(matches!(
            state.decision(),
            Decision::Block {
                status: 502,
                rule_id: 9301,
                ..
            }
        ));
    }

    #[test]
    fn phase_four_blocks_on_response_body() {
        let rules =
            load(r#"SecRule RESPONSE_BODY "@contains secret" "id:9302,phase:4,deny,status:403""#);
        let request_headers = headers(&[]);
        let view = RequestView {
            method: "GET",
            uri: "/",
            path: "/",
            query: None,
            protocol: "HTTP/1.1",
            headers: &request_headers,
            body: b"",
            remote_addr: "127.0.0.1".parse().unwrap(),
            unique_id: "test-unique-id",
        };
        let mut state = EvaluationState::new(&view);
        let response_headers = headers(&[("content-type", "text/plain")]);
        state.set_response_headers(200, &response_headers);
        state.evaluate_phase(&rules, Phase::Phase3);
        state.set_response_body(b"a secret value");
        state.evaluate_phase(&rules, Phase::Phase4);
        assert!(matches!(
            state.decision(),
            Decision::Block {
                status: 403,
                rule_id: 9302,
                ..
            }
        ));
    }

    #[test]
    fn skip_after_jumps_to_marker() {
        let rules = load(
            r#"
SecRule ARGS "@contains skip" "id:1,phase:1,pass,skipAfter:AFTER"
SecRule ARGS "@contains attack" "id:2,phase:1,deny,status:403"
SecMarker AFTER
SecRule ARGS "@contains attack" "id:3,phase:1,deny,status:401"
"#,
        );
        let skipped = eval(&rules, "GET", "/?q=skip+attack", &[], b"");
        assert!(matches!(
            skipped.decision,
            Decision::Block {
                status: 401,
                rule_id: 3,
                ..
            }
        ));
        let blocked = eval(&rules, "GET", "/?q=attack", &[], b"");
        assert!(matches!(
            blocked.decision,
            Decision::Block {
                status: 403,
                rule_id: 2,
                ..
            }
        ));
    }

    #[test]
    fn phase_five_runs_after_response() {
        let rules = load(
            r#"
SecRule RESPONSE_BODY "@contains secret" "id:9401,phase:5,pass,setvar:tx.seen=1"
SecRule TX:SEEN "@eq 1" "id:9402,phase:5,deny,status:403"
"#,
        );
        let request_headers = headers(&[]);
        let view = RequestView {
            method: "GET",
            uri: "/",
            path: "/",
            query: None,
            protocol: "HTTP/1.1",
            headers: &request_headers,
            body: b"",
            remote_addr: "127.0.0.1".parse().unwrap(),
            unique_id: "test-unique-id",
        };
        let mut state = EvaluationState::new(&view);
        let response_headers = headers(&[("content-type", "text/plain")]);
        state.set_response_headers(200, &response_headers);
        state.set_response_body(b"a secret value");
        state.evaluate_phase(&rules, Phase::Phase5);
        assert!(matches!(
            state.decision(),
            Decision::Block { rule_id: 9402, .. }
        ));
    }

    #[test]
    fn matched_vars_contains_matched_values() {
        let rules = load(
            r#"
SecRule ARGS "@contains secret" "id:9501,phase:1,pass"
SecRule MATCHED_VARS "@contains secret" "id:9502,phase:1,deny,status:403"
"#,
        );
        let evaluation = eval(&rules, "GET", "/?q=secret", &[], b"");
        assert!(matches!(
            evaluation.decision,
            Decision::Block { rule_id: 9502, .. }
        ));
        let names = eval(
            &load(
                r#"
SecRule ARGS "@contains secret" "id:9501,phase:1,pass"
SecRule MATCHED_VARS "@contains ARGS" "id:9502,phase:1,deny,status:403"
"#,
            ),
            "GET",
            "/?q=secret",
            &[],
            b"",
        );
        assert_eq!(names.decision, Decision::Pass);
    }

    #[test]
    fn rule_remove_target_by_tag_skips_matching_variable() {
        let rules = load(
            r#"
SecRule REQUEST_FILENAME "@contains admin" "id:4501,phase:1,pass,ctl:ruleRemoveTargetByTag=skip-target;REQUEST_FILENAME"
SecRule REQUEST_FILENAME "@contains admin" "id:4502,phase:1,deny,status:403,tag:'skip-target'"
"#,
        );
        let evaluation = eval(&rules, "GET", "/admin", &[], b"");
        assert_eq!(evaluation.decision, Decision::Pass);
    }

    #[test]
    fn rule_remove_target_by_id_skips_matching_variable() {
        let rules = load(
            r#"
SecRule REQUEST_FILENAME "@contains admin" "id:4511,phase:1,pass,ctl:ruleRemoveTargetById=4512;REQUEST_FILENAME"
SecRule REQUEST_FILENAME "@contains admin" "id:4512,phase:1,deny,status:403"
"#,
        );
        let evaluation = eval(&rules, "GET", "/admin", &[], b"");
        assert_eq!(evaluation.decision, Decision::Pass);
    }

    #[test]
    fn request_body_processor_ctl_overrides_content_type() {
        let rules = load(
            r#"
SecRule REQUEST_HEADERS:Content-Type "@contains text/plain" "id:4521,phase:1,pass,ctl:requestBodyProcessor=URLENCODED"
SecRule ARGS_POST:a "@eq 1" "id:4522,phase:2,deny,status:403"
"#,
        );
        let evaluation = eval(
            &rules,
            "POST",
            "/submit",
            &[("content-type", "text/plain")],
            b"a=1",
        );
        assert!(matches!(
            evaluation.decision,
            Decision::Block { rule_id: 4522, .. }
        ));
    }

    #[test]
    fn numeric_operator_arguments_expand_macros() {
        let rules = load(
            r#"
SecAction "id:4601,phase:1,pass,setvar:tx.limit=2"
SecRule &ARGS "@gt %{tx.limit}" "id:4602,phase:1,deny,status:403"
"#,
        );
        let passed = eval(&rules, "GET", "/?a=1&b=2", &[], b"");
        assert_eq!(passed.decision, Decision::Pass);
        let blocked = eval(&rules, "GET", "/?a=1&b=2&c=3", &[], b"");
        assert!(matches!(
            blocked.decision,
            Decision::Block { rule_id: 4602, .. }
        ));
    }

    #[test]
    fn multi_match_accumulates_actions_per_hit() {
        let rules = load(
            r#"
SecAction "id:4401,phase:1,pass,setvar:tx.score=0"
SecRule ARGS "@contains attack" "id:4402,phase:1,pass,multiMatch,setvar:tx.score=+1"
SecRule TX:SCORE "@eq 2" "id:4403,phase:1,deny,status:403"
"#,
        );
        let evaluation = eval(&rules, "GET", "/?a=attack&b=attack", &[], b"");
        assert!(matches!(
            evaluation.decision,
            Decision::Block { rule_id: 4403, .. }
        ));
        assert_eq!(
            evaluation
                .matched
                .iter()
                .filter(|matched| matched.id == 4402)
                .count(),
            1
        );
    }

    #[test]
    fn count_variables_report_collection_sizes() {
        let rules = load(r#"SecRule &ARGS "@eq 2" "id:4301,phase:1,deny,status:403""#);
        let evaluation = eval(&rules, "GET", "/?a=1&b=2", &[], b"");
        assert!(matches!(
            evaluation.decision,
            Decision::Block { rule_id: 4301, .. }
        ));
    }

    #[test]
    fn count_tx_reports_presence() {
        let rules = load(
            r#"
SecAction "id:4311,phase:1,pass,setvar:tx.flag=1"
SecRule &TX:FLAG "@eq 1" "id:4312,phase:1,deny,status:403"
"#,
        );
        let evaluation = eval(&rules, "GET", "/", &[], b"");
        assert!(matches!(
            evaluation.decision,
            Decision::Block { rule_id: 4312, .. }
        ));
    }

    #[test]
    fn negated_targets_exclude_items_by_name() {
        let rules = load(r#"SecRule ARGS|!ARGS:allow "@contains attack" "id:4101,phase:1,deny""#);
        let blocked = eval(&rules, "GET", "/?allow=attack", &[], b"");
        assert_eq!(blocked.decision, Decision::Pass);
        let still_blocked = eval(&rules, "GET", "/?allow=attack&other=attack", &[], b"");
        assert!(matches!(
            still_blocked.decision,
            Decision::Block { rule_id: 4101, .. }
        ));
    }

    #[test]
    fn matched_var_name_uses_collection_key() {
        let rules = load(
            r#"
SecRule ARGS "@contains attack" "id:4201,phase:1,pass,setvar:tx.seen=%{MATCHED_VAR_NAME}"
SecRule TX:SEEN "@contains ARGS:q" "id:4202,phase:1,deny,status:403"
"#,
        );
        let evaluation = eval(&rules, "GET", "/?q=attack", &[], b"");
        assert!(matches!(
            evaluation.decision,
            Decision::Block { rule_id: 4202, .. }
        ));
    }

    #[test]
    fn persistent_ip_collection_survives_requests() {
        let rules = load(
            r#"
SecAction "id:9601,phase:1,pass,initcol:ip=%{remote_addr},setvar:ip.hits=+1"
SecRule IP:HITS "@ge 2" "id:9602,phase:1,deny,status:403"
"#,
        );
        let request_headers = headers(&[]);
        let view = RequestView {
            method: "GET",
            uri: "/",
            path: "/",
            query: None,
            protocol: "HTTP/1.1",
            headers: &request_headers,
            body: b"",
            remote_addr: "127.0.0.1".parse().unwrap(),
            unique_id: "test-unique-id",
        };
        let store = std::sync::Arc::new(crate::collections::MemoryCollectionStore::new());
        let mut first = EvaluationState::new_with_store(&view, store.clone());
        first.evaluate_phase(&rules, Phase::Phase1);
        assert_eq!(first.decision(), &Decision::Pass);
        let mut second = EvaluationState::new_with_store(&view, store);
        second.evaluate_phase(&rules, Phase::Phase1);
        assert!(matches!(
            second.decision(),
            Decision::Block { rule_id: 9602, .. }
        ));
    }

    #[test]
    fn log_flag_is_recorded() {
        let rules = load(r#"SecRule ARGS "@contains x" "id:8001,phase:1,pass,log""#);
        let evaluation = eval(&rules, "GET", "/?q=x", &[], b"");
        assert_eq!(evaluation.decision, Decision::Pass);
        assert_eq!(evaluation.matched.len(), 1);
        assert!(evaluation.matched[0].log);
    }
}
