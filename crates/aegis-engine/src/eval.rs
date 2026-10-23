use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::error::EngineError;
use crate::model::{
    CompiledRule, CompiledRules, Disruptive, Phase, Prefilter, PrefilterHits, PrefilterVariant,
    RuleGroup, SetVar, SetVarOp,
};
use crate::variables::request::{RequestContext, RequestView};
use crate::variables::tx::expand_macros;

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
}

#[derive(Debug, Clone)]
pub struct EvaluationState {
    context: RequestContext,
    decision: Decision,
    matched: Vec<RuleMatch>,
}

impl EvaluationState {
    pub fn new(view: &RequestView<'_>) -> Self {
        Self {
            context: RequestContext::new(view),
            decision: Decision::Pass,
            matched: Vec::new(),
        }
    }

    pub fn set_body(&mut self, body: &[u8]) {
        self.context.set_body(body);
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
        let groups = match phase {
            Phase::Phase1 => &rules.phase1,
            Phase::Phase2 => &rules.phase2,
        };
        let prefilter_hits = rules
            .prefilter
            .as_ref()
            .map(|prefilter| prefilter_hits(prefilter, &self.context));
        for group in groups {
            if self.decision.is_decisive() {
                break;
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
                    if self.rule_matches(rule) {
                        self.apply_actions(rule);
                    }
                }
                RuleGroup::Chain(chain) => {
                    let mut all_match = true;
                    for rule in chain {
                        if !self.rule_matches(rule) {
                            all_match = false;
                            break;
                        }
                        self.apply_non_disruptive(rule);
                    }
                    if all_match {
                        for rule in chain {
                            self.apply_disruptive(rule);
                            if self.decision.is_decisive() {
                                break;
                            }
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
        }
    }

    fn rule_matches(&self, rule: &CompiledRule) -> bool {
        if rule.unconditional {
            return true;
        }
        let excluded_arcs: Vec<Arc<Vec<String>>> = rule
            .variables
            .iter()
            .filter(|spec| spec.negated)
            .map(|spec| self.context.extract(&spec.variable))
            .collect();
        let excluded: HashSet<&str> = excluded_arcs
            .iter()
            .flat_map(|values| values.iter().map(String::as_str))
            .collect();

        for spec in rule.variables.iter().filter(|spec| !spec.negated) {
            let values = self.context.extract(&spec.variable);
            for value in values.iter() {
                if excluded.contains(value.as_str()) {
                    continue;
                }
                let matched = if rule.transformations.is_empty() {
                    rule.operator.matches(value)
                } else {
                    let mut current = value.clone();
                    let mut next = String::new();
                    for transform in &rule.transformations {
                        let result = transform.apply(&current);
                        next.clear();
                        next.push_str(&result);
                        std::mem::swap(&mut current, &mut next);
                    }
                    rule.operator.matches(&current)
                };
                let matched = if rule.operator_negated {
                    !matched
                } else {
                    matched
                };
                if matched {
                    return true;
                }
            }
        }
        false
    }

    fn apply_actions(&mut self, rule: &CompiledRule) {
        self.apply_non_disruptive(rule);
        self.apply_disruptive(rule);
    }

    fn apply_non_disruptive(&mut self, rule: &CompiledRule) {
        for setvar in &rule.actions.setvars {
            self.apply_setvar(setvar);
        }
        let msg = rule
            .actions
            .msg
            .as_ref()
            .map(|template| expand_macros(template, self.context.tx()));
        let logdata = rule
            .actions
            .logdata
            .as_ref()
            .map(|template| expand_macros(template, self.context.tx()));
        self.matched.push(RuleMatch {
            id: rule.id,
            msg,
            severity: rule.actions.severity.clone(),
            tags: rule.actions.tags.clone(),
            logdata,
            log: rule.actions.log,
        });
    }

    fn apply_disruptive(&mut self, rule: &CompiledRule) {
        match &rule.actions.disruptive {
            Some(Disruptive::Deny { status }) => {
                let msg = rule
                    .actions
                    .msg
                    .as_ref()
                    .map(|template| expand_macros(template, self.context.tx()));
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
        match &setvar.op {
            SetVarOp::Assign(template) => {
                let value = expand_macros(template, self.context.tx());
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
    }
}

fn macro_integer(template: &str, context: &RequestContext) -> i64 {
    expand_macros(template, context.tx())
        .trim()
        .parse::<i64>()
        .unwrap_or(0)
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
            headers: &headers,
            body,
            remote_addr: "127.0.0.1".parse().unwrap(),
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
    fn negated_variables_exclude_values() {
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
            &[("user-agent", "evil"), ("x-other", "evil")],
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
        let evaluation = eval(&rules, "GET", "/", &[("user-agent", "sqlmap/1.0")], b"");
        assert!(matches!(
            evaluation.decision,
            Decision::Block { rule_id: 9005, .. }
        ));
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
    fn log_flag_is_recorded() {
        let rules = load(r#"SecRule ARGS "@contains x" "id:8001,phase:1,pass,log""#);
        let evaluation = eval(&rules, "GET", "/?q=x", &[], b"");
        assert_eq!(evaluation.decision, Decision::Pass);
        assert_eq!(evaluation.matched.len(), 1);
        assert!(evaluation.matched[0].log);
    }
}
