use std::borrow::Cow;
use std::collections::HashSet;
use std::time::{Duration, Instant};

use crate::error::EngineError;
use crate::model::{CompiledRule, CompiledRules, Disruptive, Phase, RuleGroup, SetVar, SetVarOp};
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
        for group in groups {
            if self.decision.is_decisive() {
                break;
            }
            match group {
                RuleGroup::Single(rule) => {
                    if self.rule_matches(rule) {
                        self.apply_actions(rule);
                    }
                }
                RuleGroup::Chain(chain) => {
                    for rule in chain {
                        if !self.rule_matches(rule) {
                            break;
                        }
                        self.apply_actions(rule);
                        if self.decision.is_decisive() {
                            break;
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
        let excluded: HashSet<String> = rule
            .variables
            .iter()
            .filter(|spec| spec.negated)
            .flat_map(|spec| self.context.extract(&spec.variable))
            .collect();
        let values: Vec<String> = rule
            .variables
            .iter()
            .filter(|spec| !spec.negated)
            .flat_map(|spec| self.context.extract(&spec.variable))
            .filter(|value| !excluded.contains(value))
            .collect();
        if values.is_empty() {
            return false;
        }
        values.iter().any(|value| {
            let mut transformed = Cow::Borrowed(value.as_str());
            for transform in &rule.transformations {
                transformed = Cow::Owned(transform.apply(&transformed).into_owned());
            }
            let matched = rule.operator.matches(&transformed);
            if rule.operator_negated {
                !matched
            } else {
                matched
            }
        })
    }

    fn apply_actions(&mut self, rule: &CompiledRule) {
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
            msg: msg.clone(),
            severity: rule.actions.severity.clone(),
            tags: rule.actions.tags.clone(),
            logdata,
            log: rule.actions.log,
        });
        match &rule.actions.disruptive {
            Some(Disruptive::Deny { status }) => {
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
    fn log_flag_is_recorded() {
        let rules = load(r#"SecRule ARGS "@contains x" "id:8001,phase:1,pass,log""#);
        let evaluation = eval(&rules, "GET", "/?q=x", &[], b"");
        assert_eq!(evaluation.decision, Decision::Pass);
        assert_eq!(evaluation.matched.len(), 1);
        assert!(evaluation.matched[0].log);
    }
}
