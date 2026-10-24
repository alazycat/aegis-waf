use std::fs;

use aegis_engine::compile::{load_rules, LoadOptions};
use aegis_engine::model::{
    CompiledOperator, CtlAction, Phase, RuleGroup, RuleIdRange, Selector, Variable,
};
use tempfile::tempdir;

fn load(text: &str) -> Result<aegis_engine::model::CompiledRules, aegis_engine::LoadError> {
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
}

fn load_lenient(text: &str) -> aegis_engine::model::CompiledRules {
    let dir = tempdir().unwrap();
    let path = dir.path().join("rules.conf");
    fs::write(&path, text).unwrap();
    load_rules(
        &[path],
        &LoadOptions {
            lenient: true,
            version: 1,
        },
    )
    .unwrap()
}

#[test]
fn compiles_basic_rule_with_defaults() {
    let rules = load(r#"SecRule ARGS "@rx foo" "id:1001,deny""#).unwrap();
    assert_eq!(rules.rule_count, 1);
    assert_eq!(rules.phase1.len(), 0);
    assert_eq!(rules.phase2.len(), 1);
    let RuleGroup::Single(rule) = &rules.phase2[0] else {
        panic!("expected single rule");
    };
    assert_eq!(rule.id, 1001);
    assert_eq!(rule.phase, Phase::Phase2);
    assert!(matches!(rule.variables[0].variable, Variable::Args(_)));
    assert!(matches!(rule.operator, CompiledOperator::Rx(_)));
    assert!(rule.actions.disruptive.is_some());
}

#[test]
fn compiles_multiple_variables_and_negation() {
    let rules = load(
        r#"SecRule ARGS|!REQUEST_HEADERS:User-Agent|REQUEST_COOKIES:session "@contains x" "id:1002,phase:1,pass""#,
    )
    .unwrap();
    let RuleGroup::Single(rule) = &rules.phase1[0] else {
        panic!("expected single rule");
    };
    assert_eq!(rule.variables.len(), 3);
    assert!(!rule.variables[0].negated);
    assert!(rule.variables[1].negated);
    assert!(matches!(
        &rule.variables[1].variable,
        Variable::RequestHeaders(Some(Selector::Literal(name))) if name == "User-Agent"
    ));
}

#[test]
fn rejects_duplicate_rule_ids() {
    let error = load(
        r#"
SecRule ARGS "@rx a" "id:1,pass"
SecRule ARGS "@rx b" "id:1,pass"
"#,
    )
    .unwrap_err();
    assert!(error.to_string().contains("duplicate rule id 1"));
}

#[test]
fn rejects_invalid_phase() {
    let error = load(r#"SecRule ARGS "@rx a" "id:1,phase:6,deny""#).unwrap_err();
    assert!(error.to_string().contains("invalid phase 6"));
}

#[test]
fn compiles_response_phases() {
    let rules = load(
        r#"
SecRule RESPONSE_STATUS "@eq 500" "id:1,phase:3,deny"
SecRule RESPONSE_BODY "@contains secret" "id:2,phase:4,deny"
SecAction "id:3,phase:5,pass,setvar:tx.reported=1"
"#,
    )
    .unwrap();
    assert_eq!(rules.phase3.len(), 1);
    assert_eq!(rules.phase4.len(), 1);
    assert_eq!(rules.phase5.len(), 1);
}

#[test]
fn rejects_unknown_action_in_strict_mode() {
    let error = load(r#"SecRule ARGS "@rx a" "id:1,deny,mystery:1""#).unwrap_err();
    assert!(error.to_string().contains("unknown action"));
}

#[test]
fn lenient_mode_ignores_unknown_action() {
    let rules = load_lenient(r#"SecRule ARGS "@rx a" "id:1,deny,mystery:1""#);
    assert_eq!(rules.rule_count, 1);
}

#[test]
fn rejects_chain_on_last_rule() {
    let error = load(r#"SecRule ARGS "@rx a" "id:1,phase:1,chain""#).unwrap_err();
    assert!(error.to_string().contains("chain"));
}

#[test]
fn rejects_disruptive_action_in_chain_middle() {
    let error = load(
        r#"
SecRule ARGS "@rx a" "id:1,phase:1,chain"
SecRule ARGS "@rx b" "id:2,phase:1,chain,deny"
SecRule ARGS "@rx c" "id:3,phase:1,deny"
"#,
    )
    .unwrap_err();
    assert!(error.to_string().contains("chain"));
}

#[test]
fn t_none_clears_default_transforms() {
    let rules = load(
        r#"
SecDefaultAction "phase:1,pass,t:lowercase"
SecRule ARGS "@contains attack" "id:1,t:none,deny"
"#,
    )
    .unwrap();
    let RuleGroup::Single(rule) = &rules.phase1[0] else {
        panic!("expected single rule");
    };
    assert!(rule.transformations.is_empty());
}

#[test]
fn chain_links_can_omit_ids_and_phase() {
    let rules = load(
        r#"
SecRule ARGS "@rx a" "id:1,phase:1,chain"
SecRule ARGS "@rx b" ""
"#,
    )
    .unwrap();
    let RuleGroup::Chain(chain) = &rules.phase1[0] else {
        panic!("expected chain");
    };
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[0].id, 1);
    assert_eq!(chain[1].id, 1);
    assert_eq!(chain[1].phase, Phase::Phase1);
    assert_eq!(rules.rule_count, 2);
}

#[test]
fn chain_starter_can_declare_block() {
    let rules = load(
        r#"
SecRule REQUEST_HEADERS:X-A "@eq 1" "id:1,phase:1,chain,block"
SecRule REQUEST_HEADERS:X-B "@eq 1" "id:2,phase:1"
"#,
    )
    .unwrap();
    let RuleGroup::Chain(chain) = &rules.phase1[0] else {
        panic!("expected chain");
    };
    assert!(matches!(
        chain[0].actions.disruptive,
        Some(aegis_engine::model::Disruptive::Deny { status: 403 })
    ));
}

#[test]
fn applies_sec_default_action_per_file() {
    let dir = tempdir().unwrap();
    let a = dir.path().join("a.conf");
    let b = dir.path().join("b.conf");
    fs::write(
        &a,
        r#"
SecDefaultAction "phase:1,deny,status:451,log"
SecRule REQUEST_URI "@contains /a" "id:1"
"#,
    )
    .unwrap();
    fs::write(&b, r#"SecRule REQUEST_URI "@contains /b" "id:2""#).unwrap();
    let rules = load_rules(
        &[a, b],
        &LoadOptions {
            lenient: false,
            version: 1,
        },
    )
    .unwrap();
    let RuleGroup::Single(first) = &rules.phase1[0] else {
        panic!("expected single rule");
    };
    let RuleGroup::Single(second) = &rules.phase2[0] else {
        panic!("expected single rule");
    };
    assert_eq!(first.phase, Phase::Phase1);
    assert!(matches!(
        first.actions.disruptive,
        Some(aegis_engine::model::Disruptive::Deny { status: 451 })
    ));
    assert_eq!(second.phase, Phase::Phase2);
    assert!(second.actions.disruptive.is_none());
}

#[test]
fn explicit_pass_overrides_default_deny() {
    let rules = load(
        r#"
SecDefaultAction "phase:1,deny,status:403"
SecRule REQUEST_URI "@contains /public" "id:1,pass"
"#,
    )
    .unwrap();
    let RuleGroup::Single(rule) = &rules.phase1[0] else {
        panic!("expected single rule");
    };
    assert!(rule.actions.disruptive.is_none());
}

#[test]
fn sec_action_inherits_default_phase_and_deny() {
    let rules = load(
        r#"
SecDefaultAction "phase:1,deny,status:451,log"
SecAction "id:1,setvar:tx.x=1"
"#,
    )
    .unwrap();
    let RuleGroup::Single(rule) = &rules.phase1[0] else {
        panic!("expected single rule");
    };
    assert!(rule.unconditional);
    assert_eq!(rule.phase, Phase::Phase1);
    assert!(matches!(
        rule.actions.disruptive,
        Some(aegis_engine::model::Disruptive::Deny { status: 451 })
    ));
    assert!(rule.actions.log);
}

#[test]
fn block_uses_default_disruptive_action() {
    let rules = load(
        r#"
SecDefaultAction "phase:2,pass"
SecRule ARGS "@contains x" "id:1,phase:2,block"
"#,
    )
    .unwrap();
    let RuleGroup::Single(rule) = &rules.phase2[0] else {
        panic!("expected single rule");
    };
    assert!(rule.actions.disruptive.is_none());
}

#[test]
fn block_defaults_to_deny_without_default_action() {
    let rules = load(r#"SecRule ARGS "@contains x" "id:1,phase:2,block""#).unwrap();
    let RuleGroup::Single(rule) = &rules.phase2[0] else {
        panic!("expected single rule");
    };
    assert!(matches!(
        rule.actions.disruptive,
        Some(aegis_engine::model::Disruptive::Deny { status: 403 })
    ));
}

#[test]
fn rejects_block_in_sec_default_action() {
    let error = load(r#"SecDefaultAction "phase:1,block""#).unwrap_err();
    assert!(
        error.to_string().contains("SecDefaultAction"),
        "unexpected error: {error}"
    );
}

#[test]
fn rejects_invalid_regex_with_location() {
    let error = load(r#"SecRule ARGS "@rx (" "id:1,deny""#).unwrap_err();
    let message = error.to_string();
    assert!(
        message.contains("rules.conf:1:1"),
        "unexpected message: {message}"
    );
    assert!(
        message.contains("invalid regex"),
        "unexpected message: {message}"
    );
}

#[test]
fn compiles_regex_selectors() {
    let rules =
        load(r#"SecRule REQUEST_COOKIES:/^_ga/ "@contains x" "id:1,phase:1,pass""#).unwrap();
    let RuleGroup::Single(rule) = &rules.phase1[0] else {
        panic!("expected single rule");
    };
    assert!(matches!(
        rule.variables[0].variable,
        Variable::RequestCookies(Some(Selector::Regex(_)))
    ));
}

#[test]
fn rejects_invalid_selector_regex() {
    let error =
        load(r#"SecRule REQUEST_COOKIES:/(/ "@contains x" "id:1,phase:1,deny""#).unwrap_err();
    let message = error.to_string();
    assert!(
        message.contains("rules.conf:1:1"),
        "unexpected message: {message}"
    );
    assert!(
        message.contains("invalid selector regex"),
        "unexpected message: {message}"
    );
}

#[test]
fn rejects_count_of_count_and_negated_count() {
    let error = load(r#"SecRule &&ARGS "@gt 0" "id:1,pass""#).unwrap_err();
    assert!(error.to_string().contains("count"));
    let error = load(r#"SecRule !&ARGS "@gt 0" "id:1,pass""#).unwrap_err();
    assert!(error.to_string().contains("count"));
}

#[test]
fn compiles_macro_numeric_arguments() {
    let rules = load(r#"SecRule &ARGS "@gt %{tx.limit}" "id:1,phase:1,pass""#).unwrap();
    assert_eq!(rules.rule_count, 1);
}

#[test]
fn compiles_rule_remove_by_id_range() {
    let rules =
        load(r#"SecRule ARGS "@contains x" "id:1,phase:1,pass,ctl:ruleRemoveById=1-999999""#)
            .unwrap();
    let RuleGroup::Single(rule) = &rules.phase1[0] else {
        panic!("expected single rule");
    };
    assert_eq!(
        rule.actions.ctl,
        vec![CtlAction::RemoveRuleById(RuleIdRange {
            start: 1,
            end: 999999,
        })]
    );
}

#[test]
fn compiles_rule_remove_by_id_single_value() {
    let rules =
        load(r#"SecRule ARGS "@contains x" "id:1,phase:1,pass,ctl:ruleRemoveById=3""#).unwrap();
    let RuleGroup::Single(rule) = &rules.phase1[0] else {
        panic!("expected single rule");
    };
    assert_eq!(
        rule.actions.ctl,
        vec![CtlAction::RemoveRuleById(RuleIdRange { start: 3, end: 3 })]
    );
}

#[test]
fn rejects_reversed_rule_remove_by_id_range() {
    let error = load(r#"SecRule ARGS "@contains x" "id:1,phase:1,pass,ctl:ruleRemoveById=9-1""#)
        .unwrap_err();
    assert!(error.to_string().contains("invalid ruleRemoveById range"));
}

#[test]
fn compiles_ctl_extensions() {
    let rules = load(
        r#"
SecRule ARGS "@contains x" "id:1,phase:1,pass,ctl:requestBodyProcessor=JSON"
SecRule ARGS "@contains x" "id:2,phase:1,pass,ctl:forceRequestBodyVariable=On"
SecRule ARGS "@contains x" "id:3,phase:1,pass,ctl:ruleRemoveTargetByTag=t;ARGS:foo"
"#,
    )
    .unwrap();
    assert_eq!(rules.rule_count, 3);
}
