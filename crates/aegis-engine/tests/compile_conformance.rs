use std::fs;

use aegis_engine::compile::{load_rules, LoadOptions};
use aegis_engine::model::{CompiledOperator, Phase, RuleGroup, Variable};
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
    assert!(matches!(rule.variables[0].variable, Variable::Args));
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
        Variable::RequestHeaders(Some(name)) if name == "User-Agent"
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
fn rejects_unsupported_phase_in_strict_mode() {
    let error = load(r#"SecRule ARGS "@rx a" "id:1,phase:3,deny""#).unwrap_err();
    assert!(error.to_string().contains("phase 3"));
}

#[test]
fn skips_unsupported_phase_in_lenient_mode() {
    let rules = load_lenient(r#"SecRule ARGS "@rx a" "id:1,phase:3,deny""#);
    assert_eq!(rules.rule_count, 0);
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
SecRule ARGS "@rx a" "id:1,phase:1,chain,deny"
SecRule ARGS "@rx b" "id:2,phase:1,deny"
"#,
    )
    .unwrap_err();
    assert!(error.to_string().contains("chain"));
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
