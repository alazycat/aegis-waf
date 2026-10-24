use std::fs;

use aegis_engine::model::CompiledRules;
use aegis_engine::{evaluate, load_rules, Decision, LoadOptions, RequestView};
use http::{HeaderMap, HeaderValue};
use tempfile::tempdir;

fn load(text: &str) -> CompiledRules {
    let dir = tempdir().unwrap();
    let path = dir.path().join("rules.conf");
    fs::write(&path, text).unwrap();
    load_rules(
        &[path],
        &LoadOptions {
            lenient: false,
            version: 7,
        },
    )
    .unwrap()
}

fn request<'a>(
    headers: &'a HeaderMap,
    method: &'a str,
    uri: &'a str,
    body: &'a [u8],
) -> RequestView<'a> {
    RequestView {
        method,
        uri,
        path: uri.split_once('?').map(|(path, _)| path).unwrap_or(uri),
        query: uri.split_once('?').map(|(_, query)| query),
        protocol: "HTTP/1.1",
        headers,
        body,
        remote_addr: "198.51.100.9".parse().unwrap(),
        unique_id: "test-unique-id",
    }
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

#[test]
fn crs_style_anomaly_scoring_blocks_at_threshold() {
    let rules = load(
        r#"
SecAction "id:901001,phase:1,pass,setvar:tx.anomaly_score=0"
SecRule REQUEST_HEADERS:User-Agent "@contains nikto" "id:913100,phase:1,pass,setvar:tx.anomaly_score=+5"
SecRule REQUEST_URI "@contains /admin" "id:973300,phase:2,pass,setvar:tx.anomaly_score=+5"
SecRule TX:ANOMALY_SCORE "@ge 10" "id:949110,phase:2,deny,status:403,msg:'Inbound Anomaly Score Exceeded: %{tx.anomaly_score}'"
"#,
    );
    let headers = headers(&[("user-agent", "nikto/2.5")]);
    let view = request(&headers, "GET", "/admin?x=1", b"");
    let evaluation = evaluate(&rules, &view);
    assert_eq!(
        evaluation.decision,
        Decision::Block {
            status: 403,
            rule_id: 949110,
            msg: Some("Inbound Anomaly Score Exceeded: 10".to_string()),
        }
    );
    assert_eq!(evaluation.matched.len(), 4);
}

#[test]
fn allow_rule_short_circuits_body_inspection() {
    let rules = load(
        r#"
SecRule REQUEST_HEADERS:X-Allow "@eq 1" "id:1,phase:1,allow"
SecRule REQUEST_BODY "@contains attack" "id:2,phase:2,deny"
"#,
    );
    let headers = headers(&[("x-allow", "1")]);
    let view = request(&headers, "POST", "/", b"attack");
    let evaluation = evaluate(&rules, &view);
    assert_eq!(evaluation.decision, Decision::Allow { rule_id: 1 });
}

#[test]
fn body_rule_runs_only_when_phase_one_passes() {
    let rules = load(r#"SecRule REQUEST_BODY "@contains attack" "id:2,phase:2,deny,status:403""#);
    let headers = headers(&[]);
    let blocked = evaluate(&rules, &request(&headers, "POST", "/", b"attack"));
    assert!(matches!(
        blocked.decision,
        Decision::Block { rule_id: 2, .. }
    ));
    let passed = evaluate(&rules, &request(&headers, "POST", "/", b"safe"));
    assert_eq!(passed.decision, Decision::Pass);
}

#[test]
fn rule_match_without_log_action_is_not_logged() {
    let rules = load(r#"SecRule ARGS "@contains x" "id:1,phase:1,pass""#);
    let headers = headers(&[]);
    let view = request(&headers, "GET", "/?a=x", b"");
    let evaluation = evaluate(&rules, &view);
    assert_eq!(evaluation.matched[0].id, 1);
    assert!(!evaluation.matched[0].log);
}

#[test]
fn validate_byte_range_flags_invalid_bytes() {
    let rules = load(r#"SecRule ARGS "@validateByteRange 32-126" "id:1,phase:1,deny""#);
    let headers = headers(&[]);
    let view = request(&headers, "GET", "/?q=hello", b"");
    assert_eq!(evaluate(&rules, &view).decision, Decision::Pass);
    let view = request(&headers, "GET", "/?q=hel%00lo", b"");
    assert!(matches!(
        evaluate(&rules, &view).decision,
        Decision::Block { rule_id: 1, .. }
    ));
}
