use std::fs;

use aegis_engine::parser::directive::Directive;
use aegis_engine::parser::parse_files;
use tempfile::tempdir;

#[test]
fn parses_rule_and_actions() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("rules.conf");
    fs::write(
        &path,
        r#"SecRule ARGS|REQUEST_HEADERS:User-Agent "@rx foo" "id:1001,phase:2,deny,status:403,msg:'bad',t:lowercase"
"#,
    )
    .unwrap();

    let directives = parse_files(&[path]).unwrap();
    assert_eq!(directives.len(), 1);
    match &directives[0].directive {
        Directive::Rule(rule) => {
            assert_eq!(rule.variables, "ARGS|REQUEST_HEADERS:User-Agent");
            assert_eq!(rule.operator, "@rx foo");
            assert_eq!(
                rule.actions,
                "id:1001,phase:2,deny,status:403,msg:'bad',t:lowercase"
            );
            assert_eq!(rule.line, 1);
        }
        other => panic!("unexpected directive: {other:?}"),
    }
}

#[test]
fn expands_includes_recursively() {
    let dir = tempdir().unwrap();
    let base = dir.path().join("base.conf");
    let child = dir.path().join("child.conf");
    fs::write(&child, "SecMarker CHILD\n").unwrap();
    fs::write(&base, "Include child.conf\nSecMarker BASE\n").unwrap();

    let directives = parse_files(&[base]).unwrap();
    assert_eq!(directives.len(), 2);
    assert!(matches!(&directives[0].directive, Directive::Marker(value) if value == "CHILD"));
    assert!(matches!(&directives[1].directive, Directive::Marker(value) if value == "BASE"));
}

#[test]
fn reports_parse_error_with_line_and_column() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("bad.conf");
    fs::write(&path, "SecRule ARGS\n").unwrap();

    let error = parse_files(&[path]).unwrap_err();
    let message = error.to_string();
    assert!(
        message.contains("bad.conf:1:1"),
        "unexpected message: {message}"
    );
    assert!(
        message.contains("expects 3 arguments"),
        "unexpected message: {message}"
    );
}

#[test]
fn detects_include_cycles() {
    let dir = tempdir().unwrap();
    let a = dir.path().join("a.conf");
    let b = dir.path().join("b.conf");
    fs::write(&a, "Include b.conf\n").unwrap();
    fs::write(&b, "Include a.conf\n").unwrap();

    let error = parse_files(&[a]).unwrap_err();
    assert!(
        error.to_string().contains("cycle"),
        "unexpected error: {error}"
    );
}

#[test]
fn preserves_unknown_directives_for_lenient_handling() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("unknown.conf");
    fs::write(&path, "SecFutureThing foo\n").unwrap();
    let directives = parse_files(&[path]).unwrap();
    assert!(matches!(
        &directives[0].directive,
        Directive::Unknown { name, .. } if name == "SecFutureThing"
    ));
}
