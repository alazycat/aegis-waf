use std::fs;

use aegis_proxy::rules::RulesManager;
use tempfile::tempdir;

#[tokio::test]
async fn reload_replaces_rules_and_increments_version() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("rules.conf");
    fs::write(&path, r#"SecRule ARGS "@rx a" "id:1,phase:1,pass""#).unwrap();

    let manager = RulesManager::load_initial(std::slice::from_ref(&path), false).unwrap();
    assert_eq!(manager.snapshot().version, 1);
    assert_eq!(manager.snapshot().rule_count, 1);

    fs::write(
        &path,
        r#"
SecRule ARGS "@rx a" "id:1,phase:1,pass"
SecRule ARGS "@rx b" "id:2,phase:1,pass"
"#,
    )
    .unwrap();
    let reloaded = manager.reload().await.unwrap();
    assert_eq!(reloaded.version, 2);
    assert_eq!(reloaded.rule_count, 2);
    assert_eq!(manager.snapshot().version, 2);
}

#[tokio::test]
async fn failed_reload_keeps_previous_rules() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("rules.conf");
    fs::write(&path, r#"SecRule ARGS "@rx a" "id:1,phase:1,pass""#).unwrap();

    let manager = RulesManager::load_initial(std::slice::from_ref(&path), false).unwrap();
    fs::write(&path, "SecRule ARGS \"@rx (\" \"id:2,deny\"\n").unwrap();

    let error = manager.reload().await.unwrap_err();
    assert!(
        error.to_string().contains("invalid regex"),
        "error: {error}"
    );
    assert_eq!(manager.snapshot().version, 1);
    assert_eq!(manager.snapshot().rule_count, 1);
}

#[tokio::test]
async fn loaded_at_changes_after_successful_reload() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("rules.conf");
    fs::write(&path, r#"SecMarker A"#).unwrap();
    let manager = RulesManager::load_initial(std::slice::from_ref(&path), false).unwrap();
    let before = manager.loaded_at();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    fs::write(&path, "SecMarker B\n").unwrap();
    manager.reload().await.unwrap();
    assert_ne!(before, manager.loaded_at());
}
