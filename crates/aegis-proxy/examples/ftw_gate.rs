use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::process::ExitCode;

use serde::Deserialize;

const GATE_PREFIXES: &[&str] = &[
    "911", "913", "920", "921", "930", "931", "932", "933", "941", "942", "943", "949",
];

#[derive(Debug, Deserialize)]
struct RunStats {
    #[serde(default)]
    run: usize,
    #[serde(default)]
    success: Vec<String>,
    #[serde(default)]
    failed: Vec<String>,
    #[serde(default)]
    skipped: Vec<String>,
}

fn rule_prefix(test_id: &str) -> &str {
    test_id
        .split('-')
        .next()
        .unwrap_or("")
        .get(..3)
        .unwrap_or("")
}

fn in_gate(test_id: &str) -> bool {
    GATE_PREFIXES.contains(&rule_prefix(test_id))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: ftw_gate <report.json> <known-gaps.txt>");
        return ExitCode::from(2);
    }
    let report = match fs::read_to_string(&args[1]) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("failed to read report {}: {error}", args[1]);
            return ExitCode::FAILURE;
        }
    };
    let stats: RunStats = match serde_json::from_str(&report) {
        Ok(stats) => stats,
        Err(error) => {
            eprintln!("failed to parse report {}: {error}", args[1]);
            return ExitCode::FAILURE;
        }
    };
    let gaps = match load_gaps(&args[2]) {
        Ok(gaps) => gaps,
        Err(error) => {
            eprintln!("failed to read known gaps {}: {error}", args[2]);
            return ExitCode::FAILURE;
        }
    };

    let gate_failures: Vec<&str> = stats
        .failed
        .iter()
        .map(String::as_str)
        .filter(|id| in_gate(id))
        .collect();
    let unknown: Vec<&str> = gate_failures
        .iter()
        .copied()
        .filter(|id| !gaps.contains_key(*id))
        .collect();
    let known: Vec<&str> = gate_failures
        .iter()
        .copied()
        .filter(|id| gaps.contains_key(*id))
        .collect();
    let stale: Vec<&str> = gaps
        .keys()
        .map(String::as_str)
        .filter(|id| stats.success.iter().any(|success| success.as_str() == *id))
        .collect();
    let gate_passed = stats
        .success
        .iter()
        .map(String::as_str)
        .filter(|id| in_gate(id))
        .count();

    let mut failed_by_prefix: BTreeMap<&str, usize> = BTreeMap::new();
    for id in &stats.failed {
        *failed_by_prefix
            .entry(rule_prefix(id.as_str()))
            .or_insert(0) += 1;
    }

    println!(
        "go-ftw: run={} success={} failed={} skipped={}",
        stats.run,
        stats.success.len(),
        stats.failed.len(),
        stats.skipped.len()
    );
    println!(
        "gate: passed={} failed={} known-gap={} stale-gap={}",
        gate_passed,
        unknown.len(),
        known.len(),
        stale.len()
    );
    println!("failed by rule prefix: {failed_by_prefix:?}");
    for id in &unknown {
        eprintln!("GATE FAILURE {id}");
    }
    for id in &known {
        println!(
            "known gap {id}: {}",
            gaps.get(*id).map(String::as_str).unwrap_or("")
        );
    }
    for id in &stale {
        println!("stale known gap {id}: now passing, remove it from the list");
    }
    if gate_passed + gate_failures.len() == 0 {
        eprintln!("no gate tests ran");
        return ExitCode::FAILURE;
    }
    if unknown.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn load_gaps(path: &str) -> Result<HashMap<String, String>, std::io::Error> {
    let text = fs::read_to_string(path)?;
    let mut gaps = HashMap::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let Some(id) = parts.next() else {
            continue;
        };
        let reason = parts.next().unwrap_or("").trim().to_string();
        if reason.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("known gap at line {} has no reason", index + 1),
            ));
        }
        gaps.insert(id.to_string(), reason);
    }
    Ok(gaps)
}
