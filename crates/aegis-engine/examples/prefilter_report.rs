use std::path::PathBuf;

use aegis_engine::model::{CompiledOperator, RuleGroup, Variable};
use aegis_engine::parser::{parse_files, Directive};
use aegis_engine::{load_rules, LoadOptions};

fn percent(part: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        part as f64 * 100.0 / total as f64
    }
}

#[derive(Default)]
struct Breakdown {
    ac_groups: usize,
    ac_rules: usize,
    regex_groups: usize,
    regex_rules: usize,
    sec_action_groups: usize,
    sec_action_rules: usize,
    tx_groups: usize,
    tx_rules: usize,
    remote_addr_groups: usize,
    remote_addr_rules: usize,
    negated_groups: usize,
    negated_rules: usize,
    empty_regex_groups: usize,
    empty_regex_rules: usize,
    small_regex_groups: usize,
    small_regex_rules: usize,
    other_groups: usize,
    other_rules: usize,
}

impl Breakdown {
    fn add(&mut self, reason: &str, rules: usize) {
        match reason {
            "ac" => {
                self.ac_groups += 1;
                self.ac_rules += rules;
            }
            "regex_set" => {
                self.regex_groups += 1;
                self.regex_rules += rules;
            }
            "sec_action" => {
                self.sec_action_groups += 1;
                self.sec_action_rules += rules;
            }
            "tx" => {
                self.tx_groups += 1;
                self.tx_rules += rules;
            }
            "remote_addr" => {
                self.remote_addr_groups += 1;
                self.remote_addr_rules += rules;
            }
            "negated" => {
                self.negated_groups += 1;
                self.negated_rules += rules;
            }
            "empty_regex" => {
                self.empty_regex_groups += 1;
                self.empty_regex_rules += rules;
            }
            "small_regex" => {
                self.small_regex_groups += 1;
                self.small_regex_rules += rules;
            }
            _ => {
                self.other_groups += 1;
                self.other_rules += rules;
            }
        }
    }

    fn print(&self) {
        let rows = [
            ("ac", self.ac_groups, self.ac_rules),
            ("regex_set", self.regex_groups, self.regex_rules),
            ("sec_action", self.sec_action_groups, self.sec_action_rules),
            ("tx", self.tx_groups, self.tx_rules),
            (
                "remote_addr",
                self.remote_addr_groups,
                self.remote_addr_rules,
            ),
            ("negated_operator", self.negated_groups, self.negated_rules),
            (
                "empty_matching_regex",
                self.empty_regex_groups,
                self.empty_regex_rules,
            ),
            (
                "small_regex_set",
                self.small_regex_groups,
                self.small_regex_rules,
            ),
            ("other", self.other_groups, self.other_rules),
        ];
        println!("breakdown:");
        for (label, groups, rules) in rows {
            println!("  {label}: groups={groups} rules={rules}");
        }
    }
}

fn classify_group(group: &RuleGroup) -> (&'static str, usize) {
    let (first, rule_count) = match group {
        RuleGroup::Single(rule) => (rule.as_ref(), 1),
        RuleGroup::Chain(rules) => (&rules[0], rules.len()),
    };
    if let Some(prefilter) = &first.prefilter {
        return if prefilter.ac_patterns.is_empty() {
            ("regex_set", rule_count)
        } else {
            ("ac", rule_count)
        };
    }
    if first.unconditional {
        return ("sec_action", rule_count);
    }
    if first
        .variables
        .iter()
        .any(|spec| matches!(spec.variable, Variable::Tx(_)))
    {
        return ("tx", rule_count);
    }
    if first
        .variables
        .iter()
        .any(|spec| matches!(spec.variable, Variable::RemoteAddr))
    {
        return ("remote_addr", rule_count);
    }
    if first.operator_negated {
        return ("negated", rule_count);
    }
    if matches!(&first.operator, CompiledOperator::Rx(regex) if regex.is_match("")) {
        return ("empty_regex", rule_count);
    }
    if matches!(&first.operator, CompiledOperator::Rx(_)) {
        return ("small_regex", rule_count);
    }
    ("other", rule_count)
}

fn main() {
    let requested: Vec<PathBuf> = std::env::args().skip(1).map(PathBuf::from).collect();
    if requested.is_empty() {
        eprintln!("usage: prefilter_report <rule-file>...");
        std::process::exit(2);
    }

    let mut parseable = Vec::new();
    let mut parse_failures = Vec::new();
    let mut rule_directives = 0usize;
    let mut action_directives = 0usize;
    let mut default_actions = 0usize;

    for file in &requested {
        match parse_files(std::slice::from_ref(file)) {
            Ok(directives) => {
                for located in &directives {
                    match &located.directive {
                        Directive::Rule(_) => rule_directives += 1,
                        Directive::Action(_) => action_directives += 1,
                        Directive::DefaultAction(_) => default_actions += 1,
                        _ => {}
                    }
                }
                parseable.push(file.clone());
            }
            Err(error) => parse_failures.push((file.clone(), error.to_string())),
        }
    }

    let compiled = match load_rules(
        &parseable,
        &LoadOptions {
            lenient: true,
            version: 1,
        },
    ) {
        Ok(compiled) => compiled,
        Err(error) => {
            eprintln!("failed to compile parseable files: {error}");
            std::process::exit(1);
        }
    };

    let stats = compiled.prefilter_stats();
    let total_rule_directives = rule_directives + action_directives;
    let skipped = total_rule_directives.saturating_sub(compiled.rule_count);

    println!("requested_files={}", requested.len());
    println!("parseable_files={}", parseable.len());
    println!("parse_failures={}", parse_failures.len());
    for (file, error) in &parse_failures {
        println!("  skipped_file={} reason={}", file.display(), error);
    }
    println!(
        "default_actions={} rule_directives={} action_directives={}",
        default_actions, rule_directives, action_directives
    );
    println!(
        "compiled_rules={} skipped_rule_directives={} ({:.1}%)",
        compiled.rule_count,
        skipped,
        percent(skipped, total_rule_directives)
    );
    println!(
        "groups={} prefiltered={} ({:.1}%) ac={} regex_set={} none={}",
        stats.total_groups,
        stats.prefiltered_groups,
        percent(stats.prefiltered_groups, stats.total_groups),
        stats.ac_groups,
        stats.regex_groups,
        stats.total_groups.saturating_sub(stats.prefiltered_groups)
    );
    println!(
        "rules_in_groups={} prefiltered_rules={} ({:.1}%)",
        stats.total_rules,
        stats.prefiltered_rules,
        percent(stats.prefiltered_rules, stats.total_rules)
    );

    let mut breakdown = Breakdown::default();
    for group in compiled.phase1.iter().chain(compiled.phase2.iter()) {
        let (reason, rules) = classify_group(group);
        breakdown.add(reason, rules);
    }
    breakdown.print();

    let operator_groups = stats
        .total_groups
        .saturating_sub(breakdown.sec_action_groups);
    let operator_rules = stats.total_rules.saturating_sub(breakdown.sec_action_rules);
    let prefiltered_operator_groups = breakdown.ac_groups + breakdown.regex_groups;
    let prefiltered_operator_rules = breakdown.ac_rules + breakdown.regex_rules;
    println!(
        "operator_groups={} prefiltered={} ({:.1}%)",
        operator_groups,
        prefiltered_operator_groups,
        percent(prefiltered_operator_groups, operator_groups)
    );
    println!(
        "operator_rules={} prefiltered={} ({:.1}%)",
        operator_rules,
        prefiltered_operator_rules,
        percent(prefiltered_operator_rules, operator_rules)
    );
    let non_tx_groups = operator_groups.saturating_sub(breakdown.tx_groups);
    let non_tx_rules = operator_rules.saturating_sub(breakdown.tx_rules);
    println!(
        "non_tx_operator_groups={} prefiltered={} ({:.1}%)",
        non_tx_groups,
        prefiltered_operator_groups,
        percent(prefiltered_operator_groups, non_tx_groups)
    );
    println!(
        "non_tx_operator_rules={} prefiltered={} ({:.1}%)",
        non_tx_rules,
        prefiltered_operator_rules,
        percent(prefiltered_operator_rules, non_tx_rules)
    );
}
