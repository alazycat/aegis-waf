use std::fmt::Write as _;
use std::fs;
use std::hint::black_box;
use std::time::Duration;

use aegis_engine::{evaluate, load_rules, CompiledRules, LoadOptions, RequestView};
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use http::{HeaderMap, HeaderValue};
use tempfile::tempdir;

const BASE_RULES: &str = include_str!("../../../rules/examples/base.conf");
const WHITELIST: &str = include_str!("../../../rules/examples/whitelist.conf");

fn compile_text(text: &str) -> (tempfile::TempDir, CompiledRules) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("rules.conf");
    fs::write(&path, text).unwrap();
    let rules = load_rules(
        &[path],
        &LoadOptions {
            lenient: false,
            version: 1,
        },
    )
    .unwrap();
    (dir, rules)
}

fn header_map(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in pairs {
        headers.append(
            http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    headers
}

fn bench_evaluate(c: &mut Criterion) {
    let (_example_dir, example_rules) = compile_text(&format!("{WHITELIST}\n{BASE_RULES}"));
    let (_empty_dir, empty_rules) = compile_text("");

    let mut many_rules_text = String::new();
    for index in 0..100 {
        writeln!(
            many_rules_text,
            "SecRule ARGS \"@contains needle{index}\" \"id:{},phase:2,pass\"",
            10_000 + index
        )
        .unwrap();
    }
    let (_many_dir, many_rules) = compile_text(&many_rules_text);

    let request_headers = header_map(&[("host", "bench.test"), ("user-agent", "aegis-bench/1.0")]);
    let body_headers = header_map(&[
        ("host", "bench.test"),
        ("user-agent", "aegis-bench/1.0"),
        ("content-type", "application/x-www-form-urlencoded"),
    ]);
    let remote_addr = "127.0.0.1".parse().unwrap();

    let safe = RequestView {
        method: "GET",
        uri: "/search?q=hello",
        path: "/search",
        query: Some("q=hello"),
        headers: &request_headers,
        body: b"",
        remote_addr,
    };
    let blocked_xss = RequestView {
        method: "GET",
        uri: "/search?q=%3Cscript%3E",
        path: "/search",
        query: Some("q=%3Cscript%3E"),
        headers: &request_headers,
        body: b"",
        remote_addr,
    };
    let blocked_body = RequestView {
        method: "POST",
        uri: "/submit",
        path: "/submit",
        query: None,
        headers: &body_headers,
        body: b"q=union+select",
        remote_addr,
    };

    let mut group = c.benchmark_group("evaluate");
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(3));
    group.sample_size(50);
    group.throughput(Throughput::Elements(1));
    group.bench_function("safe_8_rules", |b| {
        b.iter(|| black_box(evaluate(&example_rules, &safe)))
    });
    group.bench_function("block_xss_8_rules", |b| {
        b.iter(|| black_box(evaluate(&example_rules, &blocked_xss)))
    });
    group.bench_function("block_body_sqli_8_rules", |b| {
        b.iter(|| black_box(evaluate(&example_rules, &blocked_body)))
    });
    group.bench_function("safe_no_rules", |b| {
        b.iter(|| black_box(evaluate(&empty_rules, &safe)))
    });
    group.bench_function("safe_100_simple_rules", |b| {
        b.iter(|| black_box(evaluate(&many_rules, &safe)))
    });
    group.finish();
}

fn bench_compile(c: &mut Criterion) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("rules.conf");
    fs::write(&path, format!("{WHITELIST}\n{BASE_RULES}")).unwrap();
    let files = [path];
    let options = LoadOptions {
        lenient: false,
        version: 1,
    };

    let mut group = c.benchmark_group("compile");
    group.warm_up_time(Duration::from_millis(300));
    group.measurement_time(Duration::from_secs(2));
    group.sample_size(30);
    group.bench_function("example_rules", |b| {
        b.iter(|| black_box(load_rules(&files, &options).unwrap()))
    });
    group.finish();
}

fn bench_engine(c: &mut Criterion) {
    bench_evaluate(c);
    bench_compile(c);
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = bench_engine
}
criterion_main!(benches);
