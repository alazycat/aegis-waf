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

fn simple_rules(count: usize) -> String {
    let mut text = String::new();
    for index in 0..count {
        writeln!(
            text,
            "SecRule ARGS \"@contains needle-{index:04}\" \"id:{},phase:2,pass\"",
            10_000 + index
        )
        .unwrap();
    }
    text
}

fn regex_lowercase_rules(count: usize) -> String {
    let mut text = String::new();
    for index in 0..count {
        writeln!(
            text,
            "SecRule ARGS \"@rx rxneedle-{index:04}\" \"id:{},phase:2,pass,t:lowercase\"",
            30_000 + index
        )
        .unwrap();
    }
    text
}

fn regex_ignorecase_rules(count: usize) -> String {
    let mut text = String::new();
    for index in 0..count {
        writeln!(
            text,
            "SecRule ARGS \"@rx (?i)icase-{index:04}\" \"id:{},phase:2,pass\"",
            40_000 + index
        )
        .unwrap();
    }
    text
}

fn bench_evaluate(c: &mut Criterion) {
    let (_example_dir, example_rules) = compile_text(&format!("{WHITELIST}\n{BASE_RULES}"));
    let (_empty_dir, empty_rules) = compile_text("");
    let (_rules100_dir, rules100) = compile_text(&simple_rules(100));
    let (_rules200_dir, rules200) = compile_text(&simple_rules(200));
    let (_rules500_dir, rules500) = compile_text(&simple_rules(500));
    let (_regex200_dir, regex200) = compile_text(&regex_lowercase_rules(200));
    let (_regex500_dir, regex500) = compile_text(&regex_lowercase_rules(500));
    let (_icase200_dir, icase200) = compile_text(&regex_ignorecase_rules(200));
    let (_icase500_dir, icase500) = compile_text(&regex_ignorecase_rules(500));

    let request_headers = header_map(&[("host", "bench.test"), ("user-agent", "aegis-bench/1.0")]);
    let body_headers = header_map(&[
        ("host", "bench.test"),
        ("user-agent", "aegis-bench/1.0"),
        ("content-type", "application/x-www-form-urlencoded"),
    ]);
    let remote_addr = "127.0.0.1".parse().unwrap();
    let unique_id = "bench-unique-id";

    let safe = RequestView {
        method: "GET",
        uri: "/search?q=hello",
        path: "/search",
        query: Some("q=hello"),
        headers: &request_headers,
        body: b"",
        protocol: "HTTP/1.1",
        remote_addr,
        unique_id,
    };
    let blocked_xss = RequestView {
        method: "GET",
        uri: "/search?q=%3Cscript%3E",
        path: "/search",
        query: Some("q=%3Cscript%3E"),
        headers: &request_headers,
        body: b"",
        protocol: "HTTP/1.1",
        remote_addr,
        unique_id,
    };
    let blocked_body = RequestView {
        method: "POST",
        uri: "/submit",
        path: "/submit",
        query: None,
        headers: &body_headers,
        body: b"q=union+select",
        protocol: "HTTP/1.1",
        remote_addr,
        unique_id,
    };
    let match200_uri = "/search?q=needle-0199";
    let match200_query = "q=needle-0199";
    let match200 = RequestView {
        method: "GET",
        uri: match200_uri,
        path: "/search",
        query: Some(match200_query),
        headers: &request_headers,
        body: b"",
        protocol: "HTTP/1.1",
        remote_addr,
        unique_id,
    };
    let match500_uri = "/search?q=needle-0499";
    let match500_query = "q=needle-0499";
    let match500 = RequestView {
        method: "GET",
        uri: match500_uri,
        path: "/search",
        query: Some(match500_query),
        headers: &request_headers,
        body: b"",
        protocol: "HTTP/1.1",
        remote_addr,
        unique_id,
    };
    let match_regex200_uri = "/search?q=rxneedle-0199";
    let match_regex200_query = "q=rxneedle-0199";
    let match_regex200 = RequestView {
        method: "GET",
        uri: match_regex200_uri,
        path: "/search",
        query: Some(match_regex200_query),
        headers: &request_headers,
        body: b"",
        protocol: "HTTP/1.1",
        remote_addr,
        unique_id,
    };
    let match_regex500_uri = "/search?q=rxneedle-0499";
    let match_regex500_query = "q=rxneedle-0499";
    let match_regex500 = RequestView {
        method: "GET",
        uri: match_regex500_uri,
        path: "/search",
        query: Some(match_regex500_query),
        headers: &request_headers,
        body: b"",
        protocol: "HTTP/1.1",
        remote_addr,
        unique_id,
    };
    let match_icase200_uri = "/search?q=ICASE-0199";
    let match_icase200_query = "q=ICASE-0199";
    let match_icase200 = RequestView {
        method: "GET",
        uri: match_icase200_uri,
        path: "/search",
        query: Some(match_icase200_query),
        headers: &request_headers,
        body: b"",
        protocol: "HTTP/1.1",
        remote_addr,
        unique_id,
    };
    let match_icase500_uri = "/search?q=ICASE-0499";
    let match_icase500_query = "q=ICASE-0499";
    let match_icase500 = RequestView {
        method: "GET",
        uri: match_icase500_uri,
        path: "/search",
        query: Some(match_icase500_query),
        headers: &request_headers,
        body: b"",
        protocol: "HTTP/1.1",
        remote_addr,
        unique_id,
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
        b.iter(|| black_box(evaluate(&rules100, &safe)))
    });
    group.bench_function("safe_200_simple_rules", |b| {
        b.iter(|| black_box(evaluate(&rules200, &safe)))
    });
    group.bench_function("safe_500_simple_rules", |b| {
        b.iter(|| black_box(evaluate(&rules500, &safe)))
    });
    group.bench_function("match_one_200_simple_rules", |b| {
        b.iter(|| black_box(evaluate(&rules200, &match200)))
    });
    group.bench_function("match_one_500_simple_rules", |b| {
        b.iter(|| black_box(evaluate(&rules500, &match500)))
    });
    group.bench_function("safe_200_regex_lowercase_rules", |b| {
        b.iter(|| black_box(evaluate(&regex200, &safe)))
    });
    group.bench_function("safe_500_regex_lowercase_rules", |b| {
        b.iter(|| black_box(evaluate(&regex500, &safe)))
    });
    group.bench_function("match_one_200_regex_lowercase_rules", |b| {
        b.iter(|| black_box(evaluate(&regex200, &match_regex200)))
    });
    group.bench_function("match_one_500_regex_lowercase_rules", |b| {
        b.iter(|| black_box(evaluate(&regex500, &match_regex500)))
    });
    group.bench_function("safe_200_ignorecase_regex_rules", |b| {
        b.iter(|| black_box(evaluate(&icase200, &safe)))
    });
    group.bench_function("safe_500_ignorecase_regex_rules", |b| {
        b.iter(|| black_box(evaluate(&icase500, &safe)))
    });
    group.bench_function("match_one_200_ignorecase_regex_rules", |b| {
        b.iter(|| black_box(evaluate(&icase200, &match_icase200)))
    });
    group.bench_function("match_one_500_ignorecase_regex_rules", |b| {
        b.iter(|| black_box(evaluate(&icase500, &match_icase500)))
    });
    group.finish();
}

fn bench_compile(c: &mut Criterion) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("rules.conf");
    fs::write(&path, format!("{WHITELIST}\n{BASE_RULES}")).unwrap();
    let files = [path];

    let dir500 = tempdir().unwrap();
    let path500 = dir500.path().join("rules.conf");
    fs::write(&path500, simple_rules(500)).unwrap();
    let files500 = [path500];

    let dir_regex500 = tempdir().unwrap();
    let path_regex500 = dir_regex500.path().join("rules.conf");
    fs::write(&path_regex500, regex_lowercase_rules(500)).unwrap();
    let files_regex500 = [path_regex500];

    let dir_icase500 = tempdir().unwrap();
    let path_icase500 = dir_icase500.path().join("rules.conf");
    fs::write(&path_icase500, regex_ignorecase_rules(500)).unwrap();
    let files_icase500 = [path_icase500];

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
    group.bench_function("500_simple_rules", |b| {
        b.iter(|| black_box(load_rules(&files500, &options).unwrap()))
    });
    group.bench_function("500_regex_lowercase_rules", |b| {
        b.iter(|| black_box(load_rules(&files_regex500, &options).unwrap()))
    });
    group.bench_function("500_ignorecase_regex_rules", |b| {
        b.iter(|| black_box(load_rules(&files_icase500, &options).unwrap()))
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
