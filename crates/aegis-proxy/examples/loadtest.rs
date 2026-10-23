use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tokio::time::Instant;

#[derive(Debug, Clone, Copy)]
enum Mode {
    Safe,
    Block,
}

struct Options {
    addr: String,
    mode: Mode,
    path: Option<String>,
    concurrency: usize,
    duration: Duration,
    warmup: Duration,
}

fn parse_args() -> Result<Options, String> {
    let mut addr = "127.0.0.1:18080".to_string();
    let mut mode = Mode::Safe;
    let mut path = None;
    let mut concurrency = 32usize;
    let mut duration = Duration::from_secs(5);
    let mut warmup = Duration::from_secs(1);
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--addr" => addr = args.next().ok_or("--addr requires a value")?,
            "--mode" => {
                mode = match args.next().ok_or("--mode requires a value")?.as_str() {
                    "safe" => Mode::Safe,
                    "block" => Mode::Block,
                    other => return Err(format!("unknown mode {other}")),
                };
            }
            "--path" => path = Some(args.next().ok_or("--path requires a value")?),
            "--concurrency" => {
                concurrency = args
                    .next()
                    .ok_or("--concurrency requires a value")?
                    .parse()
                    .map_err(|error| format!("invalid concurrency: {error}"))?;
            }
            "--duration" => {
                duration = Duration::from_secs(
                    args.next()
                        .ok_or("--duration requires a value")?
                        .parse()
                        .map_err(|error| format!("invalid duration: {error}"))?,
                );
            }
            "--warmup" => {
                warmup = Duration::from_secs(
                    args.next()
                        .ok_or("--warmup requires a value")?
                        .parse()
                        .map_err(|error| format!("invalid warmup: {error}"))?,
                );
            }
            "--help" | "-h" => {
                return Err(
                    "usage: loadtest [--addr host:port] [--mode safe|block] [--path /uri] [--concurrency N] [--duration S] [--warmup S]"
                        .to_string(),
                );
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if concurrency == 0 {
        return Err("concurrency must be greater than zero".to_string());
    }
    if duration.is_zero() {
        return Err("duration must be greater than zero".to_string());
    }
    Ok(Options {
        addr,
        mode,
        path,
        concurrency,
        duration,
        warmup,
    })
}

#[derive(Default)]
struct TaskStats {
    count: u64,
    ok: u64,
    blocked: u64,
    other: u64,
    errors: u64,
    latencies_us: Vec<u64>,
}

impl TaskStats {
    fn merge(&mut self, other: TaskStats) {
        self.count += other.count;
        self.ok += other.ok;
        self.blocked += other.blocked;
        self.other += other.other;
        self.errors += other.errors;
        self.latencies_us.extend(other.latencies_us);
    }
}

async fn run_task(uri: String, start: Instant, deadline: Instant) -> TaskStats {
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build_http();
    let mut stats = TaskStats::default();

    loop {
        let request_start = Instant::now();
        if request_start >= deadline {
            break;
        }
        let record = request_start >= start;
        let request = match Request::builder()
            .uri(uri.as_str())
            .body(Full::new(Bytes::new()))
        {
            Ok(request) => request,
            Err(_) => {
                if record {
                    stats.errors += 1;
                }
                break;
            }
        };
        match client.request(request).await {
            Ok(response) => {
                let status = response.status();
                match response.into_body().collect().await {
                    Ok(_) => {
                        if record {
                            stats.count += 1;
                            stats
                                .latencies_us
                                .push(request_start.elapsed().as_micros() as u64);
                            match status.as_u16() {
                                200..=299 => stats.ok += 1,
                                403 => stats.blocked += 1,
                                _ => stats.other += 1,
                            }
                        }
                    }
                    Err(_) => {
                        if record {
                            stats.errors += 1;
                        }
                    }
                }
            }
            Err(_) => {
                if record {
                    stats.errors += 1;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
    }
    stats
}

fn percentile(sorted: &[u64], fraction: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let index = (((sorted.len() - 1) as f64) * fraction).round() as usize;
    sorted[index] as f64 / 1000.0
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let options = parse_args().map_err(anyhow::Error::msg)?;
    let path = options.path.as_deref().unwrap_or(match options.mode {
        Mode::Safe => "/search?q=hello",
        Mode::Block => "/search?q=%3Cscript%3E",
    });
    let uri = format!("http://{}{}", options.addr, path);
    let start = Instant::now() + options.warmup;
    let deadline = start + options.duration;

    println!(
        "mode={:?} path={} concurrency={} duration={}s warmup={}s",
        options.mode,
        path,
        options.concurrency,
        options.duration.as_secs(),
        options.warmup.as_secs()
    );

    let mut handles = Vec::with_capacity(options.concurrency);
    for _ in 0..options.concurrency {
        let uri = uri.clone();
        handles.push(tokio::spawn(
            async move { run_task(uri, start, deadline).await },
        ));
    }

    let mut stats = TaskStats::default();
    for handle in handles {
        match handle.await {
            Ok(task) => stats.merge(task),
            Err(error) => eprintln!("load task failed: {error}"),
        }
    }

    stats.latencies_us.sort_unstable();
    let mean_ms = if stats.latencies_us.is_empty() {
        0.0
    } else {
        stats.latencies_us.iter().sum::<u64>() as f64 / stats.latencies_us.len() as f64 / 1000.0
    };
    let rps = stats.count as f64 / options.duration.as_secs_f64();
    println!(
        "requests={} rps={:.0} errors={} status_2xx={} status_403={} status_other={}",
        stats.count, rps, stats.errors, stats.ok, stats.blocked, stats.other
    );
    println!(
        "latency_ms mean={:.3} p50={:.3} p95={:.3} p99={:.3} max={:.3}",
        mean_ms,
        percentile(&stats.latencies_us, 0.50),
        percentile(&stats.latencies_us, 0.95),
        percentile(&stats.latencies_us, 0.99),
        stats
            .latencies_us
            .last()
            .map(|value| *value as f64 / 1000.0)
            .unwrap_or(0.0)
    );
    Ok(())
}
