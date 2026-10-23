#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

if command -v cygpath >/dev/null 2>&1; then
    ROOT_FOR_CONFIG=$(cygpath -m "$ROOT")
    EXE_SUFFIX=".exe"
else
    ROOT_FOR_CONFIG="$ROOT"
    EXE_SUFFIX=""
fi

BENCH_DIR="$ROOT/target/bench"
UP_PORT=${UP_PORT:-13020}
PROXY_PORT=${PROXY_PORT:-18090}
ADMIN_PORT=${ADMIN_PORT:-19010}
CONCURRENCIES=${CONCURRENCIES:-"1 8 32 64 128"}
LARGE_CONCURRENCIES=${LARGE_CONCURRENCIES:-"32 64"}
DURATION=${DURATION:-5}
WARMUP=${WARMUP:-1}

mkdir -p "$BENCH_DIR"
: > "$BENCH_DIR/empty.conf"

make_rules() {
    local count=$1
    local output=$2
    local block_last=$3
    : > "$output"
    local index action
    for index in $(seq 0 $((count - 1))); do
        action="pass"
        if [ "$block_last" = "true" ] && [ "$index" -eq $((count - 1)) ]; then
            action="deny,status:403"
        fi
        printf 'SecRule ARGS "@contains needle-%04d" "id:%d,phase:2,%s"\n' \
            "$index" "$((20000 + index))" "$action" >> "$output"
    done
}

make_rules 200 "$BENCH_DIR/rules200.conf" false
make_rules 500 "$BENCH_DIR/rules500.conf" false
make_rules 500 "$BENCH_DIR/rules500_block.conf" true

write_config() {
    local output=$1
    shift
    {
        echo "listen: \"127.0.0.1:$PROXY_PORT\""
        echo "upstream:"
        echo "  url: \"http://127.0.0.1:$UP_PORT\""
        echo "  host_header: preserve"
        echo "  connect_timeout_ms: 3000"
        echo "  total_timeout_ms: 30000"
        echo "admin:"
        echo "  listen: \"127.0.0.1:$ADMIN_PORT\""
        echo "  token: null"
        echo "rules:"
        echo "  files:"
        local file
        for file in "$@"; do
            echo "    - \"$file\""
        done
        echo "  lenient: false"
        echo "limits:"
        echo "  max_header_bytes: 65536"
        echo "  max_uri_bytes: 8192"
        echo "  max_body_bytes: 1048576"
        echo "  header_read_timeout_ms: 10000"
        echo "  body_read_timeout_ms: 15000"
        echo "on_error: block"
        echo "audit:"
        echo "  sink: none"
        echo "  mode: blocked_only"
        echo "  queue_capacity: 8192"
        echo "  include_query: false"
        echo "  matched_rules_limit: 16"
    } > "$output"
}

write_config "$BENCH_DIR/example.yaml" \
    "$ROOT_FOR_CONFIG/rules/examples/whitelist.conf" \
    "$ROOT_FOR_CONFIG/rules/examples/base.conf"
write_config "$BENCH_DIR/empty.yaml" "$ROOT_FOR_CONFIG/target/bench/empty.conf"
write_config "$BENCH_DIR/rules200.yaml" "$ROOT_FOR_CONFIG/target/bench/rules200.conf"
write_config "$BENCH_DIR/rules500.yaml" "$ROOT_FOR_CONFIG/target/bench/rules500.conf"
write_config "$BENCH_DIR/rules500_block.yaml" "$ROOT_FOR_CONFIG/target/bench/rules500_block.conf"

cargo build --release -p aegis-proxy --bin aegis-proxy --examples

UPSTREAM_PID=""
PROXY_PID=""

cleanup() {
    if [ -n "$PROXY_PID" ]; then
        kill "$PROXY_PID" 2>/dev/null || true
    fi
    if [ -n "$UPSTREAM_PID" ]; then
        kill "$UPSTREAM_PID" 2>/dev/null || true
    fi
    wait 2>/dev/null || true
}
trap cleanup EXIT

"$ROOT/target/release/examples/mock_upstream$EXE_SUFFIX" "127.0.0.1:$UP_PORT" \
    > "$BENCH_DIR/upstream.log" 2>&1 &
UPSTREAM_PID=$!

start_proxy() {
    local config=$1
    local log=$2
    "$ROOT/target/release/aegis-proxy$EXE_SUFFIX" --config "$config" > "$log" 2>&1 &
    PROXY_PID=$!
    for _ in $(seq 1 50); do
        if curl -s -o /dev/null "http://127.0.0.1:$PROXY_PORT/"; then
            return 0
        fi
        sleep 0.1
    done
    echo "proxy failed to start; see $log" >&2
    return 1
}

stop_proxy() {
    if [ -n "$PROXY_PID" ]; then
        kill "$PROXY_PID" 2>/dev/null || true
        wait "$PROXY_PID" 2>/dev/null || true
        PROXY_PID=""
    fi
}

run_load() {
    local mode=$1
    local path=$2
    local concurrency=$3
    "$ROOT/target/release/examples/loadtest$EXE_SUFFIX" \
        --addr "127.0.0.1:$PROXY_PORT" \
        --mode "$mode" \
        --path "$path" \
        --concurrency "$concurrency" \
        --duration "$DURATION" \
        --warmup "$WARMUP" | tee -a "$LOG"
}

LOG="$BENCH_DIR/e2e.txt"
: > "$LOG"

echo "### example rules (8 rules)" | tee -a "$LOG"
start_proxy "$BENCH_DIR/example.yaml" "$BENCH_DIR/proxy_example.log"
for mode in block safe; do
    for concurrency in $CONCURRENCIES; do
        if [ "$mode" = "block" ]; then
            path="/search?q=%3Cscript%3E"
        else
            path="/search?q=hello"
        fi
        run_load "$mode" "$path" "$concurrency"
    done
done
stop_proxy

echo "### empty rules (baseline)" | tee -a "$LOG"
start_proxy "$BENCH_DIR/empty.yaml" "$BENCH_DIR/proxy_empty.log"
for concurrency in $CONCURRENCIES; do
    run_load safe "/search?q=hello" "$concurrency"
done
stop_proxy

for count in 200 500; do
    echo "### $count rules" | tee -a "$LOG"
    start_proxy "$BENCH_DIR/rules$count.yaml" "$BENCH_DIR/proxy_rules$count.log"
    needle=$(printf 'needle-%04d' $((count - 1)))
    for concurrency in $LARGE_CONCURRENCIES; do
        echo "--- $count rules, no hit ---" | tee -a "$LOG"
        run_load safe "/search?q=hello" "$concurrency"
        echo "--- $count rules, one hit ---" | tee -a "$LOG"
        run_load safe "/search?q=$needle" "$concurrency"
    done
    stop_proxy
done

echo "### 500 rules, matching deny" | tee -a "$LOG"
start_proxy "$BENCH_DIR/rules500_block.yaml" "$BENCH_DIR/proxy_rules500_block.log"
for concurrency in $LARGE_CONCURRENCIES; do
    run_load block "/search?q=needle-0499" "$concurrency"
done
stop_proxy

echo "results: $LOG"
