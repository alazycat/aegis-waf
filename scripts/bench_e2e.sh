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
DURATION=${DURATION:-5}
WARMUP=${WARMUP:-1}

mkdir -p "$BENCH_DIR"
: > "$BENCH_DIR/empty.conf"

cat > "$BENCH_DIR/example.yaml" <<EOF
listen: "127.0.0.1:$PROXY_PORT"
upstream:
  url: "http://127.0.0.1:$UP_PORT"
  host_header: preserve
  connect_timeout_ms: 3000
  total_timeout_ms: 30000
admin:
  listen: "127.0.0.1:$ADMIN_PORT"
  token: null
rules:
  files:
    - "$ROOT_FOR_CONFIG/rules/examples/whitelist.conf"
    - "$ROOT_FOR_CONFIG/rules/examples/base.conf"
  lenient: false
limits:
  max_header_bytes: 65536
  max_uri_bytes: 8192
  max_body_bytes: 1048576
  header_read_timeout_ms: 10000
  body_read_timeout_ms: 15000
on_error: block
audit:
  sink: none
  mode: blocked_only
  queue_capacity: 8192
  include_query: false
  matched_rules_limit: 16
EOF

cat > "$BENCH_DIR/empty.yaml" <<EOF
listen: "127.0.0.1:$PROXY_PORT"
upstream:
  url: "http://127.0.0.1:$UP_PORT"
  host_header: preserve
  connect_timeout_ms: 3000
  total_timeout_ms: 30000
admin:
  listen: "127.0.0.1:$ADMIN_PORT"
  token: null
rules:
  files:
    - "$ROOT_FOR_CONFIG/target/bench/empty.conf"
  lenient: false
limits:
  max_header_bytes: 65536
  max_uri_bytes: 8192
  max_body_bytes: 1048576
  header_read_timeout_ms: 10000
  body_read_timeout_ms: 15000
on_error: block
audit:
  sink: none
  mode: blocked_only
  queue_capacity: 8192
  include_query: false
  matched_rules_limit: 16
EOF

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

LOG="$BENCH_DIR/e2e.txt"
: > "$LOG"

echo "### example rules (8 rules)" | tee -a "$LOG"
start_proxy "$BENCH_DIR/example.yaml" "$BENCH_DIR/proxy_example.log"
for mode in block safe; do
    for concurrency in $CONCURRENCIES; do
        "$ROOT/target/release/examples/loadtest$EXE_SUFFIX" \
            --addr "127.0.0.1:$PROXY_PORT" \
            --mode "$mode" \
            --concurrency "$concurrency" \
            --duration "$DURATION" \
            --warmup "$WARMUP" | tee -a "$LOG"
    done
done
stop_proxy

echo "### empty rules (baseline)" | tee -a "$LOG"
start_proxy "$BENCH_DIR/empty.yaml" "$BENCH_DIR/proxy_empty.log"
for concurrency in $CONCURRENCIES; do
    "$ROOT/target/release/examples/loadtest$EXE_SUFFIX" \
        --addr "127.0.0.1:$PROXY_PORT" \
        --mode safe \
        --concurrency "$concurrency" \
        --duration "$DURATION" \
        --warmup "$WARMUP" | tee -a "$LOG"
done
stop_proxy

echo "results: $LOG"
