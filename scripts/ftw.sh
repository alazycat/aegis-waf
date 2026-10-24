#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
ROOT_WIN=$(cygpath -m "$ROOT" 2>/dev/null || printf '%s' "$ROOT")
cd "$ROOT"

MODE="${1:---gate}"
case "$MODE" in
    --full|--gate) ;;
    *)
        echo "usage: $0 [--full|--gate]" >&2
        exit 2
        ;;
esac

CRS_DIR="$ROOT/target/crs/coreruleset"
if [ ! -d "$CRS_DIR/.git" ]; then
    mkdir -p "$ROOT/target/crs"
    git clone --depth 1 https://github.com/coreruleset/coreruleset.git "$CRS_DIR"
fi
echo "CRS commit: $(git -C "$CRS_DIR" rev-parse --short HEAD)"

if [ -n "${FTW_BIN:-}" ]; then
    FTW="$FTW_BIN"
else
    GOBIN="$(go env GOPATH)/bin"
    if [ -x "$GOBIN/ftw" ]; then
        FTW="$GOBIN/ftw"
    elif [ -x "$GOBIN/ftw.exe" ]; then
        FTW="$GOBIN/ftw.exe"
    elif [ -x "$GOBIN/go-ftw" ]; then
        FTW="$GOBIN/go-ftw"
    elif [ -x "$GOBIN/go-ftw.exe" ]; then
        FTW="$GOBIN/go-ftw.exe"
    else
        go install github.com/coreruleset/go-ftw/v2@v2.6.1
        if [ -x "$GOBIN/go-ftw.exe" ]; then
            FTW="$GOBIN/go-ftw.exe"
        else
            FTW="$GOBIN/go-ftw"
        fi
    fi
fi

PROXY_PORT="${FTW_PROXY_PORT:-18080}"
ADMIN_PORT="${FTW_ADMIN_PORT:-18082}"
BACKEND_PORT="${FTW_BACKEND_PORT:-18081}"
WORK="$ROOT/target/ftw"
rm -rf "$WORK"
mkdir -p "$WORK"

cat > "$WORK/crs-test-setup.conf" <<'EOF'
SecAction "id:900005,\
  phase:1,\
  nolog,\
  pass,\
  ctl:ruleEngine=DetectionOnly,\
  ctl:ruleRemoveById=910000,\
  setvar:tx.blocking_paranoia_level=4,\
  setvar:tx.crs_validate_utf8_encoding=1,\
  setvar:tx.arg_name_length=100,\
  setvar:tx.arg_length=400,\
  setvar:tx.total_arg_length=64000,\
  setvar:tx.max_num_args=255,\
  setvar:tx.max_file_size=64100,\
  setvar:tx.combined_file_sizes=65535"

SecRule REQUEST_HEADERS:X-CRS-Test "@rx ^.*$" \
    "id:999999,phase:1,pass,log,msg:'X-CRS-Test %{MATCHED_VAR}',ctl:ruleRemoveById=1-999999"
EOF

cat > "$WORK/aegis-ftw.yaml" <<EOF
listen: "127.0.0.1:${PROXY_PORT}"

upstream:
  url: "http://127.0.0.1:${BACKEND_PORT}"
  host_header: preserve
  connect_timeout_ms: 3000
  total_timeout_ms: 30000

admin:
  listen: "127.0.0.1:${ADMIN_PORT}"
  token: null

rules:
  files:
    - "${ROOT_WIN}/target/crs/coreruleset/crs-setup.conf.example"
    - "${ROOT_WIN}/target/ftw/crs-test-setup.conf"
    - "${ROOT_WIN}/target/crs/coreruleset/rules/REQUEST-*.conf"
    - "${ROOT_WIN}/target/crs/coreruleset/rules/RESPONSE-*.conf"
  lenient: true

limits:
  max_header_bytes: 1048576
  max_uri_bytes: 65536
  max_body_bytes: 1048576
  max_response_body_bytes: 1048576
  response_body_limit_action: reject
  max_args: 10000
  max_multipart_parts: 1000
  max_multipart_part_headers: 64
  max_xml_depth: 64
  max_xml_values: 10000
  header_read_timeout_ms: 10000
  body_read_timeout_ms: 15000

on_error: block

audit:
  sink: file
  path: "${ROOT_WIN}/target/ftw/audit.jsonl"
  mode: all
  queue_capacity: 8192
  include_query: false
  matched_rules_limit: 256
EOF

cat > "$WORK/.ftw.yaml" <<EOF
logfile: "${ROOT_WIN}/target/ftw/audit.jsonl"
logmarkerheadername: X-CRS-Test
testoverride:
  input:
    dest_addr: "127.0.0.1"
    port: ${PROXY_PORT}
EOF

# go-ftw aborts the whole run when a retry_once test fails instead of recording
# the failure. Our phase 5 runs before the audit event is written, so the race
# the retry works around does not exist; strip the marker from a private copy.
TESTS_DIR="$WORK/tests"
cp -R "$CRS_DIR/tests/regression/tests" "$TESTS_DIR"
find "$TESTS_DIR" -name '*.yaml' -exec sed -i '/^[[:space:]]*retry_once: true/d' {} +

cargo build -p aegis-proxy --bin aegis-proxy
cargo build -p aegis-proxy --example ftw_backend

exe_path() {
    if [ -x "$1.exe" ]; then
        printf '%s.exe' "$1"
    else
        printf '%s' "$1"
    fi
}
BACKEND_BIN=$(exe_path "$ROOT/target/debug/examples/ftw_backend")
PROXY_BIN=$(exe_path "$ROOT/target/debug/aegis-proxy")

BACKEND_PID=""
PROXY_PID=""
cleanup() {
    if [ -n "$PROXY_PID" ]; then kill "$PROXY_PID" 2>/dev/null || true; fi
    if [ -n "$BACKEND_PID" ]; then kill "$BACKEND_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT

FTW_BACKEND_PORT="$BACKEND_PORT" "$BACKEND_BIN" >"$WORK/backend.log" 2>&1 &
BACKEND_PID=$!
"$PROXY_BIN" --config "$WORK/aegis-ftw.yaml" >"$WORK/proxy.log" 2>&1 &
PROXY_PID=$!

ready=0
for _ in $(seq 1 100); do
    if curl --max-time 1 -fsS "http://127.0.0.1:${ADMIN_PORT}/healthz" >/dev/null 2>&1 \
        && curl --max-time 1 -fsS "http://127.0.0.1:${BACKEND_PORT}/status/200" >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 0.1
done
if [ "$ready" -ne 1 ]; then
    echo "ftw services failed to become ready" >&2
    tail -n 40 "$WORK/proxy.log" >&2 || true
    tail -n 40 "$WORK/backend.log" >&2 || true
    exit 1
fi

# go-ftw refuses to send raw CR/LF headers, and aborts the whole run when a test
# builds one. 921140-1 uses a literal CR in a header; exclude it from the harness.
HARNESS_EXCLUDE='^921140-1$'
if [ -n "${FTW_EXCLUDE:-}" ]; then
    HARNESS_EXCLUDE="${HARNESS_EXCLUDE}|${FTW_EXCLUDE}"
fi

FILTER=()
if [ -n "${FTW_INCLUDE:-}" ]; then
    # go-ftw rejects using --include and --exclude together.
    FILTER+=(-i "$FTW_INCLUDE")
else
    FILTER+=(-e "$HARNESS_EXCLUDE")
fi

OUTPUT=(-o json -f "$ROOT_WIN/target/ftw/report.json")
DEBUG=()
if [ "${FTW_NORMAL:-}" = "1" ]; then
    OUTPUT=(-o normal)
    DEBUG=(--debug)
fi

set +e
"$FTW" "${DEBUG[@]}" --config "$ROOT_WIN/target/ftw/.ftw.yaml" run \
    "${FILTER[@]}" \
    -d "$ROOT_WIN/target/ftw/tests" \
    "${OUTPUT[@]}"
FTW_STATUS=$?
set -e

if [ ! -s "$WORK/report.json" ]; then
    echo "go-ftw produced no report (exit $FTW_STATUS)" >&2
    exit 1
fi

if [ "$MODE" = "--gate" ]; then
    cargo run -q -p aegis-proxy --example ftw_gate -- \
        "$ROOT_WIN/target/ftw/report.json" \
        "$ROOT_WIN/scripts/ftw-known-gaps.txt"
else
    echo "report: $WORK/report.json"
fi
