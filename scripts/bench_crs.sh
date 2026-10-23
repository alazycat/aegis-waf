#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

CRS_DIR="$ROOT/target/crs/coreruleset"
if [ ! -d "$CRS_DIR/.git" ]; then
    mkdir -p "$ROOT/target/crs"
    git clone --depth 1 https://github.com/coreruleset/coreruleset.git "$CRS_DIR"
fi

echo "CRS commit: $(git -C "$CRS_DIR" rev-parse --short HEAD)"

FILES=("$CRS_DIR/crs-setup.conf.example")
while IFS= read -r file; do
    FILES+=("$file")
done < <(find "$CRS_DIR/rules" -maxdepth 1 -name "REQUEST-*.conf" | sort)

cargo run --release -p aegis-engine --example prefilter_report -- "${FILES[@]}"
