#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
cleanup() {
  if command -v trash >/dev/null 2>&1; then
    trash "$TMP_DIR"
  else
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT

"$ROOT/api/scripts/oasdiff.sh" validate \
  "$ROOT/api/baselines/v0.4.0.yaml" \
  --allow-external-refs=false \
  --fail-on INFO
"$ROOT/api/scripts/oasdiff.sh" validate \
  "$ROOT/api/openapi.yaml" \
  --allow-external-refs=false \
  --fail-on INFO

"$ROOT/api/scripts/oasdiff.sh" breaking \
  "$ROOT/api/baselines/v0.4.0.yaml" \
  "$ROOT/api/openapi.yaml" \
  --format json > "$TMP_DIR/breaking.json"

python3 "$ROOT/api/scripts/check_compatibility.py" \
  "$TMP_DIR/breaking.json" \
  "$ROOT/api/compatibility-allowlist.json"
