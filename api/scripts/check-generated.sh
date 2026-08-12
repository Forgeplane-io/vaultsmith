#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)"
GO_OUTPUT="$ROOT/backend/internal/apimodels/openapi.gen.go"
TS_OUTPUT="$ROOT/frontend/src/generated/api.ts"
REFERENCE_OUTPUT="$ROOT/docs/api-reference.md"
TMP_DIR="$(mktemp -d)"

cleanup() {
  if command -v trash >/dev/null 2>&1; then
    trash "$TMP_DIR"
  else
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT

fail() {
  printf 'API generation drift check failed: %s\n' "$1" >&2
  exit 1
}

[[ -f "$GO_OUTPUT" ]] || fail "missing $GO_OUTPUT; run make generate-api"
[[ -f "$TS_OUTPUT" ]] || fail "missing $TS_OUTPUT; run make generate-api"
[[ -f "$REFERENCE_OUTPUT" ]] || fail "missing $REFERENCE_OUTPUT; run make generate-api"

cp "$GO_OUTPUT" "$TMP_DIR/openapi.gen.go.before"
cp "$TS_OUTPUT" "$TMP_DIR/api.ts.before"
cp "$REFERENCE_OUTPUT" "$TMP_DIR/api-reference.md.before"

(
  cd "$ROOT/api"
  go tool oapi-codegen --config oapi-codegen.yaml openapi.yaml
  go run ./cmd/reference -input openapi.yaml -output ../docs/api-reference.md
)
npm run generate --prefix "$ROOT/api/typescript-generator"

DRIFT=0
if ! cmp -s "$TMP_DIR/openapi.gen.go.before" "$GO_OUTPUT"; then
  printf 'generated Go DTOs are stale: %s\n' "$GO_OUTPUT" >&2
  diff -u "$TMP_DIR/openapi.gen.go.before" "$GO_OUTPUT" >&2 || true
  DRIFT=1
fi
if ! cmp -s "$TMP_DIR/api.ts.before" "$TS_OUTPUT"; then
  printf 'generated TypeScript types are stale: %s\n' "$TS_OUTPUT" >&2
  diff -u "$TMP_DIR/api.ts.before" "$TS_OUTPUT" >&2 || true
  DRIFT=1
fi
if ! cmp -s "$TMP_DIR/api-reference.md.before" "$REFERENCE_OUTPUT"; then
  printf 'generated static API reference is stale: %s\n' "$REFERENCE_OUTPUT" >&2
  diff -u "$TMP_DIR/api-reference.md.before" "$REFERENCE_OUTPUT" >&2 || true
  DRIFT=1
fi

if (( DRIFT != 0 )); then
  fail "committed outputs differ from api/openapi.yaml; review and keep the regenerated files"
fi

printf 'API generation drift check: Go, TypeScript, and static reference outputs match api/openapi.yaml.\n'
