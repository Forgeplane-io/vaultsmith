#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
SERVER_PID=""
PORT="${SMOKE_PORT:-8080}"

cleanup() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  if command -v trash >/dev/null 2>&1; then
    trash "$TMP_DIR"
  else
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT

fail() {
  printf 'smoke test failed: %s\n' "$1" >&2
  exit 1
}

if command -v lsof >/dev/null 2>&1 && lsof -nP -iTCP:"$PORT" -sTCP:LISTEN -t >/dev/null 2>&1; then
  fail "smoke port $PORT is already in use; choose another SMOKE_PORT or stop the listener"
fi

go build -o "$TMP_DIR/vaultsmith" "$ROOT/backend/cmd/server"

VAULT_PROFILES_JSON='[{"id":"dev","label":"Development","passwordEnv":"VAULT_PASSWORD_DEV"},{"id":"prod","label":"Production","passwordEnv":"VAULT_PASSWORD_PROD"}]' \
VAULT_PASSWORD_DEV='smoke-password' \
VAULT_PASSWORD_PROD='smoke-destination-password' \
AUTH_MODE='off' \
COOKIE_SECURE='false' \
HTTP_ADDR="127.0.0.1:${PORT}" \
  "$TMP_DIR/vaultsmith" >"$TMP_DIR/server.log" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 50); do
  if curl -fsS http://127.0.0.1:${PORT}/healthz >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done
curl -fsS http://127.0.0.1:${PORT}/healthz >/dev/null || fail 'health endpoint did not become ready'
curl -fsS http://127.0.0.1:${PORT}/readyz >/dev/null || fail 'readiness endpoint did not become ready'

profiles="$(curl -fsS http://127.0.0.1:${PORT}/api/v1/profiles)"
if [[ "$profiles" == *'VAULT_PASSWORD_DEV'* || "$profiles" == *'VAULT_PASSWORD_PROD'* || "$profiles" == *'smoke-password'* || "$profiles" == *'smoke-destination-password'* ]]; then
  fail 'profile response exposed secret configuration'
fi
printf '%s' "$profiles" | python3 -c 'import json, sys; profiles=json.load(sys.stdin)["profiles"]; assert len(profiles) == 2 and all(profile["capabilities"] == {"encrypt": True, "decrypt": True} for profile in profiles), profiles'

session_headers="$TMP_DIR/session.headers"
session_body="$TMP_DIR/session.json"
curl -fsS -D "$session_headers" -o "$session_body" http://127.0.0.1:${PORT}/api/v1/session
if grep -qi '^Set-Cookie:' "$session_headers"; then
  fail 'off-mode session endpoint issued a cookie'
fi
session_bootstrap="$(<"$session_body")"
printf '%s' "$session_bootstrap" | python3 -c 'import json, sys; session=json.load(sys.stdin); assert session["authRequired"] is False and session["authenticated"] is False and session["csrfToken"] == ""'
post_args=(-H 'Content-Type: application/json')

home="$(curl -fsS http://127.0.0.1:${PORT}/)"
[[ "$home" == *'Vaultsmith'* ]] || fail 'embedded SPA root is missing'
route="$(curl -fsS http://127.0.0.1:${PORT}/workbench)"
[[ "$route" == *'Vaultsmith'* ]] || fail 'SPA route fallback is missing'
if curl -fsS http://127.0.0.1:${PORT}/assets/missing.js >/dev/null 2>&1; then
  fail 'missing static asset incorrectly returned success'
fi

encrypted_response="$(curl -fsS "${post_args[@]}" \
  --data '{"profileId":"dev","mode":"encrypt","value":"smoke-value"}' \
  http://127.0.0.1:${PORT}/api/v1/operations)"
vault_text="$(printf '%s' "$encrypted_response" | python3 -c 'import json, sys; value=json.load(sys.stdin)["value"]; assert value.startswith("$ANSIBLE_VAULT;1.2;AES256;dev"); print(value, end="")')"
[[ -n "$vault_text" ]] || fail 'encrypt response was empty'

decrypt_request="$(printf '%s' "$vault_text" | python3 -c 'import json, sys; print(json.dumps({"profileId":"dev","mode":"decrypt","value":sys.stdin.read()}))')"
decrypted_response="$(curl -fsS "${post_args[@]}" \
  --data "$decrypt_request" \
  http://127.0.0.1:${PORT}/api/v1/operations)"
round_trip="$(printf '%s' "$decrypted_response" | python3 -c 'import json, sys; print(json.load(sys.stdin)["value"], end="")')"
[[ "$round_trip" == 'smoke-value' ]] || fail 'encrypt/decrypt round trip did not match'

rotate_request="$(printf '%s' "$vault_text" | python3 -c 'import json, sys; print(json.dumps({"mode":"rotate","sourceProfileId":"dev","destinationProfileId":"prod","value":sys.stdin.read()}))')"
rotated_response="$(curl -fsS "${post_args[@]}" \
  --data "$rotate_request" \
  http://127.0.0.1:${PORT}/api/v1/operations)"
rotated_vault_text="$(printf '%s' "$rotated_response" | python3 -c 'import json, sys; value=json.load(sys.stdin)["value"]; assert value.startswith("$ANSIBLE_VAULT;1.2;AES256;prod"); print(value, end="")')"
[[ -n "$rotated_vault_text" ]] || fail 'rotate response was empty'

rotated_decrypt_request="$(printf '%s' "$rotated_vault_text" | python3 -c 'import json, sys; print(json.dumps({"profileId":"prod","mode":"decrypt","value":sys.stdin.read()}))')"
rotated_decrypted_response="$(curl -fsS "${post_args[@]}" \
  --data "$rotated_decrypt_request" \
  http://127.0.0.1:${PORT}/api/v1/operations)"
rotated_round_trip="$(printf '%s' "$rotated_decrypted_response" | python3 -c 'import json, sys; print(json.load(sys.stdin)["value"], end="")')"
[[ "$rotated_round_trip" == 'smoke-value' ]] || fail 'rotate/decrypt round trip did not match'

printf 'smoke: ok (port=%s, profiles=2, round-trip=verified, rotate=verified)\n' "$PORT"
