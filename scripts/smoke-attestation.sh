#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "$0")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/vaultsmith-attestation-smoke.XXXXXX")"
PORT="${SMOKE_ATTESTATION_PORT:-8081}"
SERVER_PID=""

cleanup() {
  set +e
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
  printf 'attestation smoke test failed: %s\n' "$1" >&2
  exit 1
}

for command in curl jq go; do
  command -v "$command" >/dev/null 2>&1 || fail "missing dependency: $command"
done
if command -v lsof >/dev/null 2>&1 && lsof -nP -iTCP:"$PORT" -sTCP:LISTEN -t >/dev/null 2>&1; then
  fail "smoke port $PORT is already in use; choose another SMOKE_ATTESTATION_PORT or stop the listener"
fi

# Generate deterministic test-only key material in a disposable directory. The
# seed bytes are synthetic and never represent an operator or deployment key.
cat >"$TMP_DIR/keygen.go" <<'GO'
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
)

type key struct {
	ID         string `json:"id"`
	State      string `json:"state"`
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey,omitempty"`
}

type ring struct {
	Version int   `json:"version"`
	Active  string `json:"active"`
	Keys    []key `json:"keys"`
}

func main() {
	if len(os.Args) != 3 {
		panic("usage: keygen seed-byte key-id")
	}
	seedByte, err := strconv.ParseUint(os.Args[1], 10, 8)
	if err != nil {
		panic(err)
	}
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(seedByte)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	encoding := base64.RawURLEncoding
	value := ring{
		Version: 1,
		Active:  os.Args[2],
		Keys: []key{{
			ID:         os.Args[2],
			State:      "active",
			PublicKey:  encoding.EncodeToString(privateKey[ed25519.SeedSize:]),
			PrivateKey: encoding.EncodeToString(seed),
		}},
	}
	if err := json.NewEncoder(os.Stdout).Encode(value); err != nil {
		panic(fmt.Sprintf("encode keyring: %v", err))
	}
}
GO

go build -o "$TMP_DIR/keygen" "$TMP_DIR/keygen.go"
"$TMP_DIR/keygen" 1 synthetic-key-a >"$TMP_DIR/key-a.json"
"$TMP_DIR/keygen" 2 synthetic-key-b >"$TMP_DIR/key-b.json"
jq -n \
  --slurpfile key "$TMP_DIR/key-a.json" \
  '{version:1, active:"synthetic-key-a", keys:$key[0].keys}' \
  >"$TMP_DIR/keyring-a.json"
jq -n \
  --slurpfile old "$TMP_DIR/key-a.json" \
  --slurpfile new "$TMP_DIR/key-b.json" \
  '{version:1, active:"synthetic-key-b", keys:[($old[0].keys[0] | del(.privateKey) | .state="retired"), $new[0].keys[0]]}' \
  >"$TMP_DIR/keyring-b-retired.json"
jq -n \
  --slurpfile old "$TMP_DIR/key-a.json" \
  --slurpfile new "$TMP_DIR/key-b.json" \
  '{version:1, active:"synthetic-key-b", keys:[($old[0].keys[0] | del(.privateKey) | .state="revoked"), $new[0].keys[0]]}' \
  >"$TMP_DIR/keyring-b-revoked.json"

go build -o "$TMP_DIR/vaultsmith" "$ROOT_DIR/backend/cmd/server"

profiles='[{"id":"dev","label":"Development","passwordEnv":"VAULT_PASSWORD_DEV"},{"id":"prod","label":"Production","passwordEnv":"VAULT_PASSWORD_PROD"}]'
prod_only_profiles='[{"id":"prod","label":"Production","passwordEnv":"VAULT_PASSWORD_PROD"}]'

stop_server() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  SERVER_PID=""
}

start_server() {
  local configured_profiles="$1"
  local proofs_enabled="$2"
  stop_server
  if [[ "$proofs_enabled" == "true" ]]; then
    AUTH_MODE=off \
    COOKIE_SECURE=false \
    HTTP_ADDR="127.0.0.1:${PORT}" \
    MCP_ENABLED=true \
    PUBLIC_BASE_URL=https://vaultsmith.synthetic.test \
    PROOFS_ENABLED=true \
    PROOFS_KEYRING_FILE="$TMP_DIR/keyring.json" \
    VAULT_PROFILES_JSON="$configured_profiles" \
    VAULT_PASSWORD_DEV=synthetic-source-password \
    VAULT_PASSWORD_PROD=synthetic-destination-password \
      "$TMP_DIR/vaultsmith" >"$TMP_DIR/server.log" 2>&1 &
  else
    AUTH_MODE=off \
    COOKIE_SECURE=false \
    HTTP_ADDR="127.0.0.1:${PORT}" \
    MCP_ENABLED=true \
    VAULT_PROFILES_JSON="$configured_profiles" \
    VAULT_PASSWORD_PROD=synthetic-destination-password \
      "$TMP_DIR/vaultsmith" >"$TMP_DIR/server.log" 2>&1 &
  fi
  SERVER_PID=$!
  for _ in $(seq 1 100); do
    if curl -fsS "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1; then
      return
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      fail "server exited before healthz became available"
    fi
    sleep 0.1
  done
  fail "healthz did not become available"
}

request_json() {
  local body_file="$1"
  local path="$2"
  local output_file="$3"
  curl -fsS -H 'Content-Type: application/json' \
    --data-binary "@${body_file}" \
    "http://127.0.0.1:${PORT}${path}" >"$output_file"
}

request_status() {
  local body_file="$1"
  local path="$2"
  local output_file="$3"
  curl -sS -H 'Content-Type: application/json' \
    --data-binary "@${body_file}" \
    -o "$output_file" -w '%{http_code}' \
    "http://127.0.0.1:${PORT}${path}"
}

assert_json() {
  local file="$1"
  local expression="$2"
  local description="$3"
  jq -e "$expression" "$file" >/dev/null || fail "$description"
}

encrypt_profile() {
  local profile="$1"
  local plaintext="$2"
  local output="$3"
  jq -n --arg plaintext "$plaintext" '{plaintext:$plaintext}' >"$TMP_DIR/encrypt-request.json"
  request_json "$TMP_DIR/encrypt-request.json" "/api/v1/profiles/${profile}/encrypt" "$TMP_DIR/encrypt-response.json"
  jq -e -j -r '.vaultText // empty' "$TMP_DIR/encrypt-response.json" >"$output" || fail "${profile} encryption returned no Vault envelope"
}

write_rotation_request() {
  local input_file="$1"
  jq -n \
    --rawfile vault "$input_file" \
    --slurpfile binding "$TMP_DIR/binding.json" \
    '{sourceProfileId:"dev", destinationProfileId:"prod", vaultText:$vault, attestation:{binding:$binding[0]}}' \
    >"$TMP_DIR/rotate-request.json"
}

write_verify_request() {
  local proof_file="$1"
  local input_file="$2"
  local output_file="$3"
  local binding_file="$4"
  local request_file="$5"
  jq -n \
    --slurpfile attestation "$proof_file" \
    --rawfile inputVaultText "$input_file" \
    --rawfile outputVaultText "$output_file" \
    --slurpfile expectedBinding "$binding_file" \
    '{attestation:$attestation[0], inputVaultText:$inputVaultText, outputVaultText:$outputVaultText, expectedBinding:$expectedBinding[0]}' \
    >"$request_file"
}

verify_expected() {
  local proof_file="$1"
  local input_file="$2"
  local output_file="$3"
  local binding_file="$4"
  local expression="$5"
  local description="$6"
  write_verify_request "$proof_file" "$input_file" "$output_file" "$binding_file" "$TMP_DIR/verify-request.json"
  request_json "$TMP_DIR/verify-request.json" "/api/v1/attestations/verify" "$TMP_DIR/verify-response.json"
  assert_json "$TMP_DIR/verify-response.json" "$expression" "$description"
}

wait_for_metric() {
  local metric="$1"
  local description="$2"
  for _ in $(seq 1 90); do
    curl -fsS "http://127.0.0.1:${PORT}/metrics" >"$TMP_DIR/metrics.txt" || true
    if grep -Fq "$metric" "$TMP_DIR/metrics.txt"; then
      return
    fi
    sleep 1
  done
  fail "$description"
}

cp "$TMP_DIR/keyring-a.json" "$TMP_DIR/keyring.json"
start_server "$profiles" true

binding_file="$TMP_DIR/binding.json"
jq -n '{repository:"synthetic/project", revision:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", path:"synthetic/path", selector:"synthetic"}' >"$binding_file"
input_file="$TMP_DIR/input.vault"
output_a_file="$TMP_DIR/output-a.vault"
changed_input_file="$TMP_DIR/changed-input.vault"
changed_output_file="$TMP_DIR/changed-output.vault"
encrypt_profile dev synthetic-attestation-input "$input_file"
encrypt_profile dev synthetic-attestation-input-changed "$changed_input_file"
encrypt_profile prod synthetic-attestation-output-changed "$changed_output_file"

write_rotation_request "$input_file"
request_json "$TMP_DIR/rotate-request.json" "/api/v1/rotations" "$TMP_DIR/rotate-a-response.json"
assert_json "$TMP_DIR/rotate-a-response.json" '.attestation != null and (.vaultText | length) > 0' 'initial attested rotation returned no proof'
jq -j -r '.vaultText' "$TMP_DIR/rotate-a-response.json" >"$output_a_file"
jq '.attestation' "$TMP_DIR/rotate-a-response.json" >"$TMP_DIR/proof-a.json"
verify_expected "$TMP_DIR/proof-a.json" "$input_file" "$output_a_file" "$binding_file" '.valid == true' 'initial proof did not verify'
verify_expected "$TMP_DIR/proof-a.json" "$changed_input_file" "$output_a_file" "$binding_file" '.valid == false and .reason == "input_digest_mismatch"' 'input mismatch was not classified'
verify_expected "$TMP_DIR/proof-a.json" "$input_file" "$changed_output_file" "$binding_file" '.valid == false and .reason == "output_digest_mismatch"' 'output mismatch was not classified'
jq -n '{repository:"synthetic/project", revision:"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", path:"synthetic/path", selector:"synthetic"}' >"$TMP_DIR/wrong-binding.json"
verify_expected "$TMP_DIR/proof-a.json" "$input_file" "$output_a_file" "$TMP_DIR/wrong-binding.json" '.valid == false and .reason == "binding_mismatch"' 'binding mismatch was not classified'

stop_server
start_server "$profiles" true
verify_expected "$TMP_DIR/proof-a.json" "$input_file" "$output_a_file" "$binding_file" '.valid == true' 'proof did not survive restart'

cp "$TMP_DIR/keyring-b-retired.json" "$TMP_DIR/keyring.next"
mv "$TMP_DIR/keyring.next" "$TMP_DIR/keyring.json"
wait_for_metric 'vaultsmith_attestation_keyring_reload_total{outcome="success"} 1' 'valid keyring replacement was not reloaded'
write_rotation_request "$input_file"
request_json "$TMP_DIR/rotate-request.json" "/api/v1/rotations" "$TMP_DIR/rotate-b-response.json"
assert_json "$TMP_DIR/rotate-b-response.json" '.attestation != null' 'replacement rotation returned no proof'
jq -j -r '.vaultText' "$TMP_DIR/rotate-b-response.json" >"$TMP_DIR/output-b.vault"
jq '.attestation' "$TMP_DIR/rotate-b-response.json" >"$TMP_DIR/proof-b.json"
verify_expected "$TMP_DIR/proof-b.json" "$input_file" "$TMP_DIR/output-b.vault" "$binding_file" '.valid == true' 'replacement proof did not verify'
verify_expected "$TMP_DIR/proof-a.json" "$input_file" "$output_a_file" "$binding_file" '.valid == true' 'retired proof did not verify'
assert_json "$TMP_DIR/keyring-b-retired.json" '(.keys[] | select(.id == "synthetic-key-a") | has("privateKey")) | not' 'retired key retained private material'

cp "$TMP_DIR/keyring-b-revoked.json" "$TMP_DIR/keyring.next"
mv "$TMP_DIR/keyring.next" "$TMP_DIR/keyring.json"
wait_for_metric 'vaultsmith_attestation_keyring_reload_total{outcome="success"} 2' 'revoked keyring replacement was not reloaded'
verify_expected "$TMP_DIR/proof-a.json" "$input_file" "$output_a_file" "$binding_file" '.valid == false and .reason == "key_revoked"' 'revoked proof was not rejected'
verify_expected "$TMP_DIR/proof-b.json" "$input_file" "$TMP_DIR/output-b.vault" "$binding_file" '.valid == true' 'active replacement proof was rejected'

mcp_request="$TMP_DIR/mcp-request.json"
jq -n \
  --slurpfile attestation "$TMP_DIR/proof-b.json" \
  --rawfile inputVaultText "$input_file" \
  --rawfile outputVaultText "$TMP_DIR/output-b.vault" \
  --slurpfile expectedBinding "$binding_file" \
  '{jsonrpc:"2.0", id:1, method:"tools/call", params:{name:"verify_rotation_attestation", arguments:{attestation:$attestation[0], inputVaultText:$inputVaultText, outputVaultText:$outputVaultText, expectedBinding:$expectedBinding[0]}, _meta:{"io.modelcontextprotocol/protocolVersion":"2026-07-28", "io.modelcontextprotocol/clientCapabilities":{}}}}' \
  >"$mcp_request"
curl -fsS \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2026-07-28' \
  -H 'Mcp-Method: tools/call' \
  -H 'Mcp-Name: verify_rotation_attestation' \
  --data-binary "@${mcp_request}" \
  "http://127.0.0.1:${PORT}/mcp" >"$TMP_DIR/mcp-response.json"
assert_json "$TMP_DIR/mcp-response.json" '.result.isError == false and .result.structuredContent.valid == true' 'MCP verification failed'

stop_server
start_server "$prod_only_profiles" true
verify_expected "$TMP_DIR/proof-b.json" "$input_file" "$TMP_DIR/output-b.vault" "$binding_file" '.valid == true' 'historical proof depended on removed source profile'

stop_server
start_server "$prod_only_profiles" false
jq -n '{attestation:{}, inputVaultText:"", outputVaultText:""}' >"$TMP_DIR/off-request.json"
status="$(request_status "$TMP_DIR/off-request.json" "/api/v1/attestations/verify" "$TMP_DIR/off-response.json")"
[[ "$status" == "503" ]] || fail "disabled verification returned HTTP $status"
assert_json "$TMP_DIR/off-response.json" '.error.code == "feature_unavailable"' 'disabled verification did not return feature_unavailable'
curl -fsS "http://127.0.0.1:${PORT}/api/v1/session" >"$TMP_DIR/off-session.json"
assert_json "$TMP_DIR/off-session.json" '.attestationEnabled == false' 'off mode advertised attestation capability'

printf 'attestation smoke: ok (rotation, semantic failures, restart, reload, revocation, REST, MCP, off-mode)\n'
