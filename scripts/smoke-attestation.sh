#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "$0")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/vaultsmith-attestation-smoke.XXXXXX")"
PORT="${SMOKE_ATTESTATION_PORT:-8081}"
SERVER_PID=""
METRICS_DIR="$ROOT_DIR/.tmp/smoke-attestation"
metrics_failed=false
mkdir -p "$METRICS_DIR"

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

for command in curl jq go python3; do
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
  # One schedulable CPU gives both pools one slot for the admission smoke;
  # this is a test fixture, not a change to the compiled production ceilings.
  if [[ "$proofs_enabled" == "true" ]]; then
    GOMAXPROCS=1 \
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
    GOMAXPROCS=1 \
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

scrape_metrics() {
  curl -fsS "http://127.0.0.1:${PORT}/metrics" >"$METRICS_DIR/$1.txt"
  if grep -Eq 'profileId|synthetic|repository|revision|selector|caller|password|ciphertext|generate_token' "$METRICS_DIR/$1.txt"; then
    fail 'metrics exposed sensitive or caller-controlled labels'
  fi
}

check_metric() {
  if ! grep -Fxq "$2" "$METRICS_DIR/$1.txt"; then
    printf 'missing metric in %s: %s\n' "$1" "$2" >&2
    metrics_failed=true
  fi
}

check_mcp_admission() {
  local expected="$1"
  python3 - "$PORT" "$mcp_request" "$expected" <<'PY' | tee "$METRICS_DIR/admission-$expected.txt"
import contextlib
import http.client
import json
import socket
import sys

port, request_file, expected = int(sys.argv[1]), sys.argv[2], sys.argv[3]
with open(request_file, "rb") as fixture:
    body = fixture.read()
# Reuse the smoke's ten-second startup budget for socket progress. A timeout
# means the expected protocol header never arrived; it must fail, not truncate.
timeout = 10
mcp_headers = {
    "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
    "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "verify_rotation_attestation",
}
headers = (
    "POST /mcp HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
    + "".join(f"{name}: {value}\r\n" for name, value in mcp_headers.items())
    + f"Expect: 100-continue\r\nContent-Length: {len(body)}\r\n\r\n"
).encode("ascii")

def read_headers(stream):
    status = int(stream.readline().split()[1])
    return status, http.client.parse_headers(stream)

def assert_result(status, result):
    assert status == 200, f"available verification HTTP {status}, wanted 200"
    if expected == "ready":
        assert result["result"]["isError"] is False and result["result"]["structuredContent"]["valid"] is True, "ready verification failed"
    else:
        assert result["result"]["isError"] is True and result["result"]["structuredContent"]["error"]["code"] == expected, "unavailable verification classification changed"

try:
    with contextlib.ExitStack() as cleanup:
        # The 100 response proves the handler reached its first body read;
        # with the single fixture slot, this deterministically saturates it.
        held = cleanup.enter_context(socket.create_connection(("127.0.0.1", port), timeout))
        held_stream = cleanup.enter_context(held.makefile("rb"))
        held.sendall(headers)
        status, _ = read_headers(held_stream)
        assert status == 100, f"available verification HTTP {status}, wanted 100 before body"

        probe = cleanup.enter_context(socket.create_connection(("127.0.0.1", port), timeout))
        probe_stream = cleanup.enter_context(probe.makefile("rb"))
        probe.sendall(headers)
        status, response_headers = read_headers(probe_stream)
        print(json.dumps({"case": expected + " saturated", "status": status, "submitted_body_bytes": 0}), flush=True)
        assert status == 503, f"saturated verification HTTP {status}, wanted 503 without 100/body read"
        result = json.loads(probe_stream.read(int(response_headers["Content-Length"])))
        assert result["error"]["code"] == "attestation_busy" and response_headers["Retry-After"] == "1", "busy response contract changed"

        with contextlib.closing(http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)) as connection:
            connection.request("POST", "/api/v1/profiles/prod/encrypt", b'{"plaintext":"synthetic-admission-input"}', {"Content-Type": "application/json"})
            response = connection.getresponse()
            response.read()
            assert response.status == 200, f"verification consumed operation capacity (HTTP {response.status})"

        held.sendall(body)
        status, response_headers = read_headers(held_stream)
        assert_result(status, json.loads(held_stream.read(int(response_headers["Content-Length"]))))

        with contextlib.closing(http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)) as connection:
            connection.request("POST", "/mcp", body, mcp_headers)
            response = connection.getresponse()
            assert_result(response.status, json.loads(response.read()))
        print(json.dumps({"case": expected + " restored", "status": 200, "result_class": expected, "verifier_capacity": 1, "operation_capacity": 1}), flush=True)
except TimeoutError:
    raise SystemExit(f"MCP admission smoke exceeded socket progress budget={timeout}s; inspect the local fixture server and rerun make smoke-attestation") from None
PY
}

check_discovery() {
  local proofs_enabled="$1"
  local expected_status=503
  local path status
  if [[ "$proofs_enabled" == "true" ]]; then
    expected_status=200
  fi
  for path in '/.well-known/vaultsmith-attestation' '/.well-known/vaultsmith-attestation/jwks.json'; do
    status="$(curl -sS -D "$TMP_DIR/discovery.headers" -o "$TMP_DIR/discovery.json" \
      -w '%{http_code}' "http://127.0.0.1:${PORT}${path}")"
    [[ "$status" == "$expected_status" ]] || fail "discovery $path (proofs=$proofs_enabled) returned HTTP $status, expected $expected_status"
    grep -qi '^Content-Type: application/json; charset=utf-8' "$TMP_DIR/discovery.headers" || fail "discovery $path did not return JSON"
    grep -qi '^Cache-Control: no-store' "$TMP_DIR/discovery.headers" || fail "discovery $path did not disable caching"
    grep -qi '^X-Request-ID: [^[:space:]]' "$TMP_DIR/discovery.headers" || fail "discovery $path omitted request ID"
    if [[ "$proofs_enabled" == "false" ]]; then
      assert_json "$TMP_DIR/discovery.json" '.error.code == "feature_unavailable"' "disabled discovery $path did not return feature_unavailable"
    elif [[ "$path" == '/.well-known/vaultsmith-attestation' ]]; then
      assert_json "$TMP_DIR/discovery.json" '
        keys == ["activeKid", "attestationVersions", "issuer", "jwksUri", "revokedKids"] and
        .issuer == "https://vaultsmith.synthetic.test" and .activeKid == "synthetic-key-a" and
        .attestationVersions == [1] and .revokedKids == [] and
        .jwksUri == "https://vaultsmith.synthetic.test/.well-known/vaultsmith-attestation/jwks.json"
      ' 'discovery metadata did not match public fixture'
    else
      assert_json "$TMP_DIR/discovery.json" '
        keys == ["keys"] and (.keys | length) == 1 and
        (.keys[0] | keys == ["alg", "crv", "kid", "kty", "use", "x"] and
          .alg == "Ed25519" and .crv == "Ed25519" and .kid == "synthetic-key-a" and
          .kty == "OKP" and .use == "sig")
      ' 'discovery JWKS did not contain only the public fixture key'
      [[ "$(jq -r '.keys[0].x' "$TMP_DIR/discovery.json")" == "$(jq -r '.keys[0].publicKey' "$TMP_DIR/key-a.json")" ]] || fail 'discovery JWKS public key did not match fixture'
    fi
    status="$(curl -sS -X POST -D "$TMP_DIR/discovery.headers" -o "$TMP_DIR/discovery.json" \
      -w '%{http_code}' "http://127.0.0.1:${PORT}${path}")"
    [[ "$status" == "405" ]] || fail "discovery $path accepted POST (HTTP $status)"
    grep -qi '^Allow: GET' "$TMP_DIR/discovery.headers" || fail "discovery $path omitted Allow: GET"
    assert_json "$TMP_DIR/discovery.json" '.error.code == "method_not_allowed"' "discovery $path did not reject POST as JSON"
  done
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

check_nested_json() {
  python3 - "$PORT" "$mcp_request" <<'PY' | tee "$METRICS_DIR/nested-json.jsonl"
import base64
import contextlib
import copy
import http.client
import json
import sys

port = int(sys.argv[1])
with open(sys.argv[2], "rb") as fixture:
    valid = json.load(fixture)
# Match maxAttestationJWSComponentBytes; construction stays inside its encoded
# bound so the transport cannot mask parser rejection. Reuse the smoke's
# ten-second socket-progress budget, not a performance acceptance threshold.
encoded_limit, timeout = 64 << 10, 10
mcp_headers = {
    "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
    "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "verify_rotation_attestation",
}

def request(transport, value):
    path = "/mcp" if transport == "mcp" else "/api/v1/attestations/verify"
    body = value if transport == "mcp" else value["params"]["arguments"]
    headers = mcp_headers if transport == "mcp" else {"Content-Type": "application/json"}
    with contextlib.closing(http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)) as connection:
        connection.request("POST", path, json.dumps(body), headers)
        response = connection.getresponse()
        result = json.loads(response.read())
        assert response.getheader("Cache-Control") == "no-store", "verification cache policy changed"
        assert response.getheader("X-Request-ID"), "verification request ID missing"
        return response.status, result

try:
    for component in ("protected", "payload"):
        for shape, opening, closing in (("object", '{"x":', '}'), ("array", '[', ']')):
            levels = (encoded_limit * 3 // 4 - len('{"x":0}')) // (len(opening) + len(closing))
            raw = '{"x":' + opening * levels + '0' + closing * levels + '}'
            encoded = base64.urlsafe_b64encode(raw.encode("ascii")).decode("ascii").rstrip("=")
            assert len(encoded) <= encoded_limit, f"encoded-component budget={encoded_limit} observed={len(encoded)}; resize fixture"
            malformed = copy.deepcopy(valid)
            malformed["params"]["arguments"]["attestation"][component] = encoded
            for transport in ("rest", "mcp"):
                status, result = request(transport, malformed)
                if transport == "rest":
                    assert status == 400 and set(result) == {"error"}, "REST malformed envelope changed"
                    assert result["error"]["code"] == "invalid_request", "REST malformed classification changed"
                    assert result["error"]["message"] == "invalid attestation verification request", "REST error disclosed parser detail"
                else:
                    assert status == 200 and result["result"]["isError"] is True, "MCP malformed envelope changed"
                    assert "structuredContent" not in result["result"], "MCP malformed request exposed claims"
                    assert result["result"]["content"] == [{"type": "text", "text": "tool arguments are invalid"}], "MCP error disclosed parser detail"
                print(json.dumps({"transport": transport, "component": component, "shape": shape,
                                  "container_depth": levels + 1, "decoded_bytes": len(raw), "encoded_bytes": len(encoded),
                                  "status": status, "result_class": "malformed_request"}), flush=True)
                # A completed valid check also proves verifier capacity was
                # released, rather than merely displaying a success message.
                status, result = request(transport, valid)
                content = result["result"]["structuredContent"] if transport == "mcp" else result
                assert status == 200 and content["valid"] is True, "valid control failed after malformed request"
                if transport == "mcp":
                    assert result["result"]["isError"] is False, "MCP valid control returned tool error"
    print(json.dumps({"case": "post-malformed valid controls", "completed": 8}), flush=True)
except TimeoutError:
    raise SystemExit(f"nested JSON smoke exceeded socket progress budget={timeout}s; inspect the local fixture server and rerun make smoke-attestation") from None
PY
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
check_discovery true

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

scrape_metrics rest
check_metric rest 'vaultsmith_operation_requests_total{operation="encrypt",outcome="success"} 3'
check_metric rest 'vaultsmith_operation_duration_seconds_count{operation="encrypt"} 3'
check_metric rest 'vaultsmith_operation_requests_total{operation="rotate",outcome="success"} 1'
check_metric rest 'vaultsmith_attestation_issued_total{outcome="success"} 1'

for outcome in success invalid_request; do
  arguments='{"profileId":"dev"}'
  if [[ "$outcome" == "invalid_request" ]]; then
    arguments='{"profileId":"dev","bytes":"invalid"}'
  fi
  jq -n --argjson arguments "$arguments" \
    '{jsonrpc:"2.0",id:1,method:"tools/call",params:{name:"generate_token",arguments:$arguments,_meta:{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}' >"$TMP_DIR/generate-request.json"
  curl -fsS -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -H 'MCP-Protocol-Version: 2026-07-28' -H 'Mcp-Method: tools/call' -H 'Mcp-Name: generate_token' \
    --data-binary "@$TMP_DIR/generate-request.json" "http://127.0.0.1:${PORT}/mcp" >"$TMP_DIR/generate-response.json"
  if [[ "$outcome" == "success" ]]; then
    assert_json "$TMP_DIR/generate-response.json" '.result.isError == false and (.result.structuredContent.secret.vaultText | length) > 0' 'MCP Generate failed'
  else
    assert_json "$TMP_DIR/generate-response.json" '.result.isError == true' 'MCP Generate did not return a tool error'
  fi
done
encrypt_profile dev synthetic-rest-control "$TMP_DIR/control.vault"
scrape_metrics mcp
check_metric mcp 'vaultsmith_operation_requests_total{operation="generate",outcome="success"} 1'
check_metric mcp 'vaultsmith_operation_requests_total{operation="generate",outcome="invalid_request"} 1'
check_metric mcp 'vaultsmith_operation_duration_seconds_count{operation="generate"} 2'
check_metric mcp 'vaultsmith_operation_requests_total{operation="encrypt",outcome="success"} 4'
check_metric mcp 'vaultsmith_operation_duration_seconds_count{operation="encrypt"} 4'

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
scrape_metrics verify
check_metric verify 'vaultsmith_operation_requests_total{operation="verify",outcome="success"} 6'
check_metric verify 'vaultsmith_operation_duration_seconds_count{operation="verify"} 6'
check_metric verify 'vaultsmith_attestation_verify_total{outcome="success"} 5'
check_metric verify 'vaultsmith_attestation_verify_total{outcome="invalid"} 1'
check_mcp_admission ready
check_nested_json
scrape_metrics nested-json
check_metric nested-json 'vaultsmith_operation_requests_total{operation="verify",outcome="invalid_request"} 8'
check_metric nested-json 'vaultsmith_attestation_verify_total{outcome="invalid"} 9'

stop_server
start_server "$prod_only_profiles" true
verify_expected "$TMP_DIR/proof-b.json" "$input_file" "$TMP_DIR/output-b.vault" "$binding_file" '.valid == true' 'historical proof depended on removed source profile'

stop_server
start_server "$prod_only_profiles" false
check_discovery false
jq -n '{attestation:{}, inputVaultText:"", outputVaultText:""}' >"$TMP_DIR/off-request.json"
status="$(request_status "$TMP_DIR/off-request.json" "/api/v1/attestations/verify" "$TMP_DIR/off-response.json")"
[[ "$status" == "503" ]] || fail "disabled verification returned HTTP $status"
assert_json "$TMP_DIR/off-response.json" '.error.code == "feature_unavailable"' 'disabled verification did not return feature_unavailable'
write_rotation_request "$input_file"
status="$(request_status "$TMP_DIR/rotate-request.json" "/api/v1/rotations" "$TMP_DIR/off-rotation-response.json")"
[[ "$status" == "503" ]] || fail "disabled issuance returned HTTP $status"
assert_json "$TMP_DIR/off-rotation-response.json" '.error.code == "feature_unavailable"' 'disabled issuance did not return feature_unavailable'
scrape_metrics disabled
check_metric disabled 'vaultsmith_attestation_issued_total{outcome="feature_unavailable"} 1'
check_metric disabled 'vaultsmith_attestation_issued_total{outcome="unavailable"} 0'
check_metric disabled 'vaultsmith_operation_requests_total{operation="rotate",outcome="unavailable"} 1'
check_metric disabled 'vaultsmith_operation_duration_seconds_count{operation="rotate"} 1'
curl -fsS "http://127.0.0.1:${PORT}/api/v1/session" >"$TMP_DIR/off-session.json"
assert_json "$TMP_DIR/off-session.json" '.attestationEnabled == false' 'off mode advertised attestation capability'
check_mcp_admission feature_unavailable

[[ "$metrics_failed" == "false" ]] || fail 'metrics checks failed; sanitized scrapes are in .tmp/smoke-attestation/'
printf 'attestation smoke: ok (discovery enabled/disabled, rotation, semantic failures, restart, reload, revocation, REST/MCP nested JSON, MCP admission, off-mode, metrics); evidence: .tmp/smoke-attestation/\n'
