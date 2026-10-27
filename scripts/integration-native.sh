#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/integration/docker-compose.yml"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/vaultsmith-native-integration.XXXXXX")"
PROJECT="vaultsmith-native-integration-$$"
SERVER_PID=""
INTERACTIVE=0
compose=(docker compose --project-name "$PROJECT" --env-file "$TMP_DIR/.env" -f "$COMPOSE_FILE")
if [[ "$(uname -s)" == "Linux" ]]; then
  compose+=(-f "$ROOT_DIR/integration/docker-compose.linux.yml")
fi

case "${1:-}" in
  "") ;;
  --interactive) INTERACTIVE=1 ;;
  --help|-h)
    printf 'Usage: %s [--interactive]\n' "$0"
    printf '\nWithout arguments, runs the disposable native integration assertions.\n'
    printf 'With --interactive, keeps the stack running for browser testing until Ctrl-C.\n'
    exit 0
    ;;
  *)
    printf 'integration: unknown argument: %s\n' "$1" >&2
    exit 2
    ;;
esac

cleanup() {
  set +e
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  if command -v docker >/dev/null 2>&1; then
    "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
  fi
  if [[ "${KEEP_INTEGRATION_TMP:-0}" == "1" ]]; then
    printf 'integration: retained temporary state at %s\n' "$TMP_DIR" >&2
  else
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT

for command in docker openssl python3 go; do
  command -v "$command" >/dev/null 2>&1 || { printf 'integration: missing dependency: %s\n' "$command" >&2; exit 1; }
done
docker compose version >/dev/null

random_secret() { openssl rand -hex 24; }
KEYCLOAK_ADMIN_PASSWORD="$(random_secret)"
OIDC_CLIENT_SECRET="$(random_secret)"
MACHINE_CLIENT_SECRET="$(random_secret)"
TEST_USER_PASSWORD="$(random_secret)"
DENIED_USER_PASSWORD="$(random_secret)"
DELEGATE_USER_PASSWORD="$(random_secret)"
LANE_MACHINE_CLIENT_SECRET="$(random_secret)"
CSRF_SECRET="$(random_secret)"
VAULT_PASSWORD_DEV="$(random_secret)"
VAULT_PASSWORD_PROD="$(random_secret)"
VAULT_PASSWORD_STAGE="$(random_secret)"
VAULT_PASSWORD_ARCHIVE="$(random_secret)"

# This keyring is deterministic, disposable test material. It is never used
# outside this integration stack and is removed by cleanup().
cat > "$TMP_DIR/keyring.json" <<'KEYRING'
{"version":1,"active":"synthetic-key","keys":[{"id":"synthetic-key","state":"active","publicKey":"iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w","privateKey":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"}]}
KEYRING
chmod 600 "$TMP_DIR/keyring.json"

# The integration topology uses fixed ports throughout; do not let caller exports override its Compose env file.
unset REDIS_PORT KEYCLOAK_PORT KEYCLOAK_ADMIN_PORT EDGE_PORT

cat > "$TMP_DIR/.env" <<EOF
KEYCLOAK_ADMIN_USERNAME=integration-admin
KEYCLOAK_ADMIN_PASSWORD=$KEYCLOAK_ADMIN_PASSWORD
REDIS_PORT=16379
KEYCLOAK_PORT=18081
KEYCLOAK_ADMIN_PORT=18082
EDGE_PORT=18443
EOF
chmod 600 "$TMP_DIR/.env"

dump_startup_diagnostics() {
  printf 'native integration startup failed; container state follows\n' >&2
  "${compose[@]}" ps >&2 || true
  "${compose[@]}" logs --no-color >&2 || true
  if [[ -s "$TMP_DIR/server.log" ]]; then
    printf 'Vaultsmith server log follows\n' >&2
    tail -n 200 "$TMP_DIR/server.log" >&2
  fi
}
if ! "${compose[@]}" up -d --wait redis idp-edge >/dev/null; then
  dump_startup_diagnostics
  exit 1
fi
"${compose[@]}" cp idp-edge:/data/caddy/pki/authorities/local/root.crt "$TMP_DIR/idp-root.crt" >/dev/null

kc() {
  "${compose[@]}" exec -T keycloak /opt/keycloak/bin/kcadm.sh "$@"
}

kc config credentials \
  --server http://127.0.0.1:8080 \
  --realm master \
  --user integration-admin \
  --password "$KEYCLOAK_ADMIN_PASSWORD" >/dev/null
kc create realms -s realm=vaultsmith -s enabled=true >/dev/null
BROWSER_CLIENT_JSON="$(OIDC_CLIENT_SECRET="$OIDC_CLIENT_SECRET" python3 - <<'PY'
import json
import os

print(json.dumps({
    "clientId": "vaultsmith-integration",
    "enabled": True,
    "protocol": "openid-connect",
    "publicClient": False,
    "secret": os.environ["OIDC_CLIENT_SECRET"],
    "standardFlowEnabled": True,
    "directAccessGrantsEnabled": False,
    "serviceAccountsEnabled": False,
    "attributes": {"access.token.header.type.rfc9068": "true"},
    "redirectUris": [
        "https://localhost:18443/auth/callback",
        "https://localhost:18443/integration-callback",
    ],
    "webOrigins": ["https://localhost:18443"],
}))
PY
)"
CLIENT_ID="$(kc create clients -r vaultsmith -b "$BROWSER_CLIENT_JSON" -i)"
unset BROWSER_CLIENT_JSON

MACHINE_CLIENT_JSON="$(MACHINE_CLIENT_SECRET="$MACHINE_CLIENT_SECRET" python3 - <<'PY'
import json
import os

print(json.dumps({
    "clientId": "vaultsmith-integration-machine",
    "enabled": True,
    "protocol": "openid-connect",
    "publicClient": False,
    "secret": os.environ["MACHINE_CLIENT_SECRET"],
    "standardFlowEnabled": False,
    "directAccessGrantsEnabled": False,
    "serviceAccountsEnabled": True,
    "attributes": {"access.token.header.type.rfc9068": "true"},
}))
PY
)"
MACHINE_CLIENT_ID="$(kc create clients -r vaultsmith -b "$MACHINE_CLIENT_JSON" -i)"
unset MACHINE_CLIENT_JSON

LANE_MACHINE_CLIENT_JSON="$(LANE_MACHINE_CLIENT_SECRET="$LANE_MACHINE_CLIENT_SECRET" python3 - <<'PY'
import json
import os

print(json.dumps({
    "clientId": "vaultsmith-integration-lane",
    "enabled": True,
    "protocol": "openid-connect",
    "publicClient": False,
    "secret": os.environ["LANE_MACHINE_CLIENT_SECRET"],
    "standardFlowEnabled": False,
    "directAccessGrantsEnabled": False,
    "serviceAccountsEnabled": True,
    "attributes": {"access.token.header.type.rfc9068": "true"},
}))
PY
)"
LANE_MACHINE_CLIENT_ID="$(kc create clients -r vaultsmith -b "$LANE_MACHINE_CLIENT_JSON" -i)"
unset LANE_MACHINE_CLIENT_JSON
GROUP_ID="$(kc create groups -r vaultsmith -s name=vaultsmith-operators -i)"
USER_ID="$(kc create users -r vaultsmith \
  -s username=integration-user \
  -s enabled=true \
  -s email=integration-user@example.test \
  -s emailVerified=true \
  -s firstName=Integration \
  -s lastName=User \
  -s 'requiredActions=[]' -i)"
kc set-password -r vaultsmith --username integration-user --new-password "$TEST_USER_PASSWORD" >/dev/null
kc create users -r vaultsmith \
  -s username=integration-denied \
  -s enabled=true \
  -s email=integration-denied@example.test \
  -s emailVerified=true \
  -s firstName=No \
  -s lastName=Permissions \
  -s 'requiredActions=[]' >/dev/null
kc set-password -r vaultsmith --username integration-denied --new-password "$DENIED_USER_PASSWORD" >/dev/null
kc update "users/$USER_ID/groups/$GROUP_ID" -r vaultsmith >/dev/null

LANE_GROUP_ID="$(kc create groups -r vaultsmith -s name=vaultsmith-rekey-delegates -i)"
LANE_USER_ID="$(kc create users -r vaultsmith -s username=integration-delegate -s enabled=true -s email=delegate@example.test -s emailVerified=true -s firstName=Rekey -s lastName=Delegate -s 'requiredActions=[]' -i)"
kc set-password -r vaultsmith --username integration-delegate --new-password "$DELEGATE_USER_PASSWORD" >/dev/null
kc update "users/$LANE_USER_ID/groups/$LANE_GROUP_ID" -r vaultsmith >/dev/null


for scope in vaultsmith.profile.read vaultsmith.encrypt vaultsmith.decrypt vaultsmith.rotate vaultsmith.attestation.verify; do
  scope_id="$(kc create client-scopes -r vaultsmith -i -b "{\"name\":\"$scope\",\"protocol\":\"openid-connect\",\"attributes\":{\"include.in.token.scope\":\"true\",\"display.on.consent.screen\":\"false\"}}")"
  kc update "clients/$CLIENT_ID/optional-client-scopes/$scope_id" -r vaultsmith >/dev/null
  kc update "clients/$MACHINE_CLIENT_ID/optional-client-scopes/$scope_id" -r vaultsmith >/dev/null
  kc update "clients/$LANE_MACHINE_CLIENT_ID/optional-client-scopes/$scope_id" -r vaultsmith >/dev/null
done

configure_token_mappers() {
  local client_internal_id="$1"
  local client_id_claim="$2"
  kc create "clients/$client_internal_id/protocol-mappers/models" -r vaultsmith \
    -b '{"name":"groups","protocol":"openid-connect","protocolMapper":"oidc-group-membership-mapper","config":{"full.path":"false","id.token.claim":"true","access.token.claim":"true","userinfo.token.claim":"true","introspection.token.claim":"true","claim.name":"groups"}}' >/dev/null
  kc create "clients/$client_internal_id/protocol-mappers/models" -r vaultsmith \
    -b '{"name":"vaultsmith-audience","protocol":"openid-connect","protocolMapper":"oidc-audience-mapper","config":{"included.custom.audience":"https://localhost:18443","id.token.claim":"false","access.token.claim":"true","introspection.token.claim":"true","lightweight.claim":"false"}}' >/dev/null
  kc create "clients/$client_internal_id/protocol-mappers/models" -r vaultsmith \
    -b "{\"name\":\"client-id\",\"protocol\":\"openid-connect\",\"protocolMapper\":\"oidc-hardcoded-claim-mapper\",\"config\":{\"claim.name\":\"client_id\",\"claim.value\":\"$client_id_claim\",\"jsonType.label\":\"String\",\"id.token.claim\":\"false\",\"access.token.claim\":\"true\",\"userinfo.token.claim\":\"false\",\"introspection.token.claim\":\"true\",\"lightweight.claim\":\"false\"}}" >/dev/null
}
configure_token_mappers "$CLIENT_ID" vaultsmith-integration
configure_token_mappers "$MACHINE_CLIENT_ID" vaultsmith-integration-machine
configure_token_mappers "$LANE_MACHINE_CLIENT_ID" vaultsmith-integration-lane

SERVICE_ACCOUNT_ID="$(kc get "clients/$MACHINE_CLIENT_ID/service-account-user" -r vaultsmith --fields id --format csv --noquotes)"
kc update "users/$SERVICE_ACCOUNT_ID/groups/$GROUP_ID" -r vaultsmith >/dev/null
LANE_SERVICE_ACCOUNT_ID="$(kc get "clients/$LANE_MACHINE_CLIENT_ID/service-account-user" -r vaultsmith --fields id --format csv --noquotes)"
kc update "users/$LANE_SERVICE_ACCOUNT_ID/groups/$LANE_GROUP_ID" -r vaultsmith >/dev/null

if (( INTERACTIVE )); then
  cat > "$TMP_DIR/policy.csv" <<'POLICY'
g, group:vaultsmith-operators, role:operator
p, role:operator, profiles, profiles:list, allow
p, role:operator, profile:dev, encrypt, allow
p, role:operator, profile:dev, decrypt, allow
p, role:operator, profile:prod, encrypt, allow
p, role:operator, rotation:dev:prod, rotate, allow
p, role:operator, profile:prod, decrypt, allow
POLICY
  PROFILES_JSON='[{"id":"dev","label":"Development","passwordEnv":"VAULT_PASSWORD_DEV"},{"id":"prod","label":"Production","passwordEnv":"VAULT_PASSWORD_PROD"},{"id":"stage","label":"Staging","passwordEnv":"VAULT_PASSWORD_STAGE"},{"id":"archive","label":"Archive","passwordEnv":"VAULT_PASSWORD_ARCHIVE"}]'
else
  cat > "$TMP_DIR/policy.csv" <<'POLICY'
g, group:vaultsmith-operators, role:operator
p, role:operator, profiles, profiles:list, allow
p, role:operator, profile:dev, encrypt, allow
p, role:operator, profile:dev, decrypt, allow
p, role:operator, profile:prod, encrypt, allow
p, role:operator, rotation:dev:prod, rotate, allow
POLICY
  PROFILES_JSON='[{"id":"dev","label":"Development","passwordEnv":"VAULT_PASSWORD_DEV"},{"id":"prod","label":"Production","passwordEnv":"VAULT_PASSWORD_PROD"},{"id":"stage","label":"Staging","passwordEnv":"VAULT_PASSWORD_STAGE"},{"id":"archive","label":"Archive","passwordEnv":"VAULT_PASSWORD_ARCHIVE"}]'
fi


cat >> "$TMP_DIR/policy.csv" <<'DELEGATION_POLICY'
g, group:vaultsmith-rekey-delegates, role:rekey-delegate
p, role:rekey-delegate, profiles, profiles:list, allow
p, role:rekey-delegate, profile:dev, decrypt, deny
p, role:rekey-delegate, profile:prod, encrypt, deny
p, role:rekey-delegate, profile:stage, decrypt, deny
p, role:rekey-delegate, profile:archive, encrypt, deny
DELEGATION_POLICY

go build -o "$TMP_DIR/vaultsmith" ./backend/cmd/server
(
  AUTH_MODE=native \
  CSRF_SECRET="$CSRF_SECRET" \
  OIDC_ISSUER_URL=https://localhost:18081/realms/vaultsmith \
  OIDC_CA_FILE="$TMP_DIR/idp-root.crt" \
  OIDC_CLIENT_ID=vaultsmith-integration \
  OIDC_CLIENT_SECRET="$OIDC_CLIENT_SECRET" \
  OIDC_REDIRECT_URL=https://localhost:18443/auth/callback \
  PUBLIC_BASE_URL=https://localhost:18443 \
  REDIS_ADDR=127.0.0.1:16379 \
  REDIS_KEY_PREFIX='vaultsmith:integration:' \
  AUTHZ_POLICY_FILE="$TMP_DIR/policy.csv" \
  COOKIE_SECURE=true \
  MCP_ENABLED=true \
  PROOFS_ENABLED=true \
  PROOFS_KEYRING_FILE="$TMP_DIR/keyring.json" \
  VAULT_PROFILES_JSON="$PROFILES_JSON" \
  VAULT_PASSWORD_DEV="$VAULT_PASSWORD_DEV" \
  VAULT_PASSWORD_PROD="$VAULT_PASSWORD_PROD" \
  VAULT_PASSWORD_STAGE="$VAULT_PASSWORD_STAGE" \
  VAULT_PASSWORD_ARCHIVE="$VAULT_PASSWORD_ARCHIVE" \
  HTTP_ADDR=127.0.0.1:18080 \
  exec "$TMP_DIR/vaultsmith" >"$TMP_DIR/server.log" 2>&1
) &
SERVER_PID=$!

if ! "${compose[@]}" up -d --wait edge >/dev/null; then
  dump_startup_diagnostics
  exit 1
fi

BASE_URL='https://localhost:18443'

ROOT_DIR="$ROOT_DIR" INTERACTIVE="$INTERACTIVE" TEST_USER_PASSWORD="$TEST_USER_PASSWORD" DENIED_USER_PASSWORD="$DENIED_USER_PASSWORD" DELEGATE_USER_PASSWORD="$DELEGATE_USER_PASSWORD" LANE_MACHINE_CLIENT_SECRET="$LANE_MACHINE_CLIENT_SECRET" OIDC_CLIENT_SECRET="$OIDC_CLIENT_SECRET" MACHINE_CLIENT_SECRET="$MACHINE_CLIENT_SECRET" CSRF_SECRET="$CSRF_SECRET" VAULT_PASSWORD_DEV="$VAULT_PASSWORD_DEV" VAULT_PASSWORD_PROD="$VAULT_PASSWORD_PROD" VAULT_PASSWORD_STAGE="$VAULT_PASSWORD_STAGE" VAULT_PASSWORD_ARCHIVE="$VAULT_PASSWORD_ARCHIVE" TMP_DIR="$TMP_DIR" SERVER_PID="$SERVER_PID" python3 - "$BASE_URL" <<'PY'
import html.parser
import base64
import hashlib
import json
import os
import secrets
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import subprocess
from pathlib import Path

base = sys.argv[1]
user_password = os.environ["TEST_USER_PASSWORD"]
denied_password = os.environ["DENIED_USER_PASSWORD"]
oidc_client_secret = os.environ["OIDC_CLIENT_SECRET"]
machine_client_secret = os.environ["MACHINE_CLIENT_SECRET"]
server_log = os.path.join(os.environ["TMP_DIR"], "server.log")

class FormParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.action = ""
        self.fields = {}
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form" and not self.action:
            self.action = attrs.get("action", "")
        if tag == "input" and attrs.get("name"):
            self.fields[attrs["name"]] = attrs.get("value", "")

context = ssl._create_unverified_context()

def new_opener():
    jar = urllib.request.HTTPCookieProcessor()
    return urllib.request.build_opener(jar, urllib.request.HTTPSHandler(context=context))

opener = new_opener()

def request(path, data=None, headers=None):
    request = urllib.request.Request(base + path, data=data, headers=headers or {})
    return opener.open(request)

def json_response(response):
    return json.loads(response.read().decode("utf-8"))

def token_request(fields, client_id, client_secret):
    credentials = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode("ascii")
    request = urllib.request.Request(
        "https://localhost:18081/realms/vaultsmith/protocol/openid-connect/token",
        data=urllib.parse.urlencode(fields).encode("utf-8"),
        headers={"Authorization": "Basic " + credentials, "Content-Type": "application/x-www-form-urlencoded"},
    )
    return json_response(urllib.request.urlopen(request, context=context))

def bearer_request(path, token, data=None, headers=None):
    merged = {"Authorization": "Bearer " + token}
    merged.update(headers or {})
    request = urllib.request.Request(base + path, data=data, headers=merged)
    return urllib.request.urlopen(request, context=context)

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None

def delegated_access_token(username, password, scope):
    idp_opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(),
        urllib.request.HTTPSHandler(context=context),
        NoRedirect(),
    )
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    state = secrets.token_urlsafe(16)
    authorize = "https://localhost:18081/realms/vaultsmith/protocol/openid-connect/auth?" + urllib.parse.urlencode({
        "response_type": "code",
        "client_id": "vaultsmith-integration",
        "redirect_uri": base + "/integration-callback",
        "scope": "openid " + scope,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    login_response = idp_opener.open(authorize)
    parser = FormParser()
    parser.feed(login_response.read().decode("utf-8"))
    parser.fields["username"] = username
    parser.fields["password"] = password
    login_request = urllib.request.Request(
        urllib.parse.urljoin(login_response.geturl(), parser.action),
        data=urllib.parse.urlencode(parser.fields).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        idp_opener.open(login_request)
    except urllib.error.HTTPError as error:
        redirect = error.headers.get("Location", "")
        if error.code not in (302, 303) or not redirect.startswith(base + "/integration-callback?"):
            raise
    else:
        raise AssertionError("authorization redirect was unexpectedly followed through the application edge")
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(redirect).query)
    assert query.get("state") == [state] and len(query.get("code", [])) == 1, query
    token = token_request({
        "grant_type": "authorization_code",
        "code": query["code"][0],
        "redirect_uri": base + "/integration-callback",
        "code_verifier": verifier,
    }, "vaultsmith-integration", oidc_client_secret)
    return token["access_token"]

def client_credentials_access_token(scope):
    token = token_request({"grant_type": "client_credentials", "scope": scope}, "vaultsmith-integration-machine", machine_client_secret)
    return token["access_token"]

session = json_response(request("/api/v1/session"))
assert session["authRequired"] is True and session["authenticated"] is False

def login(username, password):
    login_response = request("/auth/login?return_to=%2F")
    login_url = login_response.geturl()
    parser = FormParser()
    parser.feed(login_response.read().decode("utf-8"))
    assert parser.action and "username" in parser.fields and "password" in parser.fields
    parser.fields["username"] = username
    parser.fields["password"] = password
    login_request = urllib.request.Request(
        urllib.parse.urljoin(login_url, parser.action),
        data=urllib.parse.urlencode(parser.fields).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    response = opener.open(login_request)
    response.read()


def logout(session):
    response = request("/auth/logout", b"", {
        "Content-Type": "application/json",
        "Origin": base,
        "Referer": base + "/",
        "X-CSRF-Token": session["csrfToken"],
    })
    assert response.status == 204 and not response.read(), response.status

login("integration-user", user_password)

session = json_response(request("/api/v1/session"))
assert session["authenticated"] is True and session["email"] == "integration-user@example.test"
profiles = json_response(request("/api/v1/profiles"))["profiles"]
assert profiles == [
    {
        "id": "dev",
        "label": "Development",
        "capabilities": {
            "encrypt": True,
            "decrypt": True,
            "rotateSource": True,
            "rotateDestination": False,
            "rotateDestinationIds": ["prod"],
        },
    },
    {
        "id": "prod",
        "label": "Production",
        "capabilities": {
            "encrypt": True,
            "decrypt": bool(int(os.environ["INTERACTIVE"])),
            "rotateSource": False,
            "rotateDestination": True,
            "rotateDestinationIds": [],
        },
    },
], profiles

body = json.dumps({"profileId": "dev", "mode": "encrypt", "value": "integration"}).encode("utf-8")
operation = json_response(request("/api/v1/operations", body, {
    "Content-Type": "application/json",
    "Origin": base,
    "Referer": base + "/",
    "X-CSRF-Token": session["csrfToken"],
}))
assert isinstance(operation.get("value"), str) and operation["value"], operation

delegated = delegated_access_token("integration-user", user_password, "vaultsmith.profile.read vaultsmith.encrypt")
bearer_profiles = json_response(bearer_request("/api/v1/profiles", delegated, headers={"X-Forwarded-User": "spoofed", "X-Remote-Groups": "admins"}))["profiles"]
scoped_profiles = [
    {
        "id": "dev",
        "label": "Development",
        "capabilities": {
            "encrypt": True,
            "decrypt": False,
            "rotateSource": False,
            "rotateDestination": False,
            "rotateDestinationIds": [],
        },
    },
    {
        "id": "prod",
        "label": "Production",
        "capabilities": {
            "encrypt": True,
            "decrypt": False,
            "rotateSource": False,
            "rotateDestination": False,
            "rotateDestinationIds": [],
        },
    },
]
assert bearer_profiles == scoped_profiles, bearer_profiles
bearer_encrypt = json_response(bearer_request(
    "/api/v1/profiles/dev/encrypt",
    delegated,
    json.dumps({"plaintext": "delegated-integration"}).encode("utf-8"),
    {"Content-Type": "application/json", "X-Forwarded-User": "spoofed"},
))
assert bearer_encrypt["vaultText"].startswith("$ANSIBLE_VAULT;1.2;AES256;dev"), bearer_encrypt

machine = client_credentials_access_token("vaultsmith.profile.read vaultsmith.encrypt")
machine_profiles = json_response(bearer_request("/api/v1/profiles", machine))["profiles"]
assert machine_profiles == scoped_profiles, machine_profiles

# Exercise attestation through both native bearer paths. The verify-only
# tokens intentionally omit profile.read to prove verification is keyring-only.
binding = {
    "repository": "synthetic/native-integration",
    "revision": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "path": "synthetic/path",
    "selector": "synthetic",
}

def attested_rotation(token):
    body = json.dumps({
        "sourceProfileId": "dev",
        "destinationProfileId": "prod",
        "vaultText": operation["value"],
        "attestation": {"binding": binding},
    }).encode("utf-8")
    return json_response(bearer_request(
        "/api/v1/rotations",
        token,
        body,
        {"Content-Type": "application/json"},
    ))

def verify_attestation(token, rotation, mcp=False):
    arguments = {
        "attestation": rotation["attestation"],
        "inputVaultText": operation["value"],
        "outputVaultText": rotation["vaultText"],
        "expectedBinding": binding,
    }
    if mcp:
        body = json.dumps({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {
            "name": "verify_rotation_attestation", "arguments": arguments,
            "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {}},
        }}).encode("utf-8")
        result = json_response(bearer_request("/mcp", token, body, {
            "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "verify_rotation_attestation",
        }))
        assert result["result"]["isError"] is False, "native MCP verification returned a tool error"
        return result["result"]["structuredContent"]
    body = json.dumps(arguments).encode("utf-8")
    return json_response(bearer_request(
        "/api/v1/attestations/verify",
        token,
        body,
        {"Content-Type": "application/json"},
    ))

delegated_rotate = delegated_access_token("integration-user", user_password, "vaultsmith.rotate")
delegated_rotation = attested_rotation(delegated_rotate)
assert delegated_rotation.get("attestation") and delegated_rotation.get("vaultText"), delegated_rotation
delegated_verify = delegated_access_token("integration-user", user_password, "vaultsmith.attestation.verify")
assert verify_attestation(delegated_verify, delegated_rotation)["valid"] is True
assert verify_attestation(delegated_verify, delegated_rotation, mcp=True)["valid"] is True
print("native integration: delegated-user MCP verification: ok")

machine_rotate = client_credentials_access_token("vaultsmith.rotate")
machine_rotation = attested_rotation(machine_rotate)
assert machine_rotation.get("attestation") and machine_rotation.get("vaultText"), machine_rotation
machine_verify = client_credentials_access_token("vaultsmith.attestation.verify")
assert verify_attestation(machine_verify, machine_rotation)["valid"] is True
assert verify_attestation(machine_verify, machine_rotation, mcp=True)["valid"] is True
print("native integration: client-credentials MCP verification: ok")

try:
    verify_attestation(machine, delegated_rotation)
except urllib.error.HTTPError as error:
    assert error.code == 403 and "insufficient_scope" in error.headers.get("WWW-Authenticate", ""), error.headers
else:
    raise AssertionError("attestation verification without its scope unexpectedly succeeded")

try:
    verify_attestation(machine, delegated_rotation, mcp=True)
except urllib.error.HTTPError as error:
    assert error.code == 403 and "insufficient_scope" in error.headers.get("WWW-Authenticate", ""), "native MCP verification omitted its scope challenge"
else:
    raise AssertionError("native MCP verification without its scope unexpectedly succeeded")
print("native integration: MCP verification scope rejection: ok")

denied_scope = client_credentials_access_token("vaultsmith.profile.read")
try:
    bearer_request(
        "/api/v1/profiles/dev/encrypt",
        denied_scope,
        b'{"plaintext":"scope-denied"}',
        {"Content-Type": "application/json"},
    )
except urllib.error.HTTPError as error:
    assert error.code == 403 and "insufficient_scope" in error.headers.get("WWW-Authenticate", ""), error.headers
else:
    raise AssertionError("insufficient-scope bearer operation unexpectedly succeeded")

denied_group = delegated_access_token("integration-denied", denied_password, "vaultsmith.profile.read vaultsmith.encrypt")
assert json_response(bearer_request("/api/v1/profiles", denied_group))["profiles"] == []
try:
    bearer_request(
        "/api/v1/profiles/dev/encrypt",
        denied_group,
        b'{"plaintext":"group-denied"}',
        {"Content-Type": "application/json"},
    )
except urllib.error.HTTPError as error:
    assert error.code == 403 and "insufficient_scope" not in error.headers.get("WWW-Authenticate", ""), error.headers
else:
    raise AssertionError("policy-denied bearer operation unexpectedly succeeded")

oversized_marker = "integration-oversized-marker"
oversized = (json.dumps({"plaintext": oversized_marker})[:-2] + "x" * (8 * 1024 * 1024) + '"}').encode("utf-8")
try:
    bearer_request(
        "/api/v1/profiles/dev/encrypt",
        delegated,
        oversized,
        {"Content-Type": "application/json"},
    )
except urllib.error.HTTPError as error:
    assert error.code == 413, error.code
else:
    raise AssertionError("oversized bearer body unexpectedly succeeded")

mcp_meta = {"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {}}
mcp_body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {"_meta": mcp_meta}}).encode("utf-8")
mcp = json_response(bearer_request("/mcp", machine, mcp_body, {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
    "MCP-Protocol-Version": "2026-07-28",
    "Mcp-Method": "server/discover",
}))
assert mcp["result"]["supportedVersions"] == ["2026-07-28"], mcp

metadata_cases = [
    ("client info", '"io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"synthetic","name":"other","version":"1"}', False),
    ("roots capability", '"io.modelcontextprotocol/clientCapabilities":{"roots":{"listChanged":true,"listChanged":false}}', False),
    ("extension object", '"io.modelcontextprotocol/clientCapabilities":{},"com.example/extension":{"field":1,"field":2}', False),
    ("valid metadata", '"io.modelcontextprotocol/clientCapabilities":{"roots":{"listChanged":true},"vendor/custom":{}},"io.modelcontextprotocol/clientInfo":{"name":"synthetic","version":"1"},"":null,"com.example/":[{"bad prefix/key":1,"":false},{"field":2}]', True),
]
for method in ("server/discover", "tools/list", "tools/call"):
    for case, fields, valid in metadata_cases:
        params = '"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",' + fields + '}'
        if method == "tools/call":
            params += ',"name":"list_profiles","arguments":{}'
        body = ('{"jsonrpc":"2.0","id":"metadata","method":' + json.dumps(method) + ',"params":{' + params + '}}').encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2026-07-28",
            "Mcp-Method": method,
        }
        if method == "tools/call":
            headers["Mcp-Name"] = "list_profiles"
        try:
            response = bearer_request("/mcp", machine, body, headers)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            assert response.code == (200 if valid else 400), (method, case, response.code)
            assert response.headers.get("Cache-Control") == "no-store", (method, case)
            assert response.headers.get("X-Request-ID"), (method, case)
            envelope = json_response(response)
        assert envelope["jsonrpc"] == "2.0" and envelope["id"] == "metadata", (method, case)
        if valid:
            assert "error" not in envelope and envelope["result"]["resultType"] == "complete", (method, case)
            if method == "tools/call":
                assert envelope["result"]["isError"] is False, (method, case)
                assert {profile["id"] for profile in envelope["result"]["structuredContent"]["profiles"]} == {"dev", "prod"}, (method, case)
        else:
            assert "result" not in envelope and envelope["error"] == {"code": -32602, "message": "invalid params"}, (method, case)
        print(f"native integration: MCP metadata {method} / {case}: ok")

for private_path in ("/healthz", "/readyz"):
    try:
        urllib.request.urlopen(base + private_path, context=context)
    except urllib.error.HTTPError as error:
        assert error.code == 404, (private_path, error.code)
    else:
        raise AssertionError(f"public edge exposed private route {private_path}")

with open(server_log, encoding="utf-8") as log_file:
    log_text = log_file.read()
for secret_value in (delegated, machine, delegated_rotate, delegated_verify, machine_rotate, machine_verify, denied_scope, denied_group, user_password, denied_password, oidc_client_secret, machine_client_secret, oversized_marker, "delegated-integration", "scope-denied", "group-denied"):
    assert secret_value not in log_text, "server log exposed a token, secret, or submitted body marker"

logout(session)
session = json_response(request("/api/v1/session"))
assert session["authenticated"] is False, session

opener = new_opener()
login("integration-denied", denied_password)
session = json_response(request("/api/v1/session"))
assert session["authenticated"] is True and session["email"] == "integration-denied@example.test"
profiles = json_response(request("/api/v1/profiles"))["profiles"]
assert profiles == [], profiles

body = json.dumps({"profileId": "dev", "mode": "encrypt", "value": "denied"}).encode("utf-8")
try:
    request("/api/v1/operations", body, {
        "Content-Type": "application/json",
        "Origin": base,
        "Referer": base + "/",
        "X-CSRF-Token": session["csrfToken"],
    })
except urllib.error.HTTPError as error:
    assert error.code == 403, error.code
else:
    raise AssertionError("no-permission operation unexpectedly succeeded")

logout(session)
session = json_response(request("/api/v1/session"))
assert session["authenticated"] is False, session

# Exact delegated routes: the owner edits only this disposable policy file.
root = Path(os.environ["ROOT_DIR"])
private = Path(os.environ["TMP_DIR"])
policy_file = private / "policy.csv"
base_policy = policy_file.read_text()
source_diff = hashlib.sha256(subprocess.check_output(["git", "diff", "--binary", "--"], cwd=root))
for relative in ("scripts/integration_native_test.py", "integration/docker-compose.linux.yml", "integration/Caddyfile-linux", "integration/delegated-rekey-browser.mjs"):
    candidate = root / relative
    if candidate.exists():
        source_diff.update(relative.encode() + b"\0" + candidate.read_bytes())
identity = {"source_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root).decode().strip(), "source_diff_sha256": source_diff.hexdigest()}
receipts = []
receipt_file = root / ".tmp/delegated-rekey-step6/native.json"
receipt_file.parent.mkdir(parents=True, exist_ok=True)

def check(scenario, transport, expected, observed):
    receipts.append({**identity, "scenario": scenario, "transport": transport, "expected": expected, "observed": observed, "pass": expected == observed})
    receipt_file.write_text(json.dumps(receipts, indent=2) + "\n")
    if expected != observed:
        raise AssertionError(f"{scenario}/{transport}: unexpected status or boolean")

def replace_policy(content):
    previous = policy_file.stat()
    replacement = policy_file.with_suffix(".replacement")
    replacement.write_text(content)
    replacement.chmod(0o600)
    changed = previous.st_mtime_ns + 1_000_000_000
    os.utime(replacement, ns=(changed, changed))
    os.replace(replacement, policy_file)

all_scopes = "vaultsmith.profile.read vaultsmith.encrypt vaultsmith.decrypt vaultsmith.rotate vaultsmith.attestation.verify"
owner = delegated_access_token("integration-user", user_password, all_scopes)
delegate_password = os.environ["DELEGATE_USER_PASSWORD"]
lane_user = delegated_access_token("integration-delegate", delegate_password, all_scopes)
lane_machine = token_request({"grant_type": "client_credentials", "scope": all_scopes}, "vaultsmith-integration-lane", os.environ["LANE_MACHINE_CLIENT_SECRET"])["access_token"]
no_rotate = delegated_access_token("integration-delegate", delegate_password, "vaultsmith.profile.read")
no_read = delegated_access_token("integration-delegate", delegate_password, "vaultsmith.rotate")
# The existing operator remains the private oracle; these extra rights never
# belong to the lane-only identities and are confined to this fixture phase.
grant_policy = base_policy
for row in ("p, role:operator, profile:prod, decrypt, allow", "p, role:operator, profile:stage, encrypt, allow", "p, role:operator, profile:archive, decrypt, allow"):
    if row not in grant_policy.splitlines():
        grant_policy += row + "\n"
grant_policy += "p, role:rekey-delegate, rotation:dev:prod, rotate, allow\np, role:rekey-delegate, rotation:stage:archive, rotate, allow\n"
# Independent route expectations are deliberately not inferred from direct rights.
expected_pairs = {"dev": ["prod"], "prod": [], "stage": ["archive"], "archive": []}
labels = {"dev": "Development", "prod": "Production", "stage": "Staging", "archive": "Archive"}

def expected_profiles(pairs):
    incoming = {target for targets in pairs.values() for target in targets}
    return [{"id": source, "label": labels[source], "capabilities": {"encrypt": False, "decrypt": False, "rotateSource": bool(targets), "rotateDestination": source in incoming, "rotateDestinationIds": targets}} for source, targets in pairs.items() if targets or source in incoming]

opener = new_opener()
login("integration-delegate", delegate_password)
lane_session = json_response(request("/api/v1/session"))

mcp_headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call"}

def lane_call(transport, name, arguments=None, token_override=None):
    arguments = arguments or {}
    token = token_override or (lane_machine if transport.endswith("machine") else lane_user)
    if transport.startswith("MCP"):
        body = json.dumps({"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {"name": name, "arguments": arguments, "_meta": mcp_meta}}).encode()
        headers = dict(mcp_headers, **{"Mcp-Name": name})
        invoke = lambda: bearer_request("/mcp", token, body, headers)
    else:
        paths = {"list_profiles": "/api/v1/profiles", "rotate": "/api/v1/rotations", "generate_age_identity": "/api/v1/generate"}
        path = paths.get(name, "/api/v1/profiles/" + arguments.get("profileId", "dev") + "/" + name)
        body_arguments = dict(arguments)
        if name in ("encrypt", "decrypt"):
            del body_arguments["profileId"]
        if name == "generate_age_identity":
            body_arguments = {"profileId": arguments["profileId"], "kind": "age_identity", "parameters": {}}
        body = None if name == "list_profiles" else json.dumps(body_arguments).encode()
        headers = {"Content-Type": "application/json"}
        if transport == "session":
            headers.update({"Origin": base, "Referer": base + "/", "X-CSRF-Token": lane_session["csrfToken"]})
            invoke = lambda: request(path, body, headers)
        else:
            invoke = lambda: bearer_request(path, token, body, headers)
    try:
        response = invoke()
    except urllib.error.HTTPError as error:
        response = error
    with response:
        status, payload = response.status, json_response(response)
    if transport.startswith("MCP") and status == 200:
        result = payload["result"]
        check("native-mcp-text-structured", transport, True, not result["isError"] and json.loads(result["content"][0]["text"]) == result["structuredContent"])
        payload = result["structuredContent"]
    return status, payload

transports = ("session", "Bearer user", "Bearer machine", "MCP user", "MCP machine")
for transport in transports:
    status, payload = lane_call(transport, "list_profiles")
    check("native-before-grant", transport, True, status == 200 and payload == {"profiles": []})
replace_policy(grant_policy)
inputs = {}
for source, destination in (("dev", "prod"), ("stage", "archive")):
    inputs[source] = json_response(bearer_request("/api/v1/profiles/" + source + "/encrypt", owner, json.dumps({"plaintext": "synthetic delegated acceptance"}).encode(), {"Content-Type": "application/json"}))["vaultText"]
for transport in transports:
    status, payload = lane_call(transport, "list_profiles")
    check("native-owner-grant-discovery", transport, True, status == 200 and payload == {"profiles": expected_profiles(expected_pairs)})
    for source, destination in (("dev", "prod"), ("stage", "archive")):
        for attested in (False, True):
            arguments = {"sourceProfileId": source, "destinationProfileId": destination, "vaultText": inputs[source]}
            if attested:
                arguments["attestation"] = {"binding": binding}
            status, rotation = lane_call(transport, "rotate", arguments)
            check("native-attested-rotation" if attested else "native-ordinary-rotation", transport, 200, status)
            plain = json_response(bearer_request("/api/v1/profiles/" + destination + "/decrypt", owner, json.dumps({"vaultText": rotation["vaultText"]}).encode(), {"Content-Type": "application/json"}))["plaintext"]
            check("native-private-oracle", transport, True, plain == "synthetic delegated acceptance")
            if attested:
                verification = json_response(bearer_request("/api/v1/attestations/verify", owner, json.dumps({"attestation": rotation["attestation"], "inputVaultText": inputs[source], "outputVaultText": rotation["vaultText"], "expectedBinding": binding}).encode(), {"Content-Type": "application/json"}))
                check("native-proof-binding", transport, True, verification["valid"] and verification["attestation"]["sourceProfileId"] == source and verification["attestation"]["destinationProfileId"] == destination)
    for source, destination in (("dev", "archive"), ("stage", "prod"), ("prod", "dev"), ("dev", "dev"), ("dev", "stage"), ("missing", "prod")):
        status, payload = lane_call(transport, "rotate", {"sourceProfileId": source, "destinationProfileId": destination, "vaultText": inputs["dev"]})
        check("native-denied-alternative", transport, True, status == 403 and payload == {"error": {"code": "forbidden", "message": "operation is not permitted"}})
    for name, arguments in (("encrypt", {"profileId": "prod", "plaintext": "synthetic denied input"}), ("decrypt", {"profileId": "dev", "vaultText": inputs["dev"]}), ("generate_age_identity", {"profileId": "prod"})):
        status, payload = lane_call(transport, name, arguments)
        check("native-direct-denial-" + name, transport, True, status == 403 and payload["error"]["code"] == "forbidden")
for token, name in ((no_rotate, "native-missing-rotate-scope"),):
    for transport in ("Bearer user", "MCP user"):
        status, _ = lane_call(transport, "rotate", {"sourceProfileId": "dev", "destinationProfileId": "prod", "vaultText": inputs["dev"]}, token)
        check(name, transport, 403, status)
status, payload = lane_call("Bearer user", "list_profiles", token_override=no_rotate)
check("native-no-rotate-relation", "Bearer user", True, status == 200 and payload == {"profiles": []})
status, _ = lane_call("Bearer user", "list_profiles", token_override=no_read)
check("native-missing-profile-read", "Bearer user", 403, status)

for scenario, path, headers, use_session in (
    ("native-missing-csrf", "/api/v1/rotations", {"Origin": base}, True),
    ("native-mixed-credentials", "/api/v1/rotations", {"Authorization": "Bearer " + lane_user, "Origin": base}, True),
    ("native-legacy-bearer", "/api/v1/operations", {"Authorization": "Bearer " + lane_user}, False),
    ("native-mcp-session", "/mcp", dict(mcp_headers, **{"Mcp-Name": "rotate"}), True),
):
    headers = dict(headers, **{"Content-Type": "application/json"})
    try:
        if use_session:
            response = request(path, b"{}", headers)
        else:
            response = urllib.request.urlopen(urllib.request.Request(base + path, data=b"{}", headers=headers), context=context)
    except urllib.error.HTTPError as error:
        response = error
    check(scenario, "session" if use_session else "Bearer user", {"native-missing-csrf": 403, "native-mixed-credentials": 400, "native-legacy-bearer": 401, "native-mcp-session": 401}[scenario], response.status)
    response.close()

removed_policy = grant_policy.replace("p, role:rekey-delegate, rotation:dev:prod, rotate, allow\n", "")
replace_policy(removed_policy)
remaining_pairs = {"stage": ["archive"], "archive": []}
for transport in transports:
    status, payload = lane_call(transport, "list_profiles")
    check("native-owner-removal", transport, True, status == 200 and payload == {"profiles": expected_profiles(remaining_pairs)})
    status, _ = lane_call(transport, "rotate", {"sourceProfileId": "dev", "destinationProfileId": "prod", "vaultText": inputs["dev"]})
    check("native-fresh-removal-denial", transport, 403, status)
    status, _ = lane_call(transport, "rotate", {"sourceProfileId": "stage", "destinationProfileId": "archive", "vaultText": inputs["stage"]})
    check("native-removal-unrelated-lane-preserved", transport, 200, status)
replace_policy(grant_policy + "p, role:rekey-delegate, rotation:dev:missing, rotate, deny\n")
for transport in transports:
    status, _ = lane_call(transport, "list_profiles")
    check("native-invalid-policy-unavailable", transport, 503, status)
    status, _ = lane_call(transport, "rotate", {"sourceProfileId": "dev", "destinationProfileId": "prod", "vaultText": inputs["dev"]})
    check("native-invalid-policy-submission", transport, 503, status)
policy_file.unlink()
for transport in transports:
    status, _ = lane_call(transport, "list_profiles")
    check("native-missing-policy-unavailable", transport, 503, status)
    status, _ = lane_call(transport, "rotate", {"sourceProfileId": "dev", "destinationProfileId": "prod", "vaultText": inputs["dev"]})
    check("native-missing-policy-submission", transport, 503, status)
policy_file.write_text(grant_policy)
policy_file.chmod(0o600)
# A complete old-format policy is valid in the new binary, but has no rotate grant.
old_policy = "\n".join(row for row in grant_policy.splitlines() if ", rotate," not in row) + "\n"
replace_policy(old_policy)
try:
    bearer_request("/api/v1/rotations", owner, json.dumps({"sourceProfileId": "dev", "destinationProfileId": "prod", "vaultText": inputs["dev"]}).encode(), {"Content-Type": "application/json"})
except urllib.error.HTTPError as error:
    check("native-new-binary-old-policy-rotation", "Bearer owner", 403, error.code)
else:
    check("native-new-binary-old-policy-rotation", "Bearer owner", 403, 200)
check("native-new-binary-old-policy-direct", "Bearer owner", True, bool(json_response(bearer_request("/api/v1/profiles/dev/encrypt", owner, json.dumps({"plaintext": "synthetic upgrade input"}).encode(), {"Content-Type": "application/json"}))["vaultText"]))
replace_policy(grant_policy)
for transport in transports:
    status, payload = lane_call(transport, "list_profiles")
    check("native-valid-policy-recovery", transport, True, status == 200 and payload == {"profiles": expected_profiles(expected_pairs)})
    status, _ = lane_call(transport, "rotate", {"sourceProfileId": "dev", "destinationProfileId": "prod", "vaultText": inputs["dev"]})
    check("native-valid-policy-submission", transport, 200, status)
# Private, disposable context for the concrete Chrome and baseline acceptance probes.
fixture_context = {"base": base, "username": "integration-delegate", "password": delegate_password, "inputVaultText": inputs["dev"], "ownerToken": owner, "expectedPlaintext": "synthetic delegated acceptance", "grantPolicy": grant_policy, "removedPolicy": removed_policy, "oldPolicy": old_policy, "policyFile": str(policy_file), "serverPID": int(os.environ["SERVER_PID"]), "identity": identity}
fixture_context["serverOptions"] = {"AUTH_MODE": "native", "CSRF_SECRET": os.environ["CSRF_SECRET"], "OIDC_ISSUER_URL": "https://localhost:18081/realms/vaultsmith", "OIDC_CA_FILE": str(private / "idp-root.crt"), "OIDC_CLIENT_ID": "vaultsmith-integration", "OIDC_CLIENT_SECRET": oidc_client_secret, "OIDC_REDIRECT_URL": base + "/auth/callback", "PUBLIC_BASE_URL": base, "REDIS_ADDR": "127.0.0.1:16379", "REDIS_KEY_PREFIX": "vaultsmith:integration:", "AUTHZ_POLICY_FILE": str(policy_file), "COOKIE_SECURE": "true", "MCP_ENABLED": "true", "PROOFS_ENABLED": "true", "PROOFS_KEYRING_FILE": str(private / "keyring.json"), "VAULT_PROFILES_JSON": json.dumps([{"id": name, "label": labels[name], "passwordEnv": "VAULT_PASSWORD_" + name.upper()} for name in labels])}
for name in labels:
    fixture_context["serverOptions"]["VAULT_PASSWORD_" + name.upper()] = os.environ["VAULT_PASSWORD_" + name.upper()]
(private / "acceptance-context.json").write_text(json.dumps(fixture_context))
(private / "acceptance-context.json").chmod(0o600)
with open(server_log, encoding="utf-8") as captured:
    safe_log = captured.read()
check("native-delegate-log-safety", "server", True, all(material not in safe_log for material in (lane_user, lane_machine, delegate_password, inputs["dev"], inputs["stage"], "synthetic delegated acceptance")))
logout(lane_session)

print("native integration: ok (session, delegated-user bearer attestation, client-credentials attestation, scopes, groups, MCP, edge, body/log safety)")
PY

if (( INTERACTIVE )); then
  "${compose[@]}" cp edge:/data/caddy/pki/authorities/local/root.crt "$TMP_DIR/edge-root.crt" >/dev/null
  cat <<INFO

Interactive Vaultsmith test environment is running.

Open:     $BASE_URL/
Login:              integration-user
Password:           $TEST_USER_PASSWORD
No-permission user:  integration-denied
No-permission pass:  $DENIED_USER_PASSWORD
Profiles:           dev, prod

Suggested browser flow:
  1. Open the URL and accept/trust the disposable local TLS certificates if prompted.
  2. Sign in with the credentials above.
  3. Verify both Development and Production are listed.
  4. Encrypt a harmless value such as: interactive-test
  5. Switch to Decrypt, paste the result, and verify the plaintext.
  6. Switch to Rotate, select Development -> Production, and verify the result.
  7. Sign out, sign in as integration-denied, and verify the session is authenticated but no profiles are available.
  8. Attempt an operation as integration-denied and verify it is rejected, then sign out.
  9. Sign back in as integration-user and verify access is restored.

Certificate files (optional trust-installation inputs):
  IdP edge:       $TMP_DIR/idp-root.crt
  Vaultsmith edge: $TMP_DIR/edge-root.crt

Server log: $TMP_DIR/server.log
Press Ctrl-C in this terminal to stop the server and remove the disposable stack.

INFO
  set +e
  wait "$SERVER_PID"
  status=$?
  set -e
  exit "$status"
fi
