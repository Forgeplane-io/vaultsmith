#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/integration/docker-compose.yml"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/vaultsmith-native-integration.XXXXXX")"
PROJECT="vaultsmith-native-integration-$$"
SERVER_PID=""
INTERACTIVE=0

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
    docker compose --project-name "$PROJECT" --env-file "$TMP_DIR/.env" -f "$COMPOSE_FILE" down --volumes --remove-orphans >/dev/null 2>&1 || true
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
CSRF_SECRET="$(random_secret)"
VAULT_PASSWORD_DEV="$(random_secret)"
VAULT_PASSWORD_PROD="$(random_secret)"

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

compose=(docker compose --project-name "$PROJECT" --env-file "$TMP_DIR/.env" -f "$COMPOSE_FILE")
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
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" cp idp-edge:/data/caddy/pki/authorities/local/root.crt "$TMP_DIR/idp-root.crt" >/dev/null

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

for scope in vaultsmith.profile.read vaultsmith.encrypt vaultsmith.decrypt vaultsmith.rotate vaultsmith.attestation.verify; do
  scope_id="$(kc create client-scopes -r vaultsmith -i -b "{\"name\":\"$scope\",\"protocol\":\"openid-connect\",\"attributes\":{\"include.in.token.scope\":\"true\",\"display.on.consent.screen\":\"false\"}}")"
  kc update "clients/$CLIENT_ID/optional-client-scopes/$scope_id" -r vaultsmith >/dev/null
  kc update "clients/$MACHINE_CLIENT_ID/optional-client-scopes/$scope_id" -r vaultsmith >/dev/null
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

SERVICE_ACCOUNT_ID="$(kc get "clients/$MACHINE_CLIENT_ID/service-account-user" -r vaultsmith --fields id --format csv --noquotes)"
kc update "users/$SERVICE_ACCOUNT_ID/groups/$GROUP_ID" -r vaultsmith >/dev/null

if (( INTERACTIVE )); then
  cat > "$TMP_DIR/policy.csv" <<'POLICY'
g, group:vaultsmith-operators, role:operator
p, role:operator, profiles, profiles:list, allow
p, role:operator, profile:dev, encrypt, allow
p, role:operator, profile:dev, decrypt, allow
p, role:operator, profile:prod, encrypt, allow
p, role:operator, profile:prod, decrypt, allow
POLICY
  PROFILES_JSON='[{"id":"dev","label":"Development","passwordEnv":"VAULT_PASSWORD_DEV"},{"id":"prod","label":"Production","passwordEnv":"VAULT_PASSWORD_PROD"}]'
else
  cat > "$TMP_DIR/policy.csv" <<'POLICY'
g, group:vaultsmith-operators, role:operator
p, role:operator, profiles, profiles:list, allow
p, role:operator, profile:dev, encrypt, allow
p, role:operator, profile:dev, decrypt, allow
p, role:operator, profile:prod, encrypt, allow
POLICY
  PROFILES_JSON='[{"id":"dev","label":"Development","passwordEnv":"VAULT_PASSWORD_DEV"},{"id":"prod","label":"Production","passwordEnv":"VAULT_PASSWORD_PROD"}]'
fi

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
  HTTP_ADDR=:18080 \
  "$TMP_DIR/vaultsmith" >"$TMP_DIR/server.log" 2>&1
) &
SERVER_PID=$!

if ! "${compose[@]}" up -d --wait edge >/dev/null; then
  dump_startup_diagnostics
  exit 1
fi

BASE_URL='https://localhost:18443'
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

TEST_USER_PASSWORD="$TEST_USER_PASSWORD" DENIED_USER_PASSWORD="$DENIED_USER_PASSWORD" OIDC_CLIENT_SECRET="$OIDC_CLIENT_SECRET" MACHINE_CLIENT_SECRET="$MACHINE_CLIENT_SECRET" TMP_DIR="$TMP_DIR" python3 - "$BASE_URL" <<'PY'
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
            "rotateDestination": True,
        },
    },
    {
        "id": "prod",
        "label": "Production",
        "capabilities": {
            "encrypt": True,
            "decrypt": False,
            "rotateSource": False,
            "rotateDestination": True,
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

def verify_attestation(token, rotation):
    body = json.dumps({
        "attestation": rotation["attestation"],
        "inputVaultText": operation["value"],
        "outputVaultText": rotation["vaultText"],
        "expectedBinding": binding,
    }).encode("utf-8")
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

machine_rotate = client_credentials_access_token("vaultsmith.rotate")
machine_rotation = attested_rotation(machine_rotate)
assert machine_rotation.get("attestation") and machine_rotation.get("vaultText"), machine_rotation
machine_verify = client_credentials_access_token("vaultsmith.attestation.verify")
assert verify_attestation(machine_verify, machine_rotation)["valid"] is True

try:
    verify_attestation(machine, delegated_rotation)
except urllib.error.HTTPError as error:
    assert error.code == 403 and "insufficient_scope" in error.headers.get("WWW-Authenticate", ""), error.headers
else:
    raise AssertionError("attestation verification without its scope unexpectedly succeeded")

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
print("native integration: ok (session, delegated-user bearer attestation, client-credentials attestation, scopes, groups, MCP, edge, body/log safety)")
PY
