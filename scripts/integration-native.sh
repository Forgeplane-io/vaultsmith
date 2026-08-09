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
TEST_USER_PASSWORD="$(random_secret)"
DENIED_USER_PASSWORD="$(random_secret)"
CSRF_SECRET="$(random_secret)"
VAULT_PASSWORD_DEV="$(random_secret)"
VAULT_PASSWORD_PROD="$(random_secret)"

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
CLIENT_ID="$(kc create clients -r vaultsmith \
  -s clientId=vaultsmith-integration \
  -s enabled=true \
  -s protocol=openid-connect \
  -s publicClient=false \
  -s secret="$OIDC_CLIENT_SECRET" \
  -s standardFlowEnabled=true \
  -s 'redirectUris=["https://localhost:18443/auth/callback"]' \
  -s 'webOrigins=["https://localhost:18443"]' -i)"
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
kc create "clients/$CLIENT_ID/protocol-mappers/models" -r vaultsmith \
  -b '{"name":"groups","protocol":"openid-connect","protocolMapper":"oidc-group-membership-mapper","config":{"full.path":"false","id.token.claim":"true","access.token.claim":"true","userinfo.token.claim":"true","claim.name":"groups"}}' >/dev/null

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
POLICY
  PROFILES_JSON='[{"id":"dev","label":"Development","passwordEnv":"VAULT_PASSWORD_DEV"}]'
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

TEST_USER_PASSWORD="$TEST_USER_PASSWORD" DENIED_USER_PASSWORD="$DENIED_USER_PASSWORD" python3 - "$BASE_URL" <<'PY'
import html.parser
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

base = sys.argv[1]
user_password = os.environ["TEST_USER_PASSWORD"]
denied_password = os.environ["DENIED_USER_PASSWORD"]

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
assert profiles == [{
    "id": "dev",
    "label": "Development",
    "capabilities": {"encrypt": True, "decrypt": True},
}], profiles

body = json.dumps({"profileId": "dev", "mode": "encrypt", "value": "integration"}).encode("utf-8")
operation = json_response(request("/api/v1/operations", body, {
    "Content-Type": "application/json",
    "Origin": base,
    "Referer": base + "/",
    "X-CSRF-Token": session["csrfToken"],
}))
assert isinstance(operation.get("value"), str) and operation["value"], operation

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
print("native integration: ok (OIDC, Redis session, authorized/no-permission users, Casbin, CSRF, operation, logout)")
PY
