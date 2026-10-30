#!/usr/bin/env bash
set -euo pipefail

CHART_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
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
  printf 'chart test failed: %s\n' "$1" >&2
  exit 1
}

assert_contains_block() {
  local rendered_file="$1"
  local expected="$2"
  local message="$3"
  local rendered
  rendered="$(<"$rendered_file")"
  [[ "$rendered" == *"$expected"* ]] || fail "$message"
}

render() {
  helm template "${release_name:-vaultsmith}" "$CHART_DIR" "$@"
}

assert_render_fails() {
  local values_file="$1"
  if render -f "$values_file" > "$TMP_DIR/negative.yaml" 2> "$TMP_DIR/negative.err"; then
    fail "expected Helm render to fail for $values_file"
  fi
}

assert_render_fails_with() {
  local expected="$1"
  shift
  if render "$@" > "$TMP_DIR/negative.yaml" 2> "$TMP_DIR/negative.err"; then
    fail "expected Helm render to fail: $*"
  fi
  grep -Fq "$expected" "$TMP_DIR/negative.err" || fail "missing expected Helm error: $expected"
}

cat > "$TMP_DIR/valid.yaml" <<'VALUES'
auth:
  mode: "off"
profiles:
  - id: dev
    label: Development
    passwordEnv: VAULT_PASSWORD_DEV
    passwordSecretKey: dev
secret:
  existingSecret: vaultsmith-passwords
networkPolicy:
  enabled: true
  allowedIngress:
    - podSelector:
        matchLabels:
          app.kubernetes.io/name: operator-shell
VALUES

if render > "$TMP_DIR/default.yaml" 2> "$TMP_DIR/default.err"; then
  fail 'default chart render unexpectedly selected an authentication mode'
fi
cat > "$TMP_DIR/off-default.yaml" <<'VALUES'
auth:
  mode: "off"
VALUES
helm lint "$CHART_DIR" -f "$TMP_DIR/off-default.yaml" >/dev/null
render -f "$TMP_DIR/off-default.yaml" > "$TMP_DIR/off-default-render.yaml"
if grep -Fq 'kind: NetworkPolicy' "$TMP_DIR/off-default-render.yaml"; then
  fail 'explicit off render unexpectedly contains a NetworkPolicy'
fi
grep -Fq 'automountServiceAccountToken: false' "$TMP_DIR/off-default-render.yaml" || fail 'service token automount is not disabled'
grep -Fq 'containerPort: 8080' "$TMP_DIR/off-default-render.yaml" || fail 'container port is not canonical 8080'
assert_contains_block "$TMP_DIR/off-default-render.yaml" $'- name: MCP_ENABLED\n              value: "false"' 'MCP_ENABLED default false env is missing'
assert_contains_block "$TMP_DIR/off-default-render.yaml" $'- name: PROOFS_ENABLED\n              value: "false"' 'PROOFS_ENABLED default false env is missing'
if grep -Fq 'name: CSRF_SECRET' "$TMP_DIR/off-default-render.yaml"; then
  fail 'explicit off render unexpectedly contains a CSRF Secret reference'
fi
if grep -Fq 'PROOFS_KEYRING_FILE' "$TMP_DIR/off-default-render.yaml" || grep -Fq 'name: attestation-keyring' "$TMP_DIR/off-default-render.yaml"; then
  fail 'proofs-disabled render unexpectedly contains keyring wiring'
fi

cat > "$TMP_DIR/proofs-enabled.yaml" <<'VALUES'
auth:
  mode: "off"
proofs:
  enabled: true
  existingSecret: vaultsmith-attestation
VALUES
helm lint "$CHART_DIR" -f "$TMP_DIR/proofs-enabled.yaml" >/dev/null
render -f "$TMP_DIR/proofs-enabled.yaml" > "$TMP_DIR/proofs-enabled-render.yaml"
assert_contains_block "$TMP_DIR/proofs-enabled-render.yaml" $'- name: PROOFS_ENABLED\n              value: "true"' 'proofs.enabled=true was not wired into PROOFS_ENABLED'
assert_contains_block "$TMP_DIR/proofs-enabled-render.yaml" $'- name: PROOFS_KEYRING_FILE\n              value: /etc/vaultsmith/attestation/keyring.json' 'proofs keyring file path is not canonical'
assert_contains_block "$TMP_DIR/proofs-enabled-render.yaml" $'- name: attestation-keyring\n          secret:\n            secretName: "vaultsmith-attestation"\n            items:\n              - key: keyring.json\n                path: keyring.json\n            optional: false' 'proofs Secret key contract is not wired'
assert_contains_block "$TMP_DIR/proofs-enabled-render.yaml" $'- name: attestation-keyring\n              mountPath: /etc/vaultsmith/attestation\n              readOnly: true' 'proofs keyring is not mounted read-only'
assert_render_fails_with 'proofs.existingSecret is required when proofs.enabled is true' --skip-schema-validation -f "$TMP_DIR/off-default.yaml" --set proofs.enabled=true
render -f "$TMP_DIR/off-default.yaml" --set valkey.enabled=false > "$TMP_DIR/mcp-disabled-render.yaml"
render -f "$TMP_DIR/off-default.yaml" --set valkey.enabled=false --set mcp.enabled=true > "$TMP_DIR/mcp-enabled-render.yaml"
assert_contains_block "$TMP_DIR/mcp-enabled-render.yaml" $'- name: MCP_ENABLED\n              value: "true"' 'mcp.enabled=true was not wired into MCP_ENABLED'
python3 - "$TMP_DIR/mcp-disabled-render.yaml" "$TMP_DIR/mcp-enabled-render.yaml" <<'PY'
import difflib
import re
import sys

pattern = re.compile(r'(?m)(- name: MCP_ENABLED\n\s+value: )"(?:true|false)"')

def normalized(path: str) -> str:
    text = open(path, encoding="utf-8").read()
    normalized_text, replacements = pattern.subn(r'\1"<MCP_ENABLED>"', text)
    if replacements != 1:
        raise SystemExit(f"{path}: expected exactly one MCP_ENABLED environment value, found {replacements}")
    return normalized_text

off = normalized(sys.argv[1])
enabled = normalized(sys.argv[2])
if off != enabled:
    sys.stderr.writelines(difflib.unified_diff(off.splitlines(True), enabled.splitlines(True), fromfile="mcp-off", tofile="mcp-enabled"))
    raise SystemExit("mcp.enabled changed chart output beyond the MCP_ENABLED application environment value")
PY

cat > "$TMP_DIR/deny-all.yaml" <<'VALUES'
auth:
  mode: "off"
networkPolicy:
  enabled: true
  denyAllIngress: true
  allowedIngress: []
VALUES
helm lint "$CHART_DIR" -f "$TMP_DIR/deny-all.yaml" >/dev/null
render -f "$TMP_DIR/deny-all.yaml" > "$TMP_DIR/deny-all-render.yaml"
grep -Fq 'kind: NetworkPolicy' "$TMP_DIR/deny-all-render.yaml" || fail 'explicit deny-all NetworkPolicy is missing'
grep -Fq 'ingress: []' "$TMP_DIR/deny-all-render.yaml" || fail 'explicit deny-all NetworkPolicy is not empty'

cat > "$TMP_DIR/egress-only.yaml" <<'VALUES'
auth:
  mode: "off"
networkPolicy:
  enabled: true
  allowedIngress: []
  denyAllIngress: false
  allowedEgress:
    - ports:
        - protocol: TCP
          port: 443
VALUES
helm lint "$CHART_DIR" -f "$TMP_DIR/egress-only.yaml" >/dev/null
render -f "$TMP_DIR/egress-only.yaml" > "$TMP_DIR/egress-only-render.yaml"
grep -Fq 'kind: NetworkPolicy' "$TMP_DIR/egress-only-render.yaml" || fail 'egress-only NetworkPolicy is missing'
grep -Fq '    - Egress' "$TMP_DIR/egress-only-render.yaml" || fail 'egress-only NetworkPolicy egress type is missing'
if grep -Fq '    - Ingress' "$TMP_DIR/egress-only-render.yaml" || grep -Fq '  ingress:' "$TMP_DIR/egress-only-render.yaml"; then
  fail 'egress-only NetworkPolicy unexpectedly selected an ingress policy'
fi

helm lint "$CHART_DIR" -f "$TMP_DIR/valid.yaml" >/dev/null
render -f "$TMP_DIR/valid.yaml" > "$TMP_DIR/valid-render.yaml"
grep -Fq 'VAULT_PROFILES_JSON' "$TMP_DIR/valid-render.yaml" || fail 'profile config env is missing'
grep -Fq 'vaultsmith-passwords' "$TMP_DIR/valid-render.yaml" || fail 'existing Secret reference is missing'
grep -Fq 'key: "dev"' "$TMP_DIR/valid-render.yaml" || fail 'Secret key reference is missing'
grep -Fq 'app.kubernetes.io/name: operator-shell' "$TMP_DIR/valid-render.yaml" || fail 'explicit NetworkPolicy selector is missing'

cat > "$TMP_DIR/native.yaml" <<'VALUES'
auth:
  mode: native
  csrf:
    existingSecret: vaultsmith-auth
    key: csrf-secret
  oidc:
    issuerURL: https://idp.example.test/realms/vaultsmith
    clientIDSecret:
      existingSecret: vaultsmith-auth
      key: oidc-client-id
    clientSecret:
      existingSecret: vaultsmith-auth
      key: oidc-client-secret
    redirectURL: https://vault.example.test/auth/callback
    publicBaseURL: https://vault.example.test
    ca:
      existingConfigMap: vaultsmith-oidc-ca
      key: ca.crt
  redis:
    address: redis.example.test:6379
    keyPrefix: "vaultsmith:"
  policy:
    key: custom.csv
    data: |-
      p, role:operator, profiles, profiles:list, allow
      p, role:operator, profile:dev, encrypt, allow
valkey:
  enabled: false
networkPolicy:
  enabled: true
  allowedIngress:
    - podSelector:
        matchLabels:
          app.kubernetes.io/name: operator-shell
  allowedEgress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
    - to:
        - ipBlock:
            cidr: 10.0.0.0/8
      ports:
        - protocol: TCP
          port: 443
        - protocol: TCP
          port: 6379
profiles:
  - id: dev
    label: Development
    passwordEnv: VAULT_PASSWORD_DEV
    passwordSecretKey: dev
secret:
  existingSecret: vaultsmith-passwords
VALUES
helm lint "$CHART_DIR" -f "$TMP_DIR/native.yaml" >/dev/null
render -f "$TMP_DIR/native.yaml" > "$TMP_DIR/native-render.yaml"
grep -Fq 'name: AUTH_MODE' "$TMP_DIR/native-render.yaml" || fail 'native auth mode env is missing'
assert_contains_block "$TMP_DIR/native-render.yaml" $'- name: CSRF_SECRET\n              valueFrom:\n                secretKeyRef:\n                  name: "vaultsmith-auth"\n                  key: "csrf-secret"\n                  optional: false' 'native CSRF Secret name/key relationship is wrong'
assert_contains_block "$TMP_DIR/native-render.yaml" $'- name: OIDC_CLIENT_SECRET\n              valueFrom:\n                secretKeyRef:\n                  name: "vaultsmith-auth"\n                  key: "oidc-client-secret"\n                  optional: false' 'native OIDC Secret name/key relationship is wrong'
assert_contains_block "$TMP_DIR/native-render.yaml" $'- name: OIDC_CLIENT_ID\n              valueFrom:\n                secretKeyRef:\n                  name: "vaultsmith-auth"\n                  key: "oidc-client-id"\n                  optional: false' 'native OIDC client ID Secret name/key relationship is wrong'
assert_contains_block "$TMP_DIR/native-render.yaml" $'- name: OIDC_CA_FILE\n              value: /etc/vaultsmith/oidc-ca/ca.crt' 'native OIDC CA env path is wrong'
assert_contains_block "$TMP_DIR/native-render.yaml" $'- name: oidc-ca\n          configMap:\n            name: "vaultsmith-oidc-ca"\n            items:\n              - key: "ca.crt"\n                path: ca.crt' 'native OIDC CA ConfigMap/key relationship is wrong'
assert_contains_block "$TMP_DIR/native-render.yaml" $'- name: oidc-ca\n              mountPath: /etc/vaultsmith/oidc-ca\n              readOnly: true' 'native OIDC CA mount relationship is wrong'
grep -Fq 'name: REDIS_ADDR' "$TMP_DIR/native-render.yaml" || fail 'native Redis address env is missing'
grep -Fq 'name: REDIS_REFRESH_LOCK_TTL' "$TMP_DIR/native-render.yaml" || fail 'native refresh lock TTL env is missing'
grep -Fq 'name: REDIS_REFRESH_LOCK_WAIT' "$TMP_DIR/native-render.yaml" || fail 'native refresh lock wait env is missing'
grep -Fq 'name: REDIS_REFRESH_LOCK_RETRY' "$TMP_DIR/native-render.yaml" || fail 'native refresh lock retry env is missing'
grep -Fq 'name: REDIS_PROVIDER_TIMEOUT' "$TMP_DIR/native-render.yaml" || fail 'native provider timeout env is missing'
grep -Fq 'key: "custom.csv"' "$TMP_DIR/native-render.yaml" || fail 'custom inline policy key is missing'
grep -Eq 'value: "?/etc/vaultsmith/policy/policy\.csv"?$' "$TMP_DIR/native-render.yaml" || fail 'policy file path is not canonical'
grep -Fq 'path: policy.csv' "$TMP_DIR/native-render.yaml" || fail 'policy mount path is missing'
grep -Fq '    - Egress' "$TMP_DIR/native-render.yaml" || fail 'native NetworkPolicy egress type is missing'
grep -Fq 'port: 53' "$TMP_DIR/native-render.yaml" || fail 'native cluster DNS egress port is missing'
grep -Fq 'port: 6379' "$TMP_DIR/native-render.yaml" || fail 'native Redis egress port is missing'

cat > "$TMP_DIR/bundled-native.yaml" <<'VALUES'
auth:
  mode: native
  csrf:
    existingSecret: vaultsmith-auth
    key: csrf-secret
  oidc:
    issuerURL: https://idp.example.test/realms/vaultsmith
    clientID: vaultsmith
    clientSecret:
      existingSecret: vaultsmith-auth
      key: oidc-client-secret
    redirectURL: https://vault.example.test/auth/callback
    publicBaseURL: https://vault.example.test
  policy:
    key: policy.csv
    data: |-
      p, role:operator, profiles, profiles:list, allow
      p, role:operator, profile:dev, encrypt, allow
networkPolicy:
  enabled: true
  allowedEgress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
    - to:
        - ipBlock:
            cidr: 10.0.0.0/8
      ports:
        - protocol: TCP
          port: 443
VALUES
helm lint "$CHART_DIR" -f "$TMP_DIR/bundled-native.yaml" >/dev/null
render -f "$TMP_DIR/bundled-native.yaml" > "$TMP_DIR/bundled-native-render.yaml"
grep -Fq 'name: vaultsmith-valkey-auth' "$TMP_DIR/bundled-native-render.yaml" || fail 'bundled Valkey auth Secret is missing'
assert_contains_block "$TMP_DIR/bundled-native-render.yaml" $'- name: REDIS_ADDR\n              value: "vaultsmith-valkey:6379"' 'bundled Valkey address was not wired into Vaultsmith'
assert_contains_block "$TMP_DIR/bundled-native-render.yaml" $'- name: REDIS_USERNAME\n              value: "default"' 'bundled Valkey username was not wired into Vaultsmith'
assert_contains_block "$TMP_DIR/bundled-native-render.yaml" $'- name: REDIS_PASSWORD\n              valueFrom:\n                secretKeyRef:\n                  name: "vaultsmith-valkey-auth"\n                  key: "default"\n                  optional: false' 'bundled Valkey password Secret was not wired into Vaultsmith'
assert_contains_block "$TMP_DIR/bundled-native-render.yaml" $'strategy:\n    type: Recreate' 'persistent bundled Valkey does not use Recreate strategy'
assert_contains_block "$TMP_DIR/bundled-native-render.yaml" $'app.kubernetes.io/name: "valkey"\n              app.kubernetes.io/instance: "vaultsmith"\n      ports:\n        - protocol: TCP\n          port: 6379' 'bundled Valkey NetworkPolicy egress is missing'

stable_secret_args=(
  --set valkey.auth.usersExistingSecret=vaultsmith-valkey-stable
)
render -f "$TMP_DIR/bundled-native.yaml" "${stable_secret_args[@]}" > "$TMP_DIR/stable-valkey-render.yaml"
render -f "$TMP_DIR/bundled-native.yaml" "${stable_secret_args[@]}" > "$TMP_DIR/stable-valkey-render-again.yaml"
cmp -s "$TMP_DIR/stable-valkey-render.yaml" "$TMP_DIR/stable-valkey-render-again.yaml" || fail 'externally managed Valkey Secret render is not deterministic'
assert_contains_block "$TMP_DIR/stable-valkey-render.yaml" $'- name: REDIS_PASSWORD\n              valueFrom:\n                secretKeyRef:\n                  name: "vaultsmith-valkey-stable"\n                  key: "default"\n                  optional: false' 'Vaultsmith does not use the externally managed Valkey Secret'
assert_contains_block "$TMP_DIR/stable-valkey-render.yaml" $'- name: valkey-users-secret\n          secret:\n            secretName: vaultsmith-valkey-stable' 'bundled Valkey does not use the externally managed Secret'
if grep -Fq '# Source: vaultsmith/templates/valkey-secret.yaml' "$TMP_DIR/stable-valkey-render.yaml"; then
  fail 'chart unexpectedly creates a bundled Valkey Secret when one is externally managed'
fi
render -f "$TMP_DIR/off-default.yaml" "${stable_secret_args[@]}" > "$TMP_DIR/stable-valkey-off-render.yaml"
assert_contains_block "$TMP_DIR/stable-valkey-off-render.yaml" $'- name: valkey-users-secret\n          secret:\n            secretName: vaultsmith-valkey-stable' 'off mode does not use the externally managed Valkey Secret'
if grep -Fq '# Source: vaultsmith/templates/valkey-secret.yaml' "$TMP_DIR/stable-valkey-off-render.yaml"; then
  fail 'off mode unexpectedly creates a bundled Valkey Secret when one is externally managed'
fi
for schema in enabled skipped; do
  schema_arg=''
  if [[ "$schema" == skipped ]]; then schema_arg=--skip-schema-validation; fi
  assert_render_fails_with 'valkey.auth.usersExistingSecret must be a literal Kubernetes Secret name' -f "$TMP_DIR/bundled-native.yaml" ${schema_arg:+'--skip-schema-validation'} --set-string 'valkey.auth.usersExistingSecret=\{\{ .Release.Name \}\}'
  assert_render_fails_with 'valkey.auth.usersExistingSecret must be a literal Kubernetes Secret name' -f "$TMP_DIR/off-default.yaml" ${schema_arg:+'--skip-schema-validation'} --set valkey.auth.usersExistingSecret=Invalid_Name
  for scalar_name in true null 123 on; do
    assert_render_fails_with 'valkey.auth.usersExistingSecret must render as a YAML string' -f "$TMP_DIR/bundled-native.yaml" ${schema_arg:+'--skip-schema-validation'} --set-string "valkey.auth.usersExistingSecret=$scalar_name"
  done
  assert_render_fails_with 'auth.redis.password.existingSecret must be empty when the bundled Valkey chart is enabled' -f "$TMP_DIR/bundled-native.yaml" ${schema_arg:+'--skip-schema-validation'} "${stable_secret_args[@]}" --set auth.redis.password.existingSecret=other
done

render -f "$TMP_DIR/native.yaml" --set auth.redis.password.existingSecret=external-redis --set auth.redis.password.key=external-password > "$TMP_DIR/external-redis-secret-render.yaml"
assert_contains_block "$TMP_DIR/external-redis-secret-render.yaml" $'- name: REDIS_PASSWORD\n              valueFrom:\n                secretKeyRef:\n                  name: "external-redis"\n                  key: "external-password"\n                  optional: false' 'external Redis Secret reference changed'

fullname_collision_error='set fullnameOverride to a distinct name'
release_name=vaultsmith-valkey assert_render_fails_with "$fullname_collision_error" -f "$TMP_DIR/bundled-native.yaml"
release_name=vaultsmith-valkey assert_render_fails_with "$fullname_collision_error" -f "$TMP_DIR/off-default.yaml"
assert_render_fails_with "$fullname_collision_error" -f "$TMP_DIR/bundled-native.yaml" --set valkey.fullnameOverride=vaultsmith
assert_render_fails_with "$fullname_collision_error" -f "$TMP_DIR/bundled-native.yaml" --set nameOverride=valkey
# Distinct override inputs still collide after the fullname helpers' DNS-label truncation.
long_fullname="$(printf 'x%.0s' {1..63})"
assert_render_fails_with "$fullname_collision_error" -f "$TMP_DIR/bundled-native.yaml" --set fullnameOverride="${long_fullname}-app" --set valkey.fullnameOverride="${long_fullname}-cache"

release_name=vaultsmith-valkey render -f "$TMP_DIR/bundled-native.yaml" --set fullnameOverride=vaultsmith-app > "$TMP_DIR/distinct-fullname-render.yaml"
for kind in Deployment Service ServiceAccount; do
  for rendered in bundled-native distinct-fullname; do
    [[ "$(grep -c "^kind: $kind$" "$TMP_DIR/$rendered-render.yaml")" == 2 ]] || fail "$rendered render must contain two distinct $kind resources"
    assert_contains_block "$TMP_DIR/$rendered-render.yaml" "$(printf 'kind: %s\nmetadata:\n  name: vaultsmith-valkey\n  labels:' "$kind")" "$rendered render has the wrong Valkey $kind name"
  done
  assert_contains_block "$TMP_DIR/bundled-native-render.yaml" "$(printf 'kind: %s\nmetadata:\n  name: vaultsmith\n  labels:' "$kind")" "normal render has the wrong Vaultsmith $kind name"
  assert_contains_block "$TMP_DIR/distinct-fullname-render.yaml" "$(printf 'kind: %s\nmetadata:\n  name: vaultsmith-app\n  labels:' "$kind")" "distinct-fullname render has the wrong Vaultsmith $kind name"
done
assert_contains_block "$TMP_DIR/distinct-fullname-render.yaml" $'- name: REDIS_ADDR\n              value: "vaultsmith-valkey:6379"' 'distinct parent fullname changed the bundled Valkey address'
assert_contains_block "$TMP_DIR/distinct-fullname-render.yaml" $'kind: Secret\nmetadata:\n  name: vaultsmith-valkey-auth' 'distinct parent fullname changed the bundled Valkey auth Secret name'
assert_contains_block "$TMP_DIR/distinct-fullname-render.yaml" $'- name: REDIS_PASSWORD\n              valueFrom:\n                secretKeyRef:\n                  name: "vaultsmith-valkey-auth"\n                  key: "default"\n                  optional: false' 'distinct parent fullname changed the Vaultsmith password Secret reference'
assert_contains_block "$TMP_DIR/distinct-fullname-render.yaml" $'- name: valkey-users-secret\n          secret:\n            secretName: vaultsmith-valkey-auth' 'distinct parent fullname changed the Valkey password Secret reference'

release_name=vaultsmith-valkey render -f "$TMP_DIR/native.yaml" > "$TMP_DIR/colliding-name-external-render.yaml"
assert_contains_block "$TMP_DIR/colliding-name-external-render.yaml" $'kind: Deployment\nmetadata:\n  name: vaultsmith-valkey' 'Valkey-disabled render rejected the otherwise colliding release name'
if grep -Fq '# Source: vaultsmith/charts/valkey/' "$TMP_DIR/colliding-name-external-render.yaml"; then
  fail 'Valkey-disabled render unexpectedly contains bundled Valkey resources'
fi

external_valkey_error='auth.redis.address must be empty when the bundled Valkey chart is enabled'
assert_render_fails_with "$external_valkey_error" -f "$TMP_DIR/bundled-native.yaml" --set auth.redis.address=redis.example.test:6379

external_address_error='auth.redis.address is required when valkey.enabled is false'
assert_render_fails_with 'auth/redis/address' -f "$TMP_DIR/bundled-native.yaml" --set valkey.enabled=false
assert_render_fails_with "$external_address_error" -f "$TMP_DIR/bundled-native.yaml" --set valkey.enabled=false --skip-schema-validation
assert_render_fails_with 'valkey/auth/enabled' -f "$TMP_DIR/valid.yaml" --set valkey.auth.enabled=false
assert_render_fails_with 'valkey.auth.enabled must remain true when the bundled Valkey chart is enabled' -f "$TMP_DIR/valid.yaml" --set valkey.auth.enabled=false --skip-schema-validation
assert_render_fails_with 'valkey/auth/aclUsers/default/passwordKey' -f "$TMP_DIR/valid.yaml" --set valkey.auth.aclUsers.default.passwordKey=other
assert_render_fails_with 'valkey.auth.aclUsers.default.passwordKey must be default for the bundled Valkey chart' -f "$TMP_DIR/valid.yaml" --set valkey.auth.aclUsers.default.passwordKey=other --skip-schema-validation
assert_render_fails_with 'valkey/auth/aclUsers' -f "$TMP_DIR/valid.yaml" --set valkey.auth.aclUsers.extra.permissions='~* +@read'
assert_render_fails_with 'valkey.auth.aclUsers must contain exactly the managed default user' -f "$TMP_DIR/valid.yaml" --set valkey.auth.aclUsers.extra.permissions='~* +@read' --skip-schema-validation
assert_render_fails_with 'valkey/auth/aclUsers/default' -f "$TMP_DIR/valid.yaml" --set valkey.auth.aclUsers.default.password=inline
assert_render_fails_with 'valkey.auth.aclUsers.default.password must not be set' -f "$TMP_DIR/valid.yaml" --set valkey.auth.aclUsers.default.password=inline --skip-schema-validation
assert_render_fails_with 'valkey/deploymentStrategy' -f "$TMP_DIR/valid.yaml" --set valkey.deploymentStrategy=RollingUpdate
assert_render_fails_with 'valkey.deploymentStrategy must be Recreate for the bundled standalone Valkey chart' -f "$TMP_DIR/valid.yaml" --set valkey.deploymentStrategy=RollingUpdate --skip-schema-validation
assert_render_fails_with 'valkey.deploymentStrategy must be Recreate for the bundled standalone Valkey chart' -f "$TMP_DIR/valid.yaml" --set valkey.deploymentStrategy=RollingUpdate --set valkey.dataStorage.enabled=false --skip-schema-validation
assert_render_fails_with 'valkey/service/port' -f "$TMP_DIR/valid.yaml" --set valkey.service.port=6380

egress_error='networkPolicy.allowedEgress must allow OIDC and Redis egress in native mode, or disable networkPolicy explicitly'
assert_render_fails_with "$egress_error" -f "$TMP_DIR/native.yaml" --set-json 'networkPolicy.allowedEgress=[]'
assert_render_fails_with "$egress_error" -f "$TMP_DIR/native.yaml" --set-json 'networkPolicy.allowedEgress=[]' --skip-schema-validation
assert_render_fails_with "$egress_error" -f "$TMP_DIR/native.yaml" --set-json 'networkPolicy.allowedEgress=[]' --show-only templates/networkpolicy.yaml --skip-schema-validation
assert_render_fails_with 'auth.oidc.clientID and auth.oidc.clientIDSecret.existingSecret are mutually exclusive' -f "$TMP_DIR/bundled-native.yaml" --set auth.oidc.clientIDSecret.existingSecret=vaultsmith-auth --skip-schema-validation

cat > "$TMP_DIR/incomplete-native.yaml" <<'VALUES'
auth:
  mode: native
VALUES
assert_render_fails "$TMP_DIR/incomplete-native.yaml"
if render -f "$TMP_DIR/native.yaml" --set auth.session.sameSite=strict > "$TMP_DIR/strict-native.yaml" 2> "$TMP_DIR/strict-native.err"; then
  fail 'native SameSite=Strict render unexpectedly succeeded'
fi

cat > "$TMP_DIR/conflicting-policy.yaml" <<'VALUES'
auth:
  mode: "off"
  policy:
    data: |
      p, role:operator, profiles, profiles:list, allow
    existingConfigMap: managed-policy
VALUES
assert_render_fails_with 'auth.policy.data and auth.policy.existingConfigMap are mutually exclusive' --skip-schema-validation -f "$TMP_DIR/conflicting-policy.yaml"

checksum_a="$(grep -m1 'checksum/profiles:' "$TMP_DIR/valid-render.yaml")"
cat > "$TMP_DIR/changed.yaml" <<'VALUES'
auth:
  mode: "off"
profiles:
  - id: dev
    label: Production
    passwordEnv: VAULT_PASSWORD_DEV
    passwordSecretKey: dev
secret:
  existingSecret: vaultsmith-passwords
networkPolicy:
  enabled: true
  allowedIngress:
    - podSelector:
        matchLabels:
          app.kubernetes.io/name: operator-shell
VALUES
render -f "$TMP_DIR/changed.yaml" > "$TMP_DIR/changed-render.yaml"
checksum_b="$(grep -m1 'checksum/profiles:' "$TMP_DIR/changed-render.yaml")"
[[ "$checksum_a" != "$checksum_b" ]] || fail 'ConfigMap checksum did not change with profile metadata'

cat > "$TMP_DIR/missing-secret.yaml" <<'VALUES'
auth:
  mode: "off"
profiles:
  - id: dev
    label: Development
    passwordEnv: VAULT_PASSWORD_DEV
    passwordSecretKey: dev
secret:
  existingSecret: ""
VALUES
assert_render_fails_with 'secret.existingSecret is required when profiles are configured' --skip-schema-validation -f "$TMP_DIR/missing-secret.yaml"

cat > "$TMP_DIR/duplicate-id.yaml" <<'VALUES'
auth:
  mode: "off"
profiles:
  - id: dev
    label: Development
    passwordEnv: VAULT_PASSWORD_DEV
    passwordSecretKey: dev
  - id: dev
    label: Duplicate
    passwordEnv: VAULT_PASSWORD_OTHER
    passwordSecretKey: other
secret:
  existingSecret: vaultsmith-passwords
VALUES
assert_render_fails_with 'profiles contains duplicate id "dev"' --skip-schema-validation -f "$TMP_DIR/duplicate-id.yaml"

cat > "$TMP_DIR/duplicate-env.yaml" <<'VALUES'
auth:
  mode: "off"
profiles:
  - id: dev
    label: Development
    passwordEnv: VAULT_PASSWORD_DEV
    passwordSecretKey: dev
  - id: stage
    label: Staging
    passwordEnv: VAULT_PASSWORD_DEV
    passwordSecretKey: stage
secret:
  existingSecret: vaultsmith-passwords
VALUES
assert_render_fails_with 'profiles contains duplicate passwordEnv "VAULT_PASSWORD_DEV"' --skip-schema-validation -f "$TMP_DIR/duplicate-env.yaml"

cat > "$TMP_DIR/reserved-env.yaml" <<'VALUES'
auth:
  mode: "off"
profiles:
  - id: dev
    label: Development
    passwordEnv: VAULT_PROFILES_JSON
    passwordSecretKey: dev
secret:
  existingSecret: vaultsmith-passwords
VALUES
assert_render_fails_with 'profiles passwordEnv "VAULT_PROFILES_JSON" is reserved' --skip-schema-validation -f "$TMP_DIR/reserved-env.yaml"
assert_render_fails_with 'profiles passwordEnv "MCP_ENABLED" is reserved' --skip-schema-validation -f "$TMP_DIR/valid.yaml" --set profiles[0].passwordEnv=MCP_ENABLED
assert_render_fails_with 'profiles passwordEnv "MCPGODEBUG" is reserved' --skip-schema-validation -f "$TMP_DIR/valid.yaml" --set profiles[0].passwordEnv=MCPGODEBUG

cat > "$TMP_DIR/broad-policy.yaml" <<'VALUES'
auth:
  mode: "off"
networkPolicy:
  enabled: true
  allowedIngress:
    - {}
VALUES
assert_render_fails_with 'networkPolicy.allowedIngress rules need namespaceSelector or podSelector' --skip-schema-validation -f "$TMP_DIR/broad-policy.yaml"

cat > "$TMP_DIR/empty-egress.yaml" <<'VALUES'
auth:
  mode: "off"
networkPolicy:
  enabled: true
  allowedEgress:
    - {}
VALUES
assert_render_fails_with 'networkPolicy.allowedEgress rules need to or ports' --skip-schema-validation -f "$TMP_DIR/empty-egress.yaml"

printf 'chart tests: ok\n'
