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

render() {
  helm template vaultsmith "$CHART_DIR" "$@"
}

assert_render_fails() {
  local values_file="$1"
  if render -f "$values_file" > "$TMP_DIR/negative.yaml" 2> "$TMP_DIR/negative.err"; then
    fail "expected Helm render to fail for $values_file"
  fi
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
if grep -Fq 'name: CSRF_SECRET' "$TMP_DIR/off-default-render.yaml"; then
  fail 'explicit off render unexpectedly contains a CSRF Secret reference'
fi
if grep -Fq 'fixture-password' "$TMP_DIR/off-default-render.yaml"; then
  fail 'off default render leaked a Secret value'
fi

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
if grep -Fq 'fixture-password' "$TMP_DIR/valid-render.yaml"; then
  fail 'password-like value leaked into rendered manifests'
fi

cat > "$TMP_DIR/native.yaml" <<'VALUES'
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
grep -Fq 'name: CSRF_SECRET' "$TMP_DIR/native-render.yaml" || fail 'native CSRF Secret reference is missing'
grep -Fq 'name: OIDC_CLIENT_SECRET' "$TMP_DIR/native-render.yaml" || fail 'native OIDC Secret reference is missing'
grep -Fq 'name: OIDC_CA_FILE' "$TMP_DIR/native-render.yaml" || fail 'native OIDC CA env is missing'
grep -Fq 'vaultsmith-oidc-ca' "$TMP_DIR/native-render.yaml" || fail 'native OIDC CA ConfigMap reference is missing'
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

cat > "$TMP_DIR/incomplete-native.yaml" <<'VALUES'
auth:
  mode: native
VALUES
assert_render_fails "$TMP_DIR/incomplete-native.yaml"
if render -f "$TMP_DIR/native.yaml" --set auth.session.sameSite=strict > "$TMP_DIR/strict-native.yaml" 2> "$TMP_DIR/strict-native.err"; then
  fail 'native SameSite=Strict render unexpectedly succeeded'
fi

cat > "$TMP_DIR/custom-policy-path.yaml" <<'VALUES'
auth:
  mode: off
  policy:
    file: /tmp/policy.csv
VALUES
assert_render_fails "$TMP_DIR/custom-policy-path.yaml"

cat > "$TMP_DIR/conflicting-policy.yaml" <<'VALUES'
auth:
  mode: off
  policy:
    data: |
      p, role:operator, profiles, profiles:list, allow
    existingConfigMap: managed-policy
VALUES
assert_render_fails "$TMP_DIR/conflicting-policy.yaml"

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
profiles:
  - id: dev
    label: Development
    passwordEnv: VAULT_PASSWORD_DEV
    passwordSecretKey: dev
secret:
  existingSecret: ""
VALUES
assert_render_fails "$TMP_DIR/missing-secret.yaml"

cat > "$TMP_DIR/duplicate-id.yaml" <<'VALUES'
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
assert_render_fails "$TMP_DIR/duplicate-id.yaml"

cat > "$TMP_DIR/duplicate-env.yaml" <<'VALUES'
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
assert_render_fails "$TMP_DIR/duplicate-env.yaml"

cat > "$TMP_DIR/reserved-env.yaml" <<'VALUES'
profiles:
  - id: dev
    label: Development
    passwordEnv: VAULT_PROFILES_JSON
    passwordSecretKey: dev
secret:
  existingSecret: vaultsmith-passwords
VALUES
assert_render_fails "$TMP_DIR/reserved-env.yaml"

cat > "$TMP_DIR/broad-policy.yaml" <<'VALUES'
networkPolicy:
  enabled: true
  allowedIngress:
    - {}
VALUES
assert_render_fails "$TMP_DIR/broad-policy.yaml"

cat > "$TMP_DIR/empty-egress.yaml" <<'VALUES'
auth:
  mode: off
networkPolicy:
  enabled: true
  allowedEgress:
    - {}
VALUES
assert_render_fails "$TMP_DIR/empty-egress.yaml"

printf 'chart tests: ok\n'
