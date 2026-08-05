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

helm lint "$CHART_DIR" >/dev/null
render > "$TMP_DIR/default.yaml"
if grep -Fq 'kind: NetworkPolicy' "$TMP_DIR/default.yaml"; then
  fail 'default render unexpectedly contains a NetworkPolicy'
fi
grep -Fq 'automountServiceAccountToken: false' "$TMP_DIR/default.yaml" || fail 'service token automount is not disabled'
grep -Fq 'containerPort: 8080' "$TMP_DIR/default.yaml" || fail 'container port is not canonical 8080'
if grep -Fq 'secretKeyRef:' "$TMP_DIR/default.yaml"; then
  fail 'default render unexpectedly contains a Secret reference'
fi

cat > "$TMP_DIR/deny-all.yaml" <<'VALUES'
networkPolicy:
  enabled: true
  denyAllIngress: true
  allowedIngress: []
VALUES
helm lint "$CHART_DIR" -f "$TMP_DIR/deny-all.yaml" >/dev/null
render -f "$TMP_DIR/deny-all.yaml" > "$TMP_DIR/deny-all-render.yaml"
grep -Fq 'kind: NetworkPolicy' "$TMP_DIR/deny-all-render.yaml" || fail 'explicit deny-all NetworkPolicy is missing'
grep -Fq 'ingress: []' "$TMP_DIR/deny-all-render.yaml" || fail 'explicit deny-all NetworkPolicy is not empty'

helm lint "$CHART_DIR" -f "$TMP_DIR/valid.yaml" >/dev/null
render -f "$TMP_DIR/valid.yaml" > "$TMP_DIR/valid-render.yaml"
grep -Fq 'VAULT_PROFILES_JSON' "$TMP_DIR/valid-render.yaml" || fail 'profile config env is missing'
grep -Fq 'vaultsmith-passwords' "$TMP_DIR/valid-render.yaml" || fail 'existing Secret reference is missing'
grep -Fq 'key: "dev"' "$TMP_DIR/valid-render.yaml" || fail 'Secret key reference is missing'
grep -Fq 'app.kubernetes.io/name: operator-shell' "$TMP_DIR/valid-render.yaml" || fail 'explicit NetworkPolicy selector is missing'
if grep -Fq 'fixture-password' "$TMP_DIR/valid-render.yaml"; then
  fail 'password-like value leaked into rendered manifests'
fi

checksum_a="$(grep -m1 'checksum/profiles:' "$TMP_DIR/valid-render.yaml")"
cat > "$TMP_DIR/changed.yaml" <<'VALUES'
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

cat > "$TMP_DIR/conflicting-policy.yaml" <<'VALUES'
networkPolicy:
  enabled: true
  denyAllIngress: true
  allowedIngress:
    - podSelector:
        matchLabels:
          app.kubernetes.io/name: operator-shell
VALUES
assert_render_fails "$TMP_DIR/conflicting-policy.yaml"

printf 'chart tests: ok\n'
