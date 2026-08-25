# Deploy Vaultsmith

Vaultsmith is an HTTP service for Ansible Vault values. Use `auth.mode: native` for an exposed deployment. `auth.mode: "off"` disables authentication and CSRF protection and is for private local development only.

This guide covers the application, Helm chart, and required edge boundary. It does not provide a portable Gateway API manifest: authentication, TLS, rate limits, header policy, and source restrictions depend on the selected edge implementation.

## Before you deploy

Prepare these resources outside the chart:

- An OIDC client with exactly one redirect URI: `OIDC_REDIRECT_URL`.
- Secrets containing the CSRF secret, OIDC client secret, Redis password when used, profile passwords, and (when proofs are enabled) the versioned attestation keyring under the fixed `keyring.json` key.
- Redis for login transactions, sessions, refresh state, and refresh locks.
- A Casbin policy, supplied inline or through an external ConfigMap.
- An edge gateway or reverse proxy that terminates TLS and applies the deployment's access policy.

Do not put passwords, tokens, private keys, CSRF values, or credential-bearing connection strings in Git. Use synthetic values in examples and untracked deployment files.

## Native authentication

Native mode requires:

- `AUTH_MODE=native`.
- `CSRF_SECRET` with at least 32 bytes.
- `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URL`, and `PUBLIC_BASE_URL`.
- `REDIS_ADDR` and a non-empty `REDIS_KEY_PREFIX` that ends with `:`.
- `AUTHZ_POLICY_FILE` pointing to a valid Casbin CSV policy.
- `COOKIE_SECURE=true` and `COOKIE_SAME_SITE=lax` or `none`.

`OIDC_REDIRECT_URL` must use the `PUBLIC_BASE_URL` origin. The issuer URL and redirect URL must be HTTPS and must not contain a query or fragment. Native mode does not fall back to unauthenticated operation when OIDC, Redis, or policy loading fails.

Vaultsmith uses the verified OIDC `(iss, sub)` pair as identity. The default groups claim is `groups`; set `OIDC_GROUPS_CLAIM` only when the provider uses another valid claim path. Sessions are opaque and stored in Redis. Mutating requests use the CSRF token returned by `GET /api/v1/session`.

If the issuer uses a private CA, mount a PEM bundle and set `OIDC_CA_FILE`. Do not disable TLS verification.

Machine clients use RFC 9068 JWT Bearer access tokens issued by the same configured issuer. The required audience is the `PUBLIC_BASE_URL` HTTPS origin, not the browser client ID. Bearer requests do not load or write Redis sessions, do not receive CSRF cookies, and require exact operation scopes: `vaultsmith.profile.read`, `vaultsmith.encrypt`, `vaultsmith.decrypt`, `vaultsmith.rotate`, and (for standalone verification) `vaultsmith.attestation.verify`.

## Helm chart

The chart creates `ClusterIP` Services for Vaultsmith and the bundled official Valkey chart. Valkey is enabled by default, uses a generated password Secret, and does not require a separately provisioned Redis service. The bundled chart requests a 1 GiB PVC by default; set `valkey.dataStorage.className` for a specific storage class or disable it for ephemeral test deployments. The bundled standalone Valkey uses a `Recreate` rollout to avoid concurrent pods sharing a `ReadWriteOnce` claim; the strategy remains fixed for every standalone backing mode. The chart does not create the OIDC, CSRF, or profile-password Secrets. Ingress and NetworkPolicy are disabled by default.

The only MCP chart value is `mcp.enabled`, which defaults to `false` and maps to `MCP_ENABLED`. Proofs expose only `proofs.enabled` and `proofs.existingSecret`; both default to disabled/empty. When enabled, the chart requires a Secret containing the fixed `keyring.json` key and mounts it read-only at `/etc/vaultsmith/attestation/keyring.json`. The chart does not parse keyring internals or expose signing, issuer, reload, KMS, policy, or verification values. `MCPGODEBUG` must be unset or empty; any non-empty value fails startup.

### Published chart

The public OCI chart command below uses the release-managed chart version:

```sh
VAULTSMITH_CHART_VERSION=0.7.1 # x-release-please-version
helm upgrade --install vaultsmith \
  oci://ghcr.io/forgeplane-io/charts/vaultsmith \
  --version "$VAULTSMITH_CHART_VERSION" \
  --namespace vaultsmith \
  --create-namespace \
  -f /path/to/vaultsmith-values.yaml
```

For a source checkout, use `deploy/helm/vaultsmith` instead of the OCI reference and omit `--version`; the source chart version is maintained separately.

### Minimal native values

Use an untracked file. The Secret names and addresses below are examples.

```yaml
auth:
  mode: native
  csrf:
    existingSecret: vaultsmith-auth
    key: csrf-secret
  oidc:
    issuerURL: https://id.example.test/realms/vaultsmith
    clientID: vaultsmith
    clientSecret:
      existingSecret: vaultsmith-auth
      key: oidc-client-secret
    redirectURL: https://vault.example.test/auth/callback
    publicBaseURL: https://vault.example.test
  redis:
    keyPrefix: "vaultsmith:"
  policy:
    existingConfigMap: vaultsmith-policy
    key: policy.csv

profiles:
  - id: dev
    label: Development
    passwordEnv: VAULT_PASSWORD_DEV
    passwordSecretKey: dev

secret:
  existingSecret: vaultsmith-passwords
```

Create the referenced application Secret and policy ConfigMap before installing. Each `passwordSecretKey` must exist in `secret.existingSecret`. The bundled Valkey service and password Secret are created by the chart. Set `valkey.enabled: false` and configure `auth.redis.address` and its credentials when using an external Redis-compatible service.

### Proof values and keyring Secret

Proofs remain disabled unless explicitly enabled:

```yaml
proofs:
  enabled: false
  existingSecret: ""
```

For an enabled deployment, create the Secret outside Helm with the application-owned versioned keyring under the fixed `keyring.json` data key, then add only:

```yaml
proofs:
  enabled: true
  existingSecret: vaultsmith-attestation
```

The keyring is mounted read-only at `/etc/vaultsmith/attestation/keyring.json`. `PUBLIC_BASE_URL` remains the issuer source. Do not put private key material in Helm values, environment variables, a ConfigMap, a container argument, or Git. See [`attestations.md`](attestations.md) for the keyring schema, active-to-retired rotation, revocation, backup, reload, and rollback procedure.

When proofs are disabled, the Secret is not required, no signing-key startup dependency is added, and normal encrypt, decrypt, and rotate behavior remains available. Attestation-specific routes retain their stable feature-unavailable behavior.

### Casbin policy

Provide exactly one policy source: `auth.policy.data` or `auth.policy.existingConfigMap`. Helm rejects both together. The policy file must map the verified OIDC groups claim to roles and grant the operations needed for the configured profile IDs.

Minimal policy:

```csv
g, group:vaultsmith-operators, role:operator
p, role:operator, profiles, profiles:list, allow
p, role:operator, profile:dev, encrypt, allow
p, role:operator, profile:dev, decrypt, allow
```

Use an external ConfigMap when policy changes should be managed separately from Helm. Keep credentials in Secrets, not in the policy ConfigMap.

### NetworkPolicy

NetworkPolicy is opt-in. It controls pod reachability; it does not authenticate HTTP callers or remove headers.

For native mode, if `networkPolicy.enabled` is true, provide `networkPolicy.allowedEgress` rules for:

- Cluster DNS over UDP and TCP port 53.
- The OIDC issuer over TCP port 443.
- Redis on its configured port, commonly TCP 6379. The bundled Valkey egress rule is added automatically; provide this rule when `valkey.enabled: false`.

Proofs add no egress, Kubernetes API access, or self-JWKS request. Verification uses the local loaded keyring.

The chart rejects native mode with an enabled NetworkPolicy and an empty egress list. Disabling NetworkPolicy is explicit unrestricted egress; otherwise use destination selectors or narrow CIDRs for the actual OIDC and Redis endpoints. Do not copy a broad placeholder CIDR into production.

Use `allowedIngress` to admit only the intended edge or probe workload. Use `denyAllIngress: true` with an empty `allowedIngress` list for explicit deny-all ingress.

## Edge boundary

Put a maintained private edge or reverse proxy in front of the Service. At minimum it must:

- Terminate TLS and enforce the deployment's authentication and access policy.
- Preserve Vaultsmith's session and CSRF cookies in native mode.
- Preserve `Authorization` unchanged for canonical `/api/v1` Bearer routes and enabled `/mcp`; Vaultsmith must validate the original token. Strip client-supplied identity headers such as `X-Auth-Request-*`, `X-Forwarded-User`, `X-Forwarded-Email`, `X-Remote-User`, and `X-Groups`. Do not synthesize `Authorization` from a browser session or gateway identity.
- Generate trusted forwarding headers instead of passing through a client-supplied forwarding chain.
- Disable request and response body logging, trace payload capture, and compression for secret-bearing operation, session, and MCP responses.
- Keep `/healthz`, `/readyz`, and `/metrics` on internal probe paths, or otherwise prevent them from being public.

Keep the authorization server and access-token flow aligned with [OAuth 2.0 Security Best Current Practice (RFC 9700)](https://www.rfc-editor.org/rfc/rfc9700). Do not use implicit grants, password grants, bearer tokens in URLs, or wildcard redirect URIs.

Use this reference boundary:

```text
client
  | HTTPS
  v
maintained edge
  - TLS and host validation
  - explicit Origin/CORS policy
  - Authorization forwarded unchanged
  - request and response body logging disabled
  - secret response compression disabled
  - 8 MiB body limit and measured rate limit
  |
  | authenticated and encrypted backend hop
  v
private ClusterIP / firewall allow-list
  |
  v
Vaultsmith :8080
  - native OIDC/session and Bearer validation
  - Casbin policy
  - private health, readiness, and metrics probes
```

The protocol boundary is the client-visible HTTPS origin in `PUBLIC_BASE_URL`. The backend hop is an operator boundary. Authenticate and encrypt it when the edge and Vaultsmith do not share one trusted host or pod network. Allow the edge and private probes only.

The application limits encrypt plaintext to 1 MiB, Vault text for decrypt/re-key to 5 MiB, and JSON request bodies to 8 MiB. Configure the edge to enforce a deliberate request limit no higher than the application limit and return an explicit `413` when exceeded. Rate limits must preserve measured normal automation bursts and identify the configured rate in operator logs or alerts; do not add a silent arbitrary cap.

Every canonical REST, legacy operation endpoint, and enabled MCP request has a server-owned 30-second application deadline after route/method/no-body header validation. The server timeouts are 5 seconds for headers, 40 seconds for reads, and 45 seconds for writes; configure edge timeouts to at least 50 seconds.

Operation admission is non-blocking after authentication and before body decoding. Saturation returns `503 temporarily_unavailable` with `Retry-After: 1`. The compiled cap is selected from [`docs/benchmarks/admission-linux-amd64-2026-08-12.md`](benchmarks/admission-linux-amd64-2026-08-12.md); Helm does not configure it.

A Gateway, HTTPRoute, Ingress annotation, or NetworkPolicy object is not proof that authentication is active. Test the selected edge implementation with unauthenticated, authenticated, denied, spoofed-header, oversized-body, and public-health-path requests.

## Deploy and verify

1. Create the namespace, application Secrets, OIDC client, and policy source. The chart creates Valkey unless `valkey.enabled` is false.
2. Render and lint the exact values file:

   ```sh
   helm lint deploy/helm/vaultsmith -f /path/to/vaultsmith-values.yaml
   helm template vaultsmith deploy/helm/vaultsmith \
     -f /path/to/vaultsmith-values.yaml >/tmp/vaultsmith-rendered.yaml
   ```

3. Install or upgrade the release:

   ```sh
   VAULTSMITH_CHART_VERSION=0.7.1 # x-release-please-version
   helm upgrade --install vaultsmith \
     oci://ghcr.io/forgeplane-io/charts/vaultsmith \
     --version "$VAULTSMITH_CHART_VERSION" \
     --namespace vaultsmith \
     --create-namespace \
     -f /path/to/vaultsmith-values.yaml \
     --wait
   kubectl rollout status deployment/vaultsmith \
     --namespace vaultsmith
   ```

4. Verify `healthz` and `readyz` from the intended internal probe path. Readiness must not be treated as proof that the public edge is authenticated.
5. Run a live request matrix at the edge:
   - no authentication: rejected;
   - valid authentication: UI and permitted API operations succeed;
   - valid Bearer token: permitted canonical REST operation succeeds without session or CSRF cookies;
   - authenticated but unauthorized group: login succeeds, profile access is empty, protected operations return `403`;
   - MCP disabled: every `/mcp` method returns `404`; when enabled, valid preflight returns `204` and non-POST application methods return `405`;
   - spoofed identity and forwarding headers: ignored;
   - public `/healthz` and `/readyz`: unavailable or `404`;
   - request bodies: absent from logs.

For a disposable native OIDC, Redis, and TLS environment, run [`scripts/integration-native.sh`](../scripts/integration-native.sh). See [`integration/README.md`](../integration/README.md).

## Upgrade and rollback

Keep the previous image digest and values file available. Upgrade with the same native dependencies and verify readiness and the request matrix after the rollout. Do not roll back an exposed deployment by setting `auth.mode: "off"`; that removes authentication. If sessions must be invalidated, use an approved Redis key-prefix or session-namespace procedure.
