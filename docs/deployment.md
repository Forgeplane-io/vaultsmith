# Deploy Vaultsmith

Vaultsmith is an HTTP service for Ansible Vault values. Use `auth.mode: native` for an exposed deployment. `auth.mode: "off"` disables authentication and CSRF protection and is for private local development only.

This guide covers the application, Helm chart, and required edge boundary. It does not provide a portable Gateway API manifest: authentication, TLS, rate limits, header policy, and source restrictions depend on the selected edge implementation.

## Before you deploy

Prepare these resources outside the chart:

- An OIDC client with exactly one redirect URI: `OIDC_REDIRECT_URL`.
- Secrets containing the CSRF secret, OIDC client secret, Redis password when used, and profile passwords.
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

## Helm chart

The chart creates a `ClusterIP` Service. Ingress and NetworkPolicy are disabled by default. The chart does not create application Secrets.

### Published chart

The public OCI chart is version `0.3.0`:

```sh
helm upgrade --install vaultsmith \
  oci://ghcr.io/forgeplane-io/charts/vaultsmith \
  --version 0.3.0 \
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
    address: redis.example.test:6379
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

Create the referenced Secret and policy ConfigMap before installing. Each `passwordSecretKey` must exist in `secret.existingSecret`.

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
- Redis on its configured port, commonly TCP 6379.

The chart rejects native mode with an enabled NetworkPolicy and an empty egress list. Disabling NetworkPolicy is explicit unrestricted egress; otherwise use destination selectors or narrow CIDRs for the actual OIDC and Redis endpoints. Do not copy a broad placeholder CIDR into production.

Use `allowedIngress` to admit only the intended edge or probe workload. Use `denyAllIngress: true` with an empty `allowedIngress` list for explicit deny-all ingress.

## Edge boundary

Put a maintained private edge or reverse proxy in front of the Service. At minimum it must:

- Terminate TLS and enforce the deployment's authentication and access policy.
- Preserve Vaultsmith's session and CSRF cookies in native mode.
- Remove client-supplied `Authorization` and identity headers before forwarding. Do not forward `X-Auth-Request-*`, `X-Forwarded-User`, `X-Forwarded-Email`, or `X-Remote-User` from the client.
- Generate trusted forwarding headers instead of passing through a client-supplied forwarding chain.
- Disable request-body logging and plaintext capture at the edge and in observability systems.
- Keep `/healthz` and `/readyz` on an internal probe path, or otherwise prevent them from being public.

The application limits encrypt plaintext to 1 MiB, Vault text for decrypt/re-key to 5 MiB, and JSON request bodies to 8 MiB. Configure the edge to enforce a deliberate request limit no higher than the application limit.

A Gateway, HTTPRoute, Ingress annotation, or NetworkPolicy object is not proof that authentication is active. Test the selected edge implementation with unauthenticated, authenticated, denied, spoofed-header, oversized-body, and public-health-path requests.

## Deploy and verify

1. Create the namespace, application Secrets, Redis, OIDC client, and policy source.
2. Render and lint the exact values file:

   ```sh
   helm lint deploy/helm/vaultsmith -f /path/to/vaultsmith-values.yaml
   helm template vaultsmith deploy/helm/vaultsmith \
     -f /path/to/vaultsmith-values.yaml >/tmp/vaultsmith-rendered.yaml
   ```

3. Install or upgrade the release:

   ```sh
   helm upgrade --install vaultsmith \
     oci://ghcr.io/forgeplane-io/charts/vaultsmith \
     --version 0.3.0 \
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
   - authenticated but unauthorized group: login succeeds, profile access is empty, protected operations return `403`;
   - spoofed identity and forwarding headers: ignored;
   - public `/healthz` and `/readyz`: unavailable or `404`;
   - request bodies: absent from logs.

For a disposable native OIDC, Redis, and TLS environment, run [`scripts/integration-native.sh`](../scripts/integration-native.sh). See [`integration/README.md`](../integration/README.md).

## Upgrade and rollback

Keep the previous image digest and values file available. Upgrade with the same native dependencies and verify readiness and the request matrix after the rollout. Do not roll back an exposed deployment by setting `auth.mode: "off"`; that removes authentication. If sessions must be invalidated, use an approved Redis key-prefix or session-namespace procedure.
