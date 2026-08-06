<a name="readme-top"></a>

# Vaultsmith

A small web UI for encrypting, decrypting, and re-keying Ansible Vault values.

Vaultsmith supports Ansible Vault 1.1 and 1.2/AES256. It runs as one Go binary with the React UI embedded in it.

## Table of contents

- [About the project](#about-the-project)
- [Built with](#built-with)
- [Getting started](#getting-started)
- [Configuration](#configuration)
- [Usage](#usage)
- [Deploy with Helm](#deploy-with-helm)
- [Security](#security)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## About the project

Vaultsmith is for short, deliberate operations on one value at a time:

- Encrypt plaintext with a selected vault profile.
- Decrypt an existing Vault 1.1 or 1.2 value.
- Re-key a value from one profile to another.
- Copy an Ansible `!vault` variable snippet from the result.

The server loads vault passwords from environment variables. The browser receives profile IDs and labels, then sends the value being operated on to the server. Vaultsmith does not persist values, upload files, store browser state, or log request bodies.

![Vaultsmith workbench](docs/screenshots/workbench.png)

![Vaultsmith encrypt result](docs/screenshots/encrypted-value.png)

Limits are deliberate:

- Encrypt: up to 1 MiB of UTF-8 plaintext.
- Decrypt and re-key: up to 5 MiB of UTF-8 Vault text.
- JSON request body: up to 8 MiB.

## Built with

- [Go](https://go.dev/) for the server and Ansible Vault operations.
- [React](https://react.dev/) and [TypeScript](https://www.typescriptlang.org/) for the UI.
- [Helm](https://helm.sh/) for Kubernetes deployment.
- Docker for the packaged image.

## Getting started

### Prerequisites

- Go 1.25 or newer
- Node.js 22 LTS and npm
- A POSIX shell

`ansible-vault` is not required at runtime. The optional compatibility test uses it when available.

### Run locally

Build the frontend into the directory embedded by the Go server:

```sh
nvm use
npm ci --prefix frontend
npm run build --prefix frontend
```

Start the server with a local profile. The password below is only a placeholder; replace it in your shell session and do not commit it.

```sh
export VAULT_PROFILES_JSON='[{"id":"dev","label":"Development","passwordEnv":"VAULT_PASSWORD_DEV"}]'
export VAULT_PASSWORD_DEV='replace-with-a-local-password'
export AUTH_MODE=off
export COOKIE_SECURE=false # local HTTP only; use true behind HTTPS
go run ./backend/cmd/server
```

The server listens on `http://localhost:8080`. Set `HTTP_ADDR` to use another address, for example `HTTP_ADDR=127.0.0.1:18080`.

For frontend work, keep the Go server running and start Vite in a second terminal:

```sh
npm run dev --prefix frontend
```

## Configuration

`VAULT_PROFILES_JSON` contains profile metadata. Each profile points to a separate environment variable containing its password:

```json
[
  {
    "id": "dev",
    "label": "Development",
    "passwordEnv": "VAULT_PASSWORD_DEV"
  },
  {
    "id": "prod",
    "label": "Production",
    "passwordEnv": "VAULT_PASSWORD_PROD"
  }
]
```

The server rejects reserved environment names, duplicate profile IDs, missing passwords, and invalid profile metadata. Password values are not returned by the profiles API.

### Authentication modes

`AUTH_MODE` must be explicit at deployment time:

- `off` is a development-only mode. It skips authentication, Redis/OIDC, session cookies, and CSRF protection while keeping operations available. The server logs a loud startup warning; do not expose this mode.
- `native` enables provider-neutral OIDC Authorization Code + PKCE, Redis-backed opaque sessions, and Casbin profile authorization. There is no authentication fallback when Redis, OIDC discovery, or policy loading fails.

An unset or blank `AUTH_MODE` is a startup error; native security is never selected or bypassed implicitly.

Native mode requires `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URL`, `PUBLIC_BASE_URL`, `REDIS_ADDR`, `REDIS_KEY_PREFIX`, `AUTHZ_POLICY_FILE`, and a random `CSRF_SECRET`. OIDC issuer discovery is single-issuer per deployment; identity is the verified `(iss, sub)` pair. Email is metadata, not identity. `OIDC_GROUPS_CLAIM` defaults to `groups`; groups must be a string array. If the issuer uses a private CA, set `OIDC_CA_FILE` to a mounted PEM bundle; do not disable TLS verification.

Sessions use host-only `__Host-` cookies with `HttpOnly`, `Path=/`, `SameSite=Lax`, and `Secure` in native mode. Refresh tokens and session data remain server-side in Redis. Requests carrying a session cookie are serialized through a Redis lease, including refresh and logout; the lease renews while the request is running so stale session commits cannot overwrite a refresh or resurrect a logged-out session. Redis credentials are optional; omitted credentials send no Redis `AUTH`. Configured credential rejection is a startup/runtime error, never a downgrade.

If an OIDC refresh response omits `id_token` (which is permitted by OIDC), Vaultsmith keeps the refreshed session valid until the earlier of the new token expiry and the SCS absolute session deadline. This prevents a standards-compliant refresh response from expiring the session at the old ID-token deadline while retaining a bounded absolute lifetime.

`AUTHZ_POLICY_FILE` uses Casbin CSV policy with `p, subject, object, action, effect` and `g, group:<claim>, role:<name>` rows. `profiles:list` gates profile listing; known-profile operations are authorized independently. Rotate requires decrypt on the source and encrypt on the destination. Supported actions are `profiles:list`, `encrypt`, and `decrypt`; unsupported audit-rotation actions are rejected during policy validation rather than accepted without enforcement.

## Usage

The UI has three operation modes: `encrypt`, `decrypt`, and `rotate`. A rotate request names both the source and destination profile.

List the profiles exposed to the browser:

```sh
curl -fsS http://localhost:8080/api/v1/profiles
```

In native mode, complete OIDC first. The browser then sends the host-only session cookie on API requests, and mutating requests also send the CSRF token returned by the session bootstrap. In local `off` mode, no session or CSRF cookie is needed.

For native-mode session bootstrap:

```sh
curl -fsS -c /tmp/vaultsmith.cookies -b /tmp/vaultsmith.cookies http://localhost:8080/api/v1/session
```

Encrypt a synthetic value in native mode:

```sh
curl -fsS \
  -b /tmp/vaultsmith.cookies \
  -H 'Origin: http://localhost:8080' \
  -H 'Referer: http://localhost:8080/' \
  -H 'X-CSRF-Token: <session-bootstrap-csrfToken>' \
  -H 'Content-Type: application/json' \
  --data '{"profileId":"dev","mode":"encrypt","value":"example-value"}' \
  http://localhost:8080/api/v1/operations
```

Decrypt an existing value with `profileId` and `mode: "decrypt"`. Re-key one with this request shape:

```json
{
  "mode": "rotate",
  "sourceProfileId": "dev",
  "destinationProfileId": "prod",
  "value": "$ANSIBLE_VAULT;1.1;AES256\n..."
}
```

Keep real plaintext, ciphertext, and passwords out of shell history, logs, tickets, screenshots, and pull requests.

## Deploy with Helm

The chart lives in `deploy/helm/vaultsmith`. It uses a `ClusterIP` service, leaves Ingress disabled, disables service-account token automount, and leaves NetworkPolicy disabled unless explicitly enabled. Set `networkPolicy.denyAllIngress: true` for an explicit deny-all policy, or provide allowed ingress/egress rules. The chart does not create password, CSRF, OIDC, or Redis Secrets, and it does not create a policy ConfigMap unless policy data is supplied in values.

For a development-only no-auth deployment, no auth or CSRF Secret is required:

```yaml
auth:
  mode: "off"
```

For native mode, provide all required external references and explicit egress:

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
    # Optional for a private issuer CA; the chart mounts this ConfigMap at a fixed read-only path.
    ca:
      existingConfigMap: vaultsmith-oidc-ca
      key: ca.crt
  redis:
    address: redis.example.test:6379
    keyPrefix: "vaultsmith:"
  policy:
    existingConfigMap: vaultsmith-policy
    key: policy.csv
networkPolicy:
  enabled: true
  allowedIngress: []
  allowedEgress:
    - to:
        - ipBlock:
            cidr: 10.0.0.0/8
      ports:
        - protocol: TCP
          port: 443
        - protocol: TCP
          port: 6379
```

Native chart rendering fails unless the OIDC, Redis, CSRF, policy, secure-cookie, and NetworkPolicy egress inputs are present. `auth.mode: off` is never an implicit fallback for native startup failures. Off mode intentionally skips authentication and CSRF protection and must remain inside a private development boundary. The chart emits `REDIS_REFRESH_LOCK_TTL`, `REDIS_REFRESH_LOCK_WAIT`, `REDIS_REFRESH_LOCK_RETRY`, and `REDIS_PROVIDER_TIMEOUT`; these values are parsed by the server and control session/refresh coordination.

### Casbin policy configuration

Native mode loads a file-backed Casbin policy from `AUTHZ_POLICY_FILE`. The chart mounts that file at `/etc/vaultsmith/policy/policy.csv`. Choose exactly one policy source: either inline `auth.policy.data`, or an external ConfigMap referenced by `auth.policy.existingConfigMap`; Helm rejects both together.

For an inline policy, replace the `auth.policy` block above with this form. The configured `key` is used for the inline ConfigMap key and can be customized; the mounted application path remains `/etc/vaultsmith/policy/policy.csv`:

```yaml
auth:
  policy:
    key: policy.csv
    data: |-
      g, group:vaultsmith-operators, role:operator
      p, role:operator, profiles, profiles:list, allow
      p, role:operator, profile:dev, encrypt, allow
      p, role:operator, profile:dev, decrypt, allow
      p, role:operator, profile:prod*, encrypt, allow
      p, role:operator, profile:prod*, decrypt, allow
```

For an externally managed policy, create a ConfigMap whose data key matches `auth.policy.key` and reference it instead:

```yaml
auth:
  policy:
    existingConfigMap: vaultsmith-policy
    key: policy.csv
```

The `group:<value>` in a `g` row must match a value from the verified OIDC groups claim (`groups` by default). Permission rows use role subjects and have the form `p, role:<name>, <resource>, <action>, <effect>`. `profiles:list` applies to the global `profiles` resource; `encrypt` and `decrypt` apply to `profile:<id>` resources. A trailing `*` is allowed for a profile prefix, but it must match at least one configured profile. Explicit `deny` rows override `allow` rows. Rotate requires decrypt permission on the source profile and encrypt permission on the destination profile. Policy validation fails closed if it references an unknown profile or invalid action.

The authorizer checks the policy file for changes before authorization and reloads a valid update, so an externally managed ConfigMap can be updated without a pod restart. A missing or malformed updated policy fails closed until a valid policy is available.

The full policy and external ConfigMap examples are in the [deployment guide](docs/deployment.md#casbin-policy-configuration). Do not put credentials or tokens in the policy; keep them in the referenced Kubernetes Secrets.

Create the profile password Secret and referenced auth Secret/ConfigMap outside Helm, then install:

```yaml
profiles:
  - id: dev
    label: Development
    passwordEnv: VAULT_PASSWORD_DEV
    passwordSecretKey: dev

secret:
  existingSecret: vaultsmith-passwords

networkPolicy:
  enabled: true
  allowedIngress: []
```

Install the local chart:

```sh
helm upgrade --install vaultsmith deploy/helm/vaultsmith \
  --namespace vaultsmith \
  --create-namespace \
  -f /path/to/vaultsmith-values.yaml
```

An empty `allowedIngress` list is deny-all when enforced by the cluster CNI. NetworkPolicy is not authentication. Put an authenticated or private edge in front of the service before enabling Ingress.

## Security

Vaultsmith has two explicit authentication modes. In `native` mode it authenticates users with provider-neutral OIDC Authorization Code + PKCE, stores opaque sessions and refresh state in Redis, and authorizes profile operations with Casbin. In `off` mode it skips authentication and CSRF protection for development only and logs a startup warning; browser security headers still apply. Native startup fails closed if Redis, OIDC discovery, or policy loading is unavailable.

Keep native deployments behind TLS and a private network boundary where practical. Treat the browser, clipboard history and sync, browser extensions, shared machines, server memory, Redis, the OIDC provider, and Kubernetes access as part of the trust boundary. Do not log or forward access tokens, refresh tokens, passwords, CSRF secrets, or credential-bearing connection strings.

See [`SECURITY.md`](SECURITY.md) for the reporting policy. See [`docs/deployment.md`](docs/deployment.md) for deployment boundary and migration guidance.

## Development

Run the main checks with:

```sh
make test
make typecheck
make build
make smoke
make helm-lint
make chart-test
```

Use `SMOKE_PORT=18080 ./scripts/smoke.sh` if port 8080 is already in use. For release configuration and local artifacts, use `make release-check` and `make release-snapshot`.

## Contributing

Keep changes small and reviewable. Use synthetic fixtures, redact sensitive output, and explain security or compatibility effects in the pull request.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full checklist.

## License

Vaultsmith is released under the [Apache License 2.0](LICENSE).

<p align="right">(<a href="#readme-top">back to top</a>)</p>
