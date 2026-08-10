# Vaultsmith

Vaultsmith is a web UI and HTTP API for encrypting, decrypting, and re-keying Ansible Vault values. It supports Ansible Vault 1.1 and 1.2/AES256. The Go server embeds the React frontend in the built binary.

## What it does

- Encrypt a value with a selected vault profile.
- Decrypt an existing Ansible Vault value.
- Re-key a value from one profile to another.
- Copy an Ansible `!vault` variable snippet from the result.

The server reads vault passwords from environment variables. It does not persist submitted values, accept file uploads, use persistent browser storage, or log request bodies.

Application limits:

- Encrypt input: 1 MiB of UTF-8 plaintext.
- Decrypt and re-key input: 5 MiB of UTF-8 Vault text.
- JSON request body: 8 MiB.

![Vaultsmith workbench](docs/screenshots/workbench.png)

## Run locally

Requirements:

- Go 1.25 or newer
- Node.js 22 and npm
- Bash

`ansible-vault` is not required at runtime. The optional compatibility test uses it when available.

Build the frontend, then start a private local server in `off` mode:

```sh
npm ci --prefix frontend
npm run build --prefix frontend

export VAULT_PROFILES_JSON='[{"id":"dev","label":"Development","passwordEnv":"VAULT_PASSWORD_DEV"}]'
export VAULT_PASSWORD_DEV='replace-with-a-local-password'
export AUTH_MODE=off
export COOKIE_SECURE=false  # local HTTP only

go run ./backend/cmd/server
```

Open <http://localhost:8080>. Check the process with:

```sh
curl -fsS http://localhost:8080/healthz
curl -fsS http://localhost:8080/readyz
```

`AUTH_MODE=off` disables authentication and CSRF protection. Never expose an off-mode server.

For frontend development, keep the Go server running and start Vite in a second terminal:

```sh
npm run dev --prefix frontend
```

Vite listens on <http://localhost:5173> and proxies `/api`, `/healthz`, and `/readyz` to the Go server.

## Configuration

`VAULT_PROFILES_JSON` defines the profiles shown to the browser. Each profile refers to a separate environment variable containing its password:

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

The server rejects duplicate profile IDs, reserved environment names, missing passwords, and invalid profile metadata. Password values never appear in the profiles API.

### Authentication modes

Set `AUTH_MODE` explicitly:

| Mode | Use | Behavior |
| --- | --- | --- |
| `off` | Private local development only | Skips authentication and CSRF protection. |
| `native` | Protected deployments | Uses OIDC Authorization Code + PKCE, Redis-backed opaque sessions, CSRF protection, and profile-scoped Casbin authorization. |

An unset or blank mode is a startup error. Native mode does not fall back to `off` when OIDC, Redis, or policy loading fails. In Helm YAML, write the development value as `mode: "off"`; unquoted `off` may parse as Boolean `false` and is rejected.

Native mode needs an OIDC issuer, client credentials, redirect URL, public base URL, Redis, a CSRF secret, and a Casbin policy file. Identity is the verified `(iss, sub)` pair. If the issuer uses a private CA, set `OIDC_CA_FILE` to a mounted PEM bundle. Do not disable TLS verification.

See [`docs/deployment.md`](docs/deployment.md) for the native configuration and deployment boundary.

## HTTP API

The browser API is same-origin. Native mode uses an opaque session cookie and does not accept bearer tokens or client-provided identity headers.

| Method and path | Purpose |
| --- | --- |
| `GET /healthz` | Liveness. |
| `GET /readyz` | Readiness. |
| `GET /api/v1/session` | Session and CSRF bootstrap. |
| `GET /api/v1/profiles` | Profiles allowed for the current user and their capabilities. |
| `POST /api/v1/operations` | Encrypt, decrypt, or rotate a value. |
| `GET /auth/login` | Start native OIDC login. |
| `GET /auth/callback` | Complete native OIDC login. |
| `POST /auth/logout` | CSRF-protected logout. |

Operation modes are `encrypt`, `decrypt`, and `rotate`. A rotate request names `sourceProfileId` and `destinationProfileId`. In native mode, the browser sends the CSRF token returned by `/api/v1/session` on mutations.

Keep plaintext, ciphertext, passwords, cookies, and tokens out of shell history, logs, screenshots, tickets, and pull requests.

## Deploy with Helm

The chart is in `deploy/helm/vaultsmith`. It creates a `ClusterIP` Service. Ingress and NetworkPolicy are disabled by default. The chart does not create application Secrets.

The public OCI chart is version `0.3.0`:

```sh
helm upgrade --install vaultsmith \
  oci://ghcr.io/forgeplane-io/charts/vaultsmith \
  --version 0.3.0 \
  --namespace vaultsmith \
  --create-namespace \
  -f /path/to/vaultsmith-values.yaml
```

Create the referenced Secrets and policy ConfigMap before installing. Use `auth.policy.data` instead of an external policy ConfigMap when the policy should be managed by Helm. For native mode with NetworkPolicy enabled, allow DNS, OIDC, and Redis egress explicitly. Put a maintained private TLS/authentication edge in front of the Service; NetworkPolicy does not authenticate HTTP callers.

For a source checkout, use `deploy/helm/vaultsmith` instead of the OCI reference and omit `--version`; the source chart version is maintained separately. See [`docs/deployment.md`](docs/deployment.md) for values, Casbin policy, NetworkPolicy, edge, verification, and rollback details.

## Native integration test

The disposable harness starts Redis, Keycloak, local TLS edges, and Vaultsmith with generated credentials:

```sh
./scripts/integration-native.sh
```

For browser testing, keep the stack running:

```sh
./scripts/integration-native.sh --interactive
```

The harness removes its containers, volumes, and temporary state on exit unless `KEEP_INTEGRATION_TMP=1` is set. See [`integration/README.md`](integration/README.md) for the test flow and cleanup rules.

## Development checks

```sh
npm ci --prefix frontend
npm test --prefix frontend -- --run
make typecheck
make build
make test
make smoke
make helm-lint
make chart-test
```

Use `SMOKE_PORT=18080 ./scripts/smoke.sh` when port 8080 is busy. `make compatibility` runs the Ansible CLI compatibility tests when the optional CLI is installed.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for pull-request, release, and sensitive-data rules. Report vulnerabilities as described in [`SECURITY.md`](SECURITY.md).

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
