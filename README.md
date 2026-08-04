# Vaultsmith

Vaultsmith is a small, self-contained web UI for encrypting, decrypting, and re-keying one value at a time with **Ansible Vault 1.1 and 1.2/AES256**. The Go server owns operator-configured vault passwords; the React UI only sees profile labels and submitted values.

> **Sensitive-data warning:** This service is not an authentication system. Do not expose it to untrusted users or the public internet. Put it behind an authenticated/private network boundary, use TLS at the edge, and treat clipboard history/sync, browser extensions, shared machines, server memory, and Kubernetes access as part of the trust boundary.

## What it does

- Go backend implementing Ansible Vault 1.1 and 1.2/AES256 directly; it does not execute `ansible-vault` at request time. New encryption uses the selected profile ID as the Vault 1.2 label, while decryption accepts both formats.
- React/TypeScript SPA served by the same Go binary through `go:embed`.
- Operator-defined profiles with passwords loaded only from environment variables or Kubernetes Secret references.
- Same-origin JSON API:
  - `GET /api/v1/profiles`
  - `POST /api/v1/operations`
  - `GET /healthz`
  - `GET /readyz`
- No server-side persistence, request logging, browser storage, file upload, batch mode, general-purpose YAML generation, or built-in authentication/RBAC. The UI can format an existing ciphertext locally as an Ansible `!vault` variable snippet.

## Compatibility and limits

- Supported vault formats:
  - `$ANSIBLE_VAULT;1.1;AES256`
  - `$ANSIBLE_VAULT;1.2;AES256;<vault-id-label>`
- New encryption emits Vault 1.2 and uses the selected profile ID as `<vault-id-label>`.
- Decryption accepts both Vault 1.1 and Vault 1.2 text; the selected profile still determines the password.
- `encrypt` accepts up to **1 MiB of UTF-8 plaintext**.
- `decrypt` accepts up to **5 MiB of UTF-8 Vault text**, enough for the envelope produced from the maximum plaintext.
- `rotate` accepts up to **5 MiB of UTF-8 Vault text**, decrypts and re-encrypts it on the server, and emits a destination-profile-labeled Vault 1.2 value. The decrypted plaintext remains subject to the 1 MiB ceiling.
- JSON request bodies are capped at **8 MiB** before decoding.
- Values are handled in request/React memory only. Copying is explicit; clearing the UI does not clear OS clipboard history or clipboard sync.
- Go cannot guarantee immediate zeroization of strings after garbage collection. Keep the service private and use short-lived operational sessions.

## Local development

Prerequisites:

- Go 1.25 or newer.
- Node.js 22 LTS. The repository records this in `.nvmrc`.
- npm and a POSIX shell.
- `ansible-vault` is **not** required at runtime. The optional compatibility gate uses it when available.

From this directory:

```sh
nvm use
npm ci --prefix frontend
npm test --prefix frontend -- --run
npm run typecheck --prefix frontend
go test ./...
go vet ./...
```

Build the SPA into the Go embed directory and start the server with synthetic local configuration:

```sh
npm run build --prefix frontend
export VAULT_PROFILES_JSON='[{"id":"dev","label":"Development","passwordEnv":"VAULT_PASSWORD_DEV"}]'
export VAULT_PASSWORD_DEV='[REDACTED]'
go run ./backend/cmd/server
```

`[REDACTED]` is a placeholder only. Use a real password through an untracked shell/session secret when operating locally; never commit it or put it in a values file.

The server listens on `:8080` by default. During frontend development, run `npm run dev --prefix frontend`; Vite proxies `/api` to `http://localhost:8080`.

Useful gates:

```sh
make test
make build
make smoke
make compatibility   # requires ansible-vault in PATH or ANSIBLE_VAULT_BIN
```

## API examples

List public profiles. Password environment names are intentionally not returned:

```sh
curl -fsS http://localhost:8080/api/v1/profiles
```

Encrypt a synthetic value:

```sh
curl -fsS \
  -H 'Content-Type: application/json' \
  --data '{"profileId":"dev","mode":"encrypt","value":"fixture-value"}' \
  http://localhost:8080/api/v1/operations
```

Re-key a complete Vault value from `dev` to `prod`. The response contains only the new ciphertext; plaintext is not returned:

```sh
curl -fsS \
  -H 'Content-Type: application/json' \
  --data @/path/to/rotate-request.json \
  http://localhost:8080/api/v1/operations
```

Use this request shape in the untracked `rotate-request.json` file:

```json
{"mode":"rotate","sourceProfileId":"dev","destinationProfileId":"prod","value":"$ANSIBLE_VAULT;1.1;AES256\n..."}
```

Decrypt a value by placing the complete Vault text in the request. Keep the ciphertext in a shell variable or file outside the repository; do not paste real secrets into tickets or logs:

```sh
curl -fsS \
  -H 'Content-Type: application/json' \
  --data @/path/to/request.json \
  http://localhost:8080/api/v1/operations
```

The API returns generic `operation_failed` errors for wrong passwords, malformed Vault text, tampering, rotate failures, and non-UTF-8 decrypted bytes. It does not reveal whether a password was correct or echo submitted values in error responses.

## Kubernetes / Helm

The chart is private by default:

- Service type is `ClusterIP`.
- Ingress is disabled.
- NetworkPolicy is enabled with an empty ingress list, which is deny-all when the cluster CNI enforces NetworkPolicy.
- Service-account token automount is disabled.
- The chart never creates a password Secret and never puts password values in a ConfigMap.
- `profiles: []` is lintable/renderable, but the workload fails startup until at least one valid profile is configured.

Create an existing Secret out-of-band. The value below is synthetic placeholder text; replace it only in your private command/session:

```sh
kubectl create secret generic vaultsmith-passwords \
  --from-literal=dev='[REDACTED]'
```

Create an untracked values file with profile metadata and an explicit trusted caller selector:

```sh
cat > /tmp/vaultsmith-values.yaml <<'VALUES'
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
```

Install or upgrade without putting a password in Helm values:

```sh
helm upgrade --install vaultsmith deploy/helm/vaultsmith \
  --namespace vaultsmith \
  --create-namespace \
  -f /tmp/vaultsmith-values.yaml
```

The selector must match the authenticated/private caller workload in your cluster. NetworkPolicy is not authentication, and enforcement depends on the CNI. Add an upstream authenticated boundary before enabling Ingress; leave Ingress disabled unless that boundary is in place.

For a local private check, use port-forwarding:

```sh
kubectl -n vaultsmith port-forward service/vaultsmith 8080:8080
```

Rotate a password by updating the existing Secret and restarting the Deployment. The profile metadata ConfigMap has a checksum rollout annotation; Secret-backed env values require an explicit restart:

```sh
kubectl create secret generic vaultsmith-passwords \
  --from-literal=dev='[REDACTED]' \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n vaultsmith rollout restart deployment/vaultsmith
kubectl -n vaultsmith rollout status deployment/vaultsmith
```

## Container

The multi-stage Dockerfile builds the frontend, compiles a static Go binary, and runs it as the non-root `distroless` user:

```sh
docker build -t vaultsmith:dev .
```

The image exposes port `8080`. Passwords must be provided by runtime environment/Kubernetes Secret wiring; never add `.env`, credentials, or generated Secret manifests to the image context.

The binary supports `--version` and release builds embed the semantic version, source commit, and build date:

```sh
./vaultsmith --version
```


## Releases

The public release target is [`forgeplane-io/vaultsmith`](https://github.com/forgeplane-io/vaultsmith). Release Please owns versioning and changelogs; GoReleaser publishes signed binary archives and checksums; the release workflow publishes the container image and Helm chart.

For a released version, verify `checksums.txt` and its keyless Cosign bundle before installing. The published OCI coordinates are:

- Image: `ghcr.io/forgeplane-io/vaultsmith:<version>`
- Helm chart: `oci://ghcr.io/forgeplane-io/charts/vaultsmith`

Example installation using the first planned release:

```sh
helm install vaultsmith oci://ghcr.io/forgeplane-io/charts/vaultsmith \
  --version 0.1.0 \
  --namespace vaultsmith \
  --create-namespace \
  -f /tmp/vaultsmith-values.yaml
```

Release automation is tag-driven. Do not create a second tag or manually overwrite an existing semantic version when recovering a failed publication; rerun the release workflow only after verifying the tag and source commit.

The documented gates are intentionally split:

```sh
npm ci --prefix frontend
npm test --prefix frontend -- --run
npm run typecheck --prefix frontend
npm run build --prefix frontend
go test ./...
go vet ./...
go build ./...
./scripts/smoke.sh
helm lint deploy/helm/vaultsmith
bash deploy/helm/vaultsmith/tests/chart_test.sh
make compatibility
```

`make compatibility` runs tagged tests against the real `ansible-vault` executable when available. Ordinary Go tests use a committed synthetic Vault 1.1 fixture and remain portable on hosts without Ansible installed.
