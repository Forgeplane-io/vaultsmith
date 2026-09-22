# Vaultsmith agent instructions

Keep changes small and preserve Vaultsmith's secret-handling, authentication,
API compatibility, and deployment boundaries.

## Sources of truth

- Use `go.mod`, `.nvmrc`, package manifests, and lockfiles for tool and
  dependency versions. Do not copy version numbers into this file.
- Use the `Makefile` and `.github/workflows/` for current validation commands.
- Read `CONTRIBUTING.md` before changing security boundaries, release behavior,
  or generated release metadata.
- Read `api/README.md` before changing the public REST or MCP contracts,
  generated API artifacts, compatibility baselines, or the compatibility
  allowlist.

## Secret safety

- Use only synthetic secret material. Never put real plaintext, Vault
  ciphertext, passwords, private keys, tokens, cookies, kubeconfigs, registry
  credentials, or private paths in commands, fixtures, logs, screenshots,
  prompts, or commits.
- Keep request bodies and credentials out of diagnostics. Redact sensitive
  values while preserving enough context to identify the failing operation.
- Preserve the documented trust boundary: authentication-off mode is for
  loopback-only local development and must not become a deployment fallback.

## API contracts and generated files

- `api/openapi.yaml` is the source of truth for the REST contract.
- Do not hand-edit `backend/internal/apimodels/openapi.gen.go`,
  `frontend/src/generated/api.ts`, or `docs/api-reference.md`. After changing
  the schema, run `make generate-api`, inspect the generated diff, and run
  `make api-check`.
- The runtime router is hand-written. Verify route behavior separately from
  generated contract types.
- MCP is outside OpenAPI. Treat REST and MCP as separate contract branches and
  run the checks for each affected branch.
- Never edit an API baseline merely to make compatibility checks pass.
  Baselines change only for tagged releases. Treat allowlist edits as reviewed
  compatibility decisions, not test fixes.

## Verification by change type

Run the narrowest checks that cover the change, then report exactly what ran
and what was not exercised.

| Change | Verification |
| --- | --- |
| Go/backend | Run affected package tests while iterating, then `go test ./...` and `go vet ./...`. Add `go test -race ./...` for concurrency, sessions, locks, or admission changes. |
| Ansible Vault format or cryptography | Run `make compatibility` with `ansible-vault` installed. |
| Frontend | Run `make lint`, `npm test --prefix frontend -- --run`, and `make typecheck`. Add `npm run build --prefix frontend` when compilation, assets, or bundling may change. |
| REST contract or generated API artifacts | Run `make generate-api`, review the generated output, run `make api-check`, and run the affected HTTP/service tests. |
| MCP contract or behavior | Run `make api-contract-test` and the affected tests under `backend/internal/httpapi` and `backend/internal/vaultservice`. Do not treat OpenAPI checks as MCP coverage. |
| Helm chart | Run `make helm-lint` and `make chart-test`. |
| OIDC, Redis, sessions, CSRF, or authenticated-edge behavior | Run `./scripts/integration-native.sh` when the required container runtime is available. |
| Cross-cutting server or embedded-frontend behavior | Run `npm run build --prefix frontend` before `make smoke`. |
| Dockerfile or container build | Run `make docker`. |
| Release packaging or metadata | Run `make release-check`; run `make release-snapshot` when artifact construction changed. |
| Documentation or agent instructions only | Check referenced paths and commands against the repository and run `git diff --check`. |

If an environment-dependent check cannot run, state the missing prerequisite
and the remaining coverage gap instead of substituting an unrelated check.
