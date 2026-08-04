# Contributing to Vaultsmith

Thanks for helping improve Vaultsmith. Keep changes small, reviewable, and safe for secret-handling software.

## Before opening a pull request

- Do not commit passwords, plaintext values, ciphertext copied from a real system, tokens, kubeconfigs, registry credentials, or local/private paths.
- Use synthetic fixtures and redact sensitive output from logs and screenshots.
- Read `SECURITY.md` before reporting a vulnerability.
- Keep the service's private-network/authenticated-edge boundary explicit in documentation and tests.

## Local checks

The repository uses Go 1.25 and Node.js 22. Run the relevant checks before opening a pull request:

```sh
npm ci --prefix frontend
npm test --prefix frontend -- --run
npm run typecheck --prefix frontend
npm run build --prefix frontend
go test ./...
go vet ./...
make helm-lint
make chart-test
make smoke
```

For release-facing changes, also run:

```sh
goreleaser check --config .goreleaser.yaml
goreleaser release --snapshot --clean
```

The snapshot command must not publish anything.

## Commit and release conventions

Use Conventional Commits so Release Please can produce reliable changelogs and version bumps. Examples:

- `feat: add a vault operation`
- `fix(api): reject oversized request bodies`
- `docs: clarify the deployment trust boundary`
- `ci: pin the release action`

Release Please owns the release PR, version decision, and changelog. GoReleaser owns binary archives, checksums, and GitHub release assets. Do not manually create a release tag or rewrite a generated release PR body without maintainer approval.

## Pull requests

Explain the behavior change, test coverage, security impact, and any migration or compatibility effect. Changes that alter release artifacts, public metadata, image names, chart names, or trust boundaries require explicit review of those contracts.
