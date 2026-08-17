# Contributing to Vaultsmith

Keep changes small, reviewable, and safe for secret-handling software.

## Before opening a pull request

- Do not commit passwords, plaintext values, real ciphertext, tokens, kubeconfigs, registry credentials, or private paths.
- Use synthetic fixtures and redact sensitive output from logs and screenshots.
- Read `SECURITY.md` before reporting a vulnerability.
- Keep the private-network and authenticated-edge boundary explicit in code, tests, and documentation.

## Local checks

The repository uses Go 1.25 and Node.js 22. Run the checks relevant to your change:

```sh
npm ci --prefix frontend
npm ci --prefix api/typescript-generator --ignore-scripts
make lint
npm test --prefix frontend -- --run
npm run typecheck --prefix frontend
npm run build --prefix frontend
make api-check
go test ./...
go vet ./...
make helm-lint
make chart-test
make smoke
```

For release-facing changes, also run:

```sh
goreleaser check --config .goreleaser.yaml
goreleaser release --config .goreleaser.yaml --snapshot --clean
```

The snapshot command does not publish anything.

## Pull requests and releases

Use Conventional Commits. Release Please owns version bumps, release pull requests, and the changelog. GoReleaser owns binary archives, checksums, and GitHub release assets. Do not create release tags or rewrite generated release metadata manually.

In a pull request, state the behavior change, validation performed, security impact, and migration or compatibility effect. Changes to release artifacts, public metadata, image or chart names, or trust boundaries need explicit review.
