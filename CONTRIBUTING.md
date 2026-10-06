# Contributing to Vaultsmith

Keep changes small, reviewable, and safe for secret-handling software.

## Before opening a pull request

- Do not commit passwords, plaintext values, real ciphertext, tokens, kubeconfigs, registry credentials, or private paths.
- Use synthetic fixtures and redact sensitive output from logs and screenshots.
- Read `SECURITY.md` before reporting a vulnerability.
- Keep the private-network and authenticated-edge boundary explicit in code, tests, and documentation.

## Local checks

The repository uses Go 1.27 and Node.js 22. Run the checks relevant to your change:

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
node scripts/ci-paths-test.cjs
node scripts/release-source-test.cjs
goreleaser check --config .goreleaser.yaml
goreleaser release --config .goreleaser.yaml --snapshot --clean
```

The snapshot command does not publish anything.

## Pull requests and releases

Use Conventional Commits. Release Please owns version bumps, release pull requests, and the changelog. GoReleaser owns binary archives, checksums, and GitHub release assets. Do not create release tags or rewrite generated release metadata manually.

In a pull request, state the behavior change, validation performed, security impact, and migration or compatibility effect. Changes to release artifacts, public metadata, image or chart names, or trust boundaries need explicit review.

### Release source integrity

Validation resolves the release tag once. Acceptance and publication check out
that immutable commit and assert HEAD equality before executing source-controlled
commands. Immediately before the first publication, the workflow checks the
remote tag again, peeling annotated tags to their commit. A moved, missing, or
unresolvable tag aborts publication; there is no mutable-ref checkout fallback.

The remote lookup is not atomic protection against later tag movement. Maintain
tag rulesets that prevent updates and deletion of release tags; an environment
reviewer gate does not replace immutable-tag protection.

Image SHA tags and revision labels use the checked-out Git context. BuildKit
provenance remains enabled for manual recovery. The additional GitHub provenance
attestation uses the workflow-event commit, so it is emitted only when that commit
equals the validated release source. A recovery run from a different workflow
commit still publishes and signs the release, but does not emit that additional
attestation.

The local source-binding regression uses only synthetic repositories and writes
its sanitized receipt to `.tmp/release-source-test.json`. It does not run hosted
Actions or verify live signing or registry publication.
