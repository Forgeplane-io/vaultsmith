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

### Dependency auto-merge

Dependabot patch and minor updates to the root Go module and frontend production
dependencies are eligible for automatic squash merging after the CI workflow
succeeds and all `main` rules pass. Every dependency in a group must qualify. Major
updates, frontend development dependencies, API generators, GitHub Actions, and
container images remain manual. Existing Dependabot ignore rules still apply.

The workflow accepts only same-repository, non-draft Dependabot PRs and never
checks out PR code. Fetch Metadata verifies the first commit only, so auto-merge
requires exactly one signed Dependabot commit. Additional commits produce a
notice with the observed count; ask Dependabot to recreate the PR or review it
manually. The workflow waits for CI on the event's exact head commit, then requests
a merge bound to that commit. It never arms native auto-merge, which could retain
merge intent after later maintainer edits. A newer PR event cancels the old run;
CI failures or a changed head prevent merging. If another `main` rule blocks the
merge, resolve it and rerun the workflow or merge manually.

Before rollout, install a GitHub App on **only this repository** with repository
permissions **Contents: read and write** and **Pull requests: read and write**.
Do not grant the App ruleset bypass access. Set the Actions repository variable
`DEPENDABOT_AUTO_MERGE_APP_CLIENT_ID` and the Actions repository secret
`DEPENDABOT_AUTO_MERGE_APP_PRIVATE_KEY`. Configure the private key through GitHub's
secret UI; never paste it into an issue, PR, chat, command, or log. Missing
credentials fail token creation rather than falling back to another identity.

The App token is minted only after CI succeeds, limited to this repository and
those permissions, and revoked when the job finishes. Using an App instead of
`GITHUB_TOKEN` preserves the normal push-triggered full CI and Release Please runs
after merging. Verify those runs on the first real eligible merge; local tests do
not prove hosted event delivery.
Run `node scripts/dependabot-auto-merge-test.cjs` for the synthetic workflow check;
its sanitized receipt is `.tmp/dependabot-auto-merge-test.json`.

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
provenance remains enabled for supported draft recovery. The additional GitHub
provenance attestation uses the workflow-event commit, so it is emitted only when
that commit equals the validated release source. A draft recovery run from a
different workflow commit still publishes and signs the release, but does not emit
that additional attestation.

Checksum signing retains the SHA-256 of GoReleaser's local `dist/checksums.txt`
immediately after production and records it in the workflow run summary. Before
signing, both the retained local bytes and the downloaded release readback must
match that producing digest. Cosign signs the local producer file, never the
downloaded asset. The uploaded asset remains `checksums.txt.bundle`.

Only draft releases that run GoReleaser are currently supported for publication
or recovery. Non-draft recovery and republishing are rejected before the first
publication because no independently trusted original checksum receipt is
available. A matching source tag, a rebuilt snapshot, or the current release
asset and its API digest do not establish original checksum provenance. Do not
bypass the guard or mark a published release as a draft to force a rebuild;
non-draft recovery requires a separately reviewed original-evidence mechanism.

The release workflow stages the chart with the producing image digest in its
`vaultsmith.io/image-digest` annotation. Missing or malformed digest output aborts
before chart registry login or push. Operator image values remain independent
overrides; chart and application version metadata stay release-managed.

Only chart sources with the packaged-digest image helper consume this annotation
as their default image. Draft recovery preserves older validated tagged sources;
their historical helpers may ignore the annotation and keep a tag fallback.
Annotation presence alone does not prove default binding. Verify the rendered
Vaultsmith image and set an explicit verified `image.digest` for those sources.
Do not substitute a newer helper into historical recovery artifacts.

Chart publication retains the producing Helm push's OCI manifest digest, pulls
that exact digest, and compares the downloaded archive byte-for-byte with the
local package before signing. Missing, malformed, or inconsistent manifest
identity or content aborts before Cosign. Chart signing and release output use
the retained digest reference, never a fresh version-tag lookup. The chart
manifest digest and the packaged image digest identify different artifacts.
This chart-manifest binding also applies to historical-source draft recovery.

The local source-binding regression uses synthetic repositories and executes the
workflow's actual packaging, signing, and output steps with native Helm packaging
and simulated registry/signing calls. It checks producing-manifest routing, tag
replacement, push/digest/readback failures, and immutable release output.
It also captures synthetic checksum signer input and checks the producing digest,
readback substitution, missing or changed producer bytes, missing or malformed
digest output, evidence-less recovery rejection, and download/sign/upload failures.
It renders the archive with synthetic native-mode Secret references and
checks the default image, overrides, invalid digest handling, and the older-helper
recovery limitation. Use release-selected Helm and a full-history Git checkout
before running `node scripts/release-source-test.cjs`; the historical helper
fixture is loaded from an immutable pre-change Git object.
The sanitized receipt is `.tmp/release-source-test.json`; the synthetic archive,
values, and deployment renders are retained in `.tmp/release-chart-test/`.
It does not run hosted Actions or verify image pulls, live signing, registry
publication, or cluster installation.
