# Profile discovery failure and standalone Verify (#107)

Baseline: `db017e8133183c2aaa48c8f110c98e1d4174612f`. Result: that source
plus the deletion in `frontend/src/App.tsx`; test edits do not affect rendering.
The initial baseline was captured before production edits. These final pairs
rerun the preserved baseline binary and the post-edit binary. No other production
changes were present. Final source also changes `frontend/src/App.test.tsx`.

Chrome/154.0.8037.98 headless, route `/`, desktop 1440x1000 and narrow
390x844, full-page screenshots. Narrow captures resize a desktop browser,
not a physical mobile device. Each flow starts with a fresh navigation.
Captures wait for fonts and two animation frames to let Chrome repaint between
full-page captures; this corrects an incomplete baseline raster found in review.

Only synthetic fixtures: loopback-only auth-off operator, dev/prod profiles,
plaintext `synthetic-issue-107`, and an ephemeral generated signing keyring.
Native encryption and attested rotation create the Verify inputs. A loopback
proxy injects only discovery responses: unexpected 403 with a synthetic
sensitive-detail marker, or legitimate 200 empty catalog. Verify and recovered
catalog requests reach the real server. This does not show that a real
deployment emits 403. Private signing material and browser profiles are removed
on exit; screenshots contain only synthetic ciphertext and public proof data.

| State | Desktop before / after | Narrow before / after |
| --- | --- | --- |
| Discovery failure | [before](before-discovery-failure-desktop.png) / [after](after-discovery-failure-desktop.png) | [before](before-discovery-failure-narrow.png) / [after](after-discovery-failure-narrow.png) |
| Completed standalone Verify during discovery failure | [before](before-standalone-verify-desktop.png) / [after](after-standalone-verify-desktop.png) | [before](before-standalone-verify-narrow.png) / [after](after-standalone-verify-narrow.png) |
| Retry recovery | [before](before-recovery-desktop.png) / [after](after-recovery-desktop.png) | [before](before-recovery-narrow.png) / [after](after-recovery-narrow.png) |
| Completed Verify with 200 empty catalog | [before](before-empty-catalog-verify-desktop.png) / [after](after-empty-catalog-verify-desktop.png) | [before](before-empty-catalog-verify-narrow.png) / [after](after-empty-catalog-verify-narrow.png) |

Recovery deliberately diverges: both fixtures allow the native catalog after
Verify, but baseline cannot initiate the absent Retry action. Its recovery image
remains on Verify; the result uses Retry and returns to Encrypt. Other pairs use
equivalent interactions. Encryption randomness, signatures and timestamps vary.

[Before receipt](before-receipt.json): 8/14 fixed-behavior expectations, six
failures (hidden error/Retry, Retry after Verify, and recovery at both widths).
[After receipt](after-receipt.json): 14/14 expectations. Both phases complete
native Verify with HTTP 200 / valid=true in all four flows. Result Retry flows
complete with native HTTP 200 and the dev/prod catalog at both widths.

## Repeat

Prerequisites: repository toolchain (`.nvmrc`, `go.mod`), locked frontend
dependencies, and Google Chrome installed at its standard macOS application path.
Use a clean isolated checkout for each source state; preserve the resulting
embedded binaries in the scratch directory, not in Git.

```sh
npm ci --prefix frontend
mkdir -p .tmp/issue-107-evidence
# On baseline source:
npm run build --prefix frontend
go build -o .tmp/issue-107-evidence/before-server ./backend/cmd/server
node docs/screenshots/profile-discovery-retry/capture.mjs before <baseline-source-reference>
# On result source:
npm run build --prefix frontend
go build -o .tmp/issue-107-evidence/after-server ./backend/cmd/server
node docs/screenshots/profile-discovery-retry/capture.mjs after <result-source-reference>
```

The script itself is supplied by this evidence directory in either checkout;
when checking out baseline, copy it from the result first. Output goes to
`.tmp/issue-107-evidence`. The source-reference argument labels the receipt;
the binary's build state, not that label, determines runtime behavior. The
30-second capture-wait tripwire comes from an earlier observed stalled capture,
not an app budget. It fails explicitly; increase only for measured slow hosts.

## Other verification and limits

`npm test --prefix frontend -- --run src/App.test.tsx -t 'offers verify without profiles|surfaces unexpected profile 403'`:
test-first baseline has one expected failure (no alert), empty-catalog control
passes; result passes both. Final `npm test --prefix frontend -- --run` passes
211 tests across eight files. `make lint`, `make typecheck`,
`npm run build --prefix frontend`, `make smoke`, `./scripts/integration-native.sh`,
and `git diff --check` pass. Lint retains four existing warnings in unchanged
`ansibleSnippet.ts` and `vaultFormat.ts`. Build-only tracked index changes were
reverted after runtime checks; no generated frontend bundle is part of this change.

Native integration separately checks OIDC/session, delegated/client-credentials
proofs, scopes, groups, MCP, authenticated edge, body/log safety, and actual
authenticated policy-denied empty catalog. That is not rendered OIDC evidence.
Loading, repeated retry failure, sign-out, 401 redirect, capability-refresh
failure, and intermediate widths are not visually shown. Related guards are
covered by the frontend suite. No backend/API/dependency/deployment changes or
migrations; full Go/vet/race, API-generation, Helm, container-build and release
packaging checks are outside the changed scope.
