# Terminal high-surrogate copy evidence

This evidence covers [#112](https://github.com/Forgeplane-io/vaultsmith/issues/112): reject a terminal unpaired high surrogate before formatting an Ansible snippet. The production change is one local guard condition; valid surrogate pairs and existing formatting/copy policies remain unchanged.

## Capture conditions

- Source commit: `cdbce8ed7517af5c8d79ed49b74d3fdd571165fa`.
- Before: the original formatter, with regression-only edits in `ansibleSnippet.test.ts`, `App.test.tsx`, and `GenerateWorkbench.test.tsx`. The baseline was captured before the production guard edit.
- After: the same source commit with the one-line `frontend/src/ansibleSnippet.ts` fix and the same test edits. This PR commits that source; adding evidence and committing does not change rendering.
- Formatter SHA-256 before: `d8e3350741d0e069dcb9e4ce9034f3bd794ba98b6ccd7538388c4cc383533c81`; after: `5cd6c19ba056430ab7f42d0f04df32fc7ab54438c3cb3056d9aa465799e789a7`.
- Browser: Headless Chrome `154.0.8037.98`, device scale factor 1.
- Route: `/`, with fixture-only `?clipboard=blocked` or `?clipboard=success` query values. Desktop viewport 1440 × 1000 and narrow viewport 390 × 844 CSS pixels; images capture the full page.
- Role: loopback-only authentication-off synthetic operator, proofs disabled. This is not a deployment configuration or authenticated-edge verification.
- Reset: fresh page for each case, one synthetic `dev` profile, synthetic Encrypt input and `app_secret` variable name. The clipboard fixture records attempts in browser memory and resolves or rejects; it does not access the OS clipboard.

The built app calls a real local Go server. A loopback response proxy appends a terminal high surrogate to the native ciphertext before the app reads the response. Normal server output is ASCII hex; the malformed suffix is a synthetic fixture, not a demonstrated normal-server failure. Each original native Encrypt/Generate result is decrypted and checked in memory before response mutation. No request bodies or private plaintext are logged. Encryption is randomized, so ciphertext differs between captures under otherwise equivalent conditions.

## Before and after

| Clipboard fixture | Desktop | Narrow |
| --- | --- | --- |
| Blocked: unsafe manual snippet → preparation error, no formatted fallback | [Before](before-terminal-blocked-desktop.png) → [After](after-terminal-blocked-desktop.png) | [Before](before-terminal-blocked-narrow.png) → [After](after-terminal-blocked-narrow.png) |
| Available: copied-success feedback → preparation error, no clipboard attempt | [Before](before-terminal-success-desktop.png) → [After](after-terminal-success-desktop.png) | [Before](before-terminal-success-narrow.png) → [After](after-terminal-success-narrow.png) |

[Before receipt](before-receipt.json) and [after receipt](after-receipt.json) record source/bundle provenance, relevant uncommitted changes, fixture conditions, assertions, completed native outcomes, and screenshot hashes. Replay uses frozen builds and checks bundle hashes rather than labeling the old baseline with the current working source.

## Verification

Commands use the repository's `.nvmrc` (`mise exec node@$(cat .nvmrc) --` in this environment).

| Command | Result |
| --- | --- |
| `npm test --prefix frontend -- --run src/ansibleSnippet.test.ts src/App.test.tsx src/GenerateWorkbench.test.tsx` before fix | Four expected new regression failures; 116 controls passed. |
| Same targeted command after fix | 120 tests passed. |
| `make lint` | Exit 0; four warnings on unchanged regexes in `vaultFormat.ts:13` and `ansibleSnippet.ts:14`. |
| `npm test --prefix frontend -- --run` | 216 tests passed in 8 files; rerun before publication. |
| `make typecheck` | Passed; rerun before publication. |
| `npm run build --prefix frontend -- --outDir ../.tmp/issue-112-evidence/before-dist` | Passed before the production edit; output isolated from tracked embedded assets. |
| `npm run build --prefix frontend -- --outDir ../.tmp/issue-112-evidence/after-dist` | Passed after the edit. |
| `go build -o .tmp/issue-112-evidence/fixture-server ./backend/cmd/server` | Passed; unchanged native server used for browser checks. |
| `node .tmp/issue-112-evidence/capture.mjs before` | 24 browser assertions passed; 10 completed native outcomes independently decrypted; four screenshots. |
| `node .tmp/issue-112-evidence/capture.mjs after` | 28 browser assertions passed; 10 completed native outcomes independently decrypted; four screenshots. |
| `git diff --check` | Passed. |

The local harness, frozen builds, binary, and logs remain in the implementation worktree's `.tmp/issue-112-evidence/`; they are not tracked or required application tooling. With those retained fixtures, repeat the browser checks using the two `capture.mjs` commands above. The repository tests provide the checked-in regressions for terminal high surrogates, valid terminal pairs, unsafe characters, both copy callers, and existing manual-fallback behavior.

## Coverage boundaries and documentation

- The malformed HTTP response and clipboard are fixtures. Real server operation/decrypt outcomes are verified, not a claim that a real server emits this malformed text or that OS clipboard permissions were exercised.
- Generate already rejects malformed HTTP results before rendering. That full-app boundary was verified unchanged at both viewports. Its copy-preparation regression injects a synthetic component result; it is not live Generate transport failure evidence.
- Encrypt represents the shared App copy handler; Rotate is not pictured. Valid ASCII and terminal-pair manual-copy controls are asserted but not pictured. Neither viewport has horizontal page overflow.
- Native OIDC roles, screen-reader announcements, physical touch, Generate material variants, and the OS clipboard are not visually exercised.
- No Go logic, REST/MCP contract, authentication, deployment, Ansible Vault envelope/cryptography, or migration changes. Backend/vet/race, API compatibility, Ansible CLI compatibility, native OIDC integration, embedded-server smoke, chart, Docker, and release suites were not run for this frontend-only guard fix.
- `README.md`, `api/README.md`, `docs/authentication.md`, `docs/deployment.md`, and `docs/api-operator-preflight.md` were inspected before publication. Their behavior and operator requirements remain accurate, so no edits are needed beyond this evidence guide. All pictured material is synthetic.
