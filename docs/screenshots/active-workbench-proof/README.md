# Active workbench proof evidence

Genuine before/after full-page captures for issue #106, using synthetic fixtures.
The baseline was captured before behavior edits.

## Capture conditions

- Before source: `626d9c9aae3cc9a83183245126821073937f4e94`, with only uncommitted regression tests.
- After source: the same base with uncommitted `frontend/src/App.tsx` and `frontend/src/App.test.tsx` changes. [Source hashes](source.sha256) identify the reviewed source precisely.
- Browser: headless Chrome 154.0.8037.98, device scale factor 1; route `/`.
- Viewports: desktop 1440 × 1000 and narrow 390 × 844 CSS pixels. Full-page image heights can exceed the viewport; narrow captures are desktop emulation, not physical-device testing.
- Role: loopback-only authentication-off development, proofs enabled with an ephemeral synthetic signing keyring; exact loopback Origin explicitly allowed. This is not a deployment configuration.
- Reset: fresh page load per scenario, synthetic `dev`/`prod` profiles, server-encrypted synthetic input, equivalent interactions. Randomized encryption changes ciphertext bytes, not fixture meaning.

The [before receipt](before-receipt.json) records six passing limit controls and
14 failed fixed-behavior expectations (seven defects at two widths). The
[after receipt](after-receipt.json) records all 20 expectations passing.

## Before and after

| State | Desktop before / after | Narrow before / after |
| --- | --- | --- |
| Hidden binding in Encrypt | [Before](before-hidden-binding-encrypt-desktop.png) / [After](after-hidden-binding-encrypt-desktop.png) | [Before](before-hidden-binding-encrypt-mobile.png) / [After](after-hidden-binding-encrypt-mobile.png) |
| Hidden binding in Decrypt | [Before](before-hidden-binding-decrypt-desktop.png) / [After](after-hidden-binding-decrypt-desktop.png) | [Before](before-hidden-binding-decrypt-mobile.png) / [After](after-hidden-binding-decrypt-mobile.png) |
| Hidden operation input error in Verify | [Before](before-hidden-input-verify-desktop.png) / [After](after-hidden-input-verify-desktop.png) | [Before](before-hidden-input-verify-mobile.png) / [After](after-hidden-input-verify-mobile.png) |
| Proof after handoff | [Before](before-proof-handoff-desktop.png) / [After](after-proof-handoff-desktop.png) | [Before](before-proof-handoff-mobile.png) / [After](after-proof-handoff-mobile.png) |
| Late proof-copy after Clear | [Before](before-proof-clear-desktop.png) / [After](after-proof-clear-desktop.png) | [Before](before-proof-clear-mobile.png) / [After](after-proof-clear-mobile.png) |
| Late proof-copy after issuance toggle | [Before](before-proof-toggle-desktop.png) / [After](after-proof-toggle-desktop.png) | [Before](before-proof-toggle-mobile.png) / [After](after-proof-toggle-mobile.png) |
| Late proof-copy after binding edit | [Before](before-proof-binding-desktop.png) / [After](after-proof-binding-desktop.png) | [Before](before-proof-binding-mobile.png) / [After](after-proof-binding-mobile.png) |

## Server outcomes and repeatable checks

HTTP is not mocked. The harness runs built Go servers with the embedded app,
checks each rotation's proof cryptographically, and decrypts its result with the
destination profile. After the fix it also completes the UI Encrypt, Decrypt,
and result-handoff flows and checks their values in memory, without logging them.
Only deferred clipboard completion is controlled at the browser platform seam;
both success and rejection are independently covered by component tests.

The disposable capture harness and baseline/result binaries remain local in
`.tmp/issue-106-evidence/`; they are not distributed application tooling. With
the repository's Node version, the capture commands are:

```sh
node .tmp/issue-106-evidence/capture.mjs before 626d9c9aae3cc9a83183245126821073937f4e94
node .tmp/issue-106-evidence/capture.mjs after 626d9c9aae3cc9a83183245126821073937f4e94+App.tsx+App.test.tsx
npm test --prefix frontend -- --run src/App.test.tsx
```

Eleven new regressions failed before the behavior fix and passed afterward.
The full frontend suite passed all 210 tests; lint, typecheck, build, and
embedded-app smoke also passed. Lint reports four warnings in unchanged files.
The test servers and isolated browsers were stopped; synthetic keyrings removed.

## Coverage gaps

- Native OIDC/Redis sign-out, native CSRF, cancellation, real clipboard permission failures, and screen-reader announcements are not live-verified by these captures. Sign-out, cancellation, limits, accessibility attributes, and both clipboard outcomes have component regression coverage.
- Generate, ordinary copy failures, and native-auth screens are not pictured; this repair does not change their rendered behavior.
- No REST/MCP, crypto, authentication, deployment, persistence, dependency, or compatibility contract changes are made by this repair.
