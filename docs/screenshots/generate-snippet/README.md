# Generate Ansible snippet evidence

## Capture conditions

- Before source: `51affceebadf4b33844ed4268beb1c038357b244` (current main when this worktree was created).
- After source: the same HEAD with the uncommitted `frontend/src/GenerateWorkbench.tsx` snippet controls and rebuilt embedded frontend. Test and README changes do not affect rendering.
- Browser: Headless Chrome `154.0.8037.98`, device scale factor 1.
- Route: `/`; desktop 1440 × 1000 and narrow 390 × 844 CSS pixels. Images capture the full page, so image heights exceed the viewport.
- Role: loopback-only authentication-off local development, not a deployment configuration.
- Reset/fixture: a fresh page load per viewport, one synthetic `dev` profile, default 32-character generated password, proofs disabled. Before and after ciphertext differs because generation is randomized. No private plaintext is pictured.

## Before and after

| State | Desktop | Narrow |
| --- | --- | --- |
| Before: existing sealed-result flow | [Before](before-generate-desktop.png) | [Before](before-generate-narrow.png) |
| After: empty variable name, snippet copy disabled | [After](after-generate-desktop.png) | [After](after-generate-narrow.png) |
| After: invalid variable name | [After](after-invalid-name-desktop.png) | [After](after-invalid-name-narrow.png) |
| After: successful snippet copy | [After](after-copied-desktop.png) | [After](after-copied-narrow.png) |
| After: clipboard unavailable, manual-copy fallback | [After](after-manual-copy-desktop.png) | [After](after-manual-copy-narrow.png) |

The baseline was captured before behavior edits. [Before receipt](before-receipt.json) and [after receipt](after-receipt.json) record source, browser, role, reset conditions, assertions, and gaps.

## Completed server outcomes and repeatable checks

The local capture harness uses real Go servers embedding the built frontend. It generates and decrypts each of the five material kinds, checks expected plaintext length/format in memory without logging it, and parses copied YAML to confirm it contains exactly the generated Vault envelope. It also checks invalid-name gating, the manual-copy fallback, and absence of horizontal page overflow at both viewports.

The retained local harness is `.tmp/generate-snippet/capture.mjs`; baseline and result binaries are in the same scratch directory. With the repository's Node version, rerun:

```sh
node .tmp/generate-snippet/capture.mjs before 51affceebadf4b33844ed4268beb1c038357b244
node .tmp/generate-snippet/capture.mjs after 51affceebadf4b33844ed4268beb1c038357b244
npm test --prefix frontend -- --run src/GenerateWorkbench.test.tsx src/GenerateApp.test.tsx
```

The scratch harness and binaries are local verification tools, not tracked artifacts. The repository tests reproduce identifier validation, copy-only behavior, both clipboard failure paths, successful retry, state clearing, and suppression of late clipboard feedback.

## Coverage gaps

- Password is the representative rendered layout. Token, SSH keypair, age identity, and X.509 CSR results are live-checked and component-tested but not pictured.
- Clipboard success/failure is controlled at the browser platform boundary; the OS clipboard is not exercised. Clipboard rejection is component-tested; the equivalent unavailable fallback is pictured.
- Headless mouse/keyboard interaction is not a screen-reader announcement audit or a physical touch-device check. Native OIDC browser roles are not visually exercised.
- This slice changes no REST/MCP contract, server generation or cryptography, permissions, persistence, or download behavior.
