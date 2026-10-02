# Workbench cleanup visual evidence

Genuine full-page captures from the embedded app, using only synthetic fixtures.
The baseline was recovered from pre-edit source after the changes were made.

| Capture context | Value |
| --- | --- |
| Before source | `132ce733e3405c0b1c83effae29a0e1aac1511a2` |
| After source | `e440506ad3397039abcf34aaf02255e678174f1b` |
| Browser | Headless Chrome 154.0.8037.98 |
| Route | `/`, Generate and Verify views |
| Viewports | Desktop 1440 × 1000; narrow layout 390 × 844; device scale 1 |
| Role | Loopback-only authentication-off development, proofs enabled with a disposable synthetic keyring |
| Build | Both versions rebuilt using the same installed dependencies and Node 22.23.2 |
| Uncommitted source changes | None; baseline build updated its generated asset reference only |

## Equivalent fixture states

Each capture starts from a fresh page load and the same synthetic `dev` profile.

- **Generate:** default password parameters; the real backend completed Generate
  with HTTP 200, and the sealed result decrypted successfully to a 32-character
  value. A loopback test proxy held response delivery, keeping the browser busy.
  The before/after capture shows the same pending-delivery state, without showing
  any generated value. After capture, Cancel was activated, its unknown-outcome
  warning checked, and the held response released. No late result appeared.
  This intentionally proves browser cancellation cannot promise server rollback.
- **Verify:** the attestation editor contains 196,609 synthetic ASCII characters,
  one byte above its unchanged 196,608-byte limit. The other two editors contain
  explicit synthetic placeholders. The after capture shows the specific local
  error and remediation; browser checks confirmed only Attestation was invalid.

The local capture action was:

```sh
node .tmp/pr-cleanups/capture.mjs \
  132ce733e3405c0b1c83effae29a0e1aac1511a2 \
  e440506ad3397039abcf34aaf02255e678174f1b
```

The disposable capture harness and its receipt remain in `.tmp/pr-cleanups/`;
they are not application code or distributed test tooling. All test servers and
the isolated browser were stopped, and the synthetic keyring was removed.

## Before and after

| State | Before | After |
| --- | --- | --- |
| Generate, desktop | [Before](before-generate-desktop.png) | [After](after-generate-desktop.png) |
| Generate, narrow | [Before](before-generate-mobile.png) | [After](after-generate-mobile.png) |
| Verify, desktop | [Before](before-verify-desktop.png) | [After](after-verify-desktop.png) |
| Verify, narrow | [Before](before-verify-mobile.png) | [After](after-verify-mobile.png) |

## Coverage gaps

- Original/Rotated Vault oversized errors and the normal operation input error
  are not pictured; the same field-level pattern is covered by integration tests.
- The cancellation warning is asserted but not separately pictured.
- Native OIDC users, real screen-reader announcements, touch-device behavior,
  and other viewport sizes were not exercised. The narrow capture is a desktop
  browser resized to the stated CSS viewport, not physical-device verification.

Repeatable behavioral checks are in `App.test.tsx` and `GenerateApp.test.tsx`:

```sh
npm test --prefix frontend -- --run src/App.test.tsx src/GenerateApp.test.tsx
```
