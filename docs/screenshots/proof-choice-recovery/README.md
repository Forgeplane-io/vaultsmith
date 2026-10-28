# Proof-choice recovery evidence

The selected attestation requirement stays visible when a later capability check
reports it unavailable. Input and binding drafts remain intact. Re-key still
requests the selected attestation; only explicitly unchecking it removes that
requirement from the next manual request.

## Genuine browser captures

All Vault values, bindings and identities are synthetic. Captures show the
workbench card; unchanged navigation is omitted.

| State | Desktop | Mobile |
| --- | --- | --- |
| Before: selected requirement hidden after recovery | [Before](before-unavailable-desktop.png) | [Before](before-unavailable-mobile.png) |
| After: requirement, snapshot warning and binding visible | [After](after-unavailable-desktop.png) | [After](after-unavailable-mobile.png) |
| After: explicit opt-out and completed rotation | [Result](after-opt-out-result-desktop.png) | [Result](after-opt-out-result-mobile.png) |
| After: capability restored, retained binding, warning removed | [Restored](after-restored-desktop.png) | Not captured |

## Conditions and server outcome

- Base/HEAD: `fa6ceac57c1782be60360d298c76d0a4e7b9c77c`.
- Before: production source unchanged; only `frontend/src/App.test.tsx` edited.
- After: the same base plus `frontend/src/App.tsx`, its regression tests and the
  rebuilt `backend/web/dist/index.html`. This evidence directory was added after
  capture. [Before](before.json) and [after](after.json) receipts record source
  diff hashes, embedded asset hashes, screenshot sizes/checksums and API outcomes.
- Google Chrome `156.0.8078.74`; desktop viewport `1440 × 1000`, mobile
  `390 × 844`, device scale factor `1`. Capture heights follow the workbench.
  Both use `/` on an ephemeral loopback HTTPS origin recorded in the receipts.
- Each run owns an isolated Chrome profile and a real HTTP handler fixture with
  native session authentication, miniredis, policy authorization and configured
  Vault executors. The principal is seeded: this is **not** an OIDC login test.
  Both runs reuse the same synthetic input envelope and fixture phases.
- Phases: allowed `a → x` with proofs enabled; denied pair plus an unavailable
  profiles handler; explicit retry discovers `a → y` with proofs disabled; later
  recovery returns proofs enabled. Pair reselection remains manual.
- With the requirement selected, the server returns `503 feature_unavailable`
  before any Vault work. After explicit opt-out, rotation returns `200`, performs
  the actual source decrypt/destination encrypt, and destination decryption
  independently matches the synthetic input. No request is automatically replayed.
- Owned server/browser processes exited; private contexts, session cookies,
  synthetic input file and Chrome profiles were removed.

## Checks and limits of coverage

The focused regression failed before the production edit and passed afterward.
`make lint`, `npm test --prefix frontend -- --run` (all 264 tests),
`make typecheck`, `npm run build --prefix frontend`, and
`SMOKE_PORT=54713 make smoke` passed. Lint reported four warnings in unchanged
`vaultFormat.ts` and `ansibleSnippet.ts`. The local repeatable browser fixture
and exact command logs remain in the task worktree's ignored `.tmp/evidence/`.

The focused command was:

```sh
npm test --prefix frontend -- --run src/App.test.tsx -t 'preserves proof intent and binding across capability recovery|does not offer a new proof requirement'
```

It recorded two expected failures before the fix and three passes afterward.
For each `before` / `after` phase, `bash .tmp/evidence/compile-runtime.sh PHASE`
built the frontend and the overlay HTTP fixture, then
`node .tmp/evidence/proof-choice-browser.mjs PHASE` completed the browser/server
journey successfully. `git diff --check` passed. A final Node check verified all
retained image hashes/dimensions, these links, the after-source diff hash and
the embedded asset hashes against the receipts.

An initial disposable recorder hid the HTTP writer's deadline capability and
caused setup failure. Its wrapper was corrected before accepting either capture;
that failed attempt is not evidence of the product bug.

Other browsers, a full accessibility audit, real OIDC login/provider recovery,
and a mobile capture of the restored state were not exercised. Full Go tests,
vet/race, native OIDC integration and contract checks were not rerun: no backend,
authentication, REST/MCP contract, policy, deployment or release behavior changed.
