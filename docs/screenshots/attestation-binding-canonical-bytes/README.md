# Canonical binding-size evidence

Genuine Chrome captures of the same synthetic attested re-key request. Before
the service fix, a valid binding is rejected. After the fix, rotation completes
and returns its proof. No frontend source, layout or copy changed.

| Viewport | Before: rejected without output or proof | After: completed output and proof |
| --- | --- | --- |
| Desktop | [Before](before-desktop.png) | [After](after-desktop.png) |
| Mobile | [Before](before-mobile.png) | [After](after-mobile.png) |

## Capture conditions

- Base source: `2d8e912b064d10e1d6b3e277feeb9b1f93a19727`.
- Before: application source unchanged; regression test edits only.
- After: the same base plus the service canonical-size fix and those test edits.
  [verification.json](verification.json) records both capture-time diff hashes,
  changed files, screenshot checksums and measured image dimensions. The source
  diffs were matched again before publication; evidence files were added later.
- Chrome 156.0.8078.48; desktop viewport 1440 × 1000 and mobile viewport 390 ×
  844, device scale factor 1. Both are full-page captures, so image heights differ
  from viewport heights.
- Route: `http://127.0.0.1:18090/`. Role: anonymous in a task-owned, loopback-only
  auth-off development fixture. Each phase uses an isolated Chrome profile.
- Interaction: select dev → prod, enable Issue attestation, enter a selector of
  700 synthetic ampersands and the same synthetic input envelope, then submit.
  Both phases use the same generated synthetic signing keyring.

The selector is 700 UTF-8 bytes. Its canonical binding object is 715 bytes, but
Go's HTML-escaped marshal output is 4,215 bytes. The existing limits remain
1,024 bytes per field and 4,096 canonical bytes in total. Oversized bindings still
fail before Vault work or signing; changing those guards requires a separately
reviewed protocol/security change, not a fixture adjustment.

## Completed server outcome

The baseline browser request returned HTTP 400 with no output or proof. The
fixed request returned HTTP 200 with a re-keyed envelope and signed proof.
Separate requests to the running server confirmed that the destination decrypts
to the expected synthetic plaintext and that the proof verifies against the
original input, rotated output and exact binding. These results are recorded in
the receipt; screenshots alone are not the operation oracle.

Only synthetic ciphertext and proof material appear in these captures. No
password, private signing key, credential or production data is pictured or
included in the receipt. All task-owned browser and server processes stopped
after the check; disposable runtime fixtures are not committed.

## Repeatable regression checks and gaps

```sh
go test ./backend/internal/vaultservice ./backend/internal/httpapi \
  -run 'TestAttestedRotationBindingCanonicalSize|TestDelegatedNativeRESTAndMCPRotationsPreserveVerifiableProofs' \
  -count=1 -v
```

The retained regressions check canonical-size boundaries, rejection without
executor work, and verifiable proofs through literal/escaped REST and MCP
requests. They use synthetic executor fixtures; the browser/server checks above
used the real local application and Vault operations. `make smoke` and
`make smoke-attestation` also passed.

Tablet, other browsers, authenticated-role renderings and the separate Verify
screen are not pictured. No production deployment or complete visual or
accessibility audit is claimed.
