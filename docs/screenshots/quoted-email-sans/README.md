# Quoted email SAN evidence

Genuine Chrome captures of the same synthetic X.509 Generate request. Before
the validator fix, the quoted email is rejected. Afterward, the server returns
a sealed private key and public CSR without changing the submitted email bytes.
No frontend source, layout or copy changed.

| Viewport | Before: rejected without output | After: sealed key and CSR |
| --- | --- | --- |
| Desktop | [Before](before-desktop.png) | [After](after-desktop.png) |
| Mobile | [Before](before-mobile.png) | [After](after-mobile.png) |

## Capture conditions

- Base source: `962e965f9bb603c775c0c36d1690f0c41963356c`.
- Before: application source unchanged; generator/HTTP regression test edits only.
- After: the same base plus the validator fix and those test edits.
  [verification.json](verification.json) records both capture-time diff hashes,
  changed files, screenshot checksums and measured image dimensions. The source
  diffs were checked again before publication; evidence files were added later.
- Chrome 156.0.8078.74; desktop viewport 1440 × 1000 and mobile viewport 390 ×
  844, device scale factor 1. Captures are cropped from SAN settings through the
  submission error or sealed result; unchanged navigation/subject fields are
  omitted. Image dimensions therefore differ from viewport dimensions.
- Route: `http://127.0.0.1:18090/`. Role: anonymous in a task-owned, loopback-only
  auth-off development fixture. Each phase uses an isolated Chrome profile and
  the same synthetic profile/password configuration.
- Interaction: Generate X.509 CSR, dev profile, Ed25519, sole email SAN
  `"ops team"@example.test`, then submit. Generated key material is intentionally
  random; the baseline never reaches generation because validation rejects it.

## Completed server outcome

The baseline browser request returned HTTP 400 with no output. After the fix,
the request returned HTTP 200 with Vault ciphertext and a public CSR. A separate
request decrypted that ciphertext through the running server. An independent
standard-library oracle then verified the exact quoted email SAN, CSR signature,
private/public key relation and advertised fingerprint. The receipt records
these checks; screenshots alone are not the operation oracle.

OpenSSL independently verified the live-generated CSR signature. Its synthetic
public CSR is retained as [after-public.csr.pem](after-public.csr.pem), so that
check is repeatable from the repository root:

```sh
openssl req -verify -noout \
  -in docs/screenshots/quoted-email-sans/after-public.csr.pem
```

Only synthetic ciphertext and a public CSR appear in the captures. No private
key, password or credential is pictured or committed. All task-owned browser
and server processes stopped after the check. Browser profiles and private
runtime material are not published.

## Repeatable regressions and gaps

```sh
go test ./backend/internal/generate ./backend/internal/httpapi \
  -run 'TestGenerateX509CSRPreservesEmailSpellings|TestGenerateX509CSRRejectsInvalidIdentityBeforeRandomness|TestGenerateSANSpellingsThroughRESTAndMCP' \
  -count=1 -v
```

The retained tests check original SAN/DER bytes, quoting/escapes, signature and
key matching, sealed output and rejection of forbidden forms before randomness
or encryption. REST/MCP handler fixtures use synthetic executors with real Vault
cryptography. The browser/server journey above uses the real local application.

Existing byte/ASCII/control/whitespace/duplicate guards remain unchanged. The
email limit is still 253 submitted ASCII bytes, including quotes/escapes, as
specified in ADR 0002. Overflow still fails before randomness or encryption;
changing this protocol safeguard requires separate review.

External CA acceptance, authenticated browser rendering, tablet/other browsers
and production deployment are not qualified. No complete visual/accessibility
audit is claimed.
