# No-refresh session evidence

Genuine Chrome captures after a verified native login with a short-lived ID token
and no refresh credential. The baseline was captured before the authentication
fix. Screenshots show the login outcome; separate HTTP checks establish server
authorization and expiry rejection.

| Viewport | Before: premature re-login | After: authenticated workbench |
| --- | --- | --- |
| Desktop | [Before](before-desktop.png) | [After](after-desktop.png) |
| Mobile | [Before](before-mobile.png) | [After](after-mobile.png) |

## Capture conditions

- Base source: `aa1c5e6c0646cc080274ae96bac2a289e96470c2`.
- Before: application source unchanged; new regression tests only.
- After: the same base plus the five-file authentication/test/documentation fix.
  [verification.json](verification.json) records both capture-time diff hashes,
  the identical disposable browser-fixture source hash, screenshot checksums and
  measured dimensions. Evidence files were added after the captures.
- Google Chrome 156.0.8078.48; desktop 1440 × 1000 and mobile 390 × 844;
  device scale factor 1. The mobile image shows the initial viewport, not a full
  page scroll.
- Role: synthetic `admins`. Each run starts with fresh cookies in an isolated
  Chrome profile against the same synthetic TLS issuer/miniredis fixture.
- The issuer completes a signed Authorization Code/PKCE/nonce flow, with an ID
  token valid for five seconds and no refresh token. This is inside the existing
  one-minute early-refresh window; it is not a new application limit.
- Interaction: open app `/`, press the issuer's synthetic Continue button,
  then observe the outcome after the first verified callback. Inputs and results
  remain empty in every capture. No credentials or tokens are pictured.

The routes differ because of the bug: before, the successful `303` callback
leads to another issuer `/authorize` prompt, while session bootstrap reports
anonymous and protected profiles returns `401`. After, the browser remains at
app `/`, bootstrap is authenticated and profiles returns `200`.

Both result runs also complete a server decrypt request (`200`, expected
synthetic fixture result), then verify rejection after actual expiry (`401`).
The fixture executor records the operation; this does not establish cryptographic
interoperability. The separate native integration harness exercises actual Vault
operations with local Keycloak, Redis and Caddy.

## Repeatable checks and gaps

Run the retained no-refresh native HTTP regression with artifact output:

```sh
mkdir -p .tmp/no-refresh-http
go test -artifacts -outputdir "$PWD/.tmp/no-refresh-http" \
  ./backend/internal/httpapi -run '^TestNativeHTTPWithoutRefreshToken$' -count=1 -v
```

The resulting `receipt.json` records bootstrap/profiles/decrypt success before
expiry, decrypt denial afterward, and zero provider refresh calls. Run
`./scripts/integration-native.sh` for the broader real local native checks.
Both checks passed for the application source pictured here.

Owned fixture processes, Chrome profiles and private runtime material were
removed after testing. Other browsers, production providers, denied roles,
logout and expired-page rendering are not pictured. No frontend styling or
layout code changed; no full visual/accessibility audit is claimed.
