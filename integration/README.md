# Native authentication integration harness

This harness runs Vaultsmith against disposable Redis, Keycloak, and local-TLS containers. It generates all passwords, tokens, policy files, cookies, and certificates at runtime. No credential fixture is committed.

## Requirements

- Docker Engine with Compose v2; the Linux override requires support for `!reset`.
- Go matching `go.mod`.
- Bash, `openssl`, and Python 3; Node matching `.nvmrc` for the browser lifecycle regression.

Before starting, ensure the ports below and the harness's Compose project are not owned by another process. Do not reuse another test's resources.

## Automated run

Run from the repository root:

```sh
python3 -B -m unittest discover -s scripts -p integration_native_test.py
node --test scripts/delegated-rekey-browser-test.mjs
./scripts/integration-native.sh
```

The focused regressions check the host-launch environment, merged Compose topology, and browser ownership/cancellation with controlled stub processes; they do not start the native stack or real Chrome. The native run then checks:

- OIDC discovery, Authorization Code + PKCE login, Redis sessions, CSRF, and logout.
- Operator access and an authenticated user with no matching group.
- Separate lane-only user and service-account identities, with no inherited operator rights.
- Offline owner grant of exactly `dev → prod` and `stage → archive`, ordered discovery (including empty destination arrays), ordinary and attested rotation, private plaintext comparison, and proof binding.
- Session REST, canonical Bearer REST, and Bearer MCP text/structured-result parity.
- Direct Encrypt/Decrypt/Generate, crossed/reverse/self/unknown pairs, missing scopes, mixed credentials, legacy Bearer, and MCP-session denials.
- Atomic metadata-changing owner removal, fresh denial, preservation of the other lane, unavailable missing/invalid policy, and valid-policy recovery without an authorization bypass.
- New-binary/old-policy direct access without implicit rotation. A pinned old-binary rollback probe requires a separately built baseline; this script does not build or launch an old revision.

Only synthetic `dev`, `prod`, `stage`, and `archive` profiles are used. The owner is a local fixture-policy editor, not an administrative API. Policy changes use atomic replacement with changed metadata; an already accepted acquisition may complete under its earlier snapshot.

The script prints a final success line after its assertions. Safe status/boolean receipts are written to `.tmp/delegated-rekey-step6/native.json`, identified by HEAD and a SHA-256 over the tracked diff plus the named focused fixture/test files. Raw output, especially interactive credentials and failure diagnostics, is sensitive: capture it privately with `umask 077`, do not publish it, and remove it after testing.

## Platform topology

The host application always listens on `127.0.0.1:18080`.

- **macOS:** the base Compose bridge edge publishes only `127.0.0.1:18443` and reaches the host through `host.docker.internal`. Docker Desktop's optional host-network feature is not required or enabled.
- **Linux:** the script also selects `docker-compose.linux.yml`. Only the application Caddy edge uses host networking; inherited published ports and host aliases are explicitly cleared. `Caddyfile-linux` binds `127.0.0.1:18443`, proxies host loopback, disables the admin API and automatic HTTP redirects, and skips trust installation. Redis, Keycloak, and the IdP edge retain their loopback-published bridge topology. The healthcheck uses the image's existing curl to require both the IPv4 HTTPS edge and `http://127.0.0.1:18080/readyz`; explicit resolution preserves the HTTPS `localhost` TLS/Host identity and the existing fixture-only certificate-check mode.

Unsupported Compose merge tags must fail the focused check; do not work around them by retaining published ports with host networking or broadening listeners. Both Caddy variants retain forwarded-header sanitation and block public health/readiness routes.

Normal CI may pull missing images. For a cached-only local qualification, apply an invocation-local private Docker wrapper that adds `compose up --pull never`; do not change CI's pull behavior or install/upgrade Docker to bypass a failed preflight.

## Interactive and concrete Chrome run

```sh
./scripts/integration-native.sh --interactive
```

The automated assertions run first. The script then prints disposable credentials and certificate paths and keeps its owned stack running. Treat that output and the temporary directory as sensitive.

For a manual journey, open `https://localhost:18443/` in an isolated browser session. Accept the fixture TLS certificates only for that session; do not install them into system trust. Test the operator and denied identities, then the lane-only delegate. Press `Ctrl-C` in the harness terminal to stop and remove its containers and temporary state.

The concrete macOS Chrome acceptance uses an existing Chrome installation and Node 22's native WebSocket support, with no browser dependencies or global TLS/trust changes:

```sh
VAULTSMITH_NATIVE_CONTEXT=/path/to/owned-private-directory/acceptance-context.json \
  node integration/delegated-rekey-browser.mjs
```

Use the context generated by that interactive harness, not a reconstructed or repaired context. It contains credentials and protected test material. The script launches a separate temporary Chrome profile with loopback-only DevTools, allows only the fixture app/IdP origins, and applies TLS acceptance only to that browser session. It verifies lane-only login, source-dependent destinations, ordinary/attested server outcomes, owner removal, result invalidation/no automatic replay, Clear, and server logout. It rejects mismatched harness/source identities before launching Chrome. On failure or SIGINT/SIGTERM it cancels pending work, terminates and reaps only its owned browser child, removes the profile, and exits unsuccessfully; cleanup does not depend on CDP. Status/boolean receipts go to `.tmp/delegated-rekey-step6/browser.json`; screenshots contain only empty/cleared workbench states, never values, proofs, credentials, or the session header.

The Chrome run removes the delegate's `dev → prod` lane. Restart the disposable harness for a fresh fixture; do not silently restore a changed live input. `KEEP_INTEGRATION_TMP=1` retains sensitive temporary state for explicit debugging only; remove it afterward.

Before sign-out, the Chrome run removes only the readable CSRF cookie and opens
a second tab to issue its replacement while preserving authentication. It checks
that sign-out from the original tab ends the backend session and retains the
empty sign-out state in `native-browser-csrf-logout.png` beside the other browser
receipts. This exercises real shared-cookie replacement, not browser restart or
session-cookie persistence across shutdown.

## Local endpoints

| Component | Address |
| --- | --- |
| Vaultsmith HTTPS edge | `https://localhost:18443/` |
| Vaultsmith HTTP process | `http://127.0.0.1:18080/` |
| Keycloak OIDC edge | `https://localhost:18081/` |
| Keycloak admin port | `http://127.0.0.1:18082/` |
| Redis | `127.0.0.1:16379` |
