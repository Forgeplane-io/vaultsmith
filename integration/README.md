# Native authentication integration harness

This harness exercises the native OIDC path against disposable Redis and Keycloak containers. It generates all admin, client, user, CSRF, and Vault password values at runtime in a temporary directory; no credential fixture is committed.

Requirements:

- Docker Engine with Compose v2
- Go 1.25+
- `curl`, `openssl`, and Python 3

Run from the repository root:

```sh
./scripts/integration-native.sh
```

For a manual browser session, keep the disposable environment running instead of executing assertions:

```bash
./scripts/integration-native.sh --interactive
```

Open the printed `https://localhost:18443/` URL. The harness prints two disposable accounts: `integration-user` is in the operator group and can use `dev` and `prod`; `integration-denied` authenticates but has no group or Casbin permissions. It also prints the two local CA certificate paths. Exercise sign-in, profile listing, encrypt, decrypt, rotate, and sign-out as the authorized user; then sign in as `integration-denied`, verify the session is authenticated with an empty profile list, and verify protected operations return `403`. Press `Ctrl-C` in the harness terminal to stop Vaultsmith and remove all containers and temporary credentials. On macOS, you can open the two `.crt` files in Keychain Access and trust them in the Login keychain for this session; remove those temporary trust entries afterward.

The automated harness starts Keycloak with a private admin HTTP port on `127.0.0.1:18082`, exposes its OIDC issuer through a disposable local-TLS Caddy edge on `127.0.0.1:18081`, Redis on `127.0.0.1:16379`, the Vaultsmith process on `127.0.0.1:18080`, and a second local-TLS Caddy edge on `127.0.0.1:18443`. The generated IdP CA is trusted only through the temporary `OIDC_CA_FILE` configuration. It performs:

1. OIDC discovery and provider configuration;
2. Authorization Code + PKCE login through the Keycloak login form;
3. Redis-backed session bootstrap and CSRF token issuance;
4. Casbin group-to-role mapping and profile filtering for an authorized user;
5. authenticated no-permission login with an empty profile set and a forbidden operation;
6. an authorized encrypt request with origin/CSRF enforcement; and
7. CSRF-protected logout and session invalidation.

The script removes the temporary Compose project, volumes, binary, policy, cookies, and generated environment on exit. Do not point it at a shared Docker project or production credentials.
