# Native authentication integration harness

This harness runs Vaultsmith against disposable Redis, Keycloak, and local-TLS containers. It generates all passwords, tokens, policy files, cookies, and certificates at runtime. No credential fixture is committed.

## Requirements

- Docker Engine with Compose v2
- Go 1.25 or newer
- Bash, `openssl`, and Python 3

## Automated run

Run from the repository root:

```sh
./scripts/integration-native.sh
```

The script checks:

- OIDC discovery and Authorization Code + PKCE login.
- Redis-backed sessions, CSRF-protected operations, and logout invalidation.
- Casbin profile filtering and encryption for an authorized user.
- Authentication with no authorization for a user with no matching group.

The automated run uses the `dev` profile. It prints a final success line when all checks pass.

## Interactive run

Keep the disposable stack running for browser testing:

```sh
./scripts/integration-native.sh --interactive
```

The script prints disposable credentials and certificate paths. Treat that output as sensitive.

1. Open the printed `https://localhost:18443/` URL.
2. Trust the printed IdP and Vaultsmith local CA certificates for this session if your browser requires it.
3. Sign in as `integration-user` and test `dev` and `prod`.
4. Sign out, then sign in as `integration-denied`.
5. Confirm that the denied user is authenticated but sees no profiles and receives `403` for a protected operation.
6. Press `Ctrl-C` in the harness terminal to stop the process and remove the containers and temporary state.

To retain the temporary directory for debugging, set `KEEP_INTEGRATION_TMP=1`. The directory contains generated credentials; remove it after use.

## Local endpoints

| Component | Address |
| --- | --- |
| Vaultsmith HTTPS edge | `https://localhost:18443/` |
| Vaultsmith HTTP process | `http://127.0.0.1:18080/` |
| Keycloak OIDC edge | `https://localhost:18081/` |
| Keycloak admin port | `http://127.0.0.1:18082/` |
| Redis | `127.0.0.1:16379` |
