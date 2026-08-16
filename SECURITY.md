# Security policy

## Scope

Vaultsmith handles Ansible Vault values and passwords. Native mode provides OIDC authentication, Redis-backed opaque sessions, CSRF protection, and profile-scoped Casbin authorization. `AUTH_MODE=off` disables authentication and CSRF protection and is for private local development only.

TLS termination, private routing, rate limits, request-body logging, and Kubernetes access controls remain deployment responsibilities. NetworkPolicy and Kubernetes RBAC do not replace application authentication.

Do not put passwords, plaintext, ciphertext, generated tokens, private keys, non-synthetic public keys or CSRs, kubeconfig data, registry credentials, authentication tokens, or personal data in issues, pull requests, logs, screenshots, fixtures, or support requests.

## Supported versions

Security fixes target the latest release on the default branch. Older releases may not receive fixes.

## Report a vulnerability

Do not open a public issue for an unpatched vulnerability. Use GitHub's private Security Advisory workflow or another private reporting channel provided by the maintainers.

Include only the minimum safe reproduction details. Redact secrets, plaintext, encrypted values, tokens, hostnames, and personal data. Maintainers will reproduce reports with synthetic fixtures, coordinate disclosure, and publish an advisory when appropriate.
