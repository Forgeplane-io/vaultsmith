# Security policy

## Scope and threat boundary

Vaultsmith is an operator UI for Ansible Vault values. Native mode provides provider-neutral OIDC authentication, Redis-backed opaque sessions, CSRF protection, and profile-scoped Casbin authorization. Explicit `AUTH_MODE=off` is development-only, skips authentication, and logs a startup warning; it must not be exposed. TLS, private routing, rate limits, and Kubernetes access controls remain deployment responsibilities. NetworkPolicy and Kubernetes RBAC do not replace application authentication.

Vault passwords and submitted values are sensitive. Do not place passwords, plaintext values, ciphertext, kubeconfig data, registry credentials, or tokens in GitHub issues, pull requests, logs, screenshots, test fixtures, or support requests.

## Supported versions

Only the latest release on the default branch is supported for security fixes until a longer support policy is published. The first public release will establish the initial supported-version policy.

## Reporting a vulnerability

For a public repository, use GitHub's private Security Advisory workflow or the repository's configured private vulnerability-reporting channel. Do not open a public issue for an unpatched vulnerability.

Include only the minimum safe reproduction details. Redact all passwords, plaintext, encrypted values, tokens, hostnames, and personal data. If a report contains sensitive material, stop sharing it and request a private channel from the maintainers.

Maintainers will acknowledge a report, reproduce it with synthetic fixtures, coordinate a fix and disclosure date, and publish a security advisory when appropriate.
