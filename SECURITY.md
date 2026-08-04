# Security policy

## Scope and threat boundary

Vaultsmith is an operator UI for Ansible Vault values. It is **not** an authentication or authorization system. The service must remain behind an authenticated/private network boundary and TLS-terminating edge. NetworkPolicy, Kubernetes RBAC, and private source visibility do not replace application authentication.

Vault passwords and submitted values are sensitive. Do not place passwords, plaintext values, ciphertext, kubeconfig data, registry credentials, or tokens in GitHub issues, pull requests, logs, screenshots, test fixtures, or support requests.

## Supported versions

Only the latest release on the default branch is supported for security fixes until a longer support policy is published. The first public release will establish the initial supported-version policy.

## Reporting a vulnerability

For a public repository, use GitHub's private Security Advisory workflow or the repository's configured private vulnerability-reporting channel. Do not open a public issue for an unpatched vulnerability.

Include only the minimum safe reproduction details. Redact all passwords, plaintext, encrypted values, tokens, hostnames, and personal data. If a report contains sensitive material, stop sharing it and request a private channel from the maintainers.

Maintainers will acknowledge a report, reproduce it with synthetic fixtures, coordinate a fix and disclosure date, and publish a security advisory when appropriate.
