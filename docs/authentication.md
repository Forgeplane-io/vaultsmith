# Authentication and authorization

Vaultsmith has two authentication modes. Select the mode for the deployment boundary, not per request.

| Mode | Browser clients | Machine clients | Authorization |
| --- | --- | --- | --- |
| `native` | OIDC login, opaque Redis-backed session, and CSRF on mutations | RFC 9068 JWT Bearer access token | Exact token scopes and the same Casbin policy |
| `off` | Anonymous | Anonymous | Every reachable caller can use every profile and operation |

Use `native` for public or shared deployments. Use `off` only behind a deliberately trusted private boundary.

## Session or Bearer

Use a session for the bundled browser UI:

1. `GET /auth/login` starts OIDC Authorization Code with PKCE.
2. Vaultsmith stores the verified identity and refresh state in its Redis-backed session.
3. `GET /api/v1/session` returns the CSRF token.
4. Browser mutations send the session cookie and `X-CSRF-Token`.

Authenticated browser sessions carry a versioned binding to the configured
`OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`, and canonical `PUBLIC_BASE_URL` origin.
Vaultsmith validates that binding before returning an identity or refreshing a
session, including after reloading it under the refresh lock. A different
binding, missing or malformed binding, or unsupported binding version causes
session destruction and requires a new verified OIDC login. Old identities and
groups are never adopted into the current configuration.

Binding version 2 also identifies sessions whose stored expiry is the deadline
of verified identity/group claims, never a refreshed OAuth token deadline.
Upgrading from an earlier binding version (or no binding) signs out existing
browser sessions on their next authenticated request. An old stored expiry may
already have been extended without fresh claims, so Vaultsmith does not adopt it.
Changing any of the three binding components also requires reauthentication.
See the [rollout and rollback
guidance](deployment.md#upgrade-and-rollback). This does not change Bearer token
authentication or its audience and scope requirements.

### Browser claim freshness and provider requirements

Browser identity and groups are authoritative only until the verified ID
token's expiry. Refreshing OAuth credentials without a new ID token can rotate
the refresh token while those claims remain valid, but cannot extend their
deadline. At that deadline, a refresh must supply a newly verified ID token;
otherwise Vaultsmith destroys the session and requires interactive login.
Protected operations return generic `401 unauthorized` without executing the
operation. A provider exchange or session-store outage fails closed with `503`,
not cached authorization.

Providers that support uninterrupted browser sessions must return refreshed ID
tokens with current groups. Vaultsmith verifies the signature, issuer, browser
client audience, and expiry, and requires the same issuer and subject as the
existing session. Fresh groups replace cached groups; an absent groups claim
grants no permissions, and malformed claims are rejected. Providers that omit
refreshed ID tokens remain usable but require login at the original claim
deadline, even if OAuth credentials are still valid.

This is not immediate membership revocation: existing verified groups may be
used until their claim deadline. Absolute and idle session lifetimes still bound
the session, including when refresh supplies a new ID token. Confirm your
provider's refresh and revocation behavior before rollout.

### Machine clients

Use a Bearer access token for canonical REST and MCP machine clients:

- `GET /api/v1/profiles`
- `POST /api/v1/profiles/{profileId}/encrypt`
- `POST /api/v1/profiles/{profileId}/decrypt`
- `POST /api/v1/rotations`
- `POST /api/v1/generate`
- `POST /api/v1/attestations/verify`
- `POST /mcp` when enabled

Bearer requests do not load or update Redis sessions. They do not use CSRF and do not receive cookies. The deprecated `POST /api/v1/operations` legacy operation endpoint stays session-only in native mode for compatibility callers.

Do not send a session cookie and `Authorization` together. Vaultsmith rejects mixed or duplicate credentials. It never falls back to a session or anonymous access after an invalid Bearer token.

### Bearer signing-key trust expiry

The process-local access-token JWKS cache honors usable issuer freshness
(`s-maxage`, `max-age`, or `Expires`) after accounting for the response's `Date`
and `Age`. It does not raise short positive freshness to a minimum. The existing
local freshness ceiling is six hours. Vaultsmith selects the first usable
freshness source in that order; malformed higher-priority directives do not hide
usable lower-priority metadata. Responses without usable freshness metadata
retain the existing one-hour fallback.

At expiry, Vaultsmith revalidates the key set. A refresh failure returns `503`
with `temporarily_unavailable` for REST and enabled MCP unless the issuer explicitly
supplied a valid positive `stale-if-error`. That grace runs from cache expiry and
is capped at the existing one-hour local ceiling. Absent, zero, negative, or
malformed `stale-if-error` grants no grace. Delta-seconds must contain decimal
digits, optionally within balanced quotes; signs or spaces within quotes are
invalid. Zero or already-consumed freshness still permits explicit grace only
until issuer-derived expiry plus the bounded grace; it is not a `no-cache`
directive. `no-store`, `no-cache`,
`must-revalidate`, `proxy-revalidate`, and usable `s-maxage` prevent stale fallback.
Conditional `304` revalidation retains stored directives unless replaced by the
issuer's response headers.

A successful refresh removing a signing key rejects tokens signed by that key,
even inside previously permitted grace. Removal is not immediate revocation:
cached trust may last through remaining freshness and any explicit permitted
outage grace. Short freshness increases issuer requests and makes machine-client
availability depend more closely on issuer availability. This cache policy does
not change browser-session or ID-token verification.

## Resource and audience

`PUBLIC_BASE_URL` is one client-visible HTTPS **origin**, for example:

```text
https://vault.example.test
```

It must not contain a path, user information, query, or fragment. Vaultsmith uses this exact origin as:

- the protected resource identifier;
- the required JWT audience for REST and MCP;
- the same-origin base for native browser requests.

The browser OIDC client ID is not the API audience. A token for another audience is rejected.

## Protected-resource discovery

In native mode, the root metadata document is:

```text
GET https://vault.example.test/.well-known/oauth-protected-resource
```

It publishes the resource origin, configured authorization-server issuer, Bearer methods, and supported scopes. It is absent in `off` mode.

A client can fetch the root document proactively. An MCP client that first derives a path-specific location from `/mcp` must fall back to the root well-known document. Vaultsmith does not serve a path-specific metadata document.

Bearer challenges on protected paths include the canonical `resource_metadata` parameter for the root document. They also contain, when applicable, a safe OAuth error and exact required scope. Clients must use the advertised root document rather than construct a pathful metadata URL from a challenge.

## Exact scopes

Scopes are case-sensitive.

| Scope | REST use | MCP use |
| --- | --- | --- |
| `vaultsmith.profile.read` | List visible profiles | `server/discover`, `tools/list`, `list_profiles` |
| `vaultsmith.encrypt` | Encrypt or Generate into a destination profile | `encrypt`, `generate_password`, `generate_token`, `generate_ssh_keypair`, `generate_age_identity`, `generate_x509_csr` |
| `vaultsmith.decrypt` | Decrypt | `decrypt` |
| `vaultsmith.rotate` | Rotate between profiles | `rotate` |
| `vaultsmith.attestation.verify` | Verify a rotation attestation | `verify_rotation_attestation` |

A scope permits a class of operation. It does not grant access to a profile. Casbin must also permit the verified caller's groups to use the requested profile. Rotation requires decrypt policy on the source and encrypt policy on the destination. Generate adds no scope or per-kind policy: REST and direct MCP tool calls require `vaultsmith.encrypt` and encrypt policy on the destination profile. `vaultsmith.profile.read` is needed separately to browse profiles or list MCP tools.

A missing fixed scope returns `403` with an `insufficient_scope` Bearer challenge before Vaultsmith reads the request body. A missing Casbin grant returns a generic `403 forbidden` without an insufficient-scope challenge because adding a scope cannot satisfy policy.

## Identity and groups

Vaultsmith identifies a caller by the verified `(iss, sub)` pair. It reads the configured groups claim as an array of non-empty strings. Each group is available to Casbin as `group:<group>`.

Example policy:

```csv
g, group:vaultsmith-operators, role:operator
p, role:operator, profiles, profiles:list, allow
p, role:operator, profile:dev, encrypt, allow
p, role:operator, profile:dev, decrypt, allow
```

`client_id` is useful token metadata, but it does not grant a role. A client-credentials token still needs a stable subject, exact scopes, and the groups required by policy. A valid profile-read token with no authorized groups receives a successful empty profile list.

## Delegated-user tokens

For a CLI acting for a user, use an authorization flow supported by the issuer, normally Authorization Code with PKCE or Device Authorization. Request the Vaultsmith resource and only the scopes needed for the task.

Conceptual authorization request values:

```text
resource=https://vault.example.test
scope=openid vaultsmith.profile.read vaultsmith.decrypt
```

The issuer must place `https://vault.example.test` in the access-token audience. The token subject and groups represent the user. Do not use an ID token as an API token.

## Client-credentials tokens

For unattended automation, register a confidential client at the same issuer. Configure a stable service-account subject and groups in the issuer. Request the Vaultsmith resource and least-privilege scopes.

Conceptual token request:

```text
grant_type=client_credentials
resource=https://vault.example.test
scope=vaultsmith.profile.read vaultsmith.rotate
```

Inject the client secret through the process secret store. Do not place it in a command argument, checked-in file, ticket, or log. The token response is sensitive. Do not log it.

Providers differ in how they express `resource`, audience mappers, service-account groups, and client authentication. Verify the issued token against Vaultsmith before rollout:

- `typ` is `at+jwt` or a supported access-token media type;
- issuer matches `OIDC_ISSUER_URL` exactly;
- audience is the `PUBLIC_BASE_URL` origin;
- subject is non-empty;
- scopes and groups are arrays/strings in the documented form;
- signing algorithm and key are accepted by the configured issuer discovery and JWKS.

## `auth.mode: off`

Off mode removes authentication, sessions, CSRF, token validation, and Casbin policy checks. Every caller that can reach Vaultsmith can list profiles, encrypt, decrypt, rotate, Generate every supported material kind, and use enabled MCP tools. Proofs are controlled separately by `proofs.enabled`: when disabled, no keyring Secret is required and attestation issuance and verification return stable feature-unavailable responses. Normal encrypt, decrypt, rotate, and Generate behavior remains available.

When `AUTH_MODE=off` is explicitly selected, an unset or empty `HTTP_ADDR` defaults to `127.0.0.1:8080` (IPv4 loopback). Native mode's implicit default remains `:8080`. Nonempty explicit addresses are used unchanged, including wildcard and IPv6 addresses. An explicit bind is an operator choice, not an authentication boundary; the off-mode warnings still apply. Helm supplies an explicit pod listener address, so its binding is unchanged.

Off-mode configurations that relied on the implicit wildcard listener must now set their intended `HTTP_ADDR` explicitly. Do not use this override to expose an unauthenticated service or as a fallback for native authentication failures.

Consequences:

- CORS restricts browsers only. It does not protect against non-browser clients.
- Forwarded user or group headers do not create an application identity.
- An authenticating gateway in front of off mode is still one anonymous Vaultsmith caller.
- Vaultsmith rejects any `Authorization` header instead of pretending to validate it.
- A network or gateway error can expose all configured operations.

Do not use off mode as an authentication migration step, outage workaround, or rollback mechanism.

## Related documents

- [Rotation attestation operator runbook](attestations.md)
- [Static REST API reference](api-reference.md)
- [Safe REST and MCP client examples](api-clients.md)
- [Deployment and gateway controls](deployment.md)
- [Machine API rollout checklist](api-operator-preflight.md)
