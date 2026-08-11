# ADR 0001: Establish the REST and MCP API foundation

- Status: Accepted
- Date: 2026-08-11
- Baseline release: Vaultsmith v0.4.0 (`881a42a248c71d740b8896d86e63b808bdf9bfa2`)

## Context

Vaultsmith v0.4.0 has a browser-oriented REST surface. `GET /api/v1/profiles` and `POST /api/v1/operations` combine HTTP decoding, credential handling, profile lookup, policy checks, limits, and Vault execution.

Vaultsmith must also support CI/CD service accounts, human OAuth clients, and MCP agents without weakening its current secret boundary. Profile passwords stay on the server. Submitted plaintext and Vault text stay in memory and are never retained as operation history.

A rolling deployment can serve old browser assets from one pod and API requests from another pod. The migration therefore needs a server bridge before the bundled UI moves to canonical routes.

## Decision

### One service and one network surface

Vaultsmith will keep one process, listener, container port, Kubernetes Service, and edge route. REST is always present because the bundled UI uses it. `/mcp` uses the same listener and is disabled by default.

The application will not infer or enforce deployment exposure, edge-to-backend TLS, or Service reachability. Operators own those controls. Deployment guidance will separate protocol-required client-visible HTTPS from operator-owned backend transport and network policy.

### Versioned REST contract

OpenAPI 3.1 at `api/openapi.yaml` is the source of truth for the v1 machine API.

Canonical routes are:

| Method | Path | Operation ID |
| --- | --- | --- |
| `GET` | `/api/v1/profiles` | `listProfiles` |
| `POST` | `/api/v1/profiles/{profileId}/encrypt` | `encryptValue` |
| `POST` | `/api/v1/profiles/{profileId}/decrypt` | `decryptValue` |
| `POST` | `/api/v1/rotations` | `rotateValue` |
| `POST` | `/api/v1/operations` | `legacyOperation` |

The legacy operation route remains for the lifetime of v1. It keeps its tagged request variants, `{ "value": ... }` success response, and ordinary error meanings. It will translate once into the shared service. It will not contain separate operation logic.

Health, readiness, login, callback, logout, and browser-session bootstrap routes are not part of the machine API contract.

### Caller and credential model

`auth.mode` remains the only authentication mode switch.

- In `native` mode, canonical REST accepts exactly one browser session or one OAuth Bearer access token.
- In `native` mode, MCP accepts Bearer access tokens only.
- In `native` mode, the legacy operation route accepts browser sessions only and rejects every `Authorization` header before reading the body.
- In `off` mode, REST and enabled MCP are anonymous. Every reachable caller has full operation access. Any supplied `Authorization` header is rejected because Vaultsmith did not validate it.
- Browser-session mutations require CSRF. Bearer and anonymous mutations do not.
- Bearer requests never fall back to session state and never touch Redis session state.
- Client-provided identity headers are ignored.

The transport-neutral caller contains only authentication kind, verified issuer and subject, verified groups, and verified OAuth scopes.

### OAuth scopes and policy

REST and MCP use the same exact, case-sensitive scopes:

- `vaultsmith.profile.read`
- `vaultsmith.encrypt`
- `vaultsmith.decrypt`
- `vaultsmith.rotate`

Bearer authorization is the intersection of the required scope and the existing Casbin policy. Session callers use Casbin only. Anonymous callers in off mode bypass both.

Rotate requires `vaultsmith.rotate`, decrypt policy on the source profile, and encrypt policy on the destination profile. It does not require the direct encrypt or decrypt OAuth scopes.

Profile discovery keeps successful-empty behavior for a caller without catalog policy access. A returned profile is visible only when at least one effective capability is true. The capability object contains `encrypt`, `decrypt`, `rotateSource`, and `rotateDestination`.

### OAuth resource

REST and MCP are one protected resource. In native mode, the canonical `PUBLIC_BASE_URL` origin is both the resource identifier and required access-token audience.

Native mode requires:

- An HTTPS `PUBLIC_BASE_URL` origin with no user information, query, fragment, or application path.
- An absolute HTTPS `OIDC_ISSUER_URL` with no user information, query, or fragment.
- Exact issuer metadata and absolute HTTPS JWKS, authorization, and token endpoints before the listener binds.
- Signed RFC 9068 JWT access tokens with the fixed algorithm allowlist `RS256`, `PS256`, `ES256`, and `EdDSA`.
- Exact issuer and audience matching, required time and token-profile claims, and a 60-second clock skew.

Vaultsmith serves one public root protected-resource metadata document in native mode. Pathful REST and MCP challenges deliberately omit `resource_metadata`.

### Shared service and admission

A transport-neutral caller package and `backend/internal/vaultservice` will own profile projection, validation, authorization, limits, operation dispatch, cancellation, and generic domain errors.

Every mutation has one full authorization point: service-owned `Prepare`. It requires the live request admission lease and returns a request-bound prepared operation. `Run` can execute only the already validated command.

A single non-blocking admission controller bounds concurrent body decoding and cryptographic work across canonical REST, legacy REST, and MCP. Capacity is fixed in code from a checked-in benchmark receipt. It is not a chart value.

### Wire rules and limits

Requests use strict JSON. Required fields must be present and non-null. Unknown fields, duplicate keys, trailing values, malformed raw UTF-8, unsupported content encoding, and invalid decoded path profile IDs are rejected.

The stable byte budgets are:

| Boundary | Budget |
| --- | ---: |
| Encrypt plaintext | 1 MiB |
| Decrypt or rotate Vault text | 5 MiB |
| Decrypted plaintext | 1 MiB |
| JSON request body | 8 MiB |
| HTTP headers | 16 KiB |

Canonical REST, legacy REST, and enabled MCP application requests receive a server-owned 30-second deadline before credential dispatch. The derived server budgets are 40-second read, 45-second write, and at least 50-second edge timeouts.

Every API error keeps the existing envelope:

```json
{
  "error": {
    "code": "operation_failed",
    "message": "vault operation failed"
  }
}
```

Stable status/code pairs are documented in OpenAPI. Messages remain safe human text. They never contain submitted values, profile configuration, token claims, or underlying Vault and token errors.

Encrypt and rotate are not automatically retried. No idempotency cache is added.

### MCP boundary

The only new Helm value is `mcp.enabled`, mapped to `MCP_ENABLED`; it defaults to false. Vaultsmith adds no second port or Service.

The MCP adapter supports only stateless Streamable HTTP protocol revision `2026-07-28` on `POST /mcp`, plus valid CORS preflight. It provides `server/discover`, `tools/list`, and `tools/call` for these tools:

- `list_profiles`
- `encrypt`
- `decrypt`
- `rotate`

Vaultsmith will use exported `github.com/modelcontextprotocol/go-sdk` v1.7.0 request, content, tool, and schema types as a library. Vaultsmith owns the one-pass HTTP/JSON-RPC facade and complete-result wire structs. It will not install the SDK stock HTTP handler, use reflection to mutate private fields, or reread request bodies.

Every non-empty `MCPGODEBUG` value is a startup error before listener binding. `MCP_ENABLED` and `MCPGODEBUG` are reserved profile password-environment names.

### Contract generation and compatibility

The v0.4.0 released REST surface is frozen at `api/baselines/v0.4.0.yaml`. The bridge contract is compared to this baseline. Later releases compare to the previous tagged `api/openapi.yaml` artifact.

Generation is intentionally small:

- `oapi-codegen` v2.8.0 generates Go DTO models only.
- `openapi-typescript` 7.13.0 generates TypeScript contract types from an isolated npm package pinned to TypeScript 5.9.3.
- `oasdiff` 1.28.0 is downloaded as a prebuilt archive and verified by checksum.

Generated files are committed. CI regenerates them, compiles the Go and TypeScript outputs, validates OpenAPI, checks for generated drift, and rejects unexpected or stale per-occurrence breaking-change fingerprints.

Response clients must ignore unknown properties. Requests remain strict. Additive routes and optional response properties remain v1. A removal, rename, or changed status meaning requires v2. The reconstructed baseline records the released value-typed decoder's omitted/null strings, empty or null variant-irrelevant members, and unvalidated profile-ID strings. The bridge intentionally rejects those forms. Each representable change has an exact reviewed `oasdiff` occurrence; case-insensitive Go field-name matching, duplicate-key, malformed raw UTF-8, content-encoding, credential-precedence, decrypted-output, and legacy middleware error-code hardening stays in prose and tests. Release notes must list all legacy hardening rather than claim byte-for-byte compatibility.

### Data and telemetry boundary

Vaultsmith will not persist operation records, submitted values, results, idempotency keys, or Bearer access tokens. Existing Redis browser sessions, including OIDC refresh tokens, remain the explicit persistence exception.

Logs, metrics, traces, errors, and new state must not contain request or response bodies, plaintext, Vault text, passwords, password-environment names, authentication values, tokens, claims, or underlying crypto errors.

## Consequences

- The bundled UI can remain on `/api/v1/operations` for the bridge release.
- Canonical external clients can start only after every serving replica runs the bridge release.
- MCP callers can start only after a separate enablement rollout completes on every replica.
- The next release can migrate the bundled UI to canonical routes without breaking old assets.
- The implementation gains explicit compatibility gates and generated DTOs without adopting a generated router or SDK.
- Native deployments must complete the [machine API operator preflight](../api-operator-preflight.md), including stricter HTTPS issuer, discovery, resource-origin, capacity, rollout, and rollback answers, before upgrade.
- Off mode remains intentionally dangerous when exposed. It does not gain forwarded-user identity or token validation.

## Rejected alternatives

- **A separate API listener or Service:** duplicates network and deployment policy without adding an authorization boundary.
- **A new exposure or trusted-edge mode:** cannot reliably describe operator-owned topology and would create false assurance.
- **Bearer support on the legacy route:** expands a compatibility surface and makes operation-specific scope selection ambiguous before strict body decoding.
- **An empty OpenAPI security alternative for off mode:** falsely advertises anonymous access for native deployments.
- **A generated server/router:** adds framework coupling where only shared DTOs are required.
- **Operation history or idempotency storage:** conflicts with Vaultsmith's no-retention boundary and cannot make randomized encryption deterministic.
- **MCP SDK stock HTTP handler:** does not satisfy the fixed protocol, one-read body, header, cache metadata, or Vaultsmith-owned error requirements.
- **Rotation attestations in this foundation:** signing-key lifecycle and verification semantics require a separate additive v1 decision.
