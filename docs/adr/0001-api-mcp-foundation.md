# ADR 0001: REST and MCP API contract

- Status: Accepted
- Date: 2026-08-11
- Baseline: Vaultsmith v0.4.0 (`881a42a248c71d740b8896d86e63b808bdf9bfa2`)

## Context

Vaultsmith v0.4.0 exposes `GET /api/v1/profiles` and `POST /api/v1/operations` to the bundled browser UI. The handlers decode HTTP requests, select credentials and profiles, enforce policy and limits, and run Vault operations.

The new API must also support OAuth clients and MCP agents. These callers must use the same profiles, policy, limits, and operation code as the UI. Profile passwords stay on the server. Vaultsmith does not store submitted plaintext, Vault text, or operation results.

During a rolling deployment, one pod can serve old UI assets while another handles the request. The legacy route must therefore keep working until every pod and the bundled UI have moved to the new routes.

## Decision

### Process and network

Vaultsmith keeps one process, listener, container port, Kubernetes Service, and edge route. REST stays available because the UI uses it. MCP uses `POST /mcp` on the same listener and is disabled by default.

Vaultsmith validates protocol-facing URLs. It does not decide whether the Service is public, require edge-to-backend TLS, or control network reachability. Those remain deployment concerns.

### REST routes

`api/openapi.yaml` defines the v1 machine API.

| Method | Path | Operation ID |
| --- | --- | --- |
| `GET` | `/api/v1/profiles` | `listProfiles` |
| `POST` | `/api/v1/profiles/{profileId}/encrypt` | `encryptValue` |
| `POST` | `/api/v1/profiles/{profileId}/decrypt` | `decryptValue` |
| `POST` | `/api/v1/rotations` | `rotateValue` |
| `POST` | `/api/v1/operations` | `legacyOperation` |

`POST /api/v1/operations` remains available throughout v1. It keeps the released request variants, `{ "value": ... }` response, and status meanings, but translates each request into the shared service instead of maintaining separate operation code.

Health, readiness, login, callback, logout, and browser-session bootstrap routes are outside this contract.

### Authentication and authorization

`auth.mode` remains the only authentication mode switch.

- In `native` mode, canonical REST accepts exactly one browser session or one OAuth Bearer token.
- In `native` mode, MCP accepts Bearer tokens only.
- In `native` mode, the legacy route accepts browser sessions only and rejects an `Authorization` header before reading the body.
- In `off` mode, REST and enabled MCP are anonymous. Any caller that can reach them can run every operation. Vaultsmith rejects supplied `Authorization` headers because it cannot validate them in this mode.
- Browser-session mutations require CSRF. Bearer and anonymous requests do not.
- Bearer requests never fall back to a session or read or write Redis session state.
- Vaultsmith ignores client-supplied identity headers.

The shared caller record contains the authentication kind, verified issuer and subject, verified groups, and verified OAuth scopes.

REST and MCP use these case-sensitive scopes:

- `vaultsmith.profile.read`
- `vaultsmith.encrypt`
- `vaultsmith.decrypt`
- `vaultsmith.rotate`

A Bearer caller needs both the OAuth scope for the operation and permission from the existing Casbin policy. Session callers use Casbin only. Anonymous callers in `off` mode bypass both checks.

Rotation needs `vaultsmith.rotate`, decrypt permission on the source profile, and encrypt permission on the destination profile. It does not also need the direct encrypt and decrypt scopes.

Profile listing returns an empty result when the caller cannot view the catalog. It returns a profile only when at least one of `encrypt`, `decrypt`, `rotateSource`, or `rotateDestination` is allowed.

### OAuth resource and tokens

REST and MCP are one protected resource. In `native` mode, the `PUBLIC_BASE_URL` origin is the resource identifier and the required token audience.

Before binding the listener, native mode requires:

- an HTTPS `PUBLIC_BASE_URL` origin without user information, query, fragment, or application path;
- an HTTPS `OIDC_ISSUER_URL` without user information, query, or fragment;
- matching issuer metadata and HTTPS JWKS, authorization, and token endpoints;
- an RFC 9068 JWT access token signed with `RS256`, `PS256`, `ES256`, or `EdDSA`; and
- matching issuer and audience claims, the required token-profile and time claims, and at most 60 seconds of clock skew.

Vaultsmith serves one public root protected-resource metadata document in native mode. REST and MCP challenges on other paths omit `resource_metadata`.

### Shared operation service

A shared caller package and `backend/internal/vaultservice` own profile projection, validation, authorization, limits, operation dispatch, cancellation, and safe domain errors.

Every mutation passes through `Prepare` once. `Prepare` is the single full authorization point: it requires the active admission lease, validates and authorizes the command, and returns a request-bound prepared operation. `Run` can execute only that operation.

One non-blocking admission controller covers body decoding and Vault work for canonical REST, the legacy route, and MCP. Its capacity is fixed in code from a checked-in benchmark. Helm does not configure it.

### JSON and HTTP limits

REST request DTOs, known JSON-RPC fields, and tool arguments use strict JSON. Required fields in these objects must be present and non-null. Unknown fields are rejected.

MCP protocol-defined extension points, including `_meta`, accept extension keys wherever the pinned `2026-07-28` schema permits them.

All request paths reject duplicate JSON keys, trailing JSON values, and malformed UTF-8. Vaultsmith also rejects unsupported content encodings and invalid decoded profile IDs in the URL path.

| Boundary | Limit |
| --- | ---: |
| Encrypt plaintext | 1 MiB |
| Decrypt or rotate Vault text | 5 MiB |
| Decrypted plaintext | 1 MiB |
| JSON request body | 8 MiB |
| HTTP headers | 16 KiB |

Canonical REST, the legacy route, and enabled MCP use a 30-second operation deadline that starts before credential dispatch. The server read and write limits are 40 and 45 seconds. The edge timeout must be at least 50 seconds.

API errors keep the existing shape:

```json
{
  "error": {
    "code": "operation_failed",
    "message": "vault operation failed"
  }
}
```

OpenAPI defines the stable status and error-code pairs. Error messages never include submitted values, profile configuration, token claims, or underlying Vault and token errors.

Vaultsmith does not retry encrypt or rotate operations and does not add an idempotency cache.

### MCP

The only new Helm value is `mcp.enabled`. It maps to `MCP_ENABLED`, defaults to `false`, and changes no Service, port, or route configuration.

The MCP endpoint supports only stateless Streamable HTTP revision `2026-07-28`. It accepts `POST /mcp` and valid CORS preflight requests. It implements:

- `server/discover`
- `tools/list`
- `tools/call`

The first tool set is `list_profiles`, `encrypt`, `decrypt`, and `rotate`.

Vaultsmith uses the exported request, content, tool, and schema types from `github.com/modelcontextprotocol/go-sdk` 1.7.0. Vaultsmith owns the one-pass HTTP and JSON-RPC adapter and the complete-result wire types. It does not use the SDK HTTP handler, use reflection to mutate private SDK fields, or read a request body twice.

Any non-empty `MCPGODEBUG` value stops startup before the listener binds. Profiles cannot use `MCP_ENABLED` or `MCPGODEBUG` as password environment names.

### Generation and compatibility

`api/baselines/v0.4.0.yaml` records the REST API from v0.4.0. The bridge compares against this file. Later releases compare against the previous tagged `api/openapi.yaml`.

The toolchain is limited to:

- `oapi-codegen` 2.8.0 for Go models;
- `openapi-typescript` 7.13.0 and TypeScript 5.9.3 for TypeScript types; and
- checksum-verified `oasdiff` 1.28.0 archives for compatibility checks.

Generated files are committed. CI regenerates and compiles them, validates OpenAPI, checks for drift, and rejects new or stale compatibility findings.

Clients must ignore unknown response properties. New routes and optional response properties remain compatible with v1. Removing or renaming a field or route, or changing a status meaning, requires v2.

The v0.4.0 decoder accepted omitted or null strings, empty or null fields from the wrong operation variant, non-canonical profile IDs, case-insensitive field names, duplicate keys, malformed UTF-8, unsupported content encodings, ambiguous credentials, oversized decrypted output, and legacy middleware error codes that the new bridge rejects. `oasdiff` findings are accepted one occurrence at a time. Release notes list every hardening in this paragraph, whether or not OpenAPI or `oasdiff` can describe it. Changes that OpenAPI cannot describe also need tests and an ADR entry. The bridge does not claim byte-for-byte compatibility with the old decoder.

### Data and telemetry

Vaultsmith does not store operations, submitted values, results, idempotency keys, or Bearer tokens. Existing Redis browser sessions and their OIDC refresh tokens remain the only persistence exception.

Logs, metrics, traces, errors, and new state must not contain request or response bodies, plaintext, Vault text, passwords, password environment names, authentication values, tokens, claims, or underlying cryptographic errors.

## Consequences

- Old UI assets can keep using `/api/v1/operations` during the bridge rollout.
- External clients do not use canonical REST until every serving pod runs the bridge release.
- MCP starts in a separate rollout after every serving pod has it enabled.
- Operators complete [`api-operator-preflight.md`](../api-operator-preflight.md) before enabling Bearer or MCP access.
- A later release can move the bundled UI to the canonical routes.
- `off` mode remains unsafe on an exposed network.

## Rejected alternatives

- Separate API listener or Service: duplicates deployment policy without adding an authorization boundary.
- Trusted-edge authentication mode: depends on topology that Vaultsmith cannot verify.
- Bearer support on the legacy route: expands the compatibility surface and makes scope selection depend on a legacy body.
- Empty OpenAPI security alternative for `off` mode: would advertise anonymous access for native deployments.
- Generated server or router: adds framework coupling when only shared types are needed.
- Operation history or idempotency storage: conflicts with the no-retention policy and cannot make randomized encryption deterministic.
- MCP SDK HTTP handler: does not meet the request-body, protocol, header, cache, and error contracts.
- Rotation attestations: need a separate design for signing keys and verification.
