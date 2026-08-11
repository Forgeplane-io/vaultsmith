# Machine API operator preflight

Complete this record for each environment before the bridge upgrade. The bridge is not implemented in the contract-foundation phase. Keep this repository file as the template. Store completed records in the approved private operations system; do not commit identity subjects, internal URLs, or environment topology. Do not replace unknown values with assumptions. Keep tokens, credentials, private keys, real Vault values, password-environment names, and private file paths out of every record.

- Environment:
- Owner:
- Review date:
- Rollout ticket:
- Planned bridge version:
- Status: blocked until each protocol and rollout gate has an exact answer

## 1. Authentication mode and public URLs

| Setting | Deployed value | Required result | Evidence |
| --- | --- | --- | --- |
| `auth.mode` | _required_ | exactly `native` or `off` | rendered configuration |
| `PUBLIC_BASE_URL` | _required in native mode_ | client-visible HTTPS origin; no user information, query, fragment, or application path | parsed-value check |
| `OIDC_ISSUER_URL` | _required in native mode_ | absolute HTTPS URL; no user information, query, or fragment | parsed-value check |
| OIDC discovery `issuer` | _required in native mode_ | exact match with `OIDC_ISSUER_URL` | redacted discovery check |
| OIDC discovery `jwks_uri` | _required in native mode_ | absolute HTTPS URL | redacted discovery check |
| OIDC discovery `authorization_endpoint` | _required in native mode_ | absolute HTTPS URL | redacted discovery check |
| OIDC discovery `token_endpoint` | _required in native mode_ | absolute HTTPS URL | redacted discovery check |
| OIDC private CA | yes/no | mounted and trusted when required; no TLS bypass | certificate-chain check |

Checks:

- [ ] Native mode uses the `PUBLIC_BASE_URL` origin as the one REST and MCP resource identifier and access-token audience.
- [ ] Native discovery returns the exact configured issuer and all required HTTPS endpoints before the listener binds.
- [ ] The private CA path, if used, is a deployment reference. It is not recorded as a private host path.
- [ ] Off mode does not claim bearer authentication or forwarded-user identity.

## 2. Browser origins

Record exact origins only. Wildcards and `Origin: null` are not valid.

| Auth mode | Browser client | Exact origin | Present in `auth.cors.allowedOrigins` | Required action |
| --- | --- | --- | --- | --- |
| `native` | bundled UI or approved client | _required_ | yes/no | the `PUBLIC_BASE_URL` origin is accepted; list each additional approved origin |
| `off` | bundled UI or approved client | _required_ | must be yes | add the exact origin before rollout |

Checks:

- [ ] Missing `Origin` remains available to native CI, agents, and other non-browser clients.
- [ ] Off-mode browser use has an exact allowed origin. Vaultsmith does not derive it from `Host` or forwarding headers.
- [ ] CORS is not treated as authorization, especially in off mode. Every caller that can reach off mode has full operation access.

## 3. Reserved environment-name preflight

Older releases allowed names that the bridge reserves. Check every deployed source before rollout.

| Check | Observed value | Required result | Remediation owner |
| --- | --- | --- | --- |
| Existing `MCP_ENABLED` process value | _required_ | unset, `true`, or `false` only | _required if invalid_ |
| Existing `MCPGODEBUG` process value | _required_ | unset or empty | _required if non-empty_ |
| Profile `passwordEnv` equal to `MCP_ENABLED` | _required_ | none | _required if found_ |
| Profile `passwordEnv` equal to `MCPGODEBUG` | _required_ | none | _required if found_ |

Do not record password values or other profile secret-environment names here. The bridge intentionally fails startup for either reserved-name collision and for any non-empty `MCPGODEBUG` value.

## 4. Edge and backend posture

Client-visible bearer traffic requires HTTPS. The operator owns the edge-to-backend transport and Service reachability. Vaultsmith reports this posture but cannot observe or enforce it; an imperfect backend topology is not presented as an application security control or hidden as an application rollout gate.

| Control | Exact deployed state | Required protocol result | Owner action or accepted exception |
| --- | --- | --- | --- |
| Client-to-edge transport | _required_ | HTTPS for native bearer clients | _required_ |
| Edge-to-backend transport | _required: authenticated TLS, private plaintext, or other_ | reported accurately | _required_ |
| Service reachability | _required_ | report edge-only or other reachable networks | _required_ |
| `Authorization` forwarding | _required_ | preserved unmodified on bearer `/api/v1` and `/mcp` requests | _required_ |
| Spoofable identity headers | _required_ | stripped; never used by Vaultsmith | _required_ |
| Request body logging | _required_ | disabled for API and MCP routes | _required_ |
| Response compression | _required_ | disabled for secret-bearing responses | _required_ |
| Edge request-body limit | _required_ | at least the documented 8 MiB JSON ceiling plus framing overhead; exact value justified | _required_ |
| Edge operation timeout | _required_ | at least 50 seconds | _required_ |
| Health and readiness exposure | _required_ | private or explicitly accepted | _required_ |

Timeout receipt:

| Measured path | Observed value | Configured value | Why the threshold exists | What happens when exceeded | Revision owner |
| --- | --- | --- | --- | --- | --- |
| Client through edge to Vaultsmith and back | _required_ | _required; minimum 50 seconds_ | exceeds the planned 45-second server write budget | request fails at the edge; no automatic operation retry | _required_ |

## 5. Machine callers and policy

Record one row per planned native-mode machine identity. Use the verified `(iss, sub)` pair. Do not use `client_id` alone as an authorization identity.

| Caller | OAuth grant | Verified issuer and subject | Required Vaultsmith scopes | Groups claim values | Profiles and actions | Token owner and rotation process |
| --- | --- | --- | --- | --- | --- | --- |
| _required_ | `client_credentials` or other approved grant | _exact `(iss, sub)`_ | _exact set_ | _exact values_ | _exact profile/action matrix_ | _owner and procedure_ |

Scopes are exact and case-sensitive:

- `vaultsmith.profile.read`
- `vaultsmith.encrypt`
- `vaultsmith.decrypt`
- `vaultsmith.rotate`

Checks:

- [ ] Each token requests the `PUBLIC_BASE_URL` origin as its resource or audience.
- [ ] Rotate-only callers get `vaultsmith.rotate`; they do not get decrypt scope unless they also need direct plaintext decryption.
- [ ] Each service token carries the configured groups claim needed by the same Casbin policy used for sessions.
- [ ] Token issuance and revocation were tested without logging a token.

## 6. Profile policy and replica parity

| Profile ID | Safe public label | Session groups and actions | Service groups and actions | Present on every serving replica |
| --- | --- | --- | --- | --- |
| _required_ | _required_ | _exact policy rows_ | _exact policy rows_ | yes/no |

Checks:

- [ ] Every profile ID matches `^[a-z0-9][a-z0-9._-]{0,63}$`.
- [ ] The configured profile order is intentional.
- [ ] Every serving replica has the same profile IDs and policy source before machine callers start.
- [ ] Password values and password-environment names are not recorded here.

## 7. Release artifacts and capacity receipt

The operation-admission capacity is compiled into the bridge from a checked-in benchmark receipt. It is not an environment variable, flag, or chart value.

| Artifact or budget | Checked-in value | Observed deployment value | Required result | Revision path |
| --- | --- | --- | --- | --- |
| OpenAPI compatibility | exact release source | `make api-check` result | zero unexpected and zero stale fingerprints | stop release; correct contract or reviewed allow-list entry |
| Generated Go and TypeScript contracts | exact release source | generated-drift result | no drift | run `make generate-api`, review output |
| Compiled admission capacity | benchmark receipt | runtime configured-capacity metric | exact match | lower compiled cap or revise receipt and rerun benchmark |
| Minimum pod memory | benchmark receipt | pod request/limit and measured peak | meets documented minimum | increase memory or lower compiled cap and rerun benchmark |
| Active operation leases | runtime metric | load-test peak | no execution above configured capacity | stop rollout and inspect admission wiring |

Do not enable machine callers until the bridge release contains the benchmark receipt, compiled capacity, minimum-memory requirement, and saturation test. Saturation must return `503 temporarily_unavailable` with `Retry-After: 1` before body decoding or execution.

## 8. Rollout and rollback

| Gate | Exact check | Required result | Rollback action |
| --- | --- | --- | --- |
| Existing UI | released frontend against mixed old/new replicas | profiles load and one legacy operation completes exactly once | route traffic to old replicas or roll back the bridge image |
| Native bearer API | synthetic service account against a bridge canary | exact audience, scopes, Casbin decisions, and ambiguous-credential rejection | stop machine callers and roll back the bridge image |
| MCP disabled bridge | every serving replica | `/mcp` returns `404` for every method, including `OPTIONS` | keep MCP callers stopped |
| MCP enablement | separate rollout with `mcp.enabled=true` | all replicas enabled before callers start | stop MCP callers; roll out `mcp.enabled=false` with separate restart approval |
| MCP protocol | `server/discover`, `tools/list`, and one call per tool | revision `2026-07-28`; bounded JSON responses; no secret-bearing logs | disable MCP as above |
| Health and readiness | `/healthz`, `/readyz`, and native issuer/JWKS readiness | exact documented status | remove canary or failing replica from service |

Checks:

- [ ] Bearer clients do not start until every serving replica runs the bridge release.
- [ ] MCP callers remain stopped during both the bridge rollout and any later MCP-enable rollout.
- [ ] Mixed-version browser behavior is tested before wider rollout.
- [ ] A rollback does not require profile-password or policy changes.
- [ ] Restart ownership and approval are explicit.
- [ ] Logs and traces were inspected for plaintext, Vault text, cookies, bearer tokens, claims, and crypto errors.

## 9. Legacy route removal criteria

Deprecated `POST /api/v1/operations` remains through v1. Removal requires v2 and every criterion below.

- [ ] The bundled UI uses only canonical routes.
- [ ] Known external callers migrated and their owners confirmed the cutover.
- [ ] Route-specific telemetry shows no expected legacy traffic for the approved observation window.
- [ ] The observation window, measured request count, threshold, exceed behavior, and revision owner are recorded.
- [ ] Removal is announced in release notes and receives compatibility review.

| Signal | Observed value | Observation window and method | Removal threshold | What happens if exceeded | Revision owner |
| --- | --- | --- | --- | --- | --- |
| Legacy requests | _required_ | _required_ | _required_ | keep the route and identify callers | _required_ |

## Approval

- Application owner:
- Security reviewer:
- Operator:
- Rollout approved at:
- Remaining exceptions and expiry dates:
