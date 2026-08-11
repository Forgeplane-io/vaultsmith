# Machine API rollout checklist

The bridge release is not implemented yet. Use this checklist when a release contains the Bearer API and MCP bridge.

Copy the checklist to the private operations system for each environment. Do not commit a completed copy: it can contain identity subjects, internal URLs, and network details. Do not record tokens, credentials, private keys, Vault values, password environment names, or private file paths. An unanswered item blocks the rollout.

- Environment:
- Owner:
- Review date:
- Rollout ticket:
- Bridge version:
- Status:

## Authentication and URLs

| Setting | Deployed value | Check | Evidence |
| --- | --- | --- | --- |
| `auth.mode` |  | `native` or `off` | rendered configuration |
| `PUBLIC_BASE_URL` |  | HTTPS origin without user information, query, fragment, or path | parsed value |
| `OIDC_ISSUER_URL` |  | HTTPS URL without user information, query, or fragment | parsed value |
| Discovery `issuer` |  | matches `OIDC_ISSUER_URL` | redacted discovery output |
| Discovery `jwks_uri` |  | absolute HTTPS URL | redacted discovery output |
| Discovery `authorization_endpoint` |  | absolute HTTPS URL | redacted discovery output |
| Discovery `token_endpoint` |  | absolute HTTPS URL | redacted discovery output |
| Private OIDC CA |  | mounted and trusted when needed; TLS verification stays enabled | certificate check |

Complete the issuer rows only in `native` mode.

- [ ] In `native` mode, the `PUBLIC_BASE_URL` origin is the REST and MCP resource identifier and token audience.
- [ ] OIDC discovery passes before Vaultsmith binds the listener.
- [ ] In `off` mode, the deployment does not claim Bearer authentication or forwarded identity.

### Browser origins

List every browser origin. Wildcards and `Origin: null` are invalid.

| Mode | Client | Origin | In `auth.cors.allowedOrigins` |
| --- | --- | --- | --- |
| `native` |  |  | yes/no |
| `off` |  |  | must be yes |

- [ ] `native` mode accepts the `PUBLIC_BASE_URL` origin.
- [ ] `off` mode has an allow-list entry for every browser origin.
- [ ] Non-browser clients can omit `Origin`.
- [ ] Vaultsmith does not derive allowed origins from `Host` or forwarding headers.
- [ ] CORS is not used as authorization. Every caller that can reach `off` mode can run every operation.

## Reserved environment names

Older releases allowed profile password environment names that the bridge reserves.

| Check | Result | Owner if it fails |
| --- | --- | --- |
| `MCP_ENABLED` is unset, `true`, or `false` |  |  |
| `MCPGODEBUG` is unset or empty |  |  |
| No profile uses `MCP_ENABLED` as `passwordEnv` |  |  |
| No profile uses `MCPGODEBUG` as `passwordEnv` |  |  |

Do not record other password environment names in this checklist. A collision or a non-empty `MCPGODEBUG` value prevents startup.

## Edge and backend

Client-to-edge Bearer traffic uses HTTPS. Record the backend transport and reachability as deployed; Vaultsmith cannot enforce either one.

| Control | Deployed state | Expected result | Owner or exception |
| --- | --- | --- | --- |
| Client-to-edge transport |  | HTTPS |  |
| Edge-to-backend transport |  | recorded accurately |  |
| Service reachability |  | reachable networks recorded |  |
| `Authorization` forwarding |  | unchanged on Bearer `/api/v1` and `/mcp` requests |  |
| Client identity headers |  | stripped and ignored |  |
| Request-body logging |  | disabled |  |
| Secret-response compression |  | disabled |  |
| Edge body limit |  | accepts the 8 MiB application limit plus framing overhead |  |
| Edge timeout |  | at least 50 seconds |  |
| Health and readiness routes |  | private or accepted as exposed |  |

Record the timeout used for the rollout:

| Measured path | Observed | Configured | Reason | Failure behavior | Owner |
| --- | ---: | ---: | --- | --- | --- |
| Client through edge to Vaultsmith and back |  |  | exceed the 45-second server write limit | edge fails the request; client does not retry automatically |  |

## Machine callers

Use the verified `(iss, sub)` pair as the identity. `client_id` alone is not an authorization identity.

| Caller | OAuth grant | `(iss, sub)` | Scopes | Groups | Profiles and actions | Token owner and rotation |
| --- | --- | --- | --- | --- | --- | --- |
|  |  |  |  |  |  |  |

Service accounts normally use `client_credentials`. Record any other grant explicitly.

Available scopes are case-sensitive:

- `vaultsmith.profile.read`
- `vaultsmith.encrypt`
- `vaultsmith.decrypt`
- `vaultsmith.rotate`

- [ ] Each token uses the `PUBLIC_BASE_URL` origin as its resource or audience.
- [ ] A rotation-only caller gets `vaultsmith.rotate`. It gets decrypt scope only if it also needs direct decryption.
- [ ] Each token contains the groups needed by the same Casbin policy as browser sessions.
- [ ] Issuance and revocation were tested without logging a token.

## Profiles and replicas

| Profile ID | Public label | Session policy | Service policy | Present on every replica |
| --- | --- | --- | --- | --- |
|  |  |  |  | yes/no |

- [ ] Every profile ID matches `^[a-z0-9][a-z0-9._-]{0,63}$`.
- [ ] Profile order is reviewed and consistent across replicas.
- [ ] Every serving replica has the same profile IDs and policy before machine callers start.
- [ ] The checklist contains no passwords or password environment names.

## Build and capacity

The bridge compiles its operation limit from a checked-in benchmark. Helm does not configure it.

| Check | Source | Evidence | Pass condition | Fix |
| --- | --- | --- | --- | --- |
| OpenAPI compatibility | release source | `make api-check` output | no new or stale findings | fix the contract or review one finding |
| Generated contracts | release source | drift-check output | no drift | run `make generate-api` and review the result |
| Admission capacity | benchmark | runtime configured-capacity metric | values match | lower the compiled limit or rerun the benchmark |
| Pod memory | benchmark minimum | request, limit, and measured peak | deployment meets the minimum | add memory or lower the operation limit |
| Active leases | runtime limit | load-test peak | never exceeds the limit | stop rollout and inspect admission wiring |

Do not start machine callers until the release includes the benchmark, compiled limit, minimum memory, and saturation test. At capacity, Vaultsmith must return `503 temporarily_unavailable` with `Retry-After: 1` before body decoding or Vault work.

## Rollout and rollback

Run these checks in order:

1. Test the released UI against a mix of old and bridge replicas. Profile listing and one legacy operation must succeed, and the operation must run once.
2. Test a Bearer client against one bridge canary. Verify audience, scopes, Casbin policy, and rejection of mixed credentials.
3. On every serving replica, verify that `/mcp` returns `404` for every method, including `OPTIONS`, while MCP is disabled.
4. Roll out the bridge to every serving replica before starting external clients on canonical REST.
5. Set `mcp.enabled=true` in a separate rollout. Start MCP callers only after every serving replica has MCP enabled.
6. Run `server/discover`, `tools/list`, and one call for each tool with protocol revision `2026-07-28`. Confirm that responses stay within the protocol limits.
7. Check `/healthz`, `/readyz`, issuer readiness, and JWKS readiness against their documented statuses.
8. Inspect logs and traces for plaintext, Vault text, cookies, Bearer tokens, claims, and cryptographic errors.

Rollback is ordered:

1. Stop all canonical external REST clients before rolling any replica below the bridge release.
2. Stop MCP callers before setting `mcp.enabled=false`.
3. Record the restart owner and get separate restart approval before the MCP-disable or bridge-image rollout.
4. Roll back the bridge image or route traffic to the previous replicas.

A rollback must not require profile password or policy changes.

## Legacy route removal

`POST /api/v1/operations` remains available throughout v1. Removal requires v2 and all of these conditions:

- [ ] The bundled UI uses only canonical routes.
- [ ] Known external callers have moved and their owners confirmed the change.
- [ ] Route metrics show no expected traffic during the agreed observation window.
- [ ] Release notes announce the removal and the change passes compatibility review.

| Signal | Observed | Window and method | Removal threshold | If exceeded | Owner |
| --- | ---: | --- | ---: | --- | --- |
| Legacy requests |  |  |  | keep the route and identify callers |  |

## Approval

- Application owner:
- Security reviewer:
- Operator:
- Approved at:
- Exceptions and expiry dates:
