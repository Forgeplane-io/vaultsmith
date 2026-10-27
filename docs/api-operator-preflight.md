# Machine API Rollout Checklist

Use this checklist before activating canonical REST Bearer clients or MCP callers for a Vaultsmith release.

Copy the checklist to the private operations system for each environment. Do not commit a completed copy: it can contain identity subjects, internal URLs, and network details. Do not record tokens, credentials, private keys, Vault values, password environment names, or private file paths. An unanswered item blocks the rollout.

- Environment:
- Owner:
- Review date:
- Rollout ticket:
- Vaultsmith version:
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

Older releases allowed profile password environment names that Vaultsmith reserves.

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
- [ ] A rotation-only caller gets `vaultsmith.rotate` and, for discovery, `vaultsmith.profile.read`. It gets decrypt or encrypt scope only if it also needs the corresponding direct operation.
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

### Delegated re-key policy

- [ ] Every intended native pair has a reviewed `p, role:<role>, rotation:<source>:<destination>, rotate, allow` row using configured profile IDs and no effective exact-pair deny. Existing group mappings and role inheritance are included in the review.
- [ ] Direct rights were reviewed independently; no decrypt/encrypt cross-product was used to generate rotation grants. Lane-only callers have no unintended direct Encrypt, Decrypt, or Generate rights.
- [ ] Destination-password custody was reviewed: its holder can decrypt re-keyed output. Pair denies do not restrict independently authorized direct decrypt-then-encrypt operations.
- [ ] Duplicate permission rows, malformed permission/grouping rows, ambiguous CSV key collisions, and unsupported model-assertion rows are treated as whole-policy failures, not a usable subset.
- [ ] REST discovery and MCP `list_profiles` return exact ordered `rotateDestinationIds` arrays, including `[]`, with matching source/destination flags. No boolean cross-product fallback is used.
- [ ] The new bundled client reaches only servers supporting the required relation contract; missing or malformed relations fail discovery.
- [ ] Native legacy operations remain session-only, native MCP remains Bearer-only, and existing CSRF, proof, and Verify requirements remain in force.

## Build and capacity

Vaultsmith compiles its operation limit from a checked-in benchmark. Helm does not configure it.

| Check | Source | Evidence | Pass condition | Fix |
| --- | --- | --- | --- | --- |
| OpenAPI compatibility | release source | `make api-check` output | no new or stale findings | fix the contract or review one finding |
| Generated contracts | release source | drift-check output | no drift | run `make generate-api` and review the result |
| Admission capacity | `docs/benchmarks/admission-linux-amd64-2026-08-12.md` | runtime configured-capacity metric | values match | lower the compiled limit or rerun the benchmark |
| Pod memory | benchmark receipt | request, limit, and measured peak | deployment meets or exceeds measured peak plus operator headroom | add memory or lower the operation limit |
| Active leases | runtime limit | load-test peak | never exceeds the limit | stop rollout and inspect admission wiring |

Do not start machine callers until the release includes the benchmark receipt, compiled limit, and saturation test. At capacity, Vaultsmith must return `503 temporarily_unavailable` with `Retry-After: 1` before body decoding or Vault work.

## Rollout and rollback

Run these checks in order:

1. Stage binaries and reviewed policy under the [delegated re-key cutover procedure](deployment.md#delegated-re-key-cutover), with affected traffic isolated and existing work drained. New binaries preserve valid old-policy direct rights but deny rotation without explicit rows; new rows are invalid to old binaries. Do not assume a mixed-version zero-downtime migration. Follow the [session cutover guidance](deployment.md#upgrade-and-rollback) as well.
2. Test the released UI, legacy session callers, and a canonical Bearer client against upgraded isolated replicas. Verify permitted direct operations, explicit-pair rotations, audience, scopes, Casbin policy, and rejection of mixed credentials. Probe every replica with synthetic allowed pairs and denied no-lane, reverse, and crossed pairs; direct decrypt plus encrypt grants must never authorize a rotation.
3. On every serving replica, verify that `/mcp` returns `404` for every method, including `OPTIONS`, while MCP is disabled.
4. Confirm every serving replica uses the new binary and stable reviewed policy before resuming affected traffic or starting external clients. Use atomic policy replacement that changes observed modification time or size. A detected missing or invalid policy fails closed without a last-good fallback; equal metadata can hide a change. A deny probe does not drain old snapshot acquisitions, which may still finish preparation and execution after removal is observed. Do not infer immediate or globally monotonic revocation.
5. Set `mcp.enabled=true` in a separate rollout. Start MCP callers only after every serving replica has MCP enabled.
6. Run `server/discover`, `tools/list`, and one call for each tool with protocol revision `2026-07-28`. Confirm that responses stay within the protocol limits.
7. Check `/healthz`, `/readyz`, issuer readiness, and JWKS readiness against their documented statuses.
8. Inspect logs and traces for plaintext, Vault text, cookies, Bearer tokens, claims, and cryptographic errors.

Rollback is ordered:

1. Stop all canonical external REST clients before rolling any replica below the current release.
2. Stop MCP callers before setting `mcp.enabled=false`.
3. Record the restart owner and get separate restart approval before the MCP-disable or application-image rollout.
4. Assess the [browser claim-freshness regression](deployment.md#upgrade-and-rollback) before rolling back the application image or routing traffic to previous release replicas; keep relying parties isolated.

Rollback does not require changing profile passwords, but policy compatibility and authorization must be reviewed. An old binary with old direct rights can restore prohibited implicit rotation. Prepare a reviewed old-format policy and isolate affected identities or traffic; if retaining direct rights would reopen prohibited rotation, keep that traffic disabled or do not downgrade. Dropping rotation rows and restarting old code is not a safe rollback. Do not expand lane grants into direct rights or switch authentication off.

## Legacy operation endpoint removal

`POST /api/v1/operations` remains available throughout v1. Removal requires v2 and all of these conditions:

- [x] The current bundled UI uses only canonical routes.
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
