# Vaultsmith deployment and trust boundary

> **Important:** Native mode provides OIDC authentication, Redis-backed sessions, CSRF protection, and Casbin authorization. Explicit `off` mode is development-only, skips authentication and CSRF protection, and logs a startup warning. Do not use it for an exposed deployment.

Vaultsmith encrypts, decrypts, and re-keys Ansible Vault values. Native mode identifies callers from verified OIDC tokens using `(iss, sub)`, authorizes profile-scoped operations with Casbin, and never trusts client-provided identity or authentication headers. It does not terminate TLS, rate-limit traffic, or replace a private edge. The deployment boundary must provide those controls where required.

This guide documents a narrow private deployment pattern. It uses synthetic hostnames, addresses, certificate references, profile metadata, policy and Secret names. Replace them in an untracked deployment file or a private secret-management workflow. Do not put passwords, tokens, private keys, CSRF secrets, or credential-bearing connection strings in this document or in a committed values file.

## Native authentication contract

Set `AUTH_MODE=native` explicitly. Startup requires successful OIDC discovery/JWKS setup, Redis connectivity, a valid Casbin policy file, a random CSRF secret, and secure host-only session-cookie settings. Redis is authoritative for login transactions, opaque sessions, refresh state, and refresh locks; Redis failure is a retryable service failure, never an unauthenticated fallback.

Register exactly the configured `OIDC_REDIRECT_URL` at the single configured issuer. The browser starts at `/auth/login?return_to=/`; the callback is `/auth/callback`. The callback consumes the Redis login transaction exactly once, verifies state, nonce, PKCE, issuer, audience, signature, expiry, and required claims, then rotates the session token. Logout is a CSRF-protected `POST /auth/logout`.

If the issuer is signed by a private CA, create the referenced ConfigMap with the PEM bundle under the configured key and set `auth.oidc.ca.existingConfigMap`; the chart mounts it read-only and sets `OIDC_CA_FILE`. Do not use an insecure TLS-verification bypass.

The frontend calls `GET /api/v1/session` before loading profiles. Native unauthenticated users are sent to `/auth/login`; the response contains the CSRF token used for mutation headers. `/api/v1/profiles` returns only profiles permitted by `profiles:list` plus per-profile action policy. Rotate requires decrypt on the source and encrypt on the destination.


## Required trust boundary

Put a maintained private edge gateway or reverse proxy in front of Vaultsmith:

```text
operator browser
      |
      | TLS + authentication + rate limit
      v
private edge gateway / reverse proxy
      |
      | private network; normalized headers; bounded body/timeouts
      v
Vaultsmith Service -> Vaultsmith Pod
```

The edge is responsible for:

- TLS termination and certificate policy.
- Authentication and the policy that decides which callers may use the UI and API.
- Request-size, upstream-timeout, and rate-limit tripwires.
- Stripping client-supplied identity and authentication headers before forwarding to the app.
- Disabling request-body logging at every layer. Do not add a request body to an access-log format.
- Keeping `/healthz` and `/readyz` on an internal probe path, not an authenticated public route.

Vaultsmith provides application-level request/value limits, security headers, CSRF protection, and (in native mode) authentication/authorization. These are not a substitute for TLS, private routing, rate limits, body-log suppression, or cluster access controls.

## Edge policy contract

The following contract applies regardless of the selected gateway implementation. A route manifest that only terminates TLS or forwards traffic is **not** a complete deployment boundary.

### Authentication and TLS

Terminate TLS at the private edge and require the edge's maintained authentication policy before forwarding to Vaultsmith. The authentication component may receive the original credentials. Vaultsmith must not receive caller `Authorization`, `Cookie`, or identity headers unless the application contract is deliberately changed and reviewed.

Gateway API does not define one portable authentication policy. Use the selected maintained implementation's current authentication extension or policy, and verify an unauthenticated request, an authenticated request, and a denied request against the live deployment. Do not treat a `Gateway`, `HTTPRoute`, NetworkPolicy, or chart annotation as proof that authentication is active.

### Header boundary

Use an explicit upstream allowlist. Remove client-supplied authentication, identity, and forwarding headers before the request reaches Vaultsmith. Preserve only headers required by the application and generate forwarding headers at the trusted edge:

| Header material | Edge authentication component | Vaultsmith upstream request |
| --- | --- | --- |
| `Authorization`, `Cookie` | Forward only to the authentication component | Not forwarded |
| `X-Auth-Request-*`, `X-Forwarded-User`, `X-Forwarded-Email`, `X-Remote-User` | Not accepted from the client | Not forwarded |
| `X-Original-URI`, `X-Original-Method` | Set by the edge for authentication | Not forwarded |
| `Host`, `Accept`, `Content-Type`, `Content-Length` | Not required | Explicit allowlist |
| `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host` | Generated by the trusted edge | Generated by the trusted edge |

The selected edge must use trusted client-IP handling before generating `X-Forwarded-For`. Never pass through a client-supplied forwarding chain. If another trusted load balancer precedes the edge, configure that relationship first and test the effective source address.

### Body, timeout, rate, and log tripwires

Use these starting values at the edge and measure the result:

- **8 MiB request body ceiling:** align the edge limit with the server's 8 MiB JSON request-body ceiling. This is an operational tripwire, not a cryptographic limit; the application has separate plaintext and Vault-text limits.
- **30-second upstream read/write/connect timeouts:** align them with the Go server's I/O timeout contract. Measure p95/p99 latency, timeout responses, and queued work before revising the value.
- **10 requests/second with a burst of 20:** use this as a starting rate policy. Revise it from observed 429 responses, queueing, CPU, memory, and operator workload; it is not a universal capacity claim.
- **No request-body logging or temporary plaintext storage:** disable body logging at the edge and in observability components. Prefer streaming request handling that does not spill bodies to temporary storage. If the selected implementation buffers, secure and monitor its temporary-storage lifecycle and confirm that body contents are not retained.

## Kubernetes and Helm

The chart keeps `ClusterIP`, disables its legacy Ingress object by default, and leaves NetworkPolicy disabled by default. Set `networkPolicy.enabled: true` with an allowlist to grant selected workloads network reachability, or set `networkPolicy.denyAllIngress: true` with an empty allowlist for an explicit deny-all policy. NetworkPolicy does **not** authenticate callers and does not prove that a Gateway implementation has configured authentication.

Prefer the Kubernetes Gateway API with a maintained implementation where it is supported. The chart exposes the existing `ingress.annotations` map for installations that must use an Ingress adapter, but those annotations are only a controller-specific adapter surface. Keep the chart Ingress disabled when using Gateway API, and do not copy old controller keys into a new deployment without checking the selected implementation's current documentation and rendered configuration.

```yaml
# /tmp/vaultsmith-values.yaml -- synthetic, untracked values
auth:
  mode: native
  csrf:
    existingSecret: vaultsmith-auth
    key: csrf-secret
  oidc:
    issuerURL: https://id.example.test/realms/vaultsmith
    clientID: vaultsmith
    clientSecret:
      existingSecret: vaultsmith-auth
      key: oidc-client-secret
    redirectURL: https://vault.example.test/auth/callback
    publicBaseURL: https://vault.example.test
    # Optional; mount a private issuer CA from this existing ConfigMap.
    ca:
      existingConfigMap: vaultsmith-oidc-ca
      key: ca.crt
  redis:
    address: redis.example.test:6379
    keyPrefix: "vaultsmith:"
  policy:
    existingConfigMap: vaultsmith-policy
    key: policy.csv
profiles:
  - id: dev
    label: Development
    passwordEnv: VAULT_PASSWORD_DEV
    passwordSecretKey: dev
secret:
  existingSecret: vaultsmith-passwords

networkPolicy:
  enabled: true
  denyAllIngress: false
  allowedIngress:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: edge-system
      podSelector:
        matchLabels:
          app.kubernetes.io/component: gateway
  allowedEgress:
    - to:
        - ipBlock:
            cidr: 10.0.0.0/8
      ports:
        - protocol: TCP
          port: 443
        - protocol: TCP
          port: 6379

# Gateway API is managed as a separate object. Keep this chart surface off
# unless a maintained Ingress adapter and its complete boundary policy are
# configured and tested.
ingress:
  enabled: false
  className: ""
  annotations: {}
```

A NetworkPolicy source selector must match only the intended edge or probe workload. It limits which workloads can open a network connection; it does not authenticate an HTTP caller, validate a session, or strip headers.

### Casbin policy configuration

Native mode uses a file-backed Casbin policy. The chart sets `AUTHZ_POLICY_FILE` to `/etc/vaultsmith/policy/policy.csv` and mounts the policy read-only. Provide exactly one policy source: inline Helm values or an external ConfigMap.

#### Inline policy data

Replace the `auth.policy` block in the values above with the following. The chart creates the policy data in its release-managed ConfigMap. Keep `key: policy.csv`, which is the default key used for inline policy data:

```yaml
auth:
  policy:
    key: policy.csv
    data: |-
      g, group:vaultsmith-operators, role:operator
      p, role:operator, profiles, profiles:list, allow
      p, role:operator, profile:dev, encrypt, allow
      p, role:operator, profile:dev, decrypt, allow
      p, role:operator, profile:prod*, encrypt, allow
      p, role:operator, profile:prod*, decrypt, allow
```

#### External policy ConfigMap

Create and manage the policy ConfigMap separately when policy changes should not be part of Helm values:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: vaultsmith-policy
  namespace: vaultsmith
data:
  policy.csv: |-
    g, group:vaultsmith-operators, role:operator
    p, role:operator, profiles, profiles:list, allow
    p, role:operator, profile:dev, encrypt, allow
    p, role:operator, profile:dev, decrypt, allow
```

Apply it before the Helm release:

```sh
kubectl apply -f vaultsmith-policy.yaml
```

Reference it with:

```yaml
auth:
  policy:
    existingConfigMap: vaultsmith-policy
    key: policy.csv
```

The `g` row maps an exact value from the verified OIDC groups claim to a role. The default claim is `groups`; set `auth.oidc.groupsClaim` when the provider uses another valid claim path. Permission rows must use role subjects and follow `p, role:<name>, <resource>, <action>, <effect>`.

- `profiles:list` grants access to the global `profiles` resource.
- `encrypt` and `decrypt` grant operations on `profile:<id>` resources.
- A trailing `*` matches a profile prefix, such as `profile:prod*`; it must match a configured profile.
- `deny` overrides `allow`; no matching allow is denied by default.
- Rotate is authorized by checking decrypt on the source and encrypt on the destination.

Policy resources must match the IDs under `.Values.profiles`. Malformed role subjects, invalid actions, duplicate rows, unknown profiles, and unmatched wildcard selectors cause authorization policy loading to fail closed. Keep credentials and tokens in Kubernetes Secrets, not in the policy ConfigMap.

### Public Gateway API route contract

The following objects describe the route shape and TLS boundary. They are synthetic and **not ready to expose unchanged**. Replace the GatewayClass, namespace, certificate Secret, Service name, and policy references with values rendered from the installed release and the selected maintained Gateway implementation.

Gateway API has no single portable authentication, body-buffering, rate-limit, source-range, or exact-path-deny resource. Before applying the public route, attach the implementation's maintained policies for:

- authentication before forwarding;
- header removal and trusted forwarding-header generation;
- an 8 MiB request ceiling and 30-second upstream timeouts;
- the 10 requests/second, burst-20 rate policy;
- body-log suppression and safe buffering;
- an exact-match 404 for `/healthz` and `/readyz` on the public host; and
- any source restriction required for the edge and probe route.

```yaml
# /tmp/vaultsmith-public-gateway.yaml -- synthetic, untracked objects
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: vaultsmith-edge
  namespace: vaultsmith
spec:
  # Synthetic only: replace with a maintained GatewayClass installed in the cluster.
  gatewayClassName: maintained-private-edge
  listeners:
    - name: public-https
      hostname: vaultsmith.example.internal
      port: 443
      protocol: HTTPS
      tls:
        mode: Terminate
        certificateRefs:
          - kind: Secret
            # Synthetic only: replace with the rendered public TLS Secret.
            name: vaultsmith-tls
      allowedRoutes:
        namespaces:
          from: Same
    - name: probes-https
      hostname: vaultsmith-probes.example.internal
      port: 443
      protocol: HTTPS
      tls:
        mode: Terminate
        certificateRefs:
          - kind: Secret
            # Synthetic only: replace with the rendered probe TLS Secret.
            name: vaultsmith-probes-tls
      allowedRoutes:
        namespaces:
          from: Same
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: vaultsmith-public
  # Synthetic only: replace with the chart release namespace.
  namespace: vaultsmith
spec:
  parentRefs:
    - name: vaultsmith-edge
      sectionName: public-https
  hostnames:
    - vaultsmith.example.internal
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /
      # This standard filter removes client-controlled trust headers. The
      # selected implementation must also generate canonical X-Forwarded-*.
      filters:
        - type: RequestHeaderModifier
          requestHeaderModifier:
            remove:
              - Authorization
              - Cookie
              - X-Auth-Request-User
              - X-Auth-Request-Email
              - X-Forwarded-User
              - X-Forwarded-Email
              - X-Remote-User
              - X-Forwarded-For
              - X-Forwarded-Proto
              - X-Forwarded-Host
              - X-Original-URI
              - X-Original-Method
      backendRefs:
        - name: vaultsmith
          # Synthetic only: replace with the rendered chart Service name and port.
          port: 8080
```

The public `PathPrefix /` route is a catch-all. The selected Gateway implementation must evaluate an exact `/healthz` and `/readyz` deny rule before that catch-all, or use an equivalent policy that guarantees those paths return 404 on the public host. Do not expose the route until that behavior is verified with live requests. The header filter is not authentication: the authentication policy must run before forwarding, and the Gateway must not copy caller-controlled identity into the removed headers.

### Separate internal probe route

Keep probes on a separate hostname and exact paths. The route below is intentionally separate from the public route and is **not ready to apply unchanged**. Replace the namespace, Service, TLS Secret, Gateway name, and source restriction with the installed chart and selected Gateway implementation. Attach that implementation's source allowlist so only the edge health checker or internal monitor can reach the probe hostname.

```yaml
# /tmp/vaultsmith-probes-route.yaml -- separate, untracked object
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: vaultsmith-probes
  # Synthetic only: replace with the chart release namespace.
  namespace: vaultsmith
spec:
  parentRefs:
    - name: vaultsmith-edge
      sectionName: probes-https
  hostnames:
    - vaultsmith-probes.example.internal
  rules:
    - matches:
        - path:
            type: Exact
            value: /healthz
      backendRefs:
        - name: vaultsmith
          # Synthetic only: replace with the rendered chart Service name and port.
          port: 8080
    - matches:
        - path:
            type: Exact
            value: /readyz
      backendRefs:
        - name: vaultsmith
          # Synthetic only: replace with the rendered chart Service name and port.
          port: 8080
```

Configure the edge health checker or internal monitor to use `https://vaultsmith-probes.example.internal/healthz` and `/readyz`. The separate hostname and exact paths keep the probe routes out of the authenticated public route. Source allowlists are not part of the core Gateway API route above; configure and test the selected implementation's source restriction before exposing the probe listener. Kubernetes kubelet probes remain Pod-direct. If the implementation cannot preserve this separation, use a separate internal load balancer or Service instead of weakening the public route.

The Gateway API objects and chart values are routing contracts, not proof that authentication is active. Check rendered objects, Gateway conditions, implementation events and configuration, and real authenticated/unauthenticated requests before exposing the Service.

## Migration and rollback

Migrate from an edge-authenticated legacy deployment in a staged change:

1. Provision Redis, the OIDC client/redirect URI, CSRF Secret, policy ConfigMap, and NetworkPolicy egress without exposing the Service.
2. Render and lint the native Helm values; verify the pod reaches `/readyz` only after Redis, OIDC discovery, and policy loading succeed.
3. Test `/api/v1/session`, login/callback, logout, profile filtering, denied operations, rotate source/destination checks, CSRF failures, and Redis outage behavior with synthetic values.
4. Switch the edge/backend route to the native deployment, then invalidate any legacy edge sessions separately. Do not forward client identity headers as an authentication substitute.

To roll back, keep the previous image and values available, route traffic back to the previous release, and retain the native Redis key prefix for forensic/session cleanup. Do not roll back a public production deployment by setting `AUTH_MODE=off`; that removes authentication. If native sessions must be invalidated, rotate the Redis key prefix or destroy the old session namespace through an approved operational procedure. Switching back to native requires the same OIDC issuer, client, redirect URI, CSRF Secret, Redis, and policy inputs.

## Verification before exposure

Use only synthetic files and values while checking the examples:

```sh
helm lint deploy/helm/vaultsmith -f /tmp/vaultsmith-values.yaml
helm template vaultsmith deploy/helm/vaultsmith \
  -f /tmp/vaultsmith-values.yaml >/tmp/vaultsmith-rendered.yaml
python3 - <<'PY'
from pathlib import Path
import yaml
for path in (
    "/tmp/vaultsmith-public-gateway.yaml",
    "/tmp/vaultsmith-probes-route.yaml",
):
    list(yaml.safe_load_all(Path(path).read_text()))
    print(f"{path}: YAML ok")
PY
# With a configured cluster and Gateway API CRDs, also run:
# kubectl apply --dry-run=server -f /tmp/vaultsmith-public-gateway.yaml
# kubectl apply --dry-run=server -f /tmp/vaultsmith-probes-route.yaml
```

A YAML parse or Helm render is not evidence that authentication, header stripping, source restrictions, exact health denies, or tripwires are active. Validate the actual selected Gateway implementation and run a disposable request matrix with spoofed authentication, identity, and forwarding headers.

Before exposure, verify all of the following at the actual boundary:

- A request without valid authentication cannot reach the UI or API.
- A request with valid authentication reaches the UI and API without forwarding client authentication or identity headers to the app.
- The public host returns 404 for `/healthz` and `/readyz`.
- The probe hostname accepts only exact `/healthz` and `/readyz` paths from the intended internal source range.
- Request bodies are absent from edge, gateway, access, error, and observability logs.
- Oversized requests return a bounded error before expensive work.
- Timeout and rate-limit responses are observable without logging sensitive values.
- `networkPolicy.allowedIngress` matches only the intended edge or probe workload.

These checks validate the deployment boundary and the selected Vaultsmith authentication mode. They do not replace live OIDC, Redis, policy, and request-matrix verification.
