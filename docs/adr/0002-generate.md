# ADR 0002: Generate sealed private material

- Status: Accepted
- Date: 2026-08-16
- Baseline: Vaultsmith post-v0.6.0 (`b0b5dcf51239bae8c3891ac2acae28cbfb1cdde4`)
- Protocol manifest: [`0002-generate-v1-manifest.json`](0002-generate-v1-manifest.json)

## Context

Vaultsmith can encrypt caller-supplied values, decrypt Vault text, rotate Vault
text between profiles, and attest rotations. Operators still need a separate
tool to create passwords, tokens, SSH keys, age identities, and private keys for
certificate signing requests before they can seal those values with Vaultsmith.

Passing newly generated private material through another process, temporary
file, clipboard, shell, or agent increases the number of places that may retain
it. Vaultsmith already owns the destination profile password and the Ansible
Vault encryption boundary. It can create the material in memory and send only
the resulting Vault envelope back to the caller.

Generate must support the bundled UI, REST clients, CI service accounts, MCP
agents, and operator key bootstrap without turning Vaultsmith into a secrets
store, PKI, CA, file service, or generic cryptographic toolbox.

## Decision

### Sealed-output rule

Vaultsmith generates one private value in memory, serializes it canonically,
encrypts those exact bytes through a server-owned destination profile, and
returns:

1. the Ansible Vault ciphertext containing the private serialization; and
2. only the public companion defined for that material kind.

Private plaintext is never included in a REST, MCP, or UI result. There is no
reveal flag, replay handle, retrieval endpoint, recovery endpoint, server-side
copy, or operation history. The product does not use "one-time reveal"
terminology.

A caller with decrypt permission for the destination profile can later decrypt
the returned Vault text. Agent separation therefore comes from issuing the
agent an identity without decrypt scope or policy, not from Generate response
semantics.

Generate has no persistence and makes no secure-erasure claim. Go cannot
guarantee that every runtime-managed copy is zeroed. Implementations minimize
the lifetime and reachability of private values and never log or persist them.

### Material contract

| Kind | Private bytes encrypted into Vault | Public result |
| --- | --- | --- |
| `password` | Printable ASCII, no terminal newline | None |
| `token` | Unpadded base64url or lowercase hexadecimal ASCII, no terminal newline | None |
| `ssh_keypair` | Unencrypted OpenSSH private-key PEM with one terminal LF | OpenSSH authorized-key line and SHA-256 fingerprint |
| `age_identity` | Canonical native age X25519 identity with one terminal LF | Canonical age X25519 recipient |
| `x509_csr` | Unencrypted PKCS#8 private-key PEM with one terminal LF | PKCS#10 CSR PEM and SHA-256 SPKI fingerprint |

"Unencrypted" in the table refers to the native private-key serialization
inside the Ansible Vault envelope. Vaultsmith does not add a second private-key
passphrase.

Every key-bearing generator derives the public result from the exact private
key passed to Vault encryption. Before writing a response, Vaultsmith parses
the private serialization and confirms that the public key matches. X.509 also
parses the generated CSR, verifies its signature, and confirms its Subject
Public Key Info matches the private key.

### Randomness

Production generation uses `crypto/rand.Reader` only. A narrow randomness
interface may be injected inside the generator package for deterministic tests
and failure injection. No environment variable, configuration file, Helm
value, REST field, MCP argument, or UI control can supply a seed or randomness
source.

Randomness or key-generation failure fails closed. Vaultsmith does not return a
partial private serialization, public companion, or Vault result.

### Passwords

The password request has only these fields:

| Field | Type | Default | Bound |
| --- | --- | --- | --- |
| `length` | integer | `32` | 22–128 |
| `lowercase` | Boolean | `true` | fixed class only |
| `uppercase` | Boolean | `true` | fixed class only |
| `digits` | Boolean | `true` | fixed class only |
| `symbols` | Boolean | `false` | fixed class only |
| `minLowercase` | integer | 1 when enabled, otherwise 0 | 0–32 |
| `minUppercase` | integer | 1 when enabled, otherwise 0 | 0–32 |
| `minDigits` | integer | 1 when enabled, otherwise 0 | 0–32 |
| `minSymbols` | integer | 1 when enabled, otherwise 0 | 0–32 |
| `excludeAmbiguous` | Boolean | `false` | fixed exclusion only |

At least one class must be enabled. A non-zero minimum requires its class, and
the sum of minima cannot exceed the requested length. Callers cannot provide a
custom alphabet, allowed-character list, exclusion string, pattern, prefix,
seed, or random bytes.

The protocol character classes are:

| Class | Characters |
| --- | --- |
| lowercase | `abcdefghijklmnopqrstuvwxyz` |
| uppercase | `ABCDEFGHIJKLMNOPQRSTUVWXYZ` |
| digits | `0123456789` |
| symbols | `!#$%&()*+,-./:;<=>?@[]^_{\|}~` |

The symbol class excludes whitespace, quotes, backslash, and backtick. When
`excludeAmbiguous` is true, Vaultsmith removes the fixed set `0O1lI|` from the
enabled classes.

For effective length `L`, effective disjoint class alphabets `A[i]`, and
effective minima `m[i]`, the accepted set is exactly every length-`L` string
over the enabled union alphabet in which the count from each `A[i]` is at least
`m[i]`. Vaultsmith computes the exact integer cardinality `N` of that accepted
set. A request is accepted only when `N >= 2^128`; this validation completes
before randomness is consumed.

Sampling is uniform over the accepted set. An implementation may use exact
dynamic-programming counts and rank/unrank selection, or an equivalent method,
but every accepted string has probability exactly `1/N`. All bounded-integer
draws use CSPRNG rejection sampling; modulo reduction is forbidden. A
force-minima/fill/shuffle construction is not conforming because it does not in
general produce a uniform distribution over the accepted set.

The schema length floor therefore does not imply that every class combination
at that length is valid; for example, digits-only generation needs a greater
effective minimum length. Exact counts use arbitrary-precision integers; no
floating-point entropy comparison decides acceptance.

### Tokens

Token parameters are:

| Field | Values | Default |
| --- | --- | --- |
| `encoding` | `base64url`, `hex` | `base64url` |
| `bytes` | integer 16–64 | `32` |

Base64url uses the RFC 4648 URL-safe alphabet without padding. Hexadecimal is
lowercase. The entropy is exactly eight times the byte count, so the 16-byte
floor is 128 bits. Tokens have no caller-provided or public prefix.

### SSH keys

REST and MCP callers must explicitly choose one algorithm:

- `ed25519`;
- `ecdsa_p256`;
- `rsa_3072`;
- `rsa_4096`.

The UI visibly preselects `ed25519`. It does not rely on a server default.

The private key uses the OpenSSH private-key format without a passphrase. The
public result contains the canonical authorized-key line without a comment and
the standard `SHA256:<base64-without-padding>` fingerprint over the OpenSSH
public-key blob.

### age identities

The age generator has no parameter or algorithm selector. It creates one
native X25519 identity and returns its native X25519 recipient. The private
serialization is the canonical uppercase `AGE-SECRET-KEY-...` identity plus one
LF. The response recipient has no terminal newline; a UI download adds one LF.

Vaultsmith does not accept imported identities and does not encrypt age files.

### X.509 key and CSR

REST and MCP callers must explicitly choose one private-key algorithm:

- `ed25519`;
- `ecdsa_p256`;
- `ecdsa_p384`;
- `rsa_3072`;
- `rsa_4096`.

The UI visibly preselects `ecdsa_p256`. It does not rely on a server default.

The private key is PKCS#8 PEM with block type `PRIVATE KEY`. The CSR is PKCS#10
PEM with block type `CERTIFICATE REQUEST`. Signature algorithms follow the key:

| Key | CSR signature |
| --- | --- |
| Ed25519 | Pure Ed25519 |
| ECDSA P-256 | ECDSA with SHA-256 |
| ECDSA P-384 | ECDSA with SHA-384 |
| RSA-3072 or RSA-4096 | PKCS #1 v1.5 with SHA-256 |

The request exposes only typed subject and SAN fields:

- scalar subject fields: `commonName`, `serialNumber`;
- repeated subject fields: `country`, `organization`,
  `organizationalUnit`, `locality`, `province`, `streetAddress`, and
  `postalCode`;
- SAN arrays: `dnsNames`, `ipAddresses`, `emailAddresses`, and `uris`.

These map to the corresponding `crypto/x509/pkix.Name` and
`crypto/x509.CertificateRequest` fields. `pkix.Name.Names` and `ExtraNames`
remain empty. At least `commonName` or one SAN is required; organization or
another DN field alone is insufficient.

Limits are:

- the complete REST Generate request body is at most 64 KiB;
- a repeated DN field has at most eight entries;
- each DN value is at most 256 UTF-8 bytes;
- a country value is exactly two uppercase ASCII letters;
- all SAN arrays together have at most 64 entries;
- DNS and email SANs are at most 253 ASCII bytes;
- URI SANs are at most 2,048 ASCII bytes;
- IP SANs must parse as canonical, unscoped IPv4 or IPv6 text. IPv4-mapped
  IPv6 text is rejected because the typed Go X.509 encoder collapses it to an
  IPv4 SAN.

Values must be non-empty after trimming and contain no NUL or ASCII control
character. DNS SANs use ASCII labels; callers supply internationalized names in
A-label/punycode form. URI SANs must be RFC 3986 ASCII absolute URIs containing
a scheme; callers percent-encode non-ASCII components rather than supplying an IRI. Email
SANs must be addr-spec mailbox values without display names. Exact duplicates
inside one field are rejected. SAN order is preserved. Repeated DN values are
passed to `pkix.Name` in caller order but are encoded as DER SET members, whose
canonical order is not caller-controlled or protocol-significant.

Vaultsmith is a key-and-CSR factory, not a PKI or CA. It does not expose:

- arbitrary raw extensions, custom OIDs, or PKCS#10 attributes;
- key usage, extended key usage, basic constraints, CA intent, or certificate
  policies;
- certificate validity, issuer, certificate serial number, signing, issuance,
  submission, renewal, revocation, or storage;
- CA, ACME, or other external-service integration.

The external CA owns all certificate and extension policy.

### X.509 fingerprint

The X.509 result fingerprint is
`SHA256:<base64-without-padding>`, computed over the DER SubjectPublicKeyInfo
embedded in the CSR. It is not a certificate fingerprint.

### REST

The implementation adds one canonical route:

```http
POST /api/v1/generate
```

Generate is not added to the deprecated `/api/v1/operations` endpoint.

The request is a strict OpenAPI 3.1 discriminated union keyed by `kind`. Every
variant requires `kind`, `profileId`, and `parameters`. The age parameters
object is empty. Unknown properties, duplicate JSON keys, trailing JSON values,
malformed UTF-8, unsupported content encodings, and an invalid content type are
rejected through the canonical REST behavior.

Every request object has `additionalProperties: false`. Every property
documented as required must be present and every other request property must be
absent or have the documented non-null type; JSON `null` is never a substitute
for omission. Defaults apply only to omitted optional request members.
`profileId` uses the existing `^[a-z0-9][a-z0-9._-]{0,63}$` schema.

The exact parameter schemas are:

| Kind | Required members | Optional non-null members and omission defaults |
| --- | --- | --- |
| `password` | None | `length`: integer 22–128, default 32; `lowercase`, `uppercase`, `digits`: Boolean, default true; `symbols`: Boolean, default false; `minLowercase`, `minUppercase`, `minDigits`, `minSymbols`: integer 0–32, default one when the corresponding effective class is enabled and zero otherwise; `excludeAmbiguous`: Boolean, default false |
| `token` | None | `encoding`: `base64url` or `hex`, default `base64url`; `bytes`: integer 16–64, default 32 |
| `ssh_keypair` | `algorithm`: `ed25519`, `ecdsa_p256`, `rsa_3072`, or `rsa_4096` | None |
| `age_identity` | None | None; the object must be exactly `{}` |
| `x509_csr` | `algorithm`: `ed25519`, `ecdsa_p256`, `ecdsa_p384`, `rsa_3072`, or `rsa_4096` | `subject`: Subject object; `sans`: SAN object; the cross-field CN-or-SAN rule still applies |

The Subject object has optional non-null scalar strings `commonName` and
`serialNumber`, plus optional non-null arrays `country`, `organization`,
`organizationalUnit`, `locality`, `province`, `streetAddress`, and
`postalCode`. The SAN object has optional non-null arrays `dnsNames`,
`ipAddresses`, `emailAddresses`, and `uris`. A supplied array contains 1–8
items for a repeated subject field or 1–64 items for a SAN field; the combined
SAN total remains at most 64. Array items are non-null and exact duplicates
within the same array are rejected. A supplied Subject or SAN object must
contain at least one member; callers omit an unused object. Omitting `subject`
is valid for a SAN-only request; omitting `sans` is valid for a CN request.

Identity strings are preserved byte-for-byte and are not case-folded,
IDNA-converted, Unicode-normalized, or deduplicated across fields. SAN array
order is preserved; repeated DN values retain their bytes but DER SET encoding
determines their serialized order. Leading or trailing Unicode whitespace is
rejected rather than silently trimmed. The format and byte ceilings in the
X.509 section are semantic validation in addition to the structural schema.

Example:

```json
{
  "kind": "ssh_keypair",
  "profileId": "production",
  "parameters": {
    "algorithm": "ed25519"
  }
}
```

The response is a strict discriminated union. Each variant requires exactly
`kind`, `profileId`, `effectiveParameters`, and `secret`, plus `public` only for
the three kinds that have a public companion. `public` is absent, not `null`,
for password and token. No response member is nullable.

"Exactly" describes the current producer shape and its pre-write validation,
not a closed v1 client schema. Consistent with ADR 0001, published REST response
objects remain forward-extensible and clients ignore unknown response
properties. Vaultsmith currently emits only the members specified here; a
future optional response property remains a compatible v1 addition. Request
schemas and MCP input/output schemas remain closed.

Every `secret` object requires exactly `format` and `vaultText`. `format` is the
kind-specific constant below and `vaultText` is the non-empty Ansible Vault
text. The exact response schemas are:

| Kind | Required `effectiveParameters` members | Required `secret.format` | Required `public` object |
| --- | --- | --- | --- |
| `password` | `length`; `lowercase`; `uppercase`; `digits`; `symbols`; `minLowercase`; `minUppercase`; `minDigits`; `minSymbols`; `excludeAmbiguous`, with the effective non-null types and values from the request schema | `password_ascii` | Absent |
| `token` | `encoding`: `base64url` or `hex`; `bytes`: integer 16–64 | `token_base64url` when base64url, otherwise `token_hex` | Absent |
| `ssh_keypair` | `algorithm`: the selected SSH enum value | `openssh_private_key` | Exactly `format`: `openssh_authorized_key`; `authorizedKey`: non-empty string; `fingerprint`: non-empty string |
| `age_identity` | `algorithm`: constant `x25519` | `age_x25519_identity` | Exactly `format`: `age_x25519_recipient`; `recipient`: non-empty string |
| `x509_csr` | `algorithm`: the selected X.509 enum value | `pkcs8_private_key_pem` | Exactly `format`: `pkcs10_csr_pem`; `csrPem`: non-empty string; `fingerprint`: non-empty string |

`effectiveParameters` never echoes generated material, Subject values, or SAN
values. Its listed members are all required so clients can see every applied
default. The response `profileId` is the requested canonical profile ID.

An SSH response therefore has this shape:

```json
{
  "kind": "ssh_keypair",
  "profileId": "production",
  "effectiveParameters": {
    "algorithm": "ed25519"
  },
  "secret": {
    "format": "openssh_private_key",
    "vaultText": "$ANSIBLE_VAULT;1.2;AES256;production\n..."
  },
  "public": {
    "format": "openssh_authorized_key",
    "authorizedKey": "ssh-ed25519 AAAA...",
    "fingerprint": "SHA256:..."
  }
}
```

Success is `200 OK`; no resource is created. The response uses the existing
`Cache-Control: no-store`, request-ID, and no-compression behavior. Vaultsmith
completes generation, consistency checks, Vault encryption, and response
validation before writing response bytes.

An `Idempotency-Key` header is rejected with the fixed `400 invalid_request`
response before generation. Its value is not logged. Generate is randomized
and non-idempotent; callers must not retry an ambiguous or failed invocation
automatically.

The safe REST status and error contract is:

| Status | Code | Meaning |
| ---: | --- | --- |
| 400 | `invalid_request` | Invalid JSON, union variant, parameters, identity, or idempotency header |
| 401 | `unauthorized` | Native credentials are missing or invalid |
| 403 | `forbidden` | Bearer scope, CORS, or profile policy denied the request |
| 403 | `csrf_failed` | Native-session request verification failed |
| 404 | `not_found` | The route or visible destination profile was not found |
| 405 | `method_not_allowed` | The route accepts POST only |
| 413 | `invalid_request` | The request body exceeds 64 KiB |
| 415 | `invalid_request` | Media type or content encoding is unsupported |
| 422 | `operation_failed` | Generation, consistency validation, serialization, or Vault encryption failed |
| 503 | `not_ready` | Shared service readiness or middleware preflight failed |
| 503 | `csrf_unavailable` | Native CSRF setup failed |
| 503 | `temporarily_unavailable` | Admission, dependency, cancellation, or deadline prevented completion |

Underlying CSPRNG, key-library, serialization, profile-password, and Vault
errors are not returned. Generate admission saturation omits `Retry-After` so a
generic client is not invited to retry a non-idempotent operation.

### Authorization and execution order

Generate reuses `vaultsmith.encrypt` and the existing profile-level
`authz.ActionEncrypt` decision. There is no Generate scope or per-kind policy.
`vaultsmith.profile.read` remains necessary only to browse profiles. Existing
profile discovery already exposes an encrypt-capable profile to a caller that
may generate into it; no new capability field is added.

In `auth.mode=native`:

- a browser session needs CSRF and profile encrypt policy;
- a Bearer caller needs `vaultsmith.encrypt` and profile encrypt policy;
- MCP remains Bearer-only and needs the same scope and policy.

In `auth.mode=off`, every reachable caller can use every Generate kind and a
supplied `Authorization` header remains invalid.

Generate extends the existing middleware and service order:

1. route, method, content headers, Origin, and CORS preflight are checked;
2. credential dispatch authenticates a session or Bearer token where required;
   a Bearer path also performs the existing early operation-scope and service
   preflight before the body is read;
3. the existing 30-second application deadline is installed;
4. the handler/service operation preflight runs under that deadline before
   admission and body reading, repeating the required-scope check defensively;
5. the shared non-blocking operation admission lease is acquired;
6. the body is read once and decoded strictly under the REST route's 64 KiB
   limit or MCP's existing 8 MiB JSON-RPC limit;
7. the service checks the minimal command shape and destination profile ID;
8. profile encrypt policy is evaluated;
9. the profile is resolved and all generation parameters are validated;
10. private generation, public derivation, serialization, and consistency
    checks run;
11. the exact private bytes are encrypted through the profile-owned executor;
12. the complete response is validated and written once.

No Generate private-material CSPRNG read, key generation, CSR signing, or Vault
encryption randomness occurs before profile authorization. Shared middleware
may already have generated a request ID or CSRF token. RSA generation uses the
same admission lease and compiled capacity as other Vault operations. There is
no separate queue, worker, or Helm capacity value. Cancellation is checked
around synchronous crypto calls; Vaultsmith does not claim that an in-progress
RSA primitive can always be interrupted.

### Shared service and generator packages

`backend/internal/generate` owns generation, native serialization, public
derivation, and consistency validation. It has no HTTP, MCP, policy, profile,
Vault-password, filesystem, command-execution, or logging dependency.

`backend/internal/vaultservice` owns Generate orchestration, admission-lease
binding, authorization, profile resolution, parameter validation, exact-byte
Vault encryption, and safe domain errors. REST and MCP call the same service
entry point. Neither transport calls another transport.

Vaultsmith uses in-process Go libraries. It never shells out to `ssh-keygen`,
`age-keygen`, `openssl`, or `ansible-vault` at runtime.

### MCP

When MCP is enabled, it adds five typed tools:

- `generate_password`;
- `generate_token`;
- `generate_ssh_keypair`;
- `generate_age_identity`;
- `generate_x509_csr`.

Discovery appends those five in that order after every pre-existing tool; the
relative order of existing tools is unchanged. Scope filtering removes
invisible tools without reordering the remaining entries.

The tool name is the material discriminator, so tool arguments contain no
`kind`. Every input and output is a strict JSON Schema 2020-12 object. SSH and
X.509 require an explicit algorithm. There is no generic Generate tool.

Tool inputs follow existing flat MCP argument conventions:

| Tool | Required arguments | Optional non-null arguments |
| --- | --- | --- |
| `generate_password` | `profileId` | The ten password parameter members with the exact REST types, bounds, defaults, and cross-field rules |
| `generate_token` | `profileId` | `encoding` and `bytes` with the exact REST types, bounds, and defaults |
| `generate_ssh_keypair` | `profileId`, `algorithm` | None; the algorithm uses the exact SSH enum |
| `generate_age_identity` | `profileId` | None |
| `generate_x509_csr` | `profileId`, `algorithm` | `subject` and `sans` with the exact REST nested-object schemas and CN-or-SAN rule |

The MCP input omits only the REST `kind` discriminator and `parameters` wrapper;
it does not rename or further flatten nested Subject or SAN fields. Defaults
apply only to omitted optional arguments, `null` is invalid, and every input
object rejects unknown properties.

MCP retains the existing 8 MiB JSON-RPC HTTP-body ceiling. It does not inherit
the REST Generate route's 64 KiB transport ceiling; the same per-field byte,
count, and algorithm bounds still constrain Generate arguments before private
generation.

Each tool's output schema is exactly the corresponding strict REST response
variant, including the constant `kind`, `profileId`, fully populated
`effectiveParameters`, `secret`, and the permitted `public` object. It does not
rename fields or flatten the response. This is also the value placed in
`structuredContent`.

Native `tools/list` retains its baseline `vaultsmith.profile.read` requirement.
Among callers allowed to list tools, the Generate tools are visible only when
the caller also has `vaultsmith.encrypt`, matching existing scope-aware MCP
visibility. A direct `tools/call` for a known Generate tool requires
`vaultsmith.encrypt` but not profile-read scope, then performs profile policy
authorization before generation. Off mode exposes all five anonymously.

The tool annotations are:

- `readOnlyHint: false`;
- `destructiveHint: false`;
- `idempotentHint: false`;
- `openWorldHint: false`.

Successful Generate results put the typed result exactly once in
`structuredContent`. The sole text content block contains exactly
`Generated material is available in structuredContent.` and no ciphertext,
public identity, fingerprint, Subject, or SAN value. The result retains the
existing `complete`, zero-TTL, private-cache metadata. Existing non-Generate
tools keep their compatibility shape. Domain failures use the existing fixed,
non-reflective tool-error behavior and have no `structuredContent`.

Generate adds no MCP resource, prompt, elicitation, sampling, job, progress,
subscription, or logging capability.

### Bundled UI

The bundled UI adds one Generate view with material-kind selection. It uses the
canonical REST route and contains no generation, crypto, profile policy, or
entropy implementation.

UI defaults are visible selections:

- password: 32 characters, lowercase/uppercase/digits enabled, symbols off;
- token: 32 bytes, base64url;
- SSH: Ed25519;
- X.509: ECDSA P-256.

The UI describes ECDSA and RSA as compatibility choices. It does not label an
algorithm as FIPS compliant.

All results have explicit copy actions. Only public companions have download
actions, implemented from the in-memory response with browser `Blob` objects:

| Public artifact | Filename | Media type |
| --- | --- | --- |
| SSH authorized key | `vaultsmith-ssh-public-key.pub` | `text/plain;charset=utf-8` |
| age recipient | `vaultsmith-age-recipient.txt` | `text/plain;charset=utf-8` |
| PKCS#10 CSR PEM | `vaultsmith-request.csr.pem` | `text/plain;charset=utf-8` |

Downloads normalize the public text to exactly one terminal LF: SSH and age
append the missing LF, while the canonical CSR PEM's existing terminal LF is
preserved without adding a second one. Filenames contain no profile, subject,
SAN, or other caller-provided identity. The UI offers no private-artifact or
Vault-text download action and never copies automatically.

Result values remain in component memory only. They do not enter
`localStorage`, `sessionStorage`, IndexedDB, URLs, navigation history,
service-worker caches, analytics, or crash reports. Starting another request
clears the previous result before dispatch. UI copy does not call the result a
one-time reveal or claim that decrypt-authorized callers cannot recover it.

### FIPS and compatibility language

Vaultsmith offers modern and broadly compatible key algorithms but does not add
a FIPS runtime mode, badge, validated-module claim, or compliance statement.
P-256, P-384, and RSA are called compatibility choices. The fixed age X25519
identity remains available and is not presented as a FIPS alternative.

### Telemetry and logs

Generate adds `generate` to the existing bounded operation metric vocabulary.
A dedicated bounded metric may distinguish the five fixed kinds and fixed
algorithm values when performance qualification needs it; no user-supplied
string becomes a label.

Logs, metrics, traces, errors, browser diagnostics, and future telemetry must
not contain:

- generated password, token, identity, or private-key bytes;
- Vault ciphertext;
- public keys, age recipients, CSRs, fingerprints, subjects, or SANs;
- request or response bodies or snippets;
- profile passwords or password environment names;
- session, CSRF, OAuth, OIDC, claim, or policy details;
- underlying random, key-library, serialization, or Vault errors.

Safe bounded fields are the operation, fixed material kind, fixed algorithm,
fixed outcome, duration, and configured profile ID only where the existing
logging policy already permits it. This feature does not add an audit subsystem.

### Compatibility and deployment

`POST /api/v1/generate` is additive in v1. The OpenAPI document is updated only
when the REST implementation lands; PR-00 does not advertise an unimplemented
route. Generated Go and TypeScript models remain committed and must regenerate
cleanly. Compatibility checks use the repository's release-managed v1 baseline;
PR-00 neither advances nor bypasses that baseline.

Generate adds no process, listener, container port, Service, Ingress, Secret,
ConfigMap, volume, service account, RBAC rule, NetworkPolicy rule, external
binary, feature switch, or Helm value. It is available wherever Encrypt is
available.

Released `ansible-vault` is a qualification oracle, not a runtime dependency.
For every private format and algorithm, qualification decrypts the returned
Vault envelope with the destination password, compares the recovered bytes to
the serialization contract, parses the recovered private value, and checks the
public companion. Tests compare recovered bytes and header semantics, never
randomized ciphertext equality.

## Consequences

- Private material can move directly from CSPRNG to an Ansible Vault envelope
  without entering a caller-provided plaintext request.
- An encrypt-only agent can create sealed values but cannot open them through
  Vaultsmith.
- A decrypt-authorized caller can still open generated ciphertext later.
- Expensive RSA generation consumes existing admission capacity and may be
  slower than modern defaults.
- X.509 support ends at key and CSR creation; CA policy remains external.
- The new REST route is canonical-only and has no legacy compatibility burden.
- The chart and deployment topology remain unchanged.

## Rejected alternatives

- Optional plaintext or "one-time reveal": the returned Vault ciphertext is
  decryptable later by an authorized caller, and replay state would add
  persistence without creating a meaningful one-time property.
- New Generate permission: encrypt policy already governs whether a caller may
  cause new private plaintext to be sealed under a profile.
- Generic material or plugin API: creates an open cryptographic surface and
  weakens strict schema, resource, and telemetry bounds.
- Custom password alphabets and token prefixes: expand validation and reduce
  comparable entropy guarantees without serving the initial workflows.
- Private-key passphrases inside Vault: add a second secret and recovery path
  without improving the server-owned Vault boundary.
- Arbitrary PKCS#10 extensions: makes Vaultsmith an issuance-policy editor and
  conflicts with the external CA boundary.
- CA, ACME, KMS, HSM, or Vault Transit integration: adds credentials, network
  dependencies, lifecycle state, and deployment policy outside this feature.
- Private or Vault-ciphertext downloads: increase local retention; the UI keeps
  the private handoff to explicit ciphertext copy only.
- File upload, batch, CLI, SDK, repository mutation, or operation history:
  conflict with the one-value stateless service boundary.
- Generate or encrypt attestations: not part of the rotation-attestation trust
  statement and would require a separate protocol decision.
- FIPS compliance mode: algorithm selection alone cannot establish runtime or
  deployment compliance.

## PR-00 boundary

This ADR, its protocol manifest, and the matching sensitive-data wording in
`SECURITY.md` are the complete PR-00 change. PR-00 adds no route, OpenAPI
schema, generated code, scope, tool, UI entry, chart value, dependency, fixture
key, or runtime behavior.
