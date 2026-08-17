<!-- Code generated from api/openapi.yaml by api/cmd/reference. DO NOT EDIT. -->

# Vaultsmith REST API reference

**Contract version:** `1.0.0`

Canonical v1 machine API for profile discovery and in-memory Ansible Vault operations. The canonical REST operations are listed first in this reference. POST /api/v1/operations is deprecated compatibility only; new clients and the bundled UI use the canonical routes. Native mode accepts either the opaque browser session or an RFC 9068 Bearer access token on canonical REST routes. Session mutations also require the CSRF header. The deprecated legacy operation endpoint remains session-only. At runtime, auth.mode=off removes these security requirements and grants every reachable caller full anonymous operation access. The static contract does not advertise an anonymous security alternative because that would be unsafe for native deployments. Submitted plaintext and Vault text are processed in memory. Vaultsmith does not persist operation records, request values, results, idempotency data, or Bearer access tokens. Secret-bearing responses and API errors use Cache-Control: no-store and are not compressed.

This is the static reference for the released REST contract. The canonical source is [`api/openapi.yaml`](../api/openapi.yaml). MCP is documented separately because it is not part of OpenAPI.

## Servers

- `https://vaultsmith.example.test` — Synthetic native-mode resource origin

## Security schemes

| Name | Type | Location | Description |
| --- | --- | --- | --- |
| `BearerAuth` | http / bearer (`RFC 9068 JWT access token`) |  | Signed access token for the exact Vaultsmith resource origin. Required scopes are fixed per operation and shown with x-required-bearer-scope. Attestation verification requires vaultsmith.attestation.verify. |
| `CsrfHeader` | apiKey | header `X-CSRF-Token` | Native-mode CSRF token required with the session on unsafe requests. |
| `SessionCookie` | apiKey | cookie `__Host-vaultsmith_session` | Opaque native-mode browser session cookie. |

# Operations

## `GET /.well-known/vaultsmith-attestation`

**Get rotation-attestation metadata**

**Operation ID:** `attestationMetadata`

### Responses

| Status | Meaning | Body |
| --- | --- | --- |
| `200` | Deterministic non-secret local attestation metadata. | `application/json` [AttestationMetadata](#schema-attestationmetadata) |
| `405` | The resource accepts GET only. | [MethodNotAllowedGet](#response-methodnotallowedget) |
| `503` | The rotation-attestation subsystem is disabled, unavailable, or saturated. | [AttestationServiceUnavailable](#response-attestationserviceunavailable) |

## `GET /.well-known/vaultsmith-attestation/jwks.json`

**Get public rotation-attestation keys**

**Operation ID:** `attestationJWKS`

### Responses

| Status | Meaning | Body |
| --- | --- | --- |
| `200` | Deterministic public-only Ed25519 JWKS. | `application/json` [AttestationJWKS](#schema-attestationjwks) |
| `405` | The resource accepts GET only. | [MethodNotAllowedGet](#response-methodnotallowedget) |
| `503` | The rotation-attestation subsystem is disabled, unavailable, or saturated. | [AttestationServiceUnavailable](#response-attestationserviceunavailable) |

## `POST /api/v1/attestations/verify`

**Verify a rotation attestation**

**Operation ID:** `verifyAttestation`

Verifies a flattened JWS rotation attestation against the local issuer, immutable keyring, and supplied Vault envelopes. Verification never decrypts either envelope or resolves configured profiles. A syntactically valid attestation with a semantic mismatch returns HTTP 200 with valid false and a closed verification reason.

**Authentication:** `SessionCookie` or `BearerAuth`

**Required Bearer scope:** `vaultsmith.attestation.verify`

**Application deadline:** 30 seconds

**Maximum HTTP body:** 12582912 bytes (12 MiB)

**Automatic retry:** Prohibited

### Request body

**Required:** yes

- `application/json`: [VerifyAttestationRequest](#schema-verifyattestationrequest)

### Responses

| Status | Meaning | Body |
| --- | --- | --- |
| `200` | Validity result and safe claims when signature verification succeeds. | `application/json` [VerifyAttestationResponse](#schema-verifyattestationresponse) |
| `400` | Invalid path value, JSON, UTF-8, fields, Origin, or credential combination. | [InvalidRequest](#response-invalidrequest) |
| `401` | Native-mode credentials are missing or invalid. | [Unauthorized](#response-unauthorized) |
| `403` | CORS, CSRF, required OAuth scope, or effective Casbin policy denied the request. | [Forbidden](#response-forbidden) |
| `405` | The resource accepts POST only. | [MethodNotAllowedPost](#response-methodnotallowedpost) |
| `413` | The JSON body or submitted value exceeds its documented byte limit. | [RequestTooLarge](#response-requesttoolarge) |
| `415` | Content-Type is not application/json or Content-Encoding is unsupported. | [UnsupportedMediaType](#response-unsupportedmediatype) |
| `503` | The rotation-attestation subsystem is disabled, unavailable, or saturated. | [AttestationServiceUnavailable](#response-attestationserviceunavailable) |

## `POST /api/v1/generate`

**Generate and seal private material**

**Operation ID:** `generateMaterial`

Generates one password, token, SSH keypair, age X25519 identity, or X.509 private key and PKCS#10 CSR in memory. The exact private serialization is encrypted with the selected server-owned profile and only the resulting Ansible Vault text and kind-specific public companion are returned. Private plaintext is never returned, persisted, or made available through a replay or recovery endpoint. This randomized operation is not idempotent and callers must not retry an ambiguous or failed invocation automatically. An Idempotency-Key header is rejected.

**Authentication:** `CsrfHeader` + `SessionCookie` or `BearerAuth`

**Required Bearer scope:** `vaultsmith.encrypt`

**Application deadline:** 30 seconds

**Maximum HTTP body:** 65536 bytes (65536 bytes)

**Automatic retry:** Prohibited

### Request body

**Required:** yes

- `application/json`: [GenerateRequest](#schema-generaterequest)

### Responses

| Status | Meaning | Body |
| --- | --- | --- |
| `200` | Newly generated private material sealed as Ansible Vault text, with its permitted public companion. | `application/json` [GenerateResponse](#schema-generateresponse) |
| `400` | Invalid path value, JSON, UTF-8, fields, Origin, or credential combination. | [InvalidRequest](#response-invalidrequest) |
| `401` | Native-mode credentials are missing or invalid. | [Unauthorized](#response-unauthorized) |
| `403` | CORS, CSRF, required OAuth scope, or effective Casbin policy denied the request. | [Forbidden](#response-forbidden) |
| `404` | The route or an off-mode profile was not found. | [NotFound](#response-notfound) |
| `405` | The resource accepts POST only. | [MethodNotAllowedPost](#response-methodnotallowedpost) |
| `413` | The JSON body or submitted value exceeds its documented byte limit. | [RequestTooLarge](#response-requesttoolarge) |
| `415` | Content-Type is not application/json or Content-Encoding is unsupported. | [UnsupportedMediaType](#response-unsupportedmediatype) |
| `422` | Generation, native serialization, consistency validation, or Vault encryption failed. Underlying random, key-library, serialization, profile-password, and Vault errors are intentionally indistinguishable. | [GenerateOperationFailed](#response-generateoperationfailed) |
| `503` | Startup state, CSRF setup, a runtime authentication dependency, operation admission, cancellation, or the 30-second application deadline prevented completion. Retry-After is never emitted for this randomized, non-idempotent operation. | [GenerateServiceUnavailable](#response-generateserviceunavailable) |

## `GET /api/v1/profiles`

**List visible Vault profiles**

**Operation ID:** `listProfiles`

Returns safe profile metadata in configured order. A native session or Bearer caller without catalog policy access receives a successful empty list. Bearer callers also need vaultsmith.profile.read, and each returned capability is the intersection of an operation scope and Casbin policy. Off mode returns every configured profile with all capabilities true. Response clients must ignore unknown properties.

**Authentication:** `SessionCookie` or `BearerAuth`

**Required Bearer scope:** `vaultsmith.profile.read`

### Responses

| Status | Meaning | Body |
| --- | --- | --- |
| `200` | Ordered visible profiles and effective capabilities. | `application/json` [ProfilesResponse](#schema-profilesresponse) |
| `400` | Invalid path value, JSON, UTF-8, fields, Origin, or credential combination. | [InvalidRequest](#response-invalidrequest) |
| `401` | Native-mode credentials are missing or invalid. | [Unauthorized](#response-unauthorized) |
| `403` | CORS, CSRF, required OAuth scope, or effective Casbin policy denied the request. | [Forbidden](#response-forbidden) |
| `405` | The resource accepts GET only. | [MethodNotAllowedGet](#response-methodnotallowedget) |
| `503` | Startup state, a runtime authentication dependency, operation admission, or the 30-second application request deadline prevented completion. Retry-After is present only for immediate admission saturation. | [ServiceUnavailable](#response-serviceunavailable) |

## `POST /api/v1/profiles/{profileId}/decrypt`

**Decrypt Ansible Vault text**

**Operation ID:** `decryptValue`

Decrypts Vault 1.1 or 1.2/AES256 text with the selected server-owned profile. The returned plaintext must be valid UTF-8 and no larger than 1 MiB. The server does not retry the operation.

**Authentication:** `CsrfHeader` + `SessionCookie` or `BearerAuth`

**Required Bearer scope:** `vaultsmith.decrypt`

**Application deadline:** 30 seconds

**Maximum HTTP body:** 8388608 bytes (8 MiB)

**Automatic retry:** Prohibited

### Parameters

| Name | In | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `profileId` | path | [ProfileId](#schema-profileid) | yes | URL-decoded configured profile ID. Encoded path separators are rejected. |

### Request body

**Required:** yes

- `application/json`: [DecryptRequest](#schema-decryptrequest)

### Responses

| Status | Meaning | Body |
| --- | --- | --- |
| `200` | UTF-8 plaintext. | `application/json` [DecryptResponse](#schema-decryptresponse) |
| `400` | Invalid path value, JSON, UTF-8, fields, Origin, or credential combination. | [InvalidRequest](#response-invalidrequest) |
| `401` | Native-mode credentials are missing or invalid. | [Unauthorized](#response-unauthorized) |
| `403` | CORS, CSRF, required OAuth scope, or effective Casbin policy denied the request. | [Forbidden](#response-forbidden) |
| `404` | The route or an off-mode profile was not found. | [NotFound](#response-notfound) |
| `405` | The resource accepts POST only. | [MethodNotAllowedPost](#response-methodnotallowedpost) |
| `413` | The JSON body or submitted value exceeds its documented byte limit. | [RequestTooLarge](#response-requesttoolarge) |
| `415` | Content-Type is not application/json or Content-Encoding is unsupported. | [UnsupportedMediaType](#response-unsupportedmediatype) |
| `422` | The Vault operation failed. Wrong passwords, malformed Vault text, MAC failures, invalid or oversized decrypted plaintext, and other Vault failures are intentionally indistinguishable. | [OperationFailed](#response-operationfailed) |
| `503` | Startup state, a runtime authentication dependency, operation admission, or the 30-second application request deadline prevented completion. Retry-After is present only for immediate admission saturation. | [ServiceUnavailable](#response-serviceunavailable) |

## `POST /api/v1/profiles/{profileId}/encrypt`

**Encrypt UTF-8 plaintext**

**Operation ID:** `encryptValue`

Encrypts plaintext with the selected server-owned profile and emits Ansible Vault 1.2/AES256 text labeled with that profile. Empty plaintext is valid. The server does not retry this randomized operation.

**Authentication:** `CsrfHeader` + `SessionCookie` or `BearerAuth`

**Required Bearer scope:** `vaultsmith.encrypt`

**Application deadline:** 30 seconds

**Maximum HTTP body:** 8388608 bytes (8 MiB)

**Automatic retry:** Prohibited

### Parameters

| Name | In | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `profileId` | path | [ProfileId](#schema-profileid) | yes | URL-decoded configured profile ID. Encoded path separators are rejected. |

### Request body

**Required:** yes

- `application/json`: [EncryptRequest](#schema-encryptrequest)

### Responses

| Status | Meaning | Body |
| --- | --- | --- |
| `200` | Newly randomized Ansible Vault text. | `application/json` [EncryptResponse](#schema-encryptresponse) |
| `400` | Invalid path value, JSON, UTF-8, fields, Origin, or credential combination. | [InvalidRequest](#response-invalidrequest) |
| `401` | Native-mode credentials are missing or invalid. | [Unauthorized](#response-unauthorized) |
| `403` | CORS, CSRF, required OAuth scope, or effective Casbin policy denied the request. | [Forbidden](#response-forbidden) |
| `404` | The route or an off-mode profile was not found. | [NotFound](#response-notfound) |
| `405` | The resource accepts POST only. | [MethodNotAllowedPost](#response-methodnotallowedpost) |
| `413` | The JSON body or submitted value exceeds its documented byte limit. | [RequestTooLarge](#response-requesttoolarge) |
| `415` | Content-Type is not application/json or Content-Encoding is unsupported. | [UnsupportedMediaType](#response-unsupportedmediatype) |
| `422` | The Vault operation failed. Wrong passwords, malformed Vault text, MAC failures, invalid or oversized decrypted plaintext, and other Vault failures are intentionally indistinguishable. | [OperationFailed](#response-operationfailed) |
| `503` | Startup state, a runtime authentication dependency, operation admission, or the 30-second application request deadline prevented completion. Retry-After is present only for immediate admission saturation. | [ServiceUnavailable](#response-serviceunavailable) |

## `POST /api/v1/rotations`

**Rotate Vault text between profiles**

**Operation ID:** `rotateValue`

Decrypts with the source profile and re-encrypts with the destination profile. Plaintext is never returned. The decrypted intermediate value must be no larger than 1 MiB. Bearer callers need vaultsmith.rotate plus decrypt policy on the source and encrypt policy on the destination. The server does not retry this randomized operation.

**Authentication:** `CsrfHeader` + `SessionCookie` or `BearerAuth`

**Required Bearer scope:** `vaultsmith.rotate`

**Application deadline:** 30 seconds

**Maximum HTTP body:** 8388608 bytes (8 MiB)

**Automatic retry:** Prohibited

### Request body

**Required:** yes

- `application/json`: [RotateRequest](#schema-rotaterequest)

### Responses

| Status | Meaning | Body |
| --- | --- | --- |
| `200` | Newly randomized Vault text labeled for the destination profile. | `application/json` [RotateResponse](#schema-rotateresponse) |
| `400` | Invalid path value, JSON, UTF-8, fields, Origin, or credential combination. | [InvalidRequest](#response-invalidrequest) |
| `401` | Native-mode credentials are missing or invalid. | [Unauthorized](#response-unauthorized) |
| `403` | CORS, CSRF, required OAuth scope, or effective Casbin policy denied the request. | [Forbidden](#response-forbidden) |
| `404` | The route or an off-mode profile was not found. | [NotFound](#response-notfound) |
| `405` | The resource accepts POST only. | [MethodNotAllowedPost](#response-methodnotallowedpost) |
| `413` | The JSON body or submitted value exceeds its documented byte limit. | [RequestTooLarge](#response-requesttoolarge) |
| `415` | Content-Type is not application/json or Content-Encoding is unsupported. | [UnsupportedMediaType](#response-unsupportedmediatype) |
| `422` | The Vault operation failed. Wrong passwords, malformed Vault text, MAC failures, invalid or oversized decrypted plaintext, and other Vault failures are intentionally indistinguishable. | [OperationFailed](#response-operationfailed) |
| `503` | The rotation-attestation subsystem is disabled, unavailable, or saturated. | [AttestationServiceUnavailable](#response-attestationserviceunavailable) |

## `GET /api/v1/session`

**Get the current session and capability state**

**Operation ID:** `getSession`

**Authentication:** `SessionCookie`

### Responses

| Status | Meaning | Body |
| --- | --- | --- |
| `200` | Session state with additive capability flags. | `application/json` [SessionResponse](#schema-sessionresponse) |
| `401` | Native-mode credentials are missing or invalid. | [Unauthorized](#response-unauthorized) |
| `405` | The resource accepts GET only. | [MethodNotAllowedGet](#response-methodnotallowedget) |
| `503` | Startup state, a runtime authentication dependency, operation admission, or the 30-second application request deadline prevented completion. Retry-After is present only for immediate admission saturation. | [ServiceUnavailable](#response-serviceunavailable) |

# Compatibility

## `POST /api/v1/operations`

**Run the deprecated legacy operation endpoint**

**Operation ID:** `legacyOperation`

**Deprecated:** Yes

Compatibility-only adapter retained for existing v1 callers. New clients and the bundled UI use the canonical REST routes instead. It accepts browser sessions only in native mode and is anonymous in off mode. It keeps the released tagged variants and generic value response, while also requiring present non-null values and canonical profile IDs, rejecting every variant-irrelevant member, non-canonical field casing, duplicate JSON keys, malformed raw UTF-8, unsupported Content-Encoding, oversized decrypted plaintext, and ambiguous credentials. Legacy CORS and CSRF failures use the stable error-code table. The adapter executes through the shared service once.

**Authentication:** `CsrfHeader` + `SessionCookie`

**Application deadline:** 30 seconds

**Maximum HTTP body:** 8388608 bytes (8 MiB)

**Automatic retry:** Prohibited

### Request body

**Required:** yes

- `application/json`: [LegacyOperationRequest](#schema-legacyoperationrequest)

### Responses

| Status | Meaning | Body |
| --- | --- | --- |
| `200` | Released generic operation result. | `application/json` [LegacyValueResponse](#schema-legacyvalueresponse) |
| `400` | Invalid path value, JSON, UTF-8, fields, Origin, or credential combination. | [InvalidRequest](#response-invalidrequest) |
| `401` | A browser session is missing or an Authorization header was supplied. | [UnauthorizedLegacy](#response-unauthorizedlegacy) |
| `403` | CORS, CSRF, required OAuth scope, or effective Casbin policy denied the request. | [Forbidden](#response-forbidden) |
| `404` | The route or an off-mode profile was not found. | [NotFound](#response-notfound) |
| `405` | The resource accepts POST only. | [MethodNotAllowedPost](#response-methodnotallowedpost) |
| `413` | The JSON body or submitted value exceeds its documented byte limit. | [RequestTooLarge](#response-requesttoolarge) |
| `415` | Content-Type is not application/json or Content-Encoding is unsupported. | [UnsupportedMediaType](#response-unsupportedmediatype) |
| `422` | The Vault operation failed. Wrong passwords, malformed Vault text, MAC failures, invalid or oversized decrypted plaintext, and other Vault failures are intentionally indistinguishable. | [OperationFailed](#response-operationfailed) |
| `503` | Startup state, a runtime authentication dependency, operation admission, or the 30-second application request deadline prevented completion. Retry-After is present only for immediate admission saturation. | [ServiceUnavailable](#response-serviceunavailable) |

# Schemas

## Schema `ApiError`

Safe stable code and human text. Clients ignore unknown properties.

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `code` | string; values `invalid_request`, `unauthorized`, `forbidden`, `csrf_failed`, `not_found`, `method_not_allowed`, `operation_failed`, `not_ready`, `csrf_unavailable`, `temporarily_unavailable` | yes | Stable machine-readable error code. |
| `message` | string | yes | Safe human text with no submitted values or underlying failure details. |

## Schema `AttestationError`

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `code` | string; values `feature_unavailable`, `attestation_unavailable`, `attestation_busy` | yes |  |
| `message` | string | yes |  |

## Schema `AttestationErrorResponse`

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `error` | [AttestationError](#schema-attestationerror) | yes |  |

## Schema `AttestationJWKS`

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `keys` | array of object | yes |  |

## Schema `AttestationMetadata`

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `activeKid` | string | yes |  |
| `attestationVersions` | array of integer; minimum 1 | yes |  |
| `issuer` | string (`uri`) | yes |  |
| `jwksUri` | string (`uri`) | yes |  |
| `revokedKids` | array of string | yes |  |

## Schema `AttestationProtectedHeader`

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `alg` | string | yes |  |
| `kid` | string | yes |  |
| `typ` | string | yes |  |

## Schema `AttestationVerificationReason`

**Type:** string; values `signature_invalid`, `unknown_key`, `key_revoked`, `issuer_mismatch`, `unsupported_version`, `input_digest_mismatch`, `output_digest_mismatch`, `binding_mismatch`

## Schema `DecryptRequest`

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `vaultText` | string | yes | UTF-8 Ansible Vault 1.1 or 1.2 text limited to 5 MiB by encoded bytes. |

## Schema `DecryptResponse`

Secret-bearing response. Clients ignore unknown properties.

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `plaintext` | string | yes | Valid UTF-8 plaintext limited to 1 MiB by encoded bytes. |

## Schema `DigestBinding`

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `algorithm` | string | yes |  |
| `digest` | string | yes |  |

## Schema `EncryptRequest`

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `plaintext` | string | yes | UTF-8 plaintext limited to 1 MiB by encoded bytes. Empty is valid. |

## Schema `EncryptResponse`

Secret-bearing response. Clients ignore unknown properties.

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `vaultText` | string | yes | Ansible Vault 1.2/AES256 text labeled with the selected profile. |

## Schema `ErrorResponse`

Safe API error envelope. Clients ignore unknown properties.

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `error` | [ApiError](#schema-apierror) | yes |  |

## Schema `GenerateAgeIdentityEffectiveParameters`

Fixed age identity algorithm. Clients ignore unknown properties.

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `algorithm` | string | yes |  |

## Schema `GenerateAgeIdentityParameters`

**Type:** object

## Schema `GenerateAgeIdentityPublic`

Native age X25519 recipient. Clients ignore unknown properties.

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `format` | string | yes |  |
| `recipient` | string | yes |  |

## Schema `GenerateAgeIdentityRequest`

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `kind` | string | yes |  |
| `parameters` | [GenerateAgeIdentityParameters](#schema-generateageidentityparameters) | yes |  |
| `profileId` | [ProfileId](#schema-profileid) | yes |  |

## Schema `GenerateAgeIdentityResponse`

Current age identity producer shape. Clients ignore unknown properties.

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `effectiveParameters` | [GenerateAgeIdentityEffectiveParameters](#schema-generateageidentityeffectiveparameters) | yes |  |
| `kind` | string | yes |  |
| `profileId` | [ProfileId](#schema-profileid) | yes |  |
| `public` | [GenerateAgeIdentityPublic](#schema-generateageidentitypublic) | yes |  |
| `secret` | [GenerateAgeIdentitySecret](#schema-generateageidentitysecret) | yes |  |

## Schema `GenerateAgeIdentitySecret`

Sealed native age X25519 identity. Clients ignore unknown properties.

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `format` | string | yes |  |
| `vaultText` | string; min length 1 | yes |  |

## Schema `GeneratePasswordEffectiveParameters`

Every applied password default is populated. Clients ignore unknown properties.

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `digits` | boolean | yes |  |
| `excludeAmbiguous` | boolean | yes |  |
| `length` | integer; minimum 22; maximum 128 | yes |  |
| `lowercase` | boolean | yes |  |
| `minDigits` | integer; minimum 0; maximum 32 | yes |  |
| `minLowercase` | integer; minimum 0; maximum 32 | yes |  |
| `minSymbols` | integer; minimum 0; maximum 32 | yes |  |
| `minUppercase` | integer; minimum 0; maximum 32 | yes |  |
| `symbols` | boolean | yes |  |
| `uppercase` | boolean | yes |  |

## Schema `GeneratePasswordParameters`

Bounded fixed-class password parameters. Runtime validation additionally requires at least one enabled class, rejects non-zero minima for disabled classes, requires the effective minima to fit the length, and requires the exact accepted-set cardinality to be at least 2^128 before consuming randomness.

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `digits` | boolean | no | Defaults to true when omitted. |
| `excludeAmbiguous` | boolean | no | Defaults to false when omitted. |
| `length` | integer; minimum 22; maximum 128 | no | Defaults to 32 when omitted. |
| `lowercase` | boolean | no | Defaults to true when omitted. |
| `minDigits` | integer; minimum 0; maximum 32 | no | Defaults to 1 when digits are enabled and 0 otherwise. |
| `minLowercase` | integer; minimum 0; maximum 32 | no | Defaults to 1 when lowercase is enabled and 0 otherwise. |
| `minSymbols` | integer; minimum 0; maximum 32 | no | Defaults to 1 when symbols are enabled and 0 otherwise. |
| `minUppercase` | integer; minimum 0; maximum 32 | no | Defaults to 1 when uppercase is enabled and 0 otherwise. |
| `symbols` | boolean | no | Defaults to false when omitted. |
| `uppercase` | boolean | no | Defaults to true when omitted. |

## Schema `GeneratePasswordRequest`

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `kind` | string | yes |  |
| `parameters` | [GeneratePasswordParameters](#schema-generatepasswordparameters) | yes |  |
| `profileId` | [ProfileId](#schema-profileid) | yes |  |

## Schema `GeneratePasswordResponse`

Current password producer shape. Clients ignore unknown properties.

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `effectiveParameters` | [GeneratePasswordEffectiveParameters](#schema-generatepasswordeffectiveparameters) | yes |  |
| `kind` | string | yes |  |
| `profileId` | [ProfileId](#schema-profileid) | yes |  |
| `secret` | [GeneratePasswordSecret](#schema-generatepasswordsecret) | yes |  |

## Schema `GeneratePasswordSecret`

Sealed password serialization. Clients ignore unknown properties.

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `format` | string | yes |  |
| `vaultText` | string; min length 1 | yes |  |

## Schema `GenerateRequest`

**Type:** one of [GeneratePasswordRequest](#schema-generatepasswordrequest), [GenerateTokenRequest](#schema-generatetokenrequest), [GenerateSSHKeyPairRequest](#schema-generatesshkeypairrequest), [GenerateAgeIdentityRequest](#schema-generateageidentityrequest), [GenerateX509CSRRequest](#schema-generatex509csrrequest)

**One of:** [GeneratePasswordRequest](#schema-generatepasswordrequest), [GenerateTokenRequest](#schema-generatetokenrequest), [GenerateSSHKeyPairRequest](#schema-generatesshkeypairrequest), [GenerateAgeIdentityRequest](#schema-generateageidentityrequest), [GenerateX509CSRRequest](#schema-generatex509csrrequest)

## Schema `GenerateResponse`

Generate success response. The server currently emits only declared properties, while published v1 response schemas remain forward-extensible and clients ignore unknown properties at every response object.

**Type:** one of [GeneratePasswordResponse](#schema-generatepasswordresponse), [GenerateTokenResponse](#schema-generatetokenresponse), [GenerateSSHKeyPairResponse](#schema-generatesshkeypairresponse), [GenerateAgeIdentityResponse](#schema-generateageidentityresponse), [GenerateX509CSRResponse](#schema-generatex509csrresponse)

**One of:** [GeneratePasswordResponse](#schema-generatepasswordresponse), [GenerateTokenResponse](#schema-generatetokenresponse), [GenerateSSHKeyPairResponse](#schema-generatesshkeypairresponse), [GenerateAgeIdentityResponse](#schema-generateageidentityresponse), [GenerateX509CSRResponse](#schema-generatex509csrresponse)

## Schema `GenerateSSHKeyAlgorithm`

**Type:** string; values `ed25519`, `ecdsa_p256`, `rsa_3072`, `rsa_4096`

## Schema `GenerateSSHKeyPairEffectiveParameters`

Selected SSH algorithm. Clients ignore unknown properties.

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `algorithm` | [GenerateSSHKeyAlgorithm](#schema-generatesshkeyalgorithm) | yes |  |

## Schema `GenerateSSHKeyPairParameters`

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `algorithm` | [GenerateSSHKeyAlgorithm](#schema-generatesshkeyalgorithm) | yes |  |

## Schema `GenerateSSHKeyPairPublic`

OpenSSH public companion. Clients ignore unknown properties.

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `authorizedKey` | string; min length 1 | yes |  |
| `fingerprint` | string | yes |  |
| `format` | string | yes |  |

## Schema `GenerateSSHKeyPairRequest`

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `kind` | string | yes |  |
| `parameters` | [GenerateSSHKeyPairParameters](#schema-generatesshkeypairparameters) | yes |  |
| `profileId` | [ProfileId](#schema-profileid) | yes |  |

## Schema `GenerateSSHKeyPairResponse`

Current SSH keypair producer shape. Clients ignore unknown properties.

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `effectiveParameters` | [GenerateSSHKeyPairEffectiveParameters](#schema-generatesshkeypaireffectiveparameters) | yes |  |
| `kind` | string | yes |  |
| `profileId` | [ProfileId](#schema-profileid) | yes |  |
| `public` | [GenerateSSHKeyPairPublic](#schema-generatesshkeypairpublic) | yes |  |
| `secret` | [GenerateSSHKeyPairSecret](#schema-generatesshkeypairsecret) | yes |  |

## Schema `GenerateSSHKeyPairSecret`

Sealed OpenSSH private-key serialization. Clients ignore unknown properties.

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `format` | string | yes |  |
| `vaultText` | string; min length 1 | yes |  |

## Schema `GenerateTokenEffectiveParameters`

Every applied token default is populated. Clients ignore unknown properties.

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `bytes` | integer; minimum 16; maximum 64 | yes |  |
| `encoding` | string; values `base64url`, `hex` | yes |  |

## Schema `GenerateTokenParameters`

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `bytes` | integer; minimum 16; maximum 64 | no | Defaults to 32 when omitted. |
| `encoding` | string; values `base64url`, `hex` | no | Defaults to base64url when omitted. |

## Schema `GenerateTokenRequest`

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `kind` | string | yes |  |
| `parameters` | [GenerateTokenParameters](#schema-generatetokenparameters) | yes |  |
| `profileId` | [ProfileId](#schema-profileid) | yes |  |

## Schema `GenerateTokenResponse`

Current token producer shape. Clients ignore unknown properties.

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `effectiveParameters` | [GenerateTokenEffectiveParameters](#schema-generatetokeneffectiveparameters) | yes |  |
| `kind` | string | yes |  |
| `profileId` | [ProfileId](#schema-profileid) | yes |  |
| `secret` | [GenerateTokenSecret](#schema-generatetokensecret) | yes |  |

## Schema `GenerateTokenSecret`

Sealed token serialization. Clients ignore unknown properties.

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `format` | string; values `token_base64url`, `token_hex` | yes |  |
| `vaultText` | string; min length 1 | yes |  |

## Schema `GenerateX509CSREffectiveParameters`

Selected X.509 private-key algorithm. Clients ignore unknown properties.

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `algorithm` | [GenerateX509KeyAlgorithm](#schema-generatex509keyalgorithm) | yes |  |

## Schema `GenerateX509CSRParameters`

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `algorithm` | [GenerateX509KeyAlgorithm](#schema-generatex509keyalgorithm) | yes |  |
| `sans` | [GenerateX509SANs](#schema-generatex509sans) | no |  |
| `subject` | [GenerateX509Subject](#schema-generatex509subject) | no |  |

## Schema `GenerateX509CSRPublic`

PKCS#10 CSR and its SHA-256 SPKI fingerprint. Clients ignore unknown properties.

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `csrPem` | string; min length 1 | yes |  |
| `fingerprint` | string | yes |  |
| `format` | string | yes |  |

## Schema `GenerateX509CSRRequest`

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `kind` | string | yes |  |
| `parameters` | [GenerateX509CSRParameters](#schema-generatex509csrparameters) | yes |  |
| `profileId` | [ProfileId](#schema-profileid) | yes |  |

## Schema `GenerateX509CSRResponse`

Current X.509 CSR producer shape. Clients ignore unknown properties.

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `effectiveParameters` | [GenerateX509CSREffectiveParameters](#schema-generatex509csreffectiveparameters) | yes |  |
| `kind` | string | yes |  |
| `profileId` | [ProfileId](#schema-profileid) | yes |  |
| `public` | [GenerateX509CSRPublic](#schema-generatex509csrpublic) | yes |  |
| `secret` | [GenerateX509CSRSecret](#schema-generatex509csrsecret) | yes |  |

## Schema `GenerateX509CSRSecret`

Sealed PKCS#8 private-key PEM. Clients ignore unknown properties.

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `format` | string | yes |  |
| `vaultText` | string; min length 1 | yes |  |

## Schema `GenerateX509CountryValues`

**Type:** array of string

## Schema `GenerateX509DNSOrEmailSANs`

**Type:** array of string; min length 1

## Schema `GenerateX509DNValue`

**Type:** string; min length 1

## Schema `GenerateX509DNValues`

**Type:** array of [GenerateX509DNValue](#schema-generatex509dnvalue)

## Schema `GenerateX509IPSANs`

**Type:** array of string; min length 1

## Schema `GenerateX509KeyAlgorithm`

**Type:** string; values `ed25519`, `ecdsa_p256`, `ecdsa_p384`, `rsa_3072`, `rsa_4096`

## Schema `GenerateX509SANs`

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `dnsNames` | [GenerateX509DNSOrEmailSANs](#schema-generatex509dnsoremailsans) | no |  |
| `emailAddresses` | [GenerateX509DNSOrEmailSANs](#schema-generatex509dnsoremailsans) | no |  |
| `ipAddresses` | [GenerateX509IPSANs](#schema-generatex509ipsans) | no |  |
| `uris` | [GenerateX509URISANs](#schema-generatex509urisans) | no |  |

## Schema `GenerateX509Subject`

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `commonName` | [GenerateX509DNValue](#schema-generatex509dnvalue) | no |  |
| `country` | [GenerateX509CountryValues](#schema-generatex509countryvalues) | no |  |
| `locality` | [GenerateX509DNValues](#schema-generatex509dnvalues) | no |  |
| `organization` | [GenerateX509DNValues](#schema-generatex509dnvalues) | no |  |
| `organizationalUnit` | [GenerateX509DNValues](#schema-generatex509dnvalues) | no |  |
| `postalCode` | [GenerateX509DNValues](#schema-generatex509dnvalues) | no |  |
| `province` | [GenerateX509DNValues](#schema-generatex509dnvalues) | no |  |
| `serialNumber` | [GenerateX509DNValue](#schema-generatex509dnvalue) | no |  |
| `streetAddress` | [GenerateX509DNValues](#schema-generatex509dnvalues) | no |  |

## Schema `GenerateX509URISANs`

**Type:** array of string; min length 1

## Schema `LegacyDecryptRequest`

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `mode` | string; values `decrypt` | yes |  |
| `profileId` | [ProfileId](#schema-profileid) | yes |  |
| `value` | string | yes | UTF-8 Ansible Vault text limited to 5 MiB by encoded bytes. |

## Schema `LegacyEncryptRequest`

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `mode` | string; values `encrypt` | yes |  |
| `profileId` | [ProfileId](#schema-profileid) | yes |  |
| `value` | string | yes | UTF-8 plaintext limited to 1 MiB by encoded bytes. Empty is valid. |

## Schema `LegacyOperationRequest`

**Type:** one of [LegacyEncryptRequest](#schema-legacyencryptrequest), [LegacyDecryptRequest](#schema-legacydecryptrequest), [LegacyRotateRequest](#schema-legacyrotaterequest)

**One of:** [LegacyEncryptRequest](#schema-legacyencryptrequest), [LegacyDecryptRequest](#schema-legacydecryptrequest), [LegacyRotateRequest](#schema-legacyrotaterequest)

## Schema `LegacyRotateRequest`

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `destinationProfileId` | [ProfileId](#schema-profileid) | yes |  |
| `mode` | string; values `rotate` | yes |  |
| `sourceProfileId` | [ProfileId](#schema-profileid) | yes |  |
| `value` | string | yes | UTF-8 Ansible Vault text limited to 5 MiB by encoded bytes. |

## Schema `LegacyValueResponse`

Deprecated generic success response. Clients ignore unknown properties.

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `value` | string | yes |  |

## Schema `Profile`

Safe public profile metadata. Clients ignore unknown properties.

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `capabilities` | [ProfileCapabilities](#schema-profilecapabilities) | yes |  |
| `id` | [ProfileId](#schema-profileid) | yes |  |
| `label` | string | yes |  |

## Schema `ProfileCapabilities`

Effective caller capabilities. Clients ignore unknown properties.

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `decrypt` | boolean | yes |  |
| `encrypt` | boolean | yes |  |
| `rotateDestination` | boolean | yes |  |
| `rotateSource` | boolean | yes |  |

## Schema `ProfileId`

**Type:** string; min length 1; max length 64

## Schema `ProfilesResponse`

Ordered visible profile catalog. Clients ignore unknown properties.

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `profiles` | array of [Profile](#schema-profile) | yes |  |

## Schema `RotateRequest`

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `attestation` | [RotationAttestationRequest](#schema-rotationattestationrequest) | no |  |
| `destinationProfileId` | [ProfileId](#schema-profileid) | yes |  |
| `sourceProfileId` | [ProfileId](#schema-profileid) | yes |  |
| `vaultText` | string | yes | UTF-8 Ansible Vault 1.1 or 1.2 text limited to 5 MiB by encoded bytes. |

## Schema `RotateResponse`

Secret-bearing response. Clients ignore unknown properties.

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `attestation` | [RotationAttestation](#schema-rotationattestation) | no |  |
| `vaultText` | string | yes | Ansible Vault 1.2/AES256 text labeled with the destination profile. |

## Schema `RotationAttestation`

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `payload` | string; max length 65536 | yes | Unpadded base64url canonical JCS claims. |
| `protected` | string; max length 65536 | yes | Unpadded base64url protected JWS header. |
| `signature` | string; max length 65536 | yes | Unpadded base64url pure Ed25519 signature. |

## Schema `RotationAttestationClaims`

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `binding` | [RotationBinding](#schema-rotationbinding) | no |  |
| `destinationProfileId` | [ProfileId](#schema-profileid) | yes |  |
| `issuedAt` | string (`date-time`) | yes |  |
| `issuer` | string (`uri`) | yes |  |
| `kid` | string | yes |  |
| `operation` | string | yes |  |
| `sourceProfileId` | [ProfileId](#schema-profileid) | yes |  |

## Schema `RotationAttestationRequest`

Optional request to bind the rotation result to caller context.

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `binding` | [RotationBinding](#schema-rotationbinding) | no |  |

## Schema `RotationBinding`

Partial exact-match binding. At least one field is required.

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `path` | string; max length 1024 | no |  |
| `repository` | string; max length 1024 | no |  |
| `revision` | string; max length 1024 | no |  |
| `selector` | string; max length 1024 | no |  |

## Schema `SessionResponse`

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `attestationEnabled` | boolean | yes |  |
| `authRequired` | boolean | yes |  |
| `authenticated` | boolean | yes |  |
| `csrfToken` | string | yes |  |
| `email` | string | no |  |

## Schema `VerifyAttestationRequest`

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `attestation` | [RotationAttestation](#schema-rotationattestation) | yes |  |
| `expectedBinding` | [RotationBinding](#schema-rotationbinding) | no |  |
| `inputVaultText` | string; max length 5242880 | yes |  |
| `outputVaultText` | string; max length 5242880 | yes |  |

## Schema `VerifyAttestationResponse`

**Type:** object

| Property | Type and limits | Required | Description |
| --- | --- | --- | --- |
| `attestation` | [RotationAttestationClaims](#schema-rotationattestationclaims) | no |  |
| `reason` | [AttestationVerificationReason](#schema-attestationverificationreason) | no |  |
| `valid` | boolean | yes |  |

# Reusable responses

## Response `AttestationServiceUnavailable`

The rotation-attestation subsystem is disabled, unavailable, or saturated.

- `application/json`: [AttestationErrorResponse](#schema-attestationerrorresponse)

## Response `Forbidden`

CORS, CSRF, required OAuth scope, or effective Casbin policy denied the request.

- `application/json`: [ErrorResponse](#schema-errorresponse)

## Response `GenerateOperationFailed`

Generation, native serialization, consistency validation, or Vault encryption failed. Underlying random, key-library, serialization, profile-password, and Vault errors are intentionally indistinguishable.

- `application/json`: [ErrorResponse](#schema-errorresponse)

## Response `GenerateServiceUnavailable`

Startup state, CSRF setup, a runtime authentication dependency, operation admission, cancellation, or the 30-second application deadline prevented completion. Retry-After is never emitted for this randomized, non-idempotent operation.

- `application/json`: [ErrorResponse](#schema-errorresponse)

## Response `InvalidRequest`

Invalid path value, JSON, UTF-8, fields, Origin, or credential combination.

- `application/json`: [ErrorResponse](#schema-errorresponse)

## Response `MethodNotAllowedGet`

The resource accepts GET only.

- `application/json`: [ErrorResponse](#schema-errorresponse)

## Response `MethodNotAllowedPost`

The resource accepts POST only.

- `application/json`: [ErrorResponse](#schema-errorresponse)

## Response `NotFound`

The route or an off-mode profile was not found.

- `application/json`: [ErrorResponse](#schema-errorresponse)

## Response `OperationFailed`

The Vault operation failed. Wrong passwords, malformed Vault text, MAC failures, invalid or oversized decrypted plaintext, and other Vault failures are intentionally indistinguishable.

- `application/json`: [ErrorResponse](#schema-errorresponse)

## Response `RequestTooLarge`

The JSON body or submitted value exceeds its documented byte limit.

- `application/json`: [ErrorResponse](#schema-errorresponse)

## Response `ServiceUnavailable`

Startup state, a runtime authentication dependency, operation admission, or the 30-second application request deadline prevented completion. Retry-After is present only for immediate admission saturation.

- `application/json`: [ErrorResponse](#schema-errorresponse)

## Response `Unauthorized`

Native-mode credentials are missing or invalid.

- `application/json`: [ErrorResponse](#schema-errorresponse)

## Response `UnauthorizedLegacy`

A browser session is missing or an Authorization header was supplied.

- `application/json`: [ErrorResponse](#schema-errorresponse)

## Response `UnsupportedMediaType`

Content-Type is not application/json or Content-Encoding is unsupported.

- `application/json`: [ErrorResponse](#schema-errorresponse)
