# Rotation attestations

Vaultsmith rotation attestations are optional, signed statements about a completed
re-key operation. They are designed for CI/CD evidence and independent
verification. They are not a replacement for Ansible Vault, a secrets store, or
an authorization policy.

## Trust model

When proofs are enabled, Vaultsmith loads a versioned Ed25519 keyring from a
read-only file. A rotation can request an attestation. The server signs the
issuer, time, source and destination profile identifiers, canonical input and
output envelope digests, and the requested binding.

A verification response with `valid: true` proves all of the following for the
request supplied to the verifier:

- the attestation has a valid v1 signature;
- the signature was made by a public key for the expected issuer;
- the signing key is currently active or retired, but not revoked;
- the canonical Ansible Vault input and output envelope digests match;
- the signed rotation and optional binding match the expected values.

`valid: true` does **not** prove that the plaintext is a particular value, that
the source or destination profile still exists, that the caller is authorized
now, or that the operation was initiated by a human. Keep the original input,
output, request identity, and deployment evidence under the CI/CD system's
normal retention and access controls.

The issuer is the canonical HTTPS origin from `PUBLIC_BASE_URL`. Verification
uses the local keyring and does not call the instance's own JWKS endpoint.

## Attestation v1

The signed v1 claims have this logical structure. The exact signed bytes are
canonical JSON; the values below are placeholders, not a production fixture:

```json
{
  "version": 1,
  "issuer": "https://vault.example.test",
  "issuedAt": "2026-08-15T00:00:00Z",
  "operation": "rotate",
  "sourceProfileId": "source",
  "destinationProfileId": "destination",
  "input": {
    "algorithm": "sha-256",
    "digest": "<64 lowercase hexadecimal characters>"
  },
  "output": {
    "algorithm": "sha-256",
    "digest": "<64 lowercase hexadecimal characters>"
  },
  "binding": {
    "repository": "example/project",
    "revision": "<reviewed revision>",
    "path": "example/path",
    "selector": "<optional selector>"
  }
}
```

The transport representation is a flattened JSON Web Signature object with
`protected`, `payload`, and `signature` components. The signing key identifier
is carried in the protected header and is resolved against the local keyring.
The public JWKS and metadata endpoints expose only public key material and
lifecycle metadata. They never expose private key material.

## Canonicalization and digest semantics

Vaultsmith canonicalizes the complete Ansible Vault envelope before hashing.
The input and output digests use SHA-256 with separate, versioned,
domain-separated prefixes. Therefore an input digest cannot be reused as an
output digest by swapping claim fields. The digest covers the envelope, not the
plaintext obtained after decryption.

Verification must receive the same input and output envelope strings that were
used for the attestation. Changing either envelope returns a semantic failure:
`input_digest_mismatch` or `output_digest_mismatch`.

Bindings are optional. Each of `repository`, `revision`, `path`, and `selector`
has a bounded UTF-8 value and the canonical serialized binding has a bounded
total size. Verification compares the requested binding as a structured value;
it does not treat a binding as an authorization policy.

## Key generation and keyring format

Use an audited Ed25519 key-generation process. Keep private seeds in the
operator's secret-management system. Do not generate production keys in a
shell command whose history, process list, CI log, or terminal recording is
retained. Record the key identifier, creation date, owner, backup location, and
rotation decision in the operator's controlled inventory.

The application-owned keyring file has this shape:

```json
{
  "version": 1,
  "active": "<key-id>",
  "keys": [
    {
      "id": "<key-id>",
      "state": "active",
      "publicKey": "<base64url raw Ed25519 public key>",
      "privateKey": "<base64url raw Ed25519 seed>"
    },
    {
      "id": "<retired-key-id>",
      "state": "retired",
      "publicKey": "<base64url raw Ed25519 public key>"
    }
  ]
}
```

The file has exactly one active key. The active key has matching public and
private material. Retired and revoked entries retain only their public key.
Key identifiers use the application's bounded identifier grammar. The
application validates the complete file, including size, schema, key material,
lifecycle state, and the active-key invariant, before using it.

Never put a private key in an environment variable, a Helm value, a ConfigMap,
a container argument, a log, or a checked-in example.

## Helm deployment

Proofs are disabled by default. The chart exposes only these proof values:

```yaml
proofs:
  enabled: false
  existingSecret: ""
```

When enabled, `proofs.existingSecret` names a pre-created Kubernetes Secret
with the fixed data key `keyring.json`. The chart mounts that key read-only at:

```text
/etc/vaultsmith/attestation/keyring.json
```

The chart does not parse the keyring or expose algorithm, key, issuer, reload,
KMS, policy, or verification values. `PUBLIC_BASE_URL` remains the issuer
source. A missing Secret or key fails pod startup only when proofs are enabled.

Example values (Secret names are synthetic):

```yaml
proofs:
  enabled: true
  existingSecret: vaultsmith-attestation
```

Create the Secret through the deployment secret-management workflow. Do not
put its private material in Git or in this document. Render and lint the exact
values file before installation, then verify the mounted path and readiness.

Proofs do not add NetworkPolicy egress or Kubernetes API access. Verification
is local and does not fetch the instance's own JWKS endpoint. When proofs are
disabled, attestation issuance, verification, metadata, and JWKS requests all
return HTTP 503 with the bounded `feature_unavailable` error code; the routes
remain stable and do not disappear from the HTTP contract.

## Key rotation and reload

The initial keyring must be valid before the application starts. The running
application polls the mounted file at a fixed five-second interval. A changed
file is read completely, size-checked, parsed, and validated before an atomic
snapshot replacement.

Use this sequence:

1. Start with key A `active`.
2. Add key B as `active` and move A to `retired` in one valid replacement.
3. Wait for the projected Secret content to change and for readiness to remain
   healthy.
4. Confirm new attestations use B and old A attestations still verify.
5. Remove A's private material only after the historical public key is backed
   up and the replacement has been verified.
6. Mark A `revoked` and replace the file.
7. Confirm A attestations return `key_revoked` while B attestations remain valid.

A malformed replacement is rejected as one unit. The previous valid snapshot
remains active and the process does not expose a partially parsed keyring. The
reload failure is logged only as a generic lifecycle event and is available in
reload metrics. Operators should alert on repeated reload failures and correct
the Secret rather than restarting blindly.

Retain historical public keys for the required verification period. Removing a
source profile does not invalidate a historical proof; key lifecycle state and
the signed statement govern verification.

## Backup and compromise recovery

Back up the encrypted or access-controlled keyring through the organization's
approved secret-management and backup process. Test restoration without
printing private material. Keep at least the public verification record and the
key lifecycle history for the retention period required by the release or
compliance process.

If a private key may be compromised:

1. prepare a new key and a valid keyring with the new key active;
2. replace the Secret and confirm new proofs use the new key;
3. revoke the compromised key in a subsequent valid keyring update;
4. verify that old proofs fail with `key_revoked` and new proofs remain valid;
5. preserve the public record and incident evidence needed for historical review.

Do not delete the old public key before the revocation and historical-review
requirements are understood.

## REST usage

Request attestation issuance by adding an `attestation` object to the canonical
rotation request. Keep the Vault text and returned attestation in protected
files or pipes; do not print them in a shared log:

```sh
jq -cn \
  --arg source "$SOURCE_PROFILE_ID" \
  --arg destination "$DESTINATION_PROFILE_ID" \
  --rawfile vault synthetic.vault \
  --slurpfile binding synthetic-binding.json \
  '{sourceProfileId:$source,destinationProfileId:$destination,vaultText:$vault,attestation:{binding:$binding[0]}}' \
  | curl --fail-with-body --silent --show-error \
      --config "$vaultsmith_curl_config" \
      --header 'Content-Type: application/json' \
      --data-binary @- \
      "$VAULTSMITH_URL/api/v1/rotations" \
  >rotation-result.json
```

Verify from protected files. This example does not print the proof or Vault
values:

```sh
jq -n \
  --slurpfile attestation attestation.json \
  --rawfile input synthetic-input.vault \
  --rawfile output synthetic-output.vault \
  --slurpfile binding synthetic-binding.json \
  '{attestation:$attestation[0],inputVaultText:$input,outputVaultText:$output,expectedBinding:$binding[0]}' \
  | curl --fail-with-body --silent --show-error \
      --config "$vaultsmith_curl_config" \
      --header 'Content-Type: application/json' \
      --data-binary @- \
      "$VAULTSMITH_URL/api/v1/attestations/verify" \
  >verification-result.json
```

A semantic mismatch is returned as a safe `valid: false` response with a
bounded reason. Stable reasons include `input_digest_mismatch`,
`output_digest_mismatch`, `binding_mismatch`, `key_revoked`,
`signature_invalid`, `unknown_key`, and `issuer_mismatch`.

## MCP usage

MCP is disabled unless explicitly enabled. When enabled, the
`verify_rotation_attestation` tool accepts the same logical inputs as the REST
verification route. Use the MCP client to pass protected file contents through
its request mechanism; do not put real Vault material, proofs, or bearer tokens
in client debug logs. A verify-only Bearer client needs the exact
`vaultsmith.attestation.verify` scope. Profile operation scopes are not required
for standalone verification, and verification uses a separate bounded
admission pool.

MCP discovery and tool-list responses advertise the verification tool only when
the configured capability and authentication scope permit it. When proofs are
disabled, issuance and verification return stable feature-unavailable results
and do not reach the Vault executor.

## Off-mode behavior

With `auth.mode: "off"`, every reachable caller is anonymous. This mode is only
for a private boundary. Proofs remain independently controlled by
`proofs.enabled`:

- disabled proofs do not require a Secret or keyring and do not add a signing
  startup dependency;
- normal encrypt, decrypt, and rotate behavior remains available as before;
- attestation issuance and verification are unavailable through stable
  feature-unavailable responses;
- the UI and MCP capability surfaces do not advertise proof operations as
  usable.

Do not expose an off-mode service to a shared or public network.

## Observability and logging

The private `/metrics` endpoint emits only bounded, low-cardinality labels:

- `vaultsmith_operation_requests_total{operation,outcome}`;
- `vaultsmith_operation_duration_seconds{operation}`;
- `vaultsmith_attestation_issued_total{outcome}`;
- `vaultsmith_attestation_verify_total{outcome}`;
- `vaultsmith_attestation_keyring_reload_total{outcome}`;
- `vaultsmith_attestation_keyring_loaded`.

Operation and attestation outcome values are closed vocabularies. No profile ID,
key ID, issuer, subject, caller, repository, revision, path, selector, or
ciphertext size is a metric label. Keep `/metrics` private and do not expose
response bodies through the edge.

Structured lifecycle logs may report only a generic operation class and outcome,
including a generic keyring reload success or failure. They must not contain
plaintext, ciphertext, attestation payloads, binding values, key material,
Bearer tokens, cookies, or user/group claims.

## CI/CD and qualification

A safe pipeline should preserve the input and output artifacts in its protected
artifact store, request a proof during rotation, verify it in a separate step,
and fail the deployment when verification is invalid. Prefer a short-lived
machine token with only the required rotate or verify scope. Do not echo request
or response bodies in CI logs.

The repository includes unit, race, and benchmark coverage for proof parsing,
canonical digests, signing, verification, key lifecycle reload, malformed
replacement handling, the separate verifier admission path, rotation overhead,
reload under traffic, large retired-key sets, and concurrent verification. Run
the repository's Helm, Go, frontend, API, compatibility, smoke, and release
checks before publishing. Benchmark results are machine and workload specific;
do not change operation-admission limits from an unmeasured local run.

The focused benchmark commands are:

```sh
go test -run '^$' -bench 'Benchmark(IssueAttestation|VerifyAttestation|RotateAttestationOverhead)$' -benchmem ./backend/internal/vaultservice
go test -run '^$' -bench 'Benchmark(KeyringReloadUnderTraffic|LargeRetiredKeySet|ConcurrentVerification)$' -benchmem ./backend/internal/attestationkeyring
go test -run '^$' -bench BenchmarkDigestBytes -benchmem ./backend/internal/attestation
```

As one local qualification sample (`darwin/arm64`, Apple M1 Pro, Go
`-benchtime=200ms`), the focused cases measured approximately:

| Case | ns/op | Notes |
| --- | ---: | --- |
| Rotation without attestation | 1,581 | Full service prepare/run path with synthetic Vault executor |
| Rotation with attestation | 68,043 | Same path plus canonical digests and Ed25519 signing |
| Keyring reload under traffic | 355,453 | Four concurrent Resolve/Sign workers while replacing the file |
| Historical verification with 255 retired keys | 61,770 | Maximum supported 256-entry keyring, one active plus 255 retired |
| Public discovery with 255 retired keys | 659,203 | JWKS serialization at the same supported bound |
| Concurrent verification | 16,822 | Parallel Ed25519 verification through the immutable manager snapshot |

These measure synthetic claims, envelopes, and keyrings only. They are
qualification inputs, not portable production SLOs or Linux/amd64 baselines.
The parser currently bounds a keyring at 256 entries and 64 KiB; those are the
supported limits for retired-key history. The reload interval remains fixed
application policy and is not a Helm value.

The release acceptance evidence must show:

- a disabled-proof Helm install/upgrade without a signing Secret;
- an enabled install with a valid Secret and the fixed read-only mount;
- invalid initial keyring failure before serving operations;
- valid replacement and atomic reload without restart;
- malformed replacement preserving the previous snapshot and readiness;
- active-to-retired rotation, revocation, and historical verification;
- unchanged non-proof operation behavior;
- no sensitive values in logs or metrics; and
- reviewed operator documentation and rollback evidence.
