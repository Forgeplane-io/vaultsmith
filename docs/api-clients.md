# REST and MCP client guide

These examples use synthetic values. Keep real plaintext, Vault text, passwords, cookies, CSRF tokens, and access tokens out of command arguments, shell history, logs, screenshots, tickets, and traces.

The canonical REST contract is in [the static API reference](api-reference.md). Authentication details are in [authentication and authorization](authentication.md).

## Safe shell setup

Set the public origin and profile identifier. These are not secrets:

```sh
VAULTSMITH_URL=https://vault.example.test
PROFILE_ID=dev
```

For native Bearer access, inject a short-lived token into `VAULTSMITH_TOKEN` through the process secret store. Do not type the token into shell history. Put the authorization header in a temporary curl configuration so the token does not appear in the process argument list:

```sh
umask 077
vaultsmith_curl_config=$(mktemp)
trap 'rm -f "$vaultsmith_curl_config"' EXIT HUP INT TERM
printf 'header = "Authorization: Bearer %s"\n' "$VAULTSMITH_TOKEN" >"$vaultsmith_curl_config"
```

All examples send JSON through standard input with `--data-binary @-`. Submitted values do not appear in curl arguments.

The examples require `jq` and curl.

## List profiles

Native Bearer mode:

```sh
curl --fail-with-body --silent --show-error \
  --config "$vaultsmith_curl_config" \
  --header 'Accept: application/json' \
  "$VAULTSMITH_URL/api/v1/profiles"
```

Off mode behind a private boundary:

```sh
curl --fail-with-body --silent --show-error \
  --header 'Accept: application/json' \
  "$VAULTSMITH_URL/api/v1/profiles"
```

Do not add an `Authorization` header in off mode. Vaultsmith rejects it.

## Encrypt standard input

This pipeline keeps plaintext out of the command arguments. Its output is sensitive Vault text.

Native Bearer mode:

```sh
printf '%s' 'synthetic plaintext' \
  | jq -Rs '{plaintext: .}' \
  | curl --fail-with-body --silent --show-error \
      --config "$vaultsmith_curl_config" \
      --header 'Accept: application/json' \
      --header 'Content-Type: application/json' \
      --data-binary @- \
      "$VAULTSMITH_URL/api/v1/profiles/$PROFILE_ID/encrypt"
```

Off mode:

```sh
printf '%s' 'synthetic plaintext' \
  | jq -Rs '{plaintext: .}' \
  | curl --fail-with-body --silent --show-error \
      --header 'Accept: application/json' \
      --header 'Content-Type: application/json' \
      --data-binary @- \
      "$VAULTSMITH_URL/api/v1/profiles/$PROFILE_ID/encrypt"
```

Encryption is randomized. **Do not retry it automatically.** A timeout can occur after the server completed the operation. Let an operator decide whether another ciphertext is acceptable.

## Decrypt a Vault file

Use a synthetic or protected local file. The response contains plaintext.

```sh
jq -Rs '{vaultText: .}' <synthetic.vault \
  | curl --fail-with-body --silent --show-error \
      --config "$vaultsmith_curl_config" \
      --header 'Accept: application/json' \
      --header 'Content-Type: application/json' \
      --data-binary @- \
      "$VAULTSMITH_URL/api/v1/profiles/$PROFILE_ID/decrypt"
```

For off mode, omit `--config "$vaultsmith_curl_config"`.

## Rotate a Vault file

Rotation decrypts with the source profile and encrypts with the destination profile. Plaintext is not returned.

```sh
SOURCE_PROFILE_ID=dev
DESTINATION_PROFILE_ID=prod
jq -Rs \
  --arg source "$SOURCE_PROFILE_ID" \
  --arg destination "$DESTINATION_PROFILE_ID" \
  '{sourceProfileId: $source, destinationProfileId: $destination, vaultText: .}' \
  <synthetic.vault \
  | curl --fail-with-body --silent --show-error \
      --config "$vaultsmith_curl_config" \
      --header 'Accept: application/json' \
      --header 'Content-Type: application/json' \
      --data-binary @- \
      "$VAULTSMITH_URL/api/v1/rotations"
```

Rotation is randomized. **Do not retry it automatically.** A timeout can occur after a new ciphertext was produced.

## Rotate with an attestation

Add a synthetic or protected binding to the canonical rotation request. The
response contains both the rotated Vault text and the signed attestation, so
store it in a protected artifact file instead of printing it:

```sh
jq -Rs \
  --arg source "$SOURCE_PROFILE_ID" \
  --arg destination "$DESTINATION_PROFILE_ID" \
  --slurpfile binding synthetic-binding.json \
  '{sourceProfileId: $source, destinationProfileId: $destination, vaultText: ., attestation: {binding: $binding[0]}}' \
  <synthetic.vault \
  | curl --fail-with-body --silent --show-error \
      --config "$vaultsmith_curl_config" \
      --header 'Accept: application/json' \
      --header 'Content-Type: application/json' \
      --data-binary @- \
      "$VAULTSMITH_URL/api/v1/rotations" \
  >rotation-result.json
```

Verify from protected files. The verifier recomputes the canonical envelope
digests and compares the requested binding:

```sh
jq -n \
  --slurpfile attestation attestation.json \
  --rawfile input synthetic-input.vault \
  --rawfile output synthetic-output.vault \
  --slurpfile binding synthetic-binding.json \
  '{attestation: $attestation[0], inputVaultText: $input, outputVaultText: $output, expectedBinding: $binding[0]}' \
  | curl --fail-with-body --silent --show-error \
      --config "$vaultsmith_curl_config" \
      --header 'Accept: application/json' \
      --header 'Content-Type: application/json' \
      --data-binary @- \
      "$VAULTSMITH_URL/api/v1/attestations/verify" \
  >verification-result.json
```

A semantic mismatch returns `valid: false` with a bounded reason such as
`input_digest_mismatch`, `output_digest_mismatch`, `binding_mismatch`, or
`key_revoked`. Do not automatically retry a failed rotation; verification can
be retried only with the exact protected artifacts and an operator-approved
policy.

## MCP over Streamable HTTP

MCP is disabled by default. Operators must set `MCP_ENABLED=true` or Helm `mcp.enabled: true`.

Vaultsmith implements a stateless JSON response profile on `POST /mcp`:

- protocol version `2026-07-28` only;
- `Accept` must allow both `application/json` and `text/event-stream`;
- `MCP-Protocol-Version` and `Mcp-Method` are required singleton headers;
- `Mcp-Name` is also required for `tools/call`, `resources/read`, and `prompts/get`;
- every request `params._meta` includes the matching protocol version and client capabilities;
- response cache metadata is private with zero TTL;
- there is no server-sent event stream and no resumable session.

The official MCP Go SDK provides the protocol data types used by Vaultsmith. Vaultsmith owns strict HTTP, header, and JSON validation to enforce this server profile.

### Discover

```sh
printf '%s' '{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}' \
  | curl --fail-with-body --silent --show-error \
      --config "$vaultsmith_curl_config" \
      --header 'Accept: application/json, text/event-stream' \
      --header 'Content-Type: application/json' \
      --header 'MCP-Protocol-Version: 2026-07-28' \
      --header 'Mcp-Method: server/discover' \
      --data-binary @- \
      "$VAULTSMITH_URL/mcp"
```

For off mode, omit the curl config and Bearer token. Never expose an off-mode MCP endpoint outside the private boundary.

### Call `encrypt`

```sh
jq -cn \
  --arg profile "$PROFILE_ID" \
  --arg plaintext 'synthetic plaintext' \
  '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"encrypt",arguments:{profileId:$profile,plaintext:$plaintext},_meta:{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}' \
  | curl --fail-with-body --silent --show-error \
      --config "$vaultsmith_curl_config" \
      --header 'Accept: application/json, text/event-stream' \
      --header 'Content-Type: application/json' \
      --header 'MCP-Protocol-Version: 2026-07-28' \
      --header 'Mcp-Method: tools/call' \
      --header 'Mcp-Name: encrypt' \
      --data-binary @- \
      "$VAULTSMITH_URL/mcp"
```

The literal synthetic plaintext is visible in this example command by design. For a real value, read standard input and use `jq -Rs` as in the REST encrypt example.

### Call `verify_rotation_attestation`

The MCP verifier accepts the attestation, input envelope, output envelope, and
optional expected binding as structured arguments. Keep all four values in
protected files and do not enable MCP client request logging for this call:

```sh
jq -n \
  --slurpfile attestation attestation.json \
  --rawfile input synthetic-input.vault \
  --rawfile output synthetic-output.vault \
  --slurpfile binding synthetic-binding.json \
  '{jsonrpc:"2.0",id:3,method:"tools/call",params:{name:"verify_rotation_attestation",arguments:{attestation:$attestation[0],inputVaultText:$input,outputVaultText:$output,expectedBinding:$binding[0]},_meta:{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}' \
  | curl --fail-with-body --silent --show-error \
      --config "$vaultsmith_curl_config" \
      --header 'Accept: application/json, text/event-stream' \
      --header 'Content-Type: application/json' \
      --header 'MCP-Protocol-Version: 2026-07-28' \
      --header 'Mcp-Method: tools/call' \
      --header 'Mcp-Name: verify_rotation_attestation' \
      --data-binary @- \
      "$VAULTSMITH_URL/mcp" \
  >verification-mcp-result.json
```

A verify-only native Bearer client needs `vaultsmith.attestation.verify`. It
does not need profile-read, rotate, or profile Casbin access. When proofs are
disabled, the tool returns a stable feature-unavailable result.

## Limits and validation

| Limit | Value | What happens when exceeded |
| --- | ---: | --- |
| Plaintext | 1 MiB of UTF-8 bytes | `413` / `invalid_request` or an MCP tool failure |
| Vault text | 5 MiB of UTF-8 bytes | `413` / `invalid_request` or an MCP tool failure |
| REST or MCP HTTP body | 8 MiB | `413` before decoding |
| Application request time | 30 seconds | `503 temporarily_unavailable`; the server cancels downstream work |
| Runtime operation admission | `min(GOMAXPROCS, 16)` | `503 temporarily_unavailable`, `Retry-After: 1`, before reading the body |

Limits count bytes, not Unicode characters. Bodies and operation strings must be valid UTF-8. Compressed request bodies are not accepted.

The admission cap of 16 is the compiled ceiling selected against the exact 2 GiB Linux/amd64 release benchmark. The running process can use a smaller capacity when `GOMAXPROCS` is smaller. Operators can inspect `/metrics` for capacity, current use, and cumulative saturation rejections. To revise the ceiling, rerun the benchmark matrix and commit a new receipt before changing the constant.

## Metrics and logging

Keep `/metrics` on a private probe path. In addition to admission metrics, the
endpoint exposes bounded operation and attestation metrics:

- `vaultsmith_operation_requests_total{operation,outcome}`;
- `vaultsmith_operation_duration_seconds{operation}`;
- `vaultsmith_attestation_issued_total{outcome}`;
- `vaultsmith_attestation_verify_total{outcome}`;
- `vaultsmith_attestation_keyring_reload_total{outcome}`;
- `vaultsmith_attestation_keyring_loaded`.

The label values are closed vocabularies. Never add profile IDs, key IDs,
issuer, subject, caller, repository, revision, path, selector, or ciphertext
size as labels. Structured logs may contain only generic operation and reload
outcomes. Request bodies, Vault values, proofs, bindings, keys, tokens, and
cookies must remain out of logs and traces.

## Error handling

REST errors use this envelope:

```json
{"error":{"code":"invalid_request","message":"request is invalid"}}
```

Stable REST codes include:

| HTTP | Code | Client action |
| ---: | --- | --- |
| 400 | `invalid_request` | Fix method-independent syntax or fields. Do not retry unchanged input. |
| 401 | `unauthorized` | Obtain a valid token or session. |
| 403 | `forbidden` | Request the indicated scope or ask an operator to change policy. |
| 404 | `not_found` | Check the route or profile identifier. |
| 405 | `method_not_allowed` | Use the `Allow` method. |
| 413 | `invalid_request` | Reduce the value or body below the stated byte limit. |
| 415 | `invalid_request` | Send identity-encoded `application/json`. |
| 422 | `operation_failed` | Treat the submitted value or crypto operation as failed. |
| 503 | `not_ready` or `temporarily_unavailable` | Use bounded operator-approved retry. Do not automatically retry encrypt or rotate. |

MCP JSON-RPC transport errors use standard parse/request/method/params codes plus:

- `-32020 HeaderMismatch` for required header/body/metadata mismatch;
- `-32022 UnsupportedProtocolVersion` for any version other than `2026-07-28`.

Known-tool schema and ordinary operation failures return a completed tool result with `isError: true`. A post-decode Casbin policy denial returns generic HTTP `403` instead of a JSON-RPC tool result.

All operation responses are `Cache-Control: no-store`. Keep response bodies out of access logs, tracing payloads, and diagnostic dumps.

## Compatibility policy

`POST /api/v1/operations` is deprecated. It remains only as the legacy operation endpoint for existing v1 compatibility callers and supports native session or off mode. New clients and the bundled UI must use the canonical REST API. The examples above use canonical Encrypt, Decrypt, and Rotate routes; they do not use the legacy endpoint.

The `/api/v1` wire contract is additive:

- clients must ignore unknown response properties;
- new optional request properties can be added only when old clients remain valid;
- stable paths, methods, semantics, error codes, limits, and security requirements remain compatible for v1;
- breaking changes require a new API version or a reviewed migration contract.

OpenAPI and the generated static reference are the canonical REST contract. MCP is versioned separately by its exact protocol header.
