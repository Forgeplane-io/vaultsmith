# API contract tooling

`openapi.yaml` is the canonical forward contract for the Vaultsmith v1 machine API. It does not mean every documented route is implemented yet.

## Requirements

- Go 1.25
- Node.js 22 and npm
- Python 3.9 or newer
- Bash, `curl`, `tar`, and either `sha256sum` or `shasum`

## Files

- `openapi.yaml`: canonical OpenAPI 3.1 source.
- `baselines/v0.4.0.yaml`: immutable reconstruction of the released v0.4.0 profile and legacy-operation routes.
- `compatibility-allowlist.json`: exact reviewed `oasdiff` occurrences for representable legacy decoder hardening.
- `oapi-codegen.yaml`: Go DTO-only generation configuration.
- `go.mod` and `go.sum`: isolated Go tool module pinned to `oapi-codegen` v2.8.0.
- `typescript-generator/package.json` and `package-lock.json`: isolated generator pinned to `openapi-typescript` 7.13.0 and TypeScript 5.x.
- `typescript-generator/package.json` overrides `js-yaml` at 4.3.1. Redocly otherwise resolves 4.3.0, which is affected by GHSA-5p4m-2wfm-xmqj. Remove the override only when the transitive range resolves a safe release and `npm audit` stays clean.

Generated outputs are committed at:

- `backend/internal/apimodels/openapi.gen.go`
- `frontend/src/generated/api.ts`

The server router and clients remain hand-written. Generated code supplies DTO and TypeScript contract types only.

## Generate and verify

Install the isolated TypeScript generator once:

```sh
npm ci --prefix api/typescript-generator --ignore-scripts --no-audit --no-fund
```

Regenerate committed outputs:

```sh
make generate-api
```

Run contract tests, a pinned compatibility comparison, deterministic drift checks, and generated-type compilation:

```sh
make api-check
```

The compatibility script downloads the official `oasdiff` v1.28.0 archive into `.tmp/oasdiff` for the current supported host. It verifies the embedded release checksum before extraction and execution. It does not install a binary into the system. The download uses a 10-second connection budget and a 120-second transfer budget for each of at most three attempts. The observed release assets are 12,478,394 bytes for Darwin, 6,361,417 bytes for Linux amd64, and 5,766,429 bytes for Linux arm64. The configured caps are 16 MiB for Darwin and 8 MiB for each Linux archive. An over-budget download or cache entry fails before hashing or extraction. Increase a cap and update its checksum only after reviewing a changed upstream release asset. The Darwin transfer budget still permits about 100 KiB/s. A timeout fails the check; rerun it after network recovery or seed the cache with the same checksum-verified archive.

## Compatibility allow-list

Do not allow-list a rule ID by itself. `oasdiff` emits a fingerprint for each concrete occurrence. Each accepted occurrence needs one object with:

- the exact `fingerprint`;
- the exact `ruleId`;
- the exact HTTP `operation`, `path`, and `operationId` when present; and
- a specific review reason.

`check_compatibility.py` rejects:

- an unlisted occurrence;
- duplicate report or allow-list fingerprints;
- metadata that does not match the occurrence; and
- stale entries that no longer appear.

An intentional behavior hardening that `oasdiff` cannot represent, such as duplicate raw JSON-key rejection, still needs ADR, tests, and release-note coverage. Do not fabricate an allow-list fingerprint for it.

## Baseline policy

`baselines/v0.4.0.yaml` is tied to release commit `881a42a248c71d740b8896d86e63b808bdf9bfa2`. Do not edit it to make a compatibility check pass. Add a new release baseline only through a reviewed compatibility decision.

The released operation decoder used one value-typed struct for every tagged variant. It therefore treated omitted and JSON-null strings as empty and tolerated variant-irrelevant members when they were null or empty. It also let arbitrary profile-ID strings reach lookup. The baseline models that behavior. The forward contract intentionally requires present, non-null fields, variant-specific members, and canonical profile IDs. Each representable difference has one exact fingerprint and behavior-specific reason in the allow-list. Case-insensitive Go field-name matching, duplicate-key, malformed raw UTF-8, content-encoding, credential-precedence, decrypted-output, and legacy middleware error-code hardening remain documented prose and tests because `oasdiff` cannot represent them.
