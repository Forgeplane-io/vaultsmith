# Attestation digest allocation comparison

`digestCanonical` now writes the unchanged role domain and canonical envelope
separately to standard-library SHA-256. It no longer copies the entire envelope
solely to prepend that domain. Digest bytes, NUL-terminated prefixes, lowercase
hex encoding, canonicalization and malformed-input handling remain unchanged.

## Measured result

The existing `BenchmarkDigestBytes` hashes the same preallocated synthetic buffer
once for each role. These are median **allocated bytes per input/output pair**,
not retained memory or concurrent RSS:

| Canonical bytes per role | Before B/pair | After B/pair |
| ---: | ---: | ---: |
| 1,024 | 2,560 | 320 |
| 65,536 | 147,712 | 320 |
| 1,048,576 | 2,113,813.5 | 320 |
| 5,242,880 | 10,502,414.5 | 320 |

The helper still performs six allocations per pair; their byte volume is now
independent of envelope size. See the [raw baseline](digest-before.txt),
[raw result](digest-after.txt), and [benchstat comparison](digest-comparison.txt).

The new service benchmark uses a genuinely service-issued proof. Fixture setup
encrypts the existing maximum synthetic plaintext with the configured executor,
rotates it through the service, and independently decrypts the destination result
back to the original plaintext. Only proof verification is timed:

- Plaintext: 1,048,576 bytes, the existing `MaxPlaintextBytes` contract.
- Input/output envelopes: 4,247,091 / 4,247,092 bytes.
- Complete verification: **78,292,444 → 69,789,248 B/op**, a **10.86% reduction**.

See the [service baseline](service-before.txt), [result](service-after.txt),
[comparison](service-comparison.txt), and [numeric summary](measurement-summary.json).
Other canonicalization and protocol-validation work remains unchanged.

## Conditions and provenance

- Base/HEAD during qualification: `fa6ceac57c1782be60360d298c76d0a4e7b9c77c`.
- Tests and the genuine service benchmark were written before production edits.
  Their hashes match before and after; only `digest.go` differs between variants.
  [Before](source-before.sha256) and [after](source-after.sha256) source receipts
  also cover the unchanged existing benchmark and Go manifests.
- Go `1.27.3`, Darwin/arm64, Apple M1 Pro; hardware reports ten logical CPUs.
  [Environment receipt](environment.txt).
- `GOMAXPROCS=8`, ten samples per case, `200ms` benchmark target. These match the
  issue's existing workload for comparability; they are sampling parameters, not
  production limits. Revise them only by measuring both variants equivalently.
- Baseline ran before the helper edit; the after run used the same workload and
  toolchain. Each variant's test binary was compiled separately. Runs were serial
  within this task, not interleaved or exclusive of other host activity.
- Allocation profiles with one measured pair and `memprofilerate=1` identify
  the [before copy site](allocation-profile-before.txt) and its
  [after result](allocation-profile-after.txt). Profile totals also include the
  preallocated benchmark input; they are not operation B/op or peak RSS.
- [Artifact checksums](artifacts.json) cover the retained measurements.

Service timings were noisy and showed no statistically significant improvement.
No latency, throughput, Linux performance, concurrent-memory, OOM, or portable
capacity claim is made. This result does not justify new admission or byte limits.

## Repeatable commands

Use separate source copies with the same tests/benchmarks. For the baseline,
use the base version of `backend/internal/attestation/digest.go`; for the result,
use the streaming helper. Do not change the existing pair benchmark or measure
fixture construction in the service-verification loop.

Run once in each corresponding source copy, selecting `before` or `after`:

```sh
export GOTOOLCHAIN=local GOMAXPROCS=8
phase=before # after in the optimized source copy
mkdir -p .tmp/evidence
go test -c -o .tmp/evidence/digest-$phase.test ./backend/internal/attestation
go test -c -o .tmp/evidence/service-$phase.test ./backend/internal/vaultservice
.tmp/evidence/digest-$phase.test -test.run '^$' -test.bench '^BenchmarkDigestBytes$' -test.benchmem -test.count=10 -test.benchtime=200ms > .tmp/evidence/digest-$phase.txt
.tmp/evidence/service-$phase.test -test.run '^$' -test.bench '^BenchmarkVerifyGenuinelyIssuedProof$' -test.benchmem -test.count=10 -test.benchtime=200ms > .tmp/evidence/service-$phase.txt
```

Compare the paired raw files with `benchstat`. Raw timing results are retained
for transparency, not as evidence of a production speed improvement.

## Correctness and repository checks

Before and after, this affected-package command passed:

```sh
go test -count=1 ./backend/internal/attestation ./backend/internal/vaultservice
```

Independent literal-domain concatenation oracles cover nil/empty input,
SHA-256 padding/block boundaries, the existing
maximum envelope size, and caller bytes including spare capacity. Existing
canonicalization, malformed-envelope and published-vector tests remain intact.
`TestAttestedRotationRealExecutorRoundTrip` proves destination plaintext equality
and successful verification of the actual service-issued proof.

The final `go test -count=1 ./...`, `go vet ./...`, `make compatibility`, and
`git diff --check` passed. Ansible CLI interoperability ran without skips.
Command logs, compiled binaries and complete allocation profiles remain in the
task worktree's ignored `.tmp/evidence/`, not in published source.

No rendered UI, REST/MCP schema, authentication, authorization, cryptographic
format, configuration, deployment, or release behavior changed. Frontend/browser,
full native OIDC integration, race, and container checks were not rerun; no
concurrency, session, lock or admission implementation changed.
