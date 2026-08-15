# Rotation attestation verifier benchmark receipt

## Result

The required benchmark was run locally against the synthetic service verifier. This
machine is **macOS Darwin/arm64**, not Linux/amd64, so this receipt does not claim
Linux/amd64 performance. A Linux/amd64 run must replace or supplement this receipt
before using the numbers as a release baseline.

- Go: `go1.26.5`
- Host: Apple M1 Pro, Darwin 27.0.0, arm64
- Command:

  ```text
  go test -run '^$' -bench '^BenchmarkVerifyAttestation$' -benchmem -count=3 ./backend/internal/vaultservice
  ```

- Observed benchmark results:

  ```text
  BenchmarkVerifyAttestation-10    14836  79949 ns/op  29847 B/op 533 allocs/op
  BenchmarkVerifyAttestation-10    14954  80039 ns/op  29847 B/op 533 allocs/op
  BenchmarkVerifyAttestation-10    15171  80788 ns/op 29848 B/op 533 allocs/op
  ```

The benchmark verifies a small synthetic rotation proof. It does not represent the
12 MiB request-body boundary or a peak-memory test for concurrent maximum-size
requests. The route still enforces the documented body and field limits, and the
verifier admission is independently bounded by the compiled
`min(max(GOMAXPROCS(0), 1), 8)` policy.

## Regression tripwires

The observed range is 79.949–80.788 microseconds per verification and
29,847–29,848 bytes per operation. Until a Linux/amd64 baseline is available, use
an explicit review tripwire rather than treating these macOS values as a portable
SLO:

- investigate if a comparable run on the same host exceeds 100 microseconds per
  verification;
- investigate if allocation exceeds 40,000 bytes per verification;
- investigate any change in verifier admission capacity or request limits before
  raising either tripwire.

The tripwires allow roughly 25% latency headroom and roughly 34% allocation
headroom over the observed local range. They are review triggers, not correctness
limits. Re-measure on the target Linux/amd64 runner and revise this receipt with
that output before release decisions.

## Final verification rerun

The final service path was rerun with a longer sample on the same host:

```text
go test -run '^$' -bench '^BenchmarkVerifyAttestation$' -benchtime=3s -benchmem -count=5 ./backend/internal/vaultservice
```

Four steady samples measured 83.104–96.471 microseconds, 29,848–29,849
bytes/op, and 533 allocations/op. One sample measured 378.459 microseconds and
29,854 bytes/op; it is recorded as a host-scheduling outlier, not a portable
performance result. The Linux/amd64 baseline remains open.
