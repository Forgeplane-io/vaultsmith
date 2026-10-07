# X.509 collection rejection evidence

The backend decoding change has no intended rendered UI effect. These genuine
running-app captures show the same generic Generate error before and after
bounded Subject/SAN collection retention. Fixtures contain only synthetic data.

| Before | After |
| --- | --- |
| [Before desktop](before-desktop.png) | [After desktop](after-desktop.png) |

## Capture conditions

- Captured on 2026-10-06 in Zen at loopback route
  `http://127.0.0.1:61521/workbench`, with the same browser window and sizing.
- Anonymous, authentication-off local development, synthetic profile `dev`.
  No deployed authentication fallback was used.
- Fresh app instance for each phase. Select X.509 CSR with the default ECDSA
  P-256 algorithm, enter common name `example.test` and nine organization lines
  `synthetic-0` through `synthetic-8`, submit once, then scroll to the lower form
  and error. Other Subject/SAN fields are empty.
- Both responses were checked at the server: Generate success count stayed at
  zero and invalid-request count became one. No private material was generated
  or displayed. The UI message remained: “The request was not accepted. Review
  the generation settings.”
- Source base: `1fb5346da7840ce036e993b8a27abb0ad3511b9f`. Before: the original
  backend source, with regression tests, benchmark, and a frontend build-only
  index change uncommitted. After: the same base plus the implementation changes
  to `backend/internal/generate/x509.go`,
  `backend/internal/httpapi/generate_http.go`, and
  `backend/internal/vaultservice/generate.go`, along with tests and the Generate
  ADR. Both phases used identical rebuilt frontend asset hashes.
- Computer Use normalized each capture to 2000×1183 pixels. The retained
  1700×1123 crop at x=300/y=60 excludes unrelated browser chrome and sidebar.
  Exact CSS viewport dimensions were not measured; window sizing was held
  constant. Pointer position differs slightly.

## Coverage limits

These captures cover the desktop Subject-overflow state only. Mobile,
authenticated UI, other algorithms, SAN overflow, and other interaction states
were not visually captured. REST/MCP boundary, strictness, authorization, CSR
signature/count, and generated-format behavior are covered by separate tests
and real-server checks. Screenshots supplement those checks; they do not prove
a successful generation operation.
