# Vaultsmith Admission Benchmark Receipt

This release receipt measures real canonical REST, legacy REST, and MCP decoders with session, delegated-user Bearer, client-credentials Bearer, and anonymous malformed traffic through the shared Vaultsmith service and Ansible Vault AES256/PBKDF2 executor. The malformed REST and MCP workloads each reach the 8 MiB HTTP body limit and are expected to fail strict JSON decoding. Each candidate records absolute per-request and concurrent process RSS peaks.

```json
{
  "generated_at": "2026-08-12T15:25:46Z",
  "release_qualified": true,
  "goos": "linux",
  "goarch": "amd64",
  "go_version": "go1.25.12",
  "host_cpu": "10",
  "host_ram_bytes": "34359738368",
  "container_cpu": 3,
  "container_ram_bytes": "2147483648",
  "gomaxprocs": 3,
  "profile_count": 4,
  "request_body_limit_bytes": 8388608,
  "candidate_capacities": [
    1,
    2,
    4,
    8,
    16
  ],
  "selected_capacity": 16,
  "minimum_pod_memory_bytes": 2147483648,
  "concurrency": 32,
  "workloads": [
    {
      "name": "canonical_encrypt_max_plaintext",
      "transport": "canonical_rest",
      "authentication_kind": "bearer_delegated_user",
      "operation": "encrypt",
      "request_body_bytes": 1048592,
      "expected_status": 200
    },
    {
      "name": "canonical_decrypt_valid_max_plaintext_vault",
      "transport": "canonical_rest",
      "authentication_kind": "bearer_client_credentials",
      "operation": "decrypt",
      "request_body_bytes": 4299545,
      "expected_status": 200
    },
    {
      "name": "canonical_rotate_valid_max_plaintext_vault",
      "transport": "canonical_rest",
      "authentication_kind": "bearer_delegated_user",
      "operation": "rotate",
      "request_body_bytes": 4299606,
      "expected_status": 200
    },
    {
      "name": "legacy_encrypt_max_plaintext",
      "transport": "legacy_rest",
      "authentication_kind": "session",
      "operation": "encrypt",
      "request_body_bytes": 1048627,
      "expected_status": 200
    },
    {
      "name": "legacy_decrypt_valid_max_plaintext_vault",
      "transport": "legacy_rest",
      "authentication_kind": "session",
      "operation": "decrypt",
      "request_body_bytes": 4299580,
      "expected_status": 200
    },
    {
      "name": "legacy_rotate_valid_max_plaintext_vault",
      "transport": "legacy_rest",
      "authentication_kind": "session",
      "operation": "rotate",
      "request_body_bytes": 4299618,
      "expected_status": 200
    },
    {
      "name": "mcp_encrypt_max_plaintext",
      "transport": "mcp",
      "authentication_kind": "bearer_client_credentials",
      "operation": "encrypt",
      "request_body_bytes": 1048814,
      "expected_status": 200
    },
    {
      "name": "mcp_decrypt_valid_max_plaintext_vault",
      "transport": "mcp",
      "authentication_kind": "bearer_delegated_user",
      "operation": "decrypt",
      "request_body_bytes": 4299767,
      "expected_status": 200
    },
    {
      "name": "mcp_rotate_valid_max_plaintext_vault",
      "transport": "mcp",
      "authentication_kind": "bearer_client_credentials",
      "operation": "rotate",
      "request_body_bytes": 4299805,
      "expected_status": 200
    },
    {
      "name": "malformed_rest_body_at_http_limit",
      "transport": "canonical_rest",
      "authentication_kind": "anonymous",
      "operation": "decode_rejection",
      "request_body_bytes": 8388608,
      "expected_status": 400
    },
    {
      "name": "malformed_mcp_body_at_http_limit",
      "transport": "mcp",
      "authentication_kind": "anonymous",
      "operation": "decode_rejection",
      "request_body_bytes": 8388608,
      "expected_status": 400
    }
  ],
  "candidates": [
    {
      "capacity": 1,
      "requested_duration_seconds": 5,
      "measured_duration_seconds": 5.295659971,
      "baseline_rss_bytes": 63918080,
      "peak_rss_bytes": 211894272,
      "per_request_peak_rss_bytes": {
        "canonical_decrypt_valid_max_plaintext_vault": 120950784,
        "canonical_encrypt_max_plaintext": 113524736,
        "canonical_rotate_valid_max_plaintext_vault": 136634368,
        "legacy_decrypt_valid_max_plaintext_vault": 123781120,
        "legacy_encrypt_max_plaintext": 114786304,
        "legacy_rotate_valid_max_plaintext_vault": 122785792,
        "malformed_mcp_body_at_http_limit": 105779200,
        "malformed_rest_body_at_http_limit": 105664512,
        "mcp_decrypt_valid_max_plaintext_vault": 137326592,
        "mcp_encrypt_max_plaintext": 166932480,
        "mcp_rotate_valid_max_plaintext_vault": 163344384
      },
      "peak_leases": 1,
      "completed_requests": 30,
      "saturation_rejections": 132250,
      "unexpected_failures": 0,
      "throughput_per_second": 5.665016289619325,
      "p50_ms": 163.561879,
      "p95_ms": 366.964007,
      "p99_ms": 437.413164,
      "cpu_seconds": 14.705223,
      "completed_by_workload": {
        "canonical_decrypt_valid_max_plaintext_vault": 2,
        "canonical_encrypt_max_plaintext": 6,
        "canonical_rotate_valid_max_plaintext_vault": 1,
        "legacy_decrypt_valid_max_plaintext_vault": 2,
        "legacy_encrypt_max_plaintext": 5,
        "legacy_rotate_valid_max_plaintext_vault": 1,
        "malformed_mcp_body_at_http_limit": 1,
        "malformed_rest_body_at_http_limit": 1,
        "mcp_decrypt_valid_max_plaintext_vault": 2,
        "mcp_encrypt_max_plaintext": 6,
        "mcp_rotate_valid_max_plaintext_vault": 3
      },
      "admission_rejection_metric": 132250
    },
    {
      "capacity": 2,
      "requested_duration_seconds": 5,
      "measured_duration_seconds": 5.317536286,
      "baseline_rss_bytes": 70565888,
      "peak_rss_bytes": 238309376,
      "per_request_peak_rss_bytes": {
        "canonical_decrypt_valid_max_plaintext_vault": 128086016,
        "canonical_encrypt_max_plaintext": 121065472,
        "canonical_rotate_valid_max_plaintext_vault": 130826240,
        "legacy_decrypt_valid_max_plaintext_vault": 131264512,
        "legacy_encrypt_max_plaintext": 117833728,
        "legacy_rotate_valid_max_plaintext_vault": 140816384,
        "malformed_mcp_body_at_http_limit": 112390144,
        "malformed_rest_body_at_http_limit": 112398336,
        "mcp_decrypt_valid_max_plaintext_vault": 147128320,
        "mcp_encrypt_max_plaintext": 177053696,
        "mcp_rotate_valid_max_plaintext_vault": 179245056
      },
      "peak_leases": 2,
      "completed_requests": 45,
      "saturation_rejections": 101691,
      "unexpected_failures": 0,
      "throughput_per_second": 8.46256566569671,
      "p50_ms": 230.504199,
      "p95_ms": 398.565748,
      "p99_ms": 581.842314,
      "cpu_seconds": 14.799571999999998,
      "completed_by_workload": {
        "canonical_decrypt_valid_max_plaintext_vault": 7,
        "canonical_encrypt_max_plaintext": 5,
        "canonical_rotate_valid_max_plaintext_vault": 4,
        "legacy_decrypt_valid_max_plaintext_vault": 2,
        "legacy_encrypt_max_plaintext": 5,
        "legacy_rotate_valid_max_plaintext_vault": 5,
        "malformed_mcp_body_at_http_limit": 1,
        "malformed_rest_body_at_http_limit": 2,
        "mcp_decrypt_valid_max_plaintext_vault": 4,
        "mcp_encrypt_max_plaintext": 7,
        "mcp_rotate_valid_max_plaintext_vault": 3
      },
      "admission_rejection_metric": 101691
    },
    {
      "capacity": 4,
      "requested_duration_seconds": 5,
      "measured_duration_seconds": 5.116697743,
      "baseline_rss_bytes": 70438912,
      "peak_rss_bytes": 271712256,
      "per_request_peak_rss_bytes": {
        "canonical_decrypt_valid_max_plaintext_vault": 125796352,
        "canonical_encrypt_max_plaintext": 122527744,
        "canonical_rotate_valid_max_plaintext_vault": 142479360,
        "legacy_decrypt_valid_max_plaintext_vault": 136634368,
        "legacy_encrypt_max_plaintext": 115007488,
        "legacy_rotate_valid_max_plaintext_vault": 148123648,
        "malformed_mcp_body_at_http_limit": 112226304,
        "malformed_rest_body_at_http_limit": 112250880,
        "mcp_decrypt_valid_max_plaintext_vault": 151957504,
        "mcp_encrypt_max_plaintext": 179576832,
        "mcp_rotate_valid_max_plaintext_vault": 158056448
      },
      "peak_leases": 4,
      "completed_requests": 67,
      "saturation_rejections": 69120,
      "unexpected_failures": 0,
      "throughput_per_second": 13.094383011320277,
      "p50_ms": 299.041728,
      "p95_ms": 646.849007,
      "p99_ms": 738.360352,
      "cpu_seconds": 14.947276999999993,
      "completed_by_workload": {
        "canonical_decrypt_valid_max_plaintext_vault": 11,
        "canonical_encrypt_max_plaintext": 8,
        "canonical_rotate_valid_max_plaintext_vault": 10,
        "legacy_decrypt_valid_max_plaintext_vault": 2,
        "legacy_encrypt_max_plaintext": 4,
        "legacy_rotate_valid_max_plaintext_vault": 8,
        "malformed_mcp_body_at_http_limit": 5,
        "malformed_rest_body_at_http_limit": 3,
        "mcp_decrypt_valid_max_plaintext_vault": 9,
        "mcp_encrypt_max_plaintext": 5,
        "mcp_rotate_valid_max_plaintext_vault": 2
      },
      "admission_rejection_metric": 69120
    },
    {
      "capacity": 8,
      "requested_duration_seconds": 5,
      "measured_duration_seconds": 5.35033907,
      "baseline_rss_bytes": 69345280,
      "peak_rss_bytes": 351457280,
      "per_request_peak_rss_bytes": {
        "canonical_decrypt_valid_max_plaintext_vault": 133259264,
        "canonical_encrypt_max_plaintext": 116035584,
        "canonical_rotate_valid_max_plaintext_vault": 142811136,
        "legacy_decrypt_valid_max_plaintext_vault": 135880704,
        "legacy_encrypt_max_plaintext": 118624256,
        "legacy_rotate_valid_max_plaintext_vault": 142843904,
        "malformed_mcp_body_at_http_limit": 111206400,
        "malformed_rest_body_at_http_limit": 111202304,
        "mcp_decrypt_valid_max_plaintext_vault": 151666688,
        "mcp_encrypt_max_plaintext": 177831936,
        "mcp_rotate_valid_max_plaintext_vault": 151130112
      },
      "peak_leases": 8,
      "completed_requests": 85,
      "saturation_rejections": 56655,
      "unexpected_failures": 0,
      "throughput_per_second": 15.886843597746038,
      "p50_ms": 438.311456,
      "p95_ms": 1150.614948,
      "p99_ms": 1537.582809,
      "cpu_seconds": 15.558995999999993,
      "completed_by_workload": {
        "canonical_decrypt_valid_max_plaintext_vault": 14,
        "canonical_encrypt_max_plaintext": 17,
        "canonical_rotate_valid_max_plaintext_vault": 4,
        "legacy_decrypt_valid_max_plaintext_vault": 6,
        "legacy_encrypt_max_plaintext": 6,
        "legacy_rotate_valid_max_plaintext_vault": 11,
        "malformed_mcp_body_at_http_limit": 6,
        "malformed_rest_body_at_http_limit": 3,
        "mcp_decrypt_valid_max_plaintext_vault": 7,
        "mcp_encrypt_max_plaintext": 6,
        "mcp_rotate_valid_max_plaintext_vault": 5
      },
      "admission_rejection_metric": 56655
    },
    {
      "capacity": 16,
      "requested_duration_seconds": 5,
      "measured_duration_seconds": 5.471465905,
      "baseline_rss_bytes": 77377536,
      "peak_rss_bytes": 487276544,
      "per_request_peak_rss_bytes": {
        "canonical_decrypt_valid_max_plaintext_vault": 137216000,
        "canonical_encrypt_max_plaintext": 121454592,
        "canonical_rotate_valid_max_plaintext_vault": 146796544,
        "legacy_decrypt_valid_max_plaintext_vault": 142163968,
        "legacy_encrypt_max_plaintext": 121208832,
        "legacy_rotate_valid_max_plaintext_vault": 147435520,
        "malformed_mcp_body_at_http_limit": 119209984,
        "malformed_rest_body_at_http_limit": 119242752,
        "mcp_decrypt_valid_max_plaintext_vault": 160186368,
        "mcp_encrypt_max_plaintext": 183898112,
        "mcp_rotate_valid_max_plaintext_vault": 177786880
      },
      "peak_leases": 16,
      "completed_requests": 118,
      "saturation_rejections": 29714,
      "unexpected_failures": 0,
      "throughput_per_second": 21.56643247875635,
      "p50_ms": 659.630562,
      "p95_ms": 1808.050341,
      "p99_ms": 1995.819827,
      "cpu_seconds": 15.71899400000001,
      "completed_by_workload": {
        "canonical_decrypt_valid_max_plaintext_vault": 20,
        "canonical_encrypt_max_plaintext": 22,
        "canonical_rotate_valid_max_plaintext_vault": 10,
        "legacy_decrypt_valid_max_plaintext_vault": 12,
        "legacy_encrypt_max_plaintext": 9,
        "legacy_rotate_valid_max_plaintext_vault": 10,
        "malformed_mcp_body_at_http_limit": 13,
        "malformed_rest_body_at_http_limit": 4,
        "mcp_decrypt_valid_max_plaintext_vault": 6,
        "mcp_encrypt_max_plaintext": 8,
        "mcp_rotate_valid_max_plaintext_vault": 4
      },
      "admission_rejection_metric": 29714
    }
  ],
  "saturation_response": {
    "http_status": 503,
    "error_code": "temporarily_unavailable",
    "retry_after_seconds": 1
  },
  "admission_metrics": [
    "vaultsmith_operation_admission_capacity",
    "vaultsmith_operation_admission_in_use",
    "vaultsmith_operation_admission_rejections_total"
  ],
  "selection_basis": "capacity 16 is the reviewed compiled tripwire; all candidates ran real canonical REST, legacy REST, and MCP decoders with session, delegated-user Bearer, client-credentials Bearer, and anonymous malformed traffic through the shared service and Ansible Vault AES256/PBKDF2 executor, while excess callers were rejected before body retention",
  "memory_threshold_basis": "2147483648 bytes is the exact 2 GiB cgroup limit used to qualify the selected capacity; the selected baseline and peak RSS are recorded in the matching candidate row",
  "threshold_exceeded_effect": "a pod below this qualified memory limit is outside the release envelope and can be OOM-killed during concurrent maximum-size requests",
  "remediation": "rerun scripts/admission-benchmark.sh on the release architecture; if selected peak RSS reaches the threshold or unexpected failures occur, lower MaxRuntimeAdmissionCapacity, rerun all candidates, update this receipt, and set pod memory no lower than the newly qualified threshold"
}
```

The minimum pod memory limit is **2147483648 bytes (2 GiB)** because this is the fixed container envelope used to qualify capacity 16. A lower limit is not covered by this receipt. If observed RSS reaches the limit, the pod can be OOM-killed. Lower the compiled capacity and rerun `scripts/admission-benchmark.sh`; do not raise the cap without a new receipt.
