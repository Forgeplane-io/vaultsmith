import copy
import unittest

import check_admission_receipt as receipt_check


class AdmissionReceiptCheckTests(unittest.TestCase):
    def valid_receipt(self):
        workloads = []
        for name, contract in receipt_check.EXPECTED_WORKLOADS.items():
            transport, auth_kind, operation, status = contract
            body_bytes = (
                receipt_check.REQUEST_BODY_LIMIT
                if name.startswith("malformed_")
                else 1024
            )
            workloads.append(
                {
                    "name": name,
                    "transport": transport,
                    "authentication_kind": auth_kind,
                    "operation": operation,
                    "request_body_bytes": body_bytes,
                    "expected_status": status,
                }
            )

        selected = {
            "capacity": 16,
            "baseline_rss_bytes": 100,
            "peak_rss_bytes": 200,
            "per_request_peak_rss_bytes": {
                name: 150 for name in receipt_check.EXPECTED_WORKLOADS
            },
            "peak_leases": 16,
            "completed_requests": 100,
            "saturation_rejections": 10,
            "unexpected_failures": 0,
            "throughput_per_second": 20.0,
            "completed_by_workload": {
                name: 1 for name in receipt_check.EXPECTED_WORKLOADS
            },
            "admission_rejection_metric": 10,
        }
        candidates = [
            selected if capacity == 16 else {"capacity": capacity}
            for capacity in receipt_check.EXPECTED_CANDIDATES
        ]
        return {
            "generated_at": "2026-08-12T12:00:00Z",
            "release_qualified": True,
            "goos": "linux",
            "goarch": "amd64",
            "container_ram_bytes": str(receipt_check.MINIMUM_POD_MEMORY),
            "minimum_pod_memory_bytes": receipt_check.MINIMUM_POD_MEMORY,
            "request_body_limit_bytes": receipt_check.REQUEST_BODY_LIMIT,
            "candidate_capacities": receipt_check.EXPECTED_CANDIDATES,
            "selected_capacity": 16,
            "concurrency": 32,
            "profile_count": 4,
            "workloads": workloads,
            "candidates": candidates,
            "saturation_response": {
                "http_status": 503,
                "error_code": "temporarily_unavailable",
                "retry_after_seconds": 1,
            },
            "admission_metrics": sorted(receipt_check.EXPECTED_METRICS),
            "selection_basis": "measured",
            "memory_threshold_basis": "2 GiB envelope",
            "threshold_exceeded_effect": "pod can be OOM-killed",
            "remediation": "lower capacity and rerun the benchmark",
        }

    def test_accepts_complete_receipt_matching_compiled_capacity(self):
        receipt_check.validate_receipt(self.valid_receipt(), 16)

    def test_rejects_stale_selected_capacity(self):
        receipt = self.valid_receipt()
        receipt["selected_capacity"] = 8
        with self.assertRaisesRegex(receipt_check.ReceiptError, "compiled capacity"):
            receipt_check.validate_receipt(receipt, 16)

    def test_rejects_missing_per_request_peak(self):
        receipt = self.valid_receipt()
        selected = receipt["candidates"][-1]
        del selected["per_request_peak_rss_bytes"]["mcp_rotate_valid_max_plaintext_vault"]
        with self.assertRaisesRegex(receipt_check.ReceiptError, "per-request RSS peak"):
            receipt_check.validate_receipt(receipt, 16)

    def test_rejects_unqualified_platform(self):
        receipt = copy.deepcopy(self.valid_receipt())
        receipt["release_qualified"] = False
        with self.assertRaisesRegex(receipt_check.ReceiptError, "not release-qualified"):
            receipt_check.validate_receipt(receipt, 16)


if __name__ == "__main__":
    unittest.main()
