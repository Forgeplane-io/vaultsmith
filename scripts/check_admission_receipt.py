#!/usr/bin/env python3
"""Validate the checked-in admission benchmark receipt against runtime code."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Any

REQUEST_BODY_LIMIT = 8 << 20
MINIMUM_POD_MEMORY = 2 << 30
EXPECTED_CANDIDATES = [1, 2, 4, 8, 16]
EXPECTED_WORKLOADS = {
    "canonical_encrypt_max_plaintext": ("canonical_rest", "bearer_delegated_user", "encrypt", 200),
    "canonical_decrypt_valid_max_plaintext_vault": ("canonical_rest", "bearer_client_credentials", "decrypt", 200),
    "canonical_rotate_valid_max_plaintext_vault": ("canonical_rest", "bearer_delegated_user", "rotate", 200),
    "legacy_encrypt_max_plaintext": ("legacy_rest", "session", "encrypt", 200),
    "legacy_decrypt_valid_max_plaintext_vault": ("legacy_rest", "session", "decrypt", 200),
    "legacy_rotate_valid_max_plaintext_vault": ("legacy_rest", "session", "rotate", 200),
    "mcp_encrypt_max_plaintext": ("mcp", "bearer_client_credentials", "encrypt", 200),
    "mcp_decrypt_valid_max_plaintext_vault": ("mcp", "bearer_delegated_user", "decrypt", 200),
    "mcp_rotate_valid_max_plaintext_vault": ("mcp", "bearer_client_credentials", "rotate", 200),
    "malformed_rest_body_at_http_limit": ("canonical_rest", "anonymous", "decode_rejection", 400),
    "malformed_mcp_body_at_http_limit": ("mcp", "anonymous", "decode_rejection", 400),
}
EXPECTED_METRICS = {
    "vaultsmith_operation_admission_capacity",
    "vaultsmith_operation_admission_in_use",
    "vaultsmith_operation_admission_rejections_total",
}


class ReceiptError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReceiptError(message)


def load_receipt(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise ReceiptError(f"cannot read benchmark receipt {path}: {error}") from error
    matches = re.findall(r"```json\s*(\{.*?\})\s*```", text, flags=re.DOTALL)
    require(len(matches) == 1, f"{path} must contain exactly one fenced JSON receipt")
    try:
        value = json.loads(matches[0])
    except json.JSONDecodeError as error:
        raise ReceiptError(f"{path} contains invalid receipt JSON: {error}") from error
    require(isinstance(value, dict), f"{path} receipt must be a JSON object")
    return value


def load_compiled_capacity(path: Path) -> int:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise ReceiptError(f"cannot read admission source {path}: {error}") from error
    matches = re.findall(r"(?m)^const MaxRuntimeAdmissionCapacity\s*=\s*([0-9]+)\s*$", text)
    require(len(matches) == 1, f"{path} must define one literal MaxRuntimeAdmissionCapacity")
    return int(matches[0])


def positive_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0


def validate_receipt(receipt: dict[str, Any], compiled_capacity: int) -> None:
    require(receipt.get("release_qualified") is True, "receipt is not release-qualified")
    require(receipt.get("goos") == "linux", "receipt GOOS must be linux")
    require(receipt.get("goarch") == "amd64", "receipt GOARCH must be amd64")
    require(receipt.get("container_ram_bytes") in (str(MINIMUM_POD_MEMORY), MINIMUM_POD_MEMORY), "receipt must use the exact 2 GiB container memory limit")
    require(receipt.get("minimum_pod_memory_bytes") == MINIMUM_POD_MEMORY, "minimum pod memory must be exactly 2 GiB")
    require(receipt.get("request_body_limit_bytes") == REQUEST_BODY_LIMIT, "receipt request-body limit does not match the 8 MiB runtime limit")
    require(receipt.get("candidate_capacities") == EXPECTED_CANDIDATES, f"candidate capacities must be {EXPECTED_CANDIDATES}")
    require(receipt.get("selected_capacity") == compiled_capacity, f"selected capacity does not match compiled capacity {compiled_capacity}")
    require(receipt.get("selected_capacity") in receipt["candidate_capacities"], "selected capacity is absent from candidate matrix")
    require(isinstance(receipt.get("concurrency"), int) and receipt["concurrency"] > compiled_capacity, "benchmark concurrency must exceed the selected capacity")
    require(isinstance(receipt.get("profile_count"), int) and receipt["profile_count"] >= 2, "benchmark must include at least two profiles for rotation")
    try:
        generated = dt.datetime.fromisoformat(str(receipt["generated_at"]).replace("Z", "+00:00"))
    except (KeyError, ValueError) as error:
        raise ReceiptError("generated_at must be an ISO-8601 timestamp") from error
    require(generated.tzinfo is not None, "generated_at must include a timezone")

    workloads_value = receipt.get("workloads")
    require(isinstance(workloads_value, list), "workloads must be an array")
    if not isinstance(workloads_value, list):
        raise AssertionError("require() did not reject invalid workloads")
    workloads: dict[str, dict[str, Any]] = {}
    for item in workloads_value:
        require(isinstance(item, dict), "each workload must be an object")
        name = item.get("name")
        require(isinstance(name, str) and name not in workloads, "workload names must be unique non-empty strings")
        workloads[name] = item
    require(set(workloads) == set(EXPECTED_WORKLOADS), "receipt workload matrix does not match the required REST/legacy/MCP matrix")
    for name, (transport, auth_kind, operation, status) in EXPECTED_WORKLOADS.items():
        item = workloads[name]
        require(item.get("transport") == transport, f"workload {name} has the wrong transport")
        require(item.get("authentication_kind") == auth_kind, f"workload {name} has the wrong authentication kind")
        require(item.get("operation") == operation, f"workload {name} has the wrong operation")
        require(item.get("expected_status") == status, f"workload {name} has the wrong expected status")
        require(isinstance(item.get("request_body_bytes"), int) and 0 < item["request_body_bytes"] <= REQUEST_BODY_LIMIT, f"workload {name} has an invalid request-body size")
    for name in ("malformed_rest_body_at_http_limit", "malformed_mcp_body_at_http_limit"):
        require(workloads[name]["request_body_bytes"] == REQUEST_BODY_LIMIT, f"workload {name} must reach the 8 MiB HTTP limit")

    candidates_value = receipt.get("candidates")
    require(isinstance(candidates_value, list), "candidates must be an array")
    if not isinstance(candidates_value, list):
        raise AssertionError("require() did not reject invalid candidates")
    candidates: dict[int, dict[str, Any]] = {}
    for item in candidates_value:
        require(isinstance(item, dict), "each candidate must be an object")
        capacity = item.get("capacity")
        require(isinstance(capacity, int) and capacity not in candidates, "candidate capacities must be unique integers")
        candidates[capacity] = item
    require(set(candidates) == set(EXPECTED_CANDIDATES), "candidate result rows do not match candidate capacities")

    selected = candidates[compiled_capacity]
    require(positive_number(selected.get("baseline_rss_bytes")), "selected candidate must record positive baseline RSS")
    require(positive_number(selected.get("peak_rss_bytes")), "selected candidate must record positive peak RSS")
    require(selected["peak_rss_bytes"] < MINIMUM_POD_MEMORY, "selected candidate peak RSS reaches or exceeds the 2 GiB threshold")
    require(selected.get("peak_leases") == compiled_capacity, "selected candidate did not observe every configured lease")
    require(selected.get("unexpected_failures") == 0, "selected candidate has unexpected failures")
    require(positive_number(selected.get("completed_requests")), "selected candidate completed no requests")
    require(positive_number(selected.get("throughput_per_second")), "selected candidate has no throughput measurement")
    require(positive_number(selected.get("saturation_rejections")), "selected candidate did not prove saturation behavior")
    require(selected.get("admission_rejection_metric") == selected.get("saturation_rejections"), "admission rejection metric does not match observed saturation")

    per_request = selected.get("per_request_peak_rss_bytes")
    require(isinstance(per_request, dict) and set(per_request) == set(EXPECTED_WORKLOADS), "selected candidate must record one per-request RSS peak for every workload")
    if not isinstance(per_request, dict):
        raise AssertionError("require() did not reject invalid per-request peaks")
    for name, peak in per_request.items():
        require(positive_number(peak), f"workload {name} has no positive per-request RSS peak")
        require(peak < MINIMUM_POD_MEMORY, f"workload {name} per-request RSS reaches or exceeds the 2 GiB threshold")

    completed = selected.get("completed_by_workload")
    require(isinstance(completed, dict) and set(completed) == set(EXPECTED_WORKLOADS), "selected candidate completion map does not match the workload matrix")
    if not isinstance(completed, dict):
        raise AssertionError("require() did not reject invalid completion counts")
    for name, count in completed.items():
        require(isinstance(count, int) and count > 0, f"selected candidate completed no requests for workload {name}")

    saturation = receipt.get("saturation_response")
    require(saturation == {"http_status": 503, "error_code": "temporarily_unavailable", "retry_after_seconds": 1}, "saturation response contract is wrong")
    metrics = receipt.get("admission_metrics")
    require(isinstance(metrics, list) and EXPECTED_METRICS.issubset(set(metrics)), "receipt is missing required bounded admission metrics")
    for field in ("selection_basis", "memory_threshold_basis", "threshold_exceeded_effect", "remediation"):
        require(isinstance(receipt.get(field), str) and receipt[field].strip(), f"receipt is missing {field}")


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, default=root / "docs/benchmarks/admission-linux-amd64-2026-08-12.md")
    parser.add_argument("--admission-source", type=Path, default=root / "backend/internal/vaultservice/admission.go")
    args = parser.parse_args()
    try:
        receipt = load_receipt(args.receipt)
        compiled_capacity = load_compiled_capacity(args.admission_source)
        validate_receipt(receipt, compiled_capacity)
    except ReceiptError as error:
        print(f"admission receipt check failed: {error}", file=sys.stderr)
        return 1
    print(f"admission receipt check: qualified capacity {compiled_capacity} under the exact 2 GiB Linux/amd64 envelope")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
