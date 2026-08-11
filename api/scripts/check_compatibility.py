#!/usr/bin/env python3
"""Require an exact documented allow-list entry per oasdiff occurrence."""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


ENTRY_KEYS = {
    "fingerprint",
    "ruleId",
    "operation",
    "operationId",
    "path",
    "section",
    "reason",
}
MATCHING_FIELDS = {
    "ruleId": "id",
    "operation": "operation",
    "operationId": "operationId",
    "path": "path",
    "section": "section",
}


class ContractCheckError(Exception):
    pass


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ContractCheckError(f"cannot read {path}: {error}") from error
    except json.JSONDecodeError as error:
        raise ContractCheckError(f"invalid JSON in {path}: {error}") from error


def require_string(value: object, field: str, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractCheckError(f"{context} field {field!r} must be a non-empty string")
    return value


def validate_report(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        raise ContractCheckError("oasdiff report must be a JSON array")

    findings: list[dict[str, object]] = []
    for index, item in enumerate(value):
        context = f"oasdiff occurrence {index}"
        if not isinstance(item, dict):
            raise ContractCheckError(f"{context} must be an object")
        require_string(item.get("fingerprint"), "fingerprint", context)
        require_string(item.get("id"), "id", context)
        findings.append(item)

    duplicates = [fingerprint for fingerprint, count in Counter(
        str(item["fingerprint"]) for item in findings
    ).items() if count > 1]
    if duplicates:
        joined = ", ".join(sorted(duplicates))
        raise ContractCheckError(
            "duplicate oasdiff fingerprint(s) cannot identify one occurrence each: " + joined
        )
    return findings


def validate_allowlist(value: object) -> list[dict[str, object]]:
    if not isinstance(value, dict):
        raise ContractCheckError("allow-list must be a JSON object")
    if value.get("version") != 1:
        raise ContractCheckError("allow-list version must be 1")

    raw_entries = value.get("entries")
    if not isinstance(raw_entries, list):
        raise ContractCheckError("allow-list entries must be a JSON array")

    entries: list[dict[str, object]] = []
    for index, item in enumerate(raw_entries):
        context = f"allow-list entry {index}"
        if not isinstance(item, dict):
            raise ContractCheckError(f"{context} must be an object")
        unknown = sorted(set(item) - ENTRY_KEYS)
        if unknown:
            raise ContractCheckError(f"{context} has unknown field(s): {', '.join(unknown)}")
        require_string(item.get("fingerprint"), "fingerprint", context)
        require_string(item.get("ruleId"), "ruleId", context)
        require_string(item.get("reason"), "reason", context)
        for field in ("operation", "operationId", "path", "section"):
            if field in item:
                require_string(item[field], field, context)
        entries.append(item)

    duplicates = [fingerprint for fingerprint, count in Counter(
        str(item["fingerprint"]) for item in entries
    ).items() if count > 1]
    if duplicates:
        joined = ", ".join(sorted(duplicates))
        raise ContractCheckError("duplicate allow-list fingerprint(s): " + joined)
    return entries


def check(findings: list[dict[str, object]], entries: list[dict[str, object]]) -> list[str]:
    errors: list[str] = []
    finding_by_fingerprint = {str(item["fingerprint"]): item for item in findings}
    entry_by_fingerprint = {str(item["fingerprint"]): item for item in entries}

    for fingerprint, finding in finding_by_fingerprint.items():
        entry = entry_by_fingerprint.get(fingerprint)
        if entry is None:
            errors.append(
                "unexpected breaking change "
                f"{fingerprint}: {finding.get('id')} "
                f"{finding.get('operation', '')} {finding.get('path', '')}".rstrip()
            )
            continue

        for entry_field, finding_field in MATCHING_FIELDS.items():
            actual = finding.get(finding_field)
            documented = entry.get(entry_field)
            if isinstance(actual, str) and actual and documented is None:
                errors.append(
                    f"allow-list metadata mismatch for {fingerprint}: "
                    f"{entry_field} must document {actual!r}"
                )
            elif documented is not None and documented != actual:
                errors.append(
                    f"allow-list metadata mismatch for {fingerprint}: "
                    f"{entry_field}={documented!r}, oasdiff={actual!r}"
                )

    for fingerprint in sorted(set(entry_by_fingerprint) - set(finding_by_fingerprint)):
        errors.append(f"stale allow-list entry {fingerprint}: remove it")

    return errors


def main(arguments: list[str]) -> int:
    if len(arguments) != 3:
        print(
            f"usage: {Path(arguments[0]).name} OASDIFF_REPORT ALLOWLIST",
            file=sys.stderr,
        )
        return 2

    try:
        findings = validate_report(load_json(Path(arguments[1])))
        entries = validate_allowlist(load_json(Path(arguments[2])))
        errors = check(findings, entries)
    except ContractCheckError as error:
        print(f"API compatibility check failed: {error}", file=sys.stderr)
        return 1

    if errors:
        print("API compatibility check failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(
        "API compatibility check: "
        f"{len(findings)} breaking change occurrence(s); {len(entries)} allow-listed."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
