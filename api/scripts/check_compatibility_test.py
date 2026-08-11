import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


CHECKER = Path(__file__).with_name("check_compatibility.py")


class CompatibilityAllowlistTest(unittest.TestCase):
    def run_checker(self, report: list[dict[str, object]], entries: list[dict[str, object]]) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = root / "report.json"
            allowlist_path = root / "allowlist.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            allowlist_path.write_text(json.dumps({"version": 1, "entries": entries}), encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(CHECKER), str(report_path), str(allowlist_path)],
                check=False,
                capture_output=True,
                text=True,
            )

    @staticmethod
    def finding(fingerprint: str = "facaba43342e") -> dict[str, object]:
        return {
            "id": "api-path-removed-without-deprecation",
            "text": "api path removed without deprecation",
            "level": 3,
            "operation": "POST",
            "operationId": "encryptValue",
            "path": "/api/v1/profiles/{profileId}/encrypt",
            "section": "paths",
            "fingerprint": fingerprint,
        }

    @staticmethod
    def entry(fingerprint: str = "facaba43342e") -> dict[str, object]:
        return {
            "fingerprint": fingerprint,
            "ruleId": "api-path-removed-without-deprecation",
            "operation": "POST",
            "operationId": "encryptValue",
            "path": "/api/v1/profiles/{profileId}/encrypt",
            "section": "paths",
            "reason": "Synthetic test exception.",
        }

    def test_accepts_an_empty_report_and_allowlist(self) -> None:
        result = self.run_checker([], [])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("0 breaking change occurrence(s)", result.stdout)

    def test_accepts_one_documented_entry_for_one_occurrence(self) -> None:
        result = self.run_checker([self.finding()], [self.entry()])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("1 allow-listed", result.stdout)

    def test_rejects_an_unlisted_occurrence(self) -> None:
        result = self.run_checker([self.finding()], [])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unexpected breaking change", result.stderr)
        self.assertIn("facaba43342e", result.stderr)

    def test_rejects_a_stale_entry(self) -> None:
        result = self.run_checker([], [self.entry()])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("stale allow-list entry", result.stderr)

    def test_rejects_metadata_that_does_not_match_the_fingerprint_occurrence(self) -> None:
        entry = self.entry()
        entry["operation"] = "GET"
        result = self.run_checker([self.finding()], [entry])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("metadata mismatch", result.stderr)

    def test_rejects_missing_occurrence_metadata(self) -> None:
        for field in ("operation", "operationId", "path", "section"):
            with self.subTest(field=field):
                entry = self.entry()
                del entry[field]
                result = self.run_checker([self.finding()], [entry])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"{field} must document", result.stderr)

    def test_rejects_duplicate_allowlist_fingerprints(self) -> None:
        result = self.run_checker([self.finding()], [self.entry(), self.entry()])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate allow-list fingerprint", result.stderr)

    def test_rejects_duplicate_report_fingerprints(self) -> None:
        result = self.run_checker([self.finding(), self.finding()], [self.entry()])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate oasdiff fingerprint", result.stderr)


if __name__ == "__main__":
    unittest.main()
