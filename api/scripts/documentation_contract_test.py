import re
import unittest
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[2]
DOCUMENTATION_FILES = (
    ROOT / "README.md",
    ROOT / "api" / "README.md",
    ROOT / "docs" / "api-reference.md",
    ROOT / "docs" / "api-clients.md",
    ROOT / "docs" / "authentication.md",
    ROOT / "docs" / "deployment.md",
    ROOT / "docs" / "api-operator-preflight.md",
    ROOT / "docs" / "adr" / "0001-api-mcp-foundation.md",
)
SOURCE_FILES = DOCUMENTATION_FILES + (
    ROOT / "api" / "openapi.yaml",
    ROOT / "frontend" / "src" / "generated" / "api.ts",
)
CANONICAL_ROUTES = (
    "GET /api/v1/profiles",
    "POST /api/v1/profiles/{profileId}/encrypt",
    "POST /api/v1/profiles/{profileId}/decrypt",
    "POST /api/v1/rotations",
)
FORBIDDEN_CURRENT_STATE_PHRASES = (
    "bridge-release",
    "server bridge release",
    "bundled UI keeps using the legacy operation route",
    "canonical REST until every serving pod",
    "below the bridge release",
    "bridge-image",
    "bridge canary",
)
LOCAL_LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
FENCED_BLOCK = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)


class DocumentationContractTest(unittest.TestCase):
    def test_canonical_routes_are_documented_in_primary_reference_files(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        reference = (ROOT / "docs" / "api-reference.md").read_text(encoding="utf-8")
        for route in CANONICAL_ROUTES:
            with self.subTest(route=route):
                self.assertIn(route, readme)
                self.assertIn(route, reference)

    def test_legacy_endpoint_is_marked_compatibility_only(self) -> None:
        contract = (ROOT / "api" / "openapi.yaml").read_text(encoding="utf-8")
        match = re.search(r"(?ms)^  /api/v1/operations:\n.*?(?=^  /api/v1/|^components:)", contract)
        if match is None:
            self.fail("OpenAPI contract is missing the legacy operation endpoint")
        legacy = match.group(0)
        self.assertIn("deprecated: true", legacy)
        self.assertIn("Compatibility-only", legacy)
        self.assertIn("bundled UI use the canonical REST routes", legacy)

    def test_legacy_endpoint_is_not_used_in_current_examples(self) -> None:
        for path in DOCUMENTATION_FILES:
            text = path.read_text(encoding="utf-8")
            for block in FENCED_BLOCK.findall(text):
                with self.subTest(path=path.relative_to(ROOT)):
                    self.assertNotIn("/api/v1/operations", block)

    def test_generated_reference_separates_compatibility_operations(self) -> None:
        reference = (ROOT / "docs" / "api-reference.md").read_text(encoding="utf-8")
        self.assertIn("# Operations", reference)
        self.assertIn("# Compatibility", reference)
        self.assertLess(
            reference.index("## `GET /api/v1/profiles`"),
            reference.index("# Compatibility"),
        )
        self.assertLess(
            reference.index("# Compatibility"),
            reference.index("## `POST /api/v1/operations`"),
        )

    def test_known_stale_bridge_phrases_are_absent_from_current_sources(self) -> None:
        for path in SOURCE_FILES:
            text = path.read_text(encoding="utf-8").lower()
            for phrase in FORBIDDEN_CURRENT_STATE_PHRASES:
                with self.subTest(path=path.relative_to(ROOT), phrase=phrase):
                    self.assertNotIn(phrase.lower(), text)

    def test_current_documentation_local_links_resolve(self) -> None:
        for path in DOCUMENTATION_FILES:
            text = path.read_text(encoding="utf-8")
            for raw_target in LOCAL_LINK.findall(text):
                target = unquote(raw_target.split("#", 1)[0].strip())
                if not target or target.startswith(("http://", "https://", "mailto:")):
                    continue
                resolved = (path.parent / target).resolve()
                with self.subTest(path=path.relative_to(ROOT), target=raw_target):
                    self.assertTrue(resolved.is_file(), f"missing local link target: {resolved}")


if __name__ == "__main__":
    unittest.main()
