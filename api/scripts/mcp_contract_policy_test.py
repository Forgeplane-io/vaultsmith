import unittest
from pathlib import Path


ADR = Path(__file__).resolve().parents[2] / "docs" / "adr" / "0001-api-mcp-foundation.md"


class MCPContractPolicyTest(unittest.TestCase):
    def test_strict_json_preserves_mcp_extension_points(self) -> None:
        text = ADR.read_text(encoding="utf-8")

        self.assertIn(
            "REST request DTOs, known JSON-RPC fields, and tool arguments use strict JSON.",
            text,
        )
        self.assertIn(
            "MCP protocol-defined extension points, including `_meta`, accept extension keys "
            "wherever the pinned `2026-07-28` schema permits them.",
            text,
        )
        self.assertNotIn("Requests use strict JSON.", text)
        self.assertNotIn("Requests remain strict.", text)


if __name__ == "__main__":
    unittest.main()
