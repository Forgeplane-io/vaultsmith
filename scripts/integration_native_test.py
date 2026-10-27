import ast
import csv
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "scripts/integration-native.sh"


class NativeHarnessTests(unittest.TestCase):
    def test_host_launch_uses_only_ipv4_loopback(self):
        source = HARNESS.read_text()
        match = re.search(r"\(\n  AUTH_MODE=native \\\n.*?\n\) &\nSERVER_PID=\$!", source, re.S)
        self.assertIsNotNone(match, "native host launch stanza is missing")
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory)
            stub = private / "vaultsmith"
            stub.write_text('#!/bin/sh\nprintf "%s" "$HTTP_ADDR" > "$TMP_DIR/bind-result"\n')
            stub.chmod(0o700)
            environment = {"PATH": os.environ["PATH"], "TMP_DIR": directory}
            for variable in re.findall(r"\$([A-Z_][A-Z_0-9]*)", match[0]):
                environment.setdefault(variable, "synthetic")
            result = subprocess.run(
                ["bash", "-c", match[0] + '\nwait "$SERVER_PID"\n'],
                env=environment, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, "inert host launch failed")
            self.assertEqual((private / "bind-result").read_text(), "127.0.0.1:18080")

    def compose_config(self, linux=False):
        arguments = ["docker", "compose", "-f", str(ROOT / "integration/docker-compose.yml")]
        if linux:
            arguments += ["-f", str(ROOT / "integration/docker-compose.linux.yml")]
        arguments += ["config", "--format", "json"]
        environment = dict(os.environ, KEYCLOAK_ADMIN_USERNAME="synthetic", KEYCLOAK_ADMIN_PASSWORD="synthetic")
        result = subprocess.run(arguments, env=environment, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, "Compose fixture configuration could not be resolved")
        return json.loads(result.stdout)

    def test_macos_edge_keeps_loopback_published_bridge_port(self):
        edge = self.compose_config()["services"]["edge"]
        self.assertNotEqual(edge.get("network_mode"), "host")
        self.assertEqual([(port["host_ip"], port["target"], str(port["published"])) for port in edge["ports"]], [("127.0.0.1", 443, "18443")])

    def test_linux_edge_has_no_inherited_published_ports_or_host_alias(self):
        edge = self.compose_config(linux=True)["services"]["edge"]
        self.assertEqual(edge["network_mode"], "host")
        self.assertFalse(edge.get("ports"), "published ports must not survive host-mode merge")
        self.assertFalse(edge.get("extra_hosts"), "bridge host alias must not survive host-mode merge")
        self.assertTrue(any(volume.get("source", "").endswith("Caddyfile-linux") for volume in edge["volumes"]))
        self.assertIn("18443", " ".join(edge["healthcheck"]["test"]))

    def healthcheck_result(self, edge_ready, app_ready):
        command = self.compose_config(linux=True)["services"]["edge"]["healthcheck"]["test"]
        self.assertEqual(command[0], "CMD-SHELL")
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory)
            tool = '''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
from urllib.parse import urlparse
name=Path(sys.argv[0]).name
arguments=sys.argv[1:]
if name == "nc":
    role="edge"
    valid=arguments == ["127.0.0.1", "18443"]
else:
    target=urlparse(arguments[-1])
    role="edge" if target.port == 18443 else "app"
    if role == "edge":
        valid=target.scheme == "https" and target.hostname == "localhost" and target.port == 18443 and "--resolve" in arguments and "localhost:18443:127.0.0.1" in arguments
    else:
        valid=target.scheme == "http" and target.hostname == "127.0.0.1" and target.port == 18080 and target.path == "/readyz"
ready=os.environ["EDGE_READY" if role == "edge" else "APP_READY"] == "1"
with Path(os.environ["CALLS"]).open("a") as output:
    output.write(json.dumps({"role":role,"explicit_ipv4_target":valid})+"\\n")
sys.exit(0 if valid and ready else 1)
'''
            for name in ("nc", "wget", "curl"):
                path = private / name
                path.write_text(tool)
                path.chmod(0o700)
            calls = private / "calls.jsonl"
            environment = dict(os.environ, PATH=str(private) + os.pathsep + os.environ["PATH"], CALLS=str(calls), EDGE_READY="1" if edge_ready else "0", APP_READY="1" if app_ready else "0")
            result = subprocess.run(["sh", "-c", command[1]], env=environment, capture_output=True)
            observed = [json.loads(line) for line in calls.read_text().splitlines()]
            self.assertTrue(all(call["explicit_ipv4_target"] for call in observed), "healthcheck used the wrong address family, port or readiness route")
            return result.returncode, observed

    def test_linux_healthcheck_requires_both_ipv4_listeners(self):
        status, calls = self.healthcheck_result(True, True)
        self.assertEqual(status, 0)
        self.assertEqual({call["role"] for call in calls}, {"edge", "app"})

    def test_linux_healthcheck_rejects_unavailable_edge(self):
        status, _ = self.healthcheck_result(False, True)
        self.assertNotEqual(status, 0)

    def test_linux_healthcheck_rejects_unready_application(self):
        status, _ = self.healthcheck_result(True, False)
        self.assertNotEqual(status, 0)

    def test_linux_caddy_has_only_the_intended_listener(self):
        source = (ROOT / "integration/Caddyfile-linux").read_text()
        for expected in ["https://localhost:18443", "bind 127.0.0.1", "reverse_proxy 127.0.0.1:18080", "admin off", "auto_https disable_redirects", "skip_install_trust"]:
            self.assertIn(expected, source)
        base = (ROOT / "integration/Caddyfile").read_text()
        self.assertEqual(re.findall(r"header_up .*", source), re.findall(r"header_up .*", base))
        self.assertIn("@private path /healthz /readyz", source)

    def test_lane_fixture_has_no_direct_grants_and_only_two_directed_allows(self):
        source = HARNESS.read_text()
        match = re.search(r"<<'DELEGATION_POLICY'\n(.*?)\nDELEGATION_POLICY", source, re.S)
        self.assertIsNotNone(match, "lane-only fixture policy is missing")
        rows = list(csv.reader(io.StringIO(match[1]), skipinitialspace=True))
        self.assertFalse(any(row[0] == "p" and row[3] in ("encrypt", "decrypt") and row[4] == "allow" for row in rows))
        self.assertEqual(set(re.findall(r"p, role:rekey-delegate, (rotation:[a-z]+:[a-z]+), rotate, allow", source)), {"rotation:dev:prod", "rotation:stage:archive"})
        self.assertIn('"native-owner-removal"', source)
        self.assertIn('"native-private-oracle"', source)

    def test_baseline_probe_context_preserves_explicit_oidc_redirect(self):
        source = HARNESS.read_text()
        start = source.index("import html.parser\n")
        module = ast.parse(source[start:source.index("\nPY\n", start)])
        option_keys = [
            [key.value for key in node.keys if isinstance(key, ast.Constant)]
            for node in ast.walk(module) if isinstance(node, ast.Dict)
        ]
        options = next(keys for keys in option_keys if "OIDC_ISSUER_URL" in keys)
        self.assertIn("OIDC_REDIRECT_URL", options)

    def test_positive_policy_fixtures_have_only_the_intended_operator_lane(self):
        blocks = re.findall(r"<<'POLICY'\n(.*?)\nPOLICY", HARNESS.read_text(), re.S)
        self.assertEqual(len(blocks), 2)
        for block in blocks:
            rows = list(csv.reader(io.StringIO(block), skipinitialspace=True))
            rotations = [row[2] for row in rows if len(row) == 5 and row[0] == "p" and row[3:] == ["rotate", "allow"]]
            self.assertEqual(rotations, ["rotation:dev:prod"])


if __name__ == "__main__":
    unittest.main()
