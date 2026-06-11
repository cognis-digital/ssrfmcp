"""Smoke tests for ssrfmcp. Standard library only; loopback only."""

import json
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ssrfmcp import TOOL_NAME, TOOL_VERSION
from ssrfmcp.cli import main
from ssrfmcp.core import scan
from ssrfmcp.mockserver import MockVulnerableServer

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestMetadata(unittest.TestCase):
    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "ssrfmcp")
        self.assertTrue(TOOL_VERSION)


class TestAuthGate(unittest.TestCase):
    def test_scan_refuses_without_authorization(self):
        with self.assertRaises(PermissionError):
            scan("http://127.0.0.1:1/x", authorized=False)

    def test_cli_scan_refuses_without_flag(self):
        # exit code 3 = authorization not granted
        rc = main(["scan", "--target", "http://127.0.0.1:1/nope"])
        self.assertEqual(rc, 3)


class TestVersionHelp(unittest.TestCase):
    def test_version_exits_zero(self):
        proc = subprocess.run(
            [sys.executable, "-m", "ssrfmcp", "--version"],
            cwd=REPO_ROOT, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(TOOL_VERSION, proc.stdout)

    def test_help_exits_zero(self):
        proc = subprocess.run(
            [sys.executable, "-m", "ssrfmcp", "--help"],
            cwd=REPO_ROOT, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("scan", proc.stdout)
        self.assertIn("demo", proc.stdout)


class TestProbeAgainstMock(unittest.TestCase):
    def test_detects_metadata_and_file_ssrf(self):
        with MockVulnerableServer() as mock:
            report = scan(mock.url, authorized=True)
        rules = {r.payload_id for r in report.results if r.vulnerable}
        self.assertIn("aws-imds-root", rules)
        self.assertIn("aws-imds-creds", rules)
        self.assertIn("file-etc-passwd", rules)
        self.assertGreater(report.vulnerable_count, 0)
        self.assertEqual(report.top_severity, "critical")
        self.assertGreaterEqual(report.risk_score, 45)

    def test_blind_canary_callback_detected(self):
        with MockVulnerableServer() as mock:
            report = scan(mock.url, authorized=True, use_canary=True)
        canary = [r for r in report.results if r.kind == "canary"]
        self.assertTrue(canary, "no canary payload was generated")
        self.assertTrue(canary[0].vulnerable,
                        "canary outbound fetch was not detected")
        # Detected either via the loopback callback log (blind SSRF) or via the
        # token reflected in the target's response (reflected SSRF).
        self.assertTrue(any(("canary callback" in e) or ("canary token" in e)
                            for e in canary[0].evidence),
                        canary[0].evidence)


class TestCli(unittest.TestCase):
    def test_demo_json_reports_ssrf(self):
        proc = subprocess.run(
            [sys.executable, "-m", "ssrfmcp", "demo",
             "--i-have-authorization", "--format", "json"],
            cwd=REPO_ROOT, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 1, proc.stderr)  # fail-on high
        data = json.loads(proc.stdout)
        self.assertGreater(data["vulnerable_count"], 0)
        self.assertEqual(data["top_severity"], "critical")

    def test_demo_refuses_without_flag(self):
        proc = subprocess.run(
            [sys.executable, "-m", "ssrfmcp", "demo"],
            cwd=REPO_ROOT, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 3)


if __name__ == "__main__":
    unittest.main()
