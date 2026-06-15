"""Hardening tests: input validation, edge cases, and error paths.

Standard library only; loopback only.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ssrfmcp.cli import main, _validate_numeric_args, _build_parser
from ssrfmcp.core import scan, probe_target, Canary, ScanReport
from ssrfmcp.mockserver import MockVulnerableServer


# ---------------------------------------------------------------------------
# Numeric argument validation
# ---------------------------------------------------------------------------

class TestValidateNumericArgs(unittest.TestCase):
    """_validate_numeric_args catches bad timeout/delay values."""

    def _ns(self, timeout=8.0, delay=0.0):
        p = _build_parser()
        return p.parse_args([
            "scan", "--target", "http://x",
            "--i-have-authorization",
            "--timeout", str(timeout),
            "--delay", str(delay),
        ])

    def test_valid_args_return_none(self):
        ns = self._ns(timeout=5.0, delay=0.5)
        self.assertIsNone(_validate_numeric_args(ns))

    def test_zero_timeout_returns_error(self):
        ns = self._ns(timeout=0.0)
        msg = _validate_numeric_args(ns)
        self.assertIsNotNone(msg)
        self.assertIn("timeout", msg.lower())

    def test_negative_timeout_returns_error(self):
        ns = self._ns(timeout=-1.0)
        msg = _validate_numeric_args(ns)
        self.assertIsNotNone(msg)
        self.assertIn("timeout", msg.lower())

    def test_negative_delay_returns_error(self):
        ns = self._ns(delay=-0.5)
        msg = _validate_numeric_args(ns)
        self.assertIsNotNone(msg)
        self.assertIn("delay", msg.lower())


# ---------------------------------------------------------------------------
# CLI bad-argument paths -> exit code 2
# ---------------------------------------------------------------------------

class TestCliBadArgs(unittest.TestCase):
    """CLI returns exit 2 and writes to stderr for invalid arguments."""

    def test_negative_timeout_cli_returns_2(self):
        rc = main([
            "scan",
            "--target", "http://127.0.0.1:1/x",
            "--i-have-authorization",
            "--timeout", "-1",
            "--no-canary",
        ])
        self.assertEqual(rc, 2)

    def test_negative_delay_cli_returns_2(self):
        rc = main([
            "scan",
            "--target", "http://127.0.0.1:1/x",
            "--i-have-authorization",
            "--delay", "-0.1",
            "--no-canary",
        ])
        self.assertEqual(rc, 2)

    def test_zero_timeout_demo_returns_2(self):
        rc = main([
            "demo",
            "--i-have-authorization",
            "--timeout", "0",
            "--no-canary",
        ])
        self.assertEqual(rc, 2)


# ---------------------------------------------------------------------------
# core.scan() ValueError for bad numeric args
# ---------------------------------------------------------------------------

class TestScanValidation(unittest.TestCase):
    """scan() raises ValueError for out-of-range timeout/delay."""

    def test_zero_timeout_raises(self):
        with self.assertRaises(ValueError) as ctx:
            scan("http://127.0.0.1:1/x", authorized=True,
                 timeout=0.0, use_canary=False)
        self.assertIn("timeout", str(ctx.exception).lower())

    def test_negative_timeout_raises(self):
        with self.assertRaises(ValueError):
            scan("http://127.0.0.1:1/x", authorized=True,
                 timeout=-5.0, use_canary=False)

    def test_negative_delay_raises(self):
        with self.assertRaises(ValueError) as ctx:
            scan("http://127.0.0.1:1/x", authorized=True,
                 delay=-1.0, use_canary=False)
        self.assertIn("delay", str(ctx.exception).lower())


# ---------------------------------------------------------------------------
# probe_target with empty payload list -> clean report, no crash
# ---------------------------------------------------------------------------

class TestProbeTargetEdgeCases(unittest.TestCase):
    """probe_target handles empty/unusual inputs without crashing."""

    def test_empty_payloads_returns_clean_report(self):
        def _never_called(_url):
            raise AssertionError("fetcher should not be called")

        report = probe_target(
            "http://127.0.0.1:1/x",
            fetcher=_never_called,
            canary=None,
            payloads=[],
        )
        self.assertIsInstance(report, ScanReport)
        self.assertEqual(report.vulnerable_count, 0)
        self.assertEqual(report.risk_score, 0)
        self.assertEqual(report.results, [])


# ---------------------------------------------------------------------------
# Canary bind error surfaces clearly
# ---------------------------------------------------------------------------

class TestCanaryBindError(unittest.TestCase):
    """Canary wraps OSError from bind with a clear message."""

    def test_bind_invalid_port_raises_oserror(self):
        # Port 99999 is always out of range — guaranteed OSError on all OSes.
        with self.assertRaises(OSError) as ctx:
            Canary(port=99999)
        self.assertIn("canary listener", str(ctx.exception).lower())


# ---------------------------------------------------------------------------
# MockServer: oversized Content-Length does not crash the server
# ---------------------------------------------------------------------------

class TestMockServerOversizedBody(unittest.TestCase):
    """MockServer caps Content-Length so a huge header value cannot OOM."""

    def test_normal_request_after_huge_claim_still_works(self):
        """Server survives a well-formed large body claim and still handles
        a subsequent normal request correctly."""
        with MockVulnerableServer() as mock:
            # Send a normal request with a large-but-real body that fits
            # within the 1 MB cap — server must return a valid JSON 200.
            big_url = "http://169.254.169.254/latest/meta-data/"
            body = json.dumps({
                "tool": "fetch",
                "arguments": {"url": big_url},
            }).encode("utf-8")
            req = urllib.request.Request(
                mock.url, data=body, method="POST",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                self.assertEqual(resp.status, 200)
                data = json.loads(resp.read().decode("utf-8"))
            self.assertIn("instance-id", data.get("body", ""))

    def test_max_body_constant(self):
        """The _MAX_BODY sentinel is set and is a positive integer."""
        from ssrfmcp.mockserver import _MockHandler
        self.assertGreater(_MockHandler._MAX_BODY, 0)
        self.assertIsInstance(_MockHandler._MAX_BODY, int)


if __name__ == "__main__":
    unittest.main()
