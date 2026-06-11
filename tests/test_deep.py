"""Deep tests for ssrfmcp: oracle logic, payload catalog, scoring, SARIF."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ssrfmcp.cli import _build_parser, _fail_code, _render_sarif, main
from ssrfmcp.core import (
    Canary,
    Payload,
    ScanReport,
    SEVERITY_ORDER,
    _builtin_payloads,
    _evaluate,
    probe_target,
    scan,
)
from ssrfmcp.mockserver import MockVulnerableServer, _fixture_for


# --- A non-vulnerable target: refuses internal URLs, echoes nothing useful ---
def _safe_fetcher(url):
    # A hardened server blocks SSRF: returns 403 with no body for everything.
    return (403, "")


# --- A target that merely echoes the URL back (should NOT be flagged) -------
def _echo_fetcher(url):
    return (200, url)


class TestPayloadCatalog(unittest.TestCase):
    def test_catalog_covers_required_classes(self):
        payloads = _builtin_payloads("http://127.0.0.1:9")
        kinds = {p.kind for p in payloads}
        for required in ("metadata", "loopback", "file", "canary", "bypass",
                         "linklocal"):
            self.assertIn(required, kinds)
        # The four headline payloads from the spec must all be present.
        urls = " ".join(p.url for p in payloads)
        self.assertIn("169.254.169.254/latest/meta-data/", urls)
        self.assertIn("http://localhost", urls)
        self.assertIn("file://", urls)
        self.assertIn("/c/", urls)  # canary URL

    def test_no_canary_payload_without_canary_base(self):
        payloads = _builtin_payloads(None)
        self.assertFalse(any(p.kind == "canary" for p in payloads))


class TestOracle(unittest.TestCase):
    def test_marker_match_is_vulnerable(self):
        p = Payload("x", "metadata", "http://169.254.169.254/latest/meta-data/",
                    "imds", "critical", ("instance-id",))
        res = _evaluate(p, 200, "ami-id\ninstance-id\n", [], None, "")
        self.assertTrue(res.vulnerable)
        self.assertEqual(res.severity, "critical")

    def test_error_is_not_vulnerable(self):
        p = Payload("x", "metadata", "http://169.254.169.254/", "imds",
                    "critical", ("instance-id",))
        res = _evaluate(p, None, "", [], None, "connection refused")
        self.assertFalse(res.vulnerable)
        self.assertEqual(res.severity, "info")

    def test_echo_only_is_not_vulnerable(self):
        # 200 + body that is just the URL echoed back must not be flagged.
        p = Payload("x", "loopback", "http://127.0.0.1/", "loopback", "high")
        res = _evaluate(p, 200, "http://127.0.0.1/", [], None, "")
        self.assertFalse(res.vulnerable)

    def test_non200_internal_not_flagged_without_marker(self):
        p = Payload("x", "loopback", "http://127.0.0.1/", "loopback", "high")
        res = _evaluate(p, 403, "", [], None, "")
        self.assertFalse(res.vulnerable)

    def test_canary_callback_oracle(self):
        token = "deadbeefcafef00d"
        p = Payload("canary-x", "canary",
                    f"http://127.0.0.1:9/c/{token}", "canary", "high", (token,))
        hits = [{"token": token, "client": "127.0.0.1",
                 "method": "GET", "path": f"/c/{token}"}]
        res = _evaluate(p, None, "", hits, token, "")
        self.assertTrue(res.vulnerable)
        self.assertTrue(any("canary callback" in e for e in res.evidence))


class TestHardenedTargetIsClean(unittest.TestCase):
    def test_safe_target_yields_no_findings(self):
        report = probe_target("http://safe", fetcher=_safe_fetcher,
                              canary=None)
        self.assertEqual(report.vulnerable_count, 0)
        self.assertEqual(report.risk_score, 0)
        self.assertIsNone(report.top_severity)

    def test_echo_target_yields_no_findings(self):
        report = probe_target("http://echo", fetcher=_echo_fetcher,
                              canary=None)
        self.assertEqual(report.vulnerable_count, 0)


class TestCanaryServer(unittest.TestCase):
    def test_canary_records_real_callback(self):
        import urllib.request
        with Canary() as canary:
            token = "abcdef0123456789"
            url = f"{canary.base_url}/c/{token}"
            with urllib.request.urlopen(url, timeout=4) as resp:
                self.assertEqual(resp.status, 200)
            self.assertTrue(any(h.get("token") == token for h in canary.hits))


class TestScoringAndReport(unittest.TestCase):
    def test_risk_score_capped_and_monotone(self):
        with MockVulnerableServer() as mock:
            report = scan(mock.url, authorized=True)
        self.assertLessEqual(report.risk_score, 100)
        self.assertGreater(report.risk_score, 0)
        d = report.to_dict()
        self.assertEqual(d["tool"], "ssrfmcp")
        self.assertIn("results", d)
        self.assertEqual(d["vulnerable_count"], report.vulnerable_count)

    def test_severity_ordering_sorts_vulnerable_first(self):
        with MockVulnerableServer() as mock:
            report = scan(mock.url, authorized=True)
        # First result should be vulnerable (sorted vulnerable-first).
        self.assertTrue(report.results[0].vulnerable)


class TestSarif(unittest.TestCase):
    def test_sarif_is_valid_json_with_results(self):
        with MockVulnerableServer() as mock:
            report = scan(mock.url, authorized=True)
        doc = json.loads(_render_sarif(report))
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "ssrfmcp")
        self.assertTrue(run["results"])
        self.assertTrue(run["tool"]["driver"]["rules"])


class TestFailOnPolicy(unittest.TestCase):
    def test_fail_on_high_trips_on_critical(self):
        with MockVulnerableServer() as mock:
            report = scan(mock.url, authorized=True)
        self.assertEqual(_fail_code(report, "high"), 1)

    def test_fail_on_clean_report_is_zero(self):
        report = ScanReport(target="x", canary_base=None, results=[])
        self.assertEqual(_fail_code(report, "low"), 0)


class TestFixtureRouting(unittest.TestCase):
    def test_decimal_ip_maps_to_imds(self):
        body = _fixture_for("http://2852039166/")
        self.assertIsNotNone(body)
        self.assertIn("instance-id", body)

    def test_file_passwd_fixture(self):
        body = _fixture_for("file:///etc/passwd")
        self.assertIn("root:x:0:0", body)


class TestParser(unittest.TestCase):
    def test_subcommands_present(self):
        p = _build_parser()
        ns = p.parse_args(["scan", "--target", "http://x",
                           "--i-have-authorization"])
        self.assertEqual(ns.command, "scan")
        self.assertTrue(ns.authorized)

    def test_unreachable_target_is_clean_report(self):
        # Per-payload connection failures are recorded as errors, not crashes;
        # an unreachable target yields a clean (no-SSRF) report -> exit 0.
        rc = main(["scan", "--target", "http://127.0.0.1:1/nope",
                   "--i-have-authorization", "--timeout", "1",
                   "--no-canary", "--format", "json"])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
