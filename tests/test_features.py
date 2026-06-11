"""Tests for v0.2 features: deep payloads, AI mode, badge + HTML output.

Standard library only; loopback only. The AI backend is exercised with an
in-process fake so no network or model is required.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ssrfmcp.cli import (
    _build_parser,
    _render_badge,
    _render_html,
    main,
)
from ssrfmcp.core import (
    CWE_BY_KIND,
    ScanReport,
    _builtin_payloads,
    merge_ai_findings,
    probe_target,
    run_ai_over_transcript,
    scan,
)
from ssrfmcp.mockserver import MockVulnerableServer


# --------------------------------------------------------------------------- #
# Deepened native detection
# --------------------------------------------------------------------------- #
class TestDeepPayloads(unittest.TestCase):
    def test_expanded_technique_coverage(self):
        payloads = _builtin_payloads("http://127.0.0.1:9")
        kinds = {p.kind for p in payloads}
        for required in ("metadata", "loopback", "linklocal", "file", "canary",
                         "bypass", "redirect", "rebind", "scheme"):
            self.assertIn(required, kinds, f"missing kind {required}")

    def test_cloud_provider_variants_present(self):
        ids = {p.id for p in _builtin_payloads(None)}
        for required in ("aws-imds-creds", "gcp-sa-token", "azure-msi-token",
                         "alibaba-metadata", "openstack-metadata",
                         "digitalocean-metadata"):
            self.assertIn(required, ids)

    def test_obfuscation_and_ipv6_present(self):
        urls = " ".join(p.url for p in _builtin_payloads(None))
        self.assertIn("0xA9FEA9FE", urls)        # hex IP
        self.assertIn("0251.0376", urls)          # octal IP
        self.assertIn("2852039166", urls)         # decimal IP
        self.assertIn("[::1]", urls)              # IPv6 loopback
        self.assertIn("@169.254.169.254", urls)   # userinfo confusion

    def test_dangerous_schemes_present(self):
        urls = " ".join(p.url for p in _builtin_payloads(None))
        self.assertIn("gopher://", urls)
        self.assertIn("dict://", urls)

    def test_every_payload_has_cwe(self):
        for p in _builtin_payloads("http://127.0.0.1:9"):
            self.assertTrue(p.cwe.startswith("CWE-"))
            self.assertIn(p.kind, CWE_BY_KIND)

    def test_results_carry_cwe_and_source(self):
        with MockVulnerableServer() as mock:
            report = scan(mock.url, authorized=True)
        vuln = [r for r in report.results if r.vulnerable]
        self.assertTrue(vuln)
        for r in vuln:
            self.assertTrue(r.cwe.startswith("CWE-"))
            self.assertEqual(r.source, "rule")
        # SSRF metadata findings must map to CWE-918.
        meta = [r for r in vuln if r.kind == "metadata"]
        self.assertTrue(all(r.cwe == "CWE-918" for r in meta))


# --------------------------------------------------------------------------- #
# AI mode — default OFF + deterministic; pluggable; graceful degradation
# --------------------------------------------------------------------------- #
class _FakeBackend:
    """Stand-in for CognisAIBackend with deterministic findings."""

    def __init__(self, enabled=True, healthy=True, findings=None):
        self._enabled = enabled
        self._healthy = healthy
        self._findings = findings or []

    def is_enabled(self):
        return self._enabled

    def health(self):
        return self._healthy

    def analyze_code(self, code, context=None, focus=None):
        return list(self._findings)


class TestAIMode(unittest.TestCase):
    def test_ai_off_by_default_is_deterministic(self):
        with MockVulnerableServer() as mock:
            r1 = scan(mock.url, authorized=True)
            r2 = scan(mock.url, authorized=True)
        self.assertEqual(r1.ai_status, "off")
        self.assertEqual(r1.ai_count, 0)
        # No source=="ai" results when AI is off.
        self.assertFalse(any(x.source == "ai" for x in r1.results))
        # Deterministic verdict set across runs. The canary/rebind payload IDs
        # embed a per-run random token by design, so compare on the stable
        # (kind, technique) fingerprint instead of the token-bearing id.
        self.assertEqual(
            sorted((x.kind, x.technique) for x in r1.results if x.vulnerable),
            sorted((x.kind, x.technique) for x in r2.results if x.vulnerable),
        )

    def test_ai_unreachable_backend_still_returns_rules(self):
        fake = _FakeBackend(enabled=True, healthy=False)
        with MockVulnerableServer() as mock:
            report = scan(mock.url, authorized=True, ai=True, ai_backend=fake)
        self.assertEqual(report.ai_status, "unreachable")
        self.assertGreater(report.vulnerable_count, 0)  # rules still present
        self.assertEqual(report.ai_count, 0)

    def test_ai_disabled_backend_marks_unreachable(self):
        fake = _FakeBackend(enabled=False)
        with MockVulnerableServer() as mock:
            report = scan(mock.url, authorized=True, ai=True, ai_backend=fake)
        self.assertEqual(report.ai_status, "unreachable")

    def test_ai_findings_merged_and_tagged(self):
        fake = _FakeBackend(findings=[{
            "title": "Timing oracle on blocked hosts",
            "severity": "medium", "cwe": "CWE-918", "line": 0,
            "evidence": "differential latency", "why": "infer internal hosts",
            "confidence": 0.7, "novel": True,
        }])
        with MockVulnerableServer() as mock:
            report = scan(mock.url, authorized=True, ai=True, ai_backend=fake)
        self.assertEqual(report.ai_status, "merged")
        ai_results = [r for r in report.results if r.source == "ai"]
        self.assertEqual(len(ai_results), 1)
        self.assertTrue(ai_results[0].novel)
        self.assertEqual(ai_results[0].cwe, "CWE-918")
        self.assertTrue(ai_results[0].payload_id.startswith("ai-"))

    def test_ai_dedupes_non_novel_against_rules(self):
        # A non-novel CWE-918 AI finding should be dropped (rules already cover).
        base = ScanReport(target="x", canary_base=None, results=[])
        from ssrfmcp.core import ProbeResult
        base.results.append(ProbeResult(
            "aws-imds-root", "metadata", "u", "d", True, "critical",
            cwe="CWE-918", technique="aws-imdsv1", source="rule"))
        merge_ai_findings(base, [{
            "title": "SSRF to metadata", "severity": "high", "cwe": "CWE-918",
            "novel": False, "confidence": 0.9,
        }])
        self.assertEqual(sum(1 for r in base.results if r.source == "ai"), 0)

    def test_run_ai_over_transcript_unreachable(self):
        status, findings = run_ai_over_transcript(
            [{"payload_id": "p", "kind": "metadata", "url": "u",
              "status": 200, "error": "", "body": "x"}],
            backend=_FakeBackend(enabled=False))
        self.assertEqual(status, "unreachable")
        self.assertEqual(findings, [])


# --------------------------------------------------------------------------- #
# Viral output formats: badge + HTML
# --------------------------------------------------------------------------- #
class TestBadge(unittest.TestCase):
    def test_badge_clean(self):
        report = ScanReport(target="x", canary_base=None, results=[])
        doc = json.loads(_render_badge(report))
        self.assertEqual(doc["schemaVersion"], 1)
        self.assertEqual(doc["label"], "ssrfmcp")
        self.assertEqual(doc["color"], "brightgreen")
        self.assertEqual(doc["message"], "no SSRF")

    def test_badge_vulnerable(self):
        with MockVulnerableServer() as mock:
            report = scan(mock.url, authorized=True)
        doc = json.loads(_render_badge(report))
        self.assertEqual(doc["color"], "red")  # critical findings
        self.assertIn("finding", doc["message"])


class TestHtml(unittest.TestCase):
    def test_html_self_contained(self):
        with MockVulnerableServer() as mock:
            report = scan(mock.url, authorized=True)
        out = _render_html(report)
        self.assertTrue(out.lstrip().lower().startswith("<!doctype html>"))
        self.assertIn("<table>", out)
        self.assertIn("</html>", out)
        self.assertNotIn("http-equiv=\"refresh\"", out)  # self-contained, no net
        # risk score surfaced
        self.assertIn(f"{report.risk_score}/100", out)

    def test_html_escapes_payload_urls(self):
        # The userinfo/unicode payloads must be HTML-escaped, not break markup.
        with MockVulnerableServer() as mock:
            report = scan(mock.url, authorized=True)
        out = _render_html(report)
        self.assertNotIn("<script", out.lower())


# --------------------------------------------------------------------------- #
# CLI plumbing
# --------------------------------------------------------------------------- #
class TestCliFlags(unittest.TestCase):
    def test_parser_has_ai_and_new_formats(self):
        p = _build_parser()
        ns = p.parse_args(["scan", "--target", "http://x",
                           "--i-have-authorization", "--ai",
                           "--format", "badge"])
        self.assertTrue(ns.ai)
        self.assertEqual(ns.format, "badge")
        ns2 = p.parse_args(["demo", "--i-have-authorization",
                            "--format", "html"])
        self.assertEqual(ns2.format, "html")

    def test_demo_badge_runs(self):
        # Badge format on the demo must succeed (exit code is fail-on policy).
        rc = main(["demo", "--i-have-authorization", "--format", "badge",
                   "--fail-on", "info"])
        # demo target is vulnerable, fail-on info -> exit 1
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
