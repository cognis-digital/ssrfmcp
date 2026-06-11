"""Command-line interface for ssrfmcp.

Consent-based SSRF probe harness for MCP servers that fetch URLs. The CLI
REFUSES to probe a target unless ``--i-have-authorization`` is supplied.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    SEVERITY_ORDER,
    ScanReport,
    TargetError,
    scan,
)

_SEV_LABEL = {
    "critical": "CRIT",
    "high": "HIGH",
    "medium": "MED ",
    "low": "LOW ",
    "info": "INFO",
}

_AUTH_BANNER = (
    "ssrfmcp is DEFENSIVE, consent-based security tooling.\n"
    "It probes ONLY the --target you supply. Run it solely against MCP\n"
    "servers you own or are explicitly authorized in writing to test.\n"
    "Re-run with --i-have-authorization to confirm you have permission."
)


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

def _render_table(report: ScanReport) -> str:
    lines: List[str] = []
    lines.append(f"ssrfmcp SSRF probe — target: {report.target}")
    if report.canary_base:
        lines.append(f"canary listener: {report.canary_base}")
    lines.append("=" * 72)
    for r in report.results:
        label = _SEV_LABEL.get(r.severity, r.severity.upper())
        verdict = "VULNERABLE" if r.vulnerable else ("ERROR" if r.error
                                                     else "no fetch")
        lines.append(f"[{label}] {r.payload_id:<20} {verdict}")
        lines.append(f"        kind={r.kind}  url={r.url}")
        if r.error:
            lines.append(f"        error: {r.error}")
        for ev in r.evidence:
            lines.append(f"        evidence: {ev}")
    c = report.counts
    lines.append("-" * 72)
    lines.append(
        f"risk={report.risk_score}/100  vulnerable={report.vulnerable_count}  "
        f"critical={c['critical']} high={c['high']} medium={c['medium']} "
        f"low={c['low']}"
    )
    top = report.top_severity or "none"
    lines.append(f"RESULT: {'SSRF FOUND' if report.vulnerable_count else 'clean'}"
                 f"  (top severity: {top})")
    return "\n".join(lines)


def _render_sarif(report: ScanReport) -> str:
    rules = []
    results = []
    seen_rules = set()
    for r in report.results:
        if not r.vulnerable:
            continue
        if r.payload_id not in seen_rules:
            seen_rules.add(r.payload_id)
            rules.append({
                "id": r.payload_id,
                "name": r.kind,
                "shortDescription": {"text": r.description},
                "defaultConfiguration": {
                    "level": _sarif_level(r.severity)},
                "properties": {"security-severity": _sarif_score(r.severity)},
            })
        results.append({
            "ruleId": r.payload_id,
            "level": _sarif_level(r.severity),
            "message": {"text": f"{r.description} — {'; '.join(r.evidence)}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": report.target},
                    "region": {"startLine": 1},
                }
            }],
            "properties": {"payload_url": r.url, "kind": r.kind},
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": TOOL_NAME,
                "version": TOOL_VERSION,
                "informationUri": "https://github.com/cognis-digital/ssrfmcp",
                "rules": rules,
            }},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


def _sarif_level(severity: str) -> str:
    return {"critical": "error", "high": "error",
            "medium": "warning", "low": "note", "info": "note"}.get(
        severity, "warning")


def _sarif_score(severity: str) -> str:
    return {"critical": "9.5", "high": "8.0", "medium": "5.0",
            "low": "3.0", "info": "0.0"}.get(severity, "5.0")


def _emit(report: ScanReport, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(report.to_dict(), indent=2))
    elif fmt == "sarif":
        print(_render_sarif(report))
    else:
        print(_render_table(report))


def _fail_code(report: ScanReport, fail_on: str) -> int:
    """Exit non-zero if any vulnerable finding is at/above ``fail_on``."""
    threshold = SEVERITY_ORDER[fail_on]
    for r in report.results:
        if r.vulnerable and SEVERITY_ORDER.get(r.severity, 99) <= threshold:
            return 1
    return 0


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Consent-based SSRF probe harness for MCP servers that "
                    "fetch URLs. DEFENSIVE / authorized-use only.",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    def _add_common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--format", choices=("table", "json", "sarif"),
                        default="table", help="Output format (default: table).")
        sp.add_argument("--fail-on", choices=tuple(SEVERITY_ORDER),
                        default="high",
                        help="Exit non-zero if a vulnerable finding is at or "
                             "above this severity (default: high).")
        sp.add_argument("--tool", default="fetch",
                        help="MCP tool name the target exposes (default: fetch).")
        sp.add_argument("--arg", default="url",
                        help="Argument name carrying the URL (default: url).")
        sp.add_argument("--timeout", type=float, default=8.0,
                        help="Per-request timeout in seconds (default: 8).")
        sp.add_argument("--delay", type=float, default=0.0,
                        help="Delay between payloads in seconds (default: 0).")
        sp.add_argument("--no-canary", action="store_true",
                        help="Disable the blind-SSRF canary listener.")

    scan_p = sub.add_parser(
        "scan", help="Probe a target MCP fetch tool for SSRF.")
    scan_p.add_argument("--target", required=True,
                        help="URL of the MCP tool endpoint to probe "
                             "(you must own / be authorized to test it).")
    scan_p.add_argument("--i-have-authorization", action="store_true",
                        dest="authorized",
                        help="REQUIRED. Confirms you are authorized to test "
                             "the target. The tool refuses to run without it.")
    _add_common(scan_p)

    demo_p = sub.add_parser(
        "demo", help="Run against a bundled local mock vulnerable endpoint.")
    demo_p.add_argument("--i-have-authorization", action="store_true",
                        dest="authorized",
                        help="REQUIRED even for the demo (loopback only).")
    _add_common(demo_p)

    mock_p = sub.add_parser(
        "mock", help="Serve the local mock vulnerable MCP fetch tool.")
    mock_p.add_argument("--host", default="127.0.0.1")
    mock_p.add_argument("--port", type=int, default=8731)

    sub.add_parser("mcp", help="Expose ssrfmcp as an MCP server capability.")
    return p


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------

def _run_scan(args: argparse.Namespace) -> int:
    if not args.authorized:
        print(_AUTH_BANNER, file=sys.stderr)
        return 3
    try:
        report = scan(
            args.target, authorized=True,
            use_canary=not args.no_canary,
            tool=args.tool, arg=args.arg,
            timeout=args.timeout, delay=args.delay,
        )
    except (TargetError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _emit(report, args.format)
    return _fail_code(report, args.fail_on)


def _run_demo(args: argparse.Namespace) -> int:
    if not args.authorized:
        print(_AUTH_BANNER, file=sys.stderr)
        return 3
    from .mockserver import MockVulnerableServer
    with MockVulnerableServer() as mock:
        if args.format == "table":
            print(f"[demo] mock vulnerable MCP fetch tool at {mock.url}\n",
                  file=sys.stderr)
        report = scan(
            mock.url, authorized=True,
            use_canary=not args.no_canary,
            tool=args.tool, arg=args.arg,
            timeout=args.timeout, delay=args.delay,
        )
    _emit(report, args.format)
    return _fail_code(report, args.fail_on)


def _run_mock(args: argparse.Namespace) -> int:  # pragma: no cover
    from .mockserver import serve
    serve(args.host, args.port)
    return 0


def _run_mcp(_args: argparse.Namespace) -> int:  # pragma: no cover
    try:
        from .mcp_server import run_mcp_server
    except Exception as exc:
        print(f"error: MCP server unavailable: {exc}", file=sys.stderr)
        return 2
    run_mcp_server()
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _run_scan(args)
    if args.command == "demo":
        return _run_demo(args)
    if args.command == "mock":
        return _run_mock(args)
    if args.command == "mcp":
        return _run_mcp(args)
    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
