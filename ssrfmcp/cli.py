"""Command-line interface for ssrfmcp.

Consent-based SSRF probe harness for MCP servers that fetch URLs. The CLI
REFUSES to probe a target unless ``--i-have-authorization`` is supplied.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

import html as _html

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
        tags = []
        if r.source == "ai":
            tags.append("AI")
        if r.novel:
            tags.append("NOVEL")
        tag_s = (" {" + ",".join(tags) + "}") if tags else ""
        lines.append(f"[{label}] {r.payload_id:<22} {verdict}{tag_s}")
        meta = f"        kind={r.kind}  cwe={r.cwe or '-'}"
        if r.technique:
            meta += f"  technique={r.technique}"
        lines.append(meta)
        lines.append(f"        url={r.url}")
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
    if report.ai_status != "off":
        lines.append(f"ai: status={report.ai_status} findings={report.ai_count}")
    top = report.top_severity or "none"
    lines.append(f"RESULT: {'SSRF FOUND' if report.vulnerable_count else 'clean'}"
                 f"  (top severity: {top})")
    return "\n".join(lines)


def _badge_color(report: ScanReport) -> str:
    if report.vulnerable_count == 0:
        return "brightgreen"
    top = report.top_severity
    return {"critical": "red", "high": "orange", "medium": "yellow",
            "low": "yellowgreen", "info": "lightgrey"}.get(top, "orange")


def _render_badge(report: ScanReport) -> str:
    """shields.io endpoint schema — point a badge at this JSON."""
    if report.vulnerable_count == 0:
        message = "no SSRF"
    else:
        message = (f"{report.vulnerable_count} finding"
                   f"{'s' if report.vulnerable_count != 1 else ''} "
                   f"({report.top_severity})")
    return json.dumps({
        "schemaVersion": 1,
        "label": "ssrfmcp",
        "message": message,
        "color": _badge_color(report),
    }, indent=2)


def _render_html(report: ScanReport) -> str:
    e = _html.escape
    c = report.counts
    color = {"critical": "#c0392b", "high": "#e67e22", "medium": "#f1c40f",
             "low": "#7cb342", "info": "#95a5a6"}
    rows = []
    for r in report.results:
        sev = r.severity
        badge = (f'<span class="sev" style="background:{color.get(sev,"#777")}">'
                 f'{e(sev.upper())}</span>')
        verdict = ("VULNERABLE" if r.vulnerable
                   else ("ERROR" if r.error else "no fetch"))
        tags = []
        if r.source == "ai":
            tags.append('<span class="tag ai">AI</span>')
        if r.novel:
            tags.append('<span class="tag novel">NOVEL</span>')
        ev = "<br>".join(e(x) for x in r.evidence) or "&mdash;"
        if r.error:
            ev = e(r.error)
        rows.append(
            "<tr class='{cls}'><td>{badge}</td><td><code>{pid}</code>{tags}</td>"
            "<td>{verdict}</td><td>{kind}</td><td><code>{cwe}</code></td>"
            "<td class='url'><code>{url}</code></td><td>{ev}</td></tr>".format(
                cls="vuln" if r.vulnerable else "ok",
                badge=badge, pid=e(r.payload_id), tags="".join(tags),
                verdict=e(verdict), kind=e(r.kind), cwe=e(r.cwe or "-"),
                url=e(r.url), ev=ev))
    ai_line = ""
    if report.ai_status != "off":
        ai_line = (f"<p class='ai-status'>AI mode: <b>{e(report.ai_status)}</b> "
                   f"&middot; AI findings: <b>{report.ai_count}</b></p>")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ssrfmcp report — {e(report.target)}</title>
<style>
 body{{font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
   margin:0;background:#0f1115;color:#e6e6e6}}
 .wrap{{max-width:1080px;margin:0 auto;padding:24px}}
 h1{{font-size:20px;margin:0 0 4px}} .sub{{color:#9aa0a6;margin:0 0 16px}}
 .kpis{{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}}
 .kpi{{background:#1b1f27;border:1px solid #2a2f3a;border-radius:10px;
   padding:12px 16px;min-width:120px}}
 .kpi b{{display:block;font-size:22px}} .kpi span{{color:#9aa0a6;font-size:12px}}
 table{{border-collapse:collapse;width:100%;margin-top:12px;
   background:#161a21;border-radius:10px;overflow:hidden}}
 th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid #232833;
   vertical-align:top;font-size:13px}}
 th{{background:#1b1f27;color:#cfd3da}}
 tr.ok{{opacity:.62}} td.url{{max-width:320px;word-break:break-all}}
 code{{background:#22272f;padding:1px 5px;border-radius:5px;font-size:12px}}
 .sev{{color:#0f1115;font-weight:700;padding:2px 8px;border-radius:6px;
   font-size:11px}}
 .tag{{margin-left:6px;padding:1px 6px;border-radius:6px;font-size:10px;
   font-weight:700}}
 .tag.ai{{background:#6b46c1;color:#fff}} .tag.novel{{background:#2b6cb0;color:#fff}}
 footer{{margin-top:24px;color:#6b7280;font-size:12px}}
 .ai-status{{color:#9aa0a6}}
</style></head><body><div class="wrap">
<h1>ssrfmcp SSRF report</h1>
<p class="sub">target: <code>{e(report.target)}</code>{(' &middot; canary: <code>'
    + e(report.canary_base) + '</code>') if report.canary_base else ''}</p>
<div class="kpis">
 <div class="kpi"><b>{report.risk_score}/100</b><span>risk score</span></div>
 <div class="kpi"><b>{report.vulnerable_count}</b><span>vulnerable</span></div>
 <div class="kpi"><b>{c['critical']}</b><span>critical</span></div>
 <div class="kpi"><b>{c['high']}</b><span>high</span></div>
 <div class="kpi"><b>{e(report.top_severity or 'none')}</b><span>top severity</span></div>
</div>
{ai_line}
<table><thead><tr><th>sev</th><th>payload</th><th>verdict</th><th>kind</th>
<th>cwe</th><th>url</th><th>evidence</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<footer>Generated by {e(TOOL_NAME)} {e(TOOL_VERSION)} &middot; Cognis Neural
Suite &middot; DEFENSIVE / authorized-use only.</footer>
</div></body></html>"""


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
                "properties": {
                    "security-severity": _sarif_score(r.severity),
                    "cwe": r.cwe,
                    "tags": [t for t in (r.kind, r.cwe,
                                         "ai" if r.source == "ai" else None)
                             if t],
                },
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
            "properties": {"payload_url": r.url, "kind": r.kind,
                           "cwe": r.cwe, "technique": r.technique,
                           "source": r.source, "novel": r.novel},
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


def _print(text: str) -> None:
    """Encoding-safe stdout write.

    Output can contain non-cp1252 characters (e.g. the ideographic full-stop in
    a parser-confusion payload URL). On a legacy Windows console, ``print`` would
    raise UnicodeEncodeError, so we write UTF-8 to the underlying buffer when
    available and fall back to a lossless escape otherwise.
    """
    buf = getattr(sys.stdout, "buffer", None)
    if buf is not None:
        buf.write((text + "\n").encode("utf-8", "replace"))
        buf.flush()
    else:  # pragma: no cover - exotic stdout shims
        enc = getattr(sys.stdout, "encoding", None) or "utf-8"
        sys.stdout.write(
            (text + "\n").encode(enc, "backslashreplace").decode(enc))


def _emit(report: ScanReport, fmt: str) -> None:
    if fmt == "json":
        _print(json.dumps(report.to_dict(), indent=2))
    elif fmt == "sarif":
        _print(_render_sarif(report))
    elif fmt == "badge":
        _print(_render_badge(report))
    elif fmt == "html":
        _print(_render_html(report))
    else:
        _print(_render_table(report))


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
        sp.add_argument("--format",
                        choices=("table", "json", "sarif", "html", "badge"),
                        default="table",
                        help="Output format: table|json|sarif|html|badge "
                             "(default: table).")
        sp.add_argument("--fail-on", choices=tuple(SEVERITY_ORDER),
                        default="high",
                        help="Exit non-zero if a vulnerable finding is at or "
                             "above this severity (default: high).")
        sp.add_argument("--ai", action="store_true",
                        help="OPT-IN: also run the pluggable Cognis AI backend "
                             "(env COGNIS_AI_*) over the probe transcript and "
                             "merge novel findings. DEFAULT OFF — without --ai "
                             "the tool is byte-for-byte deterministic. If the "
                             "backend is unreachable, rule findings are still "
                             "returned.")
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

def _ai_note(report: ScanReport, fmt: str) -> None:
    """Print a clear stderr note about AI-mode outcome (never to stdout)."""
    if report.ai_status == "off":
        return
    if report.ai_status == "unreachable":
        print("[ai] backend unreachable / not configured — continuing with "
              "deterministic rule findings only (set COGNIS_AI_BACKEND or "
              "COGNIS_AI_ENDPOINT to enable).", file=sys.stderr)
    elif report.ai_status == "error":
        print("[ai] backend errored — continuing with rule findings only.",
              file=sys.stderr)
    elif report.ai_status == "no-findings":
        print("[ai] backend reachable, no additional findings.",
              file=sys.stderr)
    elif report.ai_status == "merged":
        print(f"[ai] merged {report.ai_count} AI finding(s) into the report.",
              file=sys.stderr)


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
            ai=args.ai,
        )
    except (TargetError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _ai_note(report, args.format)
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
            ai=args.ai,
        )
    _ai_note(report, args.format)
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
