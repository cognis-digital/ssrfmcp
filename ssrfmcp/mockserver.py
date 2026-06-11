"""A deliberately SSRF-vulnerable mock MCP fetch tool, for demos + tests.

This stands up a tiny HTTP endpoint that mimics an MCP server exposing a
``fetch`` tool: it accepts ``{"tool": "fetch", "arguments": {"url": ...}}`` and
*naively* fetches whatever URL it is handed — including loopback, cloud
metadata, ``file://``, and arbitrary outbound URLs (the classic SSRF bug).

It is intended ONLY as a local target so operators can see ssrfmcp light up
end-to-end without pointing it at a real system. To keep the demo hermetic and
offline, internal/metadata/file URLs are served from canned fixtures rather
than actually hitting 169.254.169.254 — but the canary URL is fetched for
real over loopback, faithfully reproducing a blind-SSRF callback.
"""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional, Tuple

# Canned bodies a genuinely vulnerable server would return after fetching the
# internal endpoint. These contain the exact fingerprints ssrfmcp looks for.
_FIXTURES = {
    "169.254.169.254/latest/meta-data": (
        "ami-id\nami-launch-index\nhostname\niam/\ninstance-id\n"
        "instance-type\nsecurity-credentials\n"
    ),
    "iam/security-credentials": json.dumps({
        "Code": "Success",
        "AccessKeyId": "ASIAEXAMPLEKEYID",
        "SecretAccessKey": "wExampleSecretKeyDoNotUse",
        "Token": "FAKETOKEN==",
    }),
    "metadata.google.internal": (
        "computeMetadata/\ninstance/\nproject/\n"
        "instance/service-accounts/default/token\n"
    ),
    "169.254.169.254/metadata/instance": json.dumps({
        "compute": {"vmId": "00000000-0000-0000-0000-000000000000",
                    "subscriptionId": "sub-example",
                    "azEnvironment": "AzurePublicCloud"}
    }),
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
    ),
    "etc/hosts": "# Copyright (c) 1993-2009 Microsoft Corp.\n127.0.0.1 localhost\n",
}


def _fixture_for(url: str) -> Optional[str]:
    """Return a canned internal-endpoint body if the URL targets one."""
    u = url.lower()
    # Decimal/octal encodings of 169.254.169.254 also map to IMDS.
    if "2852039166" in u or "0251.0376.0251.0376" in u or "169.254.169.254" in u:
        if "iam/security-credentials" in u:
            return _FIXTURES["iam/security-credentials"]
        if "/metadata/instance" in u:
            return _FIXTURES["169.254.169.254/metadata/instance"]
        return _FIXTURES["169.254.169.254/latest/meta-data"]
    if "metadata.google.internal" in u:
        return _FIXTURES["metadata.google.internal"]
    if u.startswith("file://"):
        if "passwd" in u:
            return _FIXTURES["/etc/passwd"]
        if "hosts" in u:
            return _FIXTURES["etc/hosts"]
        return "(file contents)"
    if "localhost" in u or "127.0.0.1" in u:
        return "internal service root: admin console (no auth)\n"
    return None


class _MockHandler(BaseHTTPRequestHandler):
    server_version = "vuln-mcp-fetch/0.1"

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8", "replace"))
            url = str(payload.get("arguments", {}).get("url", ""))
        except (ValueError, AttributeError):
            url = ""

        body_text, status = self._naive_fetch(url)
        out = json.dumps({
            "tool": "fetch",
            "fetched_url": url,
            "status": status,
            "body": body_text,
        }).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def _naive_fetch(self, url: str) -> Tuple[str, int]:
        """The vulnerability: fetch ANY url with no allowlist/SSRF guard."""
        if not url:
            return "(no url)", 400
        fixture = _fixture_for(url)
        if fixture is not None:
            return fixture, 200
        # For real http(s) URLs (e.g. the operator canary on loopback) we
        # actually perform the fetch — reproducing a true blind-SSRF callback.
        if url.startswith("http://") or url.startswith("https://"):
            try:
                req = urllib.request.Request(
                    url, headers={"User-Agent": "vuln-mcp-fetch/0.1"})
                with urllib.request.urlopen(req, timeout=4) as resp:
                    return resp.read().decode("utf-8", "replace"), resp.status
            except urllib.error.HTTPError as exc:
                return "", exc.code
            except (urllib.error.URLError, socket.timeout, OSError) as exc:
                return f"(fetch error: {exc})", 502
        return "(unsupported scheme)", 400

    def log_message(self, *_args: Any) -> None:
        return


class MockVulnerableServer:
    """Context-managed, loopback-only mock vulnerable MCP fetch endpoint."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self._httpd = ThreadingHTTPServer((host, port), _MockHandler)
        self.host = self._httpd.server_address[0]
        self.port = self._httpd.server_address[1]
        self._thread = None

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}/mcp/call"

    def start(self) -> "MockVulnerableServer":
        import threading
        self._thread = threading.Thread(target=self._httpd.serve_forever,
                                        daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        try:
            self._httpd.shutdown()
        finally:
            self._httpd.server_close()

    def __enter__(self) -> "MockVulnerableServer":
        return self.start()

    def __exit__(self, *_exc: Any) -> None:
        self.stop()


def serve(host: str = "127.0.0.1", port: int = 8731) -> None:  # pragma: no cover
    srv = MockVulnerableServer(host, port).start()
    print(f"mock vulnerable MCP fetch tool listening at {srv.url}")
    print("Probe it with:  ssrfmcp scan --i-have-authorization --target "
          f"{srv.url}")
    try:
        while True:
            import time
            time.sleep(3600)
    except KeyboardInterrupt:
        srv.stop()
