"""ssrfmcp MCP server — exposes the SSRF probe as an MCP tool for Cognis.Studio.

Mirrors the Cognis Neural Suite convention: the tool is published as an MCP
capability via ``cognis_core.mcp.build_mcp_server``. When that shared helper is
not installed (e.g. running straight from this repo with stdlib only), we fall
back to a minimal stdio JSON-RPC MCP server implemented here.

In both cases the capability is consent-gated: the caller MUST pass
``i_have_authorization=true`` in the tool arguments, exactly like the CLI's
``--i-have-authorization`` flag.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict

from ssrfmcp.core import TOOL_NAME, TOOL_VERSION, scan

_DESCRIPTION = (
    "Consent-based SSRF probe harness for MCP servers that fetch URLs. "
    "Refuses to run without explicit authorization."
)


def _scan_capability(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Adapter invoked by the MCP layer for a tools/call."""
    target = arguments.get("target")
    authorized = bool(arguments.get("i_have_authorization", False))
    if not authorized:
        return {
            "error": "authorization_required",
            "message": ("ssrfmcp refuses to probe without explicit "
                        "authorization. Set i_have_authorization=true only "
                        "for targets you own or may test."),
        }
    report = scan(
        target,
        authorized=True,
        use_canary=bool(arguments.get("use_canary", True)),
        tool=arguments.get("tool", "fetch"),
        arg=arguments.get("arg", "url"),
        timeout=float(arguments.get("timeout", 8.0)),
        ai=bool(arguments.get("ai", False)),
    )
    return report.to_dict()


# Public name used by the suite's shared builder.
def scan_fn(arguments: Dict[str, Any]) -> Dict[str, Any]:
    return _scan_capability(arguments)


try:  # Preferred: the shared suite MCP builder.
    from cognis_core.mcp import build_mcp_server  # type: ignore

    run_mcp_server = build_mcp_server(
        tool_name=TOOL_NAME,
        description=_DESCRIPTION,
        scan_fn=scan_fn,
    )
except Exception:  # pragma: no cover - stdlib fallback
    _INPUT_SCHEMA = {
        "type": "object",
        "properties": {
            "target": {"type": "string",
                       "description": "MCP fetch-tool endpoint to probe."},
            "i_have_authorization": {
                "type": "boolean",
                "description": "Required; confirms authorized testing."},
            "use_canary": {"type": "boolean", "default": True},
            "tool": {"type": "string", "default": "fetch"},
            "arg": {"type": "string", "default": "url"},
            "timeout": {"type": "number", "default": 8.0},
            "ai": {"type": "boolean", "default": False,
                   "description": "Opt-in: also run the pluggable Cognis AI "
                                  "backend (env COGNIS_AI_*). Default off."},
        },
        "required": ["target", "i_have_authorization"],
        "additionalProperties": False,
    }

    def _respond(rid: Any, result: Dict[str, Any]) -> None:
        sys.stdout.write(json.dumps(
            {"jsonrpc": "2.0", "id": rid, "result": result}) + "\n")
        sys.stdout.flush()

    def run_mcp_server() -> None:
        """Minimal stdio JSON-RPC MCP loop (initialize / tools.list / call)."""
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            method = msg.get("method")
            rid = msg.get("id")
            if method == "initialize":
                _respond(rid, {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": TOOL_NAME, "version": TOOL_VERSION},
                })
            elif method in ("tools/list", "tools.list"):
                _respond(rid, {"tools": [{
                    "name": TOOL_NAME,
                    "description": _DESCRIPTION,
                    "inputSchema": _INPUT_SCHEMA,
                }]})
            elif method in ("tools/call", "tools.call"):
                params = msg.get("params", {})
                args = params.get("arguments", {})
                try:
                    result = scan_fn(args)
                    payload = {"content": [
                        {"type": "text",
                         "text": json.dumps(result, indent=2)}]}
                except Exception as exc:  # noqa: BLE001
                    payload = {"isError": True, "content": [
                        {"type": "text", "text": f"error: {exc}"}]}
                _respond(rid, payload)


if __name__ == "__main__":
    run_mcp_server()
