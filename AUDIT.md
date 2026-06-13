# Audit — ssrfmcp

Generated 2026-06-13 UTC.

```json
{
  "repo": "ssrfmcp",
  "parse_errors": [],
  "tests_passed": 46,
  "tests_failed": 0,
  "tests_errored": 0,
  "has_tests": true,
  "pytest_tail": "..............................................                           [100%]\n46 passed in 259.59s (0:04:19)",
  "package": "ssrfmcp",
  "cli_version": "ssrfmcp 0.2.0",
  "clean": true
}
```

## pytest
```
..............................................                           [100%]
46 passed in 259.59s (0:04:19)
```

## CLI
```
usage: ssrfmcp [-h] [--version] {scan,demo,mock,mcp} ...

Consent-based SSRF probe harness for MCP servers that fetch URLs. DEFENSIVE /
authorized-use only.

positional arguments:
  {scan,demo,mock,mcp}
    scan                Probe a target MCP fetch tool for SSRF.
    demo                Run against a bundled local mock vulnerable endpoint.
    mock                Serve the local mock vulnerable MCP fetch tool.
    mcp                 Expose ssrfmcp as an MCP server capability.

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
```
