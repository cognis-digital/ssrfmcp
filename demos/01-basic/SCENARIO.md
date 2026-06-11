# Demo 01 — Probing a vulnerable MCP fetch tool for SSRF

This scenario runs ssrfmcp against a **local mock MCP server** that exposes a
`fetch` tool with no SSRF protections — the classic "give me a URL and I'll
fetch it" bug. The mock is shipped in the repo (`ssrfmcp/mockserver.py`) and
binds only to loopback, so the demo is fully hermetic and offline.

## Run it

```bash
# One-shot: ssrfmcp stands up the mock, probes it, tears it down.
python -m ssrfmcp demo --i-have-authorization

# Machine-readable output:
python -m ssrfmcp demo --i-have-authorization --format json

# SARIF for GitHub code-scanning / IDE problem panes:
python -m ssrfmcp demo --i-have-authorization --format sarif

# Or run the mock yourself and point a scan at it:
python -m ssrfmcp mock --port 8731 &
python -m ssrfmcp scan --i-have-authorization --target http://127.0.0.1:8731/mcp/call
```

`config.json` in this folder records the demo invocation and the target shape
for reference / replay.

## Authorization is mandatory

Both `scan` and `demo` refuse to run without `--i-have-authorization`
(exit code `3`). ssrfmcp is dual-use security tooling: only probe targets you
own or are explicitly authorized in writing to test.

## What it should catch

The mock tool naively fetches whatever URL it is handed, so ssrfmcp reports:

| Payload            | Class            | Severity | Why                                            |
|--------------------|------------------|----------|------------------------------------------------|
| `aws-imds-root`    | metadata         | critical | EC2 IMDS root reachable (IMDSv1)               |
| `aws-imds-creds`   | metadata         | critical | IAM role credentials path — credential theft   |
| `gcp-metadata`     | metadata         | critical | GCP metadata server reachable                  |
| `azure-imds`       | metadata         | critical | Azure IMDS reachable                           |
| `file-etc-passwd`  | file             | critical | `file://` local file read (`/etc/passwd`)      |
| `localhost-http`   | loopback         | high     | Loopback service reachable                     |
| `bypass-decimal`   | bypass           | high     | IMDS reached via decimal-encoded IP            |
| `canary-XXXXXXXX`  | canary           | high     | **Blind** SSRF — target called back to canary  |

The two detection oracles fire independently: response-body fingerprints prove
reflected SSRF (IMDS/credential/`/etc/passwd` markers), and the loopback canary
callback proves blind SSRF. Because critical/high findings are present, the
process exits non-zero (`--fail-on high`), failing any CI gate that wraps it.
