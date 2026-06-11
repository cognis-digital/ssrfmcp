# ssrfmcp — Consent-based SSRF probe harness for MCP servers that fetch URLs

> Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** by [Cognis Digital](https://cognis.digital)
> Cognis Open Collaboration License (COCL) v1.0 · domain: `ai-security`

[![PyPI](https://img.shields.io/pypi/v/cognis-ssrfmcp.svg)](https://pypi.org/project/cognis-ssrfmcp/)
[![CI](https://github.com/cognis-digital/ssrfmcp/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/ssrfmcp/actions)
[![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE)
[![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

**A DEFENSIVE, consent-based SSRF test harness for MCP tools that fetch URLs.**

*AI Security & Governance — securing LLMs, agents, and the MCP supply chain.*

Many MCP servers expose a "fetch this URL" tool. If that tool has no SSRF
guard, an attacker (or a prompt-injected agent) can make the server reach cloud
metadata endpoints (`169.254.169.254`), loopback admin services, or read local
files via `file://`. `ssrfmcp` probes a target you control for exactly these
weaknesses and reports which payloads got through, with severity.

## Responsible / authorized use

This is **dual-use security software**. It runs **only** against the
`--target` you explicitly supply, and it **refuses to run without
`--i-have-authorization`**. Use it solely against MCP servers you own or are
explicitly authorized in writing to test, and in compliance with applicable law.

## How it works

1. **Canary** — stands up a local, loopback-only `http.server` with a unique
   per-run token. If the target fetches the canary URL, that proves a *blind*
   SSRF callback and the hit is attributed to the exact payload.
2. **Payloads** — submits a curated set of SSRF probes to the target's fetch
   tool: AWS/GCP/Azure metadata endpoints, `http://localhost` / `127.0.0.1`,
   link-local, `file://`, decimal/octal IP bypass encodings, and the canary URL.
3. **Two-oracle detection** — fuses (a) response-body fingerprints of internal
   endpoints (reflected SSRF — IMDS markers, IAM credential fields,
   `root:x:0:0`, …) with (b) the canary callback log (blind SSRF), then assigns
   a severity and a 0–100 risk score.

No payload is ever sent anywhere except the supplied target. The canary listens
only on loopback. Standard library only — no pip dependencies.

## Install

```bash
pip install cognis-ssrfmcp
# or, from this repo:
pip install -e ".[dev]"
```

## Quick start

```bash
ssrfmcp --version
ssrfmcp demo --i-have-authorization                 # probe the bundled mock target
ssrfmcp demo --i-have-authorization --format json   # machine-readable
ssrfmcp demo --i-have-authorization --format sarif   # GitHub code-scanning

# Against your own MCP fetch tool:
ssrfmcp scan --i-have-authorization \
    --target http://127.0.0.1:8731/mcp/call \
    --tool fetch --arg url --fail-on high

# Serve the bundled mock vulnerable endpoint yourself:
ssrfmcp mock --port 8731

# Expose ssrfmcp as an MCP server (Cognis.Studio / Claude Desktop / Cursor):
ssrfmcp mcp
```

### Target contract

`ssrfmcp scan` POSTs JSON of the shape
`{"tool": "<--tool>", "arguments": {"<--arg>": "<payload-url>"}}` to your
`--target` and inspects the response body. Adjust `--tool` / `--arg` to match
your server's fetch tool. (Wrap a non-conforming server with a tiny shim if
needed.)

## Output formats

- **Table** (default) — human-readable terminal summary with per-payload verdict
- **JSON** — machine-readable findings + risk score for pipelines
- **SARIF** — drops into GitHub code-scanning / IDE problem panes

`--fail-on <severity>` makes the process exit non-zero when a vulnerable finding
is at or above the given severity (default `high`), so it gates CI cleanly.

## Built-in demo scenario

- [`demos/01-basic/`](demos/01-basic/SCENARIO.md) — probes a deliberately
  SSRF-vulnerable mock MCP fetch tool shipped in this repo.

## How it fits the Cognis Neural Suite

`ssrfmcp` ships an MCP server, so [Cognis.Studio](https://cognis.studio) agents
can call it as a scoped, consent-gated capability (the MCP tool requires
`i_have_authorization=true`, mirroring the CLI flag).

**Sibling tools in `ai-security`:** [`mcpharden`](https://github.com/cognis-digital/mcpharden), [`aegis`](https://github.com/cognis-digital/aegis), [`promptmirror`](https://github.com/cognis-digital/promptmirror), [`adversa`](https://github.com/cognis-digital/adversa), [`guardpost`](https://github.com/cognis-digital/guardpost), [`ragshield`](https://github.com/cognis-digital/ragshield)

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** —
free for personal, internal-evaluation, research, and educational use;
**commercial / production use requires a license** (licensing@cognis.digital).
See [LICENSE](LICENSE).

## About

**[Cognis Digital](https://cognis.digital)** — Wyoming, USA · *Making Tomorrow Better Today: Advanced Cybersecurity, AI Innovation, and Blockchain Expertise.*
