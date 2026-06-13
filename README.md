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

## Usage — step by step

`ssrfmcp` is a **consent-based, defensive** SSRF probe for MCP servers that fetch
URLs. It refuses to run against a `--target` unless you confirm authorization.

1. **Install** (editable from a clone, or from the wheel):
   ```bash
   pip install -e .
   # provides the `ssrfmcp` console script
   ```
2. **Try it safely first** against the bundled local mock (loopback only — still
   requires the authorization flag):
   ```bash
   ssrfmcp demo --i-have-authorization
   ```
3. **Probe a real target you own / are authorized to test.** Point `--target` at
   the MCP tool endpoint; `--tool`/`--arg` name the fetch tool and its URL arg:
   ```bash
   ssrfmcp scan --target http://127.0.0.1:8080/mcp \
     --tool fetch --arg url --i-have-authorization
   ```
   (Run `ssrfmcp mock` in another shell to serve the local vulnerable endpoint,
   or `ssrfmcp mcp` to expose ssrfmcp itself as an MCP server capability.)
4. **Read / use the output.** Default `--format table` prints a risk score and
   per-payload verdicts; switch to `json`, `sarif`, `html`, or `badge` for
   tooling. The opt-in `--ai` flag (env `COGNIS_AI_*`) merges novel findings and
   degrades gracefully if the backend is unreachable:
   ```bash
   ssrfmcp scan --target http://127.0.0.1:8080/mcp --i-have-authorization \
     --format json > ssrf.json
   ```
5. **Gate CI** with `--fail-on` (`critical|high|medium|low|info`); the exit code
   is non-zero when a vulnerable finding at/above that severity is present:
   ```bash
   ssrfmcp scan --target http://127.0.0.1:8080/mcp --i-have-authorization \
     --format sarif --fail-on high > ssrf.sarif
   ```

## Responsible / authorized use

This is **dual-use security software**. It runs **only** against the
`--target` you explicitly supply, and it **refuses to run without
`--i-have-authorization`**. Use it solely against MCP servers you own or are
explicitly authorized in writing to test, and in compliance with applicable law.

## How it works

1. **Canary** — stands up a local, loopback-only `http.server` with a unique
   per-run token. If the target fetches the canary URL, that proves a *blind*
   SSRF callback and the hit is attributed to the exact payload.
2. **Payloads** — submits a curated, deep set of SSRF probes to the target's
   fetch tool:
   - **Cloud metadata:** AWS IMDSv1 (root / IAM creds / user-data), GCP
     (metadata + default service-account OAuth token), Azure (IMDS + Managed
     Identity token), Alibaba (`100.100.100.200`), OpenStack, DigitalOcean.
   - **Internal reach:** `http://localhost`, `127.0.0.1`, IPv6 `[::1]`, common
     admin ports, link-local (v4 + AWS IMDS over IPv6 `fd00:ec2::254`).
   - **`file://`** local disclosure (POSIX + Windows).
   - **Alternate schemes:** `gopher://` (Redis smuggling), `dict://`
     (memcached), `ftp://`.
   - **IP obfuscation / blocklist bypass:** decimal, octal, hex, dotted-hex,
     short-form `127.1`, ideographic-dot host trick, `userinfo@` confusion.
   - **Redirect-based** reach to internal endpoints, and a **DNS-rebinding
     precursor** canary that proves the target re-resolves attacker hostnames.
3. **Two-oracle detection** — fuses (a) response-body fingerprints of internal
   endpoints (reflected SSRF — IMDS markers, IAM/OAuth credential fields,
   `root:x:0:0`, …) with (b) the loopback canary callback log (blind SSRF),
   then assigns a severity, a **CWE** (CWE-918 SSRF / CWE-22 file / CWE-350
   rebind), and a 0–100 risk score.

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
ssrfmcp demo --i-have-authorization --format sarif  # GitHub code-scanning
ssrfmcp demo --i-have-authorization --format html > report.html   # shareable report
ssrfmcp demo --i-have-authorization --format badge > badge.json   # shields.io endpoint

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

- **Table** (default) — human-readable terminal summary with per-payload
  verdict, CWE, and technique
- **JSON** — machine-readable findings + risk score + CWE for pipelines
- **SARIF** — drops into GitHub code-scanning / IDE problem panes (CWE-tagged)
- **HTML** (`--format html`) — a clean, self-contained report (no external
  assets, no JS, no network) you can attach to a ticket or email
- **Badge** (`--format badge`) — a [shields.io endpoint](https://shields.io/endpoint)
  JSON `{schemaVersion,label,message,color}` so you can show a live status badge

`--fail-on <severity>` makes the process exit non-zero when a vulnerable finding
is at or above the given severity (default `high`), so it gates CI cleanly.

### Status badge

Publish `ssrfmcp --format badge` output somewhere reachable (e.g. a Pages URL or
gist), then point shields.io at it:

```markdown
![ssrfmcp](https://img.shields.io/endpoint?url=https://example.com/ssrfmcp-badge.json)
```

## Pluggable AI mode (opt-in, default OFF)

`ssrfmcp` is **byte-for-byte deterministic by default** — with `--ai` absent, no
AI backend is even constructed. Pass `--ai` to *additionally* run the pluggable
**Cognis AI backend** over the probe transcript and merge any **novel** findings
(tagged `source="ai"`, `novel=true`) that the deterministic rules might miss
(timing/error-leak oracles, unusual accepted schemes, redirect behavior, …).
AI findings are deduped against rule findings by `(CWE, technique)`.

It runs entirely against your **local** OpenAI-compatible fleet — nothing leaves
the box. Configure via environment variables (off until one is set):

```bash
export COGNIS_AI_BACKEND=uncensored-fleet   # or: cognis-code
# or point directly:
export COGNIS_AI_ENDPOINT=http://127.0.0.1:8774/v1
export COGNIS_AI_MODEL=Josiefied-Qwen3-8B-abliterated

ssrfmcp demo --i-have-authorization --ai --format json
```

If `--ai` is given but the backend is unreachable/unconfigured, `ssrfmcp` prints
a clear note to stderr and **continues with the deterministic rule findings**
(it never crashes, and the exit code still reflects the rule findings).

## Use in CI — reusable GitHub Action

`ssrfmcp` ships a composite GitHub Action. Drop this into a workflow to scan a
target in CI, comment the findings on the PR, and fail on a severity threshold:

```yaml
jobs:
  ssrf-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write        # to comment findings on the PR
    steps:
      - uses: cognis-digital/ssrfmcp@main
        with:
          target: http://127.0.0.1:8731/mcp/call
          tool: fetch
          arg: url
          fail-on: high
          comment-pr: "true"
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

Just trying it out? Set `demo: "true"` to probe the bundled mock target instead
of a `target`. The action uploads `scan.json`, `scan.sarif`, `scan.html`, and
`badge.json` as build artifacts. **DEFENSIVE / authorized-use only** — only
point `target` at an MCP server you own or are explicitly authorized to test.

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
