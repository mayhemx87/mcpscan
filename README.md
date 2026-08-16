# mcpscan

[![CI](https://github.com/mayhemx87/mcpscan/actions/workflows/ci.yml/badge.svg)](https://github.com/mayhemx87/mcpscan/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Node >= 20](https://img.shields.io/badge/node-%3E%3D20-brightgreen)

**Static scanner for MCP config files committed in repos — catch malicious
configs before your AI editor auto-executes them.**

When you open a repo in Claude Code, Cursor, VS Code, Windsurf, Amazon Q, Roo,
Kiro, or Gemini CLI, MCP config files in that repo can declare servers that the
editor launches automatically — as *your* user, inheriting *your* environment and
credentials (see CVE-2026-12957). A cloned repo is arbitrary-code-execution
waiting for an editor to open it.

`mcpscan` scans a checkout **statically** — no network calls, no subprocess
execution of anything in the scanned repo — and flags:

- commands that fetch and execute remote code (`curl … | sh`)
- unpinned `npx`/`uvx`/`pipx` packages (supply-chain risk)
- credential env inheritance (`AWS_*`, `GITHUB_TOKEN`, …) and **hardcoded secrets**
- remote (`url`-based) MCP endpoints, escalating over insecure `http://`
- shell metacharacter chaining, paths escaping the repo, untracked config files

## How it differs from other MCP security tools

Most MCP scanners ([mcp-scan](https://github.com/invariantlabs-ai/mcp-scan),
[MCP-Shield](https://github.com/riseandignite/mcp-shield),
[Snyk agent-scan](https://github.com/snyk/agent-scan)) analyze the MCP servers
**you have installed** — connecting to them at runtime to detect tool poisoning
and prompt injection. That protects you from servers you chose to run.

`mcpscan` covers the step *before* that: the repo you just cloned, in CI, or at
`git commit` time. It never starts a server, never needs an API key, and is safe
to point at hostile checkouts. Use both — they solve different halves of the
problem.

## Install

```sh
npm install -g @mayhemx87/mcpscan

# or straight from the repo
npm install -g github:mayhemx87/mcpscan
```

Either way the installed command is `mcpscan`. (The npm package is scoped
because the registry reserves the bare name as too similar to `mcp-scan` —
a different, runtime-focused tool.)

## Usage

```sh
mcpscan .                     # scan current directory
mcpscan path/to/checkout      # scan any checkout
mcpscan . --json              # machine-readable findings
mcpscan . --sarif             # SARIF 2.1.0 for GitHub code scanning
mcpscan . --fail-on critical  # only exit non-zero on critical
mcpscan . --quiet             # exit code only
mcpscan install-hook          # install the git pre-commit hook
mcpscan rules                 # list detection rules
```

### GitHub Actions

```yaml
jobs:
  mcpscan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # only needed for SARIF upload
    steps:
      - uses: actions/checkout@v4
      - uses: mayhemx87/mcpscan@main
        with:
          fail-on: high
          sarif-file: mcpscan.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: mcpscan.sarif
```

Findings then appear in the repo's **Security → Code scanning** tab, annotated on
the exact line of the offending server definition.

### pre-commit framework

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/mayhemx87/mcpscan
    rev: v0.3.1
    hooks:
      - id: mcpscan
```

### Plain git hook

`mcpscan install-hook` installs a POSIX pre-commit hook (respects
`core.hooksPath`; appends safely to an existing hook; idempotent). Bypass a
single commit with `MCPSCAN_SKIP=1 git commit`.

## What gets scanned

Dedicated MCP config files and editor settings files that embed MCP servers:

| Path | Client |
|---|---|
| `.mcp.json`, `mcp.json` | Claude Code and others |
| `.cursor/mcp.json` | Cursor |
| `.vscode/mcp.json`, `.vscode/settings.json` (`mcp.servers`) | VS Code |
| `.windsurf/mcp.json` | Windsurf |
| `.amazonq/mcp.json` | Amazon Q |
| `.roo/mcp.json` | Roo Code |
| `.kiro/settings/mcp.json` | Kiro |
| `.claude/settings.json`, `.claude/settings.local.json` | Claude Code |
| `.gemini/settings.json` | Gemini CLI |
| `.zed/settings.json` (`context_servers`) | Zed |

Both `mcpServers` and VS Code's `servers` keys are understood, as is Zed's
`context_servers` key; `command` and `args` are analyzed together, including
Zed's legacy nested command format; remote (`url`-based) servers are covered. Nested
occurrences of these paths are scanned too (any subdirectory can be opened as a
workspace root). Only `.git/` and `node_modules/` are skipped; `.gitignore` is
deliberately ignored — an injected config would be exactly the file that's
untracked. Symlinked directories are never followed.

Your editor auto-loads a config path we don't scan?
[Open a "new client" issue](../../issues/new?template=new-client.md) — it's a
one-line fix and the best first contribution.

## Detection rules

| Rule | Severity | Description |
|---|---|---|
| MCP-001 | CRITICAL | Server command executes a remote URL or network tool (curl, wget, https://) |
| MCP-002 | HIGH | Server uses npx/uvx/pipx with an unversioned package (supply-chain risk) |
| MCP-003 | HIGH | Server env block inherits high-value credential env vars (AWS_*, GITHUB_TOKEN, etc.) |
| MCP-004 | MEDIUM | Server command references a path outside the repository (absolute or ../) |
| MCP-005 | MEDIUM | MCP config file is not tracked by git (may have been injected) |
| MCP-006 | INFO | Server passed all detection rules (inventory signal) |
| MCP-007 | CRITICAL | Hardcoded secret-looking value in env or headers (`${VAR}` interpolations exempt) |
| MCP-008 | INFO/HIGH | Remote MCP server (`url`-based) declared — inventory; HIGH over insecure http:// |
| MCP-009 | MEDIUM | Shell command-chaining metacharacters in command/args (`$()`, backticks, `\| sh`) |
| MCP-PARSE | HIGH | Config file has invalid JSON — cannot verify safety |

## Flags

| Flag | Default | Description |
|---|---|---|
| `--json` | off | Output findings as a JSON array |
| `--sarif` | off | Output SARIF 2.1.0 (GitHub code scanning) |
| `--quiet` | off | Suppress all output (exit code only) |
| `--severity <level>` | info | Minimum severity to report |
| `--fail-on <level>` | high | Exit non-zero if any finding at or above this severity |
| `--max-depth <n>` | unlimited | Limit directory traversal depth |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No findings at or above `--fail-on` threshold |
| 1 | One or more findings at or above `--fail-on` threshold |
| 2 | Scan error (invalid argument, cannot determine git root, etc.) |

## Limitations

Static and heuristic by design: a clean scan lowers risk, it does not certify a
repo as safe, and it says nothing about what a declared server *does* at
runtime. Bypass reports are treated as vulnerabilities — see
[SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Adding a client config path is a
one-line change with a test; new detection rules and false-positive reports are
equally welcome.

## License

MIT
