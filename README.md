# mcpscan

Static scanner for malicious MCP config files in AI-integrated editor repos.

Scans dedicated MCP config files (`.mcp.json`, `mcp.json`, `.amazonq/mcp.json`,
`.cursor/mcp.json`, `.vscode/mcp.json`, `.windsurf/mcp.json`) AND embedded
MCP sections in editor/agent settings (`.vscode/settings.json` `mcp.servers`,
`.claude/settings.json` / `.claude/settings.local.json` `mcpServers`,
`.gemini/settings.json`) for supply-chain risks and credential exposure before
a repo is opened in an AI-integrated editor. Both `mcpServers` and VS Code's
`servers` top-level keys are understood, `command` and `args` are analyzed
together, and remote (`url`-based) servers are covered.

Motivated by CVE-2026-12957: MCP config files auto-execute with full credential
inheritance when a repo is opened.

## Install

Not yet published to npm -- build from source:

```sh
npm ci && npm run build
```

Then run via node:

```sh
node dist/cli.js .
```

Or link the `mcpscan` command globally:

```sh
npm link
```

## Usage

```sh
# Scan current directory
mcpscan .

# Scan with JSON output
mcpscan . --json

# Fail only on critical findings
mcpscan . --fail-on critical

# Quiet mode (exit code only)
mcpscan . --quiet

# Install as a pre-commit hook
mcpscan install-hook

# List all detection rules
mcpscan rules
```

## Detection rules

| Rule | Severity | Description |
|---|---|---|
| MCP-001 | CRITICAL | Server command executes a remote URL or network tool (curl, wget, https://) |
| MCP-002 | HIGH | Server uses npx/uvx/pipx with an unversioned package (supply-chain risk) |
| MCP-003 | HIGH | Server env block inherits high-value credential env vars (AWS_*, GITHUB_TOKEN, etc.) |
| MCP-004 | MEDIUM | Server command references a path outside the repository (absolute or ../) |
| MCP-005 | MEDIUM | MCP config file is not tracked by git (may have been injected) |
| MCP-006 | INFO | Server passed all detection rules (inventory signal) |
| MCP-007 | CRITICAL | Hardcoded secret-looking value in env or headers (committed credential; `${VAR}` interpolations exempt) |
| MCP-008 | INFO/HIGH | Remote MCP server (`url`-based) declared -- inventory; HIGH over insecure http:// |
| MCP-009 | MEDIUM | Shell command-chaining metacharacters in command/args (`$()`, backticks, `\| sh`) |

## Flags

| Flag | Default | Description |
|---|---|---|
| `--json` | off | Output findings as a JSON array |
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

## Pre-commit hook

```sh
mcpscan install-hook
```

Installs a POSIX shell pre-commit hook that blocks commits when high or critical
MCP config findings are detected. Safe to append to an existing hook. The hook
runs `mcpscan` from `PATH` when available, falling back to
`npx --yes mcpscan@latest`.

Override: `MCPSCAN_SKIP=1 git commit`

## License

MIT
