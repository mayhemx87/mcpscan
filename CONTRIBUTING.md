# Contributing to mcpscan

Thanks for your interest! This project is small on purpose: a fast, zero-network,
static scanner for MCP config files committed in repos. Contributions that keep it
small, fast, and dependency-light are the most welcome kind.

## Development setup

```sh
git clone https://github.com/mayhemx87/mcpscan
cd mcpscan
npm ci
npm test        # vitest, runs in a few seconds
npm run build   # tsc -> dist/
node dist/cli.js __tests__/fixtures/cve-12957   # see it fire
```

The codebase is four files:

| File | Role |
|---|---|
| `discovery.ts` | Walks the tree, decides which files are MCP configs |
| `engine.ts` | Pure analysis: config content in, findings out. No fs, no subprocess, no network |
| `sarif.ts` | Converts findings to SARIF 2.1.0 |
| `cli.ts` | Flags, output formatting, git integration, hook installer |

## The easiest first contribution: add a client

Every AI editor/agent that auto-loads MCP configs from a repo path should be
covered. To add one:

1. Add the repo-relative path to `MCP_CONFIG_SUFFIXES` in `discovery.ts`.
   Check first — a client whose file is a bare `<dot-dir>/mcp.json` (Trae, for
   example) is already matched by the `mcp.json` suffix and needs no new entry,
   just the fixture and test below.
2. If the file is a general settings file that merely *embeds* MCP servers under
   a nested key, make sure `isEmbeddedHostFile()` and `extractServers()` in
   `engine.ts` understand it (embedded files with no MCP section must produce
   zero findings).
3. Add a fixture under `__tests__/fixtures/<client>/` and a discovery test.
4. Cite the client's documentation for the path in your PR description —
   we only scan paths that are actually auto-loaded.

## Adding a detection rule

1. Add the rule metadata to `RULES` in `engine.ts` (next free `MCP-0xx` id).
2. Implement it inside the per-server loop in `analyzeConfig()` — it must stay a
   pure function of the config content.
3. Add tests: at least one firing case and one non-firing case.
4. In the PR, explain the attack the rule catches and the false-positive
   surface you considered. Rules that fire on common legitimate configs need a
   severity of `medium` or below, or a way to be precise.
5. Update the rules table in `README.md`.

## Ground rules

- **No network calls, no subprocess execution in the engine.** The scanner must
  be safe to run on hostile repos. (The CLI shells out to `git` only, with
  `execFileSync` and argument arrays — never string-built shell commands.)
- **No new runtime dependencies** without prior discussion in an issue.
- **Findings are advisory output** — messages should say what was found and how
  to fix it, without drama.
- Run `npm test` before pushing; CI runs Linux + Windows.

## Reporting false positives / false negatives

These are the most valuable bug reports a scanner can get. Please open an issue
with the (sanitized) config that was mis-scanned and the output you expected.

## Releases

Maintainers: bump `version` in `package.json`, tag `vX.Y.Z`, create a GitHub
release — the publish workflow pushes to npm with provenance.
