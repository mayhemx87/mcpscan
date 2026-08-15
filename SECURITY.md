# Security Policy

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting on this repository
(Security tab → "Report a vulnerability") rather than opening a public issue.

Reports of **scanner bypasses** are explicitly in scope: if you can construct an
MCP config that auto-executes code when a repo is opened in an AI-integrated
editor but produces no high/critical finding from `mcpscan`, that's a
vulnerability in this tool — please report it privately first.

Also in scope:

- Any way a scanned (hostile) repository can make `mcpscan` itself execute code,
  hang, escape the scan root, or exfiltrate data. The scanner is designed to be
  safe to point at untrusted checkouts; anything that breaks that promise is
  critical.

## What mcpscan does and does not promise

mcpscan is a static, heuristic scanner. A clean scan lowers risk; it does not
certify a repo as safe. In particular, it does not inspect the behavior of the
MCP servers themselves — only how they are declared. For runtime analysis of
installed servers, pair it with a runtime scanner.

## Supported versions

Only the latest release receives security fixes.
