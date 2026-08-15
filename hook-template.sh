#!/bin/sh
# MCPScan pre-commit hook -- do not edit manually
# To bypass: MCPSCAN_SKIP=1 git commit
# mcpscan exit codes: 0 = clean, 1 = findings at/above --fail-on, 2 = scan error

if [ "${MCPSCAN_SKIP}" = "1" ]; then
  printf 'mcpscan: skipping MCP config scan (MCPSCAN_SKIP=1)\n' >&2
  exit 0
fi

if command -v mcpscan >/dev/null 2>&1; then
  mcpscan . --fail-on high --quiet
  MCPSCAN_EXIT=$?
else
  npx --yes mcpscan@latest . --fail-on high --quiet
  MCPSCAN_EXIT=$?
fi

if [ $MCPSCAN_EXIT -eq 1 ]; then
  printf '\nmcpscan: commit blocked -- high or critical MCP config findings detected.\n' >&2
  printf "Run 'mcpscan .' for details, or set MCPSCAN_SKIP=1 to bypass.\n" >&2
elif [ $MCPSCAN_EXIT -ne 0 ]; then
  printf '\nmcpscan: commit blocked -- the scan failed to run (exit %s, NOT a security finding).\n' "$MCPSCAN_EXIT" >&2
  printf "Run 'mcpscan .' for the error, or bypass once with MCPSCAN_SKIP=1 git commit.\n" >&2
fi

exit $MCPSCAN_EXIT
