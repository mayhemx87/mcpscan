#!/usr/bin/env node
import { Command } from 'commander';
import { readFileSync, writeFileSync, existsSync, chmodSync } from 'fs';
import { execSync } from 'child_process';
import { resolve, relative, dirname } from 'path';
import { discoverConfigs } from './discovery.js';
import { analyzeConfig, type Finding, type Severity, SEVERITY_RANK } from './engine.js';

const VERSION = '0.2.0';

const RULES = [
  { id: 'MCP-001', severity: 'critical', description: 'Server command or args execute a remote URL or network tool (curl, wget, https://)' },
  { id: 'MCP-002', severity: 'high',     description: 'Server uses npx/uvx/pipx with an unversioned package, in command or args (supply-chain risk)' },
  { id: 'MCP-003', severity: 'high',     description: 'Server env block inherits high-value credential env vars (AWS_*, GITHUB_TOKEN, etc.)' },
  { id: 'MCP-004', severity: 'medium',   description: 'Server command or args reference a path outside the repository (absolute or ../)' },
  { id: 'MCP-005', severity: 'medium',   description: 'MCP config file is not tracked by git (may have been injected)' },
  { id: 'MCP-006', severity: 'info',     description: 'Server passed all detection rules (inventory signal)' },
  { id: 'MCP-007', severity: 'critical', description: 'Hardcoded secret-looking value in env or headers (committed credential; ${VAR} interpolations exempt)' },
  { id: 'MCP-008', severity: 'info',     description: 'Remote MCP server (url-based) declared -- inventory; escalates to HIGH over insecure http://' },
  { id: 'MCP-009', severity: 'medium',   description: 'Shell command-chaining metacharacters in command/args ($(), backticks, | sh)' },
];

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: '[CRITICAL]',
  high:     '[HIGH]    ',
  medium:   '[MEDIUM]  ',
  info:     '[INFO]    ',
};

function isFileGitTracked(filePath: string): boolean {
  try {
    // cwd MUST be the file's own directory: without it the check runs
    // against whatever repo the shell happens to be in, corrupting MCP-005
    // both directions when scanning a repo from outside it (v0.1.0 bug).
    execSync(`git ls-files --error-unmatch "${filePath}"`, {
      stdio: 'ignore',
      cwd: dirname(filePath),
    });
    return true;
  } catch {
    return false;
  }
}

function isInGitRepo(dir: string): boolean {
  try {
    execSync('git rev-parse --is-inside-work-tree', { stdio: 'ignore', cwd: dir });
    return true;
  } catch {
    return false;
  }
}

function parseSeverity(s: string): Severity {
  if (['critical', 'high', 'medium', 'info'].includes(s)) return s as Severity;
  throw new Error(`Invalid severity: ${s}`);
}

function scanDirectory(
  scanRoot: string,
  opts: { json: boolean; severity: Severity; failOn: Severity; quiet: boolean; maxDepth?: number },
): number {
  const absRoot = resolve(scanRoot);
  const configFiles = discoverConfigs(absRoot, opts.maxDepth);
  const inGit = isInGitRepo(absRoot);

  const allFindings: Finding[] = [];

  for (const configPath of configFiles) {
    let content: string;
    try {
      content = readFileSync(configPath, 'utf-8');
    } catch {
      if (!opts.quiet) {
        console.log(`  ${configPath}\n  [HIGH]     MCP-SCAN: cannot read file (permission denied)\n`);
      }
      allFindings.push({
        file: relative(absRoot, configPath),
        rule_id: 'MCP-SCAN',
        severity: 'high',
        server_name: '(file)',
        message: 'Cannot read MCP config file (permission denied).',
        remediation: 'Check file permissions.',
      });
      continue;
    }

    const tracked = inGit ? isFileGitTracked(configPath) : true;
    const findings = analyzeConfig(relative(absRoot, configPath), content, tracked);
    allFindings.push(...findings);
  }

  // Filter by --severity threshold
  const filtered = allFindings.filter(
    f => SEVERITY_RANK[f.severity] >= SEVERITY_RANK[opts.severity],
  );

  if (opts.json) {
    if (!opts.quiet) process.stdout.write(JSON.stringify(filtered, null, 2) + '\n');
    return filtered.some(f => SEVERITY_RANK[f.severity] >= SEVERITY_RANK[opts.failOn]) ? 1 : 0;
  }

  if (!opts.quiet) {
    if (!opts.json) {
      console.log(`mcpscan ${VERSION} -- scanning ${absRoot}\n`);
    }

    // Group by file
    const byFile = new Map<string, Finding[]>();
    for (const f of filtered) {
      if (!byFile.has(f.file)) byFile.set(f.file, []);
      byFile.get(f.file)!.push(f);
    }

    for (const [file, findings] of byFile) {
      console.log(`  ${file}`);
      for (const f of findings) {
        console.log(`  ${SEVERITY_LABEL[f.severity]} ${f.rule_id}: ${f.message}`);
        if (f.rule_id !== 'MCP-006') {
          console.log(`             Remediation: ${f.remediation}`);
        }
      }
      console.log('');
    }

    const critical = filtered.filter(f => f.severity === 'critical').length;
    const high = filtered.filter(f => f.severity === 'high').length;
    const medium = filtered.filter(f => f.severity === 'medium').length;
    const info = filtered.filter(f => f.severity === 'info').length;

    if (filtered.length === 0) {
      console.log(`0 findings -- no MCP config files detected or all passed.`);
    } else {
      console.log(
        `${filtered.length} findings (${critical} critical, ${high} high, ${medium} medium, ${info} info)`,
      );
      if (!opts.json) {
        console.log('Run with --json for machine-readable output.');
      }
    }
  }

  return filtered.some(f => SEVERITY_RANK[f.severity] >= SEVERITY_RANK[opts.failOn]) ? 1 : 0;
}

const HOOK_TEMPLATE = `#!/bin/sh
# MCPScan pre-commit hook -- do not edit manually
# To bypass: MCPSCAN_SKIP=1 git commit
# mcpscan exit codes: 0 = clean, 1 = findings at/above --fail-on, 2 = scan error

if [ "\${MCPSCAN_SKIP}" = "1" ]; then
  printf 'mcpscan: skipping MCP config scan (MCPSCAN_SKIP=1)\\n' >&2
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
  printf '\\nmcpscan: commit blocked -- high or critical MCP config findings detected.\\n' >&2
  printf "Run 'mcpscan .' for details, or set MCPSCAN_SKIP=1 to bypass.\\n" >&2
elif [ $MCPSCAN_EXIT -ne 0 ]; then
  printf '\\nmcpscan: commit blocked -- the scan failed to run (exit %s, NOT a security finding).\\n' "\$MCPSCAN_EXIT" >&2
  printf "Run 'mcpscan .' for the error, or bypass once with MCPSCAN_SKIP=1 git commit.\\n" >&2
fi

exit $MCPSCAN_EXIT
`;

const HOOK_MARKER = '# MCPScan pre-commit hook';

function installHook(targetDir: string): void {
  const absDir = resolve(targetDir);

  if (!isInGitRepo(absDir)) {
    console.error(`mcpscan: no git repository found at ${absDir}`);
    process.exit(2);
  }

  let gitRoot: string;
  try {
    gitRoot = execSync('git rev-parse --show-toplevel', { cwd: absDir, encoding: 'utf-8' }).trim();
  } catch {
    console.error('mcpscan: could not determine git root');
    process.exit(2);
  }

  const hookPath = `${gitRoot}/.git/hooks/pre-commit`;

  if (existsSync(hookPath)) {
    const existing = readFileSync(hookPath, 'utf-8');
    if (existing.includes(HOOK_MARKER)) {
      console.log('mcpscan: pre-commit hook already installed (idempotent -- no changes).');
      return;
    }
    // Append to existing hook
    console.warn(
      `mcpscan: existing pre-commit hook found at ${hookPath} -- appending mcpscan hook.`,
    );
    writeFileSync(hookPath, existing.trimEnd() + '\n\n' + HOOK_TEMPLATE, 'utf-8');
  } else {
    writeFileSync(hookPath, HOOK_TEMPLATE, 'utf-8');
  }

  chmodSync(hookPath, 0o755);
  console.log(`mcpscan: pre-commit hook installed at ${hookPath}`);
  console.log('Commits will be blocked if high or critical MCP config findings are detected.');
  console.log('Override: MCPSCAN_SKIP=1 git commit');
}

// ---- CLI definition ----

const program = new Command();

program
  .name('mcpscan')
  .description('Static scanner for malicious MCP config files in AI-integrated editor repos')
  .version(VERSION, '-v, --version')
  .argument('[path]', 'directory to scan', '.')
  .option('--json', 'output findings as JSON array')
  .option('--quiet', 'suppress all output (exit code only)')
  .option('--max-depth <n>', 'limit directory traversal depth', parseInt)
  .option(
    '--severity <level>',
    'minimum severity to report (critical|high|medium|info)',
    'info',
  )
  .option(
    '--fail-on <level>',
    'exit non-zero if any finding at or above this severity (critical|high|medium)',
    'high',
  )
  .action((scanPath: string, opts) => {
    try {
      const severity = parseSeverity(opts.severity);
      const failOn = parseSeverity(opts.failOn);
      const exitCode = scanDirectory(scanPath, {
        json: Boolean(opts.json),
        quiet: Boolean(opts.quiet),
        severity,
        failOn,
        maxDepth: opts.maxDepth as number | undefined,
      });
      process.exit(exitCode);
    } catch (err) {
      console.error(`mcpscan: error -- ${(err as Error).message}`);
      process.exit(2);
    }
  });

program
  .command('install-hook [path]')
  .description('install mcpscan as a pre-commit hook in the git repository')
  .action((hookPath: string = '.') => {
    installHook(hookPath);
  });

program
  .command('rules')
  .description('list all detection rules')
  .action(() => {
    console.log('MCPScan detection rules:\n');
    for (const rule of RULES) {
      console.log(`  ${rule.id}  [${rule.severity.toUpperCase()}]`);
      console.log(`       ${rule.description}\n`);
    }
    process.exit(0);
  });

program
  .command('version')
  .description('print version')
  .action(() => {
    console.log(`mcpscan ${VERSION}`);
    process.exit(0);
  });

program.parse();
