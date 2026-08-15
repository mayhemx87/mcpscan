#!/usr/bin/env node
import { Command } from 'commander';
import { readFileSync, writeFileSync, existsSync, chmodSync, mkdirSync } from 'fs';
import { execFileSync } from 'child_process';
import { fileURLToPath } from 'url';
import { resolve, relative, dirname, join } from 'path';
import { discoverConfigs } from './discovery.js';
import { analyzeConfig, RULES, type Finding, type Severity, SEVERITY_RANK } from './engine.js';
import { toSarif } from './sarif.js';

// Single source of truth for the version: this package's package.json. The
// location differs between the built layout (dist/cli.js, one level down) and
// running the TypeScript source directly under tsx (cli.ts, package root).
// The name check prevents picking up an unrelated parent package.json.
const moduleDir = dirname(fileURLToPath(import.meta.url));
function loadVersion(): string {
  for (const p of [join(moduleDir, 'package.json'), join(moduleDir, '..', 'package.json')]) {
    try {
      const pkg = JSON.parse(readFileSync(p, 'utf-8')) as { name?: string; version?: string };
      if (pkg.name === 'mcpscan' && pkg.version) return pkg.version;
    } catch {
      /* try next */
    }
  }
  return '0.0.0';
}
const VERSION = loadVersion();

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
    // execFileSync (no shell): the path is untrusted input from the scanned
    // repo -- interpolating it into a shell string would let a crafted
    // filename execute commands.
    execFileSync('git', ['ls-files', '--error-unmatch', '--', filePath], {
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
    execFileSync('git', ['rev-parse', '--is-inside-work-tree'], { stdio: 'ignore', cwd: dir });
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
  opts: {
    json: boolean;
    sarif: boolean;
    severity: Severity;
    failOn: Severity;
    quiet: boolean;
    maxDepth?: number;
  },
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

  if (opts.sarif) {
    process.stdout.write(JSON.stringify(toSarif(filtered, VERSION), null, 2) + '\n');
    return filtered.some(f => SEVERITY_RANK[f.severity] >= SEVERITY_RANK[opts.failOn]) ? 1 : 0;
  }

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

  // --git-path respects core.hooksPath, worktrees, and submodules -- a
  // hardcoded .git/hooks path silently installs a hook git never runs.
  let hooksDir: string;
  try {
    const raw = execFileSync('git', ['rev-parse', '--git-path', 'hooks'], {
      cwd: absDir,
      encoding: 'utf-8',
    }).trim();
    hooksDir = resolve(absDir, raw);
  } catch {
    console.error('mcpscan: could not determine git hooks directory');
    process.exit(2);
  }

  mkdirSync(hooksDir, { recursive: true });
  const hookPath = join(hooksDir, 'pre-commit');

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
  .option('--sarif', 'output findings as SARIF 2.1.0 (for GitHub code scanning)')
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
      if (opts.json && opts.sarif) {
        throw new Error('--json and --sarif are mutually exclusive');
      }
      const maxDepth = opts.maxDepth as number | undefined;
      if (maxDepth !== undefined && (!Number.isInteger(maxDepth) || maxDepth < 0)) {
        throw new Error('--max-depth must be a non-negative integer');
      }
      const exitCode = scanDirectory(scanPath, {
        json: Boolean(opts.json),
        sarif: Boolean(opts.sarif),
        quiet: Boolean(opts.quiet),
        severity,
        failOn,
        maxDepth,
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
