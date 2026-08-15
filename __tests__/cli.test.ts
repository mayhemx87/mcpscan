import { describe, it, expect } from 'vitest';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { spawnSync } from 'child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const FIXTURES = join(__dirname, 'fixtures');
const CLI_PATH = join(__dirname, '..', 'cli.ts');
// Invoke tsx via its JS entry under node -- the .bin/tsx shim is a POSIX
// shell script that spawnSync cannot execute on Windows (the whole suite
// silently returned empty output + exit 1 there).
const TSX_ENTRY = join(__dirname, '..', 'node_modules', 'tsx', 'dist', 'cli.mjs');

function runCli(args: string[], cwd: string = FIXTURES) {
  const result = spawnSync(process.execPath, [TSX_ENTRY, CLI_PATH, ...args], {
    cwd,
    encoding: 'utf-8',
    env: { ...process.env },
  });
  return {
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
    exitCode: result.status ?? 1,
  };
}

describe('CLI -- C3', () => {
  describe('scan subcommand', () => {
    it('exits 0 and prints no critical/high findings for clean-repo', () => {
      const { exitCode, stdout } = runCli([join(FIXTURES, 'clean-repo')]);
      expect(exitCode).toBe(0);
      expect(stdout).not.toMatch(/\[CRITICAL\]/);
      expect(stdout).not.toMatch(/\[HIGH\]/);
    });

    it('exits 1 for cve-12957 fixture with CRITICAL finding', () => {
      const { exitCode, stdout } = runCli([join(FIXTURES, 'cve-12957')]);
      expect(exitCode).toBe(1);
      expect(stdout).toMatch(/\[CRITICAL\]/);
      expect(stdout).toMatch(/MCP-001/);
    });

    it('exits 1 for credential-leak fixture with HIGH finding', () => {
      const { exitCode, stdout } = runCli([join(FIXTURES, 'credential-leak')]);
      expect(exitCode).toBe(1);
      expect(stdout).toMatch(/\[HIGH\]/);
      expect(stdout).toMatch(/MCP-003/);
    });

    it('exits 0 for no-mcp fixture', () => {
      const { exitCode, stdout } = runCli([join(FIXTURES, 'no-mcp')]);
      expect(exitCode).toBe(0);
      expect(stdout).toMatch(/0 findings/);
    });

    it('discovers nested .amazonq/mcp.json and reports it', () => {
      const { exitCode, stdout } = runCli([join(FIXTURES, 'nested')]);
      expect(exitCode).toBe(1);
      expect(stdout).toMatch(/\.amazonq[/\\]mcp\.json|amazonq.*mcp/i);
    });
  });

  describe('--json flag', () => {
    it('outputs valid JSON array for cve-12957', () => {
      const { stdout, exitCode } = runCli([join(FIXTURES, 'cve-12957'), '--json']);
      expect(exitCode).toBe(1);
      let parsed: unknown;
      expect(() => { parsed = JSON.parse(stdout); }).not.toThrow();
      expect(Array.isArray(parsed)).toBe(true);
      const findings = parsed as Array<Record<string, unknown>>;
      expect(findings.length).toBeGreaterThan(0);
      const f = findings[0];
      expect(f).toHaveProperty('file');
      expect(f).toHaveProperty('rule_id');
      expect(f).toHaveProperty('severity');
      expect(f).toHaveProperty('server_name');
      expect(f).toHaveProperty('message');
      expect(f).toHaveProperty('remediation');
    });

    it('JSON output uses relative paths (no absolute paths in file field)', () => {
      const { stdout } = runCli([join(FIXTURES, 'cve-12957'), '--json']);
      const findings = JSON.parse(stdout) as Array<{ file: string }>;
      for (const f of findings) {
        expect(f.file).not.toMatch(/^\/(?!\.)/); // must not start with /
      }
    });
  });

  describe('--severity and --fail-on flags', () => {
    it('--severity high --fail-on critical with only a high finding exits 0', () => {
      // credential-leak has HIGH (MCP-003) but no CRITICAL
      const { exitCode } = runCli([join(FIXTURES, 'credential-leak'), '--severity', 'high', '--fail-on', 'critical']);
      expect(exitCode).toBe(0);
    });

    it('--fail-on high with a high finding exits 1', () => {
      const { exitCode } = runCli([join(FIXTURES, 'credential-leak'), '--fail-on', 'high']);
      expect(exitCode).toBe(1);
    });
  });

  describe('--quiet flag', () => {
    it('suppresses stdout output but exits 1 when findings above threshold', () => {
      const { exitCode, stdout } = runCli([join(FIXTURES, 'cve-12957'), '--quiet']);
      expect(exitCode).toBe(1);
      expect(stdout.trim()).toBe('');
    });
  });

  describe('install-hook subcommand', () => {
    // These tests use temp directories under os.tmpdir(), never the fixtures
    // dir. git resolves the repository root by walking UP from the target
    // path, so a target inside any git repository -- including the one
    // containing this test suite -- installs the hook into THAT repository.
    // An earlier version of the no-git test passed the fixtures dir and
    // silently installed the hook into the enclosing repo on every test run.

    it('exits 2 with a clear error when the target is not inside a git repository', () => {
      const noGitDir = mkdtempSync(join(tmpdir(), 'mcpscan-nogit-'));
      try {
        const { exitCode, stderr } = runCli(['install-hook', noGitDir]);
        expect(exitCode).toBe(2);
        expect(stderr).toMatch(/no git repository found/);
      } finally {
        rmSync(noGitDir, { recursive: true, force: true });
      }
    });

    it('installs the hook into the target repository only, idempotently', () => {
      // Guard against the leak described above: capture whether the repo
      // containing this suite has a pre-commit hook before the run, and
      // assert the run does not create one.
      const enclosingRoot = spawnSync('git', ['rev-parse', '--show-toplevel'], {
        cwd: __dirname,
        encoding: 'utf-8',
      }).stdout?.trim();
      const enclosingHook = enclosingRoot
        ? join(enclosingRoot, '.git', 'hooks', 'pre-commit')
        : null;
      const enclosingHadHook = enclosingHook ? existsSync(enclosingHook) : false;

      const repoDir = mkdtempSync(join(tmpdir(), 'mcpscan-repo-'));
      try {
        spawnSync('git', ['init', '-q'], { cwd: repoDir });

        const first = runCli(['install-hook', repoDir]);
        expect(first.exitCode).toBe(0);

        const hookPath = join(repoDir, '.git', 'hooks', 'pre-commit');
        expect(existsSync(hookPath)).toBe(true);
        const hook = readFileSync(hookPath, 'utf-8');
        expect(hook).toMatch(/# MCPScan pre-commit hook/);
        expect(hook).toMatch(/npx --yes mcpscan@latest/);

        const second = runCli(['install-hook', repoDir]);
        expect(second.exitCode).toBe(0);
        expect(second.stdout).toMatch(/already installed/);

        if (enclosingHook && !enclosingHadHook) {
          expect(existsSync(enclosingHook)).toBe(false);
        }
      } finally {
        rmSync(repoDir, { recursive: true, force: true });
      }
    });
  });

  describe('rules subcommand', () => {
    it('lists all six rules', () => {
      const { exitCode, stdout } = runCli(['rules']);
      expect(exitCode).toBe(0);
      expect(stdout).toMatch(/MCP-001/);
      expect(stdout).toMatch(/MCP-002/);
      expect(stdout).toMatch(/MCP-003/);
      expect(stdout).toMatch(/MCP-004/);
      expect(stdout).toMatch(/MCP-005/);
      expect(stdout).toMatch(/MCP-006/);
    });
  });

  describe('version subcommand', () => {
    it('prints version string', () => {
      const { exitCode, stdout } = runCli(['version']);
      expect(exitCode).toBe(0);
      expect(stdout).toMatch(/mcpscan \d+\.\d+\.\d+/);
    });
  });

  describe('Constraint: no absolute paths in --json output', () => {
    it('file paths in JSON output are relative to scan root', () => {
      const { stdout } = runCli([join(FIXTURES, 'cve-12957'), '--json']);
      const findings = JSON.parse(stdout) as Array<{ file: string }>;
      for (const f of findings) {
        expect(f.file.startsWith('/')).toBe(false);
      }
    });
  });

  describe('--sarif flag', () => {
    it('outputs valid SARIF 2.1.0 and exits 1 for cve-12957', () => {
      const { stdout, exitCode } = runCli([join(FIXTURES, 'cve-12957'), '--sarif']);
      expect(exitCode).toBe(1);
      const sarif = JSON.parse(stdout) as {
        version: string;
        runs: Array<{ tool: { driver: { name: string } }; results: Array<{ ruleId: string }> }>;
      };
      expect(sarif.version).toBe('2.1.0');
      expect(sarif.runs[0].tool.driver.name).toBe('mcpscan');
      expect(sarif.runs[0].results.some(r => r.ruleId === 'MCP-001')).toBe(true);
    });

    it('rejects --json combined with --sarif with exit 2', () => {
      const { exitCode, stderr } = runCli([join(FIXTURES, 'cve-12957'), '--json', '--sarif']);
      expect(exitCode).toBe(2);
      expect(stderr).toMatch(/mutually exclusive/);
    });
  });

  describe('--max-depth validation', () => {
    it('rejects a non-numeric --max-depth with exit 2', () => {
      const { exitCode, stderr } = runCli([join(FIXTURES, 'clean-repo'), '--max-depth', 'abc']);
      expect(exitCode).toBe(2);
      expect(stderr).toMatch(/max-depth/);
    });
  });

  describe('untrusted filenames', () => {
    it('handles config paths containing shell metacharacters without executing them', () => {
      // isFileGitTracked receives paths from the scanned repo; a crafted
      // directory name must be passed as an argv element, never a shell string.
      const evilDir = mkdtempSync(join(tmpdir(), 'mcpscan-evil-'));
      try {
        spawnSync('git', ['init', '-q'], { cwd: evilDir });
        // The trap name must stay Windows-legal (no colons), so the canary is
        // a bare filename: the vulnerable execSync ran with cwd = the config's
        // own directory, so a shell-interpreted backtick would create the
        // canary right inside the trap dir.
        const trap = join(evilDir, '`touch pwned`');
        mkdirSync(trap, { recursive: true });
        writeFileSync(join(trap, '.mcp.json'), JSON.stringify({ mcpServers: { s: { command: 'node ./x.js' } } }));
        const { exitCode } = runCli([evilDir]);
        expect([0, 1]).toContain(exitCode); // scan completes either way
        expect(existsSync(join(trap, 'pwned'))).toBe(false); // and nothing was executed
        expect(existsSync(join(evilDir, 'pwned'))).toBe(false);
      } finally {
        rmSync(evilDir, { recursive: true, force: true });
      }
    });
  });

  describe('Malformed config (C5 fixture)', () => {
    it('reports HIGH parse error and exits 1 for malformed fixture', () => {
      const { exitCode, stdout } = runCli([join(FIXTURES, 'malformed')]);
      expect(exitCode).toBe(1);
      expect(stdout).toMatch(/\[HIGH\]/);
    });
  });
});
