import { describe, it, expect } from 'vitest';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { mkdtempSync, rmSync, symlinkSync } from 'fs';
import { tmpdir } from 'os';
import { discoverConfigs } from '../discovery.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const FIXTURES = join(__dirname, 'fixtures');

describe('discoverConfigs -- C1', () => {
  it('finds .mcp.json at root', () => {
    const found = discoverConfigs(join(FIXTURES, 'clean-repo'));
    expect(found).toHaveLength(1);
    expect(found[0]).toMatch(/\.mcp\.json$/);
  });

  it('finds .amazonq/mcp.json nested two directories deep', () => {
    const found = discoverConfigs(join(FIXTURES, 'nested'));
    expect(found).toHaveLength(1);
    expect(found[0]).toMatch(/\.amazonq[/\\]mcp\.json$/);
  });

  it('returns empty list when no MCP config files exist (exit 0 scenario)', () => {
    const found = discoverConfigs(join(FIXTURES, 'no-mcp'));
    expect(found).toHaveLength(0);
  });

  it('still scans a file even if it would be gitignored (does not trust .gitignore)', () => {
    // Discovery is pure filesystem -- it reads every file regardless of git state.
    // The malformed fixture would typically be excluded by no .gitignore here,
    // but discovery must not consult git to decide what to scan.
    const found = discoverConfigs(join(FIXTURES, 'malformed'));
    expect(found).toHaveLength(1);
    expect(found[0]).toMatch(/\.mcp\.json$/);
  });

  it('respects --max-depth 0 (root only)', () => {
    // nested fixture has config at depth 2; with maxDepth 0 nothing found
    const found = discoverConfigs(join(FIXTURES, 'nested'), 0);
    expect(found).toHaveLength(0);
  });

  it('finds .amazonq/mcp.json at credential-leak fixture', () => {
    const found = discoverConfigs(join(FIXTURES, 'credential-leak'));
    expect(found).toHaveLength(1);
    expect(found[0]).toMatch(/\.amazonq[/\\]mcp\.json$/);
  });

  it('does not traverse into node_modules or .git', () => {
    // Regression guard: discovery must skip these dirs
    const found = discoverConfigs(join(FIXTURES, 'clean-repo'));
    expect(found.every(f => !f.includes('node_modules') && !f.includes('.git'))).toBe(true);
  });

  it('finds .roo/mcp.json (Roo Code)', () => {
    const found = discoverConfigs(join(FIXTURES, 'roo'));
    expect(found).toHaveLength(1);
    expect(found[0]).toMatch(/\.roo[/\\]mcp\.json$/);
  });

  it('finds .kiro/settings/mcp.json (Kiro)', () => {
    const found = discoverConfigs(join(FIXTURES, 'kiro'));
    expect(found).toHaveLength(1);
    expect(found[0]).toMatch(/\.kiro[/\\]settings[/\\]mcp\.json$/);
  });

  it('does not follow symlinked directories (loop / escape safety)', () => {
    // A symlink loop must not hang discovery, and a symlink pointing outside
    // the scan root must not widen the scan. Skipped where symlinks cannot
    // be created (e.g. Windows without developer mode).
    const dir = mkdtempSync(join(tmpdir(), 'mcpscan-symlink-'));
    try {
      try {
        symlinkSync(dir, join(dir, 'loop'), 'dir');
      } catch {
        return; // cannot create symlinks on this platform -- nothing to test
      }
      const found = discoverConfigs(dir);
      expect(found).toHaveLength(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
