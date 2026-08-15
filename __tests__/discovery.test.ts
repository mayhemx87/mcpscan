import { describe, it, expect } from 'vitest';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
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
});
