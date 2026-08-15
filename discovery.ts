import { readdirSync, statSync } from 'fs';
import { join, relative, resolve } from 'path';

const SKIP_DIRS = new Set(['.git', 'node_modules', 'dist', '.cache', '__pycache__', '__tests__']);

/**
 * Returns true if the relative path from scan root matches a known
 * auto-loading MCP config file pattern.
 */
const MCP_CONFIG_SUFFIXES = [
  '.mcp.json',
  'mcp.json',
  '.amazonq/mcp.json',
  '.cursor/mcp.json',
  '.vscode/mcp.json',
  '.windsurf/mcp.json',
  // Embedded hosts (v0.2.0): MCP servers under a nested key; the engine
  // ignores these files entirely when they carry no MCP section.
  '.vscode/settings.json',
  '.claude/settings.json',
  '.claude/settings.local.json',
  '.gemini/settings.json',
];

function isMcpConfigPath(relPath: string): boolean {
  const p = relPath.replace(/\\/g, '/');
  return MCP_CONFIG_SUFFIXES.some(s => p === s || p.endsWith('/' + s));
}

/**
 * Recursively discovers MCP config files under rootDir.
 * Does not consult .gitignore -- security tools must scan all files.
 * Skips node_modules and .git for performance.
 */
export function discoverConfigs(rootDir: string, maxDepth?: number): string[] {
  const absRoot = resolve(rootDir);
  const found: string[] = [];
  walkDir(absRoot, absRoot, found, 0, maxDepth);
  return found;
}

function walkDir(
  absRoot: string,
  currentDir: string,
  found: string[],
  depth: number,
  maxDepth: number | undefined,
): void {
  if (maxDepth !== undefined && depth > maxDepth) return;

  let entries: string[];
  try {
    entries = readdirSync(currentDir);
  } catch {
    return; // permission denied or other OS error -- skip silently
  }

  for (const entry of entries) {
    const fullPath = join(currentDir, entry);

    let isDir = false;
    try {
      isDir = statSync(fullPath).isDirectory();
    } catch {
      continue;
    }

    if (isDir) {
      if (SKIP_DIRS.has(entry)) continue;
      walkDir(absRoot, fullPath, found, depth + 1, maxDepth);
    } else {
      const relPath = relative(absRoot, fullPath);
      if (isMcpConfigPath(relPath)) {
        found.push(fullPath);
      }
    }
  }
}
