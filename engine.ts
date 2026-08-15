import { parse as parseJsonc, type ParseError } from 'jsonc-parser';

export type Severity = 'critical' | 'high' | 'medium' | 'info';

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  info: 1,
};

export interface Finding {
  file: string;
  rule_id: string;
  severity: Severity;
  server_name: string;
  message: string;
  remediation: string;
}

interface MCPServer {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  type?: string;
  url?: string;
  headers?: Record<string, string>;
}

const CREDENTIAL_PATTERNS: RegExp[] = [
  /^AWS_/,
  /^GITHUB_TOKEN$/,
  /^ANTHROPIC_API_KEY$/,
  /^OPENAI_API_KEY$/,
  /^AZURE_/,
  /^GCP_/,
  /^GOOGLE_APPLICATION_CREDENTIALS$/,
  /SECRET/i,
  /PRIVATE_KEY/i,
];

/** Literal secret-looking VALUES (v0.2.0, MCP-007). A hardcoded credential in
 * a committed config is worse than env inheritance. `${...}`/`$VAR`
 * interpolations are exempt -- they resolve at runtime, nothing is committed. */
const SECRET_VALUE_PATTERNS: RegExp[] = [
  /AKIA[0-9A-Z]{16}/, // AWS access key id
  /sk-ant-[A-Za-z0-9_-]{8,}/, // Anthropic
  /sk-[A-Za-z0-9]{20,}/, // OpenAI-style
  /ghp_[A-Za-z0-9]{36}/, // GitHub PAT (classic)
  /github_pat_[A-Za-z0-9_]{20,}/, // GitHub PAT (fine-grained)
  /xox[abps]-[A-Za-z0-9-]{10,}/, // Slack
  /AIza[0-9A-Za-z_-]{35}/, // Google API key
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
];

function isHighValueCredential(key: string): boolean {
  return CREDENTIAL_PATTERNS.some(p => p.test(key));
}

function isInterpolation(value: string): boolean {
  return value.includes('${') || value.trim().startsWith('$');
}

function looksLikeLiteralSecret(value: string): boolean {
  if (isInterpolation(value)) return false;
  return SECRET_VALUE_PATTERNS.some(p => p.test(value));
}

/**
 * Returns true if the command line contains npx/uvx/pipx with an unversioned
 * package (handles compound commands like cmd1 && npx pkg). Runner flags
 * (-y, --yes, -q, --package=...) are skipped to find the real package token.
 * A version pin looks like @1.2.3 after the package name; scoped packages
 * (@scope/name) need a second @.
 */
function isUnversionedPackageRunner(line: string): boolean {
  const matches = [...line.matchAll(/\b(npx|uvx|pipx)\s+((?:[-@\w./=:]+\s+)*?)([@\w][\w./@-]*)/g)];
  for (const match of matches) {
    // Walk tokens after the runner, skipping flags, to the package token.
    const tokens = (match[2] + match[3]).trim().split(/\s+/).filter(Boolean);
    const pkg = tokens.find(t => !t.startsWith('-'));
    if (!pkg) continue;
    if (pkg.startsWith('@')) {
      if (!pkg.slice(1).includes('@')) return true; // @scope/pkg without @version
    } else if (!pkg.includes('@')) {
      return true; // pkg without @version
    }
  }
  return false;
}

/** Embedded-host files (editor/agent settings.json) carry MCP servers under a
 * nested key; a settings file with NO MCP section is out of scope entirely --
 * no findings, not even MCP-005, or every untracked settings.json in the wild
 * would produce noise. */
export function isEmbeddedHostFile(filePath: string): boolean {
  const p = filePath.replace(/\\/g, '/');
  return p.endsWith('settings.json') || p.endsWith('settings.local.json');
}

/** Extract the server map from any known config shape:
 * - dedicated files: { mcpServers: {...} } or VS Code's { servers: {...} }
 * - embedded hosts:  { mcpServers: {...} } (Claude/Gemini settings) or
 *                    { mcp: { servers: {...} } } (VS Code settings.json)   */
function extractServers(config: Record<string, unknown>): Record<string, MCPServer> | null {
  if (config.mcpServers && typeof config.mcpServers === 'object') {
    return config.mcpServers as Record<string, MCPServer>;
  }
  if (config.servers && typeof config.servers === 'object') {
    return config.servers as Record<string, MCPServer>;
  }
  const mcp = config.mcp as Record<string, unknown> | undefined;
  if (mcp && typeof mcp === 'object' && mcp.servers && typeof mcp.servers === 'object') {
    return mcp.servers as Record<string, MCPServer>;
  }
  return null;
}

/**
 * Statically analyzes the content of an MCP config file and returns findings.
 * Pure function -- no filesystem access, no subprocesses, no network calls.
 */
export function analyzeConfig(
  filePath: string,
  content: string,
  isGitTracked: boolean,
): Finding[] {
  const findings: Finding[] = [];
  const embedded = isEmbeddedHostFile(filePath);

  const errors: ParseError[] = [];
  let config: unknown;
  try {
    config = parseJsonc(content, errors);
  } catch {
    return embedded ? [] : [parseErrorFinding(filePath)];
  }

  if (errors.length > 0 || config === null || typeof config !== 'object' || Array.isArray(config)) {
    return embedded ? [] : [parseErrorFinding(filePath)];
  }

  const servers = extractServers(config as Record<string, unknown>);

  // Embedded settings files without an MCP section are out of scope.
  if (embedded && servers === null) return [];

  // MCP-005: file not tracked by git (may have been injected)
  if (!isGitTracked) {
    findings.push({
      file: filePath,
      rule_id: 'MCP-005',
      severity: 'medium',
      server_name: '(file)',
      message: 'MCP config file is not tracked by git -- may have been injected.',
      remediation:
        'Run `git add` to track intentionally, or delete if not placed by your team.',
    });
  }

  for (const [serverName, server] of Object.entries(servers ?? {})) {
    if (!server || typeof server !== 'object') continue;

    // Analyze command AND args as one line -- the dominant real-world shape
    // is {"command": "npx", "args": ["-y", "pkg"]}, invisible to any rule
    // that inspects `command` alone (the v0.1.0 gap).
    const args = Array.isArray(server.args) ? server.args.filter(a => typeof a === 'string') : [];
    const line = [server.command ?? '', ...args].join(' ').trim();
    const serverFindings: Finding[] = [];

    // MCP-001: remote URL or network command execution
    if (line && (/https?:\/\//.test(line) || /\b(curl|wget)\b/.test(line))) {
      serverFindings.push({
        file: filePath,
        rule_id: 'MCP-001',
        severity: 'critical',
        server_name: serverName,
        message: `Server "${serverName}" executes a remote URL or network command: ${line}`,
        remediation:
          'Replace with a locally-installed binary or a pinned, audited npm package.',
      });
    }

    // MCP-002: unversioned package runner (supply-chain risk)
    if (line && isUnversionedPackageRunner(line)) {
      serverFindings.push({
        file: filePath,
        rule_id: 'MCP-002',
        severity: 'high',
        server_name: serverName,
        message: `Server "${serverName}" runs an unversioned package: ${line}`,
        remediation:
          'Pin to a specific version (e.g., npx package@1.2.3) and audit the package.',
      });
    }

    // MCP-003: high-value credential env inheritance (key names)
    const env = server.env ?? {};
    for (const key of Object.keys(env)) {
      if (isHighValueCredential(key)) {
        serverFindings.push({
          file: filePath,
          rule_id: 'MCP-003',
          severity: 'high',
          server_name: serverName,
          message: `Server "${serverName}" inherits high-value credential env var: ${key}`,
          remediation:
            'Review whether this server requires live credentials and scope to least-privilege.',
        });
        break; // one MCP-003 finding per server
      }
    }

    // MCP-004: absolute path or path traversal outside repo
    const cmd = server.command ?? '';
    if (
      cmd.startsWith('/') ||
      args.some(a => a.startsWith('/')) ||
      /(?:^|[\s;|&])\.\.\//.test(line)
    ) {
      serverFindings.push({
        file: filePath,
        rule_id: 'MCP-004',
        severity: 'medium',
        server_name: serverName,
        message: `Server "${serverName}" references a path outside the repository: ${line}`,
        remediation:
          'Use a relative path within the repo or a globally-installed binary on PATH.',
      });
    }

    // MCP-007: hardcoded secret-looking value in env or headers
    for (const [source, record] of [['env', env], ['headers', server.headers ?? {}]] as const) {
      for (const [key, value] of Object.entries(record)) {
        if (typeof value === 'string' && looksLikeLiteralSecret(value)) {
          serverFindings.push({
            file: filePath,
            rule_id: 'MCP-007',
            severity: 'critical',
            server_name: serverName,
            message: `Server "${serverName}" has a hardcoded secret-looking value in ${source}.${key} -- a committed credential.`,
            remediation:
              'Remove the literal secret, rotate it immediately, and use an env interpolation (${VAR}) instead.',
          });
        }
      }
    }

    // MCP-008: remote MCP server (url-based) -- invisible in v0.1.0
    if (typeof server.url === 'string' && server.url.length > 0) {
      const insecure = server.url.startsWith('http://');
      serverFindings.push({
        file: filePath,
        rule_id: 'MCP-008',
        severity: insecure ? 'high' : 'info',
        server_name: serverName,
        message: insecure
          ? `Server "${serverName}" connects to a remote MCP endpoint over insecure HTTP: ${server.url}`
          : `Server "${serverName}" is a remote MCP endpoint: ${server.url} -- verify the endpoint is trusted.`,
        remediation: insecure
          ? 'Use HTTPS for remote MCP endpoints.'
          : 'Confirm this endpoint is operated by a party you trust; remote servers receive your prompts and tool traffic.',
      });
    }

    // MCP-009: shell metacharacters (execution chaining without literal curl/URL)
    if (line && (/\$\(/.test(line) || /`/.test(line) || /\|\s*(sh|bash|zsh)\b/.test(line))) {
      serverFindings.push({
        file: filePath,
        rule_id: 'MCP-009',
        severity: 'medium',
        server_name: serverName,
        message: `Server "${serverName}" uses shell command-chaining metacharacters: ${line}`,
        remediation:
          'Avoid command substitution and pipes in MCP server commands; invoke a single audited binary directly.',
      });
    }

    // MCP-006: clean server -- no other findings for this server
    if (serverFindings.length === 0) {
      serverFindings.push({
        file: filePath,
        rule_id: 'MCP-006',
        severity: 'info',
        server_name: serverName,
        message: `Server "${serverName}" passed all detection rules.`,
        remediation: 'No action required.',
      });
    }

    findings.push(...serverFindings);
  }

  return findings;
}

function parseErrorFinding(filePath: string): Finding {
  return {
    file: filePath,
    rule_id: 'MCP-PARSE',
    severity: 'high',
    server_name: '(unknown)',
    message: 'MCP config file has invalid JSON syntax -- cannot verify safety.',
    remediation:
      'Fix the JSON syntax or remove the file if it is not a valid MCP config.',
  };
}
