import { RULES, type Finding, type Severity } from './engine.js';

/** SARIF 2.1.0 output for GitHub code scanning and other SARIF consumers. */

const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  info: 'note',
};

// GitHub code scanning buckets: 9.0+ critical, 7.0-8.9 high, 4.0-6.9 medium.
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: '9.5',
  high: '8.0',
  medium: '5.0',
  info: '0.0',
};

export function toSarif(findings: Finding[], version: string): object {
  const ruleIndex = new Map(RULES.map((r, i) => [r.id, i]));

  return {
    $schema:
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'mcpscan',
            version,
            informationUri: 'https://github.com/mayhemx87/mcpscan',
            rules: RULES.map(r => ({
              id: r.id,
              shortDescription: { text: r.description },
              helpUri: 'https://github.com/mayhemx87/mcpscan#detection-rules',
              defaultConfiguration: { level: LEVEL[r.severity] },
              properties: {
                'security-severity': SECURITY_SEVERITY[r.severity],
                tags: ['security', 'supply-chain', 'mcp'],
              },
            })),
          },
        },
        results: findings.map(f => ({
          ruleId: f.rule_id,
          ...(ruleIndex.has(f.rule_id) ? { ruleIndex: ruleIndex.get(f.rule_id) } : {}),
          level: LEVEL[f.severity],
          message: { text: `${f.message} Remediation: ${f.remediation}` },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: f.file.replace(/\\/g, '/'),
                  uriBaseId: '%SRCROOT%',
                },
                region: { startLine: f.line ?? 1 },
              },
            },
          ],
        })),
      },
    ],
  };
}
