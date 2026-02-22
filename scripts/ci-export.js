#!/usr/bin/env node
/**
 * E18: JSON Export for CI
 *
 * Generates a machine-readable JSON report for CI/CD pipeline integration.
 * The script exits with a non-zero code when severity thresholds are exceeded,
 * making it usable as a CI gate (e.g., fail the build on critical issues).
 *
 * Exit codes:
 *   0 — PASS: all thresholds met
 *   1 — FAIL: one or more severity thresholds exceeded
 *   2 — ERROR: script failed to run (API error, etc.)
 *
 * Output:
 *   - Writes JSON to stdout (pipe-friendly for CI)
 *   - Optionally writes to experiments/ci-export-{date}/ directory
 *
 * Environment:
 *   OX_APP_NAME       — filter to matching app name
 *   OX_SEVERITY       — comma-separated severities to include (default: all)
 *   OX_LIMIT          — max issues to fetch (default: 500)
 *   OX_MAX_CRITICAL   — max allowed critical issues before FAIL (default: 0)
 *   OX_MAX_HIGH       — max allowed high issues before FAIL (default: -1 = unlimited)
 *   OX_MAX_MEDIUM     — max allowed medium issues before FAIL (default: -1 = unlimited)
 *   OX_MAX_LOW        — max allowed low issues before FAIL (default: -1 = unlimited)
 *   OX_MAX_TOTAL      — max allowed total issues before FAIL (default: -1 = unlimited)
 *   OX_OUTPUT_FILE    — write JSON to this file path instead of stdout (default: off)
 *   OX_SAVE_EXPERIMENT— set to "true" to save to experiments/ directory (default: true)
 *   OX_QUIET          — set to "true" to suppress stderr status messages
 *
 * Usage:
 *   # Basic — fail if any critical issues exist
 *   node scripts/ci-export.js
 *
 *   # Custom thresholds
 *   OX_MAX_CRITICAL=2 OX_MAX_HIGH=10 node scripts/ci-export.js
 *
 *   # Pipe JSON to jq
 *   node scripts/ci-export.js | jq '.summary'
 *
 *   # Filter by app, write to file
 *   OX_APP_NAME=MyBankingApp OX_OUTPUT_FILE=report.json node scripts/ci-export.js
 *
 *   # In CI pipeline (GitHub Actions example):
 *   #   - run: node scripts/ci-export.js > scan-results.json
 *   #     env:
 *   #       OX_API_KEY: ${{ secrets.OX_API_KEY }}
 *   #       OX_MAX_CRITICAL: 0
 *   #       OX_MAX_HIGH: 5
 */
import { writeFileSync, mkdirSync, readFileSync, existsSync } from 'fs';
import { resolve } from 'path';

// ---------------------------------------------------------------------------
// .env loader
// ---------------------------------------------------------------------------
function loadEnvQuiet() {
  const envPath = resolve(process.cwd(), '.env');
  if (!existsSync(envPath)) return;
  const lines = readFileSync(envPath, 'utf-8').split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx === -1) continue;
    const key = trimmed.slice(0, eqIdx).trim();
    const val = trimmed.slice(eqIdx + 1).trim();
    if (!process.env[key]) process.env[key] = val;
  }
}

loadEnvQuiet();
const USE_MOCK = !process.env.OX_API_KEY;
const QUIET = process.env.OX_QUIET === 'true';

let queryFn;
if (!USE_MOCK) {
  const client = await import('../lib/ox-client.js');
  queryFn = client.query;
}

// Status logging to stderr (so stdout stays clean JSON for piping)
function log(msg) {
  if (!QUIET) process.stderr.write(msg + '\n');
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
const CONFIG = {
  appFilter: process.env.OX_APP_NAME || process.argv[2] || '',
  severityFilter: process.env.OX_SEVERITY ? process.env.OX_SEVERITY.split(',').map(s => s.trim()) : [],
  limit: parseInt(process.env.OX_LIMIT || '500', 10),
  thresholds: {
    critical: parseInt(process.env.OX_MAX_CRITICAL ?? '0', 10),
    high: parseInt(process.env.OX_MAX_HIGH ?? '-1', 10),
    medium: parseInt(process.env.OX_MAX_MEDIUM ?? '-1', 10),
    low: parseInt(process.env.OX_MAX_LOW ?? '-1', 10),
    total: parseInt(process.env.OX_MAX_TOTAL ?? '-1', 10),
  },
  outputFile: process.env.OX_OUTPUT_FILE || '',
  saveExperiment: process.env.OX_SAVE_EXPERIMENT !== 'false',
};

// ---------------------------------------------------------------------------
// Severity helpers
// ---------------------------------------------------------------------------
const SEV_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Info'];
const SEV_WEIGHT = { Critical: 10, High: 5, Medium: 2, Low: 0.5, Info: 0 };

// ---------------------------------------------------------------------------
// Mock data — realistic iOS app issues for offline/demo mode
// ---------------------------------------------------------------------------
function getMockApps() {
  return [
    {
      appId: 'app-1', appName: 'MyBankingApp-iOS', risk: 82, type: 'Mobile',
      businessPriority: 'Critical',
      issuesBySeverity: { critical: 2, high: 3, medium: 1, low: 0, info: 0 },
    },
    {
      appId: 'app-2', appName: 'HealthTracker-iOS', risk: 68, type: 'Mobile',
      businessPriority: 'High',
      issuesBySeverity: { critical: 1, high: 2, medium: 2, low: 0, info: 0 },
    },
    {
      appId: 'app-3', appName: 'ShopEasy-iOS', risk: 55, type: 'Mobile',
      businessPriority: 'Medium',
      issuesBySeverity: { critical: 1, high: 2, medium: 0, low: 1, info: 0 },
    },
  ];
}

function getMockIssues() {
  return [
    {
      issueId: 'ISS-001', mainTitle: 'Remote Code Execution in libxml2',
      secondTitle: 'CVE-2024-40896 affects libxml2 < 2.12.5 used via CocoaPods',
      severity: 'Critical', originalSeverity: 'Critical', sourceType: 'SCA',
      created: '2025-12-15T10:30:00Z',
      app: { id: 'app-1', name: 'MyBankingApp-iOS', type: 'Mobile' },
      category: { name: 'Vulnerable Dependency' },
    },
    {
      issueId: 'ISS-002', mainTitle: 'Prototype Pollution in lodash',
      secondTitle: 'lodash < 4.17.21 allows prototype pollution',
      severity: 'Critical', originalSeverity: 'Critical', sourceType: 'SCA',
      created: '2025-11-20T08:00:00Z',
      app: { id: 'app-1', name: 'MyBankingApp-iOS', type: 'Mobile' },
      category: { name: 'Vulnerable Dependency' },
    },
    {
      issueId: 'ISS-003', mainTitle: 'Insecure Data Storage — Keychain Missing Accessibility',
      secondTitle: 'Sensitive credentials stored without kSecAttrAccessibleWhenUnlockedThisDeviceOnly',
      severity: 'High', originalSeverity: 'Critical', sourceType: 'SAST',
      created: '2026-01-05T14:20:00Z',
      app: { id: 'app-2', name: 'HealthTracker-iOS', type: 'Mobile' },
      category: { name: 'Mobile Security' },
    },
    {
      issueId: 'ISS-004', mainTitle: 'Missing Certificate Pinning',
      secondTitle: 'App does not implement SSL/TLS certificate pinning',
      severity: 'High', originalSeverity: 'High', sourceType: 'SAST',
      created: '2026-01-10T09:15:00Z',
      app: { id: 'app-1', name: 'MyBankingApp-iOS', type: 'Mobile' },
      category: { name: 'Mobile Security' },
    },
    {
      issueId: 'ISS-005', mainTitle: 'SQL Injection in SQLite Query Builder',
      secondTitle: 'User input concatenated directly into SQLite query',
      severity: 'Critical', originalSeverity: 'Critical', sourceType: 'SAST',
      created: '2026-01-18T16:45:00Z',
      app: { id: 'app-2', name: 'HealthTracker-iOS', type: 'Mobile' },
      category: { name: 'Code Vulnerability' },
    },
    {
      issueId: 'ISS-006', mainTitle: 'Vulnerable OpenSSL in Alamofire',
      secondTitle: 'Alamofire 5.6.x bundles OpenSSL with known CVEs',
      severity: 'High', originalSeverity: 'Critical', sourceType: 'SCA',
      created: '2025-10-22T11:30:00Z',
      app: { id: 'app-1', name: 'MyBankingApp-iOS', type: 'Mobile' },
      category: { name: 'Vulnerable Dependency' },
    },
    {
      issueId: 'ISS-007', mainTitle: 'Hardcoded API Key in Source Code',
      secondTitle: 'Firebase API key found in GoogleService-Info.plist',
      severity: 'High', originalSeverity: 'High', sourceType: 'Secret Detection',
      created: '2026-02-01T13:00:00Z',
      app: { id: 'app-3', name: 'ShopEasy-iOS', type: 'Mobile' },
      category: { name: 'Secret Detection' },
    },
    {
      issueId: 'ISS-008', mainTitle: 'Denial of Service in libexpat',
      secondTitle: 'CVE-2024-50602 — libexpat before 2.6.4 allows DoS',
      severity: 'High', originalSeverity: 'High', sourceType: 'SCA',
      created: '2026-01-25T10:00:00Z',
      app: { id: 'app-2', name: 'HealthTracker-iOS', type: 'Mobile' },
      category: { name: 'Vulnerable Dependency' },
    },
    {
      issueId: 'ISS-009', mainTitle: 'Insecure App Transport Security Configuration',
      secondTitle: 'NSAllowsArbitraryLoads set to YES in Info.plist',
      severity: 'High', originalSeverity: 'Medium', sourceType: 'SAST',
      created: '2026-02-05T15:30:00Z',
      app: { id: 'app-3', name: 'ShopEasy-iOS', type: 'Mobile' },
      category: { name: 'Mobile Security' },
    },
    {
      issueId: 'ISS-010', mainTitle: 'Outdated React Native with Known Vulnerabilities',
      secondTitle: 'react-native 0.71.x has multiple known CVEs in Hermes engine',
      severity: 'Critical', originalSeverity: 'High', sourceType: 'SCA',
      created: '2026-02-10T09:00:00Z',
      app: { id: 'app-3', name: 'ShopEasy-iOS', type: 'Mobile' },
      category: { name: 'Vulnerable Dependency' },
    },
    {
      issueId: 'ISS-011', mainTitle: 'ReDoS in Realm Query Parser',
      secondTitle: 'Realm < 10.45.0 regex parser vulnerable to ReDoS',
      severity: 'Medium', originalSeverity: 'Medium', sourceType: 'SCA',
      created: '2026-01-20T11:00:00Z',
      app: { id: 'app-2', name: 'HealthTracker-iOS', type: 'Mobile' },
      category: { name: 'Vulnerable Dependency' },
    },
    {
      issueId: 'ISS-012', mainTitle: 'Information Disclosure via Error Messages',
      secondTitle: 'Detailed stack traces returned in API error responses',
      severity: 'Medium', originalSeverity: 'Medium', sourceType: 'SAST',
      created: '2026-02-08T14:00:00Z',
      app: { id: 'app-1', name: 'MyBankingApp-iOS', type: 'Mobile' },
      category: { name: 'Code Vulnerability' },
    },
    {
      issueId: 'ISS-013', mainTitle: 'Buffer Overflow in hermes-engine',
      secondTitle: 'hermes-engine 0.71.x has heap buffer overflow in regex JIT',
      severity: 'High', originalSeverity: 'High', sourceType: 'SCA',
      created: '2026-02-12T09:30:00Z',
      app: { id: 'app-3', name: 'ShopEasy-iOS', type: 'Mobile' },
      category: { name: 'Vulnerable Dependency' },
    },
    {
      issueId: 'ISS-014', mainTitle: 'Outdated follow-redirects Dependency',
      secondTitle: 'follow-redirects < 1.15.6 has minor info leak',
      severity: 'Low', originalSeverity: 'Low', sourceType: 'SCA',
      created: '2026-01-30T08:00:00Z',
      app: { id: 'app-3', name: 'ShopEasy-iOS', type: 'Mobile' },
      category: { name: 'Vulnerable Dependency' },
    },
  ];
}

// ---------------------------------------------------------------------------
// Data fetching
// ---------------------------------------------------------------------------
async function fetchApps(appFilter) {
  if (USE_MOCK) {
    let apps = getMockApps();
    if (appFilter) apps = apps.filter(a => a.appName.toLowerCase().includes(appFilter.toLowerCase()));
    return apps;
  }

  const { GET_APPLICATIONS } = await import('../queries/applications.js');
  const data = await queryFn(GET_APPLICATIONS, {
    getApplicationsInput: { offset: 0, limit: 100 },
  });
  let apps = data.getApplications.applications;
  if (appFilter) apps = apps.filter(a => a.appName.toLowerCase().includes(appFilter.toLowerCase()));
  return apps;
}

async function fetchIssues(appFilter, severityFilter, limit) {
  if (USE_MOCK) {
    let issues = getMockIssues();
    if (appFilter) issues = issues.filter(i => i.app?.name?.toLowerCase().includes(appFilter.toLowerCase()));
    if (severityFilter.length) issues = issues.filter(i => severityFilter.includes(i.severity));
    return issues;
  }

  const { GET_ISSUES } = await import('../queries/issues.js');
  let allIssues = [];
  let offset = 0;
  const pageSize = Math.min(limit, 100);

  while (allIssues.length < limit) {
    const data = await queryFn(GET_ISSUES, {
      isDemo: false,
      getIssuesInput: {
        offset,
        limit: pageSize,
        sort: { fields: ['Severity'], order: ['DESC'] },
      },
    });
    const page = data.getIssues.issues || [];
    allIssues.push(...page);
    if (page.length < pageSize || allIssues.length >= data.getIssues.totalFilteredIssues) break;
    offset += pageSize;
  }

  // Apply filters
  if (appFilter) allIssues = allIssues.filter(i => i.app?.name?.toLowerCase().includes(appFilter.toLowerCase()));
  if (severityFilter.length) allIssues = allIssues.filter(i => severityFilter.includes(i.severity));

  return allIssues.slice(0, limit);
}

// ---------------------------------------------------------------------------
// Severity counting and threshold evaluation
// ---------------------------------------------------------------------------
function countBySeverity(issues) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const issue of issues) {
    const key = (issue.severity || 'info').toLowerCase();
    if (key in counts) counts[key]++;
  }
  counts.total = issues.length;
  return counts;
}

function countBySourceType(issues) {
  const counts = {};
  for (const issue of issues) {
    const st = issue.sourceType || 'Unknown';
    counts[st] = (counts[st] || 0) + 1;
  }
  return counts;
}

function countByCategory(issues) {
  const counts = {};
  for (const issue of issues) {
    const cat = issue.category?.name || 'Unknown';
    counts[cat] = (counts[cat] || 0) + 1;
  }
  return counts;
}

function countByApp(issues) {
  const apps = {};
  for (const issue of issues) {
    const name = issue.app?.name || 'Unknown';
    if (!apps[name]) apps[name] = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
    const key = (issue.severity || 'info').toLowerCase();
    if (key in apps[name]) apps[name][key]++;
    apps[name].total++;
  }
  return apps;
}

/**
 * Evaluate thresholds and return gate result.
 * Returns { passed: boolean, violations: [...] }
 */
function evaluateThresholds(counts, thresholds) {
  const violations = [];

  const checks = [
    { key: 'critical', label: 'Critical', threshold: thresholds.critical },
    { key: 'high', label: 'High', threshold: thresholds.high },
    { key: 'medium', label: 'Medium', threshold: thresholds.medium },
    { key: 'low', label: 'Low', threshold: thresholds.low },
    { key: 'total', label: 'Total', threshold: thresholds.total },
  ];

  for (const check of checks) {
    // -1 means unlimited (no threshold)
    if (check.threshold < 0) continue;

    const actual = counts[check.key] || 0;
    if (actual > check.threshold) {
      violations.push({
        severity: check.label,
        threshold: check.threshold,
        actual,
        exceeded_by: actual - check.threshold,
      });
    }
  }

  return {
    passed: violations.length === 0,
    violations,
  };
}

// ---------------------------------------------------------------------------
// Risk score computation (simplified from E11)
// ---------------------------------------------------------------------------
function computeRiskScore(counts) {
  const weighted = (counts.critical * SEV_WEIGHT.Critical)
    + (counts.high * SEV_WEIGHT.High)
    + (counts.medium * SEV_WEIGHT.Medium)
    + (counts.low * SEV_WEIGHT.Low)
    + (counts.info * SEV_WEIGHT.Info);
  // Normalize: 0 issues = 0, 100+ weighted = 100
  return Math.min(100, Math.round(weighted));
}

// ---------------------------------------------------------------------------
// Build CI-friendly JSON report
// ---------------------------------------------------------------------------
function buildReport(issues, apps, counts, gate, timestamp) {
  const byApp = countByApp(issues);
  const bySource = countBySourceType(issues);
  const byCategory = countByCategory(issues);

  // Format issues for CI consumption — flat, scannable structure
  const formattedIssues = issues.map(issue => ({
    id: issue.issueId,
    title: issue.mainTitle,
    description: issue.secondTitle || '',
    severity: issue.severity,
    original_severity: issue.originalSeverity || issue.severity,
    source_type: issue.sourceType || 'Unknown',
    category: issue.category?.name || 'Unknown',
    app: issue.app?.name || 'Unknown',
    created: issue.created || null,
    // For CI rule matching
    severity_weight: SEV_WEIGHT[issue.severity] || 0,
  }));

  // Sort: critical first, then high, then by date desc
  formattedIssues.sort((a, b) => {
    const sevDiff = (SEV_WEIGHT[b.severity] || 0) - (SEV_WEIGHT[a.severity] || 0);
    if (sevDiff !== 0) return sevDiff;
    return (b.created || '').localeCompare(a.created || '');
  });

  // Build the CI report structure
  const report = {
    // Schema version for forward compatibility
    schema_version: '1.0.0',
    tool: 'ox-security-ci-export',
    tool_version: '0.1.0',

    // Scan metadata
    scan: {
      timestamp,
      source: USE_MOCK ? 'mock' : 'ox-security-api',
      filters: {
        app: CONFIG.appFilter || null,
        severities: CONFIG.severityFilter.length ? CONFIG.severityFilter : null,
        limit: CONFIG.limit,
      },
    },

    // Gate result — the primary output for CI decision-making
    gate: {
      status: gate.passed ? 'PASS' : 'FAIL',
      exit_code: gate.passed ? 0 : 1,
      thresholds: {
        critical: CONFIG.thresholds.critical < 0 ? 'unlimited' : CONFIG.thresholds.critical,
        high: CONFIG.thresholds.high < 0 ? 'unlimited' : CONFIG.thresholds.high,
        medium: CONFIG.thresholds.medium < 0 ? 'unlimited' : CONFIG.thresholds.medium,
        low: CONFIG.thresholds.low < 0 ? 'unlimited' : CONFIG.thresholds.low,
        total: CONFIG.thresholds.total < 0 ? 'unlimited' : CONFIG.thresholds.total,
      },
      violations: gate.violations,
    },

    // Aggregate summary
    summary: {
      total_issues: counts.total,
      by_severity: {
        critical: counts.critical,
        high: counts.high,
        medium: counts.medium,
        low: counts.low,
        info: counts.info,
      },
      by_source_type: bySource,
      by_category: byCategory,
      risk_score: computeRiskScore(counts),
      apps_scanned: apps.length,
    },

    // Per-app breakdown
    apps: Object.entries(byApp).map(([name, appCounts]) => ({
      name,
      total_issues: appCounts.total,
      by_severity: {
        critical: appCounts.critical,
        high: appCounts.high,
        medium: appCounts.medium,
        low: appCounts.low,
        info: appCounts.info,
      },
      risk_score: computeRiskScore(appCounts),
    })).sort((a, b) => b.risk_score - a.risk_score),

    // Full issue list
    issues: formattedIssues,
  };

  return report;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  const timestamp = new Date().toISOString();

  log('E18: JSON Export for CI');
  log('=' .repeat(50));
  if (USE_MOCK) log('  No API key found — running with mock data');
  log(`  App filter: ${CONFIG.appFilter || 'all'}`);
  log(`  Severity filter: ${CONFIG.severityFilter.length ? CONFIG.severityFilter.join(', ') : 'all'}`);
  log(`  Thresholds: critical=${CONFIG.thresholds.critical}, high=${CONFIG.thresholds.high}, medium=${CONFIG.thresholds.medium}, low=${CONFIG.thresholds.low}, total=${CONFIG.thresholds.total}`);
  log('');

  // Fetch data
  log('Fetching applications...');
  const apps = await fetchApps(CONFIG.appFilter);
  log(`  Found ${apps.length} apps`);

  log('Fetching issues...');
  const issues = await fetchIssues(CONFIG.appFilter, CONFIG.severityFilter, CONFIG.limit);
  log(`  Found ${issues.length} issues`);

  // Count severities
  const counts = countBySeverity(issues);
  log(`  Severity counts: Critical=${counts.critical} High=${counts.high} Medium=${counts.medium} Low=${counts.low} Info=${counts.info}`);

  // Evaluate gate
  const gate = evaluateThresholds(counts, CONFIG.thresholds);
  log('');
  if (gate.passed) {
    log('Gate: PASS — all thresholds met');
  } else {
    log('Gate: FAIL — thresholds exceeded:');
    for (const v of gate.violations) {
      log(`  ${v.severity}: ${v.actual} found (max allowed: ${v.threshold}, exceeded by ${v.exceeded_by})`);
    }
  }
  log('');

  // Build report
  const report = buildReport(issues, apps, counts, gate, timestamp);

  // Output JSON to stdout
  const jsonStr = JSON.stringify(report, null, 2);
  process.stdout.write(jsonStr + '\n');

  // Optionally write to specific file
  if (CONFIG.outputFile) {
    writeFileSync(resolve(process.cwd(), CONFIG.outputFile), jsonStr);
    log(`Written to ${CONFIG.outputFile}`);
  }

  // Save to experiments directory
  if (CONFIG.saveExperiment) {
    const dateStr = timestamp.slice(0, 10);
    const outDir = resolve(process.cwd(), 'experiments', `ci-export-${dateStr}`);
    mkdirSync(outDir, { recursive: true });
    writeFileSync(resolve(outDir, 'ci-report.json'), jsonStr);

    // Also generate a human-readable summary for the experiments dir
    const summaryLines = [];
    summaryLines.push('# E18: CI Export Report');
    summaryLines.push(`\n*Generated: ${timestamp}*`);
    if (USE_MOCK) summaryLines.push('\n> **Mock Mode** — using realistic sample data (no OX_API_KEY configured)');
    summaryLines.push('');
    summaryLines.push(`## Gate Result: **${report.gate.status}**`);
    summaryLines.push('');
    summaryLines.push('### Thresholds');
    summaryLines.push('');
    summaryLines.push('| Severity | Threshold | Actual | Status |');
    summaryLines.push('|----------|-----------|--------|--------|');
    const threshMap = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', total: 'Total' };
    for (const [key, label] of Object.entries(threshMap)) {
      const thresh = CONFIG.thresholds[key];
      const actual = key === 'total' ? counts.total : (counts[key] || 0);
      const threshStr = thresh < 0 ? 'unlimited' : String(thresh);
      const violation = gate.violations.find(v => v.severity === label);
      const status = thresh < 0 ? '-' : (violation ? `FAIL (+${violation.exceeded_by})` : 'PASS');
      summaryLines.push(`| ${label} | ${threshStr} | ${actual} | ${status} |`);
    }
    summaryLines.push('');
    summaryLines.push('### Summary');
    summaryLines.push('');
    summaryLines.push(`- **Total issues:** ${counts.total}`);
    summaryLines.push(`- **Risk score:** ${report.summary.risk_score}/100`);
    summaryLines.push(`- **Apps scanned:** ${apps.length}`);
    summaryLines.push('');
    summaryLines.push('### Issues by Severity');
    summaryLines.push('');
    for (const sev of SEV_ORDER) {
      const count = counts[sev.toLowerCase()] || 0;
      if (count > 0) summaryLines.push(`- **${sev}:** ${count}`);
    }
    summaryLines.push('');
    summaryLines.push('### Per-App Breakdown');
    summaryLines.push('');
    summaryLines.push('| App | Critical | High | Medium | Low | Total | Risk |');
    summaryLines.push('|-----|----------|------|--------|-----|-------|------|');
    for (const app of report.apps) {
      summaryLines.push(`| ${app.name} | ${app.by_severity.critical} | ${app.by_severity.high} | ${app.by_severity.medium} | ${app.by_severity.low} | ${app.total_issues} | ${app.risk_score} |`);
    }
    summaryLines.push('');
    summaryLines.push('### CI Integration');
    summaryLines.push('');
    summaryLines.push('```yaml');
    summaryLines.push('# GitHub Actions example');
    summaryLines.push('- name: Ox Security Gate');
    summaryLines.push('  run: node scripts/ci-export.js > scan-results.json');
    summaryLines.push('  env:');
    summaryLines.push('    OX_API_KEY: ${{ secrets.OX_API_KEY }}');
    summaryLines.push('    OX_MAX_CRITICAL: 0');
    summaryLines.push('    OX_MAX_HIGH: 5');
    summaryLines.push('```');
    summaryLines.push('');
    summaryLines.push('```yaml');
    summaryLines.push('# GitLab CI example');
    summaryLines.push('security_gate:');
    summaryLines.push('  script:');
    summaryLines.push('    - node scripts/ci-export.js > scan-results.json');
    summaryLines.push('  variables:');
    summaryLines.push('    OX_API_KEY: $OX_API_KEY');
    summaryLines.push('    OX_MAX_CRITICAL: "0"');
    summaryLines.push('    OX_MAX_HIGH: "5"');
    summaryLines.push('  artifacts:');
    summaryLines.push('    paths:');
    summaryLines.push('      - scan-results.json');
    summaryLines.push('    when: always');
    summaryLines.push('```');
    summaryLines.push('');
    summaryLines.push('Exit codes: `0` = PASS, `1` = FAIL (threshold exceeded), `2` = ERROR');
    summaryLines.push('');

    writeFileSync(resolve(outDir, 'ci-export-report.md'), summaryLines.join('\n'));
    log(`Experiment saved to experiments/ci-export-${dateStr}/`);
    log('  - ci-report.json         (machine-readable)');
    log('  - ci-export-report.md    (human-readable summary)');
  }

  // Exit with appropriate code
  log(`\nExit code: ${gate.passed ? 0 : 1} (${gate.passed ? 'PASS' : 'FAIL'})`);
  process.exit(gate.passed ? 0 : 1);
}

main().catch(e => {
  process.stderr.write(`\nFatal: ${e.message}\n`);
  process.exit(2);
});
