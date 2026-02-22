#!/usr/bin/env node
/**
 * E19: Diff Report
 *
 * Compares two scan snapshots and reports what changed:
 *   - New issues (appeared in "after" but not "before")
 *   - Resolved issues (present in "before" but gone from "after")
 *   - Severity changes (same issue, different severity)
 *   - App-level risk score changes
 *   - Severity distribution shifts
 *
 * Modes:
 *   1. snapshot  — Save current scan data as a named snapshot for later diffing
 *   2. diff      — Compare two snapshots (or two JSON files) and generate report
 *   3. demo      — Run with built-in mock "before" and "after" data (default)
 *
 * Usage:
 *   # Save a snapshot (uses API or mock data)
 *   node scripts/diff-report.js snapshot baseline
 *   node scripts/diff-report.js snapshot after-fix
 *
 *   # Diff two snapshots
 *   node scripts/diff-report.js diff baseline after-fix
 *
 *   # Diff two arbitrary JSON files (CI export format)
 *   OX_BEFORE=path/to/before.json OX_AFTER=path/to/after.json node scripts/diff-report.js
 *
 *   # Demo mode with mock data
 *   node scripts/diff-report.js
 *
 * Environment:
 *   OX_APP_NAME   — filter to matching app name
 *   OX_BEFORE     — path to "before" JSON file (CI export format)
 *   OX_AFTER      — path to "after" JSON file (CI export format)
 *
 * Output:
 *   experiments/diff-report-{date}/diff-report.md   — human-readable report
 *   experiments/diff-report-{date}/diff-data.json   — machine-readable diff
 *   experiments/snapshots/{name}.json               — saved snapshots
 */
import { writeFileSync, mkdirSync, readFileSync, existsSync, readdirSync } from 'fs';
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
const APP_FILTER = process.env.OX_APP_NAME || '';
const SNAPSHOTS_DIR = resolve(process.cwd(), 'experiments', 'snapshots');

let queryFn;
if (!USE_MOCK) {
  const client = await import('../lib/ox-client.js');
  queryFn = client.query;
}

// ---------------------------------------------------------------------------
// Severity helpers
// ---------------------------------------------------------------------------
const SEV_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Info'];
const SEV_WEIGHT = { Critical: 10, High: 5, Medium: 2, Low: 0.5, Info: 0 };
const SEV_IDX = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };

function sevCompare(a, b) {
  return (SEV_IDX[a] ?? 5) - (SEV_IDX[b] ?? 5);
}

function computeRiskScore(counts) {
  const weighted = (counts.critical * SEV_WEIGHT.Critical)
    + (counts.high * SEV_WEIGHT.High)
    + (counts.medium * SEV_WEIGHT.Medium)
    + (counts.low * SEV_WEIGHT.Low)
    + ((counts.info || 0) * SEV_WEIGHT.Info);
  return Math.min(100, Math.round(weighted));
}

// ---------------------------------------------------------------------------
// Mock data — "before" snapshot (older scan)
// ---------------------------------------------------------------------------
function getMockBefore() {
  return {
    schema_version: '1.0.0',
    scan: { timestamp: '2026-02-01T10:00:00Z', source: 'mock' },
    summary: { total_issues: 12, by_severity: { critical: 3, high: 4, medium: 3, low: 2, info: 0 } },
    apps: [
      { name: 'MyBankingApp-iOS', total_issues: 5, by_severity: { critical: 2, high: 2, medium: 1, low: 0, info: 0 }, risk_score: 55 },
      { name: 'HealthTracker-iOS', total_issues: 4, by_severity: { critical: 1, high: 1, medium: 1, low: 1, info: 0 }, risk_score: 22 },
      { name: 'ShopEasy-iOS', total_issues: 3, by_severity: { critical: 0, high: 1, medium: 1, low: 1, info: 0 }, risk_score: 12 },
    ],
    issues: [
      // MyBankingApp
      { id: 'ISS-001', title: 'Remote Code Execution in libxml2', severity: 'Critical', original_severity: 'Critical', source_type: 'SCA', category: 'Vulnerable Dependency', app: 'MyBankingApp-iOS', created: '2025-12-15T10:30:00Z' },
      { id: 'ISS-002', title: 'Prototype Pollution in lodash', severity: 'Critical', original_severity: 'Critical', source_type: 'SCA', category: 'Vulnerable Dependency', app: 'MyBankingApp-iOS', created: '2025-11-20T08:00:00Z' },
      { id: 'ISS-004', title: 'Missing Certificate Pinning', severity: 'High', original_severity: 'High', source_type: 'SAST', category: 'Mobile Security', app: 'MyBankingApp-iOS', created: '2026-01-10T09:15:00Z' },
      { id: 'ISS-006', title: 'Vulnerable OpenSSL in Alamofire', severity: 'High', original_severity: 'Critical', source_type: 'SCA', category: 'Vulnerable Dependency', app: 'MyBankingApp-iOS', created: '2025-10-22T11:30:00Z' },
      { id: 'ISS-012', title: 'Information Disclosure via Error Messages', severity: 'Medium', original_severity: 'Medium', source_type: 'SAST', category: 'Code Vulnerability', app: 'MyBankingApp-iOS', created: '2026-02-08T14:00:00Z' },
      // HealthTracker
      { id: 'ISS-003', title: 'Insecure Data Storage — Keychain Missing Accessibility', severity: 'Critical', original_severity: 'Critical', source_type: 'SAST', category: 'Mobile Security', app: 'HealthTracker-iOS', created: '2026-01-05T14:20:00Z' },
      { id: 'ISS-005', title: 'SQL Injection in SQLite Query Builder', severity: 'High', original_severity: 'High', source_type: 'SAST', category: 'Code Vulnerability', app: 'HealthTracker-iOS', created: '2026-01-18T16:45:00Z' },
      { id: 'ISS-011', title: 'ReDoS in Realm Query Parser', severity: 'Medium', original_severity: 'Medium', source_type: 'SCA', category: 'Vulnerable Dependency', app: 'HealthTracker-iOS', created: '2026-01-20T11:00:00Z' },
      { id: 'ISS-015', title: 'Cleartext HTTP traffic allowed in HealthKit sync', severity: 'Low', original_severity: 'Low', source_type: 'SAST', category: 'Mobile Security', app: 'HealthTracker-iOS', created: '2025-12-10T09:00:00Z' },
      // ShopEasy
      { id: 'ISS-007', title: 'Hardcoded API Key in Source Code', severity: 'High', original_severity: 'High', source_type: 'Secret Detection', category: 'Secret Detection', app: 'ShopEasy-iOS', created: '2026-02-01T13:00:00Z' },
      { id: 'ISS-009', title: 'Insecure App Transport Security Configuration', severity: 'Medium', original_severity: 'Medium', source_type: 'SAST', category: 'Mobile Security', app: 'ShopEasy-iOS', created: '2026-02-05T15:30:00Z' },
      { id: 'ISS-014', title: 'Outdated follow-redirects Dependency', severity: 'Low', original_severity: 'Low', source_type: 'SCA', category: 'Vulnerable Dependency', app: 'ShopEasy-iOS', created: '2026-01-30T08:00:00Z' },
    ],
  };
}

// ---------------------------------------------------------------------------
// Mock data — "after" snapshot (newer scan — some fixed, some new, some changed)
// ---------------------------------------------------------------------------
function getMockAfter() {
  return {
    schema_version: '1.0.0',
    scan: { timestamp: '2026-02-22T10:00:00Z', source: 'mock' },
    summary: { total_issues: 11, by_severity: { critical: 2, high: 3, medium: 3, low: 2, info: 1 } },
    apps: [
      { name: 'MyBankingApp-iOS', total_issues: 4, by_severity: { critical: 1, high: 1, medium: 1, low: 0, info: 1 }, risk_score: 27 },
      { name: 'HealthTracker-iOS', total_issues: 3, by_severity: { critical: 1, high: 1, medium: 1, low: 0, info: 0 }, risk_score: 17 },
      { name: 'ShopEasy-iOS', total_issues: 4, by_severity: { critical: 0, high: 1, medium: 1, low: 2, info: 0 }, risk_score: 10 },
    ],
    issues: [
      // MyBankingApp — ISS-002 (lodash) resolved, ISS-006 (OpenSSL) resolved, ISS-001 downgraded to High
      { id: 'ISS-001', title: 'Remote Code Execution in libxml2', severity: 'High', original_severity: 'Critical', source_type: 'SCA', category: 'Vulnerable Dependency', app: 'MyBankingApp-iOS', created: '2025-12-15T10:30:00Z' },
      { id: 'ISS-004', title: 'Missing Certificate Pinning', severity: 'High', original_severity: 'High', source_type: 'SAST', category: 'Mobile Security', app: 'MyBankingApp-iOS', created: '2026-01-10T09:15:00Z' },
      // ISS-004 severity unchanged but kept — not a change
      { id: 'ISS-012', title: 'Information Disclosure via Error Messages', severity: 'Info', original_severity: 'Medium', source_type: 'SAST', category: 'Code Vulnerability', app: 'MyBankingApp-iOS', created: '2026-02-08T14:00:00Z' },
      // New issue in banking app
      { id: 'ISS-016', title: 'Weak TLS 1.0 Still Enabled in URLSession', severity: 'Critical', original_severity: 'Critical', source_type: 'SAST', category: 'Mobile Security', app: 'MyBankingApp-iOS', created: '2026-02-20T08:00:00Z' },
      // HealthTracker — ISS-015 (cleartext) resolved, ISS-003 severity changed
      { id: 'ISS-003', title: 'Insecure Data Storage — Keychain Missing Accessibility', severity: 'High', original_severity: 'Critical', source_type: 'SAST', category: 'Mobile Security', app: 'HealthTracker-iOS', created: '2026-01-05T14:20:00Z' },
      { id: 'ISS-005', title: 'SQL Injection in SQLite Query Builder', severity: 'Critical', original_severity: 'Critical', source_type: 'SAST', category: 'Code Vulnerability', app: 'HealthTracker-iOS', created: '2026-01-18T16:45:00Z' },
      { id: 'ISS-011', title: 'ReDoS in Realm Query Parser', severity: 'Medium', original_severity: 'Medium', source_type: 'SCA', category: 'Vulnerable Dependency', app: 'HealthTracker-iOS', created: '2026-01-20T11:00:00Z' },
      // ShopEasy — ISS-009 kept, ISS-007 kept, ISS-014 kept, new issue
      { id: 'ISS-007', title: 'Hardcoded API Key in Source Code', severity: 'High', original_severity: 'High', source_type: 'Secret Detection', category: 'Secret Detection', app: 'ShopEasy-iOS', created: '2026-02-01T13:00:00Z' },
      { id: 'ISS-009', title: 'Insecure App Transport Security Configuration', severity: 'Medium', original_severity: 'Medium', source_type: 'SAST', category: 'Mobile Security', app: 'ShopEasy-iOS', created: '2026-02-05T15:30:00Z' },
      { id: 'ISS-014', title: 'Outdated follow-redirects Dependency', severity: 'Low', original_severity: 'Low', source_type: 'SCA', category: 'Vulnerable Dependency', app: 'ShopEasy-iOS', created: '2026-01-30T08:00:00Z' },
      { id: 'ISS-017', title: 'Insecure Biometric Auth Fallback', severity: 'Low', original_severity: 'Low', source_type: 'SAST', category: 'Mobile Security', app: 'ShopEasy-iOS', created: '2026-02-18T11:00:00Z' },
    ],
  };
}

// ---------------------------------------------------------------------------
// Data fetching — create a snapshot from the current API state
// ---------------------------------------------------------------------------
async function fetchCurrentSnapshot() {
  if (USE_MOCK) return getMockAfter();

  const { GET_APPLICATIONS } = await import('../queries/applications.js');
  const { GET_ISSUES } = await import('../queries/issues.js');

  // Fetch apps
  const appsData = await queryFn(GET_APPLICATIONS, {
    getApplicationsInput: { offset: 0, limit: 100 },
  });
  let apps = appsData.getApplications.applications || [];
  if (APP_FILTER) apps = apps.filter(a => a.appName.toLowerCase().includes(APP_FILTER.toLowerCase()));

  // Fetch all issues (paginated)
  const allIssues = [];
  let offset = 0;
  const pageSize = 200;
  while (true) {
    const data = await queryFn(GET_ISSUES, {
      isDemo: false,
      getIssuesInput: { offset, limit: pageSize, sort: { fields: ['Severity'], order: ['DESC'] } },
    });
    const page = data.getIssues.issues || [];
    allIssues.push(...page);
    if (page.length < pageSize || allIssues.length >= data.getIssues.totalFilteredIssues) break;
    offset += pageSize;
  }

  let filtered = allIssues;
  if (APP_FILTER) filtered = filtered.filter(i => i.app?.name?.toLowerCase().includes(APP_FILTER.toLowerCase()));

  // Build snapshot in CI export format
  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const issue of filtered) {
    const key = (issue.severity || 'info').toLowerCase();
    if (key in sevCounts) sevCounts[key]++;
  }

  const byApp = {};
  for (const issue of filtered) {
    const name = issue.app?.name || 'Unknown';
    if (!byApp[name]) byApp[name] = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
    const key = (issue.severity || 'info').toLowerCase();
    if (key in byApp[name]) byApp[name][key]++;
    byApp[name].total++;
  }

  return {
    schema_version: '1.0.0',
    scan: { timestamp: new Date().toISOString(), source: 'ox-security-api' },
    summary: { total_issues: filtered.length, by_severity: sevCounts },
    apps: Object.entries(byApp).map(([name, counts]) => ({
      name,
      total_issues: counts.total,
      by_severity: { critical: counts.critical, high: counts.high, medium: counts.medium, low: counts.low, info: counts.info },
      risk_score: computeRiskScore(counts),
    })),
    issues: filtered.map(i => ({
      id: i.issueId,
      title: i.mainTitle,
      description: i.secondTitle || '',
      severity: i.severity,
      original_severity: i.originalSeverity || i.severity,
      source_type: i.sourceType || 'Unknown',
      category: i.category?.name || 'Unknown',
      app: i.app?.name || 'Unknown',
      created: i.created || null,
    })),
  };
}

// ---------------------------------------------------------------------------
// Snapshot management
// ---------------------------------------------------------------------------
function saveSnapshot(name, data) {
  mkdirSync(SNAPSHOTS_DIR, { recursive: true });
  const filePath = resolve(SNAPSHOTS_DIR, `${name}.json`);
  writeFileSync(filePath, JSON.stringify(data, null, 2));
  return filePath;
}

function loadSnapshot(name) {
  // Check if it's a direct file path
  if (existsSync(name)) return JSON.parse(readFileSync(name, 'utf-8'));
  // Check snapshots directory
  const filePath = resolve(SNAPSHOTS_DIR, `${name}.json`);
  if (existsSync(filePath)) return JSON.parse(readFileSync(filePath, 'utf-8'));
  return null;
}

function listSnapshots() {
  if (!existsSync(SNAPSHOTS_DIR)) return [];
  return readdirSync(SNAPSHOTS_DIR)
    .filter(f => f.endsWith('.json'))
    .map(f => f.replace('.json', ''));
}

// ---------------------------------------------------------------------------
// Diff engine — compare two snapshots
// ---------------------------------------------------------------------------
function computeDiff(before, after) {
  const beforeMap = new Map(before.issues.map(i => [i.id, i]));
  const afterMap = new Map(after.issues.map(i => [i.id, i]));

  // New issues: in after but not in before
  const newIssues = after.issues
    .filter(i => !beforeMap.has(i.id))
    .sort((a, b) => sevCompare(a.severity, b.severity));

  // Resolved issues: in before but not in after
  const resolvedIssues = before.issues
    .filter(i => !afterMap.has(i.id))
    .sort((a, b) => sevCompare(a.severity, b.severity));

  // Severity changes: same issue ID, different severity
  const severityChanges = [];
  for (const [id, afterIssue] of afterMap) {
    const beforeIssue = beforeMap.get(id);
    if (beforeIssue && beforeIssue.severity !== afterIssue.severity) {
      severityChanges.push({
        id,
        title: afterIssue.title,
        app: afterIssue.app,
        before_severity: beforeIssue.severity,
        after_severity: afterIssue.severity,
        direction: sevCompare(afterIssue.severity, beforeIssue.severity) < 0 ? 'upgraded' : 'downgraded',
        source_type: afterIssue.source_type,
        category: afterIssue.category,
      });
    }
  }
  severityChanges.sort((a, b) => sevCompare(a.after_severity, b.after_severity));

  // Unchanged issues: same ID, same severity
  const unchangedIssues = after.issues.filter(i => {
    const b = beforeMap.get(i.id);
    return b && b.severity === i.severity;
  });

  // Severity distribution shift
  const sevShift = {};
  for (const sev of SEV_ORDER) {
    const key = sev.toLowerCase();
    const bCount = before.summary?.by_severity?.[key] || 0;
    const aCount = after.summary?.by_severity?.[key] || 0;
    sevShift[sev] = { before: bCount, after: aCount, delta: aCount - bCount };
  }

  // Per-app changes
  const allAppNames = new Set([
    ...(before.apps || []).map(a => a.name),
    ...(after.apps || []).map(a => a.name),
  ]);

  const appChanges = [];
  for (const name of allAppNames) {
    const bApp = (before.apps || []).find(a => a.name === name);
    const aApp = (after.apps || []).find(a => a.name === name);

    const bIssues = bApp?.total_issues || 0;
    const aIssues = aApp?.total_issues || 0;
    const bRisk = bApp?.risk_score || 0;
    const aRisk = aApp?.risk_score || 0;

    appChanges.push({
      name,
      before_issues: bIssues,
      after_issues: aIssues,
      issue_delta: aIssues - bIssues,
      before_risk: bRisk,
      after_risk: aRisk,
      risk_delta: aRisk - bRisk,
      new_count: newIssues.filter(i => i.app === name).length,
      resolved_count: resolvedIssues.filter(i => i.app === name).length,
      severity_changes: severityChanges.filter(i => i.app === name).length,
      status: aRisk < bRisk ? 'improved' : aRisk > bRisk ? 'worsened' : 'stable',
    });
  }
  appChanges.sort((a, b) => b.risk_delta - a.risk_delta);

  // Risk-weighted impact
  function weightedCount(issues) {
    return issues.reduce((s, i) => s + (SEV_WEIGHT[i.severity] || 0), 0);
  }
  const newRiskWeight = weightedCount(newIssues);
  const resolvedRiskWeight = weightedCount(resolvedIssues);
  const netRiskChange = newRiskWeight - resolvedRiskWeight;

  // Source type breakdown for new issues
  const newBySource = {};
  for (const i of newIssues) {
    newBySource[i.source_type] = (newBySource[i.source_type] || 0) + 1;
  }

  // Category breakdown for new issues
  const newByCategory = {};
  for (const i of newIssues) {
    newByCategory[i.category] = (newByCategory[i.category] || 0) + 1;
  }

  return {
    timestamps: {
      before: before.scan?.timestamp || 'unknown',
      after: after.scan?.timestamp || 'unknown',
    },
    summary: {
      before_total: before.summary?.total_issues || before.issues.length,
      after_total: after.summary?.total_issues || after.issues.length,
      total_delta: (after.summary?.total_issues || after.issues.length) - (before.summary?.total_issues || before.issues.length),
      new_issues: newIssues.length,
      resolved_issues: resolvedIssues.length,
      severity_changes: severityChanges.length,
      unchanged: unchangedIssues.length,
      net_risk_change: netRiskChange,
    },
    severity_shift: sevShift,
    new_issues: newIssues,
    resolved_issues: resolvedIssues,
    severity_changes: severityChanges,
    app_changes: appChanges,
    new_by_source: newBySource,
    new_by_category: newByCategory,
  };
}

// ---------------------------------------------------------------------------
// Markdown report generation
// ---------------------------------------------------------------------------
function generateReport(diff, before, after) {
  const lines = [];
  const ts = new Date().toISOString();
  const usedMock = before.scan?.source === 'mock' || after.scan?.source === 'mock';

  lines.push('# E19: Scan Diff Report');
  lines.push(`\n*Generated: ${ts}*`);
  if (usedMock) lines.push('\n> **Mock Mode** — using built-in sample data (no OX_API_KEY configured)');
  lines.push('');

  // Time range
  lines.push('## Scan Window');
  lines.push('');
  lines.push(`| | Timestamp |`);
  lines.push(`|---|---|`);
  lines.push(`| **Before** | ${diff.timestamps.before} |`);
  lines.push(`| **After** | ${diff.timestamps.after} |`);
  lines.push('');

  // Overview
  lines.push('## Overview');
  lines.push('');
  const s = diff.summary;
  const deltaSign = n => n > 0 ? `+${n}` : String(n);
  const riskDir = s.net_risk_change > 0 ? 'higher' : s.net_risk_change < 0 ? 'lower' : 'unchanged';
  lines.push(`| Metric | Count |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Issues before | ${s.before_total} |`);
  lines.push(`| Issues after | ${s.after_total} |`);
  lines.push(`| Net change | ${deltaSign(s.total_delta)} |`);
  lines.push(`| New issues | ${s.new_issues} |`);
  lines.push(`| Resolved issues | ${s.resolved_issues} |`);
  lines.push(`| Severity changes | ${s.severity_changes} |`);
  lines.push(`| Unchanged | ${s.unchanged} |`);
  lines.push(`| Net risk weight change | ${deltaSign(s.net_risk_change)} (${riskDir}) |`);
  lines.push('');

  // Severity shift
  lines.push('## Severity Distribution Shift');
  lines.push('');
  lines.push('| Severity | Before | After | Delta |');
  lines.push('|----------|--------|-------|-------|');
  for (const sev of SEV_ORDER) {
    const sh = diff.severity_shift[sev];
    if (sh.before === 0 && sh.after === 0) continue;
    const arrow = sh.delta > 0 ? ' ▲' : sh.delta < 0 ? ' ▼' : '';
    lines.push(`| ${sev} | ${sh.before} | ${sh.after} | ${deltaSign(sh.delta)}${arrow} |`);
  }
  lines.push('');

  // ASCII delta chart
  lines.push('```');
  for (const sev of SEV_ORDER) {
    const sh = diff.severity_shift[sev];
    if (sh.before === 0 && sh.after === 0) continue;
    const maxVal = Math.max(sh.before, sh.after, 1);
    const scale = 30 / maxVal;
    const bBar = '█'.repeat(Math.round(sh.before * scale));
    const aBar = '█'.repeat(Math.round(sh.after * scale));
    lines.push(`${sev.padEnd(9)} Before: ${bBar} ${sh.before}`);
    lines.push(`${' '.repeat(9)} After:  ${aBar} ${sh.after}`);
    lines.push('');
  }
  lines.push('```');
  lines.push('');

  // Per-app changes
  lines.push('## Per-App Changes');
  lines.push('');
  lines.push('| App | Issues (before→after) | Risk (before→after) | New | Resolved | Sev Changes | Status |');
  lines.push('|-----|----------------------|---------------------|-----|----------|-------------|--------|');
  for (const app of diff.app_changes) {
    const issueStr = `${app.before_issues} → ${app.after_issues} (${deltaSign(app.issue_delta)})`;
    const riskStr = `${app.before_risk} → ${app.after_risk} (${deltaSign(app.risk_delta)})`;
    const statusEmoji = app.status === 'improved' ? 'Improved' : app.status === 'worsened' ? 'Worsened' : 'Stable';
    lines.push(`| ${app.name} | ${issueStr} | ${riskStr} | ${app.new_count} | ${app.resolved_count} | ${app.severity_changes} | ${statusEmoji} |`);
  }
  lines.push('');

  // New issues
  if (diff.new_issues.length > 0) {
    lines.push('## New Issues');
    lines.push('');
    lines.push(`${diff.new_issues.length} new issue(s) appeared since the previous scan:`);
    lines.push('');
    lines.push('| # | Severity | Issue | App | Source | Category |');
    lines.push('|---|----------|-------|-----|--------|----------|');
    diff.new_issues.forEach((issue, idx) => {
      lines.push(`| ${idx + 1} | **${issue.severity}** | ${issue.title} | ${issue.app} | ${issue.source_type} | ${issue.category} |`);
    });
    lines.push('');

    // Breakdown
    if (Object.keys(diff.new_by_source).length > 0) {
      lines.push('**New issues by source type:**');
      for (const [src, count] of Object.entries(diff.new_by_source).sort((a, b) => b[1] - a[1])) {
        lines.push(`- ${src}: ${count}`);
      }
      lines.push('');
    }
    if (Object.keys(diff.new_by_category).length > 0) {
      lines.push('**New issues by category:**');
      for (const [cat, count] of Object.entries(diff.new_by_category).sort((a, b) => b[1] - a[1])) {
        lines.push(`- ${cat}: ${count}`);
      }
      lines.push('');
    }
  }

  // Resolved issues
  if (diff.resolved_issues.length > 0) {
    lines.push('## Resolved Issues');
    lines.push('');
    lines.push(`${diff.resolved_issues.length} issue(s) resolved since the previous scan:`);
    lines.push('');
    lines.push('| # | Severity | Issue | App | Source | Category |');
    lines.push('|---|----------|-------|-----|--------|----------|');
    diff.resolved_issues.forEach((issue, idx) => {
      lines.push(`| ${idx + 1} | ~~${issue.severity}~~ | ${issue.title} | ${issue.app} | ${issue.source_type} | ${issue.category} |`);
    });
    lines.push('');

    // Risk reduction summary
    const resolvedWeight = diff.resolved_issues.reduce((s, i) => s + (SEV_WEIGHT[i.severity] || 0), 0);
    lines.push(`**Risk weight removed:** ${resolvedWeight} points`);
    lines.push('');
  }

  // Severity changes
  if (diff.severity_changes.length > 0) {
    lines.push('## Severity Changes');
    lines.push('');
    lines.push(`${diff.severity_changes.length} issue(s) had their severity re-assessed:`);
    lines.push('');
    lines.push('| # | Direction | Issue | Before | After | App |');
    lines.push('|---|-----------|-------|--------|-------|-----|');
    diff.severity_changes.forEach((change, idx) => {
      const arrow = change.direction === 'upgraded' ? '▲ Upgraded' : '▼ Downgraded';
      lines.push(`| ${idx + 1} | ${arrow} | ${change.title} | ${change.before_severity} | ${change.after_severity} | ${change.app} |`);
    });
    lines.push('');

    const upgraded = diff.severity_changes.filter(c => c.direction === 'upgraded');
    const downgraded = diff.severity_changes.filter(c => c.direction === 'downgraded');
    if (upgraded.length > 0) lines.push(`- **Upgraded:** ${upgraded.length} issue(s) — increased severity requires attention`);
    if (downgraded.length > 0) lines.push(`- **Downgraded:** ${downgraded.length} issue(s) — reduced severity frees triage effort`);
    lines.push('');
  }

  // Insights & recommendations
  lines.push('## Insights & Recommendations');
  lines.push('');
  const recs = [];

  if (s.new_issues > s.resolved_issues) {
    recs.push(`Issue backlog is **growing** (${s.new_issues} new vs ${s.resolved_issues} resolved). Increase remediation velocity to prevent accumulation.`);
  } else if (s.resolved_issues > s.new_issues) {
    recs.push(`Issue backlog is **shrinking** (${s.resolved_issues} resolved vs ${s.new_issues} new). Good progress on remediation.`);
  } else if (s.new_issues === 0 && s.resolved_issues === 0) {
    recs.push('No issue churn detected between scans. Verify scans are running on updated code.');
  }

  const newCritical = diff.new_issues.filter(i => i.severity === 'Critical');
  if (newCritical.length > 0) {
    recs.push(`**${newCritical.length} new Critical issue(s)** introduced — investigate immediately: ${newCritical.map(i => i.title).join(', ')}`);
  }

  const upgradedIssues = diff.severity_changes.filter(c => c.direction === 'upgraded');
  if (upgradedIssues.length > 0) {
    recs.push(`${upgradedIssues.length} issue(s) upgraded to higher severity — re-prioritize these in the current sprint.`);
  }

  const worsenedApps = diff.app_changes.filter(a => a.status === 'worsened');
  if (worsenedApps.length > 0) {
    recs.push(`Apps with worsened posture: **${worsenedApps.map(a => a.name).join(', ')}** — focus remediation efforts here.`);
  }

  const improvedApps = diff.app_changes.filter(a => a.status === 'improved');
  if (improvedApps.length > 0) {
    recs.push(`Apps with improved posture: **${improvedApps.map(a => a.name).join(', ')}** — maintain the momentum.`);
  }

  if (recs.length === 0) recs.push('No significant changes detected between scans.');

  recs.forEach((r, i) => lines.push(`${i + 1}. ${r}`));
  lines.push('');

  // Usage section
  lines.push('## Usage');
  lines.push('');
  lines.push('```bash');
  lines.push('# Save a named snapshot of the current scan state');
  lines.push('node scripts/diff-report.js snapshot baseline');
  lines.push('');
  lines.push('# ... time passes, fixes are applied, new scans run ...');
  lines.push('');
  lines.push('# Save another snapshot');
  lines.push('node scripts/diff-report.js snapshot after-sprint-23');
  lines.push('');
  lines.push('# Compare the two snapshots');
  lines.push('node scripts/diff-report.js diff baseline after-sprint-23');
  lines.push('');
  lines.push('# Compare arbitrary JSON files (CI export format)');
  lines.push('OX_BEFORE=report-v1.json OX_AFTER=report-v2.json node scripts/diff-report.js');
  lines.push('');
  lines.push('# Run demo with built-in mock data');
  lines.push('node scripts/diff-report.js');
  lines.push('```');
  lines.push('');

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  const args = process.argv.slice(2);
  const command = args[0] || '';
  const timestamp = new Date().toISOString();

  console.log('E19: Diff Report — Scan Comparison Tool');
  console.log('='.repeat(50));

  // ----- Snapshot mode -----
  if (command === 'snapshot') {
    const name = args[1];
    if (!name) {
      console.error('Usage: node scripts/diff-report.js snapshot <name>');
      console.error('Example: node scripts/diff-report.js snapshot baseline');
      process.exit(1);
    }

    console.log(`\nSaving snapshot "${name}"...`);
    if (USE_MOCK) console.log('  (No API key — using mock data)');

    const data = await fetchCurrentSnapshot();
    const filePath = saveSnapshot(name, data);
    console.log(`  Saved ${data.issues.length} issues across ${data.apps.length} apps`);
    console.log(`  File: ${filePath}`);
    console.log('\nDone. Use "diff" command later to compare snapshots.');

    const existing = listSnapshots();
    if (existing.length > 1) {
      console.log(`\nAvailable snapshots: ${existing.join(', ')}`);
    }
    return;
  }

  // ----- List snapshots -----
  if (command === 'list') {
    const snapshots = listSnapshots();
    if (snapshots.length === 0) {
      console.log('\nNo snapshots found. Create one with:');
      console.log('  node scripts/diff-report.js snapshot <name>');
    } else {
      console.log(`\nAvailable snapshots (${snapshots.length}):`);
      for (const name of snapshots) {
        const data = loadSnapshot(name);
        const ts = data?.scan?.timestamp || 'unknown';
        const count = data?.issues?.length || 0;
        console.log(`  - ${name} (${count} issues, ${ts})`);
      }
    }
    return;
  }

  // ----- Diff mode -----
  let before, after;

  if (command === 'diff') {
    const beforeName = args[1];
    const afterName = args[2];
    if (!beforeName || !afterName) {
      console.error('Usage: node scripts/diff-report.js diff <before> <after>');
      console.error('Example: node scripts/diff-report.js diff baseline after-fix');
      console.error('\nAvailable snapshots:', listSnapshots().join(', ') || '(none)');
      process.exit(1);
    }

    before = loadSnapshot(beforeName);
    if (!before) { console.error(`Snapshot "${beforeName}" not found.`); process.exit(1); }
    after = loadSnapshot(afterName);
    if (!after) { console.error(`Snapshot "${afterName}" not found.`); process.exit(1); }

    console.log(`\nComparing: "${beforeName}" vs "${afterName}"`);
  } else if (process.env.OX_BEFORE && process.env.OX_AFTER) {
    // File-based diff
    const beforePath = resolve(process.cwd(), process.env.OX_BEFORE);
    const afterPath = resolve(process.cwd(), process.env.OX_AFTER);

    if (!existsSync(beforePath)) { console.error(`Before file not found: ${beforePath}`); process.exit(1); }
    if (!existsSync(afterPath)) { console.error(`After file not found: ${afterPath}`); process.exit(1); }

    before = JSON.parse(readFileSync(beforePath, 'utf-8'));
    after = JSON.parse(readFileSync(afterPath, 'utf-8'));

    console.log(`\nComparing files:`);
    console.log(`  Before: ${process.env.OX_BEFORE}`);
    console.log(`  After:  ${process.env.OX_AFTER}`);
  } else {
    // Demo mode with mock data
    console.log('\n  Running in demo mode with built-in mock data');
    console.log('  (Use "snapshot" command to save real scans, or set OX_BEFORE / OX_AFTER)');
    before = getMockBefore();
    after = getMockAfter();
  }

  console.log(`  Before: ${before.issues.length} issues (${before.scan?.timestamp || 'unknown'})`);
  console.log(`  After:  ${after.issues.length} issues (${after.scan?.timestamp || 'unknown'})`);
  console.log('');

  // Compute diff
  const diff = computeDiff(before, after);

  // Print summary to stdout
  console.log('--- Diff Summary ---');
  console.log(`  Total issues: ${diff.summary.before_total} → ${diff.summary.after_total} (${diff.summary.total_delta >= 0 ? '+' : ''}${diff.summary.total_delta})`);
  console.log(`  New issues:      ${diff.summary.new_issues}`);
  console.log(`  Resolved issues: ${diff.summary.resolved_issues}`);
  console.log(`  Severity changes: ${diff.summary.severity_changes}`);
  console.log(`  Unchanged:       ${diff.summary.unchanged}`);
  console.log(`  Net risk change: ${diff.summary.net_risk_change >= 0 ? '+' : ''}${diff.summary.net_risk_change} (severity-weighted)`);
  console.log('');

  // Severity shift
  console.log('--- Severity Shift ---');
  for (const sev of SEV_ORDER) {
    const sh = diff.severity_shift[sev];
    if (sh.before === 0 && sh.after === 0) continue;
    const arrow = sh.delta > 0 ? '▲' : sh.delta < 0 ? '▼' : '=';
    console.log(`  ${sev.padEnd(9)}: ${sh.before} → ${sh.after} (${sh.delta >= 0 ? '+' : ''}${sh.delta}) ${arrow}`);
  }
  console.log('');

  // New issues
  if (diff.new_issues.length > 0) {
    console.log('--- New Issues ---');
    for (const issue of diff.new_issues) {
      console.log(`  [${issue.severity.toUpperCase()}] ${issue.title} (${issue.app})`);
    }
    console.log('');
  }

  // Resolved issues
  if (diff.resolved_issues.length > 0) {
    console.log('--- Resolved Issues ---');
    for (const issue of diff.resolved_issues) {
      console.log(`  [RESOLVED] ${issue.title} (${issue.app}) — was ${issue.severity}`);
    }
    console.log('');
  }

  // Severity changes
  if (diff.severity_changes.length > 0) {
    console.log('--- Severity Changes ---');
    for (const change of diff.severity_changes) {
      const arrow = change.direction === 'upgraded' ? '▲' : '▼';
      console.log(`  ${arrow} ${change.title}: ${change.before_severity} → ${change.after_severity} (${change.app})`);
    }
    console.log('');
  }

  // Per-app summary
  console.log('--- Per-App Summary ---');
  for (const app of diff.app_changes) {
    const riskDir = app.risk_delta > 0 ? '▲ worse' : app.risk_delta < 0 ? '▼ better' : '= stable';
    console.log(`  ${app.name}: risk ${app.before_risk} → ${app.after_risk} (${riskDir}), issues ${app.before_issues} → ${app.after_issues}`);
  }
  console.log('');

  // Save outputs
  const dateStr = timestamp.slice(0, 10);
  const outDir = resolve(process.cwd(), 'experiments', `diff-report-${dateStr}`);
  mkdirSync(outDir, { recursive: true });

  const report = generateReport(diff, before, after);
  writeFileSync(resolve(outDir, 'diff-report.md'), report);

  const diffJson = {
    generated: timestamp,
    source: before.scan?.source === 'mock' ? 'mock' : 'ox-security-api',
    ...diff,
  };
  writeFileSync(resolve(outDir, 'diff-data.json'), JSON.stringify(diffJson, null, 2));

  console.log(`Output saved to ${outDir}/`);
  console.log('  - diff-report.md   (human-readable)');
  console.log('  - diff-data.json   (machine-readable)');
}

main().catch(e => {
  console.error(`\nFatal: ${e.message}`);
  process.exit(1);
});
