#!/usr/bin/env node
/**
 * E16: Severity Drift Report
 *
 * Compares original (scanner-reported) severity vs Ox-prioritized severity
 * for every issue. Highlights where Ox upgraded or downgraded severity and
 * surfaces the reasons behind each re-prioritization.
 *
 * Key analyses:
 *   - Drift classification: upgraded, downgraded, unchanged
 *   - Drift magnitude: how many severity levels each issue shifted
 *   - Drift matrix: original severity → Ox severity cross-tabulation
 *   - Reason analysis: why Ox changed severity (reachability, exploitability, etc.)
 *   - Per-app and per-category drift patterns
 *   - Aggregate prioritization comparison (original vs Ox totals)
 *   - Confidence impact: which downgrades save the most triage effort
 *
 * Falls back to realistic mock data when OX_API_KEY is not configured.
 *
 * Usage:
 *   node scripts/severity-drift.js [appFilter]
 *
 * Environment:
 *   OX_APP_NAME    — filter to matching app name
 *   OX_LIMIT       — max issues to fetch (default: 200)
 *   OX_CONCURRENCY — parallel detail fetches (default: 5)
 */
import { writeFileSync, mkdirSync, readFileSync, existsSync } from 'fs';
import { resolve } from 'path';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const SEV_ICON = { Critical: '🔴', High: '🟠', Medium: '🟡', Low: '🔵', Info: '⚪' };
const SEV_LEVELS = ['Critical', 'High', 'Medium', 'Low', 'Info'];
const SEV_RANK = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };
const SEV_WEIGHT = { Critical: 10, High: 5, Medium: 2, Low: 0.5, Info: 0 };

const DRIFT_ICON = { upgraded: '⬆️', downgraded: '⬇️', unchanged: '➡️' };

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

let queryFn;
if (!USE_MOCK) {
  const client = await import('../lib/ox-client.js');
  queryFn = client.query;
}

// ---------------------------------------------------------------------------
// Mock data — realistic iOS issues with varied severity drift patterns
// ---------------------------------------------------------------------------
function getMockIssues() {
  return [
    // DOWNGRADED: Critical → High (reachability analysis shows not directly exploitable)
    {
      issueId: 'ISS-001', mainTitle: 'Remote Code Execution in libxml2',
      secondTitle: 'CVE-2024-40896 affects libxml2 < 2.12.5 used via CocoaPods',
      severity: 'High', originalSeverity: 'Critical', sourceType: 'SCA',
      created: '2025-12-15T10:30:00Z',
      app: { id: 'app-1', name: 'MyBankingApp-iOS' },
      category: { name: 'Vulnerable Dependency' },
    },
    // UNCHANGED: Critical stays Critical
    {
      issueId: 'ISS-002', mainTitle: 'Prototype Pollution in lodash',
      secondTitle: 'lodash < 4.17.21 allows prototype pollution',
      severity: 'Critical', originalSeverity: 'Critical', sourceType: 'SCA',
      created: '2025-11-20T08:00:00Z',
      app: { id: 'app-1', name: 'MyBankingApp-iOS' },
      category: { name: 'Vulnerable Dependency' },
    },
    // DOWNGRADED: Critical → High (limited attack surface on mobile)
    {
      issueId: 'ISS-003', mainTitle: 'Insecure Data Storage — Keychain Missing Accessibility',
      secondTitle: 'Sensitive credentials stored without kSecAttrAccessibleWhenUnlockedThisDeviceOnly',
      severity: 'High', originalSeverity: 'Critical', sourceType: 'SAST',
      created: '2026-01-05T14:20:00Z',
      app: { id: 'app-2', name: 'HealthTracker-iOS' },
      category: { name: 'Mobile Security' },
    },
    // UNCHANGED: High stays High
    {
      issueId: 'ISS-004', mainTitle: 'Missing Certificate Pinning',
      secondTitle: 'App does not implement SSL/TLS certificate pinning',
      severity: 'High', originalSeverity: 'High', sourceType: 'SAST',
      created: '2026-01-10T09:15:00Z',
      app: { id: 'app-1', name: 'MyBankingApp-iOS' },
      category: { name: 'Mobile Security' },
    },
    // UNCHANGED: Critical stays Critical
    {
      issueId: 'ISS-005', mainTitle: 'SQL Injection in SQLite Query Builder',
      secondTitle: 'User input concatenated directly into SQLite query',
      severity: 'Critical', originalSeverity: 'Critical', sourceType: 'SAST',
      created: '2026-01-18T16:45:00Z',
      app: { id: 'app-2', name: 'HealthTracker-iOS' },
      category: { name: 'Code Vulnerability' },
    },
    // DOWNGRADED: Critical → High (not directly reachable via user input)
    {
      issueId: 'ISS-006', mainTitle: 'Vulnerable OpenSSL in Alamofire',
      secondTitle: 'Alamofire 5.6.x bundles OpenSSL with known CVEs',
      severity: 'High', originalSeverity: 'Critical', sourceType: 'SCA',
      created: '2025-10-22T11:30:00Z',
      app: { id: 'app-1', name: 'MyBankingApp-iOS' },
      category: { name: 'Vulnerable Dependency' },
    },
    // UNCHANGED: High stays High
    {
      issueId: 'ISS-007', mainTitle: 'Hardcoded API Key in Source Code',
      secondTitle: 'Firebase API key found in GoogleService-Info.plist',
      severity: 'High', originalSeverity: 'High', sourceType: 'Secret Detection',
      created: '2026-02-01T13:00:00Z',
      app: { id: 'app-3', name: 'ShopEasy-iOS' },
      category: { name: 'Secret Detection' },
    },
    // DOWNGRADED: High → Medium (no known exploit in the wild)
    {
      issueId: 'ISS-008', mainTitle: 'Denial of Service in libexpat',
      secondTitle: 'CVE-2024-50602 — libexpat before 2.6.4 allows DoS',
      severity: 'Medium', originalSeverity: 'High', sourceType: 'SCA',
      created: '2026-01-25T10:00:00Z',
      app: { id: 'app-2', name: 'HealthTracker-iOS' },
      category: { name: 'Vulnerable Dependency' },
    },
    // UPGRADED: Medium → High (exposed to untrusted network)
    {
      issueId: 'ISS-009', mainTitle: 'Insecure App Transport Security Configuration',
      secondTitle: 'NSAllowsArbitraryLoads set to YES in Info.plist',
      severity: 'High', originalSeverity: 'Medium', sourceType: 'SAST',
      created: '2026-02-05T15:30:00Z',
      app: { id: 'app-3', name: 'ShopEasy-iOS' },
      category: { name: 'Mobile Security' },
    },
    // UPGRADED: High → Critical (public-facing app with sensitive data)
    {
      issueId: 'ISS-010', mainTitle: 'Outdated React Native with Known Vulnerabilities',
      secondTitle: 'react-native 0.71.x has multiple known CVEs in Hermes engine',
      severity: 'Critical', originalSeverity: 'High', sourceType: 'SCA',
      created: '2026-02-10T09:00:00Z',
      app: { id: 'app-3', name: 'ShopEasy-iOS' },
      category: { name: 'Vulnerable Dependency' },
    },
    // UNCHANGED: Medium stays Medium
    {
      issueId: 'ISS-011', mainTitle: 'ReDoS in Realm Query Parser',
      secondTitle: 'Realm < 10.45.0 regex parser vulnerable to ReDoS',
      severity: 'Medium', originalSeverity: 'Medium', sourceType: 'SCA',
      created: '2026-01-20T11:00:00Z',
      app: { id: 'app-2', name: 'HealthTracker-iOS' },
      category: { name: 'Vulnerable Dependency' },
    },
    // DOWNGRADED: Medium → Low (info disclosure limited to debug builds)
    {
      issueId: 'ISS-012', mainTitle: 'Information Disclosure via Error Messages',
      secondTitle: 'Detailed stack traces returned in API error responses',
      severity: 'Low', originalSeverity: 'Medium', sourceType: 'SAST',
      created: '2026-02-08T14:00:00Z',
      app: { id: 'app-1', name: 'MyBankingApp-iOS' },
      category: { name: 'Code Vulnerability' },
    },
    // UNCHANGED: High stays High
    {
      issueId: 'ISS-013', mainTitle: 'Buffer Overflow in hermes-engine',
      secondTitle: 'hermes-engine 0.71.x has heap buffer overflow in regex JIT',
      severity: 'High', originalSeverity: 'High', sourceType: 'SCA',
      created: '2026-02-12T09:30:00Z',
      app: { id: 'app-3', name: 'ShopEasy-iOS' },
      category: { name: 'Vulnerable Dependency' },
    },
    // UNCHANGED: Low stays Low
    {
      issueId: 'ISS-014', mainTitle: 'Outdated follow-redirects Dependency',
      secondTitle: 'follow-redirects < 1.15.6 has minor info leak',
      severity: 'Low', originalSeverity: 'Low', sourceType: 'SCA',
      created: '2026-01-30T08:00:00Z',
      app: { id: 'app-3', name: 'ShopEasy-iOS' },
      category: { name: 'Vulnerable Dependency' },
    },
    // UPGRADED: Low → Medium (used in auth flow)
    {
      issueId: 'ISS-015', mainTitle: 'Weak Random Number Generator in SecureRandom',
      secondTitle: 'Math.random() used for token generation instead of crypto',
      severity: 'Medium', originalSeverity: 'Low', sourceType: 'SAST',
      created: '2026-02-14T10:00:00Z',
      app: { id: 'app-1', name: 'MyBankingApp-iOS' },
      category: { name: 'Code Vulnerability' },
    },
    // DOWNGRADED: High → Medium (not reachable from external input)
    {
      issueId: 'ISS-016', mainTitle: 'Path Traversal in File Handler',
      secondTitle: 'File path constructed from user input without sanitization',
      severity: 'Medium', originalSeverity: 'High', sourceType: 'SAST',
      created: '2026-02-16T11:00:00Z',
      app: { id: 'app-2', name: 'HealthTracker-iOS' },
      category: { name: 'Code Vulnerability' },
    },
  ];
}

function getMockIssueDetail(issueId) {
  // Severity change reasons for drifted issues
  const reasons = {
    'ISS-001': {
      severityChangedReason: [
        { reason: 'The vulnerable function is not directly reachable from user-controlled input based on code analysis', shortName: 'Not Reachable', changeCategory: 'Reachability' },
        { reason: 'No known exploit in the wild for this specific version combination', shortName: 'No Known Exploit', changeCategory: 'Exploitability' },
      ],
    },
    'ISS-003': {
      severityChangedReason: [
        { reason: 'Physical device access required to exploit keychain misconfiguration', shortName: 'Physical Access Required', changeCategory: 'Attack Vector' },
      ],
    },
    'ISS-006': {
      severityChangedReason: [
        { reason: 'OpenSSL vulnerability requires specific TLS handshake conditions not typical in mobile apps', shortName: 'Limited Attack Surface', changeCategory: 'Reachability' },
        { reason: 'Alamofire usage pattern does not expose vulnerable code path', shortName: 'Code Path Not Exercised', changeCategory: 'Reachability' },
      ],
    },
    'ISS-008': {
      severityChangedReason: [
        { reason: 'DoS impact is limited to app crash (self-recovering) rather than service disruption', shortName: 'Limited DoS Impact', changeCategory: 'Impact' },
        { reason: 'No proof of concept exploit available', shortName: 'No PoC', changeCategory: 'Exploitability' },
      ],
    },
    'ISS-009': {
      severityChangedReason: [
        { reason: 'App handles payment data over HTTP connections due to ATS bypass, increasing real-world risk', shortName: 'Sensitive Data Exposure', changeCategory: 'Business Context' },
        { reason: 'App is deployed to production with active users', shortName: 'Production Deployment', changeCategory: 'Environment' },
      ],
    },
    'ISS-010': {
      severityChangedReason: [
        { reason: 'Public-facing e-commerce app processing financial transactions', shortName: 'Business Critical App', changeCategory: 'Business Context' },
        { reason: 'Multiple CVEs with known exploits targeting Hermes engine', shortName: 'Active Exploits', changeCategory: 'Exploitability' },
        { reason: 'Vulnerability is reachable via JavaScript execution in React Native runtime', shortName: 'Directly Reachable', changeCategory: 'Reachability' },
      ],
    },
    'ISS-012': {
      severityChangedReason: [
        { reason: 'Stack traces only present in debug builds, not in production release configuration', shortName: 'Debug Only', changeCategory: 'Environment' },
      ],
    },
    'ISS-015': {
      severityChangedReason: [
        { reason: 'Weak RNG used in authentication token generation — predictable tokens enable session hijacking', shortName: 'Auth Token Risk', changeCategory: 'Business Context' },
      ],
    },
    'ISS-016': {
      severityChangedReason: [
        { reason: 'Path traversal input comes from local app storage, not external user input', shortName: 'Internal Input Only', changeCategory: 'Reachability' },
      ],
    },
  };

  const issues = getMockIssues();
  const issue = issues.find(i => i.issueId === issueId);
  if (!issue) return null;

  return {
    ...issue,
    ...(reasons[issueId] || { severityChangedReason: [] }),
  };
}

function getMockPrioritization() {
  return {
    original:      { critical: 5, high: 5, medium: 3, low: 2, info: 1 },
    oxPrioritized: { critical: 3, high: 6, medium: 4, low: 2, info: 1 },
    aggregated:    { critical: 3, high: 6, medium: 4, low: 2, info: 1 },
  };
}

// ---------------------------------------------------------------------------
// Drift classification
// ---------------------------------------------------------------------------

/**
 * Compute drift direction and magnitude between two severity levels.
 * Returns { direction, magnitude, fromRank, toRank }
 *   direction: 'upgraded' | 'downgraded' | 'unchanged'
 *   magnitude: number of severity levels shifted (0, 1, 2, 3, 4)
 */
function classifyDrift(originalSev, oxSev) {
  const fromRank = SEV_RANK[originalSev] ?? 0;
  const toRank = SEV_RANK[oxSev] ?? 0;
  const diff = toRank - fromRank;

  if (diff > 0) return { direction: 'upgraded', magnitude: diff, fromRank, toRank };
  if (diff < 0) return { direction: 'downgraded', magnitude: Math.abs(diff), fromRank, toRank };
  return { direction: 'unchanged', magnitude: 0, fromRank, toRank };
}

/**
 * Compute the triage effort saved by a downgrade.
 * Higher original severity = more effort saved when downgraded.
 */
function triageEffortSaved(originalSev, oxSev) {
  const origWeight = SEV_WEIGHT[originalSev] || 0;
  const oxWeight = SEV_WEIGHT[oxSev] || 0;
  return Math.max(0, origWeight - oxWeight);
}

// ---------------------------------------------------------------------------
// API fetching
// ---------------------------------------------------------------------------
async function fetchIssues(limit, appFilter) {
  if (USE_MOCK) return getMockIssues();

  const { GET_ISSUES } = await import('../queries/issues.js');
  const data = await queryFn(GET_ISSUES, {
    isDemo: false,
    getIssuesInput: {
      offset: 0, limit,
      sort: { fields: ['Severity'], order: ['DESC'] },
    },
  });
  return data.getIssues.issues;
}

async function fetchPrioritization() {
  if (USE_MOCK) return getMockPrioritization();

  const { GET_ISSUE_PRIORITIZATION } = await import('../queries/issues.js');
  const data = await queryFn(GET_ISSUE_PRIORITIZATION, { getIssuesInput: {} });
  return data.getIssuePrioritization;
}

async function fetchIssueDetail(issueId) {
  if (USE_MOCK) return getMockIssueDetail(issueId);

  try {
    const { GET_SINGLE_ISSUE } = await import('../queries/issues.js');
    const data = await queryFn(GET_SINGLE_ISSUE, { getSingleIssueInput: { issueId } });
    return data.getSingleIssueInfo;
  } catch {
    try {
      await new Promise(r => setTimeout(r, 1000));
      const { GET_SINGLE_ISSUE } = await import('../queries/issues.js');
      const data = await queryFn(GET_SINGLE_ISSUE, { getSingleIssueInput: { issueId } });
      return data.getSingleIssueInfo;
    } catch {
      return null;
    }
  }
}

async function fetchDetailsForDrifted(driftedIssues, concurrency) {
  const results = [];
  for (let i = 0; i < driftedIssues.length; i += concurrency) {
    const batch = driftedIssues.slice(i, i + concurrency);
    const batchResults = await Promise.all(batch.map(iss => fetchIssueDetail(iss.issueId)));
    results.push(...batchResults);
    const done = Math.min(i + concurrency, driftedIssues.length);
    process.stdout.write(`\r  Enriched ${done}/${driftedIssues.length} drifted issues...`);
  }
  console.log('');
  return results;
}

// ---------------------------------------------------------------------------
// Analysis pipeline
// ---------------------------------------------------------------------------
function analyzeIssues(issues) {
  const analyzed = [];

  for (const issue of issues) {
    const orig = issue.originalSeverity || issue.severity;
    const ox = issue.severity;
    const drift = classifyDrift(orig, ox);
    const effortSaved = triageEffortSaved(orig, ox);

    analyzed.push({
      issueId: issue.issueId,
      mainTitle: issue.mainTitle,
      secondTitle: issue.secondTitle,
      originalSeverity: orig,
      oxSeverity: ox,
      sourceType: issue.sourceType,
      created: issue.created,
      app: issue.app,
      category: issue.category?.name,
      driftDirection: drift.direction,
      driftMagnitude: drift.magnitude,
      effortSaved,
      // Will be enriched later for drifted issues
      reasons: [],
    });
  }

  return analyzed;
}

function enrichWithReasons(analyzed, details) {
  const detailMap = new Map();
  for (const d of details) {
    if (d) detailMap.set(d.issueId, d);
  }

  for (const item of analyzed) {
    const detail = detailMap.get(item.issueId);
    if (detail && detail.severityChangedReason) {
      item.reasons = (Array.isArray(detail.severityChangedReason)
        ? detail.severityChangedReason
        : [detail.severityChangedReason]
      ).filter(r => r && r.reason);
    }
  }
}

function computeStats(analyzed, prioritization) {
  const total = analyzed.length;
  const upgraded = analyzed.filter(a => a.driftDirection === 'upgraded');
  const downgraded = analyzed.filter(a => a.driftDirection === 'downgraded');
  const unchanged = analyzed.filter(a => a.driftDirection === 'unchanged');

  // Drift matrix: original → ox
  const matrix = {};
  for (const sev of SEV_LEVELS) {
    matrix[sev] = {};
    for (const sev2 of SEV_LEVELS) matrix[sev][sev2] = 0;
  }
  for (const a of analyzed) {
    if (matrix[a.originalSeverity]) {
      matrix[a.originalSeverity][a.oxSeverity] = (matrix[a.originalSeverity][a.oxSeverity] || 0) + 1;
    }
  }

  // Per-app drift
  const byApp = {};
  for (const a of analyzed) {
    const appName = a.app?.name || 'Unknown';
    if (!byApp[appName]) byApp[appName] = { total: 0, upgraded: 0, downgraded: 0, unchanged: 0, totalEffortSaved: 0 };
    byApp[appName].total++;
    byApp[appName][a.driftDirection]++;
    byApp[appName].totalEffortSaved += a.effortSaved;
  }

  // Per-category drift
  const byCategory = {};
  for (const a of analyzed) {
    const cat = a.category || 'Unknown';
    if (!byCategory[cat]) byCategory[cat] = { total: 0, upgraded: 0, downgraded: 0, unchanged: 0 };
    byCategory[cat].total++;
    byCategory[cat][a.driftDirection]++;
  }

  // Per-sourceType drift
  const bySourceType = {};
  for (const a of analyzed) {
    const st = a.sourceType || 'Unknown';
    if (!bySourceType[st]) bySourceType[st] = { total: 0, upgraded: 0, downgraded: 0, unchanged: 0 };
    bySourceType[st].total++;
    bySourceType[st][a.driftDirection]++;
  }

  // Reason category aggregation
  const reasonCategories = {};
  for (const a of analyzed) {
    for (const r of a.reasons) {
      const cat = r.changeCategory || 'Other';
      if (!reasonCategories[cat]) reasonCategories[cat] = { count: 0, upgrades: 0, downgrades: 0, reasons: new Set() };
      reasonCategories[cat].count++;
      if (a.driftDirection === 'upgraded') reasonCategories[cat].upgrades++;
      if (a.driftDirection === 'downgraded') reasonCategories[cat].downgrades++;
      reasonCategories[cat].reasons.add(r.shortName || r.reason.slice(0, 50));
    }
  }
  // Convert sets to arrays for serialization
  for (const cat of Object.keys(reasonCategories)) {
    reasonCategories[cat].reasons = [...reasonCategories[cat].reasons];
  }

  // Total triage effort saved
  const totalEffortSaved = downgraded.reduce((s, a) => s + a.effortSaved, 0);
  const totalEffortAdded = upgraded.reduce((s, a) => s + triageEffortSaved(a.oxSeverity, a.originalSeverity), 0);

  // Drift magnitude distribution
  const magnitudeDistribution = { 0: 0, 1: 0, 2: 0, 3: 0, 4: 0 };
  for (const a of analyzed) magnitudeDistribution[a.driftMagnitude]++;

  return {
    total,
    upgradedCount: upgraded.length,
    downgradedCount: downgraded.length,
    unchangedCount: unchanged.length,
    upgradedPct: total > 0 ? Math.round((upgraded.length / total) * 100) : 0,
    downgradedPct: total > 0 ? Math.round((downgraded.length / total) * 100) : 0,
    unchangedPct: total > 0 ? Math.round((unchanged.length / total) * 100) : 0,
    driftRate: total > 0 ? Math.round(((upgraded.length + downgraded.length) / total) * 100) : 0,
    matrix,
    byApp,
    byCategory,
    bySourceType,
    reasonCategories,
    totalEffortSaved,
    totalEffortAdded,
    magnitudeDistribution,
    prioritization,
    upgraded,
    downgraded,
    unchanged,
  };
}

// ---------------------------------------------------------------------------
// Console output
// ---------------------------------------------------------------------------
function renderConsole(analyzed, stats) {
  const lines = [];

  lines.push('');
  lines.push('='.repeat(70));
  lines.push('  E16: Severity Drift Report');
  lines.push('  Ox Security — Original vs Prioritized Severity Analysis');
  lines.push('='.repeat(70));
  if (USE_MOCK) lines.push('\n[Mock Mode — using realistic sample data]');
  lines.push('');

  // Overview
  lines.push('Overview');
  lines.push('-'.repeat(50));
  lines.push(`  Total issues analyzed:  ${stats.total}`);
  lines.push(`  Drift rate:             ${stats.driftRate}% of issues re-prioritized`);
  lines.push(`  ⬆️  Upgraded:            ${stats.upgradedCount} (${stats.upgradedPct}%)`);
  lines.push(`  ⬇️  Downgraded:          ${stats.downgradedCount} (${stats.downgradedPct}%)`);
  lines.push(`  ➡️  Unchanged:           ${stats.unchangedCount} (${stats.unchangedPct}%)`);
  lines.push('');

  // Drift magnitude
  lines.push('Drift Magnitude Distribution');
  lines.push('-'.repeat(50));
  for (let mag = 0; mag <= 4; mag++) {
    const count = stats.magnitudeDistribution[mag];
    const pct = stats.total > 0 ? Math.round((count / stats.total) * 100) : 0;
    const barLen = Math.min(30, Math.max(0, Math.round(pct * 0.6)));
    const bar = '\u2588'.repeat(barLen) + '\u2591'.repeat(30 - barLen);
    const label = mag === 0 ? 'No change     ' : `${mag} level shift${mag > 1 ? 's' : ' '}  `;
    lines.push(`  ${label} ${bar} ${String(count).padStart(3)} (${String(pct).padStart(3)}%)`);
  }
  lines.push('');

  // Drift matrix
  lines.push('Severity Drift Matrix  (rows = original, columns = Ox-prioritized)');
  lines.push('-'.repeat(60));
  const matHeader = '  Original\\Ox   ' + SEV_LEVELS.map(s => s.slice(0, 4).padStart(6)).join('');
  lines.push(matHeader);
  lines.push('  ' + '-'.repeat(matHeader.length - 2));
  for (const origSev of SEV_LEVELS) {
    const row = SEV_LEVELS.map(oxSev => {
      const val = stats.matrix[origSev]?.[oxSev] || 0;
      return String(val || '.').padStart(6);
    }).join('');
    lines.push(`  ${origSev.padEnd(14)} ${row}`);
  }
  lines.push('');
  lines.push('  Diagonal (.) = unchanged. Above diagonal = upgraded. Below = downgraded.');
  lines.push('');

  // Aggregate prioritization comparison
  if (stats.prioritization) {
    const p = stats.prioritization;
    lines.push('Aggregate Prioritization Comparison');
    lines.push('-'.repeat(50));
    lines.push('  Severity     Original   Ox-Prioritized   Delta');
    lines.push('  ' + '-'.repeat(48));
    for (const sev of SEV_LEVELS) {
      const sevKey = sev.toLowerCase();
      const orig = p.original?.[sevKey] ?? '-';
      const ox = p.oxPrioritized?.[sevKey] ?? '-';
      const delta = (typeof orig === 'number' && typeof ox === 'number')
        ? (ox - orig > 0 ? `+${ox - orig}` : `${ox - orig}`)
        : '-';
      lines.push(`  ${(SEV_ICON[sev] + ' ' + sev).padEnd(17)} ${String(orig).padStart(8)}   ${String(ox).padStart(14)}   ${String(delta).padStart(5)}`);
    }
    lines.push('');
  }

  // Triage effort impact
  lines.push('Triage Effort Impact');
  lines.push('-'.repeat(50));
  lines.push(`  Severity-weighted effort saved by downgrades:  ${stats.totalEffortSaved.toFixed(1)}`);
  lines.push(`  Severity-weighted effort added by upgrades:    ${stats.totalEffortAdded.toFixed(1)}`);
  const netEffect = stats.totalEffortSaved - stats.totalEffortAdded;
  lines.push(`  Net effect: ${netEffect > 0 ? 'Reduced' : 'Increased'} triage workload by ${Math.abs(netEffect).toFixed(1)} severity-weighted points`);
  lines.push('');

  // Per-app drift
  lines.push('Per-App Severity Drift');
  lines.push('-'.repeat(50));
  const appNames = Object.keys(stats.byApp).sort();
  for (const appName of appNames) {
    const a = stats.byApp[appName];
    const driftPct = a.total > 0 ? Math.round(((a.upgraded + a.downgraded) / a.total) * 100) : 0;
    lines.push(`\n  ${appName} (${a.total} issues, ${driftPct}% drifted)`);
    lines.push(`    ⬆️ ${a.upgraded} upgraded  ⬇️ ${a.downgraded} downgraded  ➡️ ${a.unchanged} unchanged`);
    if (a.totalEffortSaved > 0) lines.push(`    Triage effort saved: ${a.totalEffortSaved.toFixed(1)} points`);
  }
  lines.push('');

  // Reason categories
  const reasonCats = Object.entries(stats.reasonCategories).sort((a, b) => b[1].count - a[1].count);
  if (reasonCats.length > 0) {
    lines.push('Severity Change Reasons');
    lines.push('-'.repeat(50));
    for (const [cat, data] of reasonCats) {
      lines.push(`\n  ${cat} (${data.count} occurrences)`);
      lines.push(`    Upgrades: ${data.upgrades}  |  Downgrades: ${data.downgrades}`);
      for (const reason of data.reasons) {
        lines.push(`    • ${reason}`);
      }
    }
    lines.push('');
  }

  // Top drifted issues
  const drifted = analyzed.filter(a => a.driftDirection !== 'unchanged')
    .sort((a, b) => b.driftMagnitude - a.driftMagnitude || b.effortSaved - a.effortSaved);

  if (drifted.length > 0) {
    lines.push('All Drifted Issues (sorted by magnitude)');
    lines.push('-'.repeat(50));
    lines.push('  Dir  From → To          Issue');
    lines.push('  ' + '-'.repeat(65));
    for (const d of drifted) {
      const arrow = d.driftDirection === 'upgraded' ? '⬆️' : '⬇️';
      const from = `${SEV_ICON[d.originalSeverity]} ${d.originalSeverity}`;
      const to = `${SEV_ICON[d.oxSeverity]} ${d.oxSeverity}`;
      lines.push(`  ${arrow}   ${from.padEnd(14)} → ${to.padEnd(14)} ${d.mainTitle.slice(0, 40)}`);
      if (d.reasons.length > 0) {
        for (const r of d.reasons) {
          lines.push(`       Reason: ${r.shortName || r.reason.slice(0, 55)}`);
        }
      }
    }
    lines.push('');
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Markdown report
// ---------------------------------------------------------------------------
function generateMarkdown(analyzed, stats, timestamp) {
  const lines = [];

  lines.push('# E16: Severity Drift Report');
  lines.push(`\n*Generated: ${timestamp}*`);
  if (USE_MOCK) lines.push('\n> **Mock Mode** — using realistic sample data (no OX_API_KEY configured)');
  lines.push('');

  // Explanation
  lines.push('## What is Severity Drift?');
  lines.push('');
  lines.push('Ox Security re-prioritizes vulnerability severity based on contextual analysis:');
  lines.push('reachability, exploitability, business context, environment, and attack surface.');
  lines.push('This report compares scanner-reported (original) severity with Ox-prioritized');
  lines.push('severity to show where and why Ox adjusts risk assessments.');
  lines.push('');
  lines.push('- **Upgraded**: Ox raised the severity (higher real-world risk than scanner reported)');
  lines.push('- **Downgraded**: Ox lowered the severity (lower real-world risk based on context)');
  lines.push('- **Unchanged**: Ox agrees with the scanner\'s severity assessment');
  lines.push('');

  // Overview
  lines.push('## Overview');
  lines.push('');
  lines.push('| Metric | Value |');
  lines.push('|--------|-------|');
  lines.push(`| Total issues analyzed | ${stats.total} |`);
  lines.push(`| Drift rate | ${stats.driftRate}% |`);
  lines.push(`| ⬆️ Upgraded | ${stats.upgradedCount} (${stats.upgradedPct}%) |`);
  lines.push(`| ⬇️ Downgraded | ${stats.downgradedCount} (${stats.downgradedPct}%) |`);
  lines.push(`| ➡️ Unchanged | ${stats.unchangedCount} (${stats.unchangedPct}%) |`);
  lines.push(`| Net triage effort change | ${(stats.totalEffortSaved - stats.totalEffortAdded).toFixed(1)} points saved |`);
  lines.push('');

  // Drift magnitude
  lines.push('## Drift Magnitude Distribution');
  lines.push('');
  lines.push('| Magnitude | Count | % | Description |');
  lines.push('|-----------|-------|---|-------------|');
  const magDescriptions = {
    0: 'No change — Ox agrees with scanner',
    1: 'One level shift (e.g., High → Medium)',
    2: 'Two level shift (e.g., Critical → Medium)',
    3: 'Three level shift (e.g., Critical → Low)',
    4: 'Maximum shift (e.g., Critical → Info)',
  };
  for (let mag = 0; mag <= 4; mag++) {
    const count = stats.magnitudeDistribution[mag];
    if (count === 0 && mag > 2) continue;
    const pct = stats.total > 0 ? Math.round((count / stats.total) * 100) : 0;
    lines.push(`| ${mag} | ${count} | ${pct}% | ${magDescriptions[mag]} |`);
  }
  lines.push('');

  // Drift matrix
  lines.push('## Severity Drift Matrix');
  lines.push('');
  lines.push('Rows = original scanner severity, Columns = Ox-prioritized severity.');
  lines.push('Diagonal = unchanged. Upper-right = upgraded. Lower-left = downgraded.');
  lines.push('');
  const matCols = SEV_LEVELS.filter(s => {
    // Only show columns that have data
    return SEV_LEVELS.some(origS => (stats.matrix[origS]?.[s] || 0) > 0);
  });
  lines.push(`| Original \\ Ox | ${matCols.join(' | ')} |`);
  lines.push(`|${'-'.repeat(14)}|${matCols.map(() => '-'.repeat(10)).join('|')}|`);
  for (const origSev of SEV_LEVELS) {
    const hasRow = matCols.some(oxSev => (stats.matrix[origSev]?.[oxSev] || 0) > 0);
    if (!hasRow) continue;
    const cells = matCols.map(oxSev => {
      const val = stats.matrix[origSev]?.[oxSev] || 0;
      if (val === 0) return '  .  ';
      const marker = origSev === oxSev ? `**${val}**` : `${val}`;
      return ` ${marker} `;
    });
    lines.push(`| ${SEV_ICON[origSev]} ${origSev.padEnd(9)} | ${cells.join(' | ')} |`);
  }
  lines.push('');

  // Aggregate prioritization
  if (stats.prioritization) {
    const p = stats.prioritization;
    lines.push('## Aggregate Prioritization Comparison');
    lines.push('');
    lines.push('How the overall severity distribution shifts after Ox re-prioritization:');
    lines.push('');
    lines.push('| Severity | Original Count | Ox-Prioritized | Delta |');
    lines.push('|----------|---------------|----------------|-------|');
    for (const sev of SEV_LEVELS) {
      const sevKey = sev.toLowerCase();
      const orig = p.original?.[sevKey] ?? '-';
      const ox = p.oxPrioritized?.[sevKey] ?? '-';
      let delta = '-';
      if (typeof orig === 'number' && typeof ox === 'number') {
        const diff = ox - orig;
        delta = diff > 0 ? `+${diff}` : `${diff}`;
      }
      lines.push(`| ${SEV_ICON[sev]} ${sev} | ${orig} | ${ox} | ${delta} |`);
    }
    lines.push('');
  }

  // Triage effort impact
  lines.push('## Triage Effort Impact');
  lines.push('');
  lines.push('Severity-weighted measure of how Ox re-prioritization affects triage workload.');
  lines.push('Weights: Critical=10, High=5, Medium=2, Low=0.5, Info=0');
  lines.push('');
  lines.push(`- **Effort saved by downgrades:** ${stats.totalEffortSaved.toFixed(1)} weighted points`);
  lines.push(`- **Effort added by upgrades:** ${stats.totalEffortAdded.toFixed(1)} weighted points`);
  const netEffect = stats.totalEffortSaved - stats.totalEffortAdded;
  lines.push(`- **Net effect:** ${netEffect > 0 ? 'Reduced' : 'Increased'} triage workload by **${Math.abs(netEffect).toFixed(1)}** points`);
  lines.push('');
  if (netEffect > 0) {
    lines.push(`> Ox prioritization reduces your triage burden — ${stats.downgradedCount} issue(s) were deprioritized, saving focus for truly critical items.`);
  } else if (netEffect < 0) {
    lines.push(`> Ox prioritization surfaces hidden risks — ${stats.upgradedCount} issue(s) were escalated that scanners underestimated.`);
  }
  lines.push('');

  // Per-app breakdown
  lines.push('## Per-App Severity Drift');
  lines.push('');
  lines.push('| App | Total | ⬆️ Upgraded | ⬇️ Downgraded | ➡️ Unchanged | Drift Rate | Effort Saved |');
  lines.push('|-----|-------|-----------|-------------|------------|------------|--------------|');
  const appNames = Object.keys(stats.byApp).sort();
  for (const appName of appNames) {
    const a = stats.byApp[appName];
    const driftPct = a.total > 0 ? Math.round(((a.upgraded + a.downgraded) / a.total) * 100) : 0;
    lines.push(`| ${appName} | ${a.total} | ${a.upgraded} | ${a.downgraded} | ${a.unchanged} | ${driftPct}% | ${a.totalEffortSaved.toFixed(1)} |`);
  }
  lines.push('');

  // Per-category breakdown
  lines.push('## Drift by Issue Category');
  lines.push('');
  lines.push('| Category | Total | ⬆️ Upgraded | ⬇️ Downgraded | ➡️ Unchanged | Drift Rate |');
  lines.push('|----------|-------|-----------|-------------|------------|------------|');
  const catNames = Object.keys(stats.byCategory).sort();
  for (const cat of catNames) {
    const c = stats.byCategory[cat];
    const driftPct = c.total > 0 ? Math.round(((c.upgraded + c.downgraded) / c.total) * 100) : 0;
    lines.push(`| ${cat} | ${c.total} | ${c.upgraded} | ${c.downgraded} | ${c.unchanged} | ${driftPct}% |`);
  }
  lines.push('');

  // Per-sourceType breakdown
  lines.push('## Drift by Source Type');
  lines.push('');
  lines.push('| Source Type | Total | ⬆️ Upgraded | ⬇️ Downgraded | ➡️ Unchanged | Drift Rate |');
  lines.push('|------------|-------|-----------|-------------|------------|------------|');
  const stNames = Object.keys(stats.bySourceType).sort();
  for (const st of stNames) {
    const s = stats.bySourceType[st];
    const driftPct = s.total > 0 ? Math.round(((s.upgraded + s.downgraded) / s.total) * 100) : 0;
    lines.push(`| ${st} | ${s.total} | ${s.upgraded} | ${s.downgraded} | ${s.unchanged} | ${driftPct}% |`);
  }
  lines.push('');

  // Reason analysis
  const reasonCats = Object.entries(stats.reasonCategories).sort((a, b) => b[1].count - a[1].count);
  if (reasonCats.length > 0) {
    lines.push('## Severity Change Reason Analysis');
    lines.push('');
    lines.push('Why Ox re-prioritized severity, grouped by reason category:');
    lines.push('');
    for (const [cat, data] of reasonCats) {
      lines.push(`### ${cat} (${data.count} occurrences)`);
      lines.push('');
      lines.push(`- Upgrades driven: ${data.upgrades} | Downgrades driven: ${data.downgrades}`);
      lines.push('- Specific reasons:');
      for (const reason of data.reasons) {
        lines.push(`  - ${reason}`);
      }
      lines.push('');
    }
  }

  // Upgraded issues detail
  const upgraded = analyzed.filter(a => a.driftDirection === 'upgraded')
    .sort((a, b) => b.driftMagnitude - a.driftMagnitude);
  if (upgraded.length > 0) {
    lines.push('## ⬆️ Upgraded Issues (Scanner Underestimated)');
    lines.push('');
    lines.push('These issues were escalated by Ox — the real-world risk is higher than scanner severity suggested:');
    lines.push('');
    for (const u of upgraded) {
      lines.push(`### ${SEV_ICON[u.originalSeverity]} ${u.originalSeverity} → ${SEV_ICON[u.oxSeverity]} ${u.oxSeverity}: ${u.mainTitle}`);
      lines.push('');
      lines.push(`- **Issue ID:** ${u.issueId}`);
      lines.push(`- **App:** ${u.app?.name || 'N/A'}`);
      lines.push(`- **Category:** ${u.category || 'N/A'}`);
      lines.push(`- **Source:** ${u.sourceType}`);
      lines.push(`- **Drift magnitude:** +${u.driftMagnitude} level(s)`);
      if (u.reasons.length > 0) {
        lines.push('- **Reasons:**');
        for (const r of u.reasons) {
          lines.push(`  - **${r.shortName || r.changeCategory}:** ${r.reason}`);
        }
      }
      lines.push(`- **Detail:** ${u.secondTitle}`);
      lines.push('');
    }
  }

  // Downgraded issues detail
  const downgraded = analyzed.filter(a => a.driftDirection === 'downgraded')
    .sort((a, b) => b.driftMagnitude - a.driftMagnitude || b.effortSaved - a.effortSaved);
  if (downgraded.length > 0) {
    lines.push('## ⬇️ Downgraded Issues (Scanner Overestimated)');
    lines.push('');
    lines.push('These issues were deprioritized by Ox — real-world risk is lower than scanner severity suggested:');
    lines.push('');
    for (const d of downgraded) {
      lines.push(`### ${SEV_ICON[d.originalSeverity]} ${d.originalSeverity} → ${SEV_ICON[d.oxSeverity]} ${d.oxSeverity}: ${d.mainTitle}`);
      lines.push('');
      lines.push(`- **Issue ID:** ${d.issueId}`);
      lines.push(`- **App:** ${d.app?.name || 'N/A'}`);
      lines.push(`- **Category:** ${d.category || 'N/A'}`);
      lines.push(`- **Source:** ${d.sourceType}`);
      lines.push(`- **Drift magnitude:** -${d.driftMagnitude} level(s)`);
      lines.push(`- **Triage effort saved:** ${d.effortSaved.toFixed(1)} weighted points`);
      if (d.reasons.length > 0) {
        lines.push('- **Reasons:**');
        for (const r of d.reasons) {
          lines.push(`  - **${r.shortName || r.changeCategory}:** ${r.reason}`);
        }
      }
      lines.push(`- **Detail:** ${d.secondTitle}`);
      lines.push('');
    }
  }

  // Recommendations
  lines.push('## Recommendations');
  lines.push('');

  let recNum = 1;

  if (upgraded.length > 0) {
    lines.push(`${recNum}. **Prioritize upgraded issues:** ${upgraded.length} issue(s) were escalated by Ox. These represent hidden risks that scanners alone would underestimate. Review these first.`);
    recNum++;
  }

  if (downgraded.length > 0) {
    lines.push(`${recNum}. **Defer downgraded issues:** ${downgraded.length} issue(s) were deprioritized. Use Ox severity for sprint planning rather than raw scanner severity to reduce noise.`);
    recNum++;
  }

  if (stats.driftRate > 30) {
    lines.push(`${recNum}. **High drift rate (${stats.driftRate}%):** Scanner severity alone is unreliable for this portfolio. Rely on Ox-prioritized severity for triage decisions.`);
    recNum++;
  }

  const highDriftApps = appNames.filter(name => {
    const a = stats.byApp[name];
    return a.total > 0 && ((a.upgraded + a.downgraded) / a.total) > 0.4;
  });
  if (highDriftApps.length > 0) {
    lines.push(`${recNum}. **Apps with high drift:** ${highDriftApps.join(', ')} have >40% severity drift. These apps benefit most from Ox contextual analysis.`);
    recNum++;
  }

  const reachabilityCount = stats.reasonCategories['Reachability']?.count || 0;
  if (reachabilityCount > 0) {
    lines.push(`${recNum}. **Reachability analysis is key:** ${reachabilityCount} re-prioritization(s) were driven by reachability analysis. Ensure code-level scanning is connected for best results.`);
    recNum++;
  }

  if (netEffect > 0) {
    lines.push(`${recNum}. **Triage efficiency gained:** Ox prioritization saves ${netEffect.toFixed(1)} severity-weighted triage points. This translates to less time spent on false-positive critical findings.`);
  }

  lines.push('');

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  const appFilter = process.env.OX_APP_NAME || process.argv[2] || '';
  const limit = parseInt(process.env.OX_LIMIT || '200', 10);
  const concurrency = parseInt(process.env.OX_CONCURRENCY || '5', 10);
  const timestamp = new Date().toISOString();

  console.log('E16: Severity Drift Report');
  console.log('='.repeat(50));
  if (USE_MOCK) console.log('  No API key found — running with mock data');
  console.log(`  App filter: ${appFilter || 'all'}`);
  console.log('');

  // Step 1: Fetch issue list
  console.log('Step 1: Fetching issue list...');
  let issues = await fetchIssues(limit, appFilter);
  console.log(`  Loaded ${issues.length} issues`);

  // Apply app filter
  if (appFilter) {
    issues = issues.filter(i => i.app?.name?.toLowerCase().includes(appFilter.toLowerCase()));
    console.log(`  After app filter: ${issues.length}`);
  }

  if (issues.length === 0) {
    console.log('\nNo issues match the filter criteria.');
    return;
  }

  // Step 2: Classify drift
  console.log('\nStep 2: Classifying severity drift...');
  const analyzed = analyzeIssues(issues);
  const drifted = analyzed.filter(a => a.driftDirection !== 'unchanged');
  console.log(`  Drifted: ${drifted.length}/${analyzed.length} issues`);

  // Step 3: Fetch detail for drifted issues (to get severity change reasons)
  if (drifted.length > 0) {
    console.log(`\nStep 3: Fetching details for ${drifted.length} drifted issues...`);
    const details = await fetchDetailsForDrifted(drifted, concurrency);
    enrichWithReasons(analyzed, details);
    const withReasons = analyzed.filter(a => a.reasons.length > 0);
    console.log(`  Got severity change reasons for ${withReasons.length} issues`);
  } else {
    console.log('\nStep 3: No drifted issues to enrich.');
  }

  // Step 4: Fetch aggregate prioritization
  console.log('\nStep 4: Fetching aggregate prioritization data...');
  let prioritization = null;
  try {
    prioritization = await fetchPrioritization();
    console.log('  Got prioritization comparison data');
  } catch (e) {
    console.log(`  Could not fetch prioritization: ${e.message}`);
  }

  // Step 5: Compute statistics
  console.log('\nStep 5: Computing drift statistics...');
  const stats = computeStats(analyzed, prioritization);

  // Step 6: Output
  const consoleOutput = renderConsole(analyzed, stats);
  console.log(consoleOutput);

  // Write to experiments/
  const dateStr = timestamp.slice(0, 10);
  const outDir = resolve(process.cwd(), 'experiments', `severity-drift-${dateStr}`);
  mkdirSync(outDir, { recursive: true });

  // JSON
  const jsonData = {
    meta: {
      timestamp,
      mockData: USE_MOCK,
      appFilter: appFilter || null,
      totalIssues: stats.total,
      driftRate: stats.driftRate,
    },
    summary: {
      total: stats.total,
      upgradedCount: stats.upgradedCount,
      downgradedCount: stats.downgradedCount,
      unchangedCount: stats.unchangedCount,
      upgradedPct: stats.upgradedPct,
      downgradedPct: stats.downgradedPct,
      unchangedPct: stats.unchangedPct,
      driftRate: stats.driftRate,
      totalEffortSaved: stats.totalEffortSaved,
      totalEffortAdded: stats.totalEffortAdded,
      netTriageEffect: stats.totalEffortSaved - stats.totalEffortAdded,
    },
    magnitudeDistribution: stats.magnitudeDistribution,
    driftMatrix: stats.matrix,
    prioritization: stats.prioritization,
    byApp: stats.byApp,
    byCategory: stats.byCategory,
    bySourceType: stats.bySourceType,
    reasonCategories: stats.reasonCategories,
    issues: analyzed.map(a => ({
      issueId: a.issueId,
      mainTitle: a.mainTitle,
      secondTitle: a.secondTitle,
      originalSeverity: a.originalSeverity,
      oxSeverity: a.oxSeverity,
      sourceType: a.sourceType,
      app: a.app?.name,
      category: a.category,
      driftDirection: a.driftDirection,
      driftMagnitude: a.driftMagnitude,
      effortSaved: a.effortSaved,
      reasons: a.reasons,
    })),
  };
  writeFileSync(resolve(outDir, 'severity-drift.json'), JSON.stringify(jsonData, null, 2));

  // Markdown
  const mdReport = generateMarkdown(analyzed, stats, timestamp);
  writeFileSync(resolve(outDir, 'severity-drift-report.md'), mdReport);

  console.log(`\nResults written to experiments/severity-drift-${dateStr}/`);
  console.log('  - severity-drift.json         (machine-readable)');
  console.log('  - severity-drift-report.md    (human-readable)');
}

main().catch(e => { console.error(`\nFatal: ${e.message}`); process.exit(1); });
