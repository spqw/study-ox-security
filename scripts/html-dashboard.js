#!/usr/bin/env node
/**
 * E17: HTML Dashboard
 *
 * Generates a self-contained static HTML page showing a vulnerability overview
 * dashboard. No server needed — just open the file in a browser.
 *
 * Aggregates: app inventory, issue severity breakdown, SBOM health,
 * risk scores, top issues, and per-app detail cards.
 *
 * Falls back to realistic mock data when OX_API_KEY is not configured.
 *
 * Usage:
 *   node scripts/html-dashboard.js [appFilter]
 *
 * Environment:
 *   OX_APP_NAME  — filter to a specific app name
 *
 * Output:
 *   experiments/dashboard-{date}/dashboard.html  — open in any browser
 *   experiments/dashboard-{date}/data.json       — raw data backing the dashboard
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

let queryFn;
if (!USE_MOCK) {
  const client = await import('../lib/ox-client.js');
  queryFn = client.query;
}

const APP_FILTER = process.env.OX_APP_NAME || process.argv[2] || '';

// ---------------------------------------------------------------------------
// GraphQL queries (inline to keep self-contained)
// ---------------------------------------------------------------------------
const Q_APPS = `query GetApplications($getApplicationsInput: GetApplicationsInput!) {
  getApplications(getApplicationsInput: $getApplicationsInput) {
    applications { appId appName type risk issuesBySeverity { critical high medium low info } }
    totalCount
  }
}`;

const Q_ISSUES = `query GetIssues($isDemo: Boolean!, $getIssuesInput: GetIssuesInput!) {
  getIssues(isDemo: $isDemo, getIssuesInput: $getIssuesInput) {
    issues {
      issueId mainTitle secondTitle severity originalSeverity category { name }
      sourceType created app { name } autoFix { fixTitle fixType }
    }
    totalCount
  }
}`;

const Q_SBOM = `query GetSBOMLibraries($getSBOMInput: GetSBOMInput!) {
  getSBOMLibraries(getSBOMInput: $getSBOMInput) {
    libraries { name version source totalVulnerabilities isDeprecated isMaintained
      vulnerabilities { critical high medium low } app { name } }
    totalCount
  }
}`;

// ---------------------------------------------------------------------------
// Mock data
// ---------------------------------------------------------------------------
function getMockData() {
  const apps = [
    {
      appId: 'app-1', appName: 'SecureBank iOS', type: 'Mobile', risk: 72,
      issuesBySeverity: { critical: 3, high: 8, medium: 15, low: 22, info: 5 },
    },
    {
      appId: 'app-2', appName: 'HealthTracker Pro', type: 'Mobile', risk: 58,
      issuesBySeverity: { critical: 1, high: 5, medium: 12, low: 18, info: 8 },
    },
    {
      appId: 'app-3', appName: 'ShopEasy Mobile', type: 'Mobile', risk: 45,
      issuesBySeverity: { critical: 0, high: 3, medium: 8, low: 14, info: 12 },
    },
    {
      appId: 'app-4', appName: 'InternalTools iPad', type: 'Mobile', risk: 33,
      issuesBySeverity: { critical: 0, high: 1, medium: 5, low: 9, info: 3 },
    },
  ];

  const issues = [
    { issueId: 'i-1', mainTitle: 'Remote Code Execution in CocoaPods dependency', secondTitle: 'AFNetworking < 4.0.0', severity: 'Critical', originalSeverity: 'Critical', category: { name: 'SCA' }, sourceType: 'SCA', created: '2026-01-15T10:00:00Z', app: { name: 'SecureBank iOS' }, autoFix: { fixTitle: 'Upgrade AFNetworking to 4.0.1', fixType: 'VersionBump' } },
    { issueId: 'i-2', mainTitle: 'SQL Injection via FMDB raw query', secondTitle: 'Unsanitized input in database query', severity: 'Critical', originalSeverity: 'Critical', category: { name: 'SAST' }, sourceType: 'SAST', created: '2026-01-18T14:30:00Z', app: { name: 'SecureBank iOS' }, autoFix: null },
    { issueId: 'i-3', mainTitle: 'Prototype Pollution in lodash', secondTitle: 'lodash < 4.17.21', severity: 'Critical', originalSeverity: 'High', category: { name: 'SCA' }, sourceType: 'SCA', created: '2026-01-20T09:00:00Z', app: { name: 'HealthTracker Pro' }, autoFix: { fixTitle: 'Upgrade lodash to 4.17.21', fixType: 'VersionBump' } },
    { issueId: 'i-4', mainTitle: 'Missing App Transport Security exception', secondTitle: 'NSAllowsArbitraryLoads = YES in Info.plist', severity: 'Critical', originalSeverity: 'High', category: { name: 'IaC' }, sourceType: 'IaC', created: '2026-02-01T11:00:00Z', app: { name: 'SecureBank iOS' }, autoFix: null },
    { issueId: 'i-5', mainTitle: 'Hardcoded API key in source code', secondTitle: 'Stripe secret key in PaymentService.swift', severity: 'High', originalSeverity: 'High', category: { name: 'Secret Detection' }, sourceType: 'SecretDetection', created: '2026-01-22T16:00:00Z', app: { name: 'ShopEasy Mobile' }, autoFix: null },
    { issueId: 'i-6', mainTitle: 'Insecure Keychain access level', secondTitle: 'kSecAttrAccessibleAlways used for auth tokens', severity: 'High', originalSeverity: 'High', category: { name: 'SAST' }, sourceType: 'SAST', created: '2026-01-25T08:00:00Z', app: { name: 'SecureBank iOS' }, autoFix: null },
    { issueId: 'i-7', mainTitle: 'Missing certificate pinning', secondTitle: 'No SSL pinning configured for API calls', severity: 'High', originalSeverity: 'Medium', category: { name: 'SAST' }, sourceType: 'SAST', created: '2026-01-28T13:00:00Z', app: { name: 'HealthTracker Pro' }, autoFix: null },
    { issueId: 'i-8', mainTitle: 'OpenSSL vulnerability CVE-2024-5535', secondTitle: 'OpenSSL 1.1.1w affected', severity: 'High', originalSeverity: 'High', category: { name: 'SCA' }, sourceType: 'SCA', created: '2026-02-02T10:00:00Z', app: { name: 'SecureBank iOS' }, autoFix: { fixTitle: 'Upgrade OpenSSL to 3.0.13', fixType: 'VersionBump' } },
    { issueId: 'i-9', mainTitle: 'React Native bridge exposure', secondTitle: 'Sensitive methods exposed to JS bridge', severity: 'High', originalSeverity: 'High', category: { name: 'SAST' }, sourceType: 'SAST', created: '2026-02-05T09:00:00Z', app: { name: 'ShopEasy Mobile' }, autoFix: null },
    { issueId: 'i-10', mainTitle: 'Weak biometric authentication fallback', secondTitle: 'Password fallback allows bypass of FaceID', severity: 'High', originalSeverity: 'Medium', category: { name: 'SAST' }, sourceType: 'SAST', created: '2026-02-08T14:00:00Z', app: { name: 'HealthTracker Pro' }, autoFix: null },
    { issueId: 'i-11', mainTitle: 'Outdated Firebase SDK', secondTitle: 'Firebase 8.x has known auth bypass', severity: 'Medium', originalSeverity: 'Medium', category: { name: 'SCA' }, sourceType: 'SCA', created: '2026-01-10T11:00:00Z', app: { name: 'ShopEasy Mobile' }, autoFix: { fixTitle: 'Upgrade Firebase to 10.x', fixType: 'VersionBump' } },
    { issueId: 'i-12', mainTitle: 'Unencrypted Core Data store', secondTitle: 'NSPersistentStoreDescription missing encryption', severity: 'Medium', originalSeverity: 'Medium', category: { name: 'SAST' }, sourceType: 'SAST', created: '2026-01-12T10:00:00Z', app: { name: 'HealthTracker Pro' }, autoFix: null },
    { issueId: 'i-13', mainTitle: 'UIWebView usage detected', secondTitle: 'Deprecated UIWebView should be migrated to WKWebView', severity: 'Medium', originalSeverity: 'Low', category: { name: 'SAST' }, sourceType: 'SAST', created: '2026-02-10T08:00:00Z', app: { name: 'InternalTools iPad' }, autoFix: null },
    { issueId: 'i-14', mainTitle: 'Alamofire security configuration', secondTitle: 'ServerTrustManager not properly configured', severity: 'Medium', originalSeverity: 'Medium', category: { name: 'SCA' }, sourceType: 'SCA', created: '2026-02-12T15:00:00Z', app: { name: 'SecureBank iOS' }, autoFix: { fixTitle: 'Update Alamofire to 5.9.0', fixType: 'VersionBump' } },
    { issueId: 'i-15', mainTitle: 'Excessive app permissions', secondTitle: 'Location always + camera + contacts not all needed', severity: 'Low', originalSeverity: 'Low', category: { name: 'IaC' }, sourceType: 'IaC', created: '2026-02-14T09:00:00Z', app: { name: 'ShopEasy Mobile' }, autoFix: null },
    { issueId: 'i-16', mainTitle: 'Debug logging enabled in release build', secondTitle: 'NSLog statements leak sensitive data', severity: 'Low', originalSeverity: 'Info', category: { name: 'SAST' }, sourceType: 'SAST', created: '2026-02-15T11:00:00Z', app: { name: 'InternalTools iPad' }, autoFix: null },
  ];

  const libraries = [
    { name: 'AFNetworking', version: '3.2.1', source: 'CocoaPods', totalVulnerabilities: 3, isDeprecated: true, isMaintained: false, vulnerabilities: { critical: 1, high: 1, medium: 1, low: 0 }, app: { name: 'SecureBank iOS' } },
    { name: 'Alamofire', version: '5.8.0', source: 'SPM', totalVulnerabilities: 1, isDeprecated: false, isMaintained: true, vulnerabilities: { critical: 0, high: 0, medium: 1, low: 0 }, app: { name: 'SecureBank iOS' } },
    { name: 'OpenSSL', version: '1.1.1w', source: 'CocoaPods', totalVulnerabilities: 2, isDeprecated: false, isMaintained: true, vulnerabilities: { critical: 0, high: 1, medium: 1, low: 0 }, app: { name: 'SecureBank iOS' } },
    { name: 'FMDB', version: '2.7.5', source: 'CocoaPods', totalVulnerabilities: 1, isDeprecated: true, isMaintained: false, vulnerabilities: { critical: 0, high: 1, medium: 0, low: 0 }, app: { name: 'SecureBank iOS' } },
    { name: 'KeychainAccess', version: '4.2.2', source: 'SPM', totalVulnerabilities: 0, isDeprecated: false, isMaintained: true, vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0 }, app: { name: 'SecureBank iOS' } },
    { name: 'SnapKit', version: '5.6.0', source: 'SPM', totalVulnerabilities: 0, isDeprecated: false, isMaintained: true, vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0 }, app: { name: 'SecureBank iOS' } },
    { name: 'lodash', version: '4.17.15', source: 'npm', totalVulnerabilities: 2, isDeprecated: false, isMaintained: true, vulnerabilities: { critical: 1, high: 1, medium: 0, low: 0 }, app: { name: 'HealthTracker Pro' } },
    { name: 'HealthKit', version: '1.0.0', source: 'iOS SDK', totalVulnerabilities: 0, isDeprecated: false, isMaintained: true, vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0 }, app: { name: 'HealthTracker Pro' } },
    { name: 'Charts', version: '4.1.0', source: 'SPM', totalVulnerabilities: 0, isDeprecated: false, isMaintained: true, vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0 }, app: { name: 'HealthTracker Pro' } },
    { name: 'CryptoSwift', version: '1.7.0', source: 'SPM', totalVulnerabilities: 0, isDeprecated: false, isMaintained: true, vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0 }, app: { name: 'HealthTracker Pro' } },
    { name: 'Realm', version: '10.42.0', source: 'CocoaPods', totalVulnerabilities: 1, isDeprecated: false, isMaintained: true, vulnerabilities: { critical: 0, high: 0, medium: 1, low: 0 }, app: { name: 'HealthTracker Pro' } },
    { name: 'react-native', version: '0.72.4', source: 'npm', totalVulnerabilities: 1, isDeprecated: false, isMaintained: true, vulnerabilities: { critical: 0, high: 1, medium: 0, low: 0 }, app: { name: 'ShopEasy Mobile' } },
    { name: 'Firebase', version: '8.15.0', source: 'CocoaPods', totalVulnerabilities: 1, isDeprecated: false, isMaintained: true, vulnerabilities: { critical: 0, high: 0, medium: 1, low: 0 }, app: { name: 'ShopEasy Mobile' } },
    { name: 'Stripe', version: '23.8.0', source: 'SPM', totalVulnerabilities: 0, isDeprecated: false, isMaintained: true, vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0 }, app: { name: 'ShopEasy Mobile' } },
    { name: 'SDWebImage', version: '5.18.0', source: 'CocoaPods', totalVulnerabilities: 0, isDeprecated: false, isMaintained: true, vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0 }, app: { name: 'ShopEasy Mobile' } },
    { name: 'Kingfisher', version: '7.9.0', source: 'SPM', totalVulnerabilities: 0, isDeprecated: false, isMaintained: true, vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0 }, app: { name: 'InternalTools iPad' } },
    { name: 'SQLite.swift', version: '0.14.1', source: 'SPM', totalVulnerabilities: 0, isDeprecated: false, isMaintained: true, vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0 }, app: { name: 'InternalTools iPad' } },
    { name: 'SwiftyJSON', version: '5.0.1', source: 'CocoaPods', totalVulnerabilities: 0, isDeprecated: false, isMaintained: false, vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0 }, app: { name: 'InternalTools iPad' } },
  ];

  return { apps, issues, libraries };
}

// ---------------------------------------------------------------------------
// Fetch real data from API
// ---------------------------------------------------------------------------
async function fetchRealData() {
  console.log('  Fetching applications...');
  const appsData = await queryFn(Q_APPS, {
    getApplicationsInput: { offset: 0, limit: 500 },
  });
  let apps = appsData.getApplications.applications;

  console.log('  Fetching issues...');
  const issuesData = await queryFn(Q_ISSUES, {
    isDemo: false,
    getIssuesInput: { offset: 0, limit: 1000, sort: { fields: ['Severity'], order: ['DESC'] } },
  });
  let issues = issuesData.getIssues.issues;

  console.log('  Fetching SBOM libraries...');
  const sbomData = await queryFn(Q_SBOM, {
    getSBOMInput: { offset: 0, limit: 1000 },
  });
  let libraries = sbomData.getSBOMLibraries.libraries;

  // Apply app filter
  if (APP_FILTER) {
    const f = APP_FILTER.toLowerCase();
    apps = apps.filter(a => a.appName.toLowerCase().includes(f));
    issues = issues.filter(i => i.app?.name?.toLowerCase().includes(f));
    libraries = libraries.filter(l => l.app?.name?.toLowerCase().includes(f));
  }

  return { apps, issues, libraries };
}

// ---------------------------------------------------------------------------
// Analysis helpers
// ---------------------------------------------------------------------------
function analyzeData(data) {
  const { apps, issues, libraries } = data;

  // Severity totals
  const sevTotals = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  for (const i of issues) sevTotals[i.severity] = (sevTotals[i.severity] || 0) + 1;

  // Source type distribution
  const sourceTypes = {};
  for (const i of issues) {
    const src = i.sourceType || 'Unknown';
    sourceTypes[src] = (sourceTypes[src] || 0) + 1;
  }

  // Category distribution
  const categories = {};
  for (const i of issues) {
    const cat = i.category?.name || 'Unknown';
    categories[cat] = (categories[cat] || 0) + 1;
  }

  // Per-app analysis
  const appAnalysis = apps.map(app => {
    const appIssues = issues.filter(i => i.app?.name === app.appName);
    const appLibs = libraries.filter(l => l.app?.name === app.appName);
    const vulnLibs = appLibs.filter(l => l.totalVulnerabilities > 0);
    const deprecatedLibs = appLibs.filter(l => l.isDeprecated);
    const unmaintainedLibs = appLibs.filter(l => l.isMaintained === false);
    const autoFixable = appIssues.filter(i => i.autoFix);
    const sev = app.issuesBySeverity || {};
    return {
      ...app,
      issueCount: appIssues.length,
      libCount: appLibs.length,
      vulnLibCount: vulnLibs.length,
      deprecatedCount: deprecatedLibs.length,
      unmaintainedCount: unmaintainedLibs.length,
      autoFixCount: autoFixable.length,
      sevBreakdown: { critical: sev.critical || 0, high: sev.high || 0, medium: sev.medium || 0, low: sev.low || 0, info: sev.info || 0 },
    };
  });

  // SBOM health
  const totalLibs = libraries.length;
  const vulnLibs = libraries.filter(l => l.totalVulnerabilities > 0).length;
  const deprecatedLibs = libraries.filter(l => l.isDeprecated).length;
  const unmaintainedLibs = libraries.filter(l => l.isMaintained === false).length;

  // Top vulnerable libraries
  const topVulnLibs = [...libraries]
    .filter(l => l.totalVulnerabilities > 0)
    .sort((a, b) => b.totalVulnerabilities - a.totalVulnerabilities)
    .slice(0, 10);

  // Issues with auto-fix available
  const autoFixable = issues.filter(i => i.autoFix);

  // Severity drift (original vs current)
  const drifted = issues.filter(i => i.originalSeverity && i.severity !== i.originalSeverity);

  // Issues by age (recent = last 30 days)
  const now = Date.now();
  const thirtyDaysAgo = now - 30 * 24 * 60 * 60 * 1000;
  const recentIssues = issues.filter(i => new Date(i.created).getTime() > thirtyDaysAgo);

  return {
    summary: {
      totalApps: apps.length,
      totalIssues: issues.length,
      totalLibraries: totalLibs,
      sevTotals,
      sourceTypes,
      categories,
      autoFixCount: autoFixable.length,
      driftedCount: drifted.length,
      recentCount: recentIssues.length,
    },
    sbomHealth: {
      total: totalLibs,
      vulnerable: vulnLibs,
      deprecated: deprecatedLibs,
      unmaintained: unmaintainedLibs,
      healthyPct: totalLibs > 0 ? Math.round(((totalLibs - vulnLibs) / totalLibs) * 100) : 100,
    },
    appAnalysis,
    topVulnLibs,
    topIssues: issues.slice(0, 20),
    autoFixable,
    generatedAt: new Date().toISOString(),
    dataSource: USE_MOCK ? 'Mock Data' : 'Ox Security API',
  };
}

// ---------------------------------------------------------------------------
// HTML generation
// ---------------------------------------------------------------------------
function generateHTML(analysis) {
  const { summary, sbomHealth, appAnalysis, topVulnLibs, topIssues, autoFixable, generatedAt, dataSource } = analysis;

  // Color palette
  const COLORS = {
    critical: '#dc2626',
    high: '#ea580c',
    medium: '#ca8a04',
    low: '#2563eb',
    info: '#6b7280',
    bg: '#0f172a',
    card: '#1e293b',
    cardHover: '#334155',
    border: '#334155',
    text: '#e2e8f0',
    textMuted: '#94a3b8',
    accent: '#3b82f6',
    success: '#22c55e',
    warning: '#f59e0b',
  };

  const sevOrder = ['Critical', 'High', 'Medium', 'Low', 'Info'];
  const sevColorMap = { Critical: COLORS.critical, High: COLORS.high, Medium: COLORS.medium, Low: COLORS.low, Info: COLORS.info };

  // Helper: risk grade
  function riskGrade(score) {
    if (score <= 20) return { grade: 'A', color: COLORS.success };
    if (score <= 40) return { grade: 'B', color: '#4ade80' };
    if (score <= 60) return { grade: 'C', color: COLORS.warning };
    if (score <= 80) return { grade: 'D', color: COLORS.high };
    return { grade: 'F', color: COLORS.critical };
  }

  // Build severity donut data for inline SVG
  const totalIssues = summary.totalIssues || 1;
  let donutSegments = '';
  let offset = 0;
  const radius = 40;
  const circumference = 2 * Math.PI * radius;
  for (const sev of sevOrder) {
    const count = summary.sevTotals[sev] || 0;
    if (count === 0) continue;
    const pct = count / totalIssues;
    const dashLen = pct * circumference;
    const dashGap = circumference - dashLen;
    donutSegments += `<circle cx="50" cy="50" r="${radius}" fill="none" stroke="${sevColorMap[sev]}" stroke-width="12" stroke-dasharray="${dashLen} ${dashGap}" stroke-dashoffset="${-offset}" />`;
    offset += dashLen;
  }

  // Build source type bars
  const sourceEntries = Object.entries(summary.sourceTypes).sort((a, b) => b[1] - a[1]);
  const maxSource = sourceEntries.length > 0 ? sourceEntries[0][1] : 1;
  const sourceColors = ['#3b82f6', '#8b5cf6', '#ec4899', '#14b8a6', '#f59e0b', '#ef4444', '#06b6d4'];

  // App cards
  const appCards = appAnalysis.map(app => {
    const g = riskGrade(app.risk);
    const maxSev = Math.max(app.sevBreakdown.critical, app.sevBreakdown.high, app.sevBreakdown.medium, app.sevBreakdown.low, app.sevBreakdown.info, 1);
    return `
      <div class="app-card">
        <div class="app-header">
          <div>
            <div class="app-name">${esc(app.appName)}</div>
            <div class="app-type">${esc(app.type || 'Application')}</div>
          </div>
          <div class="risk-badge" style="background:${g.color}20;color:${g.color};border:1px solid ${g.color}40">
            ${g.grade} <span class="risk-num">${app.risk}</span>
          </div>
        </div>
        <div class="sev-bars">
          ${['critical', 'high', 'medium', 'low'].map(s => `
            <div class="sev-bar-row">
              <span class="sev-label" style="color:${sevColorMap[s.charAt(0).toUpperCase() + s.slice(1)]}">${s.charAt(0).toUpperCase()}</span>
              <div class="sev-bar-track">
                <div class="sev-bar-fill" style="width:${maxSev > 0 ? (app.sevBreakdown[s] / maxSev) * 100 : 0}%;background:${sevColorMap[s.charAt(0).toUpperCase() + s.slice(1)]}"></div>
              </div>
              <span class="sev-count">${app.sevBreakdown[s]}</span>
            </div>
          `).join('')}
        </div>
        <div class="app-stats">
          <div class="app-stat"><span class="stat-val">${app.libCount}</span><span class="stat-label">Libraries</span></div>
          <div class="app-stat"><span class="stat-val">${app.vulnLibCount}</span><span class="stat-label">Vulnerable</span></div>
          <div class="app-stat"><span class="stat-val">${app.autoFixCount}</span><span class="stat-label">Auto-fixable</span></div>
          <div class="app-stat"><span class="stat-val">${app.deprecatedCount}</span><span class="stat-label">Deprecated</span></div>
        </div>
      </div>`;
  }).join('\n');

  // Top issues table
  const issueRows = topIssues.map((issue, idx) => `
    <tr>
      <td>${idx + 1}</td>
      <td><span class="sev-pill" style="background:${sevColorMap[issue.severity]}20;color:${sevColorMap[issue.severity]};border:1px solid ${sevColorMap[issue.severity]}40">${esc(issue.severity)}</span></td>
      <td class="issue-title">${esc(issue.mainTitle)}</td>
      <td>${esc(issue.app?.name || 'N/A')}</td>
      <td>${esc(issue.sourceType || 'N/A')}</td>
      <td>${issue.autoFix ? '<span class="fix-badge">Auto-fix</span>' : '<span class="no-fix">Manual</span>'}</td>
    </tr>`).join('\n');

  // Vulnerable libraries table
  const libRows = topVulnLibs.map(lib => `
    <tr>
      <td>${esc(lib.name)}</td>
      <td>${esc(lib.version)}</td>
      <td>${esc(lib.source || 'Unknown')}</td>
      <td>${esc(lib.app?.name || 'N/A')}</td>
      <td class="vuln-counts">
        ${lib.vulnerabilities?.critical ? `<span class="vc vc-c">${lib.vulnerabilities.critical}C</span>` : ''}
        ${lib.vulnerabilities?.high ? `<span class="vc vc-h">${lib.vulnerabilities.high}H</span>` : ''}
        ${lib.vulnerabilities?.medium ? `<span class="vc vc-m">${lib.vulnerabilities.medium}M</span>` : ''}
        ${lib.vulnerabilities?.low ? `<span class="vc vc-l">${lib.vulnerabilities.low}L</span>` : ''}
      </td>
      <td>${lib.isDeprecated ? '<span class="dep-badge">Deprecated</span>' : lib.isMaintained === false ? '<span class="unm-badge">Unmaintained</span>' : '<span class="ok-badge">OK</span>'}</td>
    </tr>`).join('\n');

  // Auto-fix opportunities
  const fixRows = autoFixable.slice(0, 10).map(issue => `
    <tr>
      <td><span class="sev-pill" style="background:${sevColorMap[issue.severity]}20;color:${sevColorMap[issue.severity]}">${esc(issue.severity)}</span></td>
      <td>${esc(issue.mainTitle)}</td>
      <td>${esc(issue.app?.name || 'N/A')}</td>
      <td class="fix-action">${esc(issue.autoFix.fixTitle)}</td>
    </tr>`).join('\n');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ox Security — iOS Vulnerability Dashboard</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    background: ${COLORS.bg};
    color: ${COLORS.text};
    line-height: 1.6;
    padding: 0;
  }
  .container { max-width: 1400px; margin: 0 auto; padding: 24px; }

  /* Header */
  .header { display: flex; justify-content: space-between; align-items: center; padding: 20px 0; border-bottom: 1px solid ${COLORS.border}; margin-bottom: 24px; }
  .header h1 { font-size: 24px; font-weight: 700; }
  .header h1 span { color: ${COLORS.accent}; }
  .header-meta { text-align: right; color: ${COLORS.textMuted}; font-size: 13px; }
  .data-source { display: inline-block; background: ${COLORS.accent}20; color: ${COLORS.accent}; padding: 2px 10px; border-radius: 12px; font-size: 12px; font-weight: 600; margin-bottom: 4px; }

  /* KPI row */
  .kpi-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }
  .kpi-card { background: ${COLORS.card}; border: 1px solid ${COLORS.border}; border-radius: 12px; padding: 20px; text-align: center; transition: transform 0.15s, border-color 0.15s; }
  .kpi-card:hover { transform: translateY(-2px); border-color: ${COLORS.accent}40; }
  .kpi-value { font-size: 36px; font-weight: 800; line-height: 1.1; }
  .kpi-label { font-size: 13px; color: ${COLORS.textMuted}; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }

  /* Section */
  .section { margin-bottom: 32px; }
  .section-title { font-size: 18px; font-weight: 700; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }
  .section-title::before { content: ''; width: 4px; height: 20px; background: ${COLORS.accent}; border-radius: 2px; }

  /* Two-column layout */
  .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 24px; }
  @media (max-width: 900px) { .two-col { grid-template-columns: 1fr; } }

  /* Card */
  .card { background: ${COLORS.card}; border: 1px solid ${COLORS.border}; border-radius: 12px; padding: 24px; }

  /* Donut chart */
  .donut-container { display: flex; align-items: center; gap: 32px; }
  .donut-svg { flex-shrink: 0; }
  .donut-legend { display: flex; flex-direction: column; gap: 8px; }
  .legend-item { display: flex; align-items: center; gap: 8px; font-size: 14px; }
  .legend-dot { width: 12px; height: 12px; border-radius: 3px; flex-shrink: 0; }
  .legend-count { font-weight: 700; min-width: 30px; }

  /* Source type bars */
  .source-bars { display: flex; flex-direction: column; gap: 10px; }
  .source-row { display: flex; align-items: center; gap: 12px; }
  .source-label { width: 120px; font-size: 13px; color: ${COLORS.textMuted}; text-align: right; flex-shrink: 0; }
  .source-track { flex: 1; height: 24px; background: ${COLORS.bg}; border-radius: 4px; overflow: hidden; }
  .source-fill { height: 100%; border-radius: 4px; transition: width 0.6s ease; display: flex; align-items: center; justify-content: flex-end; padding-right: 8px; font-size: 12px; font-weight: 600; min-width: 30px; }

  /* SBOM health */
  .health-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-top: 16px; }
  .health-item { text-align: center; }
  .health-num { font-size: 28px; font-weight: 800; }
  .health-lbl { font-size: 12px; color: ${COLORS.textMuted}; text-transform: uppercase; }
  .health-bar { width: 100%; height: 8px; background: ${COLORS.bg}; border-radius: 4px; margin-top: 16px; overflow: hidden; }
  .health-fill { height: 100%; border-radius: 4px; transition: width 0.6s ease; }

  /* App cards */
  .app-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px; }
  .app-card { background: ${COLORS.card}; border: 1px solid ${COLORS.border}; border-radius: 12px; padding: 20px; transition: border-color 0.15s; }
  .app-card:hover { border-color: ${COLORS.accent}40; }
  .app-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 16px; }
  .app-name { font-size: 16px; font-weight: 700; }
  .app-type { font-size: 12px; color: ${COLORS.textMuted}; }
  .risk-badge { font-size: 18px; font-weight: 800; padding: 4px 12px; border-radius: 8px; display: flex; align-items: baseline; gap: 4px; }
  .risk-num { font-size: 12px; font-weight: 600; opacity: 0.7; }
  .sev-bars { margin-bottom: 16px; display: flex; flex-direction: column; gap: 6px; }
  .sev-bar-row { display: flex; align-items: center; gap: 8px; }
  .sev-label { width: 14px; font-size: 12px; font-weight: 700; text-align: center; }
  .sev-bar-track { flex: 1; height: 8px; background: ${COLORS.bg}; border-radius: 4px; overflow: hidden; }
  .sev-bar-fill { height: 100%; border-radius: 4px; transition: width 0.4s ease; min-width: 2px; }
  .sev-count { font-size: 12px; font-weight: 600; width: 24px; text-align: right; color: ${COLORS.textMuted}; }
  .app-stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; border-top: 1px solid ${COLORS.border}; padding-top: 12px; }
  .app-stat { text-align: center; }
  .stat-val { display: block; font-size: 18px; font-weight: 700; }
  .stat-label { font-size: 10px; color: ${COLORS.textMuted}; text-transform: uppercase; }

  /* Tables */
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; padding: 10px 12px; border-bottom: 2px solid ${COLORS.border}; color: ${COLORS.textMuted}; font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; }
  td { padding: 10px 12px; border-bottom: 1px solid ${COLORS.border}20; }
  tr:hover td { background: ${COLORS.cardHover}30; }
  .issue-title { max-width: 350px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

  /* Pills and badges */
  .sev-pill { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
  .fix-badge { background: ${COLORS.success}20; color: ${COLORS.success}; padding: 2px 8px; border-radius: 8px; font-size: 11px; font-weight: 600; }
  .no-fix { color: ${COLORS.textMuted}; font-size: 11px; }
  .fix-action { color: ${COLORS.success}; font-size: 12px; }
  .dep-badge { background: ${COLORS.critical}20; color: ${COLORS.critical}; padding: 2px 8px; border-radius: 8px; font-size: 11px; font-weight: 600; }
  .unm-badge { background: ${COLORS.warning}20; color: ${COLORS.warning}; padding: 2px 8px; border-radius: 8px; font-size: 11px; font-weight: 600; }
  .ok-badge { color: ${COLORS.success}; font-size: 11px; }
  .vuln-counts { white-space: nowrap; }
  .vc { display: inline-block; padding: 1px 6px; border-radius: 6px; font-size: 11px; font-weight: 700; margin-right: 2px; }
  .vc-c { background: ${COLORS.critical}20; color: ${COLORS.critical}; }
  .vc-h { background: ${COLORS.high}20; color: ${COLORS.high}; }
  .vc-m { background: ${COLORS.medium}20; color: ${COLORS.medium}; }
  .vc-l { background: ${COLORS.low}20; color: ${COLORS.low}; }

  /* Footer */
  .footer { text-align: center; color: ${COLORS.textMuted}; font-size: 12px; padding: 24px 0; border-top: 1px solid ${COLORS.border}; margin-top: 32px; }

  /* Tab navigation */
  .tabs { display: flex; gap: 4px; margin-bottom: 24px; background: ${COLORS.card}; border-radius: 12px; padding: 4px; border: 1px solid ${COLORS.border}; }
  .tab { padding: 10px 20px; border-radius: 8px; cursor: pointer; font-size: 14px; font-weight: 600; color: ${COLORS.textMuted}; transition: all 0.15s; border: none; background: none; }
  .tab:hover { color: ${COLORS.text}; background: ${COLORS.bg}; }
  .tab.active { color: ${COLORS.text}; background: ${COLORS.accent}; }
  .tab-content { display: none; }
  .tab-content.active { display: block; }
</style>
</head>
<body>
<div class="container">
  <!-- Header -->
  <div class="header">
    <h1><span>Ox Security</span> — iOS Vulnerability Dashboard</h1>
    <div class="header-meta">
      <div class="data-source">${esc(dataSource)}</div>
      <div>Generated: ${new Date(generatedAt).toLocaleString()}</div>
      <div>Filter: ${esc(APP_FILTER || 'All Applications')}</div>
    </div>
  </div>

  <!-- KPI Row -->
  <div class="kpi-row">
    <div class="kpi-card">
      <div class="kpi-value">${summary.totalApps}</div>
      <div class="kpi-label">Applications</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-value" style="color:${summary.sevTotals.Critical > 0 ? COLORS.critical : COLORS.text}">${summary.totalIssues}</div>
      <div class="kpi-label">Total Issues</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-value" style="color:${COLORS.critical}">${summary.sevTotals.Critical || 0}</div>
      <div class="kpi-label">Critical</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-value" style="color:${COLORS.high}">${summary.sevTotals.High || 0}</div>
      <div class="kpi-label">High</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-value" style="color:${COLORS.success}">${summary.autoFixCount}</div>
      <div class="kpi-label">Auto-fixable</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-value">${summary.totalLibraries}</div>
      <div class="kpi-label">Libraries</div>
    </div>
  </div>

  <!-- Tabs -->
  <div class="tabs">
    <button class="tab active" onclick="showTab('overview')">Overview</button>
    <button class="tab" onclick="showTab('issues')">Issues</button>
    <button class="tab" onclick="showTab('sbom')">SBOM Health</button>
    <button class="tab" onclick="showTab('fixes')">Quick Fixes</button>
  </div>

  <!-- Tab: Overview -->
  <div id="tab-overview" class="tab-content active">
    <div class="two-col">
      <!-- Severity Distribution -->
      <div class="card">
        <div class="section-title">Severity Distribution</div>
        <div class="donut-container">
          <svg class="donut-svg" viewBox="0 0 100 100" width="160" height="160">
            ${donutSegments}
            <text x="50" y="46" text-anchor="middle" fill="${COLORS.text}" font-size="16" font-weight="800">${summary.totalIssues}</text>
            <text x="50" y="58" text-anchor="middle" fill="${COLORS.textMuted}" font-size="7">ISSUES</text>
          </svg>
          <div class="donut-legend">
            ${sevOrder.map(sev => `
              <div class="legend-item">
                <div class="legend-dot" style="background:${sevColorMap[sev]}"></div>
                <span class="legend-count">${summary.sevTotals[sev] || 0}</span>
                <span>${sev}</span>
              </div>
            `).join('')}
          </div>
        </div>
      </div>

      <!-- Source Distribution -->
      <div class="card">
        <div class="section-title">Issue Sources</div>
        <div class="source-bars">
          ${sourceEntries.map(([src, count], idx) => `
            <div class="source-row">
              <span class="source-label">${esc(src)}</span>
              <div class="source-track">
                <div class="source-fill" style="width:${(count / maxSource) * 100}%;background:${sourceColors[idx % sourceColors.length]}">${count}</div>
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    </div>

    <!-- App Cards -->
    <div class="section">
      <div class="section-title">Application Security Posture</div>
      <div class="app-grid">
        ${appCards}
      </div>
    </div>
  </div>

  <!-- Tab: Issues -->
  <div id="tab-issues" class="tab-content">
    <div class="section">
      <div class="section-title">Top Issues by Severity</div>
      <div class="card" style="overflow-x:auto">
        <table>
          <thead><tr><th>#</th><th>Severity</th><th>Issue</th><th>App</th><th>Source</th><th>Fix</th></tr></thead>
          <tbody>${issueRows}</tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Tab: SBOM Health -->
  <div id="tab-sbom" class="tab-content">
    <div class="section">
      <div class="section-title">SBOM Health Overview</div>
      <div class="card">
        <div class="health-grid">
          <div class="health-item">
            <div class="health-num" style="color:${COLORS.text}">${sbomHealth.total}</div>
            <div class="health-lbl">Total Libraries</div>
          </div>
          <div class="health-item">
            <div class="health-num" style="color:${COLORS.critical}">${sbomHealth.vulnerable}</div>
            <div class="health-lbl">Vulnerable</div>
          </div>
          <div class="health-item">
            <div class="health-num" style="color:${COLORS.warning}">${sbomHealth.deprecated}</div>
            <div class="health-lbl">Deprecated</div>
          </div>
          <div class="health-item">
            <div class="health-num" style="color:${COLORS.high}">${sbomHealth.unmaintained}</div>
            <div class="health-lbl">Unmaintained</div>
          </div>
        </div>
        <div class="health-bar">
          <div class="health-fill" style="width:${sbomHealth.healthyPct}%;background:${sbomHealth.healthyPct > 80 ? COLORS.success : sbomHealth.healthyPct > 60 ? COLORS.warning : COLORS.critical}"></div>
        </div>
        <div style="text-align:center;margin-top:8px;font-size:13px;color:${COLORS.textMuted}">${sbomHealth.healthyPct}% of libraries have no known vulnerabilities</div>
      </div>
    </div>

    <div class="section">
      <div class="section-title">Most Vulnerable Libraries</div>
      <div class="card" style="overflow-x:auto">
        <table>
          <thead><tr><th>Library</th><th>Version</th><th>Source</th><th>App</th><th>Vulnerabilities</th><th>Status</th></tr></thead>
          <tbody>${libRows}</tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Tab: Quick Fixes -->
  <div id="tab-fixes" class="tab-content">
    <div class="section">
      <div class="section-title">Auto-Fix Opportunities (${autoFixable.length} available)</div>
      <div class="card" style="overflow-x:auto">
        ${autoFixable.length > 0 ? `
        <table>
          <thead><tr><th>Severity</th><th>Issue</th><th>App</th><th>Fix Action</th></tr></thead>
          <tbody>${fixRows}</tbody>
        </table>
        ` : '<p style="color:' + COLORS.textMuted + ';text-align:center;padding:40px">No auto-fix opportunities found.</p>'}
      </div>
    </div>
  </div>

  <div class="footer">
    Generated by Ox Security Study Toolkit &middot; ${new Date(generatedAt).toISOString().slice(0, 10)} &middot; Data source: ${esc(dataSource)}
  </div>
</div>

<script>
function showTab(name) {
  document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  event.target.classList.add('active');
}
</script>
</body>
</html>`;
}

// HTML escape helper
function esc(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  console.log('Ox Security — HTML Dashboard Generator (E17)');
  console.log('='.repeat(50));

  // Fetch data
  let data;
  if (USE_MOCK) {
    console.log('Using mock data (OX_API_KEY not set)');
    data = getMockData();
    if (APP_FILTER) {
      const f = APP_FILTER.toLowerCase();
      data.apps = data.apps.filter(a => a.appName.toLowerCase().includes(f));
      data.issues = data.issues.filter(i => i.app?.name?.toLowerCase().includes(f));
      data.libraries = data.libraries.filter(l => l.app?.name?.toLowerCase().includes(f));
    }
  } else {
    console.log('Fetching data from Ox Security API...');
    data = await fetchRealData();
  }

  console.log(`  Apps: ${data.apps.length}`);
  console.log(`  Issues: ${data.issues.length}`);
  console.log(`  Libraries: ${data.libraries.length}`);
  console.log('');

  // Analyze
  console.log('Analyzing data...');
  const analysis = analyzeData(data);

  // Generate HTML
  console.log('Generating HTML dashboard...');
  const html = generateHTML(analysis);

  // Write output
  const dateStr = new Date().toISOString().slice(0, 10);
  const outDir = resolve('experiments', `dashboard-${dateStr}`);
  mkdirSync(outDir, { recursive: true });

  const htmlPath = resolve(outDir, 'dashboard.html');
  const jsonPath = resolve(outDir, 'data.json');

  writeFileSync(htmlPath, html);
  writeFileSync(jsonPath, JSON.stringify(analysis, null, 2));

  console.log('');
  console.log('Dashboard generated successfully!');
  console.log(`  HTML: ${htmlPath}`);
  console.log(`  Data: ${jsonPath}`);
  console.log('');
  console.log('Open the HTML file in any browser to view the dashboard.');

  // Print summary stats to stdout
  console.log('');
  console.log('=== Dashboard Summary ===');
  console.log(`  Applications:     ${analysis.summary.totalApps}`);
  console.log(`  Total Issues:     ${analysis.summary.totalIssues}`);
  console.log(`  Critical:         ${analysis.summary.sevTotals.Critical || 0}`);
  console.log(`  High:             ${analysis.summary.sevTotals.High || 0}`);
  console.log(`  Medium:           ${analysis.summary.sevTotals.Medium || 0}`);
  console.log(`  Low:              ${analysis.summary.sevTotals.Low || 0}`);
  console.log(`  Auto-fixable:     ${analysis.summary.autoFixCount}`);
  console.log(`  SBOM Health:      ${analysis.sbomHealth.healthyPct}% clean`);
  console.log(`  Vulnerable libs:  ${analysis.sbomHealth.vulnerable}`);
  console.log(`  Deprecated libs:  ${analysis.sbomHealth.deprecated}`);
}

main().catch(e => { console.error('Error:', e.message); process.exit(1); });
