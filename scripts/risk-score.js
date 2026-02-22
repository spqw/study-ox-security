#!/usr/bin/env node
/**
 * E11: Risk Scoring Model
 *
 * Combines multiple data sources into a composite risk score per app:
 *   - Ox Security risk score (from app metadata)
 *   - Issue severity counts (weighted: Critical=10, High=5, Medium=2, Low=0.5)
 *   - SBOM vulnerability density (vulnerable libs / total libs)
 *   - Maintenance health (deprecated, unmaintained, license issues)
 *   - Transitive risk ratio (what % of risk comes from transitive deps)
 *
 * Each dimension is scored 0-100, then combined with configurable weights
 * into a final composite score. Generates a risk matrix, per-app breakdown,
 * radar-style text profiles, and actionable recommendations.
 *
 * Falls back to realistic mock data when OX_API_KEY is not configured.
 *
 * Usage:
 *   node scripts/risk-score.js [appFilter]
 *
 * Environment:
 *   OX_APP_NAME  — filter to a specific app name
 */
import { writeFileSync, mkdirSync, readFileSync, existsSync } from 'fs';
import { resolve } from 'path';

// ---------------------------------------------------------------------------
// API key detection
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
// Scoring weights and constants
// ---------------------------------------------------------------------------

// How much each severity level contributes to the issue score
const SEV_WEIGHTS = { critical: 10, high: 5, medium: 2, low: 0.5, info: 0 };

// Dimension weights for the final composite score (must sum to 1.0)
const DIMENSION_WEIGHTS = {
  issueRisk:       0.35,  // weighted severity counts
  sbomHealth:      0.25,  // vulnerable/deprecated/unmaintained lib ratio
  transitiveRisk:  0.15,  // what % of vulns come from transitive deps
  maintenanceDebt: 0.15,  // deprecated + unmaintained libs
  oxRiskScore:     0.10,  // Ox's built-in risk score
};

// Risk grade thresholds
const GRADES = [
  { max: 20,  grade: 'A', label: 'Excellent',  bar: '██████████' },
  { max: 40,  grade: 'B', label: 'Good',       bar: '████████░░' },
  { max: 60,  grade: 'C', label: 'Moderate',   bar: '██████░░░░' },
  { max: 80,  grade: 'D', label: 'Poor',       bar: '████░░░░░░' },
  { max: 100, grade: 'F', label: 'Critical',   bar: '██░░░░░░░░' },
];

function getGrade(score) {
  return GRADES.find(g => score <= g.max) || GRADES[GRADES.length - 1];
}

// ---------------------------------------------------------------------------
// Mock data
// ---------------------------------------------------------------------------
function getMockApps() {
  return [
    {
      appId: 'app-1', appName: 'MyBankingApp-iOS', risk: 72, type: 'Mobile',
      businessPriority: 'Critical',
      issuesBySeverity: { critical: 3, high: 8, medium: 14, low: 25, info: 5 },
      appOwners: [{ name: 'Alice Chen', email: 'alice@example.com' }],
      tags: [{ displayName: 'ios' }, { displayName: 'fintech' }],
    },
    {
      appId: 'app-2', appName: 'HealthTracker-iOS', risk: 55, type: 'Mobile',
      businessPriority: 'High',
      issuesBySeverity: { critical: 1, high: 4, medium: 9, low: 18, info: 3 },
      appOwners: [{ name: 'Bob Park', email: 'bob@example.com' }],
      tags: [{ displayName: 'ios' }, { displayName: 'healthcare' }],
    },
    {
      appId: 'app-3', appName: 'ShopEasy-iOS', risk: 68, type: 'Mobile',
      businessPriority: 'Medium',
      issuesBySeverity: { critical: 2, high: 6, medium: 11, low: 20, info: 8 },
      appOwners: [{ name: 'Carol Li', email: 'carol@example.com' }],
      tags: [{ displayName: 'ios' }, { displayName: 'ecommerce' }],
    },
  ];
}

function getMockSBOM() {
  return [
    // MyBankingApp-iOS — 10 libs, 4 vulnerable, 1 unmaintained
    { libraryName: 'Alamofire', libraryVersion: '5.6.4', appName: 'MyBankingApp-iOS', dependencyLevel: 'Direct', vulnerabilityCounts: { critical: 0, high: 2, medium: 1, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'Ono', libraryVersion: '2.5.0', appName: 'MyBankingApp-iOS', dependencyLevel: 'Direct', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: true, isDeprecated: false, licenseIssue: false },
    { libraryName: 'KeychainAccess', libraryVersion: '4.2.2', appName: 'MyBankingApp-iOS', dependencyLevel: 'Direct', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'CryptoSwift', libraryVersion: '1.7.2', appName: 'MyBankingApp-iOS', dependencyLevel: 'Direct', vulnerabilityCounts: { critical: 0, high: 0, medium: 1, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'lodash', libraryVersion: '4.17.19', appName: 'MyBankingApp-iOS', dependencyLevel: 'Direct', vulnerabilityCounts: { critical: 1, high: 0, medium: 1, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'SwiftLint', libraryVersion: '0.54.0', appName: 'MyBankingApp-iOS', dependencyLevel: 'Direct', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'libxml2', libraryVersion: '2.11.6', appName: 'MyBankingApp-iOS', dependencyLevel: 'Transitive', vulnerabilityCounts: { critical: 1, high: 1, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'OpenSSL', libraryVersion: '1.1.1w', appName: 'MyBankingApp-iOS', dependencyLevel: 'Transitive', vulnerabilityCounts: { critical: 0, high: 1, medium: 1, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'BoringSSL-GRPC', libraryVersion: '0.0.27', appName: 'MyBankingApp-iOS', dependencyLevel: 'Transitive', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 1 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'CFNetwork', libraryVersion: '0.0.0', appName: 'MyBankingApp-iOS', dependencyLevel: 'Transitive', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },

    // HealthTracker-iOS — 9 libs, 3 vulnerable
    { libraryName: 'SQLite.swift', libraryVersion: '0.14.1', appName: 'HealthTracker-iOS', dependencyLevel: 'Direct', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'Charts', libraryVersion: '5.0.0', appName: 'HealthTracker-iOS', dependencyLevel: 'Direct', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'Realm', libraryVersion: '10.44.0', appName: 'HealthTracker-iOS', dependencyLevel: 'Direct', vulnerabilityCounts: { critical: 0, high: 0, medium: 1, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'HealthKit', libraryVersion: '17.0', appName: 'HealthTracker-iOS', dependencyLevel: 'Direct', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'SnapKit', libraryVersion: '5.6.0', appName: 'HealthTracker-iOS', dependencyLevel: 'Direct', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'libexpat', libraryVersion: '2.5.0', appName: 'HealthTracker-iOS', dependencyLevel: 'Transitive', vulnerabilityCounts: { critical: 0, high: 1, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'RealmCore', libraryVersion: '13.26.0', appName: 'HealthTracker-iOS', dependencyLevel: 'Transitive', vulnerabilityCounts: { critical: 0, high: 0, medium: 1, low: 1 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'libuv', libraryVersion: '1.44.2', appName: 'HealthTracker-iOS', dependencyLevel: 'Transitive', vulnerabilityCounts: { critical: 0, high: 0, medium: 1, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'sqlite3', libraryVersion: '3.42.0', appName: 'HealthTracker-iOS', dependencyLevel: 'Transitive', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },

    // ShopEasy-iOS — 13 libs, 5 vulnerable, 1 unmaintained, 1 deprecated
    { libraryName: 'react-native', libraryVersion: '0.71.8', appName: 'ShopEasy-iOS', dependencyLevel: 'Direct', vulnerabilityCounts: { critical: 1, high: 2, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'react', libraryVersion: '18.2.0', appName: 'ShopEasy-iOS', dependencyLevel: 'Direct', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: '@react-navigation/native', libraryVersion: '6.1.9', appName: 'ShopEasy-iOS', dependencyLevel: 'Direct', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'stripe-react-native', libraryVersion: '0.35.0', appName: 'ShopEasy-iOS', dependencyLevel: 'Direct', vulnerabilityCounts: { critical: 0, high: 0, medium: 1, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'axios', libraryVersion: '1.6.0', appName: 'ShopEasy-iOS', dependencyLevel: 'Direct', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'moment', libraryVersion: '2.29.4', appName: 'ShopEasy-iOS', dependencyLevel: 'Direct', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: true, isDeprecated: false, licenseIssue: false },
    { libraryName: 'react-native-firebase', libraryVersion: '18.6.0', appName: 'ShopEasy-iOS', dependencyLevel: 'Direct', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'hermes-engine', libraryVersion: '0.71.14', appName: 'ShopEasy-iOS', dependencyLevel: 'Transitive', vulnerabilityCounts: { critical: 1, high: 1, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'jsc-android', libraryVersion: '250231.0.0', appName: 'ShopEasy-iOS', dependencyLevel: 'Transitive', vulnerabilityCounts: { critical: 0, high: 1, medium: 0, low: 0 }, notMaintained: false, isDeprecated: true, licenseIssue: false },
    { libraryName: 'metro', libraryVersion: '0.76.8', appName: 'ShopEasy-iOS', dependencyLevel: 'Transitive', vulnerabilityCounts: { critical: 0, high: 0, medium: 1, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'follow-redirects', libraryVersion: '1.15.3', appName: 'ShopEasy-iOS', dependencyLevel: 'Transitive', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 1 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'nanopb', libraryVersion: '2.30909.0', appName: 'ShopEasy-iOS', dependencyLevel: 'Transitive', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'GoogleUtilities', libraryVersion: '7.12.0', appName: 'ShopEasy-iOS', dependencyLevel: 'Transitive', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
  ];
}

function getMockIssues() {
  // Mock prioritization data (original vs Ox-prioritized severity counts)
  return {
    'MyBankingApp-iOS': {
      original:      { critical: 5, high: 12, medium: 14, low: 25 },
      oxPrioritized: { critical: 3, high: 8,  medium: 14, low: 25 },
    },
    'HealthTracker-iOS': {
      original:      { critical: 2, high: 6,  medium: 9,  low: 18 },
      oxPrioritized: { critical: 1, high: 4,  medium: 9,  low: 18 },
    },
    'ShopEasy-iOS': {
      original:      { critical: 4, high: 9,  medium: 11, low: 20 },
      oxPrioritized: { critical: 2, high: 6,  medium: 11, low: 20 },
    },
  };
}

// ---------------------------------------------------------------------------
// Data fetching (API or mock)
// ---------------------------------------------------------------------------
async function fetchApps(appFilter) {
  if (USE_MOCK) {
    console.log('  [mock mode — no OX_API_KEY]\n');
    let apps = getMockApps();
    if (appFilter) apps = apps.filter(a => a.appName.toLowerCase().includes(appFilter.toLowerCase()));
    return apps;
  }

  const { GET_APPLICATIONS } = await import('../queries/applications.js');
  const data = await queryFn(GET_APPLICATIONS, {
    getApplicationsInput: { offset: 0, limit: 200 },
  });
  let apps = data.getApplications.applications;
  if (appFilter) apps = apps.filter(a => a.appName.toLowerCase().includes(appFilter.toLowerCase()));
  return apps;
}

async function fetchSBOM(appFilter) {
  if (USE_MOCK) return getMockSBOM().filter(l => !appFilter || l.appName.toLowerCase().includes(appFilter.toLowerCase()));

  const { GET_SBOM_LIBRARIES } = await import('../queries/sbom.js');
  let allLibs = [];
  let offset = 0;
  const pageSize = 500;
  while (true) {
    const data = await queryFn(GET_SBOM_LIBRARIES, {
      getSbomLibrariesInput: { offset, limit: pageSize, filters: {}, search: '', owners: [] },
    });
    allLibs = allLibs.concat(data.getSbomLibraries.sbomLibs);
    if (allLibs.length >= data.getSbomLibraries.total) break;
    offset += pageSize;
  }
  if (appFilter) allLibs = allLibs.filter(l => l.appName.toLowerCase().includes(appFilter.toLowerCase()));
  return allLibs;
}

// ---------------------------------------------------------------------------
// Scoring functions — each returns 0-100 (higher = more risk)
// ---------------------------------------------------------------------------

/** Score based on weighted issue severity counts */
function scoreIssueRisk(issuesBySeverity) {
  const sev = issuesBySeverity || {};
  const weighted =
    (sev.critical || 0) * SEV_WEIGHTS.critical +
    (sev.high     || 0) * SEV_WEIGHTS.high +
    (sev.medium   || 0) * SEV_WEIGHTS.medium +
    (sev.low      || 0) * SEV_WEIGHTS.low;
  // Normalize: 0 issues = 0, 100+ weighted points = 100
  return Math.min(100, Math.round(weighted));
}

/** Score based on SBOM vulnerability density */
function scoreSbomHealth(libs) {
  if (libs.length === 0) return 0;
  const vulnCount = libs.filter(l => {
    const vc = l.vulnerabilityCounts || {};
    return ((vc.critical || 0) + (vc.high || 0) + (vc.medium || 0) + (vc.low || 0)) > 0;
  }).length;
  const ratio = vulnCount / libs.length;
  // 0% vulnerable = 0 risk, 50%+ vulnerable = 100 risk
  return Math.min(100, Math.round(ratio * 200));
}

/** Score based on transitive dependency risk */
function scoreTransitiveRisk(libs) {
  if (libs.length === 0) return 0;

  let directWeighted = 0;
  let transitiveWeighted = 0;

  for (const lib of libs) {
    const vc = lib.vulnerabilityCounts || {};
    const w =
      (vc.critical || 0) * SEV_WEIGHTS.critical +
      (vc.high     || 0) * SEV_WEIGHTS.high +
      (vc.medium   || 0) * SEV_WEIGHTS.medium +
      (vc.low      || 0) * SEV_WEIGHTS.low;

    if (lib.dependencyLevel === 'Transitive') {
      transitiveWeighted += w;
    } else {
      directWeighted += w;
    }
  }

  const total = directWeighted + transitiveWeighted;
  if (total === 0) return 0;

  // Higher score = more risk coming from transitive deps (harder to control)
  const transitiveRatio = transitiveWeighted / total;
  return Math.min(100, Math.round(transitiveRatio * 100));
}

/** Score based on maintenance debt (deprecated, unmaintained, license issues) */
function scoreMaintenanceDebt(libs) {
  if (libs.length === 0) return 0;

  let debtCount = 0;
  for (const lib of libs) {
    if (lib.notMaintained) debtCount += 1;
    if (lib.isDeprecated) debtCount += 1.5;  // deprecated is slightly worse
    if (lib.licenseIssue) debtCount += 0.5;
  }

  // Normalize: 0 debt items = 0, 30%+ of libs having issues = 100
  const ratio = debtCount / libs.length;
  return Math.min(100, Math.round(ratio * 333));
}

/** Normalize Ox risk score to 0-100 */
function scoreOxRisk(oxRisk) {
  // Ox risk is already 0-100 scale
  return Math.min(100, Math.max(0, Math.round(oxRisk || 0)));
}

// ---------------------------------------------------------------------------
// Composite scoring
// ---------------------------------------------------------------------------
function computeCompositeScore(dimensions) {
  let composite = 0;
  for (const [key, weight] of Object.entries(DIMENSION_WEIGHTS)) {
    composite += (dimensions[key] || 0) * weight;
  }
  return Math.round(composite);
}

function analyzeApp(app, libs) {
  const dimensions = {
    issueRisk:       scoreIssueRisk(app.issuesBySeverity),
    sbomHealth:      scoreSbomHealth(libs),
    transitiveRisk:  scoreTransitiveRisk(libs),
    maintenanceDebt: scoreMaintenanceDebt(libs),
    oxRiskScore:     scoreOxRisk(app.risk),
  };

  const composite = computeCompositeScore(dimensions);
  const grade = getGrade(composite);

  // SBOM summary stats
  const totalLibs = libs.length;
  const directLibs = libs.filter(l => l.dependencyLevel === 'Direct').length;
  const transitiveLibs = libs.filter(l => l.dependencyLevel === 'Transitive').length;
  const vulnLibs = libs.filter(l => {
    const vc = l.vulnerabilityCounts || {};
    return ((vc.critical || 0) + (vc.high || 0) + (vc.medium || 0) + (vc.low || 0)) > 0;
  }).length;
  const deprecatedLibs = libs.filter(l => l.isDeprecated).length;
  const unmaintainedLibs = libs.filter(l => l.notMaintained).length;
  const licenseIssueLibs = libs.filter(l => l.licenseIssue).length;

  // Top risky libs
  const riskySorted = [...libs]
    .map(l => {
      const vc = l.vulnerabilityCounts || {};
      const w =
        (vc.critical || 0) * SEV_WEIGHTS.critical +
        (vc.high     || 0) * SEV_WEIGHTS.high +
        (vc.medium   || 0) * SEV_WEIGHTS.medium +
        (vc.low      || 0) * SEV_WEIGHTS.low;
      return { ...l, riskWeight: w };
    })
    .filter(l => l.riskWeight > 0)
    .sort((a, b) => b.riskWeight - a.riskWeight);

  return {
    appName: app.appName,
    appId: app.appId,
    type: app.type,
    businessPriority: app.businessPriority,
    owners: app.appOwners?.map(o => o.name || o.email) || [],
    tags: app.tags?.map(t => t.displayName) || [],
    issuesBySeverity: app.issuesBySeverity,
    dimensions,
    composite,
    grade: grade.grade,
    gradeLabel: grade.label,
    sbomStats: { totalLibs, directLibs, transitiveLibs, vulnLibs, deprecatedLibs, unmaintainedLibs, licenseIssueLibs },
    topRiskyLibs: riskySorted.slice(0, 5),
  };
}

// ---------------------------------------------------------------------------
// Recommendations engine
// ---------------------------------------------------------------------------
function generateRecommendations(results) {
  const recs = [];

  for (const r of results) {
    const d = r.dimensions;
    const prefix = `**${r.appName}**`;

    if (d.issueRisk >= 80) {
      recs.push({ app: r.appName, priority: 'Critical', text: `${prefix}: Very high issue burden (score ${d.issueRisk}/100). Focus on resolving critical and high severity issues first.` });
    } else if (d.issueRisk >= 60) {
      recs.push({ app: r.appName, priority: 'High', text: `${prefix}: Elevated issue count (score ${d.issueRisk}/100). Prioritize fixing critical issues, then high severity.` });
    }

    if (d.sbomHealth >= 60) {
      recs.push({ app: r.appName, priority: 'High', text: `${prefix}: ${r.sbomStats.vulnLibs}/${r.sbomStats.totalLibs} libraries have known vulnerabilities (score ${d.sbomHealth}/100). Run dependency updates.` });
    }

    if (d.transitiveRisk >= 70) {
      recs.push({ app: r.appName, priority: 'Medium', text: `${prefix}: ${d.transitiveRisk}% of vulnerability risk comes from transitive dependencies. Review direct deps that pull in risky transitive deps.` });
    }

    if (d.maintenanceDebt >= 40) {
      recs.push({ app: r.appName, priority: 'Medium', text: `${prefix}: Maintenance debt detected — ${r.sbomStats.deprecatedLibs} deprecated, ${r.sbomStats.unmaintainedLibs} unmaintained libraries. Plan migration.` });
    }

    if (r.topRiskyLibs.length > 0) {
      const top = r.topRiskyLibs[0];
      recs.push({ app: r.appName, priority: 'High', text: `${prefix}: Highest-risk library is ${top.libraryName}@${top.libraryVersion} (risk weight ${top.riskWeight}). Check for available updates.` });
    }
  }

  // Sort by priority
  const prioOrder = { Critical: 0, High: 1, Medium: 2, Low: 3 };
  recs.sort((a, b) => (prioOrder[a.priority] ?? 9) - (prioOrder[b.priority] ?? 9));
  return recs;
}

// ---------------------------------------------------------------------------
// Text rendering helpers
// ---------------------------------------------------------------------------

/** Render a text-based radar/bar profile for a single app's dimensions */
function renderRadarProfile(result) {
  const d = result.dimensions;
  const lines = [];
  const maxLabel = 18;
  const barWidth = 30;

  const dims = [
    { label: 'Issue Risk',       value: d.issueRisk },
    { label: 'SBOM Health',      value: d.sbomHealth },
    { label: 'Transitive Risk',  value: d.transitiveRisk },
    { label: 'Maintenance Debt', value: d.maintenanceDebt },
    { label: 'Ox Risk Score',    value: d.oxRiskScore },
  ];

  for (const dim of dims) {
    const filledLen = Math.round((dim.value / 100) * barWidth);
    const bar = '\u2588'.repeat(filledLen) + '\u2591'.repeat(barWidth - filledLen);
    const label = dim.label.padEnd(maxLabel);
    lines.push(`  ${label} ${bar} ${String(dim.value).padStart(3)}/100`);
  }

  return lines.join('\n');
}

/** Render comparison table of all apps */
function renderComparisonTable(results) {
  // Header
  const nameW = Math.max(20, ...results.map(r => r.appName.length + 2));
  const hdr = [
    'App'.padEnd(nameW),
    'Score'.padStart(5),
    'Grd',
    'Issues'.padStart(6),
    'SBOM'.padStart(6),
    'Trans'.padStart(6),
    'Maint'.padStart(6),
    'OxRsk'.padStart(6),
    'Priority',
  ].join(' | ');

  const sep = '-'.repeat(hdr.length);
  const rows = results.map(r => {
    const d = r.dimensions;
    return [
      r.appName.padEnd(nameW),
      String(r.composite).padStart(5),
      ` ${r.grade} `,
      String(d.issueRisk).padStart(6),
      String(d.sbomHealth).padStart(6),
      String(d.transitiveRisk).padStart(6),
      String(d.maintenanceDebt).padStart(6),
      String(d.oxRiskScore).padStart(6),
      r.businessPriority || 'N/A',
    ].join(' | ');
  });

  return [hdr, sep, ...rows].join('\n');
}

// ---------------------------------------------------------------------------
// Output generation
// ---------------------------------------------------------------------------
function generateConsoleOutput(results, recs) {
  const lines = [];

  lines.push('');
  lines.push('='.repeat(70));
  lines.push('  E11: Composite Risk Scoring Model');
  lines.push('  Ox Security — iOS App Risk Analysis');
  lines.push('='.repeat(70));
  lines.push('');

  if (USE_MOCK) {
    lines.push('[Mock Mode — using realistic sample data]');
    lines.push('');
  }

  // Scoring methodology
  lines.push('Scoring Methodology');
  lines.push('-'.repeat(40));
  lines.push('  Five dimensions scored 0-100 (higher = more risk):');
  lines.push(`    Issue Risk       (${(DIMENSION_WEIGHTS.issueRisk * 100).toFixed(0)}%) — weighted severity: C*${SEV_WEIGHTS.critical} H*${SEV_WEIGHTS.high} M*${SEV_WEIGHTS.medium} L*${SEV_WEIGHTS.low}`);
  lines.push(`    SBOM Health      (${(DIMENSION_WEIGHTS.sbomHealth * 100).toFixed(0)}%) — vulnerable library density`);
  lines.push(`    Transitive Risk  (${(DIMENSION_WEIGHTS.transitiveRisk * 100).toFixed(0)}%) — % of risk from transitive deps`);
  lines.push(`    Maintenance Debt (${(DIMENSION_WEIGHTS.maintenanceDebt * 100).toFixed(0)}%) — deprecated/unmaintained/license`);
  lines.push(`    Ox Risk Score    (${(DIMENSION_WEIGHTS.oxRiskScore * 100).toFixed(0)}%) — Ox Security built-in score`);
  lines.push('');
  lines.push('  Grades: A (0-20 Excellent) | B (21-40 Good) | C (41-60 Moderate) | D (61-80 Poor) | F (81-100 Critical)');
  lines.push('');

  // Comparison table
  lines.push('Risk Comparison Matrix');
  lines.push('-'.repeat(40));
  lines.push(renderComparisonTable(results));
  lines.push('');

  // Per-app profiles
  lines.push('Per-App Risk Profiles');
  lines.push('-'.repeat(40));
  for (const r of results) {
    const g = getGrade(r.composite);
    lines.push('');
    lines.push(`  ${r.appName}  [${g.grade}] ${g.label}  —  Composite: ${r.composite}/100  ${g.bar}`);
    lines.push(`  Type: ${r.type} | Priority: ${r.businessPriority || 'N/A'} | Owners: ${r.owners.join(', ') || 'N/A'}`);
    const sev = r.issuesBySeverity || {};
    lines.push(`  Issues: C:${sev.critical || 0} H:${sev.high || 0} M:${sev.medium || 0} L:${sev.low || 0}`);
    lines.push(`  SBOM: ${r.sbomStats.totalLibs} libs (${r.sbomStats.directLibs} direct, ${r.sbomStats.transitiveLibs} transitive) — ${r.sbomStats.vulnLibs} vulnerable`);
    if (r.sbomStats.deprecatedLibs || r.sbomStats.unmaintainedLibs || r.sbomStats.licenseIssueLibs) {
      lines.push(`  Flags: ${r.sbomStats.deprecatedLibs} deprecated, ${r.sbomStats.unmaintainedLibs} unmaintained, ${r.sbomStats.licenseIssueLibs} license issues`);
    }
    lines.push('');
    lines.push(renderRadarProfile(r));
    lines.push('');

    if (r.topRiskyLibs.length > 0) {
      lines.push('  Top risky libraries:');
      for (const lib of r.topRiskyLibs) {
        const vc = lib.vulnerabilityCounts || {};
        lines.push(`    - ${lib.libraryName}@${lib.libraryVersion} (${lib.dependencyLevel}) — C:${vc.critical||0} H:${vc.high||0} M:${vc.medium||0} L:${vc.low||0} [weight: ${lib.riskWeight}]`);
      }
    }
    lines.push('');
  }

  // Recommendations
  if (recs.length > 0) {
    lines.push('Recommendations');
    lines.push('-'.repeat(40));
    for (const rec of recs) {
      const icon = { Critical: '[!!!]', High: '[!!]', Medium: '[!]', Low: '[.]' }[rec.priority] || '[?]';
      lines.push(`  ${icon} ${rec.text}`);
    }
    lines.push('');
  }

  // Overall fleet summary
  lines.push('Fleet Summary');
  lines.push('-'.repeat(40));
  const avgScore = Math.round(results.reduce((s, r) => s + r.composite, 0) / results.length);
  const worstApp = results.reduce((w, r) => r.composite > w.composite ? r : w, results[0]);
  const bestApp = results.reduce((b, r) => r.composite < b.composite ? r : b, results[0]);
  const avgGrade = getGrade(avgScore);
  lines.push(`  Apps analyzed:   ${results.length}`);
  lines.push(`  Average score:   ${avgScore}/100 [${avgGrade.grade}] ${avgGrade.label}`);
  lines.push(`  Highest risk:    ${worstApp.appName} (${worstApp.composite}/100 [${worstApp.grade}])`);
  lines.push(`  Lowest risk:     ${bestApp.appName} (${bestApp.composite}/100 [${bestApp.grade}])`);
  lines.push('');

  return lines.join('\n');
}

function generateMarkdownReport(results, recs, timestamp) {
  const lines = [];

  lines.push('# E11: Composite Risk Scoring Model');
  lines.push(`\n*Generated: ${timestamp}*`);
  if (USE_MOCK) lines.push('\n> **Mock Mode** — using realistic sample data (no OX_API_KEY configured)');
  lines.push('');

  // Methodology
  lines.push('## Scoring Methodology');
  lines.push('');
  lines.push('Five risk dimensions are independently scored 0-100 (higher = more risk), then combined with weighted averaging:');
  lines.push('');
  lines.push('| Dimension | Weight | Description |');
  lines.push('|-----------|--------|-------------|');
  lines.push(`| Issue Risk | ${(DIMENSION_WEIGHTS.issueRisk * 100).toFixed(0)}% | Weighted severity counts (C*${SEV_WEIGHTS.critical}, H*${SEV_WEIGHTS.high}, M*${SEV_WEIGHTS.medium}, L*${SEV_WEIGHTS.low}) |`);
  lines.push(`| SBOM Health | ${(DIMENSION_WEIGHTS.sbomHealth * 100).toFixed(0)}% | Ratio of vulnerable libraries to total libraries |`);
  lines.push(`| Transitive Risk | ${(DIMENSION_WEIGHTS.transitiveRisk * 100).toFixed(0)}% | Percentage of total risk coming from transitive dependencies |`);
  lines.push(`| Maintenance Debt | ${(DIMENSION_WEIGHTS.maintenanceDebt * 100).toFixed(0)}% | Deprecated, unmaintained, and license-issue libraries |`);
  lines.push(`| Ox Risk Score | ${(DIMENSION_WEIGHTS.oxRiskScore * 100).toFixed(0)}% | Ox Security's built-in risk assessment |`);
  lines.push('');
  lines.push('**Grades:** A (0-20 Excellent) | B (21-40 Good) | C (41-60 Moderate) | D (61-80 Poor) | F (81-100 Critical)');
  lines.push('');

  // Comparison table
  lines.push('## Risk Comparison Matrix');
  lines.push('');
  lines.push('| App | Composite | Grade | Issue Risk | SBOM | Transitive | Maint Debt | Ox Risk | Priority |');
  lines.push('|-----|-----------|-------|------------|------|------------|------------|---------|----------|');
  for (const r of results) {
    const d = r.dimensions;
    lines.push(`| ${r.appName} | **${r.composite}**/100 | **${r.grade}** ${r.gradeLabel} | ${d.issueRisk} | ${d.sbomHealth} | ${d.transitiveRisk} | ${d.maintenanceDebt} | ${d.oxRiskScore} | ${r.businessPriority || 'N/A'} |`);
  }
  lines.push('');

  // Per-app detail
  lines.push('## Per-App Risk Profiles');
  for (const r of results) {
    lines.push('');
    lines.push(`### ${r.appName} — Grade ${r.grade} (${r.composite}/100)`);
    lines.push('');
    lines.push(`- **Type:** ${r.type}`);
    lines.push(`- **Business Priority:** ${r.businessPriority || 'N/A'}`);
    lines.push(`- **Owners:** ${r.owners.join(', ') || 'N/A'}`);
    if (r.tags.length) lines.push(`- **Tags:** ${r.tags.join(', ')}`);

    const sev = r.issuesBySeverity || {};
    lines.push(`- **Issues:** Critical: ${sev.critical || 0}, High: ${sev.high || 0}, Medium: ${sev.medium || 0}, Low: ${sev.low || 0}`);
    lines.push(`- **SBOM:** ${r.sbomStats.totalLibs} libraries (${r.sbomStats.directLibs} direct, ${r.sbomStats.transitiveLibs} transitive)`);
    lines.push(`- **Vulnerable libraries:** ${r.sbomStats.vulnLibs}/${r.sbomStats.totalLibs}`);

    if (r.sbomStats.deprecatedLibs || r.sbomStats.unmaintainedLibs || r.sbomStats.licenseIssueLibs) {
      lines.push(`- **Flags:** ${r.sbomStats.deprecatedLibs} deprecated, ${r.sbomStats.unmaintainedLibs} unmaintained, ${r.sbomStats.licenseIssueLibs} license issues`);
    }

    lines.push('');
    lines.push('#### Dimension Scores');
    lines.push('');
    lines.push('```');
    lines.push(renderRadarProfile(r));
    lines.push('```');

    if (r.topRiskyLibs.length > 0) {
      lines.push('');
      lines.push('#### Top Risky Libraries');
      lines.push('');
      lines.push('| Library | Version | Level | C | H | M | L | Risk Weight |');
      lines.push('|---------|---------|-------|---|---|---|---|-------------|');
      for (const lib of r.topRiskyLibs) {
        const vc = lib.vulnerabilityCounts || {};
        lines.push(`| ${lib.libraryName} | ${lib.libraryVersion} | ${lib.dependencyLevel} | ${vc.critical||0} | ${vc.high||0} | ${vc.medium||0} | ${vc.low||0} | ${lib.riskWeight} |`);
      }
    }
  }
  lines.push('');

  // Recommendations
  if (recs.length > 0) {
    lines.push('## Recommendations');
    lines.push('');
    for (const rec of recs) {
      const icon = { Critical: '🔴', High: '🟠', Medium: '🟡', Low: '🔵' }[rec.priority] || '⚪';
      lines.push(`- ${icon} **[${rec.priority}]** ${rec.text}`);
    }
    lines.push('');
  }

  // Fleet summary
  lines.push('## Fleet Summary');
  lines.push('');
  const avgScore = Math.round(results.reduce((s, r) => s + r.composite, 0) / results.length);
  const avgGrade = getGrade(avgScore);
  const worstApp = results.reduce((w, r) => r.composite > w.composite ? r : w, results[0]);
  const bestApp = results.reduce((b, r) => r.composite < b.composite ? r : b, results[0]);
  lines.push(`| Metric | Value |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Apps analyzed | ${results.length} |`);
  lines.push(`| Average composite score | ${avgScore}/100 [${avgGrade.grade}] ${avgGrade.label} |`);
  lines.push(`| Highest risk | ${worstApp.appName} (${worstApp.composite}/100) |`);
  lines.push(`| Lowest risk | ${bestApp.appName} (${bestApp.composite}/100) |`);
  lines.push('');

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  const appFilter = process.env.OX_APP_NAME || process.argv[2] || '';
  const timestamp = new Date().toISOString();

  console.log('E11: Risk Scoring Model');
  console.log('Fetching data...');

  // Fetch all data sources
  const apps = await fetchApps(appFilter);
  const allLibs = await fetchSBOM(appFilter);

  if (apps.length === 0) {
    console.log('No applications found.');
    return;
  }

  // Group SBOM by app
  const libsByApp = {};
  for (const lib of allLibs) {
    if (!libsByApp[lib.appName]) libsByApp[lib.appName] = [];
    libsByApp[lib.appName].push(lib);
  }

  // Analyze each app
  const results = apps
    .map(app => analyzeApp(app, libsByApp[app.appName] || []))
    .sort((a, b) => b.composite - a.composite); // highest risk first

  // Generate recommendations
  const recs = generateRecommendations(results);

  // Console output
  const consoleOutput = generateConsoleOutput(results, recs);
  console.log(consoleOutput);

  // Write results to experiments/
  const dateStr = timestamp.slice(0, 10);
  const outDir = resolve(process.cwd(), 'experiments', `risk-scores-${dateStr}`);
  mkdirSync(outDir, { recursive: true });

  // JSON export
  const jsonData = {
    timestamp,
    methodology: {
      severityWeights: SEV_WEIGHTS,
      dimensionWeights: DIMENSION_WEIGHTS,
      gradeThresholds: GRADES.map(g => ({ max: g.max, grade: g.grade, label: g.label })),
    },
    results,
    recommendations: recs,
    fleetSummary: {
      appsAnalyzed: results.length,
      averageScore: Math.round(results.reduce((s, r) => s + r.composite, 0) / results.length),
      highestRisk: results[0]?.appName,
      lowestRisk: results[results.length - 1]?.appName,
    },
  };
  writeFileSync(resolve(outDir, 'risk-scores.json'), JSON.stringify(jsonData, null, 2));

  // Markdown report
  const mdReport = generateMarkdownReport(results, recs, timestamp);
  writeFileSync(resolve(outDir, 'risk-report.md'), mdReport);

  console.log(`Results written to experiments/risk-scores-${dateStr}/`);
  console.log(`  - risk-scores.json  (machine-readable)`);
  console.log(`  - risk-report.md    (human-readable)`);
}

main().catch(e => { console.error('Error:', e.message); process.exit(1); });
