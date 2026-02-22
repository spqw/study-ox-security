#!/usr/bin/env node
/**
 * E14: Deprecated Dependency Alert
 *
 * Scans the SBOM for deprecated and unmaintained libraries, then ranks them
 * by a composite risk score combining:
 *   - Deprecation status (deprecated > unmaintained > active)
 *   - Vulnerability exposure (weighted severity counts)
 *   - Dependency level (direct deps are higher priority than transitive)
 *   - Age signals (version staleness heuristics)
 *
 * Produces a prioritized alert list with per-app breakdowns, migration
 * urgency ratings, and actionable recommendations.
 *
 * Falls back to realistic mock data when OX_API_KEY is not configured.
 *
 * Usage:
 *   node scripts/deprecated-deps.js [appFilter]
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
// Risk scoring constants
// ---------------------------------------------------------------------------

// Severity weights for vulnerability scoring
const SEV_WEIGHTS = { critical: 10, high: 5, medium: 2, low: 0.5, info: 0 };

// Migration urgency thresholds
const URGENCY_LEVELS = [
  { min: 80, label: 'CRITICAL',  icon: '[!!!]', description: 'Immediate replacement required' },
  { min: 60, label: 'HIGH',      icon: '[!!]',  description: 'Plan replacement within 1 sprint' },
  { min: 40, label: 'MEDIUM',    icon: '[!]',   description: 'Schedule replacement this quarter' },
  { min: 0,  label: 'LOW',       icon: '[.]',   description: 'Monitor and replace when convenient' },
];

function getUrgency(score) {
  return URGENCY_LEVELS.find(u => score >= u.min) || URGENCY_LEVELS[URGENCY_LEVELS.length - 1];
}

// ---------------------------------------------------------------------------
// Known alternatives database — maps deprecated/unmaintained libs to suggested replacements
// ---------------------------------------------------------------------------
const KNOWN_ALTERNATIVES = {
  // iOS / CocoaPods
  'Ono':                    { alt: 'SWXMLHash or XMLCoder', reason: 'Ono is unmaintained since 2019; SWXMLHash is actively maintained pure Swift' },
  'AFNetworking':           { alt: 'Alamofire', reason: 'AFNetworking is deprecated; Alamofire is the standard Swift networking library' },
  'UIWebView':              { alt: 'WKWebView', reason: 'UIWebView was deprecated in iOS 12 and rejected by App Store since 2020' },
  'MBProgressHUD':          { alt: 'SVProgressHUD or SwiftUI ProgressView', reason: 'MBProgressHUD has minimal maintenance' },
  'iCarousel':              { alt: 'UICollectionView compositional layout', reason: 'iCarousel is unmaintained; use UIKit\'s built-in compositional layouts' },
  'FMDB':                   { alt: 'SQLite.swift or GRDB.swift', reason: 'FMDB is an Obj-C wrapper with declining maintenance; modern Swift alternatives exist' },
  'RestKit':                { alt: 'Alamofire + Codable', reason: 'RestKit is unmaintained; Swift Codable with Alamofire covers all use cases' },
  'CocoaAsyncSocket':       { alt: 'Network.framework (NWConnection)', reason: 'Apple\'s Network framework replaces third-party socket libraries' },
  'AsyncDisplayKit':        { alt: 'SwiftUI or UICollectionView diffable data sources', reason: 'AsyncDisplayKit (Texture) has minimal maintenance' },
  'RNCryptor':              { alt: 'CryptoKit', reason: 'Apple\'s CryptoKit (iOS 13+) provides native encryption APIs' },

  // JavaScript / React Native
  'moment':                 { alt: 'date-fns or luxon', reason: 'moment.js is officially in maintenance mode since 2020; date-fns is tree-shakeable' },
  'jsc-android':            { alt: 'hermes-engine', reason: 'JSC for Android is deprecated; Hermes is the default RN JS engine since RN 0.70' },
  'request':                { alt: 'node-fetch or axios', reason: 'request is deprecated since 2020' },
  'lodash':                 { alt: 'Native ES6+ methods or lodash-es (tree-shakeable)', reason: 'Many lodash utilities now have native equivalents; use targeted imports' },
  'node-uuid':              { alt: 'uuid', reason: 'node-uuid was renamed to uuid' },
  'react-native-camera':    { alt: 'react-native-vision-camera', reason: 'react-native-camera is deprecated; vision-camera is the maintained replacement' },
  'react-native-fs':        { alt: '@dr.pogodin/react-native-fs', reason: 'Original react-native-fs is unmaintained; community fork is active' },
  'react-native-image-picker': { alt: 'react-native-image-crop-picker or expo-image-picker', reason: 'Original package has irregular maintenance' },

  // General
  'OpenSSL':                { alt: 'BoringSSL or Apple Security framework', reason: 'OpenSSL 1.1.x is EOL; use BoringSSL or Apple\'s native crypto' },
  'libxml2':                { alt: 'libxml2 2.12+ or native XMLParser', reason: 'Old libxml2 versions have CVEs; update to latest or use native parsers' },
  'follow-redirects':       { alt: 'undici or native fetch', reason: 'Has had repeated security issues; native fetch handles redirects' },
};

// ---------------------------------------------------------------------------
// Mock data — enriched with deprecation/unmaintained flags and varied risk profiles
// ---------------------------------------------------------------------------
function getMockSBOM() {
  return [
    // MyBankingApp-iOS — 12 libs, 2 deprecated, 2 unmaintained
    { libraryName: 'Alamofire',       libraryVersion: '5.6.4',     appName: 'MyBankingApp-iOS',  dependencyLevel: 'Direct',     source: 'Swift Package Manager', license: 'MIT', vulnerabilityCounts: { critical: 0, high: 2, medium: 1, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'Ono',             libraryVersion: '2.5.0',     appName: 'MyBankingApp-iOS',  dependencyLevel: 'Direct',     source: 'CocoaPods',             license: 'MIT', vulnerabilityCounts: { critical: 0, high: 0, medium: 1, low: 0 }, notMaintained: true,  isDeprecated: false, licenseIssue: false },
    { libraryName: 'KeychainAccess',  libraryVersion: '4.2.2',     appName: 'MyBankingApp-iOS',  dependencyLevel: 'Direct',     source: 'Swift Package Manager', license: 'MIT', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'CryptoSwift',     libraryVersion: '1.7.2',     appName: 'MyBankingApp-iOS',  dependencyLevel: 'Direct',     source: 'Swift Package Manager', license: 'MIT', vulnerabilityCounts: { critical: 0, high: 0, medium: 1, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'lodash',          libraryVersion: '4.17.19',   appName: 'MyBankingApp-iOS',  dependencyLevel: 'Direct',     source: 'npm',                   license: 'MIT', vulnerabilityCounts: { critical: 1, high: 0, medium: 1, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'SwiftLint',       libraryVersion: '0.54.0',    appName: 'MyBankingApp-iOS',  dependencyLevel: 'Direct',     source: 'Swift Package Manager', license: 'MIT', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'AFNetworking',    libraryVersion: '4.0.1',     appName: 'MyBankingApp-iOS',  dependencyLevel: 'Direct',     source: 'CocoaPods',             license: 'MIT', vulnerabilityCounts: { critical: 0, high: 1, medium: 2, low: 0 }, notMaintained: false, isDeprecated: true,  licenseIssue: false },
    { libraryName: 'libxml2',         libraryVersion: '2.11.6',    appName: 'MyBankingApp-iOS',  dependencyLevel: 'Transitive', source: 'CocoaPods',             license: 'MIT', vulnerabilityCounts: { critical: 1, high: 1, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'OpenSSL',         libraryVersion: '1.1.1w',    appName: 'MyBankingApp-iOS',  dependencyLevel: 'Transitive', source: 'CocoaPods',             license: 'OpenSSL', vulnerabilityCounts: { critical: 0, high: 1, medium: 1, low: 0 }, notMaintained: true,  isDeprecated: false, licenseIssue: false },
    { libraryName: 'BoringSSL-GRPC',  libraryVersion: '0.0.27',    appName: 'MyBankingApp-iOS',  dependencyLevel: 'Transitive', source: 'CocoaPods',             license: 'ISC', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 1 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'CocoaAsyncSocket', libraryVersion: '7.6.5',    appName: 'MyBankingApp-iOS',  dependencyLevel: 'Direct',     source: 'CocoaPods',             license: 'Public Domain', vulnerabilityCounts: { critical: 0, high: 0, medium: 1, low: 1 }, notMaintained: true, isDeprecated: false, licenseIssue: false },
    { libraryName: 'CFNetwork',       libraryVersion: '0.0.0',     appName: 'MyBankingApp-iOS',  dependencyLevel: 'Transitive', source: 'CocoaPods',             license: 'Apple', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },

    // HealthTracker-iOS — 10 libs, 1 deprecated, 2 unmaintained
    { libraryName: 'SQLite.swift',    libraryVersion: '0.14.1',    appName: 'HealthTracker-iOS', dependencyLevel: 'Direct',     source: 'Swift Package Manager', license: 'MIT', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'Charts',          libraryVersion: '5.0.0',     appName: 'HealthTracker-iOS', dependencyLevel: 'Direct',     source: 'Swift Package Manager', license: 'Apache-2.0', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'Realm',           libraryVersion: '10.44.0',   appName: 'HealthTracker-iOS', dependencyLevel: 'Direct',     source: 'CocoaPods',             license: 'Apache-2.0', vulnerabilityCounts: { critical: 0, high: 0, medium: 1, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'SnapKit',         libraryVersion: '5.6.0',     appName: 'HealthTracker-iOS', dependencyLevel: 'Direct',     source: 'Swift Package Manager', license: 'MIT', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'FMDB',            libraryVersion: '2.7.5',     appName: 'HealthTracker-iOS', dependencyLevel: 'Direct',     source: 'CocoaPods',             license: 'MIT', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 1 }, notMaintained: true,  isDeprecated: false, licenseIssue: false },
    { libraryName: 'AsyncDisplayKit', libraryVersion: '3.1.0',     appName: 'HealthTracker-iOS', dependencyLevel: 'Direct',     source: 'CocoaPods',             license: 'Apache-2.0', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: true,  isDeprecated: false, licenseIssue: false },
    { libraryName: 'libexpat',        libraryVersion: '2.5.0',     appName: 'HealthTracker-iOS', dependencyLevel: 'Transitive', source: 'CocoaPods',             license: 'MIT', vulnerabilityCounts: { critical: 0, high: 1, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'RealmCore',       libraryVersion: '13.26.0',   appName: 'HealthTracker-iOS', dependencyLevel: 'Transitive', source: 'CocoaPods',             license: 'Apache-2.0', vulnerabilityCounts: { critical: 0, high: 0, medium: 1, low: 1 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'libuv',           libraryVersion: '1.44.2',    appName: 'HealthTracker-iOS', dependencyLevel: 'Transitive', source: 'CocoaPods',             license: 'MIT', vulnerabilityCounts: { critical: 0, high: 0, medium: 1, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'RNCryptor',       libraryVersion: '5.1.0',     appName: 'HealthTracker-iOS', dependencyLevel: 'Direct',     source: 'CocoaPods',             license: 'MIT', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: true,  licenseIssue: false },

    // ShopEasy-iOS — 14 libs, 2 deprecated, 1 unmaintained
    { libraryName: 'react-native',             libraryVersion: '0.71.8',    appName: 'ShopEasy-iOS', dependencyLevel: 'Direct',     source: 'npm', license: 'MIT', vulnerabilityCounts: { critical: 1, high: 2, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'react',                    libraryVersion: '18.2.0',    appName: 'ShopEasy-iOS', dependencyLevel: 'Direct',     source: 'npm', license: 'MIT', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: '@react-navigation/native', libraryVersion: '6.1.9',     appName: 'ShopEasy-iOS', dependencyLevel: 'Direct',     source: 'npm', license: 'MIT', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'stripe-react-native',      libraryVersion: '0.35.0',    appName: 'ShopEasy-iOS', dependencyLevel: 'Direct',     source: 'npm', license: 'MIT', vulnerabilityCounts: { critical: 0, high: 0, medium: 1, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'moment',                   libraryVersion: '2.29.4',    appName: 'ShopEasy-iOS', dependencyLevel: 'Direct',     source: 'npm', license: 'MIT', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: true,  isDeprecated: false, licenseIssue: false },
    { libraryName: 'react-native-firebase',    libraryVersion: '18.6.0',    appName: 'ShopEasy-iOS', dependencyLevel: 'Direct',     source: 'npm', license: 'Apache-2.0', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'hermes-engine',            libraryVersion: '0.71.14',   appName: 'ShopEasy-iOS', dependencyLevel: 'Transitive', source: 'npm', license: 'MIT', vulnerabilityCounts: { critical: 1, high: 1, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'jsc-android',              libraryVersion: '250231.0.0',appName: 'ShopEasy-iOS', dependencyLevel: 'Transitive', source: 'npm', license: 'BSD-2-Clause', vulnerabilityCounts: { critical: 0, high: 1, medium: 0, low: 0 }, notMaintained: false, isDeprecated: true,  licenseIssue: false },
    { libraryName: 'metro',                    libraryVersion: '0.76.8',    appName: 'ShopEasy-iOS', dependencyLevel: 'Transitive', source: 'npm', license: 'MIT', vulnerabilityCounts: { critical: 0, high: 0, medium: 1, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'follow-redirects',         libraryVersion: '1.15.3',    appName: 'ShopEasy-iOS', dependencyLevel: 'Transitive', source: 'npm', license: 'MIT', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 1 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'nanopb',                   libraryVersion: '2.30909.0', appName: 'ShopEasy-iOS', dependencyLevel: 'Transitive', source: 'CocoaPods', license: 'Zlib', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'GoogleUtilities',          libraryVersion: '7.12.0',    appName: 'ShopEasy-iOS', dependencyLevel: 'Transitive', source: 'CocoaPods', license: 'Apache-2.0', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'iCarousel',                libraryVersion: '1.8.3',     appName: 'ShopEasy-iOS', dependencyLevel: 'Direct',     source: 'CocoaPods', license: 'GPL-3.0', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: true,  isDeprecated: true,  licenseIssue: true },
    { libraryName: 'analytics-swift',          libraryVersion: '1.5.3',     appName: 'ShopEasy-iOS', dependencyLevel: 'Direct',     source: 'Swift Package Manager', license: 'MIT', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
  ];
}

// ---------------------------------------------------------------------------
// Data fetching
// ---------------------------------------------------------------------------
async function fetchSBOM(appFilter) {
  if (USE_MOCK) {
    console.log('  [mock mode — no OX_API_KEY]\n');
    let libs = getMockSBOM();
    if (appFilter) libs = libs.filter(l => l.appName.toLowerCase().includes(appFilter.toLowerCase()));
    return libs;
  }

  const { GET_SBOM_LIBRARIES } = await import('../queries/sbom.js');
  let allLibs = [];
  let offset = 0;
  const pageSize = 500;
  while (true) {
    const data = await queryFn(GET_SBOM_LIBRARIES, {
      getSbomLibrariesInput: { offset, limit: pageSize, filters: {}, search: '', owners: [] },
    });
    allLibs = allLibs.concat(data.getSbomLibraries.sbomLibs);
    if (allLibs.length >= data.getSbomLibraries.total || data.getSbomLibraries.sbomLibs.length === 0) break;
    offset += pageSize;
  }
  if (appFilter) allLibs = allLibs.filter(l => l.appName.toLowerCase().includes(appFilter.toLowerCase()));
  return allLibs;
}

// ---------------------------------------------------------------------------
// Risk scoring for deprecated/unmaintained libraries
// ---------------------------------------------------------------------------

/**
 * Compute a deprecation risk score (0-100) for a single library.
 * Only libraries that are deprecated or unmaintained get scored.
 * Higher = more urgent to replace.
 */
function scoreLibrary(lib) {
  let score = 0;

  // Base score from status (max 40 points)
  if (lib.isDeprecated && lib.notMaintained) {
    score += 40;  // Both deprecated AND unmaintained — worst case
  } else if (lib.isDeprecated) {
    score += 35;  // Explicitly deprecated by author
  } else if (lib.notMaintained) {
    score += 25;  // Unmaintained (no updates) but not formally deprecated
  }

  // Vulnerability exposure (max 40 points)
  const vc = lib.vulnerabilityCounts || {};
  const vulnWeight =
    (vc.critical || 0) * SEV_WEIGHTS.critical +
    (vc.high     || 0) * SEV_WEIGHTS.high +
    (vc.medium   || 0) * SEV_WEIGHTS.medium +
    (vc.low      || 0) * SEV_WEIGHTS.low;
  // Normalize: 0 vulns = 0, 20+ weighted points = 40
  score += Math.min(40, Math.round(vulnWeight * 2));

  // Dependency level bonus (max 10 points)
  // Direct deps are higher priority — you control them directly
  if (lib.dependencyLevel === 'Direct') {
    score += 10;
  } else {
    score += 3; // Transitive still matters but less actionable
  }

  // License issue bonus (max 10 points)
  if (lib.licenseIssue) {
    score += 10;
  }

  return Math.min(100, score);
}

/**
 * Compute total vulnerability count for a library
 */
function totalVulns(lib) {
  const vc = lib.vulnerabilityCounts || {};
  return (vc.critical || 0) + (vc.high || 0) + (vc.medium || 0) + (vc.low || 0);
}

/**
 * Get vulnerability weight for a library
 */
function vulnWeight(lib) {
  const vc = lib.vulnerabilityCounts || {};
  return (vc.critical || 0) * SEV_WEIGHTS.critical +
         (vc.high     || 0) * SEV_WEIGHTS.high +
         (vc.medium   || 0) * SEV_WEIGHTS.medium +
         (vc.low      || 0) * SEV_WEIGHTS.low;
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------
function analyzeDeprecated(allLibs) {
  // Separate deprecated/unmaintained from healthy
  const flagged = [];
  const healthy = [];

  for (const lib of allLibs) {
    if (lib.isDeprecated || lib.notMaintained) {
      const riskScore = scoreLibrary(lib);
      const urgency = getUrgency(riskScore);
      const altInfo = KNOWN_ALTERNATIVES[lib.libraryName] || null;

      flagged.push({
        libraryName: lib.libraryName,
        libraryVersion: lib.libraryVersion,
        appName: lib.appName,
        dependencyLevel: lib.dependencyLevel || 'Unknown',
        source: lib.source || 'Unknown',
        isDeprecated: !!lib.isDeprecated,
        notMaintained: !!lib.notMaintained,
        licenseIssue: !!lib.licenseIssue,
        license: lib.license || '',
        vulnerabilityCounts: lib.vulnerabilityCounts || {},
        totalVulns: totalVulns(lib),
        vulnWeight: vulnWeight(lib),
        riskScore,
        urgency: urgency.label,
        urgencyDescription: urgency.description,
        alternative: altInfo ? altInfo.alt : null,
        alternativeReason: altInfo ? altInfo.reason : null,
      });
    } else {
      healthy.push(lib);
    }
  }

  // Sort flagged by risk score (highest first)
  flagged.sort((a, b) => b.riskScore - a.riskScore);

  // Per-app summary
  const perApp = {};
  for (const lib of allLibs) {
    if (!perApp[lib.appName]) {
      perApp[lib.appName] = {
        totalLibs: 0,
        deprecatedCount: 0,
        unmaintainedCount: 0,
        flaggedLibs: [],
        totalFlaggedVulns: 0,
        maxRiskScore: 0,
      };
    }
    const app = perApp[lib.appName];
    app.totalLibs++;
  }

  for (const f of flagged) {
    const app = perApp[f.appName];
    if (f.isDeprecated) app.deprecatedCount++;
    if (f.notMaintained) app.unmaintainedCount++;
    app.flaggedLibs.push(f);
    app.totalFlaggedVulns += f.totalVulns;
    if (f.riskScore > app.maxRiskScore) app.maxRiskScore = f.riskScore;
  }

  // Compute per-app health ratio
  for (const app of Object.values(perApp)) {
    const flaggedCount = app.deprecatedCount + app.unmaintainedCount;
    app.healthRatio = app.totalLibs > 0 ? Math.round((1 - flaggedCount / app.totalLibs) * 100) : 100;
  }

  // Cross-app analysis: find libs that are flagged in multiple apps
  const crossApp = {};
  for (const f of flagged) {
    if (!crossApp[f.libraryName]) crossApp[f.libraryName] = [];
    crossApp[f.libraryName].push(f.appName);
  }
  const sharedFlagged = Object.entries(crossApp)
    .filter(([, apps]) => apps.length > 1)
    .map(([name, apps]) => ({ libraryName: name, apps: [...new Set(apps)] }));

  // Portfolio summary
  const totalFlagged = flagged.length;
  const totalDeprecated = flagged.filter(f => f.isDeprecated).length;
  const totalUnmaintained = flagged.filter(f => f.notMaintained).length;
  const uniqueFlagged = [...new Set(flagged.map(f => f.libraryName))].length;
  const withVulns = flagged.filter(f => f.totalVulns > 0).length;
  const withAlternatives = flagged.filter(f => f.alternative).length;
  const criticalUrgency = flagged.filter(f => f.urgency === 'CRITICAL').length;
  const highUrgency = flagged.filter(f => f.urgency === 'HIGH').length;

  return {
    flagged,
    perApp,
    sharedFlagged,
    summary: {
      totalLibraries: allLibs.length,
      totalFlagged,
      totalDeprecated,
      totalUnmaintained,
      uniqueFlagged,
      withVulns,
      withAlternatives,
      criticalUrgency,
      highUrgency,
      appsAffected: Object.values(perApp).filter(a => a.deprecatedCount > 0 || a.unmaintainedCount > 0).length,
      totalApps: Object.keys(perApp).length,
    },
  };
}

// ---------------------------------------------------------------------------
// Recommendations engine
// ---------------------------------------------------------------------------
function generateRecommendations(analysis) {
  const { flagged, perApp, sharedFlagged, summary } = analysis;
  const recs = [];

  // Critical: deprecated libs with known CVEs
  const criticalVuln = flagged.filter(f => f.urgency === 'CRITICAL' && f.totalVulns > 0);
  if (criticalVuln.length > 0) {
    const names = [...new Set(criticalVuln.map(f => `${f.libraryName}@${f.libraryVersion}`))].join(', ');
    recs.push({
      priority: 'Critical',
      text: `${criticalVuln.length} deprecated/unmaintained libraries with active vulnerabilities need immediate replacement: ${names}. These will never receive security patches.`,
    });
  }

  // High: libs with known alternatives
  const withAlts = flagged.filter(f => f.alternative);
  if (withAlts.length > 0) {
    for (const f of withAlts) {
      if (f.urgency === 'CRITICAL' || f.urgency === 'HIGH') {
        recs.push({
          priority: 'High',
          text: `Replace ${f.libraryName}@${f.libraryVersion} with ${f.alternative}. ${f.alternativeReason}`,
        });
      }
    }
  }

  // High: libs deprecated in multiple apps (fix once, benefit everywhere)
  if (sharedFlagged.length > 0) {
    for (const sf of sharedFlagged) {
      recs.push({
        priority: 'High',
        text: `${sf.libraryName} is flagged in ${sf.apps.length} apps (${sf.apps.join(', ')}). Replacing it will improve security across the portfolio.`,
      });
    }
  }

  // Medium: apps with high deprecated ratio
  for (const [appName, app] of Object.entries(perApp)) {
    if (app.healthRatio < 80) {
      recs.push({
        priority: 'Medium',
        text: `${appName} has a dependency health ratio of ${app.healthRatio}% (${app.deprecatedCount} deprecated, ${app.unmaintainedCount} unmaintained out of ${app.totalLibs} total). Consider a dedicated dependency cleanup sprint.`,
      });
    }
  }

  // Medium: remaining flagged libs without alternatives
  const noAlts = flagged.filter(f => !f.alternative && f.urgency !== 'LOW');
  if (noAlts.length > 0) {
    const names = [...new Set(noAlts.map(f => f.libraryName))].join(', ');
    recs.push({
      priority: 'Medium',
      text: `${noAlts.length} flagged libraries without known alternatives (${names}). Research replacement options or evaluate if the functionality is still needed.`,
    });
  }

  // General: CI pipeline integration
  if (summary.totalFlagged > 0) {
    recs.push({
      priority: 'Medium',
      text: 'Add deprecated dependency checks to your CI pipeline. Block PRs that introduce new deprecated or unmaintained dependencies.',
    });
  }

  // Deduplicate
  const seen = new Set();
  return recs.filter(r => {
    const key = r.text.slice(0, 80);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// ---------------------------------------------------------------------------
// Console output
// ---------------------------------------------------------------------------
function generateConsoleOutput(analysis, recs) {
  const { flagged, perApp, sharedFlagged, summary } = analysis;
  const lines = [];

  lines.push('');
  lines.push('='.repeat(70));
  lines.push('  E14: Deprecated Dependency Alert');
  lines.push('  Ox Security — Deprecated & Unmaintained Library Analysis');
  lines.push('='.repeat(70));
  lines.push('');

  if (USE_MOCK) {
    lines.push('[Mock Mode — using realistic sample data]');
    lines.push('');
  }

  // Portfolio summary
  lines.push('Portfolio Summary');
  lines.push('-'.repeat(40));
  lines.push(`  Total libraries scanned:       ${summary.totalLibraries}`);
  lines.push(`  Deprecated libraries:          ${summary.totalDeprecated}`);
  lines.push(`  Unmaintained libraries:        ${summary.totalUnmaintained}`);
  lines.push(`  Unique flagged libraries:      ${summary.uniqueFlagged}`);
  lines.push(`  Flagged with vulnerabilities:  ${summary.withVulns}`);
  lines.push(`  Known alternatives available:  ${summary.withAlternatives}`);
  lines.push(`  Apps affected:                 ${summary.appsAffected}/${summary.totalApps}`);
  lines.push('');

  // Urgency breakdown
  lines.push('Migration Urgency Breakdown');
  lines.push('-'.repeat(40));
  const urgencyCounts = {};
  for (const f of flagged) {
    urgencyCounts[f.urgency] = (urgencyCounts[f.urgency] || 0) + 1;
  }
  for (const level of URGENCY_LEVELS) {
    const count = urgencyCounts[level.label] || 0;
    if (count > 0) {
      const bar = '\u2588'.repeat(Math.max(1, Math.round(count * 3)));
      lines.push(`  ${level.icon} ${level.label.padEnd(10)} ${bar} ${count} — ${level.description}`);
    }
  }
  lines.push('');

  // Alert list — sorted by risk score
  if (flagged.length > 0) {
    lines.push('Deprecated / Unmaintained Library Alerts');
    lines.push('-'.repeat(40));
    lines.push('');

    for (const f of flagged) {
      const urgency = getUrgency(f.riskScore);
      const status = [];
      if (f.isDeprecated) status.push('DEPRECATED');
      if (f.notMaintained) status.push('UNMAINTAINED');
      if (f.licenseIssue) status.push('LICENSE');

      lines.push(`  ${urgency.icon} ${f.libraryName}@${f.libraryVersion}  [Risk: ${f.riskScore}/100  ${f.urgency}]`);
      lines.push(`     App: ${f.appName} | Level: ${f.dependencyLevel} | Source: ${f.source}`);
      lines.push(`     Status: ${status.join(', ')}`);

      if (f.totalVulns > 0) {
        const vc = f.vulnerabilityCounts;
        lines.push(`     Vulns: C:${vc.critical||0} H:${vc.high||0} M:${vc.medium||0} L:${vc.low||0} (${f.totalVulns} total, weight ${f.vulnWeight})`);
      }

      if (f.alternative) {
        lines.push(`     -> Replace with: ${f.alternative}`);
        lines.push(`        ${f.alternativeReason}`);
      }
      lines.push('');
    }
  } else {
    lines.push('No deprecated or unmaintained libraries found!');
    lines.push('');
  }

  // Per-app breakdown
  lines.push('Per-App Dependency Health');
  lines.push('-'.repeat(40));
  const sortedApps = Object.entries(perApp).sort((a, b) => a[1].healthRatio - b[1].healthRatio);
  for (const [appName, app] of sortedApps) {
    const barWidth = 20;
    const filledLen = Math.round((app.healthRatio / 100) * barWidth);
    const bar = '\u2588'.repeat(filledLen) + '\u2591'.repeat(barWidth - filledLen);
    const flagCount = app.deprecatedCount + app.unmaintainedCount;
    lines.push(`  ${appName}`);
    lines.push(`    Health: ${bar} ${app.healthRatio}%  (${flagCount} flagged / ${app.totalLibs} total)`);
    if (app.deprecatedCount > 0) lines.push(`    Deprecated:   ${app.deprecatedCount}`);
    if (app.unmaintainedCount > 0) lines.push(`    Unmaintained: ${app.unmaintainedCount}`);
    if (app.totalFlaggedVulns > 0) lines.push(`    Vulns in flagged libs: ${app.totalFlaggedVulns}`);
    if (app.flaggedLibs.length > 0) {
      lines.push(`    Flagged: ${app.flaggedLibs.map(f => f.libraryName).join(', ')}`);
    }
    lines.push('');
  }

  // Cross-app flagged libraries
  if (sharedFlagged.length > 0) {
    lines.push('Cross-App Flagged Libraries');
    lines.push('-'.repeat(40));
    for (const sf of sharedFlagged) {
      lines.push(`  ${sf.libraryName} — appears in ${sf.apps.length} apps: ${sf.apps.join(', ')}`);
    }
    lines.push('');
  }

  // Recommendations
  if (recs.length > 0) {
    lines.push('Recommendations');
    lines.push('-'.repeat(40));
    for (const rec of recs) {
      const icon = { Critical: '[!!!]', High: '[!!]', Medium: '[!]', Low: '[.]' }[rec.priority] || '[?]';
      lines.push(`  ${icon} [${rec.priority}] ${rec.text}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Markdown report
// ---------------------------------------------------------------------------
function generateMarkdownReport(analysis, recs, timestamp) {
  const { flagged, perApp, sharedFlagged, summary } = analysis;
  const lines = [];

  lines.push('# E14: Deprecated Dependency Alert');
  lines.push(`\n*Generated: ${timestamp}*`);
  if (USE_MOCK) lines.push('\n> **Mock Mode** — using realistic sample data (no OX_API_KEY configured)');
  lines.push('');

  // Summary
  lines.push('## Portfolio Summary');
  lines.push('');
  lines.push('| Metric | Value |');
  lines.push('|--------|-------|');
  lines.push(`| Total libraries scanned | ${summary.totalLibraries} |`);
  lines.push(`| Deprecated libraries | ${summary.totalDeprecated} |`);
  lines.push(`| Unmaintained libraries | ${summary.totalUnmaintained} |`);
  lines.push(`| Unique flagged libraries | ${summary.uniqueFlagged} |`);
  lines.push(`| Flagged with active vulnerabilities | ${summary.withVulns} |`);
  lines.push(`| Known alternatives available | ${summary.withAlternatives} |`);
  lines.push(`| Apps affected | ${summary.appsAffected}/${summary.totalApps} |`);
  lines.push(`| Critical urgency | ${summary.criticalUrgency} |`);
  lines.push(`| High urgency | ${summary.highUrgency} |`);
  lines.push('');

  // Scoring methodology
  lines.push('## Scoring Methodology');
  lines.push('');
  lines.push('Each deprecated/unmaintained library receives a risk score (0-100):');
  lines.push('');
  lines.push('| Factor | Max Points | Description |');
  lines.push('|--------|-----------|-------------|');
  lines.push('| Status | 40 | Deprecated+unmaintained=40, deprecated=35, unmaintained=25 |');
  lines.push('| Vulnerabilities | 40 | Weighted: Critical*10, High*5, Medium*2, Low*0.5 |');
  lines.push('| Dependency Level | 10 | Direct=10, Transitive=3 |');
  lines.push('| License Issue | 10 | Ox-flagged license problem=10 |');
  lines.push('');
  lines.push('**Migration Urgency:**');
  lines.push('');
  lines.push('| Score Range | Urgency | Action |');
  lines.push('|-------------|---------|--------|');
  lines.push('| 80-100 | CRITICAL | Immediate replacement required |');
  lines.push('| 60-79 | HIGH | Plan replacement within 1 sprint |');
  lines.push('| 40-59 | MEDIUM | Schedule replacement this quarter |');
  lines.push('| 0-39 | LOW | Monitor and replace when convenient |');
  lines.push('');

  // Alert table
  if (flagged.length > 0) {
    lines.push('## Deprecated / Unmaintained Library Alerts');
    lines.push('');
    lines.push('| # | Library | Version | App | Level | Status | Vulns | Risk | Urgency | Alternative |');
    lines.push('|---|---------|---------|-----|-------|--------|-------|------|---------|-------------|');
    flagged.forEach((f, i) => {
      const status = [];
      if (f.isDeprecated) status.push('Deprecated');
      if (f.notMaintained) status.push('Unmaintained');
      if (f.licenseIssue) status.push('License');
      const vc = f.vulnerabilityCounts;
      const vulnStr = f.totalVulns > 0 ? `C:${vc.critical||0} H:${vc.high||0} M:${vc.medium||0} L:${vc.low||0}` : '-';
      const altStr = f.alternative || '-';
      lines.push(`| ${i + 1} | **${f.libraryName}** | ${f.libraryVersion} | ${f.appName} | ${f.dependencyLevel} | ${status.join(', ')} | ${vulnStr} | **${f.riskScore}**/100 | ${f.urgency} | ${altStr} |`);
    });
    lines.push('');

    // Detailed alternatives section
    const withAlts = flagged.filter(f => f.alternative);
    if (withAlts.length > 0) {
      lines.push('### Migration Alternatives');
      lines.push('');
      const seen = new Set();
      for (const f of withAlts) {
        if (seen.has(f.libraryName)) continue;
        seen.add(f.libraryName);
        lines.push(`#### ${f.libraryName} -> ${f.alternative}`);
        lines.push('');
        lines.push(`- **Current:** ${f.libraryName}@${f.libraryVersion}`);
        lines.push(`- **Recommended:** ${f.alternative}`);
        lines.push(`- **Reason:** ${f.alternativeReason}`);
        lines.push(`- **Urgency:** ${f.urgency} (score ${f.riskScore}/100)`);
        lines.push('');
      }
    }
  }

  // Per-app breakdown
  lines.push('## Per-App Dependency Health');
  lines.push('');
  lines.push('| App | Health | Total Libs | Deprecated | Unmaintained | Vulns in Flagged |');
  lines.push('|-----|--------|-----------|------------|--------------|-----------------|');
  const sortedApps = Object.entries(perApp).sort((a, b) => a[1].healthRatio - b[1].healthRatio);
  for (const [appName, app] of sortedApps) {
    lines.push(`| ${appName} | ${app.healthRatio}% | ${app.totalLibs} | ${app.deprecatedCount} | ${app.unmaintainedCount} | ${app.totalFlaggedVulns} |`);
  }
  lines.push('');

  // Per-app detail
  for (const [appName, app] of sortedApps) {
    if (app.flaggedLibs.length === 0) continue;
    lines.push(`### ${appName} — ${app.healthRatio}% Health`);
    lines.push('');
    for (const f of app.flaggedLibs) {
      const status = [];
      if (f.isDeprecated) status.push('Deprecated');
      if (f.notMaintained) status.push('Unmaintained');
      lines.push(`- **${f.libraryName}@${f.libraryVersion}** (${f.dependencyLevel}) — ${status.join(', ')} — Risk: ${f.riskScore}/100 ${f.urgency}`);
      if (f.totalVulns > 0) {
        lines.push(`  - Vulnerabilities: ${f.totalVulns} (C:${f.vulnerabilityCounts.critical||0} H:${f.vulnerabilityCounts.high||0} M:${f.vulnerabilityCounts.medium||0} L:${f.vulnerabilityCounts.low||0})`);
      }
      if (f.alternative) {
        lines.push(`  - Migrate to: **${f.alternative}** — ${f.alternativeReason}`);
      }
    }
    lines.push('');
  }

  // Cross-app
  if (sharedFlagged.length > 0) {
    lines.push('## Cross-App Flagged Libraries');
    lines.push('');
    lines.push('Libraries flagged in multiple apps — fixing these yields portfolio-wide improvement:');
    lines.push('');
    for (const sf of sharedFlagged) {
      lines.push(`- **${sf.libraryName}** — ${sf.apps.join(', ')}`);
    }
    lines.push('');
  }

  // Recommendations
  if (recs.length > 0) {
    lines.push('## Recommendations');
    lines.push('');
    for (const rec of recs) {
      lines.push(`- **[${rec.priority}]** ${rec.text}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  const appFilter = process.env.OX_APP_NAME || process.argv[2] || '';
  const timestamp = new Date().toISOString();

  console.log('E14: Deprecated Dependency Alert');
  console.log('Scanning SBOM for deprecated and unmaintained libraries...');

  // Fetch SBOM
  const allLibs = await fetchSBOM(appFilter);
  console.log(`  Libraries fetched: ${allLibs.length}`);
  if (appFilter) console.log(`  Filtered by: "${appFilter}"`);
  console.log('');

  if (allLibs.length === 0) {
    console.log('No libraries found.');
    return;
  }

  // Analyze
  console.log('Analyzing deprecation status...');
  const analysis = analyzeDeprecated(allLibs);
  console.log(`  Deprecated:   ${analysis.summary.totalDeprecated}`);
  console.log(`  Unmaintained: ${analysis.summary.totalUnmaintained}`);
  console.log(`  With vulns:   ${analysis.summary.withVulns}`);
  console.log('');

  // Generate recommendations
  const recs = generateRecommendations(analysis);

  // Console output
  const consoleOutput = generateConsoleOutput(analysis, recs);
  console.log(consoleOutput);

  // Write results to experiments/
  const dateStr = timestamp.slice(0, 10);
  const outDir = resolve(process.cwd(), 'experiments', `deprecated-deps-${dateStr}`);
  mkdirSync(outDir, { recursive: true });

  // JSON export
  const jsonData = {
    timestamp,
    mockMode: USE_MOCK,
    filter: appFilter || null,
    summary: analysis.summary,
    scoringMethodology: {
      statusPoints: { 'deprecated+unmaintained': 40, deprecated: 35, unmaintained: 25 },
      vulnWeights: SEV_WEIGHTS,
      maxVulnPoints: 40,
      directDepBonus: 10,
      transitiveDepBonus: 3,
      licenseIssueBonus: 10,
      urgencyThresholds: URGENCY_LEVELS.map(u => ({ min: u.min, label: u.label, description: u.description })),
    },
    alerts: analysis.flagged,
    perApp: Object.fromEntries(
      Object.entries(analysis.perApp).map(([name, app]) => [name, {
        healthRatio: app.healthRatio,
        totalLibs: app.totalLibs,
        deprecatedCount: app.deprecatedCount,
        unmaintainedCount: app.unmaintainedCount,
        totalFlaggedVulns: app.totalFlaggedVulns,
        maxRiskScore: app.maxRiskScore,
        flaggedLibs: app.flaggedLibs.map(f => f.libraryName),
      }])
    ),
    sharedFlagged: analysis.sharedFlagged,
    recommendations: recs,
  };
  writeFileSync(resolve(outDir, 'deprecated-deps.json'), JSON.stringify(jsonData, null, 2));

  // Markdown report
  const mdReport = generateMarkdownReport(analysis, recs, timestamp);
  writeFileSync(resolve(outDir, 'deprecated-deps-report.md'), mdReport);

  console.log(`Results written to experiments/deprecated-deps-${dateStr}/`);
  console.log(`  - deprecated-deps.json       (machine-readable)`);
  console.log(`  - deprecated-deps-report.md  (human-readable)`);
}

main().catch(e => { console.error('Error:', e.message); process.exit(1); });
