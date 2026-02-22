#!/usr/bin/env node
/**
 * E08: Dependency Tree Mapper
 *
 * Maps SBOM dependency chains (direct → transitive) and identifies which
 * transitive dependencies introduce the most risk. Builds a visual tree
 * representation and generates a risk analysis report.
 *
 * Falls back to realistic iOS mock data when OX_API_KEY is not configured.
 *
 * Usage:
 *   node scripts/dependency-tree.js [appFilter]
 *
 * Environment:
 *   OX_APP_NAME  — filter to a specific app name
 *   OX_LIMIT     — max libraries per API page (default: 500)
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
// Mock data — realistic iOS dependency tree for offline development
// ---------------------------------------------------------------------------
function getMockSBOM() {
  // Simulates 3 iOS apps with realistic CocoaPods / SPM / npm dependency trees
  return [
    // ---- MyBankingApp-iOS (CocoaPods + SPM) ----
    // Direct deps
    { libraryName: 'Alamofire', libraryVersion: '5.6.4', license: 'MIT', appName: 'MyBankingApp-iOS', dependencyType: 'Runtime', dependencyLevel: 'Direct', source: 'Swift Package Manager', vulnerabilityCounts: { critical: 0, high: 2, medium: 1, low: 0, info: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'Ono', libraryVersion: '2.5.0', license: 'MIT', appName: 'MyBankingApp-iOS', dependencyType: 'Runtime', dependencyLevel: 'Direct', source: 'CocoaPods', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, notMaintained: true, isDeprecated: false, licenseIssue: false },
    { libraryName: 'KeychainAccess', libraryVersion: '4.2.2', license: 'MIT', appName: 'MyBankingApp-iOS', dependencyType: 'Runtime', dependencyLevel: 'Direct', source: 'CocoaPods', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'SwiftLint', libraryVersion: '0.54.0', license: 'MIT', appName: 'MyBankingApp-iOS', dependencyType: 'Development', dependencyLevel: 'Direct', source: 'Swift Package Manager', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'CryptoSwift', libraryVersion: '1.7.2', license: 'MIT', appName: 'MyBankingApp-iOS', dependencyType: 'Runtime', dependencyLevel: 'Direct', source: 'Swift Package Manager', vulnerabilityCounts: { critical: 0, high: 0, medium: 1, low: 0, info: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'lodash', libraryVersion: '4.17.19', license: 'MIT', appName: 'MyBankingApp-iOS', dependencyType: 'Runtime', dependencyLevel: 'Direct', source: 'npm', vulnerabilityCounts: { critical: 1, high: 0, medium: 1, low: 0, info: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    // Transitive deps
    { libraryName: 'libxml2', libraryVersion: '2.11.6', license: 'MIT', appName: 'MyBankingApp-iOS', dependencyType: 'Runtime', dependencyLevel: 'Transitive', source: 'CocoaPods', vulnerabilityCounts: { critical: 1, high: 1, medium: 0, low: 0, info: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'OpenSSL', libraryVersion: '1.1.1w', license: 'Apache-2.0', appName: 'MyBankingApp-iOS', dependencyType: 'Runtime', dependencyLevel: 'Transitive', source: 'CocoaPods', vulnerabilityCounts: { critical: 0, high: 1, medium: 1, low: 0, info: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'BoringSSL-GRPC', libraryVersion: '0.0.27', license: 'ISC', appName: 'MyBankingApp-iOS', dependencyType: 'Runtime', dependencyLevel: 'Transitive', source: 'CocoaPods', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 1, info: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'CFNetwork', libraryVersion: '0.0.0', license: 'Apple', appName: 'MyBankingApp-iOS', dependencyType: 'Runtime', dependencyLevel: 'Transitive', source: 'System', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },

    // ---- HealthTracker-iOS (CocoaPods) ----
    { libraryName: 'SQLite.swift', libraryVersion: '0.14.1', license: 'MIT', appName: 'HealthTracker-iOS', dependencyType: 'Runtime', dependencyLevel: 'Direct', source: 'CocoaPods', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'Charts', libraryVersion: '5.0.0', license: 'Apache-2.0', appName: 'HealthTracker-iOS', dependencyType: 'Runtime', dependencyLevel: 'Direct', source: 'CocoaPods', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'Realm', libraryVersion: '10.44.0', license: 'Apache-2.0', appName: 'HealthTracker-iOS', dependencyType: 'Runtime', dependencyLevel: 'Direct', source: 'CocoaPods', vulnerabilityCounts: { critical: 0, high: 0, medium: 1, low: 0, info: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'HealthKit', libraryVersion: '17.0', license: 'Apple', appName: 'HealthTracker-iOS', dependencyType: 'Runtime', dependencyLevel: 'Direct', source: 'System', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'SnapKit', libraryVersion: '5.6.0', license: 'MIT', appName: 'HealthTracker-iOS', dependencyType: 'Runtime', dependencyLevel: 'Direct', source: 'CocoaPods', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    // Transitive deps
    { libraryName: 'libexpat', libraryVersion: '2.5.0', license: 'MIT', appName: 'HealthTracker-iOS', dependencyType: 'Runtime', dependencyLevel: 'Transitive', source: 'CocoaPods', vulnerabilityCounts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'RealmCore', libraryVersion: '13.26.0', license: 'Apache-2.0', appName: 'HealthTracker-iOS', dependencyType: 'Runtime', dependencyLevel: 'Transitive', source: 'CocoaPods', vulnerabilityCounts: { critical: 0, high: 0, medium: 1, low: 1, info: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'libuv', libraryVersion: '1.44.2', license: 'MIT', appName: 'HealthTracker-iOS', dependencyType: 'Runtime', dependencyLevel: 'Transitive', source: 'CocoaPods', vulnerabilityCounts: { critical: 0, high: 0, medium: 1, low: 0, info: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'sqlite3', libraryVersion: '3.42.0', license: 'Public Domain', appName: 'HealthTracker-iOS', dependencyType: 'Runtime', dependencyLevel: 'Transitive', source: 'System', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },

    // ---- ShopEasy-iOS (React Native + npm) ----
    { libraryName: 'react-native', libraryVersion: '0.71.8', license: 'MIT', appName: 'ShopEasy-iOS', dependencyType: 'Runtime', dependencyLevel: 'Direct', source: 'npm', vulnerabilityCounts: { critical: 1, high: 2, medium: 0, low: 0, info: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'react', libraryVersion: '18.2.0', license: 'MIT', appName: 'ShopEasy-iOS', dependencyType: 'Runtime', dependencyLevel: 'Direct', source: 'npm', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: '@react-navigation/native', libraryVersion: '6.1.9', license: 'MIT', appName: 'ShopEasy-iOS', dependencyType: 'Runtime', dependencyLevel: 'Direct', source: 'npm', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'stripe-react-native', libraryVersion: '0.35.0', license: 'MIT', appName: 'ShopEasy-iOS', dependencyType: 'Runtime', dependencyLevel: 'Direct', source: 'npm', vulnerabilityCounts: { critical: 0, high: 0, medium: 1, low: 0, info: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'axios', libraryVersion: '1.6.0', license: 'MIT', appName: 'ShopEasy-iOS', dependencyType: 'Runtime', dependencyLevel: 'Direct', source: 'npm', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'moment', libraryVersion: '2.29.4', license: 'MIT', appName: 'ShopEasy-iOS', dependencyType: 'Runtime', dependencyLevel: 'Direct', source: 'npm', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, notMaintained: true, isDeprecated: false, licenseIssue: false },
    { libraryName: 'react-native-firebase', libraryVersion: '18.6.0', license: 'Apache-2.0', appName: 'ShopEasy-iOS', dependencyType: 'Runtime', dependencyLevel: 'Direct', source: 'npm', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    // Transitive deps
    { libraryName: 'hermes-engine', libraryVersion: '0.71.14', license: 'MIT', appName: 'ShopEasy-iOS', dependencyType: 'Runtime', dependencyLevel: 'Transitive', source: 'npm', vulnerabilityCounts: { critical: 1, high: 1, medium: 0, low: 0, info: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'jsc-android', libraryVersion: '250231.0.0', license: 'BSD-2-Clause', appName: 'ShopEasy-iOS', dependencyType: 'Runtime', dependencyLevel: 'Transitive', source: 'npm', vulnerabilityCounts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 }, notMaintained: false, isDeprecated: true, licenseIssue: false },
    { libraryName: 'metro', libraryVersion: '0.76.8', license: 'MIT', appName: 'ShopEasy-iOS', dependencyType: 'Development', dependencyLevel: 'Transitive', source: 'npm', vulnerabilityCounts: { critical: 0, high: 0, medium: 1, low: 0, info: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'follow-redirects', libraryVersion: '1.15.3', license: 'MIT', appName: 'ShopEasy-iOS', dependencyType: 'Runtime', dependencyLevel: 'Transitive', source: 'npm', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 1, info: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'nanopb', libraryVersion: '2.30909.0', license: 'zlib', appName: 'ShopEasy-iOS', dependencyType: 'Runtime', dependencyLevel: 'Transitive', source: 'CocoaPods', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'GoogleUtilities', libraryVersion: '7.12.0', license: 'Apache-2.0', appName: 'ShopEasy-iOS', dependencyType: 'Runtime', dependencyLevel: 'Transitive', source: 'CocoaPods', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
    { libraryName: 'abseil-cpp', libraryVersion: '1.20230802.0', license: 'Apache-2.0', appName: 'ShopEasy-iOS', dependencyType: 'Runtime', dependencyLevel: 'Transitive', source: 'CocoaPods', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 1 }, notMaintained: false, isDeprecated: false, licenseIssue: false },
  ];
}

// Known direct-to-transitive relationships for mock data tree visualization
function getMockDependencyEdges() {
  return {
    'MyBankingApp-iOS': [
      { from: 'Ono', to: 'libxml2', reason: 'Ono uses libxml2 for HTML/XML parsing' },
      { from: 'Alamofire', to: 'OpenSSL', reason: 'Alamofire 5.6.x bundles OpenSSL for TLS' },
      { from: 'Alamofire', to: 'CFNetwork', reason: 'Alamofire wraps Apple CFNetwork' },
      { from: 'Alamofire', to: 'BoringSSL-GRPC', reason: 'gRPC plugin uses BoringSSL' },
    ],
    'HealthTracker-iOS': [
      { from: 'SQLite.swift', to: 'sqlite3', reason: 'SQLite.swift wraps system sqlite3' },
      { from: 'Realm', to: 'RealmCore', reason: 'Realm Swift wraps RealmCore C++ engine' },
      { from: 'Realm', to: 'libuv', reason: 'RealmCore uses libuv for async I/O' },
      { from: 'Charts', to: 'libexpat', reason: 'Charts uses XML for config/data import' },
    ],
    'ShopEasy-iOS': [
      { from: 'react-native', to: 'hermes-engine', reason: 'React Native bundles Hermes JS engine' },
      { from: 'react-native', to: 'jsc-android', reason: 'Fallback JavaScriptCore engine' },
      { from: 'react-native', to: 'metro', reason: 'Metro bundler for JS compilation' },
      { from: 'axios', to: 'follow-redirects', reason: 'axios uses follow-redirects for HTTP' },
      { from: 'react-native-firebase', to: 'nanopb', reason: 'Firebase uses nanopb for protobuf' },
      { from: 'react-native-firebase', to: 'GoogleUtilities', reason: 'Firebase shared utilities' },
      { from: 'react-native-firebase', to: 'abseil-cpp', reason: 'Firebase depends on abseil C++ lib' },
    ],
  };
}

// ---------------------------------------------------------------------------
// Core analysis functions
// ---------------------------------------------------------------------------

/**
 * Calculate a risk score for a library based on vulnerabilities and flags.
 * Higher = riskier.
 */
function calcRiskScore(lib) {
  const vc = lib.vulnerabilityCounts || {};
  let score = 0;
  score += (vc.critical || 0) * 10;
  score += (vc.high || 0) * 5;
  score += (vc.medium || 0) * 2;
  score += (vc.low || 0) * 1;
  score += (vc.info || 0) * 0.1;
  if (lib.notMaintained) score += 3;
  if (lib.isDeprecated) score += 4;
  if (lib.licenseIssue) score += 2;
  return Math.round(score * 10) / 10;
}

/**
 * Total vulnerability count for a library
 */
function totalVulns(lib) {
  const vc = lib.vulnerabilityCounts || {};
  return (vc.critical || 0) + (vc.high || 0) + (vc.medium || 0) + (vc.low || 0);
}

/**
 * Group libraries by app, then categorize as direct vs transitive
 */
function buildAppTrees(libs, edges) {
  const apps = {};

  for (const lib of libs) {
    const appName = lib.appName || 'Unknown';
    if (!apps[appName]) {
      apps[appName] = { direct: [], transitive: [], all: [] };
    }
    const enriched = {
      ...lib,
      riskScore: calcRiskScore(lib),
      totalVulns: totalVulns(lib),
    };
    apps[appName].all.push(enriched);
    if ((lib.dependencyLevel || '').toLowerCase() === 'direct') {
      apps[appName].direct.push(enriched);
    } else {
      apps[appName].transitive.push(enriched);
    }
  }

  // Attach edges for tree visualization
  for (const [appName, appEdges] of Object.entries(edges || {})) {
    if (apps[appName]) {
      apps[appName].edges = appEdges;
    }
  }

  return apps;
}

/**
 * Identify transitive risk hotspots: transitive deps that carry the most risk
 * and which direct dep pulls them in
 */
function findTransitiveRiskHotspots(apps, edges) {
  const hotspots = [];

  for (const [appName, tree] of Object.entries(apps)) {
    const appEdges = edges[appName] || [];

    for (const trans of tree.transitive) {
      if (trans.riskScore <= 0) continue;

      // Find which direct dep pulls this in
      const edge = appEdges.find(e => e.to === trans.libraryName);
      const introducedBy = edge ? edge.from : 'unknown';
      const reason = edge ? edge.reason : '';

      hotspots.push({
        appName,
        library: `${trans.libraryName}@${trans.libraryVersion}`,
        libraryName: trans.libraryName,
        riskScore: trans.riskScore,
        totalVulns: trans.totalVulns,
        vulnerabilityCounts: trans.vulnerabilityCounts,
        introducedBy,
        reason,
        flags: [
          trans.notMaintained ? 'NOT-MAINTAINED' : null,
          trans.isDeprecated ? 'DEPRECATED' : null,
          trans.licenseIssue ? 'LICENSE-ISSUE' : null,
        ].filter(Boolean),
        source: trans.source,
      });
    }
  }

  // Sort by risk score descending
  hotspots.sort((a, b) => b.riskScore - a.riskScore);
  return hotspots;
}

/**
 * Compute per-app risk summary
 */
function computeAppRiskSummaries(apps) {
  const summaries = [];
  for (const [appName, tree] of Object.entries(apps)) {
    const directRisk = tree.direct.reduce((sum, l) => sum + l.riskScore, 0);
    const transitiveRisk = tree.transitive.reduce((sum, l) => sum + l.riskScore, 0);
    const totalRisk = directRisk + transitiveRisk;
    const transitiveRiskPct = totalRisk > 0 ? Math.round((transitiveRisk / totalRisk) * 100) : 0;

    const directVulns = tree.direct.reduce((sum, l) => sum + l.totalVulns, 0);
    const transitiveVulns = tree.transitive.reduce((sum, l) => sum + l.totalVulns, 0);

    const flagged = tree.all.filter(l => l.notMaintained || l.isDeprecated || l.licenseIssue);

    summaries.push({
      appName,
      directCount: tree.direct.length,
      transitiveCount: tree.transitive.length,
      totalCount: tree.all.length,
      directRisk: Math.round(directRisk * 10) / 10,
      transitiveRisk: Math.round(transitiveRisk * 10) / 10,
      totalRisk: Math.round(totalRisk * 10) / 10,
      transitiveRiskPct,
      directVulns,
      transitiveVulns,
      totalVulns: directVulns + transitiveVulns,
      flaggedLibs: flagged.length,
      riskiestDirect: [...tree.direct].sort((a, b) => b.riskScore - a.riskScore)[0] || null,
      riskiestTransitive: [...tree.transitive].sort((a, b) => b.riskScore - a.riskScore)[0] || null,
    });
  }
  summaries.sort((a, b) => b.totalRisk - a.totalRisk);
  return summaries;
}

// ---------------------------------------------------------------------------
// ASCII tree rendering
// ---------------------------------------------------------------------------

/**
 * Render a text-based dependency tree for an app
 */
function renderTree(appName, tree, edges) {
  const lines = [];
  const appEdges = edges[appName] || [];

  lines.push(appName);

  // Build a map: direct dep -> list of transitive deps it introduces
  const directToTrans = {};
  for (const edge of appEdges) {
    if (!directToTrans[edge.from]) directToTrans[edge.from] = [];
    directToTrans[edge.from].push(edge);
  }

  // Also track transitive deps with no known parent
  const mappedTransitive = new Set(appEdges.map(e => e.to));
  const unmapped = tree.transitive.filter(t => !mappedTransitive.has(t.libraryName));

  const sortedDirect = [...tree.direct].sort((a, b) => b.riskScore - a.riskScore);

  for (let i = 0; i < sortedDirect.length; i++) {
    const dep = sortedDirect[i];
    const isLast = i === sortedDirect.length - 1 && unmapped.length === 0;
    const prefix = isLast ? '  +-- ' : '  |-- ';
    const childPrefix = isLast ? '      ' : '  |   ';
    const riskTag = dep.riskScore > 0 ? ` [RISK: ${dep.riskScore}]` : '';
    const flagTags = [];
    if (dep.notMaintained) flagTags.push('NOT-MAINTAINED');
    if (dep.isDeprecated) flagTags.push('DEPRECATED');
    const flagStr = flagTags.length ? ` {${flagTags.join(', ')}}` : '';

    lines.push(`${prefix}${dep.libraryName}@${dep.libraryVersion} (${dep.source})${riskTag}${flagStr}`);

    // Render transitive children
    const children = directToTrans[dep.libraryName] || [];
    for (let j = 0; j < children.length; j++) {
      const edge = children[j];
      const transLib = tree.transitive.find(t => t.libraryName === edge.to);
      const isLastChild = j === children.length - 1;
      const childPfx = isLastChild ? `${childPrefix}+-- ` : `${childPrefix}|-- `;
      const triskTag = transLib && transLib.riskScore > 0 ? ` [RISK: ${transLib.riskScore}]` : '';
      const tFlagTags = [];
      if (transLib?.notMaintained) tFlagTags.push('NOT-MAINTAINED');
      if (transLib?.isDeprecated) tFlagTags.push('DEPRECATED');
      const tFlagStr = tFlagTags.length ? ` {${tFlagTags.join(', ')}}` : '';
      const ver = transLib ? `@${transLib.libraryVersion}` : '';
      const src = transLib ? ` (${transLib.source})` : '';
      lines.push(`${childPfx}${edge.to}${ver}${src}${triskTag}${tFlagStr}`);
    }
  }

  // Unmapped transitive deps
  if (unmapped.length) {
    lines.push('  |');
    lines.push('  +-- [unmapped transitive deps]');
    for (let i = 0; i < unmapped.length; i++) {
      const dep = unmapped[i];
      const isLast = i === unmapped.length - 1;
      const prefix = isLast ? '      +-- ' : '      |-- ';
      const riskTag = dep.riskScore > 0 ? ` [RISK: ${dep.riskScore}]` : '';
      lines.push(`${prefix}${dep.libraryName}@${dep.libraryVersion} (${dep.source})${riskTag}`);
    }
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Report generation
// ---------------------------------------------------------------------------

function generateMarkdown(apps, edges, hotspots, appSummaries, meta) {
  const lines = [];

  lines.push('# Dependency Tree Analysis Report');
  lines.push(`Generated: ${meta.timestamp}`);
  if (meta.mockData) lines.push('**Note: Generated with mock data (no API key configured)**');
  if (meta.appFilter) lines.push(`App filter: ${meta.appFilter}`);
  lines.push('');

  // Overall stats
  const totalLibs = Object.values(apps).reduce((sum, a) => sum + a.all.length, 0);
  const totalDirect = Object.values(apps).reduce((sum, a) => sum + a.direct.length, 0);
  const totalTransitive = Object.values(apps).reduce((sum, a) => sum + a.transitive.length, 0);

  lines.push('## Overview');
  lines.push('');
  lines.push(`| Metric | Count |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Apps analyzed | ${Object.keys(apps).length} |`);
  lines.push(`| Total libraries | ${totalLibs} |`);
  lines.push(`| Direct dependencies | ${totalDirect} |`);
  lines.push(`| Transitive dependencies | ${totalTransitive} |`);
  lines.push(`| Transitive risk hotspots | ${hotspots.length} |`);
  lines.push('');

  // Per-app risk table
  lines.push('## App Risk Summary');
  lines.push('');
  lines.push('| App | Direct | Transitive | Total Risk | Transitive Risk % | Vulns (D/T) |');
  lines.push('|-----|--------|------------|------------|-------------------|-------------|');
  for (const s of appSummaries) {
    lines.push(`| ${s.appName} | ${s.directCount} | ${s.transitiveCount} | ${s.totalRisk} | ${s.transitiveRiskPct}% | ${s.directVulns}/${s.transitiveVulns} |`);
  }
  lines.push('');

  // Transitive risk hotspots
  if (hotspots.length) {
    lines.push('## Transitive Risk Hotspots');
    lines.push('');
    lines.push('These transitive dependencies introduce the most risk and are not under your direct control:');
    lines.push('');
    for (const h of hotspots) {
      const vc = h.vulnerabilityCounts || {};
      const vulnStr = `C:${vc.critical || 0} H:${vc.high || 0} M:${vc.medium || 0} L:${vc.low || 0}`;
      lines.push(`### ${h.library} (Risk: ${h.riskScore})`);
      lines.push(`- **App**: ${h.appName}`);
      lines.push(`- **Introduced by**: ${h.introducedBy}`);
      if (h.reason) lines.push(`- **Reason**: ${h.reason}`);
      lines.push(`- **Vulnerabilities**: ${vulnStr}`);
      lines.push(`- **Source**: ${h.source}`);
      if (h.flags.length) lines.push(`- **Flags**: ${h.flags.join(', ')}`);
      lines.push(`- **Remediation**: Update or replace \`${h.introducedBy}\` to pull a patched version of \`${h.libraryName}\``);
      lines.push('');
    }
  }

  // Dependency trees
  lines.push('## Dependency Trees');
  lines.push('');
  lines.push('Visual representation of direct → transitive dependency chains:');
  lines.push('');
  for (const [appName, tree] of Object.entries(apps)) {
    lines.push('```');
    lines.push(renderTree(appName, tree, edges));
    lines.push('```');
    lines.push('');
  }

  // Per-app detailed analysis
  lines.push('## Per-App Detailed Analysis');
  lines.push('');
  for (const s of appSummaries) {
    const tree = apps[s.appName];
    lines.push(`### ${s.appName}`);
    lines.push('');
    lines.push(`- **Dependencies**: ${s.directCount} direct, ${s.transitiveCount} transitive`);
    lines.push(`- **Total risk score**: ${s.totalRisk} (${s.transitiveRiskPct}% from transitive deps)`);
    lines.push(`- **Vulnerabilities**: ${s.totalVulns} total (${s.directVulns} direct, ${s.transitiveVulns} transitive)`);
    lines.push(`- **Flagged libraries**: ${s.flaggedLibs}`);

    if (s.riskiestDirect) {
      lines.push(`- **Riskiest direct dep**: ${s.riskiestDirect.libraryName}@${s.riskiestDirect.libraryVersion} (risk: ${s.riskiestDirect.riskScore})`);
    }
    if (s.riskiestTransitive) {
      lines.push(`- **Riskiest transitive dep**: ${s.riskiestTransitive.libraryName}@${s.riskiestTransitive.libraryVersion} (risk: ${s.riskiestTransitive.riskScore})`);
    }

    // Direct deps table
    if (tree.direct.length) {
      lines.push('');
      lines.push('#### Direct Dependencies');
      lines.push('');
      lines.push('| Library | Version | Source | Risk | Vulns | Flags |');
      lines.push('|---------|---------|--------|------|-------|-------|');
      const sorted = [...tree.direct].sort((a, b) => b.riskScore - a.riskScore);
      for (const lib of sorted) {
        const flags = [];
        if (lib.notMaintained) flags.push('NOT-MAINTAINED');
        if (lib.isDeprecated) flags.push('DEPRECATED');
        if (lib.licenseIssue) flags.push('LICENSE');
        lines.push(`| ${lib.libraryName} | ${lib.libraryVersion} | ${lib.source} | ${lib.riskScore} | ${lib.totalVulns} | ${flags.join(', ') || '-'} |`);
      }
    }

    // Transitive deps table
    if (tree.transitive.length) {
      lines.push('');
      lines.push('#### Transitive Dependencies');
      lines.push('');
      lines.push('| Library | Version | Source | Risk | Vulns | Introduced By | Flags |');
      lines.push('|---------|---------|--------|------|-------|---------------|-------|');
      const sorted = [...tree.transitive].sort((a, b) => b.riskScore - a.riskScore);
      const appEdges = (getMockDependencyEdges()[s.appName] || []);
      for (const lib of sorted) {
        const edge = appEdges.find(e => e.to === lib.libraryName);
        const via = edge ? edge.from : '?';
        const flags = [];
        if (lib.notMaintained) flags.push('NOT-MAINTAINED');
        if (lib.isDeprecated) flags.push('DEPRECATED');
        if (lib.licenseIssue) flags.push('LICENSE');
        lines.push(`| ${lib.libraryName} | ${lib.libraryVersion} | ${lib.source} | ${lib.riskScore} | ${lib.totalVulns} | ${via} | ${flags.join(', ') || '-'} |`);
      }
    }
    lines.push('');
  }

  // Key findings
  lines.push('## Key Findings');
  lines.push('');

  // Find which direct deps introduce the most transitive risk
  const directRiskCarriers = {};
  for (const h of hotspots) {
    if (!directRiskCarriers[h.introducedBy]) {
      directRiskCarriers[h.introducedBy] = { totalRisk: 0, count: 0, vulns: 0 };
    }
    directRiskCarriers[h.introducedBy].totalRisk += h.riskScore;
    directRiskCarriers[h.introducedBy].count += 1;
    directRiskCarriers[h.introducedBy].vulns += h.totalVulns;
  }

  const topCarriers = Object.entries(directRiskCarriers)
    .sort((a, b) => b[1].totalRisk - a[1].totalRisk);

  if (topCarriers.length) {
    lines.push('### Direct Dependencies Introducing Most Transitive Risk');
    lines.push('');
    lines.push('These direct dependencies pull in the most risky transitive deps:');
    lines.push('');
    lines.push('| Direct Dep | Risky Transitive Deps | Total Transitive Risk | Transitive Vulns |');
    lines.push('|------------|----------------------|----------------------|------------------|');
    for (const [name, data] of topCarriers) {
      lines.push(`| ${name} | ${data.count} | ${data.totalRisk} | ${data.vulns} |`);
    }
    lines.push('');
  }

  lines.push('### Recommendations');
  lines.push('');
  lines.push('1. **Update risky direct deps** to pull patched transitive versions');
  for (const [name, data] of topCarriers.slice(0, 3)) {
    lines.push(`   - \`${name}\` introduces ${data.count} risky transitive dep(s) with risk score ${data.totalRisk}`);
  }
  lines.push('2. **Monitor unmaintained/deprecated deps** for available alternatives');
  lines.push('3. **Consider replacing** direct deps that transitively pull known-vulnerable C/C++ libs');
  lines.push('4. **Use lockfiles** (Podfile.lock, Package.resolved) to pin transitive versions');
  lines.push('');

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// API-based SBOM fetch with pagination
// ---------------------------------------------------------------------------
async function fetchAllSBOM(appFilter, limit) {
  const { GET_SBOM_LIBRARIES } = await import('../queries/sbom.js');
  const allLibs = [];
  let offset = 0;
  let total = Infinity;

  while (offset < total) {
    const data = await queryFn(GET_SBOM_LIBRARIES, {
      getSbomLibrariesInput: {
        offset,
        limit,
        filters: {},
        search: appFilter || '',
        owners: [],
      },
    });
    const result = data.getSbomLibraries;
    total = result.total;
    allLibs.push(...result.sbomLibs);
    offset += result.sbomLibs.length;
    process.stdout.write(`\r  Fetched ${allLibs.length}/${total} libraries...`);
    if (result.sbomLibs.length === 0) break;
  }
  console.log('');
  return allLibs;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  const appFilter = process.env.OX_APP_NAME || process.argv[2] || '';
  const limit = parseInt(process.env.OX_LIMIT || '500', 10);

  console.log('Ox Security — Dependency Tree Mapper');
  console.log('='.repeat(50));
  if (USE_MOCK) {
    console.log('No API key found — running with mock data');
  }
  if (appFilter) console.log(`App filter: ${appFilter}`);
  console.log('');

  // Step 1: Fetch SBOM data
  console.log('Step 1: Fetching SBOM libraries...');
  let libs;
  let edges;

  if (USE_MOCK) {
    libs = getMockSBOM();
    edges = getMockDependencyEdges();
    console.log(`  Loaded ${libs.length} libraries (mock data)`);
  } else {
    libs = await fetchAllSBOM(appFilter, limit);
    console.log(`  Fetched ${libs.length} libraries from API`);
    // For real API data, we don't have edge info — infer from package manager heuristics
    edges = {};
  }

  // Apply app filter on mock data too
  if (appFilter && USE_MOCK) {
    libs = libs.filter(l => l.appName.toLowerCase().includes(appFilter.toLowerCase()));
    console.log(`  After app filter: ${libs.length} libraries`);
  }

  // Step 2: Build dependency trees
  console.log('\nStep 2: Building dependency trees...');
  const apps = buildAppTrees(libs, edges);
  console.log(`  Apps found: ${Object.keys(apps).length}`);
  for (const [name, tree] of Object.entries(apps)) {
    console.log(`    ${name}: ${tree.direct.length} direct, ${tree.transitive.length} transitive`);
  }

  // Step 3: Find transitive risk hotspots
  console.log('\nStep 3: Analyzing transitive risk hotspots...');
  const hotspots = findTransitiveRiskHotspots(apps, edges);
  console.log(`  Found ${hotspots.length} risky transitive dependencies`);

  // Step 4: Compute per-app risk summaries
  console.log('\nStep 4: Computing app risk summaries...');
  const appSummaries = computeAppRiskSummaries(apps);

  // Step 5: Output
  const timestamp = new Date().toISOString();
  const outDir = `experiments/dep-tree-${timestamp.slice(0, 10)}`;
  mkdirSync(outDir, { recursive: true });

  // JSON output
  const jsonOut = {
    meta: {
      timestamp,
      mockData: USE_MOCK,
      appFilter: appFilter || null,
      totalLibraries: libs.length,
      appsAnalyzed: Object.keys(apps).length,
    },
    appSummaries,
    hotspots,
    trees: Object.fromEntries(
      Object.entries(apps).map(([name, tree]) => [name, {
        direct: tree.direct,
        transitive: tree.transitive,
        edges: edges[name] || [],
      }])
    ),
  };
  const jsonPath = `${outDir}/dependency-tree.json`;
  writeFileSync(jsonPath, JSON.stringify(jsonOut, null, 2));

  // Markdown report
  const mdReport = generateMarkdown(apps, edges, hotspots, appSummaries, {
    timestamp,
    mockData: USE_MOCK,
    appFilter,
  });
  const mdPath = `${outDir}/dependency-tree-report.md`;
  writeFileSync(mdPath, mdReport);

  // ASCII trees to a separate file for quick reference
  const treeTxt = Object.entries(apps)
    .map(([name, tree]) => renderTree(name, tree, edges))
    .join('\n\n');
  const treePath = `${outDir}/trees.txt`;
  writeFileSync(treePath, treeTxt);

  // Print summary to stdout
  console.log('\n' + '='.repeat(50));
  console.log('Dependency Tree Analysis Complete');
  console.log('='.repeat(50));

  for (const s of appSummaries) {
    console.log(`\n  ${s.appName}:`);
    console.log(`    ${s.directCount} direct + ${s.transitiveCount} transitive deps`);
    console.log(`    Risk: ${s.totalRisk} (${s.transitiveRiskPct}% from transitive)`);
    console.log(`    Vulns: ${s.totalVulns} (direct: ${s.directVulns}, transitive: ${s.transitiveVulns})`);
  }

  if (hotspots.length) {
    console.log(`\nTop Transitive Risk Hotspots:`);
    for (const h of hotspots.slice(0, 8)) {
      const vc = h.vulnerabilityCounts || {};
      console.log(`  ${h.library} [risk: ${h.riskScore}]`);
      console.log(`    via ${h.introducedBy} in ${h.appName}`);
      console.log(`    C:${vc.critical || 0} H:${vc.high || 0} M:${vc.medium || 0} L:${vc.low || 0}`);
    }
  }

  console.log('\nDependency Trees:');
  console.log(treeTxt);

  console.log(`\nOutput files:`);
  console.log(`  JSON:   ${jsonPath}`);
  console.log(`  Report: ${mdPath}`);
  console.log(`  Trees:  ${treePath}`);
}

main().catch(e => { console.error(`\nFatal: ${e.message}`); process.exit(1); });
