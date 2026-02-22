#!/usr/bin/env node
/**
 * E15: Fix Prioritizer
 *
 * Ranks all issues by fixability to help teams allocate remediation effort
 * efficiently. Each issue is classified into a fix tier:
 *
 *   Tier 1: Auto-fix available (Ox can auto-remediate)
 *   Tier 2: Minor/patch version bump (backward-compatible SCA fix)
 *   Tier 3: Major version upgrade (may have breaking changes)
 *   Tier 4: Code change required (manual code fix with guidance)
 *   Tier 5: Manual remediation (no fix info — requires investigation)
 *
 * Each issue also gets an ROI score combining severity weight and fix ease,
 * so teams can prioritize the highest-impact, lowest-effort fixes first.
 *
 * Falls back to realistic mock data when OX_API_KEY is not configured.
 *
 * Usage:
 *   node scripts/fix-prioritizer.js [appFilter]
 *
 * Environment:
 *   OX_APP_NAME    — filter to matching app name
 *   OX_SEVERITY    — comma-separated severities (default: all)
 *   OX_LIMIT       — max issues to fetch (default: 200)
 *   OX_CONCURRENCY — parallel detail fetches (default: 5)
 */
import { writeFileSync, mkdirSync, readFileSync, existsSync } from 'fs';
import { resolve } from 'path';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const SEV_ICON = { Critical: '🔴', High: '🟠', Medium: '🟡', Low: '🔵', Info: '⚪' };
const SEV_WEIGHT = { Critical: 10, High: 5, Medium: 2, Low: 0.5, Info: 0 };

// Fix tier ordering for iteration
const TIER_ORDER = ['AUTO_FIX', 'MINOR_VERSION', 'MAJOR_VERSION', 'CODE_CHANGE', 'MANUAL'];

// Fix tiers — lower number = easier to fix = higher priority
const FIX_TIERS = {
  AUTO_FIX:      { tier: 1, label: 'Auto-Fix Available',    effort: 'Minimal', easeScore: 100, icon: '⚡' },
  MINOR_VERSION: { tier: 2, label: 'Minor/Patch Version Bump', effort: 'Low',  easeScore: 80,  icon: '🔧' },
  MAJOR_VERSION: { tier: 3, label: 'Major Version Upgrade',   effort: 'Medium', easeScore: 50,  icon: '🔨' },
  CODE_CHANGE:   { tier: 4, label: 'Code Change Required',    effort: 'High',   easeScore: 30,  icon: '✏️' },
  MANUAL:        { tier: 5, label: 'Manual Remediation',      effort: 'Very High', easeScore: 10, icon: '🔍' },
};

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
// Mock data — realistic iOS issues with varied fix availability
// ---------------------------------------------------------------------------
function getMockIssues() {
  return [
    // AUTO-FIX: version bump type
    {
      issueId: 'ISS-001', mainTitle: 'Remote Code Execution in libxml2',
      secondTitle: 'CVE-2024-40896 affects libxml2 < 2.12.5 used via CocoaPods',
      severity: 'Critical', originalSeverity: 'Critical', sourceType: 'SCA',
      created: '2025-12-15T10:30:00Z',
      app: { id: 'app-1', name: 'MyBankingApp-iOS' },
      category: { name: 'Vulnerable Dependency' },
    },
    // AUTO-FIX: version bump type
    {
      issueId: 'ISS-002', mainTitle: 'Prototype Pollution in lodash',
      secondTitle: 'lodash < 4.17.21 allows prototype pollution',
      severity: 'Critical', originalSeverity: 'Critical', sourceType: 'SCA',
      created: '2025-11-20T08:00:00Z',
      app: { id: 'app-1', name: 'MyBankingApp-iOS' },
      category: { name: 'Vulnerable Dependency' },
    },
    // NO AUTO-FIX, SAST — manual remediation
    {
      issueId: 'ISS-003', mainTitle: 'Insecure Data Storage — Keychain Missing Accessibility',
      secondTitle: 'Sensitive credentials stored without kSecAttrAccessibleWhenUnlockedThisDeviceOnly',
      severity: 'High', originalSeverity: 'Critical', sourceType: 'SAST',
      created: '2026-01-05T14:20:00Z',
      app: { id: 'app-2', name: 'HealthTracker-iOS' },
      category: { name: 'Mobile Security' },
    },
    // NO AUTO-FIX, SAST — manual
    {
      issueId: 'ISS-004', mainTitle: 'Missing Certificate Pinning',
      secondTitle: 'App does not implement SSL/TLS certificate pinning',
      severity: 'High', originalSeverity: 'High', sourceType: 'SAST',
      created: '2026-01-10T09:15:00Z',
      app: { id: 'app-1', name: 'MyBankingApp-iOS' },
      category: { name: 'Mobile Security' },
    },
    // AUTO-FIX: code change type
    {
      issueId: 'ISS-005', mainTitle: 'SQL Injection in SQLite Query Builder',
      secondTitle: 'User input concatenated directly into SQLite query',
      severity: 'Critical', originalSeverity: 'Critical', sourceType: 'SAST',
      created: '2026-01-18T16:45:00Z',
      app: { id: 'app-2', name: 'HealthTracker-iOS' },
      category: { name: 'Code Vulnerability' },
    },
    // AUTO-FIX: version bump (major only)
    {
      issueId: 'ISS-006', mainTitle: 'Vulnerable OpenSSL in Alamofire',
      secondTitle: 'Alamofire 5.6.x bundles OpenSSL with known CVEs',
      severity: 'High', originalSeverity: 'Critical', sourceType: 'SCA',
      created: '2025-10-22T11:30:00Z',
      app: { id: 'app-1', name: 'MyBankingApp-iOS' },
      category: { name: 'Vulnerable Dependency' },
    },
    // NO AUTO-FIX, secrets — manual
    {
      issueId: 'ISS-007', mainTitle: 'Hardcoded API Key in Source Code',
      secondTitle: 'Firebase API key found in GoogleService-Info.plist',
      severity: 'High', originalSeverity: 'High', sourceType: 'Secret Detection',
      created: '2026-02-01T13:00:00Z',
      app: { id: 'app-3', name: 'ShopEasy-iOS' },
      category: { name: 'Secret Detection' },
    },
    // AUTO-FIX: version bump (minor)
    {
      issueId: 'ISS-008', mainTitle: 'Denial of Service in libexpat',
      secondTitle: 'CVE-2024-50602 — libexpat before 2.6.4 allows DoS',
      severity: 'High', originalSeverity: 'High', sourceType: 'SCA',
      created: '2026-01-25T10:00:00Z',
      app: { id: 'app-2', name: 'HealthTracker-iOS' },
      category: { name: 'Vulnerable Dependency' },
    },
    // AUTO-FIX: code change
    {
      issueId: 'ISS-009', mainTitle: 'Insecure App Transport Security Configuration',
      secondTitle: 'NSAllowsArbitraryLoads set to YES in Info.plist',
      severity: 'High', originalSeverity: 'Medium', sourceType: 'SAST',
      created: '2026-02-05T15:30:00Z',
      app: { id: 'app-3', name: 'ShopEasy-iOS' },
      category: { name: 'Mobile Security' },
    },
    // AUTO-FIX: version bump (major only — breaking)
    {
      issueId: 'ISS-010', mainTitle: 'Outdated React Native with Known Vulnerabilities',
      secondTitle: 'react-native 0.71.x has multiple known CVEs in Hermes engine',
      severity: 'Critical', originalSeverity: 'High', sourceType: 'SCA',
      created: '2026-02-10T09:00:00Z',
      app: { id: 'app-3', name: 'ShopEasy-iOS' },
      category: { name: 'Vulnerable Dependency' },
    },
    // Minor version fix available, no auto-fix
    {
      issueId: 'ISS-011', mainTitle: 'ReDoS in Realm Query Parser',
      secondTitle: 'Realm < 10.45.0 regex parser vulnerable to ReDoS',
      severity: 'Medium', originalSeverity: 'Medium', sourceType: 'SCA',
      created: '2026-01-20T11:00:00Z',
      app: { id: 'app-2', name: 'HealthTracker-iOS' },
      category: { name: 'Vulnerable Dependency' },
    },
    // No fix available at all
    {
      issueId: 'ISS-012', mainTitle: 'Information Disclosure via Error Messages',
      secondTitle: 'Detailed stack traces returned in API error responses',
      severity: 'Medium', originalSeverity: 'Medium', sourceType: 'SAST',
      created: '2026-02-08T14:00:00Z',
      app: { id: 'app-1', name: 'MyBankingApp-iOS' },
      category: { name: 'Code Vulnerability' },
    },
    // Major version fix only, no auto-fix
    {
      issueId: 'ISS-013', mainTitle: 'Buffer Overflow in hermes-engine',
      secondTitle: 'hermes-engine 0.71.x has heap buffer overflow in regex JIT',
      severity: 'High', originalSeverity: 'High', sourceType: 'SCA',
      created: '2026-02-12T09:30:00Z',
      app: { id: 'app-3', name: 'ShopEasy-iOS' },
      category: { name: 'Vulnerable Dependency' },
    },
    // Low severity, auto-fix available
    {
      issueId: 'ISS-014', mainTitle: 'Outdated follow-redirects Dependency',
      secondTitle: 'follow-redirects < 1.15.6 has minor info leak',
      severity: 'Low', originalSeverity: 'Low', sourceType: 'SCA',
      created: '2026-01-30T08:00:00Z',
      app: { id: 'app-3', name: 'ShopEasy-iOS' },
      category: { name: 'Vulnerable Dependency' },
    },
  ];
}

function getMockIssueDetail(issueId) {
  const details = {
    'ISS-001': {
      issueId: 'ISS-001', mainTitle: 'Remote Code Execution in libxml2',
      secondTitle: 'CVE-2024-40896 affects libxml2 < 2.12.5 used via CocoaPods',
      severity: 'Critical', originalSeverity: 'Critical', sourceType: 'SCA',
      created: '2025-12-15T10:30:00Z',
      app: { id: 'app-1', name: 'MyBankingApp-iOS' },
      category: { name: 'Vulnerable Dependency' },
      sbom: { libraryName: 'libxml2', libraryVersion: '2.11.6', packageManager: 'CocoaPods' },
      scaVulnerabilities: [
        { cve: 'CVE-2024-40896', originalSeverity: 'Critical', minorVerWithFix: '2.12.5', majorVerWithFix: '2.12.5' },
        { cve: 'CVE-2024-34459', originalSeverity: 'High', minorVerWithFix: '2.12.7', majorVerWithFix: null },
      ],
      autoFix: { fixType: 'VersionBump', fixTitle: 'Upgrade libxml2 to 2.12.5+', fixDescription: 'Update CocoaPods dependency to pull libxml2 >= 2.12.5' },
    },
    'ISS-002': {
      issueId: 'ISS-002', mainTitle: 'Prototype Pollution in lodash',
      secondTitle: 'lodash < 4.17.21 allows prototype pollution',
      severity: 'Critical', originalSeverity: 'Critical', sourceType: 'SCA',
      created: '2025-11-20T08:00:00Z',
      app: { id: 'app-1', name: 'MyBankingApp-iOS' },
      category: { name: 'Vulnerable Dependency' },
      sbom: { libraryName: 'lodash', libraryVersion: '4.17.19', packageManager: 'npm' },
      scaVulnerabilities: [
        { cve: 'CVE-2021-23337', originalSeverity: 'Critical', minorVerWithFix: '4.17.21', majorVerWithFix: '4.17.21' },
        { cve: 'CVE-2020-28500', originalSeverity: 'Medium', minorVerWithFix: '4.17.21', majorVerWithFix: null },
      ],
      autoFix: { fixType: 'VersionBump', fixTitle: 'Upgrade lodash to 4.17.21', fixDescription: 'Run npm update lodash or pin >= 4.17.21 in package.json' },
    },
    'ISS-003': {
      issueId: 'ISS-003', mainTitle: 'Insecure Data Storage — Keychain Missing Accessibility',
      secondTitle: 'Sensitive credentials stored without kSecAttrAccessibleWhenUnlockedThisDeviceOnly',
      severity: 'High', originalSeverity: 'Critical', sourceType: 'SAST',
      created: '2026-01-05T14:20:00Z',
      app: { id: 'app-2', name: 'HealthTracker-iOS' },
      category: { name: 'Mobile Security' },
      sbom: null, scaVulnerabilities: [], autoFix: null,
    },
    'ISS-004': {
      issueId: 'ISS-004', mainTitle: 'Missing Certificate Pinning',
      secondTitle: 'App does not implement SSL/TLS certificate pinning',
      severity: 'High', originalSeverity: 'High', sourceType: 'SAST',
      created: '2026-01-10T09:15:00Z',
      app: { id: 'app-1', name: 'MyBankingApp-iOS' },
      category: { name: 'Mobile Security' },
      sbom: null, scaVulnerabilities: [], autoFix: null,
    },
    'ISS-005': {
      issueId: 'ISS-005', mainTitle: 'SQL Injection in SQLite Query Builder',
      secondTitle: 'User input concatenated directly into SQLite query',
      severity: 'Critical', originalSeverity: 'Critical', sourceType: 'SAST',
      created: '2026-01-18T16:45:00Z',
      app: { id: 'app-2', name: 'HealthTracker-iOS' },
      category: { name: 'Code Vulnerability' },
      sbom: null, scaVulnerabilities: [],
      autoFix: { fixType: 'CodeChange', fixTitle: 'Use parameterized SQLite queries', fixDescription: 'Replace string concatenation with sqlite3_bind_text() parameterized query.' },
    },
    'ISS-006': {
      issueId: 'ISS-006', mainTitle: 'Vulnerable OpenSSL in Alamofire',
      secondTitle: 'Alamofire 5.6.x bundles OpenSSL with known CVEs',
      severity: 'High', originalSeverity: 'Critical', sourceType: 'SCA',
      created: '2025-10-22T11:30:00Z',
      app: { id: 'app-1', name: 'MyBankingApp-iOS' },
      category: { name: 'Vulnerable Dependency' },
      sbom: { libraryName: 'Alamofire', libraryVersion: '5.6.4', packageManager: 'Swift Package Manager' },
      scaVulnerabilities: [
        { cve: 'CVE-2024-0727', originalSeverity: 'High', minorVerWithFix: null, majorVerWithFix: '5.8.0' },
        { cve: 'CVE-2023-5678', originalSeverity: 'Medium', minorVerWithFix: null, majorVerWithFix: '5.8.0' },
      ],
      autoFix: { fixType: 'VersionBump', fixTitle: 'Upgrade Alamofire to 5.8+', fixDescription: 'Update Package.swift to require Alamofire >= 5.8.0' },
    },
    'ISS-007': {
      issueId: 'ISS-007', mainTitle: 'Hardcoded API Key in Source Code',
      secondTitle: 'Firebase API key found in GoogleService-Info.plist',
      severity: 'High', originalSeverity: 'High', sourceType: 'Secret Detection',
      created: '2026-02-01T13:00:00Z',
      app: { id: 'app-3', name: 'ShopEasy-iOS' },
      category: { name: 'Secret Detection' },
      sbom: null, scaVulnerabilities: [], autoFix: null,
    },
    'ISS-008': {
      issueId: 'ISS-008', mainTitle: 'Denial of Service in libexpat',
      secondTitle: 'CVE-2024-50602 — libexpat before 2.6.4 allows DoS',
      severity: 'High', originalSeverity: 'High', sourceType: 'SCA',
      created: '2026-01-25T10:00:00Z',
      app: { id: 'app-2', name: 'HealthTracker-iOS' },
      category: { name: 'Vulnerable Dependency' },
      sbom: { libraryName: 'libexpat', libraryVersion: '2.5.0', packageManager: 'CocoaPods' },
      scaVulnerabilities: [
        { cve: 'CVE-2024-50602', originalSeverity: 'High', minorVerWithFix: '2.6.4', majorVerWithFix: '2.6.4' },
      ],
      autoFix: { fixType: 'VersionBump', fixTitle: 'Upgrade libexpat to 2.6.4+', fixDescription: 'Update CocoaPods dependency to pull libexpat >= 2.6.4' },
    },
    'ISS-009': {
      issueId: 'ISS-009', mainTitle: 'Insecure App Transport Security Configuration',
      secondTitle: 'NSAllowsArbitraryLoads set to YES in Info.plist',
      severity: 'High', originalSeverity: 'Medium', sourceType: 'SAST',
      created: '2026-02-05T15:30:00Z',
      app: { id: 'app-3', name: 'ShopEasy-iOS' },
      category: { name: 'Mobile Security' },
      sbom: null, scaVulnerabilities: [],
      autoFix: { fixType: 'CodeChange', fixTitle: 'Remove NSAllowsArbitraryLoads from Info.plist', fixDescription: 'Set NSAllowsArbitraryLoads to NO; add exception domains only for required HTTP hosts.' },
    },
    'ISS-010': {
      issueId: 'ISS-010', mainTitle: 'Outdated React Native with Known Vulnerabilities',
      secondTitle: 'react-native 0.71.x has multiple known CVEs in Hermes engine',
      severity: 'Critical', originalSeverity: 'High', sourceType: 'SCA',
      created: '2026-02-10T09:00:00Z',
      app: { id: 'app-3', name: 'ShopEasy-iOS' },
      category: { name: 'Vulnerable Dependency' },
      sbom: { libraryName: 'react-native', libraryVersion: '0.71.8', packageManager: 'npm' },
      scaVulnerabilities: [
        { cve: 'CVE-2024-21514', originalSeverity: 'High', minorVerWithFix: null, majorVerWithFix: '0.73.0' },
        { cve: 'CVE-2024-28244', originalSeverity: 'High', minorVerWithFix: null, majorVerWithFix: '0.73.0' },
      ],
      autoFix: { fixType: 'VersionBump', fixTitle: 'Upgrade React Native to 0.73+', fixDescription: 'Update react-native to >= 0.73.0. Major version upgrade — may require code changes.' },
    },
    'ISS-011': {
      issueId: 'ISS-011', mainTitle: 'ReDoS in Realm Query Parser',
      secondTitle: 'Realm < 10.45.0 regex parser vulnerable to ReDoS',
      severity: 'Medium', originalSeverity: 'Medium', sourceType: 'SCA',
      created: '2026-01-20T11:00:00Z',
      app: { id: 'app-2', name: 'HealthTracker-iOS' },
      category: { name: 'Vulnerable Dependency' },
      sbom: { libraryName: 'Realm', libraryVersion: '10.44.0', packageManager: 'CocoaPods' },
      scaVulnerabilities: [
        { cve: 'CVE-2024-41110', originalSeverity: 'Medium', minorVerWithFix: '10.45.0', majorVerWithFix: null },
      ],
      autoFix: null,
    },
    'ISS-012': {
      issueId: 'ISS-012', mainTitle: 'Information Disclosure via Error Messages',
      secondTitle: 'Detailed stack traces returned in API error responses',
      severity: 'Medium', originalSeverity: 'Medium', sourceType: 'SAST',
      created: '2026-02-08T14:00:00Z',
      app: { id: 'app-1', name: 'MyBankingApp-iOS' },
      category: { name: 'Code Vulnerability' },
      sbom: null, scaVulnerabilities: [], autoFix: null,
    },
    'ISS-013': {
      issueId: 'ISS-013', mainTitle: 'Buffer Overflow in hermes-engine',
      secondTitle: 'hermes-engine 0.71.x has heap buffer overflow in regex JIT',
      severity: 'High', originalSeverity: 'High', sourceType: 'SCA',
      created: '2026-02-12T09:30:00Z',
      app: { id: 'app-3', name: 'ShopEasy-iOS' },
      category: { name: 'Vulnerable Dependency' },
      sbom: { libraryName: 'hermes-engine', libraryVersion: '0.71.14', packageManager: 'npm' },
      scaVulnerabilities: [
        { cve: 'CVE-2024-49relative', originalSeverity: 'High', minorVerWithFix: null, majorVerWithFix: '0.73.0' },
      ],
      autoFix: null,
    },
    'ISS-014': {
      issueId: 'ISS-014', mainTitle: 'Outdated follow-redirects Dependency',
      secondTitle: 'follow-redirects < 1.15.6 has minor info leak',
      severity: 'Low', originalSeverity: 'Low', sourceType: 'SCA',
      created: '2026-01-30T08:00:00Z',
      app: { id: 'app-3', name: 'ShopEasy-iOS' },
      category: { name: 'Vulnerable Dependency' },
      sbom: { libraryName: 'follow-redirects', libraryVersion: '1.15.3', packageManager: 'npm' },
      scaVulnerabilities: [
        { cve: 'CVE-2024-28849', originalSeverity: 'Low', minorVerWithFix: '1.15.6', majorVerWithFix: null },
      ],
      autoFix: { fixType: 'VersionBump', fixTitle: 'Upgrade follow-redirects to 1.15.6+', fixDescription: 'Run npm update follow-redirects' },
    },
  };
  return details[issueId] || null;
}

// ---------------------------------------------------------------------------
// Fix tier classification engine
// ---------------------------------------------------------------------------

/**
 * Classify an enriched issue detail into a fix tier.
 *
 * Priority order:
 *   1. Auto-fix with VersionBump and minor version available → AUTO_FIX
 *   2. Auto-fix with VersionBump but only major version → depends on version analysis
 *   3. Auto-fix with CodeChange → CODE_CHANGE (but still auto-fixable, so tier 1)
 *   4. No auto-fix but SCA with minorVerWithFix → MINOR_VERSION
 *   5. No auto-fix but SCA with majorVerWithFix → MAJOR_VERSION
 *   6. Everything else → MANUAL
 */
function classifyFixTier(detail) {
  if (!detail) return { tierKey: 'MANUAL', reason: 'No detail available' };

  const hasAutoFix = !!detail.autoFix;
  const vulns = detail.scaVulnerabilities || [];
  const hasMinorFix = vulns.some(v => v.minorVerWithFix);
  const hasMajorFix = vulns.some(v => v.majorVerWithFix);

  // Determine fix version info
  const minorFixVersions = [...new Set(vulns.filter(v => v.minorVerWithFix).map(v => v.minorVerWithFix))];
  const majorFixVersions = [...new Set(vulns.filter(v => v.majorVerWithFix).map(v => v.majorVerWithFix))];

  if (hasAutoFix) {
    // Auto-fix available — classify sub-type
    if (detail.autoFix.fixType === 'VersionBump') {
      if (hasMinorFix) {
        return {
          tierKey: 'AUTO_FIX',
          reason: `Auto-fix: ${detail.autoFix.fixTitle}`,
          fixAction: detail.autoFix.fixDescription,
          fixVersions: minorFixVersions,
          breakingChange: false,
        };
      }
      if (hasMajorFix) {
        // Auto-fix exists but it's a major version bump — still auto-fixable but flag breaking changes
        return {
          tierKey: 'AUTO_FIX',
          reason: `Auto-fix (major upgrade): ${detail.autoFix.fixTitle}`,
          fixAction: detail.autoFix.fixDescription,
          fixVersions: majorFixVersions,
          breakingChange: true,
        };
      }
      return {
        tierKey: 'AUTO_FIX',
        reason: `Auto-fix: ${detail.autoFix.fixTitle}`,
        fixAction: detail.autoFix.fixDescription,
        fixVersions: [],
        breakingChange: false,
      };
    }
    if (detail.autoFix.fixType === 'CodeChange') {
      return {
        tierKey: 'AUTO_FIX',
        reason: `Auto-fix (code change): ${detail.autoFix.fixTitle}`,
        fixAction: detail.autoFix.fixDescription,
        fixVersions: [],
        breakingChange: false,
      };
    }
    // Unknown auto-fix type — still auto-fixable
    return {
      tierKey: 'AUTO_FIX',
      reason: `Auto-fix: ${detail.autoFix.fixTitle || detail.autoFix.fixType}`,
      fixAction: detail.autoFix.fixDescription,
      fixVersions: [],
      breakingChange: false,
    };
  }

  // No auto-fix — check SCA fix versions
  if (hasMinorFix) {
    return {
      tierKey: 'MINOR_VERSION',
      reason: `Minor/patch version fix available: ${minorFixVersions.join(', ')}`,
      fixAction: `Upgrade to version ${minorFixVersions.join(' or ')}`,
      fixVersions: minorFixVersions,
      breakingChange: false,
    };
  }

  if (hasMajorFix) {
    return {
      tierKey: 'MAJOR_VERSION',
      reason: `Major version upgrade required: ${majorFixVersions.join(', ')}`,
      fixAction: `Upgrade to version ${majorFixVersions.join(' or ')} — breaking changes possible`,
      fixVersions: majorFixVersions,
      breakingChange: true,
    };
  }

  // No fix info at all
  if (detail.sourceType === 'SAST' || detail.sourceType === 'Secret Detection') {
    return {
      tierKey: 'CODE_CHANGE',
      reason: `${detail.sourceType} finding — requires manual code review and fix`,
      fixAction: null,
      fixVersions: [],
      breakingChange: false,
    };
  }

  return {
    tierKey: 'MANUAL',
    reason: 'No fix information available — requires investigation',
    fixAction: null,
    fixVersions: [],
    breakingChange: false,
  };
}

/**
 * Compute an ROI score: severity weight * ease of fix.
 * Higher = fix this first (high impact + easy fix = best ROI).
 */
function computeROI(severity, tierKey) {
  const sevW = SEV_WEIGHT[severity] || 1;
  const easeS = FIX_TIERS[tierKey]?.easeScore || 10;
  return Math.round(sevW * easeS);
}

// ---------------------------------------------------------------------------
// API fetching with concurrency control
// ---------------------------------------------------------------------------
async function fetchIssueDetail(issueId) {
  if (USE_MOCK) return getMockIssueDetail(issueId);
  try {
    const { GET_SINGLE_ISSUE } = await import('../queries/issues.js');
    const data = await queryFn(GET_SINGLE_ISSUE, { getSingleIssueInput: { issueId } });
    return data.getSingleIssueInfo;
  } catch (e) {
    try {
      await new Promise(r => setTimeout(r, 1000));
      const { GET_SINGLE_ISSUE } = await import('../queries/issues.js');
      const data = await queryFn(GET_SINGLE_ISSUE, { getSingleIssueInput: { issueId } });
      return data.getSingleIssueInfo;
    } catch (e2) {
      return null;
    }
  }
}

async function fetchAllDetails(issues, concurrency) {
  const results = [];
  for (let i = 0; i < issues.length; i += concurrency) {
    const batch = issues.slice(i, i + concurrency);
    const batchResults = await Promise.all(batch.map(iss => fetchIssueDetail(iss.issueId)));
    results.push(...batchResults);
    const done = Math.min(i + concurrency, issues.length);
    process.stdout.write(`\r  Enriched ${done}/${issues.length} issues...`);
  }
  console.log('');
  return results;
}

// ---------------------------------------------------------------------------
// Analysis pipeline
// ---------------------------------------------------------------------------
function analyzeIssues(details) {
  const classified = [];

  for (const detail of details) {
    if (!detail) continue;

    const tierInfo = classifyFixTier(detail);
    const tier = FIX_TIERS[tierInfo.tierKey];
    const roi = computeROI(detail.severity, tierInfo.tierKey);

    classified.push({
      issueId: detail.issueId,
      mainTitle: detail.mainTitle,
      secondTitle: detail.secondTitle,
      severity: detail.severity,
      originalSeverity: detail.originalSeverity,
      sourceType: detail.sourceType,
      created: detail.created,
      app: detail.app,
      category: detail.category?.name,
      library: detail.sbom ? {
        name: detail.sbom.libraryName,
        version: detail.sbom.libraryVersion,
        packageManager: detail.sbom.packageManager,
      } : null,
      cveCount: (detail.scaVulnerabilities || []).length,
      cves: (detail.scaVulnerabilities || []).map(v => v.cve),
      // Fix classification
      fixTier: tier.tier,
      fixTierLabel: tier.label,
      fixTierKey: tierInfo.tierKey,
      fixEffort: tier.effort,
      fixIcon: tier.icon,
      fixReason: tierInfo.reason,
      fixAction: tierInfo.fixAction,
      fixVersions: tierInfo.fixVersions,
      breakingChange: tierInfo.breakingChange,
      hasAutoFix: !!detail.autoFix,
      autoFixType: detail.autoFix?.fixType || null,
      // ROI
      roiScore: roi,
      sevWeight: SEV_WEIGHT[detail.severity] || 0,
    });
  }

  // Sort by ROI score descending (best fixes first)
  classified.sort((a, b) => b.roiScore - a.roiScore || a.fixTier - b.fixTier);

  return classified;
}

// ---------------------------------------------------------------------------
// Statistics computation
// ---------------------------------------------------------------------------
function computeStats(classified) {
  const totalIssues = classified.length;
  const byTier = {};
  const byApp = {};
  const bySeverity = {};

  for (const c of classified) {
    // By tier
    if (!byTier[c.fixTierKey]) byTier[c.fixTierKey] = { count: 0, issues: [], sevCounts: {} };
    byTier[c.fixTierKey].count++;
    byTier[c.fixTierKey].issues.push(c);
    byTier[c.fixTierKey].sevCounts[c.severity] = (byTier[c.fixTierKey].sevCounts[c.severity] || 0) + 1;

    // By app
    const appName = c.app?.name || 'Unknown';
    if (!byApp[appName]) byApp[appName] = { total: 0, tiers: {}, quickWins: 0, totalROI: 0 };
    byApp[appName].total++;
    byApp[appName].tiers[c.fixTierKey] = (byApp[appName].tiers[c.fixTierKey] || 0) + 1;
    byApp[appName].totalROI += c.roiScore;
    if (c.fixTier <= 2) byApp[appName].quickWins++;

    // By severity
    if (!bySeverity[c.severity]) bySeverity[c.severity] = { total: 0, fixable: 0, autoFix: 0, manual: 0 };
    bySeverity[c.severity].total++;
    if (c.fixTier <= 3) bySeverity[c.severity].fixable++;
    if (c.fixTier === 1) bySeverity[c.severity].autoFix++;
    if (c.fixTier === 5) bySeverity[c.severity].manual++;
  }

  // Quick wins = auto-fix + minor version (tiers 1 & 2)
  const quickWins = classified.filter(c => c.fixTier <= 2);
  const fixableCount = classified.filter(c => c.fixTier <= 3).length;
  const autoFixCount = classified.filter(c => c.fixTier === 1).length;
  const manualCount = classified.filter(c => c.fixTier >= 4).length;

  // Breaking change warnings
  const breakingChanges = classified.filter(c => c.breakingChange);

  return {
    totalIssues,
    autoFixCount,
    fixableCount,
    manualCount,
    quickWinCount: quickWins.length,
    quickWins,
    breakingChanges,
    fixablePercent: totalIssues > 0 ? Math.round((fixableCount / totalIssues) * 100) : 0,
    autoFixPercent: totalIssues > 0 ? Math.round((autoFixCount / totalIssues) * 100) : 0,
    byTier,
    byApp,
    bySeverity,
    avgROI: totalIssues > 0 ? Math.round(classified.reduce((s, c) => s + c.roiScore, 0) / totalIssues) : 0,
  };
}

// ---------------------------------------------------------------------------
// Console output
// ---------------------------------------------------------------------------
function renderConsole(classified, stats) {
  const lines = [];

  lines.push('');
  lines.push('='.repeat(70));
  lines.push('  E15: Fix Prioritizer');
  lines.push('  Ox Security — Remediation Priority Analysis');
  lines.push('='.repeat(70));
  if (USE_MOCK) lines.push('\n[Mock Mode — using realistic sample data]');
  lines.push('');

  // Overview bar chart
  lines.push('Fix Tier Distribution');
  lines.push('-'.repeat(50));
  for (const key of TIER_ORDER) {
    const tier = FIX_TIERS[key];
    const count = stats.byTier[key]?.count || 0;
    const pct = stats.totalIssues > 0 ? Math.round((count / stats.totalIssues) * 100) : 0;
    const barLen = Math.min(25, Math.max(0, Math.round(pct / 2)));
    const bar = '\u2588'.repeat(barLen) + '\u2591'.repeat(25 - barLen);
    lines.push(`  ${tier.icon} Tier ${tier.tier}: ${tier.label.padEnd(26)} ${bar} ${String(count).padStart(3)} (${String(pct).padStart(3)}%)`);
  }
  lines.push('');

  // Key metrics
  lines.push('Key Metrics');
  lines.push('-'.repeat(50));
  lines.push(`  Total issues analyzed:     ${stats.totalIssues}`);
  lines.push(`  Auto-fixable (Tier 1):     ${stats.autoFixCount} (${stats.autoFixPercent}%)`);
  lines.push(`  Fixable (Tiers 1-3):       ${stats.fixableCount} (${stats.fixablePercent}%)`);
  lines.push(`  Manual remediation needed:  ${stats.manualCount}`);
  lines.push(`  Quick wins (Tiers 1-2):    ${stats.quickWinCount}`);
  lines.push(`  Breaking changes possible:  ${stats.breakingChanges.length}`);
  lines.push(`  Average ROI score:         ${stats.avgROI}`);
  lines.push('');

  // Severity x fixability matrix
  lines.push('Severity vs Fixability Matrix');
  lines.push('-'.repeat(50));
  lines.push('  Severity     Total  AutoFix  Fixable  Manual');
  lines.push('  ' + '-'.repeat(48));
  for (const sev of ['Critical', 'High', 'Medium', 'Low', 'Info']) {
    const s = stats.bySeverity[sev];
    if (!s) continue;
    lines.push(`  ${(SEV_ICON[sev] + ' ' + sev).padEnd(15)} ${String(s.total).padStart(5)}  ${String(s.autoFix).padStart(7)}  ${String(s.fixable).padStart(7)}  ${String(s.manual).padStart(6)}`);
  }
  lines.push('');

  // Per-app summary
  lines.push('Per-App Remediation Summary');
  lines.push('-'.repeat(50));
  const appNames = Object.keys(stats.byApp).sort();
  for (const appName of appNames) {
    const a = stats.byApp[appName];
    lines.push(`\n  ${appName}`);
    lines.push(`    Total issues: ${a.total} | Quick wins: ${a.quickWins} | Avg ROI: ${a.total > 0 ? Math.round(a.totalROI / a.total) : 0}`);
    const tierParts = [];
    for (const key of TIER_ORDER) {
      const count = a.tiers[key] || 0;
      if (count > 0) tierParts.push(`${FIX_TIERS[key].icon} T${FIX_TIERS[key].tier}:${count}`);
    }
    lines.push(`    Tiers: ${tierParts.join('  ')}`);
  }
  lines.push('');

  // Top ROI ranked list (all issues sorted by ROI)
  lines.push('Prioritized Fix List (by ROI Score)');
  lines.push('-'.repeat(50));
  lines.push('  ROI  Tier  Severity     Issue');
  lines.push('  ' + '-'.repeat(68));
  for (const c of classified.slice(0, 20)) {
    const sevStr = `${SEV_ICON[c.severity]} ${c.severity}`;
    lines.push(`  ${String(c.roiScore).padStart(4)}  T${c.fixTier}    ${sevStr.padEnd(15)} ${c.mainTitle.slice(0, 45)}`);
    if (c.fixAction) {
      lines.push(`${' '.repeat(32)}→ ${c.fixAction.slice(0, 55)}`);
    }
  }
  if (classified.length > 20) {
    lines.push(`  ... and ${classified.length - 20} more issues`);
  }
  lines.push('');

  // Quick wins callout
  if (stats.quickWins.length > 0) {
    lines.push('Quick Wins — Fix These First');
    lines.push('-'.repeat(50));
    lines.push('  These issues have auto-fix or minor version bump available:');
    lines.push('');
    for (const c of stats.quickWins) {
      lines.push(`  ${c.fixIcon} [${c.severity}] ${c.mainTitle}`);
      if (c.library) lines.push(`    Library: ${c.library.name}@${c.library.version} (${c.library.packageManager})`);
      lines.push(`    Fix: ${c.fixReason}`);
      if (c.fixAction) lines.push(`    Action: ${c.fixAction}`);
      lines.push('');
    }
  }

  // Breaking change warnings
  if (stats.breakingChanges.length > 0) {
    lines.push('Breaking Change Warnings');
    lines.push('-'.repeat(50));
    for (const c of stats.breakingChanges) {
      lines.push(`  ${SEV_ICON[c.severity]} ${c.mainTitle}`);
      if (c.library) lines.push(`    ${c.library.name}: ${c.library.version} → ${c.fixVersions.join(', ')}`);
      lines.push(`    ${c.fixReason}`);
      lines.push('');
    }
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Markdown report
// ---------------------------------------------------------------------------
function generateMarkdown(classified, stats, timestamp) {
  const lines = [];

  lines.push('# E15: Fix Prioritizer Report');
  lines.push(`\n*Generated: ${timestamp}*`);
  if (USE_MOCK) lines.push('\n> **Mock Mode** — using realistic sample data (no OX_API_KEY configured)');
  lines.push('');

  // Methodology
  lines.push('## Fix Tier Methodology');
  lines.push('');
  lines.push('Issues are classified into 5 fix tiers based on remediation effort:');
  lines.push('');
  lines.push('| Tier | Label | Effort | Ease Score | Description |');
  lines.push('|------|-------|--------|------------|-------------|');
  for (const key of TIER_ORDER) {
    const t = FIX_TIERS[key];
    const desc = {
      AUTO_FIX: 'Ox can auto-remediate or provides a ready-to-apply fix',
      MINOR_VERSION: 'SCA issue fixable with a backward-compatible version bump',
      MAJOR_VERSION: 'SCA issue requiring a major version upgrade (may break APIs)',
      CODE_CHANGE: 'Requires manual code modification with guidance',
      MANUAL: 'No fix information — requires investigation and manual remediation',
    }[key];
    lines.push(`| ${t.icon} T${t.tier} | ${t.label} | ${t.effort} | ${t.easeScore} | ${desc} |`);
  }
  lines.push('');
  lines.push('**ROI Score** = Severity Weight × Ease Score. Higher = fix first (high impact + easy fix).');
  lines.push('');
  lines.push('Severity weights: Critical=10, High=5, Medium=2, Low=0.5');
  lines.push('');

  // Overview stats
  lines.push('## Overview');
  lines.push('');
  lines.push('| Metric | Value |');
  lines.push('|--------|-------|');
  lines.push(`| Total issues | ${stats.totalIssues} |`);
  lines.push(`| Auto-fixable (Tier 1) | ${stats.autoFixCount} (${stats.autoFixPercent}%) |`);
  lines.push(`| Fixable (Tiers 1-3) | ${stats.fixableCount} (${stats.fixablePercent}%) |`);
  lines.push(`| Manual remediation | ${stats.manualCount} |`);
  lines.push(`| Quick wins (Tiers 1-2) | ${stats.quickWinCount} |`);
  lines.push(`| Breaking changes | ${stats.breakingChanges.length} |`);
  lines.push(`| Average ROI score | ${stats.avgROI} |`);
  lines.push('');

  // Tier distribution
  lines.push('## Fix Tier Distribution');
  lines.push('');
  lines.push('| Tier | Label | Count | % | Severities |');
  lines.push('|------|-------|-------|---|------------|');
  for (const key of TIER_ORDER) {
    const tier = FIX_TIERS[key];
    const bt = stats.byTier[key];
    const count = bt?.count || 0;
    const pct = stats.totalIssues > 0 ? Math.round((count / stats.totalIssues) * 100) : 0;
    const sevParts = [];
    for (const sev of ['Critical', 'High', 'Medium', 'Low']) {
      const sc = bt?.sevCounts?.[sev] || 0;
      if (sc > 0) sevParts.push(`${sev}: ${sc}`);
    }
    lines.push(`| ${tier.icon} T${tier.tier} | ${tier.label} | ${count} | ${pct}% | ${sevParts.join(', ') || '-'} |`);
  }
  lines.push('');

  // Severity vs fixability
  lines.push('## Severity vs Fixability');
  lines.push('');
  lines.push('| Severity | Total | Auto-Fix | Fixable (T1-3) | Manual (T4-5) |');
  lines.push('|----------|-------|----------|----------------|---------------|');
  for (const sev of ['Critical', 'High', 'Medium', 'Low', 'Info']) {
    const s = stats.bySeverity[sev];
    if (!s) continue;
    lines.push(`| ${SEV_ICON[sev]} ${sev} | ${s.total} | ${s.autoFix} | ${s.fixable} | ${s.manual} |`);
  }
  lines.push('');

  // Per-app breakdown
  lines.push('## Per-App Remediation Summary');
  lines.push('');
  const appNames = Object.keys(stats.byApp).sort();
  for (const appName of appNames) {
    const a = stats.byApp[appName];
    lines.push(`### ${appName}`);
    lines.push('');
    lines.push(`- **Total issues:** ${a.total}`);
    lines.push(`- **Quick wins (T1-2):** ${a.quickWins}`);
    lines.push(`- **Average ROI:** ${a.total > 0 ? Math.round(a.totalROI / a.total) : 0}`);
    lines.push('');
    lines.push('| Tier | Count |');
    lines.push('|------|-------|');
    for (const key of TIER_ORDER) {
      const count = a.tiers[key] || 0;
      if (count > 0) {
        lines.push(`| ${FIX_TIERS[key].icon} T${FIX_TIERS[key].tier}: ${FIX_TIERS[key].label} | ${count} |`);
      }
    }
    lines.push('');
  }

  // Full prioritized list
  lines.push('## Prioritized Fix List');
  lines.push('');
  lines.push('Sorted by ROI score (highest = fix first):');
  lines.push('');
  lines.push('| Rank | ROI | Tier | Severity | App | Issue | Fix Action |');
  lines.push('|------|-----|------|----------|-----|-------|------------|');
  classified.forEach((c, i) => {
    const lib = c.library ? `${c.library.name}@${c.library.version}` : '';
    const action = c.fixAction ? c.fixAction.slice(0, 60) : c.fixReason.slice(0, 60);
    lines.push(`| ${i + 1} | ${c.roiScore} | ${c.fixIcon} T${c.fixTier} | ${SEV_ICON[c.severity]} ${c.severity} | ${c.app?.name || 'N/A'} | ${c.mainTitle}${lib ? ` (${lib})` : ''} | ${action} |`);
  });
  lines.push('');

  // Quick wins
  if (stats.quickWins.length > 0) {
    lines.push('## Quick Wins — Fix These First');
    lines.push('');
    lines.push('These issues have auto-fix or minor version bump available and offer the best remediation ROI:');
    lines.push('');
    for (const c of stats.quickWins) {
      lines.push(`### ${c.fixIcon} [${c.severity}] ${c.mainTitle}`);
      lines.push('');
      lines.push(`- **Issue ID:** ${c.issueId}`);
      lines.push(`- **App:** ${c.app?.name || 'N/A'}`);
      lines.push(`- **ROI Score:** ${c.roiScore}`);
      lines.push(`- **Tier:** T${c.fixTier} — ${c.fixTierLabel}`);
      if (c.library) lines.push(`- **Library:** ${c.library.name}@${c.library.version} (${c.library.packageManager})`);
      if (c.cves.length) lines.push(`- **CVEs:** ${c.cves.join(', ')}`);
      lines.push(`- **Fix:** ${c.fixReason}`);
      if (c.fixAction) lines.push(`- **Action:** ${c.fixAction}`);
      if (c.breakingChange) lines.push(`- **Warning:** Breaking changes possible`);
      lines.push('');
    }
  }

  // Breaking changes
  if (stats.breakingChanges.length > 0) {
    lines.push('## Breaking Change Warnings');
    lines.push('');
    lines.push('These fixes involve major version upgrades that may require code changes:');
    lines.push('');
    for (const c of stats.breakingChanges) {
      lines.push(`- **${c.mainTitle}** (${c.app?.name})`);
      if (c.library) lines.push(`  - ${c.library.name}: ${c.library.version} → ${c.fixVersions.join(', ')}`);
      lines.push(`  - ${c.fixReason}`);
    }
    lines.push('');
  }

  // Recommendations
  lines.push('## Recommendations');
  lines.push('');

  if (stats.autoFixPercent > 0) {
    lines.push(`1. **Start with auto-fixes:** ${stats.autoFixCount} issues (${stats.autoFixPercent}%) can be auto-remediated. Apply these immediately for maximum risk reduction with minimal effort.`);
  }
  if (stats.quickWinCount > stats.autoFixCount) {
    const minorOnly = stats.quickWinCount - stats.autoFixCount;
    lines.push(`2. **Apply minor version bumps:** ${minorOnly} additional issue(s) fixable with backward-compatible version updates.`);
  }
  if (stats.breakingChanges.length > 0) {
    lines.push(`3. **Plan major upgrades:** ${stats.breakingChanges.length} issue(s) require major version upgrades. Schedule these in sprint planning with proper testing.`);
  }
  if (stats.manualCount > 0) {
    lines.push(`4. **Investigate manual fixes:** ${stats.manualCount} issue(s) need manual investigation. Triage these by severity in code review sessions.`);
  }

  // Compute theoretical risk reduction from quick wins
  const totalSevWeight = classified.reduce((s, c) => s + c.sevWeight, 0);
  const quickWinSevWeight = stats.quickWins.reduce((s, c) => s + c.sevWeight, 0);
  const reductionPct = totalSevWeight > 0 ? Math.round((quickWinSevWeight / totalSevWeight) * 100) : 0;
  lines.push('');
  lines.push(`**Impact projection:** Fixing all quick wins (Tiers 1-2) would address ${reductionPct}% of the total severity-weighted risk.`);
  lines.push('');

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  const appFilter = process.env.OX_APP_NAME || process.argv[2] || '';
  const sevArg = process.env.OX_SEVERITY || '';
  const limit = parseInt(process.env.OX_LIMIT || '200', 10);
  const concurrency = parseInt(process.env.OX_CONCURRENCY || '5', 10);
  const targetSeverities = sevArg ? sevArg.split(',').map(s => s.trim()) : [];
  const timestamp = new Date().toISOString();

  console.log('E15: Fix Prioritizer');
  console.log('='.repeat(50));
  if (USE_MOCK) console.log('  No API key found — running with mock data');
  console.log(`  App filter: ${appFilter || 'all'}`);
  console.log(`  Severity filter: ${targetSeverities.length ? targetSeverities.join(', ') : 'all'}`);
  console.log('');

  // Step 1: Fetch issue list
  console.log('Step 1: Fetching issue list...');
  let issues;
  if (USE_MOCK) {
    issues = getMockIssues();
    console.log(`  Loaded ${issues.length} mock issues`);
  } else {
    const { GET_ISSUES } = await import('../queries/issues.js');
    const data = await queryFn(GET_ISSUES, {
      isDemo: false,
      getIssuesInput: {
        offset: 0, limit,
        sort: { fields: ['Severity'], order: ['DESC'] },
      },
    });
    issues = data.getIssues.issues;
    console.log(`  Fetched ${issues.length}/${data.getIssues.totalFilteredIssues} issues`);
  }

  // Apply filters
  if (targetSeverities.length) {
    issues = issues.filter(i => targetSeverities.includes(i.severity));
    console.log(`  After severity filter: ${issues.length}`);
  }
  if (appFilter) {
    issues = issues.filter(i => i.app?.name?.toLowerCase().includes(appFilter.toLowerCase()));
    console.log(`  After app filter: ${issues.length}`);
  }

  if (issues.length === 0) {
    console.log('\nNo issues match the filter criteria.');
    return;
  }

  // Step 2: Fetch detailed info for each issue
  console.log(`\nStep 2: Fetching details for ${issues.length} issues...`);
  const details = await fetchAllDetails(issues, concurrency);
  const validDetails = details.filter(d => d !== null);
  console.log(`  Successfully enriched: ${validDetails.length}/${issues.length}`);

  // Step 3: Classify and score
  console.log('\nStep 3: Classifying fix tiers and computing ROI...');
  const classified = analyzeIssues(validDetails);

  // Step 4: Compute statistics
  const stats = computeStats(classified);

  // Step 5: Output
  const consoleOutput = renderConsole(classified, stats);
  console.log(consoleOutput);

  // Write to experiments/
  const dateStr = timestamp.slice(0, 10);
  const outDir = resolve(process.cwd(), 'experiments', `fix-priority-${dateStr}`);
  mkdirSync(outDir, { recursive: true });

  // JSON
  const jsonData = {
    meta: {
      timestamp,
      mockData: USE_MOCK,
      appFilter: appFilter || null,
      severityFilter: targetSeverities.length ? targetSeverities : 'all',
      totalIssues: stats.totalIssues,
    },
    methodology: {
      fixTiers: Object.fromEntries(
        Object.entries(FIX_TIERS).map(([k, v]) => [k, { tier: v.tier, label: v.label, effort: v.effort, easeScore: v.easeScore }])
      ),
      severityWeights: SEV_WEIGHT,
      roiFormula: 'ROI = severityWeight * fixEaseScore',
    },
    summary: {
      totalIssues: stats.totalIssues,
      autoFixCount: stats.autoFixCount,
      autoFixPercent: stats.autoFixPercent,
      fixableCount: stats.fixableCount,
      fixablePercent: stats.fixablePercent,
      manualCount: stats.manualCount,
      quickWinCount: stats.quickWinCount,
      breakingChangeCount: stats.breakingChanges.length,
      avgROI: stats.avgROI,
    },
    byTier: Object.fromEntries(
      TIER_ORDER.map(key => [key, {
        count: stats.byTier[key]?.count || 0,
        sevCounts: stats.byTier[key]?.sevCounts || {},
      }])
    ),
    byApp: stats.byApp,
    bySeverity: stats.bySeverity,
    issues: classified,
  };
  writeFileSync(resolve(outDir, 'fix-priority.json'), JSON.stringify(jsonData, null, 2));

  // Markdown
  const mdReport = generateMarkdown(classified, stats, timestamp);
  writeFileSync(resolve(outDir, 'fix-priority-report.md'), mdReport);

  console.log(`\nResults written to experiments/fix-priority-${dateStr}/`);
  console.log('  - fix-priority.json       (machine-readable)');
  console.log('  - fix-priority-report.md  (human-readable)');
}

main().catch(e => { console.error(`\nFatal: ${e.message}`); process.exit(1); });
