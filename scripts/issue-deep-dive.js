#!/usr/bin/env node
/**
 * E07: Issue Deep-Dive
 *
 * Fetches all critical and high severity issues, then enriches each one
 * with full detail: CVEs, fix suggestions, severity change reasons,
 * auto-fix info, and SBOM context. Writes an enriched JSON dump and
 * a detailed markdown report to experiments/.
 *
 * Falls back to realistic mock data when OX_API_KEY is not configured.
 *
 * Usage:
 *   node scripts/issue-deep-dive.js [severity] [appFilter]
 *
 * Environment:
 *   OX_APP_NAME    — filter issues to matching app name
 *   OX_SEVERITY    — comma-separated severities (default: Critical,High)
 *   OX_LIMIT       — max issues to fetch from list (default: 200)
 *   OX_CONCURRENCY — parallel detail fetches (default: 5)
 */
import { writeFileSync, mkdirSync, readFileSync, existsSync } from 'fs';
import { resolve } from 'path';

// Severity icons for display
const SEV_ICON = { Critical: '🔴', High: '🟠', Medium: '🟡', Low: '🔵', Info: '⚪' };

// ---------------------------------------------------------------------------
// API key detection — load .env manually to check before importing ox-client
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

// Dynamic import of real client only when API key exists
let queryFn;
if (!USE_MOCK) {
  const client = await import('../lib/ox-client.js');
  queryFn = client.query;
}

// ---------------------------------------------------------------------------
// Mock data — realistic iOS vulnerability dataset for offline development
// ---------------------------------------------------------------------------
function getMockIssues() {
  return {
    getIssues: {
      totalIssues: 147,
      totalFilteredIssues: 147,
      totalResolvedIssues: 23,
      offset: 0,
      issues: [
        {
          id: '1', issueId: 'ISS-001', mainTitle: 'Remote Code Execution in libxml2',
          secondTitle: 'CVE-2024-40896 affects libxml2 < 2.12.5 used via CocoaPods',
          severity: 'Critical', originalSeverity: 'Critical', owners: ['ios-team'],
          created: '2025-12-15T10:30:00Z',
          app: { id: 'app-1', name: 'MyBankingApp-iOS', type: 'iOS' },
          category: { name: 'Vulnerable Dependency' },
          policy: { name: 'Critical SCA Policy', detailedDescription: 'Block critical SCA vulnerabilities' },
          sourceType: 'SCA',
        },
        {
          id: '2', issueId: 'ISS-002', mainTitle: 'Prototype Pollution in lodash',
          secondTitle: 'lodash < 4.17.21 allows prototype pollution via merge/zipObjectDeep',
          severity: 'Critical', originalSeverity: 'Critical', owners: ['ios-team'],
          created: '2025-11-20T08:00:00Z',
          app: { id: 'app-1', name: 'MyBankingApp-iOS', type: 'iOS' },
          category: { name: 'Vulnerable Dependency' },
          policy: { name: 'Critical SCA Policy', detailedDescription: 'Block critical SCA vulnerabilities' },
          sourceType: 'SCA',
        },
        {
          id: '3', issueId: 'ISS-003', mainTitle: 'Insecure Data Storage — Keychain Missing Accessibility',
          secondTitle: 'Sensitive credentials stored without kSecAttrAccessibleWhenUnlockedThisDeviceOnly',
          severity: 'High', originalSeverity: 'Critical', owners: ['ios-security'],
          created: '2026-01-05T14:20:00Z',
          app: { id: 'app-2', name: 'HealthTracker-iOS', type: 'iOS' },
          category: { name: 'Mobile Security' },
          policy: { name: 'iOS Security Policy', detailedDescription: 'iOS-specific security checks' },
          sourceType: 'SAST',
        },
        {
          id: '4', issueId: 'ISS-004', mainTitle: 'Missing Certificate Pinning',
          secondTitle: 'App does not implement SSL/TLS certificate pinning for API connections',
          severity: 'High', originalSeverity: 'High', owners: ['ios-team'],
          created: '2026-01-10T09:15:00Z',
          app: { id: 'app-1', name: 'MyBankingApp-iOS', type: 'iOS' },
          category: { name: 'Mobile Security' },
          policy: { name: 'iOS Security Policy', detailedDescription: 'iOS-specific security checks' },
          sourceType: 'SAST',
        },
        {
          id: '5', issueId: 'ISS-005', mainTitle: 'SQL Injection in SQLite Query Builder',
          secondTitle: 'User input concatenated directly into SQLite query in DataManager.swift',
          severity: 'Critical', originalSeverity: 'Critical', owners: ['ios-team'],
          created: '2026-01-18T16:45:00Z',
          app: { id: 'app-2', name: 'HealthTracker-iOS', type: 'iOS' },
          category: { name: 'Code Vulnerability' },
          policy: { name: 'Critical SAST Policy', detailedDescription: 'Block critical code vulnerabilities' },
          sourceType: 'SAST',
        },
        {
          id: '6', issueId: 'ISS-006', mainTitle: 'Vulnerable OpenSSL in Alamofire',
          secondTitle: 'Alamofire 5.6.x bundles OpenSSL with known CVEs',
          severity: 'High', originalSeverity: 'Critical', owners: ['ios-team'],
          created: '2025-10-22T11:30:00Z',
          app: { id: 'app-1', name: 'MyBankingApp-iOS', type: 'iOS' },
          category: { name: 'Vulnerable Dependency' },
          policy: { name: 'Critical SCA Policy', detailedDescription: 'Block critical SCA vulnerabilities' },
          sourceType: 'SCA',
        },
        {
          id: '7', issueId: 'ISS-007', mainTitle: 'Hardcoded API Key in Source Code',
          secondTitle: 'Firebase API key found in GoogleService-Info.plist committed to repo',
          severity: 'High', originalSeverity: 'High', owners: ['ios-security'],
          created: '2026-02-01T13:00:00Z',
          app: { id: 'app-3', name: 'ShopEasy-iOS', type: 'iOS' },
          category: { name: 'Secret Detection' },
          policy: { name: 'Secrets Policy', detailedDescription: 'Detect hardcoded secrets and credentials' },
          sourceType: 'Secret Detection',
        },
        {
          id: '8', issueId: 'ISS-008', mainTitle: 'Denial of Service in libexpat',
          secondTitle: 'CVE-2024-50602 — libexpat before 2.6.4 allows DoS via XML parsing',
          severity: 'High', originalSeverity: 'High', owners: ['ios-team'],
          created: '2026-01-25T10:00:00Z',
          app: { id: 'app-2', name: 'HealthTracker-iOS', type: 'iOS' },
          category: { name: 'Vulnerable Dependency' },
          policy: { name: 'High SCA Policy', detailedDescription: 'Flag high severity SCA issues' },
          sourceType: 'SCA',
        },
        {
          id: '9', issueId: 'ISS-009', mainTitle: 'Insecure App Transport Security Configuration',
          secondTitle: 'NSAllowsArbitraryLoads set to YES in Info.plist',
          severity: 'High', originalSeverity: 'Medium', owners: ['ios-team'],
          created: '2026-02-05T15:30:00Z',
          app: { id: 'app-3', name: 'ShopEasy-iOS', type: 'iOS' },
          category: { name: 'Mobile Security' },
          policy: { name: 'iOS Security Policy', detailedDescription: 'iOS-specific security checks' },
          sourceType: 'SAST',
        },
        {
          id: '10', issueId: 'ISS-010', mainTitle: 'Outdated React Native with Known Vulnerabilities',
          secondTitle: 'react-native 0.71.x has multiple known CVEs in bundled Hermes engine',
          severity: 'Critical', originalSeverity: 'High', owners: ['mobile-platform'],
          created: '2026-02-10T09:00:00Z',
          app: { id: 'app-3', name: 'ShopEasy-iOS', type: 'iOS' },
          category: { name: 'Vulnerable Dependency' },
          policy: { name: 'Critical SCA Policy', detailedDescription: 'Block critical SCA vulnerabilities' },
          sourceType: 'SCA',
        },
      ],
    },
  };
}

function getMockIssueDetail(issueId) {
  const details = {
    'ISS-001': {
      id: '1', issueId: 'ISS-001', mainTitle: 'Remote Code Execution in libxml2',
      secondTitle: 'CVE-2024-40896 affects libxml2 < 2.12.5 used via CocoaPods',
      description: 'libxml2 before 2.12.5 has a use-after-free in xmlXIncludeAddNode that can be triggered by crafted XML documents, leading to remote code execution. This library is pulled in transitively through the Ono CocoaPods dependency used for HTML/XML parsing.',
      severity: 'Critical', originalSeverity: 'Critical', owners: ['ios-team'],
      created: '2025-12-15T10:30:00Z',
      app: { id: 'app-1', name: 'MyBankingApp-iOS', type: 'iOS' },
      category: { name: 'Vulnerable Dependency' },
      policy: { name: 'Critical SCA Policy', detailedDescription: 'Block critical SCA vulnerabilities' },
      sbom: { libraryName: 'libxml2', libraryVersion: '2.11.6', license: 'MIT', packageManager: 'CocoaPods' },
      scaVulnerabilities: [
        { cve: 'CVE-2024-40896', cveLink: 'https://nvd.nist.gov/vuln/detail/CVE-2024-40896', originalSeverity: 'Critical', minorVerWithFix: '2.12.5', majorVerWithFix: '2.12.5' },
        { cve: 'CVE-2024-34459', cveLink: 'https://nvd.nist.gov/vuln/detail/CVE-2024-34459', originalSeverity: 'High', minorVerWithFix: '2.12.7', majorVerWithFix: null },
      ],
      severityChangedReason: null,
      autoFix: { fixType: 'VersionBump', fixTitle: 'Upgrade libxml2 to 2.12.5+', fixDescription: 'Update the Ono CocoaPods dependency to a version that bundles libxml2 >= 2.12.5' },
    },
    'ISS-002': {
      id: '2', issueId: 'ISS-002', mainTitle: 'Prototype Pollution in lodash',
      secondTitle: 'lodash < 4.17.21 allows prototype pollution via merge/zipObjectDeep',
      description: 'lodash versions prior to 4.17.21 are vulnerable to Prototype Pollution via the set, setWith, and zipObjectDeep functions, potentially allowing attackers to modify object prototypes and inject malicious properties.',
      severity: 'Critical', originalSeverity: 'Critical', owners: ['ios-team'],
      created: '2025-11-20T08:00:00Z',
      app: { id: 'app-1', name: 'MyBankingApp-iOS', type: 'iOS' },
      category: { name: 'Vulnerable Dependency' },
      policy: { name: 'Critical SCA Policy', detailedDescription: 'Block critical SCA vulnerabilities' },
      sbom: { libraryName: 'lodash', libraryVersion: '4.17.19', license: 'MIT', packageManager: 'npm' },
      scaVulnerabilities: [
        { cve: 'CVE-2021-23337', cveLink: 'https://nvd.nist.gov/vuln/detail/CVE-2021-23337', originalSeverity: 'Critical', minorVerWithFix: '4.17.21', majorVerWithFix: '4.17.21' },
        { cve: 'CVE-2020-28500', cveLink: 'https://nvd.nist.gov/vuln/detail/CVE-2020-28500', originalSeverity: 'Medium', minorVerWithFix: '4.17.21', majorVerWithFix: null },
      ],
      severityChangedReason: null,
      autoFix: { fixType: 'VersionBump', fixTitle: 'Upgrade lodash to 4.17.21', fixDescription: 'Run npm update lodash or update package.json to pin lodash >= 4.17.21' },
    },
    'ISS-003': {
      id: '3', issueId: 'ISS-003', mainTitle: 'Insecure Data Storage — Keychain Missing Accessibility',
      secondTitle: 'Sensitive credentials stored without kSecAttrAccessibleWhenUnlockedThisDeviceOnly',
      description: 'The app stores sensitive authentication tokens in the iOS Keychain without specifying the kSecAttrAccessibleWhenUnlockedThisDeviceOnly attribute. This means data may be accessible when the device is locked and could be included in unencrypted backups.',
      severity: 'High', originalSeverity: 'Critical', owners: ['ios-security'],
      created: '2026-01-05T14:20:00Z',
      app: { id: 'app-2', name: 'HealthTracker-iOS', type: 'iOS' },
      category: { name: 'Mobile Security' },
      policy: { name: 'iOS Security Policy', detailedDescription: 'iOS-specific security checks' },
      sbom: null,
      scaVulnerabilities: [],
      severityChangedReason: { reason: 'Ox determined this issue is exploitable only with physical device access, reducing effective severity', shortName: 'Physical access required', changeCategory: 'Exploitability' },
      autoFix: null,
    },
    'ISS-004': {
      id: '4', issueId: 'ISS-004', mainTitle: 'Missing Certificate Pinning',
      secondTitle: 'App does not implement SSL/TLS certificate pinning for API connections',
      description: 'The banking application communicates with backend APIs over HTTPS but does not implement certificate pinning. An attacker with network access (e.g., rogue Wi-Fi) could perform a man-in-the-middle attack using a forged certificate trusted by the device.',
      severity: 'High', originalSeverity: 'High', owners: ['ios-team'],
      created: '2026-01-10T09:15:00Z',
      app: { id: 'app-1', name: 'MyBankingApp-iOS', type: 'iOS' },
      category: { name: 'Mobile Security' },
      policy: { name: 'iOS Security Policy', detailedDescription: 'iOS-specific security checks' },
      sbom: null,
      scaVulnerabilities: [],
      severityChangedReason: null,
      autoFix: null,
    },
    'ISS-005': {
      id: '5', issueId: 'ISS-005', mainTitle: 'SQL Injection in SQLite Query Builder',
      secondTitle: 'User input concatenated directly into SQLite query in DataManager.swift',
      description: 'In DataManager.swift line 142, user-supplied search text is concatenated directly into a SQLite query string without parameterized queries. This allows SQL injection that could read or modify the local SQLite database containing health records.',
      severity: 'Critical', originalSeverity: 'Critical', owners: ['ios-team'],
      created: '2026-01-18T16:45:00Z',
      app: { id: 'app-2', name: 'HealthTracker-iOS', type: 'iOS' },
      category: { name: 'Code Vulnerability' },
      policy: { name: 'Critical SAST Policy', detailedDescription: 'Block critical code vulnerabilities' },
      sbom: null,
      scaVulnerabilities: [],
      severityChangedReason: null,
      autoFix: { fixType: 'CodeChange', fixTitle: 'Use parameterized SQLite queries', fixDescription: 'Replace string concatenation with sqlite3_bind_text() parameterized query to prevent SQL injection. Change: let query = "SELECT * FROM records WHERE name = \'\\(searchText)\'" to use ? placeholder with bound parameter.' },
    },
    'ISS-006': {
      id: '6', issueId: 'ISS-006', mainTitle: 'Vulnerable OpenSSL in Alamofire',
      secondTitle: 'Alamofire 5.6.x bundles OpenSSL with known CVEs',
      description: 'Alamofire 5.6.4 depends on an OpenSSL version with multiple known vulnerabilities including CVE-2024-0727 (denial of service) and CVE-2023-5678 (excessive time in DH key generation). Upgrading to Alamofire 5.8+ resolves these.',
      severity: 'High', originalSeverity: 'Critical', owners: ['ios-team'],
      created: '2025-10-22T11:30:00Z',
      app: { id: 'app-1', name: 'MyBankingApp-iOS', type: 'iOS' },
      category: { name: 'Vulnerable Dependency' },
      policy: { name: 'Critical SCA Policy', detailedDescription: 'Block critical SCA vulnerabilities' },
      sbom: { libraryName: 'Alamofire', libraryVersion: '5.6.4', license: 'MIT', packageManager: 'Swift Package Manager' },
      scaVulnerabilities: [
        { cve: 'CVE-2024-0727', cveLink: 'https://nvd.nist.gov/vuln/detail/CVE-2024-0727', originalSeverity: 'High', minorVerWithFix: null, majorVerWithFix: '5.8.0' },
        { cve: 'CVE-2023-5678', cveLink: 'https://nvd.nist.gov/vuln/detail/CVE-2023-5678', originalSeverity: 'Medium', minorVerWithFix: null, majorVerWithFix: '5.8.0' },
      ],
      severityChangedReason: { reason: 'The OpenSSL vulnerabilities in this context are limited to denial of service; no remote code execution is possible through Alamofire usage pattern', shortName: 'Limited exploitability', changeCategory: 'Exploitability' },
      autoFix: { fixType: 'VersionBump', fixTitle: 'Upgrade Alamofire to 5.8+', fixDescription: 'Update Package.swift to require Alamofire >= 5.8.0 which bundles patched OpenSSL' },
    },
    'ISS-007': {
      id: '7', issueId: 'ISS-007', mainTitle: 'Hardcoded API Key in Source Code',
      secondTitle: 'Firebase API key found in GoogleService-Info.plist committed to repo',
      description: 'A Firebase API key is hardcoded in GoogleService-Info.plist which is committed to the repository. While Firebase API keys are generally not secret, this plist also contains the database URL and storage bucket which could be used to enumerate resources.',
      severity: 'High', originalSeverity: 'High', owners: ['ios-security'],
      created: '2026-02-01T13:00:00Z',
      app: { id: 'app-3', name: 'ShopEasy-iOS', type: 'iOS' },
      category: { name: 'Secret Detection' },
      policy: { name: 'Secrets Policy', detailedDescription: 'Detect hardcoded secrets and credentials' },
      sbom: null,
      scaVulnerabilities: [],
      severityChangedReason: null,
      autoFix: null,
    },
    'ISS-008': {
      id: '8', issueId: 'ISS-008', mainTitle: 'Denial of Service in libexpat',
      secondTitle: 'CVE-2024-50602 — libexpat before 2.6.4 allows DoS via XML parsing',
      description: 'libexpat before version 2.6.4 has a vulnerability where XML_ResumeParser can crash when called after XML_StopParser, leading to a denial of service. This affects iOS apps using any XML parsing that depends on libexpat.',
      severity: 'High', originalSeverity: 'High', owners: ['ios-team'],
      created: '2026-01-25T10:00:00Z',
      app: { id: 'app-2', name: 'HealthTracker-iOS', type: 'iOS' },
      category: { name: 'Vulnerable Dependency' },
      policy: { name: 'High SCA Policy', detailedDescription: 'Flag high severity SCA issues' },
      sbom: { libraryName: 'libexpat', libraryVersion: '2.5.0', license: 'MIT', packageManager: 'CocoaPods' },
      scaVulnerabilities: [
        { cve: 'CVE-2024-50602', cveLink: 'https://nvd.nist.gov/vuln/detail/CVE-2024-50602', originalSeverity: 'High', minorVerWithFix: '2.6.4', majorVerWithFix: '2.6.4' },
      ],
      severityChangedReason: null,
      autoFix: { fixType: 'VersionBump', fixTitle: 'Upgrade libexpat to 2.6.4+', fixDescription: 'Update the CocoaPods dependency to pull libexpat >= 2.6.4' },
    },
    'ISS-009': {
      id: '9', issueId: 'ISS-009', mainTitle: 'Insecure App Transport Security Configuration',
      secondTitle: 'NSAllowsArbitraryLoads set to YES in Info.plist',
      description: 'The app\'s Info.plist has NSAllowsArbitraryLoads set to YES under NSAppTransportSecurity, disabling App Transport Security for all connections. This allows unencrypted HTTP traffic which can be intercepted.',
      severity: 'High', originalSeverity: 'Medium', owners: ['ios-team'],
      created: '2026-02-05T15:30:00Z',
      app: { id: 'app-3', name: 'ShopEasy-iOS', type: 'iOS' },
      category: { name: 'Mobile Security' },
      policy: { name: 'iOS Security Policy', detailedDescription: 'iOS-specific security checks' },
      sbom: null,
      scaVulnerabilities: [],
      severityChangedReason: { reason: 'Ox elevated severity because the app handles payment data, making cleartext traffic a higher risk', shortName: 'Sensitive data context', changeCategory: 'Business Impact' },
      autoFix: { fixType: 'CodeChange', fixTitle: 'Remove NSAllowsArbitraryLoads from Info.plist', fixDescription: 'Set NSAllowsArbitraryLoads to NO and add exception domains only for hosts that require HTTP (e.g., legacy internal APIs)' },
    },
    'ISS-010': {
      id: '10', issueId: 'ISS-010', mainTitle: 'Outdated React Native with Known Vulnerabilities',
      secondTitle: 'react-native 0.71.x has multiple known CVEs in bundled Hermes engine',
      description: 'ShopEasy uses React Native 0.71.8 which includes the Hermes JavaScript engine with known vulnerabilities. The Hermes engine has buffer overflow and type confusion issues that could allow code execution through crafted JavaScript.',
      severity: 'Critical', originalSeverity: 'High', owners: ['mobile-platform'],
      created: '2026-02-10T09:00:00Z',
      app: { id: 'app-3', name: 'ShopEasy-iOS', type: 'iOS' },
      category: { name: 'Vulnerable Dependency' },
      policy: { name: 'Critical SCA Policy', detailedDescription: 'Block critical SCA vulnerabilities' },
      sbom: { libraryName: 'react-native', libraryVersion: '0.71.8', license: 'MIT', packageManager: 'npm' },
      scaVulnerabilities: [
        { cve: 'CVE-2024-21514', cveLink: 'https://nvd.nist.gov/vuln/detail/CVE-2024-21514', originalSeverity: 'High', minorVerWithFix: null, majorVerWithFix: '0.73.0' },
        { cve: 'CVE-2024-28244', cveLink: 'https://nvd.nist.gov/vuln/detail/CVE-2024-28244', originalSeverity: 'High', minorVerWithFix: null, majorVerWithFix: '0.73.0' },
        { cve: 'CVE-2023-49relative', cveLink: null, originalSeverity: 'Medium', minorVerWithFix: null, majorVerWithFix: '0.72.0' },
      ],
      severityChangedReason: { reason: 'Ox elevated from High to Critical because the app processes payment card data and the Hermes RCE could lead to credential theft', shortName: 'Payment data risk', changeCategory: 'Business Impact' },
      autoFix: { fixType: 'VersionBump', fixTitle: 'Upgrade React Native to 0.73+', fixDescription: 'Update react-native to >= 0.73.0 in package.json. This is a major version upgrade that may require code changes for breaking API changes.' },
    },
  };
  return details[issueId] || null;
}

function getMockPrioritization() {
  return {
    original: { critical: 5, high: 12, medium: 45, low: 67, info: 18 },
    oxPrioritized: { critical: 4, high: 10, medium: 38, low: 72, info: 23 },
    aggregated: { critical: 4, high: 10, medium: 38, low: 72, info: 23 },
  };
}

// ---------------------------------------------------------------------------
// Core logic (works with both real API and mock data)
// ---------------------------------------------------------------------------

/**
 * Fetch issue detail with retry
 */
async function fetchIssueDetail(issueId) {
  if (USE_MOCK) {
    return getMockIssueDetail(issueId);
  }
  try {
    const data = await queryFn(
      (await import('../queries/issues.js')).GET_SINGLE_ISSUE,
      { getSingleIssueInput: { issueId } }
    );
    return data.getSingleIssueInfo;
  } catch (e) {
    // One retry after 1s
    try {
      await new Promise(r => setTimeout(r, 1000));
      const data = await queryFn(
        (await import('../queries/issues.js')).GET_SINGLE_ISSUE,
        { getSingleIssueInput: { issueId } }
      );
      return data.getSingleIssueInfo;
    } catch (e2) {
      return { error: e2.message, issueId };
    }
  }
}

/**
 * Fetch details for multiple issues with bounded concurrency
 */
async function fetchAllDetails(issues, concurrency) {
  const results = [];
  for (let i = 0; i < issues.length; i += concurrency) {
    const batch = issues.slice(i, i + concurrency);
    const batchResults = await Promise.all(
      batch.map(issue => fetchIssueDetail(issue.issueId))
    );
    results.push(...batchResults);

    const done = Math.min(i + concurrency, issues.length);
    process.stdout.write(`\r  Enriched ${done}/${issues.length} issues...`);
  }
  console.log('');
  return results;
}

/**
 * Build enrichment summary for a single issue detail
 */
function summarizeDetail(detail) {
  if (!detail) return { error: 'No detail returned' };
  if (detail.error) return { error: detail.error, issueId: detail.issueId };

  const summary = {
    issueId: detail.issueId,
    mainTitle: detail.mainTitle,
    secondTitle: detail.secondTitle,
    description: detail.description,
    severity: detail.severity,
    originalSeverity: detail.originalSeverity,
    severityChanged: detail.severity !== detail.originalSeverity,
    created: detail.created,
    app: detail.app,
    category: detail.category?.name,
    owners: detail.owners,
  };

  // Severity change analysis
  if (detail.severityChangedReason) {
    summary.severityChange = {
      from: detail.originalSeverity,
      to: detail.severity,
      reason: detail.severityChangedReason.reason,
      shortName: detail.severityChangedReason.shortName,
      category: detail.severityChangedReason.changeCategory,
    };
  }

  // CVE details
  if (detail.scaVulnerabilities?.length) {
    summary.cves = detail.scaVulnerabilities.map(v => ({
      cve: v.cve,
      link: v.cveLink,
      severity: v.originalSeverity,
      minorFix: v.minorVerWithFix || null,
      majorFix: v.majorVerWithFix || null,
      fixAvailable: !!(v.minorVerWithFix || v.majorVerWithFix),
    }));
  }

  // SBOM context
  if (detail.sbom) {
    summary.library = {
      name: detail.sbom.libraryName,
      version: detail.sbom.libraryVersion,
      license: detail.sbom.license,
      packageManager: detail.sbom.packageManager,
    };
  }

  // Auto-fix info
  if (detail.autoFix) {
    summary.autoFix = {
      type: detail.autoFix.fixType,
      title: detail.autoFix.fixTitle,
      description: detail.autoFix.fixDescription,
    };
  }

  // Policy context
  if (detail.policy) {
    summary.policy = {
      name: detail.policy.name,
      description: detail.policy.detailedDescription,
    };
  }

  return summary;
}

/**
 * Generate the markdown deep-dive report
 */
function generateMarkdown(enriched, prioritization, meta) {
  const lines = [];

  lines.push('# Issue Deep-Dive Report');
  lines.push(`Generated: ${meta.timestamp}`);
  if (meta.mockData) lines.push('**Note: Generated with mock data (no API key configured)**');
  lines.push(`Filter: severities=${meta.severities.join(',')}, app=${meta.appFilter || 'all'}`);
  lines.push(`Issues analyzed: ${enriched.length}`);
  lines.push('');

  // Prioritization comparison
  if (prioritization) {
    lines.push('## Severity Prioritization Overview');
    lines.push('');
    lines.push('How Ox Security re-prioritized issues vs original scanner severity:');
    lines.push('');
    lines.push('| Severity | Original | Ox Prioritized | Delta |');
    lines.push('|----------|----------|----------------|-------|');
    const orig = prioritization.original || {};
    const oxp = prioritization.oxPrioritized || {};
    for (const sev of ['critical', 'high', 'medium', 'low', 'info']) {
      const o = orig[sev] || 0;
      const p = oxp[sev] || 0;
      const delta = p - o;
      const sign = delta > 0 ? '+' : '';
      lines.push(`| ${sev.charAt(0).toUpperCase() + sev.slice(1)} | ${o} | ${p} | ${sign}${delta} |`);
    }
    lines.push('');
  }

  // Aggregate stats
  const stats = {
    total: enriched.length,
    withCVEs: enriched.filter(e => e.cves?.length).length,
    withAutoFix: enriched.filter(e => e.autoFix).length,
    severityChanged: enriched.filter(e => e.severityChanged).length,
    withLibrary: enriched.filter(e => e.library).length,
    errors: enriched.filter(e => e.error).length,
  };

  lines.push('## Enrichment Summary');
  lines.push('');
  lines.push('| Metric | Count |');
  lines.push('|--------|-------|');
  lines.push(`| Total issues analyzed | ${stats.total} |`);
  lines.push(`| Issues with CVE data | ${stats.withCVEs} |`);
  lines.push(`| Issues with auto-fix | ${stats.withAutoFix} |`);
  lines.push(`| Severity re-prioritized | ${stats.severityChanged} |`);
  lines.push(`| Issues with library context | ${stats.withLibrary} |`);
  lines.push(`| Failed to enrich | ${stats.errors} |`);
  lines.push('');

  // Auto-fix opportunities (high value for remediation)
  const fixable = enriched.filter(e => e.autoFix);
  if (fixable.length) {
    lines.push('## Auto-Fix Opportunities');
    lines.push('');
    lines.push('These issues have automated fixes available — highest ROI for remediation:');
    lines.push('');
    for (const issue of fixable) {
      lines.push(`### ${SEV_ICON[issue.severity] || '?'} [${issue.severity}] ${issue.mainTitle}`);
      if (issue.secondTitle) lines.push(`> ${issue.secondTitle}`);
      lines.push(`- **Fix type**: ${issue.autoFix.type}`);
      lines.push(`- **Fix**: ${issue.autoFix.title}`);
      if (issue.autoFix.description) lines.push(`- **Details**: ${issue.autoFix.description}`);
      if (issue.library) lines.push(`- **Library**: ${issue.library.name}@${issue.library.version} (${issue.library.packageManager})`);
      lines.push('');
    }
  }

  // Severity changes (where Ox disagreed with scanner)
  const changed = enriched.filter(e => e.severityChange);
  if (changed.length) {
    lines.push('## Severity Re-Prioritizations');
    lines.push('');
    lines.push('Issues where Ox adjusted severity from the original scanner assessment:');
    lines.push('');
    for (const issue of changed) {
      const sc = issue.severityChange;
      lines.push(`- **${issue.mainTitle}**: ${sc.from} → ${sc.to}`);
      lines.push(`  - Reason: ${sc.reason || sc.shortName || 'N/A'} (${sc.category || 'N/A'})`);
    }
    lines.push('');
  }

  // Detailed per-issue deep-dive
  lines.push('## Detailed Issue Analysis');
  lines.push('');

  // Group by severity
  const bySeverity = {};
  for (const issue of enriched) {
    if (issue.error) continue;
    const sev = issue.severity || 'Unknown';
    if (!bySeverity[sev]) bySeverity[sev] = [];
    bySeverity[sev].push(issue);
  }

  for (const sev of ['Critical', 'High', 'Medium', 'Low', 'Info']) {
    const group = bySeverity[sev];
    if (!group?.length) continue;

    lines.push(`### ${SEV_ICON[sev] || ''} ${sev} Issues (${group.length})`);
    lines.push('');

    for (const issue of group) {
      lines.push(`#### ${issue.mainTitle}`);
      if (issue.secondTitle) lines.push(`> ${issue.secondTitle}`);
      lines.push('');

      lines.push(`- **Issue ID**: ${issue.issueId}`);
      lines.push(`- **App**: ${issue.app?.name || 'N/A'} (${issue.app?.type || 'N/A'})`);
      lines.push(`- **Category**: ${issue.category || 'N/A'}`);
      lines.push(`- **Created**: ${issue.created || 'N/A'}`);
      lines.push(`- **Owners**: ${issue.owners?.join(', ') || 'unassigned'}`);

      if (issue.description) {
        lines.push(`- **Description**: ${issue.description.slice(0, 500)}${issue.description.length > 500 ? '...' : ''}`);
      }

      if (issue.severityChange) {
        lines.push(`- **Severity changed**: ${issue.severityChange.from} → ${issue.severityChange.to}`);
        lines.push(`  - Reason: ${issue.severityChange.reason || issue.severityChange.shortName || 'N/A'}`);
      }

      if (issue.library) {
        lines.push(`- **Library**: ${issue.library.name}@${issue.library.version}`);
        lines.push(`  - Package manager: ${issue.library.packageManager || 'N/A'}`);
        lines.push(`  - License: ${issue.library.license || 'N/A'}`);
      }

      if (issue.cves?.length) {
        lines.push(`- **CVEs** (${issue.cves.length}):`);
        for (const cve of issue.cves) {
          const fix = cve.minorFix
            ? `minor fix: ${cve.minorFix}`
            : cve.majorFix
              ? `major fix: ${cve.majorFix}`
              : 'no fix available';
          const link = cve.link ? ` [link](${cve.link})` : '';
          lines.push(`  - **${cve.cve}** (${cve.severity}) — ${fix}${link}`);
        }
      }

      if (issue.autoFix) {
        lines.push(`- **Auto-fix available**: ${issue.autoFix.title} (${issue.autoFix.type})`);
        if (issue.autoFix.description) {
          lines.push(`  - ${issue.autoFix.description}`);
        }
      }

      if (issue.policy?.name) {
        lines.push(`- **Policy**: ${issue.policy.name}`);
      }

      lines.push('');
    }
  }

  // Errors section
  const errors = enriched.filter(e => e.error);
  if (errors.length) {
    lines.push('## Enrichment Errors');
    lines.push('');
    for (const e of errors) {
      lines.push(`- Issue ${e.issueId}: ${e.error}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  const appFilter = process.env.OX_APP_NAME || process.argv[3] || '';
  const sevArg = process.env.OX_SEVERITY || process.argv[2] || 'Critical,High';
  const limit = parseInt(process.env.OX_LIMIT || '200', 10);
  const concurrency = parseInt(process.env.OX_CONCURRENCY || '5', 10);
  const targetSeverities = sevArg.split(',').map(s => s.trim());

  console.log('Ox Security — Issue Deep-Dive');
  console.log('='.repeat(50));
  if (USE_MOCK) {
    console.log('⚠  No API key found — running with mock data');
  }
  console.log(`Severities: ${targetSeverities.join(', ')}`);
  console.log(`App filter: ${appFilter || 'all'}`);
  console.log(`Limit: ${limit}, Concurrency: ${concurrency}`);
  console.log('');

  // Step 1: Fetch issue list
  console.log('Step 1: Fetching issue list...');
  let issuesData;
  if (USE_MOCK) {
    issuesData = getMockIssues();
  } else {
    const { GET_ISSUES } = await import('../queries/issues.js');
    issuesData = await queryFn(GET_ISSUES, {
      isDemo: false,
      getIssuesInput: {
        offset: 0,
        limit,
        sort: { fields: ['Severity'], order: ['DESC'] },
      },
    });
  }

  let issues = issuesData.getIssues.issues;
  console.log(`  Total issues from API: ${issuesData.getIssues.totalFilteredIssues}`);

  // Filter by severity
  issues = issues.filter(i => targetSeverities.includes(i.severity));
  console.log(`  After severity filter (${targetSeverities.join(',')}): ${issues.length}`);

  // Filter by app name
  if (appFilter) {
    issues = issues.filter(i => i.app?.name?.toLowerCase().includes(appFilter.toLowerCase()));
    console.log(`  After app filter ("${appFilter}"): ${issues.length}`);
  }

  if (issues.length === 0) {
    console.log('\nNo issues match the filter criteria. Exiting.');
    return;
  }

  // Step 2: Fetch prioritization data
  console.log('\nStep 2: Fetching prioritization data...');
  let prioritization = null;
  if (USE_MOCK) {
    prioritization = getMockPrioritization();
    console.log('  Prioritization data loaded (mock).');
  } else {
    try {
      const { GET_ISSUE_PRIORITIZATION } = await import('../queries/issues.js');
      const prioData = await queryFn(GET_ISSUE_PRIORITIZATION, {
        getIssuesInput: { offset: 0, limit: 1 },
      });
      prioritization = prioData.getIssuePrioritization;
      console.log('  Prioritization data loaded.');
    } catch (e) {
      console.log(`  Could not fetch prioritization: ${e.message}`);
    }
  }

  // Step 3: Deep-dive — fetch full detail for each issue
  console.log(`\nStep 3: Enriching ${issues.length} issues with full detail...`);
  const details = await fetchAllDetails(issues, concurrency);

  // Step 4: Build enriched summaries
  console.log('Step 4: Building enriched summaries...');
  const enriched = details.map(d => summarizeDetail(d));

  // Step 5: Generate outputs
  const timestamp = new Date().toISOString();
  const outDir = `experiments/deep-dive-${timestamp.slice(0, 10)}`;
  mkdirSync(outDir, { recursive: true });

  // JSON output
  const jsonOut = {
    meta: {
      timestamp,
      mockData: USE_MOCK,
      severities: targetSeverities,
      appFilter: appFilter || null,
      totalIssuesFetched: issuesData.getIssues.totalFilteredIssues,
      issuesEnriched: enriched.length,
    },
    prioritization,
    issues: enriched,
  };
  const jsonPath = `${outDir}/enriched-issues.json`;
  writeFileSync(jsonPath, JSON.stringify(jsonOut, null, 2));

  // Markdown output
  const mdReport = generateMarkdown(enriched, prioritization, {
    timestamp,
    severities: targetSeverities,
    appFilter,
    mockData: USE_MOCK,
  });
  const mdPath = `${outDir}/deep-dive-report.md`;
  writeFileSync(mdPath, mdReport);

  // Print summary to stdout
  console.log('\n' + '='.repeat(50));
  console.log('Deep-Dive Complete');
  console.log('='.repeat(50));

  const stats = {
    total: enriched.length,
    withCVEs: enriched.filter(e => e.cves?.length).length,
    withAutoFix: enriched.filter(e => e.autoFix).length,
    severityChanged: enriched.filter(e => e.severityChanged).length,
    errors: enriched.filter(e => e.error).length,
  };

  console.log(`  Issues analyzed:       ${stats.total}`);
  console.log(`  With CVE data:         ${stats.withCVEs}`);
  console.log(`  With auto-fix:         ${stats.withAutoFix}`);
  console.log(`  Severity re-ranked:    ${stats.severityChanged}`);
  console.log(`  Enrichment errors:     ${stats.errors}`);
  console.log('');
  console.log(`  JSON: ${jsonPath}`);
  console.log(`  Report: ${mdPath}`);

  // Print top auto-fix opportunities
  const fixable = enriched.filter(e => e.autoFix);
  if (fixable.length) {
    console.log(`\nTop Auto-Fix Opportunities (${fixable.length}):`);
    for (const issue of fixable.slice(0, 10)) {
      console.log(`  ${SEV_ICON[issue.severity] || '?'} ${issue.mainTitle}`);
      console.log(`    → ${issue.autoFix.title} (${issue.autoFix.type})`);
    }
  }

  // Print CVE highlights
  const withCVEs = enriched.filter(e => e.cves?.length);
  if (withCVEs.length) {
    const allCVEs = withCVEs.flatMap(e => e.cves);
    const uniqueCVEs = [...new Set(allCVEs.map(c => c.cve))];
    console.log(`\nUnique CVEs found: ${uniqueCVEs.length}`);
    for (const cve of uniqueCVEs.slice(0, 15)) {
      const detail = allCVEs.find(c => c.cve === cve);
      console.log(`  ${cve} (${detail.severity}) — ${detail.fixAvailable ? 'fix available' : 'no fix'}`);
    }
  }
}

main().catch(e => { console.error(`\nFatal: ${e.message}`); process.exit(1); });
