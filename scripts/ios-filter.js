#!/usr/bin/env node
/**
 * E12: iOS-Specific Filter
 *
 * Identifies iOS-specific vulnerabilities by matching issues and SBOM data
 * against iOS platform patterns:
 *   - CocoaPods dependencies
 *   - Swift Package Manager (SPM) dependencies
 *   - Xcode / iOS SDK issues
 *   - App Transport Security (ATS) misconfigurations
 *   - Keychain and data protection issues
 *   - Certificate pinning gaps
 *   - iOS-specific third-party SDK risks (analytics, ads, payments)
 *   - React Native / cross-platform iOS concerns
 *
 * Combines issue data and SBOM data to produce a filtered, categorized
 * report of iOS-relevant security findings.
 *
 * Falls back to realistic mock data when OX_API_KEY is not configured.
 *
 * Usage:
 *   node scripts/ios-filter.js [appFilter]
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
// iOS detection patterns
// ---------------------------------------------------------------------------

// Known iOS package managers
const IOS_PACKAGE_MANAGERS = ['cocoapods', 'swift package manager', 'spm', 'carthage'];

// Libraries that are inherently iOS/Apple-platform
const IOS_LIBRARY_PATTERNS = [
  // CocoaPods / SPM / Carthage native libs
  /^alamofire$/i, /^moya$/i, /^kingfisher$/i, /^snapkit$/i, /^rxswift$/i,
  /^swiftlint$/i, /^realm$/i, /^realmcore$/i, /^charts$/i,
  /^keychainaccess$/i, /^locksmith$/i, /^samauthentication$/i,
  /^sqlite\.swift$/i, /^grdb\.swift$/i,
  /^ono$/i, /^fuzi$/i, /^swiftsoup$/i,
  /^cryptoswift$/i, /^swcrypt$/i,
  /^sdwebimage$/i, /^nuke$/i,
  /^lottie-ios$/i, /^hero$/i,
  /^swiftybeaver$/i, /^cocoalumberjack$/i,
  /^afnetworking$/i, /^sdkplayground$/i,

  // Apple SDK / system libs
  /^healthkit$/i, /^homekit$/i, /^mapkit$/i, /^storekit$/i,
  /^cfnetwork$/i, /^coredata$/i, /^corelocation$/i,
  /^uikit$/i, /^swiftui$/i, /^foundation$/i,

  // React Native iOS bridge
  /^react-native/i, /^hermes-engine$/i, /^jsc-android$/i,
  /^react-native-firebase$/i, /^stripe-react-native$/i,

  // Firebase iOS
  /^firebase/i, /^googleutilities$/i, /^nanopb$/i,
  /^google.*info\.plist/i,

  // C/C++ libs commonly bundled in iOS via CocoaPods
  /^libxml2$/i, /^libexpat$/i, /^openssl$/i, /^boringssl/i,
  /^libuv$/i, /^sqlite3$/i, /^zlib$/i, /^curl$/i,
];

// Issue title/description patterns that indicate iOS-specific concerns
const IOS_ISSUE_PATTERNS = [
  { pattern: /cocoapods?/i,              category: 'CocoaPods',              weight: 10 },
  { pattern: /swift\s*package/i,         category: 'Swift Package Manager',  weight: 10 },
  { pattern: /carthage/i,               category: 'Carthage',               weight: 10 },
  { pattern: /xcode/i,                  category: 'Xcode',                  weight: 10 },
  { pattern: /ios\s*sdk/i,              category: 'iOS SDK',                weight: 10 },
  { pattern: /app\s*transport\s*security|NSAppTransportSecurity|NSAllowsArbitraryLoads/i,
                                          category: 'App Transport Security', weight: 9 },
  { pattern: /keychain|kSecAttr|SecItem/i, category: 'Keychain Security',    weight: 9 },
  { pattern: /certificate\s*pinning|ssl\s*pinning|TrustKit/i,
                                          category: 'Certificate Pinning',   weight: 9 },
  { pattern: /info\.plist/i,            category: 'Plist Configuration',     weight: 8 },
  { pattern: /entitlement/i,            category: 'Entitlements',            weight: 8 },
  { pattern: /code\s*sign/i,            category: 'Code Signing',           weight: 8 },
  { pattern: /\.swift\b/i,              category: 'Swift Code',             weight: 7 },
  { pattern: /\.m\b|objective.c/i,      category: 'Objective-C Code',       weight: 7 },
  { pattern: /UIWebView|WKWebView/i,    category: 'WebView Security',       weight: 8 },
  { pattern: /react.native/i,           category: 'React Native (iOS)',      weight: 6 },
  { pattern: /hermes\s*engine/i,        category: 'React Native (iOS)',      weight: 6 },
  { pattern: /firebase/i,              category: 'Firebase SDK',            weight: 5 },
  { pattern: /GoogleService/i,         category: 'Firebase SDK',            weight: 5 },
  { pattern: /healthkit|health\s*data/i, category: 'HealthKit',              weight: 7 },
  { pattern: /biometric|face\s*id|touch\s*id/i, category: 'Biometrics',     weight: 8 },
  { pattern: /\.ipa\b/i,               category: 'iOS Binary',              weight: 8 },
  { pattern: /provisioning\s*profile/i, category: 'Provisioning',            weight: 7 },
  { pattern: /alamofire/i,             category: 'iOS Networking',           weight: 6 },
  { pattern: /realm/i,                 category: 'iOS Storage',             weight: 5 },
];

// SBOM source patterns indicating iOS origin
const IOS_SOURCE_PATTERNS = [
  /cocoapods/i, /swift/i, /xcode/i, /ios/i, /apple/i,
  /carthage/i, /\.xcodeproj/i, /\.xcworkspace/i,
  /podfile/i, /package\.swift/i,
];

// Category groupings for the report
const CATEGORY_GROUPS = {
  'Dependency Management': ['CocoaPods', 'Swift Package Manager', 'Carthage'],
  'Platform Security':     ['App Transport Security', 'Keychain Security', 'Certificate Pinning', 'Biometrics', 'Code Signing', 'Entitlements'],
  'Configuration':         ['Plist Configuration', 'Provisioning', 'Xcode', 'iOS SDK'],
  'Code Analysis':         ['Swift Code', 'Objective-C Code', 'WebView Security', 'iOS Binary'],
  'Third-Party SDKs':      ['React Native (iOS)', 'Firebase SDK', 'HealthKit', 'iOS Networking', 'iOS Storage'],
};

// ---------------------------------------------------------------------------
// Mock data
// ---------------------------------------------------------------------------
function getMockIssues() {
  return [
    {
      issueId: 'ISS-001', mainTitle: 'Remote Code Execution in libxml2',
      secondTitle: 'CVE-2024-40896 affects libxml2 < 2.12.5 used via CocoaPods',
      description: 'libxml2 before 2.12.5 has a use-after-free in xmlXIncludeAddNode. This library is pulled in transitively through the Ono CocoaPods dependency.',
      severity: 'Critical', originalSeverity: 'Critical', sourceType: 'SCA',
      app: { name: 'MyBankingApp-iOS' }, category: { name: 'Vulnerable Dependency' },
      sbom: { libraryName: 'libxml2', libraryVersion: '2.11.6', packageManager: 'CocoaPods' },
    },
    {
      issueId: 'ISS-002', mainTitle: 'Prototype Pollution in lodash',
      secondTitle: 'lodash < 4.17.21 allows prototype pollution via merge/zipObjectDeep',
      description: 'lodash versions prior to 4.17.21 are vulnerable to Prototype Pollution.',
      severity: 'Critical', originalSeverity: 'Critical', sourceType: 'SCA',
      app: { name: 'MyBankingApp-iOS' }, category: { name: 'Vulnerable Dependency' },
      sbom: { libraryName: 'lodash', libraryVersion: '4.17.19', packageManager: 'npm' },
    },
    {
      issueId: 'ISS-003', mainTitle: 'Insecure Data Storage — Keychain Missing Accessibility',
      secondTitle: 'Sensitive credentials stored without kSecAttrAccessibleWhenUnlockedThisDeviceOnly',
      description: 'The app stores sensitive authentication tokens in the iOS Keychain without specifying the kSecAttrAccessibleWhenUnlockedThisDeviceOnly attribute.',
      severity: 'High', originalSeverity: 'Critical', sourceType: 'SAST',
      app: { name: 'HealthTracker-iOS' }, category: { name: 'Mobile Security' },
      sbom: null,
    },
    {
      issueId: 'ISS-004', mainTitle: 'Missing Certificate Pinning',
      secondTitle: 'App does not implement SSL/TLS certificate pinning for API connections',
      description: 'The banking application communicates with backend APIs over HTTPS but does not implement certificate pinning.',
      severity: 'High', originalSeverity: 'High', sourceType: 'SAST',
      app: { name: 'MyBankingApp-iOS' }, category: { name: 'Mobile Security' },
      sbom: null,
    },
    {
      issueId: 'ISS-005', mainTitle: 'SQL Injection in SQLite Query Builder',
      secondTitle: 'User input concatenated directly into SQLite query in DataManager.swift',
      description: 'In DataManager.swift line 142, user-supplied search text is concatenated directly into a SQLite query string.',
      severity: 'Critical', originalSeverity: 'Critical', sourceType: 'SAST',
      app: { name: 'HealthTracker-iOS' }, category: { name: 'Code Vulnerability' },
      sbom: null,
    },
    {
      issueId: 'ISS-006', mainTitle: 'Vulnerable OpenSSL in Alamofire',
      secondTitle: 'Alamofire 5.6.x bundles OpenSSL with known CVEs',
      description: 'Alamofire 5.6.4 depends on an OpenSSL version with multiple known vulnerabilities. Upgrading to Alamofire 5.8+ resolves these.',
      severity: 'High', originalSeverity: 'Critical', sourceType: 'SCA',
      app: { name: 'MyBankingApp-iOS' }, category: { name: 'Vulnerable Dependency' },
      sbom: { libraryName: 'Alamofire', libraryVersion: '5.6.4', packageManager: 'Swift Package Manager' },
    },
    {
      issueId: 'ISS-007', mainTitle: 'Hardcoded API Key in Source Code',
      secondTitle: 'Firebase API key found in GoogleService-Info.plist committed to repo',
      description: 'A Firebase API key is hardcoded in GoogleService-Info.plist which is committed to the repository.',
      severity: 'High', originalSeverity: 'High', sourceType: 'Secret Detection',
      app: { name: 'ShopEasy-iOS' }, category: { name: 'Secret Detection' },
      sbom: null,
    },
    {
      issueId: 'ISS-008', mainTitle: 'Denial of Service in libexpat',
      secondTitle: 'CVE-2024-50602 — libexpat before 2.6.4 allows DoS via XML parsing',
      description: 'libexpat before version 2.6.4 has a vulnerability where XML_ResumeParser can crash. Pulled via CocoaPods.',
      severity: 'High', originalSeverity: 'High', sourceType: 'SCA',
      app: { name: 'HealthTracker-iOS' }, category: { name: 'Vulnerable Dependency' },
      sbom: { libraryName: 'libexpat', libraryVersion: '2.5.0', packageManager: 'CocoaPods' },
    },
    {
      issueId: 'ISS-009', mainTitle: 'Insecure App Transport Security Configuration',
      secondTitle: 'NSAllowsArbitraryLoads set to YES in Info.plist',
      description: 'The app\'s Info.plist has NSAllowsArbitraryLoads set to YES under NSAppTransportSecurity, disabling ATS.',
      severity: 'High', originalSeverity: 'Medium', sourceType: 'SAST',
      app: { name: 'ShopEasy-iOS' }, category: { name: 'Mobile Security' },
      sbom: null,
    },
    {
      issueId: 'ISS-010', mainTitle: 'Outdated React Native with Known Vulnerabilities',
      secondTitle: 'react-native 0.71.x has multiple known CVEs in bundled Hermes engine',
      description: 'ShopEasy uses React Native 0.71.8 which includes the Hermes JavaScript engine with known vulnerabilities.',
      severity: 'Critical', originalSeverity: 'High', sourceType: 'SCA',
      app: { name: 'ShopEasy-iOS' }, category: { name: 'Vulnerable Dependency' },
      sbom: { libraryName: 'react-native', libraryVersion: '0.71.8', packageManager: 'npm' },
    },
    // A few non-iOS issues to show filtering works
    {
      issueId: 'ISS-011', mainTitle: 'Cross-Site Scripting in Admin Dashboard',
      secondTitle: 'Reflected XSS in /admin/search endpoint',
      description: 'The admin web dashboard has a reflected XSS vulnerability in the search parameter.',
      severity: 'High', originalSeverity: 'High', sourceType: 'DAST',
      app: { name: 'AdminPortal-Web' }, category: { name: 'Web Vulnerability' },
      sbom: null,
    },
    {
      issueId: 'ISS-012', mainTitle: 'Outdated Spring Boot in Backend',
      secondTitle: 'Spring Boot 2.7.x has known CVEs',
      description: 'The backend API server uses Spring Boot 2.7.14 which has known security issues.',
      severity: 'High', originalSeverity: 'High', sourceType: 'SCA',
      app: { name: 'PaymentAPI-Backend' }, category: { name: 'Vulnerable Dependency' },
      sbom: { libraryName: 'spring-boot', libraryVersion: '2.7.14', packageManager: 'maven' },
    },
    {
      issueId: 'ISS-013', mainTitle: 'UIWebView Deprecated Usage',
      secondTitle: 'App still uses deprecated UIWebView instead of WKWebView',
      description: 'The app uses UIWebView which Apple has deprecated. UIWebView has known security issues and apps using it may be rejected from the App Store.',
      severity: 'Medium', originalSeverity: 'Medium', sourceType: 'SAST',
      app: { name: 'HealthTracker-iOS' }, category: { name: 'Mobile Security' },
      sbom: null,
    },
    {
      issueId: 'ISS-014', mainTitle: 'Biometric Authentication Bypass',
      secondTitle: 'Touch ID / Face ID can be bypassed by presenting fallback passcode dialog',
      description: 'The biometric authentication implementation falls back to device passcode without re-authentication delay, allowing bypass.',
      severity: 'Medium', originalSeverity: 'Medium', sourceType: 'SAST',
      app: { name: 'MyBankingApp-iOS' }, category: { name: 'Mobile Security' },
      sbom: null,
    },
  ];
}

function getMockSBOM() {
  return [
    // MyBankingApp-iOS
    { libraryName: 'Alamofire', libraryVersion: '5.6.4', appName: 'MyBankingApp-iOS', dependencyLevel: 'Direct', source: 'Swift Package Manager', vulnerabilityCounts: { critical: 0, high: 2, medium: 1, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'Ono', libraryVersion: '2.5.0', appName: 'MyBankingApp-iOS', dependencyLevel: 'Direct', source: 'CocoaPods', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: true, isDeprecated: false },
    { libraryName: 'KeychainAccess', libraryVersion: '4.2.2', appName: 'MyBankingApp-iOS', dependencyLevel: 'Direct', source: 'Swift Package Manager', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'CryptoSwift', libraryVersion: '1.7.2', appName: 'MyBankingApp-iOS', dependencyLevel: 'Direct', source: 'Swift Package Manager', vulnerabilityCounts: { critical: 0, high: 0, medium: 1, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'lodash', libraryVersion: '4.17.19', appName: 'MyBankingApp-iOS', dependencyLevel: 'Direct', source: 'npm', vulnerabilityCounts: { critical: 1, high: 0, medium: 1, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'SwiftLint', libraryVersion: '0.54.0', appName: 'MyBankingApp-iOS', dependencyLevel: 'Direct', source: 'Swift Package Manager', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'libxml2', libraryVersion: '2.11.6', appName: 'MyBankingApp-iOS', dependencyLevel: 'Transitive', source: 'CocoaPods', vulnerabilityCounts: { critical: 1, high: 1, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'OpenSSL', libraryVersion: '1.1.1w', appName: 'MyBankingApp-iOS', dependencyLevel: 'Transitive', source: 'CocoaPods', vulnerabilityCounts: { critical: 0, high: 1, medium: 1, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'BoringSSL-GRPC', libraryVersion: '0.0.27', appName: 'MyBankingApp-iOS', dependencyLevel: 'Transitive', source: 'CocoaPods', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 1 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'CFNetwork', libraryVersion: '0.0.0', appName: 'MyBankingApp-iOS', dependencyLevel: 'Transitive', source: 'iOS SDK', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false },

    // HealthTracker-iOS
    { libraryName: 'SQLite.swift', libraryVersion: '0.14.1', appName: 'HealthTracker-iOS', dependencyLevel: 'Direct', source: 'Swift Package Manager', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'Charts', libraryVersion: '5.0.0', appName: 'HealthTracker-iOS', dependencyLevel: 'Direct', source: 'Swift Package Manager', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'Realm', libraryVersion: '10.44.0', appName: 'HealthTracker-iOS', dependencyLevel: 'Direct', source: 'CocoaPods', vulnerabilityCounts: { critical: 0, high: 0, medium: 1, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'HealthKit', libraryVersion: '17.0', appName: 'HealthTracker-iOS', dependencyLevel: 'Direct', source: 'iOS SDK', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'SnapKit', libraryVersion: '5.6.0', appName: 'HealthTracker-iOS', dependencyLevel: 'Direct', source: 'Swift Package Manager', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'libexpat', libraryVersion: '2.5.0', appName: 'HealthTracker-iOS', dependencyLevel: 'Transitive', source: 'CocoaPods', vulnerabilityCounts: { critical: 0, high: 1, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'RealmCore', libraryVersion: '13.26.0', appName: 'HealthTracker-iOS', dependencyLevel: 'Transitive', source: 'CocoaPods', vulnerabilityCounts: { critical: 0, high: 0, medium: 1, low: 1 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'libuv', libraryVersion: '1.44.2', appName: 'HealthTracker-iOS', dependencyLevel: 'Transitive', source: 'CocoaPods', vulnerabilityCounts: { critical: 0, high: 0, medium: 1, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'sqlite3', libraryVersion: '3.42.0', appName: 'HealthTracker-iOS', dependencyLevel: 'Transitive', source: 'CocoaPods', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false },

    // ShopEasy-iOS
    { libraryName: 'react-native', libraryVersion: '0.71.8', appName: 'ShopEasy-iOS', dependencyLevel: 'Direct', source: 'npm', vulnerabilityCounts: { critical: 1, high: 2, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'react', libraryVersion: '18.2.0', appName: 'ShopEasy-iOS', dependencyLevel: 'Direct', source: 'npm', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: '@react-navigation/native', libraryVersion: '6.1.9', appName: 'ShopEasy-iOS', dependencyLevel: 'Direct', source: 'npm', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'stripe-react-native', libraryVersion: '0.35.0', appName: 'ShopEasy-iOS', dependencyLevel: 'Direct', source: 'npm', vulnerabilityCounts: { critical: 0, high: 0, medium: 1, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'moment', libraryVersion: '2.29.4', appName: 'ShopEasy-iOS', dependencyLevel: 'Direct', source: 'npm', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: true, isDeprecated: false },
    { libraryName: 'react-native-firebase', libraryVersion: '18.6.0', appName: 'ShopEasy-iOS', dependencyLevel: 'Direct', source: 'npm', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'hermes-engine', libraryVersion: '0.71.14', appName: 'ShopEasy-iOS', dependencyLevel: 'Transitive', source: 'npm', vulnerabilityCounts: { critical: 1, high: 1, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'jsc-android', libraryVersion: '250231.0.0', appName: 'ShopEasy-iOS', dependencyLevel: 'Transitive', source: 'npm', vulnerabilityCounts: { critical: 0, high: 1, medium: 0, low: 0 }, notMaintained: false, isDeprecated: true },
    { libraryName: 'nanopb', libraryVersion: '2.30909.0', appName: 'ShopEasy-iOS', dependencyLevel: 'Transitive', source: 'CocoaPods', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'GoogleUtilities', libraryVersion: '7.12.0', appName: 'ShopEasy-iOS', dependencyLevel: 'Transitive', source: 'CocoaPods', vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false },

    // Non-iOS app libs (for filtering)
    { libraryName: 'spring-boot', libraryVersion: '2.7.14', appName: 'PaymentAPI-Backend', dependencyLevel: 'Direct', source: 'maven', vulnerabilityCounts: { critical: 0, high: 2, medium: 1, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'express', libraryVersion: '4.18.2', appName: 'AdminPortal-Web', dependencyLevel: 'Direct', source: 'npm', vulnerabilityCounts: { critical: 0, high: 0, medium: 1, low: 0 }, notMaintained: false, isDeprecated: false },
  ];
}

// ---------------------------------------------------------------------------
// Data fetching
// ---------------------------------------------------------------------------
async function fetchIssues(appFilter) {
  if (USE_MOCK) {
    console.log('  [mock mode — no OX_API_KEY]\n');
    let issues = getMockIssues();
    if (appFilter) issues = issues.filter(i => i.app?.name?.toLowerCase().includes(appFilter.toLowerCase()));
    return issues;
  }

  const { GET_ISSUES } = await import('../queries/issues.js');
  let allIssues = [];
  let offset = 0;
  const pageSize = 200;
  while (true) {
    const data = await queryFn(GET_ISSUES, {
      isDemo: false,
      getIssuesInput: { offset, limit: pageSize, sort: { fields: ['Severity'], order: ['DESC'] } },
    });
    allIssues = allIssues.concat(data.getIssues.issues);
    if (allIssues.length >= data.getIssues.totalFilteredIssues || data.getIssues.issues.length === 0) break;
    offset += pageSize;
  }
  if (appFilter) allIssues = allIssues.filter(i => i.app?.name?.toLowerCase().includes(appFilter.toLowerCase()));
  return allIssues;
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
// iOS classification engine
// ---------------------------------------------------------------------------

/**
 * Determine if a library is iOS-relevant and return matched categories.
 */
function classifyLibrary(lib) {
  const matches = [];

  // Check package manager
  const pm = (lib.source || lib.packageManager || '').toLowerCase();
  if (IOS_PACKAGE_MANAGERS.some(p => pm.includes(p))) {
    matches.push({ reason: `Package manager: ${lib.source || lib.packageManager}`, category: pm.includes('cocoapods') ? 'CocoaPods' : 'Swift Package Manager', confidence: 'high' });
  }

  // Check library name against known iOS patterns
  for (const pattern of IOS_LIBRARY_PATTERNS) {
    if (pattern.test(lib.libraryName)) {
      matches.push({ reason: `Known iOS library: ${lib.libraryName}`, category: 'iOS Library', confidence: 'high' });
      break;
    }
  }

  // Check source for iOS indicators
  const source = (lib.source || '').toLowerCase();
  if (IOS_SOURCE_PATTERNS.some(p => p.test(source))) {
    if (!matches.some(m => m.confidence === 'high')) {
      matches.push({ reason: `Source: ${lib.source}`, category: 'iOS Source', confidence: 'medium' });
    }
  }

  // App name heuristic: if the app name contains "ios" it's likely iOS
  const appName = (lib.appName || '').toLowerCase();
  if (appName.includes('ios') || appName.includes('iphone') || appName.includes('ipad')) {
    if (matches.length === 0) {
      matches.push({ reason: `iOS app: ${lib.appName}`, category: 'iOS App Context', confidence: 'low' });
    }
  }

  return matches;
}

/**
 * Classify an issue as iOS-relevant and return matched categories with weights.
 */
function classifyIssue(issue) {
  const matches = [];
  const text = [
    issue.mainTitle || '',
    issue.secondTitle || '',
    issue.description || '',
  ].join(' ');

  // Check text patterns
  for (const { pattern, category, weight } of IOS_ISSUE_PATTERNS) {
    if (pattern.test(text)) {
      matches.push({ category, weight, reason: `Text match: ${pattern.source}` });
    }
  }

  // Check if issue has SBOM context with iOS package manager
  if (issue.sbom) {
    const pm = (issue.sbom.packageManager || '').toLowerCase();
    if (IOS_PACKAGE_MANAGERS.some(p => pm.includes(p))) {
      matches.push({ category: pm.includes('cocoapods') ? 'CocoaPods' : 'Swift Package Manager', weight: 10, reason: `Package manager: ${issue.sbom.packageManager}` });
    }
    // Check if the library itself is a known iOS lib
    for (const pattern of IOS_LIBRARY_PATTERNS) {
      if (pattern.test(issue.sbom.libraryName)) {
        matches.push({ category: 'iOS Library', weight: 8, reason: `Known iOS lib: ${issue.sbom.libraryName}` });
        break;
      }
    }
  }

  // App name heuristic
  const appName = (issue.app?.name || '').toLowerCase();
  if (appName.includes('ios') || appName.includes('iphone') || appName.includes('ipad')) {
    matches.push({ category: 'iOS App Context', weight: 3, reason: `iOS app: ${issue.app.name}` });
  }

  // Mobile Security category from Ox
  if (issue.category?.name === 'Mobile Security') {
    matches.push({ category: 'Mobile Security', weight: 7, reason: 'Ox category: Mobile Security' });
  }

  return matches;
}

/**
 * Compute an iOS relevance score from classification matches.
 * Returns 0-100 where higher = more iOS-specific.
 */
function computeIOSScore(matches) {
  if (matches.length === 0) return 0;
  // Take the max weight from matches, plus a small bonus for multiple signals
  const maxWeight = Math.max(...matches.map(m => m.weight || 5));
  const bonus = Math.min(20, (matches.length - 1) * 5);
  return Math.min(100, maxWeight * 10 + bonus);
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------
function analyzeIssues(issues) {
  const classified = [];

  for (const issue of issues) {
    const matches = classifyIssue(issue);
    if (matches.length === 0) continue;

    const score = computeIOSScore(matches);
    const categories = [...new Set(matches.map(m => m.category))];
    const primaryCategory = matches.sort((a, b) => (b.weight || 0) - (a.weight || 0))[0]?.category || 'Unknown';

    classified.push({
      issueId: issue.issueId,
      title: issue.mainTitle,
      subtitle: issue.secondTitle,
      severity: issue.severity,
      originalSeverity: issue.originalSeverity,
      app: issue.app?.name,
      sourceType: issue.sourceType,
      oxCategory: issue.category?.name,
      iosScore: score,
      primaryIOSCategory: primaryCategory,
      iosCategories: categories,
      matchReasons: matches.map(m => m.reason),
      library: issue.sbom ? { name: issue.sbom.libraryName, version: issue.sbom.libraryVersion, pm: issue.sbom.packageManager } : null,
    });
  }

  // Sort by severity weight then iOS score
  const sevOrder = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
  classified.sort((a, b) => {
    const sevDiff = (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9);
    if (sevDiff !== 0) return sevDiff;
    return b.iosScore - a.iosScore;
  });

  return classified;
}

function analyzeSBOM(libs) {
  const iosLibs = [];
  for (const lib of libs) {
    const matches = classifyLibrary(lib);
    if (matches.length === 0) continue;

    const vc = lib.vulnerabilityCounts || {};
    const vulnTotal = (vc.critical || 0) + (vc.high || 0) + (vc.medium || 0) + (vc.low || 0);

    iosLibs.push({
      name: lib.libraryName,
      version: lib.libraryVersion,
      app: lib.appName,
      level: lib.dependencyLevel,
      source: lib.source,
      vulnTotal,
      vulns: vc,
      notMaintained: lib.notMaintained,
      isDeprecated: lib.isDeprecated,
      confidence: matches[0]?.confidence || 'low',
      matchReasons: matches.map(m => m.reason),
    });
  }

  return iosLibs;
}

function buildCategorySummary(classifiedIssues) {
  const summary = {};
  for (const issue of classifiedIssues) {
    for (const cat of issue.iosCategories) {
      if (!summary[cat]) summary[cat] = { count: 0, critical: 0, high: 0, medium: 0, low: 0, issues: [] };
      summary[cat].count++;
      const sev = (issue.severity || '').toLowerCase();
      if (summary[cat][sev] !== undefined) summary[cat][sev]++;
      summary[cat].issues.push(issue.issueId);
    }
  }
  return summary;
}

function buildGroupedSummary(catSummary) {
  const grouped = {};
  for (const [groupName, categories] of Object.entries(CATEGORY_GROUPS)) {
    const groupData = { totalIssues: 0, categories: {} };
    for (const cat of categories) {
      if (catSummary[cat]) {
        groupData.categories[cat] = catSummary[cat];
        groupData.totalIssues += catSummary[cat].count;
      }
    }
    if (groupData.totalIssues > 0) {
      grouped[groupName] = groupData;
    }
  }
  // Collect uncategorized
  const allGrouped = new Set(Object.values(CATEGORY_GROUPS).flat());
  const uncategorized = {};
  for (const [cat, data] of Object.entries(catSummary)) {
    if (!allGrouped.has(cat)) uncategorized[cat] = data;
  }
  if (Object.keys(uncategorized).length > 0) {
    grouped['Other iOS Signals'] = {
      totalIssues: Object.values(uncategorized).reduce((s, d) => s + d.count, 0),
      categories: uncategorized,
    };
  }
  return grouped;
}

// ---------------------------------------------------------------------------
// Report generation
// ---------------------------------------------------------------------------
function generateConsoleOutput(classifiedIssues, iosLibs, catSummary, groupedSummary, allIssuesCount) {
  const lines = [];

  lines.push('');
  lines.push('='.repeat(70));
  lines.push('  E12: iOS-Specific Vulnerability Filter');
  lines.push('  Ox Security — iOS Platform Security Analysis');
  lines.push('='.repeat(70));
  lines.push('');

  if (USE_MOCK) {
    lines.push('[Mock Mode — using realistic sample data]');
    lines.push('');
  }

  // Overview
  lines.push('Overview');
  lines.push('-'.repeat(40));
  lines.push(`  Total issues scanned:     ${allIssuesCount}`);
  lines.push(`  iOS-relevant issues:      ${classifiedIssues.length} (${allIssuesCount ? Math.round(classifiedIssues.length / allIssuesCount * 100) : 0}%)`);
  lines.push(`  iOS-relevant SBOM libs:   ${iosLibs.length}`);
  lines.push(`  iOS categories detected:  ${Object.keys(catSummary).length}`);
  lines.push('');

  // Severity breakdown
  const sevCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  for (const issue of classifiedIssues) {
    if (sevCounts[issue.severity] !== undefined) sevCounts[issue.severity]++;
  }
  lines.push('  Severity breakdown:');
  for (const [sev, count] of Object.entries(sevCounts)) {
    if (count > 0) {
      const bar = '\u2588'.repeat(Math.min(30, count * 3)) + ` ${count}`;
      lines.push(`    ${sev.padEnd(10)} ${bar}`);
    }
  }
  lines.push('');

  // Category group summary
  lines.push('iOS Security Categories');
  lines.push('-'.repeat(40));
  for (const [groupName, groupData] of Object.entries(groupedSummary)) {
    lines.push(`  ${groupName} (${groupData.totalIssues} issues)`);
    for (const [cat, data] of Object.entries(groupData.categories)) {
      const sevStr = [];
      if (data.critical) sevStr.push(`C:${data.critical}`);
      if (data.high) sevStr.push(`H:${data.high}`);
      if (data.medium) sevStr.push(`M:${data.medium}`);
      if (data.low) sevStr.push(`L:${data.low}`);
      lines.push(`    - ${cat}: ${data.count} issues [${sevStr.join(' ')}]`);
    }
  }
  lines.push('');

  // Top iOS issues
  lines.push('iOS-Specific Issues (by severity)');
  lines.push('-'.repeat(40));
  const SEV_ICON = { Critical: '[!!!]', High: '[!!]', Medium: '[!]', Low: '[.]' };
  for (const issue of classifiedIssues.slice(0, 15)) {
    const icon = SEV_ICON[issue.severity] || '[?]';
    lines.push(`  ${icon} ${issue.title}`);
    lines.push(`       App: ${issue.app} | Category: ${issue.primaryIOSCategory} | Score: ${issue.iosScore}/100`);
    if (issue.library) {
      lines.push(`       Lib: ${issue.library.name}@${issue.library.version} (${issue.library.pm})`);
    }
  }
  lines.push('');

  // iOS SBOM summary
  const vulnIosLibs = iosLibs.filter(l => l.vulnTotal > 0);
  if (vulnIosLibs.length > 0) {
    lines.push('Vulnerable iOS Libraries');
    lines.push('-'.repeat(40));
    const nameW = Math.max(20, ...vulnIosLibs.map(l => l.name.length + 2));
    for (const lib of vulnIosLibs.sort((a, b) => b.vulnTotal - a.vulnTotal)) {
      const vc = lib.vulns;
      const flags = [];
      if (lib.notMaintained) flags.push('UNMAINT');
      if (lib.isDeprecated) flags.push('DEPR');
      const flagStr = flags.length ? ` [${flags.join(',')}]` : '';
      lines.push(`  ${lib.name.padEnd(nameW)} ${lib.version.padEnd(12)} ${lib.app.padEnd(22)} C:${vc.critical||0} H:${vc.high||0} M:${vc.medium||0} L:${vc.low||0}${flagStr}`);
    }
    lines.push('');
  }

  // Per-app breakdown
  const appIssues = {};
  for (const issue of classifiedIssues) {
    if (!appIssues[issue.app]) appIssues[issue.app] = [];
    appIssues[issue.app].push(issue);
  }
  lines.push('Per-App iOS Issue Summary');
  lines.push('-'.repeat(40));
  for (const [app, issues] of Object.entries(appIssues)) {
    const sc = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    for (const i of issues) if (sc[i.severity] !== undefined) sc[i.severity]++;
    const cats = [...new Set(issues.flatMap(i => i.iosCategories))].join(', ');
    lines.push(`  ${app}: ${issues.length} iOS issues (C:${sc.Critical} H:${sc.High} M:${sc.Medium} L:${sc.Low})`);
    lines.push(`    Categories: ${cats}`);
  }
  lines.push('');

  return lines.join('\n');
}

function generateMarkdownReport(classifiedIssues, iosLibs, catSummary, groupedSummary, allIssuesCount, timestamp) {
  const lines = [];

  lines.push('# E12: iOS-Specific Vulnerability Filter');
  lines.push(`\n*Generated: ${timestamp}*`);
  if (USE_MOCK) lines.push('\n> **Mock Mode** — using realistic sample data (no OX_API_KEY configured)');
  lines.push('');

  // Overview
  lines.push('## Overview');
  lines.push('');
  lines.push('| Metric | Value |');
  lines.push('|--------|-------|');
  lines.push(`| Total issues scanned | ${allIssuesCount} |`);
  lines.push(`| iOS-relevant issues | ${classifiedIssues.length} (${allIssuesCount ? Math.round(classifiedIssues.length / allIssuesCount * 100) : 0}%) |`);
  lines.push(`| iOS SBOM libraries | ${iosLibs.length} |`);
  lines.push(`| iOS categories detected | ${Object.keys(catSummary).length} |`);
  lines.push('');

  // Methodology
  lines.push('## Detection Methodology');
  lines.push('');
  lines.push('Issues and SBOM libraries are classified as iOS-relevant using multiple signals:');
  lines.push('');
  lines.push('1. **Package Manager** — CocoaPods, Swift Package Manager, Carthage');
  lines.push('2. **Library Name** — Known iOS/Apple-platform libraries (Alamofire, KeychainAccess, etc.)');
  lines.push('3. **Issue Text** — Pattern matching for iOS keywords (ATS, Keychain, Xcode, .swift, etc.)');
  lines.push('4. **Ox Category** — Mobile Security category from Ox Security');
  lines.push('5. **App Name** — Apps with "iOS" in their name (low confidence fallback)');
  lines.push('');
  lines.push('Each match contributes to an iOS relevance score (0-100). Higher scores indicate stronger iOS-specific signals.');
  lines.push('');

  // Severity breakdown
  lines.push('## Severity Breakdown');
  lines.push('');
  const sevCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  for (const issue of classifiedIssues) {
    if (sevCounts[issue.severity] !== undefined) sevCounts[issue.severity]++;
  }
  lines.push('| Severity | Count |');
  lines.push('|----------|-------|');
  for (const [sev, count] of Object.entries(sevCounts)) {
    if (count > 0) lines.push(`| ${sev} | ${count} |`);
  }
  lines.push('');

  // Grouped categories
  lines.push('## iOS Security Categories');
  lines.push('');
  for (const [groupName, groupData] of Object.entries(groupedSummary)) {
    lines.push(`### ${groupName} (${groupData.totalIssues} issues)`);
    lines.push('');
    lines.push('| Category | Issues | Critical | High | Medium | Low |');
    lines.push('|----------|--------|----------|------|--------|-----|');
    for (const [cat, data] of Object.entries(groupData.categories)) {
      lines.push(`| ${cat} | ${data.count} | ${data.critical} | ${data.high} | ${data.medium} | ${data.low} |`);
    }
    lines.push('');
  }

  // Full issue table
  lines.push('## iOS-Specific Issues');
  lines.push('');
  lines.push('| Severity | Issue | App | iOS Category | Score | Library |');
  lines.push('|----------|-------|-----|-------------|-------|---------|');
  for (const issue of classifiedIssues) {
    const lib = issue.library ? `${issue.library.name}@${issue.library.version}` : '-';
    lines.push(`| **${issue.severity}** | ${issue.title} | ${issue.app} | ${issue.primaryIOSCategory} | ${issue.iosScore} | ${lib} |`);
  }
  lines.push('');

  // Vulnerable iOS libraries
  const vulnIosLibs = iosLibs.filter(l => l.vulnTotal > 0);
  if (vulnIosLibs.length > 0) {
    lines.push('## Vulnerable iOS Libraries');
    lines.push('');
    lines.push('| Library | Version | App | Level | C | H | M | L | Flags |');
    lines.push('|---------|---------|-----|-------|---|---|---|---|-------|');
    for (const lib of vulnIosLibs.sort((a, b) => b.vulnTotal - a.vulnTotal)) {
      const flags = [];
      if (lib.notMaintained) flags.push('Unmaintained');
      if (lib.isDeprecated) flags.push('Deprecated');
      lines.push(`| ${lib.name} | ${lib.version} | ${lib.app} | ${lib.level} | ${lib.vulns.critical||0} | ${lib.vulns.high||0} | ${lib.vulns.medium||0} | ${lib.vulns.low||0} | ${flags.join(', ') || '-'} |`);
    }
    lines.push('');
  }

  // All iOS SBOM
  lines.push('## Full iOS SBOM');
  lines.push('');
  lines.push(`Total iOS-relevant libraries: ${iosLibs.length}`);
  lines.push('');
  // Group by app
  const libsByApp = {};
  for (const lib of iosLibs) {
    if (!libsByApp[lib.app]) libsByApp[lib.app] = [];
    libsByApp[lib.app].push(lib);
  }
  for (const [app, libs] of Object.entries(libsByApp)) {
    lines.push(`### ${app} (${libs.length} iOS libs)`);
    lines.push('');
    lines.push('| Library | Version | Level | Source | Vulns | Confidence |');
    lines.push('|---------|---------|-------|--------|-------|------------|');
    for (const lib of libs) {
      lines.push(`| ${lib.name} | ${lib.version} | ${lib.level} | ${lib.source} | ${lib.vulnTotal} | ${lib.confidence} |`);
    }
    lines.push('');
  }

  // Recommendations
  lines.push('## Recommendations');
  lines.push('');
  const recs = generateRecommendations(classifiedIssues, iosLibs, catSummary);
  for (const rec of recs) {
    lines.push(`- **[${rec.priority}]** ${rec.text}`);
  }
  lines.push('');

  return lines.join('\n');
}

function generateRecommendations(classifiedIssues, iosLibs, catSummary) {
  const recs = [];

  // CocoaPods vulnerabilities
  if (catSummary['CocoaPods']?.critical > 0) {
    recs.push({ priority: 'Critical', text: `${catSummary['CocoaPods'].critical} critical vulnerabilities in CocoaPods dependencies. Run \`pod update\` and verify transitive dependency versions.` });
  }

  // ATS issues
  if (catSummary['App Transport Security']) {
    recs.push({ priority: 'High', text: 'App Transport Security is misconfigured. Remove NSAllowsArbitraryLoads and use exception domains only for specific legacy hosts.' });
  }

  // Certificate pinning
  if (catSummary['Certificate Pinning']) {
    recs.push({ priority: 'High', text: 'Certificate pinning is missing. Implement TrustKit or URLSession certificate pinning for all API connections, especially for financial/health data.' });
  }

  // Keychain security
  if (catSummary['Keychain Security']) {
    recs.push({ priority: 'High', text: 'Keychain accessibility attributes are not properly set. Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly for sensitive credentials.' });
  }

  // React Native
  if (catSummary['React Native (iOS)']) {
    recs.push({ priority: 'High', text: 'React Native version has known vulnerabilities in the Hermes engine. Upgrade to the latest stable React Native release.' });
  }

  // Deprecated WebView
  if (catSummary['WebView Security']) {
    recs.push({ priority: 'Medium', text: 'Migrate from deprecated UIWebView to WKWebView. Apple may reject App Store submissions using UIWebView.' });
  }

  // Biometrics
  if (catSummary['Biometrics']) {
    recs.push({ priority: 'Medium', text: 'Review biometric authentication implementation. Ensure fallback passcode does not bypass biometric requirement without delay.' });
  }

  // Firebase
  if (catSummary['Firebase SDK']) {
    recs.push({ priority: 'Medium', text: 'Firebase configuration files (GoogleService-Info.plist) should not be committed to source control. Use environment-specific configs.' });
  }

  // Unmaintained iOS libs
  const unmaintained = iosLibs.filter(l => l.notMaintained);
  if (unmaintained.length > 0) {
    const names = [...new Set(unmaintained.map(l => l.name))].join(', ');
    recs.push({ priority: 'Medium', text: `${unmaintained.length} unmaintained iOS libraries detected (${names}). Plan migration to actively maintained alternatives.` });
  }

  // Deprecated iOS libs
  const deprecated = iosLibs.filter(l => l.isDeprecated);
  if (deprecated.length > 0) {
    const names = [...new Set(deprecated.map(l => l.name))].join(', ');
    recs.push({ priority: 'Medium', text: `${deprecated.length} deprecated iOS libraries (${names}). Replace with current alternatives to avoid unpatched vulnerabilities.` });
  }

  // Swift code issues
  if (catSummary['Swift Code']) {
    recs.push({ priority: 'High', text: 'Code vulnerabilities detected in Swift source files. Review parameterized query usage and input validation patterns.' });
  }

  return recs;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  const appFilter = process.env.OX_APP_NAME || process.argv[2] || '';
  const timestamp = new Date().toISOString();

  console.log('E12: iOS-Specific Vulnerability Filter');
  console.log('Fetching data...');

  // Fetch all data
  const allIssues = await fetchIssues(appFilter);
  const allLibs = await fetchSBOM(appFilter);

  console.log(`  Issues fetched: ${allIssues.length}`);
  console.log(`  SBOM libraries fetched: ${allLibs.length}`);
  console.log('');

  // Classify
  console.log('Classifying iOS-specific findings...');
  const classifiedIssues = analyzeIssues(allIssues);
  const iosLibs = analyzeSBOM(allLibs);

  console.log(`  iOS issues identified: ${classifiedIssues.length}/${allIssues.length}`);
  console.log(`  iOS libraries identified: ${iosLibs.length}/${allLibs.length}`);
  console.log('');

  if (classifiedIssues.length === 0 && iosLibs.length === 0) {
    console.log('No iOS-specific findings detected.');
    return;
  }

  // Build category summaries
  const catSummary = buildCategorySummary(classifiedIssues);
  const groupedSummary = buildGroupedSummary(catSummary);

  // Console output
  const consoleOutput = generateConsoleOutput(classifiedIssues, iosLibs, catSummary, groupedSummary, allIssues.length);
  console.log(consoleOutput);

  // Write results to experiments/
  const dateStr = timestamp.slice(0, 10);
  const outDir = resolve(process.cwd(), 'experiments', `ios-filter-${dateStr}`);
  mkdirSync(outDir, { recursive: true });

  // JSON export
  const jsonData = {
    timestamp,
    mockMode: USE_MOCK,
    filter: appFilter || null,
    summary: {
      totalIssuesScanned: allIssues.length,
      iosIssuesFound: classifiedIssues.length,
      iosLibsFound: iosLibs.length,
      categoriesDetected: Object.keys(catSummary).length,
    },
    categoryGroups: groupedSummary,
    categories: catSummary,
    issues: classifiedIssues,
    libraries: iosLibs,
  };
  writeFileSync(resolve(outDir, 'ios-filter.json'), JSON.stringify(jsonData, null, 2));

  // Markdown report
  const mdReport = generateMarkdownReport(classifiedIssues, iosLibs, catSummary, groupedSummary, allIssues.length, timestamp);
  writeFileSync(resolve(outDir, 'ios-filter-report.md'), mdReport);

  console.log(`Results written to experiments/ios-filter-${dateStr}/`);
  console.log(`  - ios-filter.json       (machine-readable)`);
  console.log(`  - ios-filter-report.md  (human-readable)`);
}

main().catch(e => { console.error('Error:', e.message); process.exit(1); });
