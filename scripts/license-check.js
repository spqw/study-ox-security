#!/usr/bin/env node
/**
 * E13: License Compliance Check
 *
 * Scans SBOM for license conflicts and compliance risks:
 *   - Classifies every library license (permissive, weak-copyleft, strong-copyleft, proprietary, unknown)
 *   - Detects conflicts: strong-copyleft (GPL) in proprietary/closed-source apps
 *   - Flags weak-copyleft (LGPL/MPL) that may need review
 *   - Identifies missing/unknown licenses
 *   - Leverages Ox Security's licenseIssue flag as an additional signal
 *   - Per-app compliance summary with risk grades
 *
 * Falls back to realistic mock data when OX_API_KEY is not configured.
 *
 * Usage:
 *   node scripts/license-check.js [appFilter]
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
// License classification database
// ---------------------------------------------------------------------------

/**
 * License categories:
 *   permissive      — MIT, BSD, Apache, ISC, etc. — free to use in proprietary software
 *   weak-copyleft   — LGPL, MPL, EPL — file-level copyleft, may need review for static linking
 *   strong-copyleft  — GPL, AGPL, SSPL — viral copyleft, requires derivative works to be open-sourced
 *   public-domain   — CC0, Unlicense, WTFPL — no restrictions at all
 *   proprietary     — Commercial/proprietary licenses — need license agreement
 *   unknown         — Missing or unrecognized license
 */
const LICENSE_RULES = [
  // Permissive
  { pattern: /\bMIT\b/i,                                         category: 'permissive',      spdx: 'MIT',             risk: 'none' },
  { pattern: /\bISC\b/i,                                         category: 'permissive',      spdx: 'ISC',             risk: 'none' },
  { pattern: /\bApache[\s-]*2/i,                                  category: 'permissive',      spdx: 'Apache-2.0',      risk: 'none' },
  { pattern: /\bApache\s*License/i,                               category: 'permissive',      spdx: 'Apache-2.0',      risk: 'none' },
  { pattern: /\bBSD[\s-]*3/i,                                     category: 'permissive',      spdx: 'BSD-3-Clause',    risk: 'none' },
  { pattern: /\bBSD[\s-]*2/i,                                     category: 'permissive',      spdx: 'BSD-2-Clause',    risk: 'none' },
  { pattern: /\bBSD\b(?!.*GPL)/i,                                 category: 'permissive',      spdx: 'BSD',             risk: 'none' },
  { pattern: /\bZlib\b/i,                                         category: 'permissive',      spdx: 'Zlib',            risk: 'none' },
  { pattern: /\bBoost\b/i,                                        category: 'permissive',      spdx: 'BSL-1.0',         risk: 'none' },
  { pattern: /\bPSF\b/i,                                          category: 'permissive',      spdx: 'PSF-2.0',         risk: 'none' },
  { pattern: /\bX11\b/i,                                          category: 'permissive',      spdx: 'X11',             risk: 'none' },
  { pattern: /\bOpenSSL\b/i,                                      category: 'permissive',      spdx: 'OpenSSL',         risk: 'none' },
  { pattern: /\bArtistic[\s-]*2/i,                                category: 'permissive',      spdx: 'Artistic-2.0',    risk: 'none' },
  { pattern: /\bJSON\b/i,                                         category: 'permissive',      spdx: 'JSON',            risk: 'none' },

  // Public domain
  { pattern: /\bCC0\b/i,                                          category: 'public-domain',   spdx: 'CC0-1.0',         risk: 'none' },
  { pattern: /\bUnlicense\b/i,                                    category: 'public-domain',   spdx: 'Unlicense',       risk: 'none' },
  { pattern: /\bWTFPL\b/i,                                        category: 'public-domain',   spdx: 'WTFPL',           risk: 'none' },
  { pattern: /\bpublic\s*domain\b/i,                              category: 'public-domain',   spdx: 'Public Domain',   risk: 'none' },

  // Weak copyleft — order matters: match LGPL before GPL
  { pattern: /\bLGPL[\s-]*3/i,                                    category: 'weak-copyleft',   spdx: 'LGPL-3.0',        risk: 'medium' },
  { pattern: /\bLGPL[\s-]*2\.1/i,                                 category: 'weak-copyleft',   spdx: 'LGPL-2.1',        risk: 'medium' },
  { pattern: /\bLGPL\b/i,                                         category: 'weak-copyleft',   spdx: 'LGPL',            risk: 'medium' },
  { pattern: /\bMPL[\s-]*2/i,                                     category: 'weak-copyleft',   spdx: 'MPL-2.0',         risk: 'medium' },
  { pattern: /\bMPL\b/i,                                          category: 'weak-copyleft',   spdx: 'MPL',             risk: 'medium' },
  { pattern: /\bEPL[\s-]*[12]/i,                                  category: 'weak-copyleft',   spdx: 'EPL',             risk: 'medium' },
  { pattern: /\bCPL\b/i,                                          category: 'weak-copyleft',   spdx: 'CPL-1.0',         risk: 'medium' },
  { pattern: /\bCDDL\b/i,                                         category: 'weak-copyleft',   spdx: 'CDDL-1.0',        risk: 'medium' },

  // Strong copyleft — check after LGPL
  { pattern: /\bAGPL[\s-]*3/i,                                    category: 'strong-copyleft', spdx: 'AGPL-3.0',        risk: 'critical' },
  { pattern: /\bAGPL\b/i,                                         category: 'strong-copyleft', spdx: 'AGPL',            risk: 'critical' },
  { pattern: /\bSSPL\b/i,                                         category: 'strong-copyleft', spdx: 'SSPL-1.0',        risk: 'critical' },
  { pattern: /\bGPL[\s-]*3/i,                                     category: 'strong-copyleft', spdx: 'GPL-3.0',         risk: 'high' },
  { pattern: /\bGPL[\s-]*2/i,                                     category: 'strong-copyleft', spdx: 'GPL-2.0',         risk: 'high' },
  { pattern: /\bGPL\b/i,                                          category: 'strong-copyleft', spdx: 'GPL',             risk: 'high' },
  { pattern: /\bEuPL\b/i,                                         category: 'strong-copyleft', spdx: 'EUPL-1.2',        risk: 'high' },

  // Proprietary/commercial
  { pattern: /\bproprietary\b/i,                                  category: 'proprietary',     spdx: 'Proprietary',     risk: 'high' },
  { pattern: /\bcommercial\b/i,                                   category: 'proprietary',     spdx: 'Commercial',      risk: 'high' },
  { pattern: /\bEULA\b/i,                                         category: 'proprietary',     spdx: 'EULA',            risk: 'high' },
];

/**
 * Known iOS-specific license compatibility notes.
 * Apple's App Store has restrictions that make some licenses problematic.
 */
const APPSTORE_NOTES = {
  'strong-copyleft': 'GPL/AGPL are widely considered incompatible with Apple App Store distribution. The App Store\'s DRM and distribution terms conflict with GPL\'s freedom-to-redistribute requirement.',
  'SSPL-1.0': 'SSPL (Server Side Public License) is not OSI-approved and has extremely broad copyleft scope. Avoid in any commercial product.',
  'AGPL-3.0': 'AGPL requires source distribution for network interaction. Combined with App Store incompatibility, this is a critical compliance risk.',
};

// ---------------------------------------------------------------------------
// License classifier
// ---------------------------------------------------------------------------

/**
 * Classify a license string. Returns { category, spdx, risk, raw }.
 */
function classifyLicense(licenseStr) {
  if (!licenseStr || licenseStr.trim() === '' || licenseStr === 'N/A' || licenseStr === 'UNKNOWN') {
    return { category: 'unknown', spdx: 'UNKNOWN', risk: 'medium', raw: licenseStr || '' };
  }

  const raw = licenseStr.trim();

  // Try each rule in order (order matters — LGPL before GPL, etc.)
  for (const rule of LICENSE_RULES) {
    if (rule.pattern.test(raw)) {
      return { category: rule.category, spdx: rule.spdx, risk: rule.risk, raw };
    }
  }

  // Unrecognized license
  return { category: 'unknown', spdx: raw, risk: 'low', raw };
}

/**
 * Detect conflicts for a library within an app context.
 * Returns array of conflict objects.
 */
function detectConflicts(lib, licenseInfo) {
  const conflicts = [];

  // Strong copyleft in any app is a potential issue (especially for iOS/App Store)
  if (licenseInfo.category === 'strong-copyleft') {
    conflicts.push({
      type: 'copyleft-in-proprietary',
      severity: licenseInfo.spdx.includes('AGPL') || licenseInfo.spdx.includes('SSPL') ? 'critical' : 'high',
      message: `${licenseInfo.spdx} license on ${lib.libraryName} — strong copyleft may require open-sourcing your app`,
      detail: APPSTORE_NOTES['strong-copyleft'],
    });
    if (APPSTORE_NOTES[licenseInfo.spdx]) {
      conflicts.push({
        type: 'appstore-incompatible',
        severity: 'critical',
        message: `${licenseInfo.spdx} is likely incompatible with Apple App Store distribution`,
        detail: APPSTORE_NOTES[licenseInfo.spdx],
      });
    }
  }

  // Weak copyleft may need review (static linking on iOS is common)
  if (licenseInfo.category === 'weak-copyleft') {
    const isStatic = (lib.dependencyLevel || '').toLowerCase() === 'direct';
    conflicts.push({
      type: 'weak-copyleft-review',
      severity: 'medium',
      message: `${licenseInfo.spdx} on ${lib.libraryName} — review required for iOS static linking compliance`,
      detail: isStatic
        ? 'iOS apps typically link libraries statically. LGPL requires allowing re-linking, which may need special build configuration.'
        : 'Transitive dependency with weak copyleft. Verify linking model.',
    });
  }

  // Unknown license is a compliance gap
  if (licenseInfo.category === 'unknown' && licenseInfo.raw === '') {
    conflicts.push({
      type: 'missing-license',
      severity: 'medium',
      message: `No license declared for ${lib.libraryName}@${lib.libraryVersion}`,
      detail: 'Missing license means uncertain legal standing. The default copyright applies — you may not have rights to use this code.',
    });
  }

  // Ox flagged it as a license issue
  if (lib.licenseIssue) {
    // Don't duplicate if we already flagged it
    const alreadyFlagged = conflicts.some(c => c.severity === 'critical' || c.severity === 'high');
    if (!alreadyFlagged) {
      conflicts.push({
        type: 'ox-license-flag',
        severity: 'high',
        message: `Ox Security flagged license issue on ${lib.libraryName}@${lib.libraryVersion} (${licenseInfo.raw || 'unknown license'})`,
        detail: 'Ox Security\'s compliance engine detected a license issue with this library.',
      });
    }
  }

  return conflicts;
}

// ---------------------------------------------------------------------------
// Mock data
// ---------------------------------------------------------------------------
function getMockSBOM() {
  return [
    // MyBankingApp-iOS — proprietary app with mixed licenses
    { libraryName: 'Alamofire',       libraryVersion: '5.6.4',     appName: 'MyBankingApp-iOS',  dependencyLevel: 'Direct',     source: 'Swift Package Manager', license: 'MIT',                  licenseIssue: false, vulnerabilityCounts: { critical: 0, high: 2, medium: 1, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'Ono',             libraryVersion: '2.5.0',     appName: 'MyBankingApp-iOS',  dependencyLevel: 'Direct',     source: 'CocoaPods',             license: 'MIT',                  licenseIssue: false, vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: true,  isDeprecated: false },
    { libraryName: 'KeychainAccess',  libraryVersion: '4.2.2',     appName: 'MyBankingApp-iOS',  dependencyLevel: 'Direct',     source: 'Swift Package Manager', license: 'MIT',                  licenseIssue: false, vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'CryptoSwift',     libraryVersion: '1.7.2',     appName: 'MyBankingApp-iOS',  dependencyLevel: 'Direct',     source: 'Swift Package Manager', license: 'AGPL-3.0',            licenseIssue: true,  vulnerabilityCounts: { critical: 0, high: 0, medium: 1, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'lodash',          libraryVersion: '4.17.19',   appName: 'MyBankingApp-iOS',  dependencyLevel: 'Direct',     source: 'npm',                   license: 'MIT',                  licenseIssue: false, vulnerabilityCounts: { critical: 1, high: 0, medium: 1, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'SwiftLint',       libraryVersion: '0.54.0',    appName: 'MyBankingApp-iOS',  dependencyLevel: 'Direct',     source: 'Swift Package Manager', license: 'MIT',                  licenseIssue: false, vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'libxml2',         libraryVersion: '2.11.6',    appName: 'MyBankingApp-iOS',  dependencyLevel: 'Transitive', source: 'CocoaPods',             license: 'MIT',                  licenseIssue: false, vulnerabilityCounts: { critical: 1, high: 1, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'OpenSSL',         libraryVersion: '1.1.1w',    appName: 'MyBankingApp-iOS',  dependencyLevel: 'Transitive', source: 'CocoaPods',             license: 'OpenSSL/SSLeay',       licenseIssue: false, vulnerabilityCounts: { critical: 0, high: 1, medium: 1, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'BoringSSL-GRPC',  libraryVersion: '0.0.27',    appName: 'MyBankingApp-iOS',  dependencyLevel: 'Transitive', source: 'CocoaPods',             license: 'ISC',                  licenseIssue: false, vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 1 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'FFmpeg-iOS',      libraryVersion: '4.4.3',     appName: 'MyBankingApp-iOS',  dependencyLevel: 'Direct',     source: 'CocoaPods',             license: 'LGPL-2.1',            licenseIssue: true,  vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false },

    // HealthTracker-iOS — health app with stricter compliance needs
    { libraryName: 'SQLite.swift',    libraryVersion: '0.14.1',    appName: 'HealthTracker-iOS', dependencyLevel: 'Direct',     source: 'Swift Package Manager', license: 'MIT',                  licenseIssue: false, vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'Charts',          libraryVersion: '5.0.0',     appName: 'HealthTracker-iOS', dependencyLevel: 'Direct',     source: 'Swift Package Manager', license: 'Apache-2.0',           licenseIssue: false, vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'Realm',           libraryVersion: '10.44.0',   appName: 'HealthTracker-iOS', dependencyLevel: 'Direct',     source: 'CocoaPods',             license: 'Apache-2.0',           licenseIssue: false, vulnerabilityCounts: { critical: 0, high: 0, medium: 1, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'SnapKit',         libraryVersion: '5.6.0',     appName: 'HealthTracker-iOS', dependencyLevel: 'Direct',     source: 'Swift Package Manager', license: 'MIT',                  licenseIssue: false, vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'libexpat',        libraryVersion: '2.5.0',     appName: 'HealthTracker-iOS', dependencyLevel: 'Transitive', source: 'CocoaPods',             license: 'MIT',                  licenseIssue: false, vulnerabilityCounts: { critical: 0, high: 1, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'RealmCore',       libraryVersion: '13.26.0',   appName: 'HealthTracker-iOS', dependencyLevel: 'Transitive', source: 'CocoaPods',             license: 'Apache-2.0',           licenseIssue: false, vulnerabilityCounts: { critical: 0, high: 0, medium: 1, low: 1 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'libuv',           libraryVersion: '1.44.2',    appName: 'HealthTracker-iOS', dependencyLevel: 'Transitive', source: 'CocoaPods',             license: 'MIT',                  licenseIssue: false, vulnerabilityCounts: { critical: 0, high: 0, medium: 1, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'FMDB',            libraryVersion: '2.7.5',     appName: 'HealthTracker-iOS', dependencyLevel: 'Direct',     source: 'CocoaPods',             license: '',                     licenseIssue: true,  vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: true,  isDeprecated: false },
    { libraryName: 'OpenCV',          libraryVersion: '4.8.0',     appName: 'HealthTracker-iOS', dependencyLevel: 'Direct',     source: 'CocoaPods',             license: 'BSD-3-Clause',         licenseIssue: false, vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false },

    // ShopEasy-iOS — React Native e-commerce
    { libraryName: 'react-native',             libraryVersion: '0.71.8',    appName: 'ShopEasy-iOS', dependencyLevel: 'Direct',     source: 'npm', license: 'MIT',                  licenseIssue: false, vulnerabilityCounts: { critical: 1, high: 2, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'react',                    libraryVersion: '18.2.0',    appName: 'ShopEasy-iOS', dependencyLevel: 'Direct',     source: 'npm', license: 'MIT',                  licenseIssue: false, vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: '@react-navigation/native', libraryVersion: '6.1.9',     appName: 'ShopEasy-iOS', dependencyLevel: 'Direct',     source: 'npm', license: 'MIT',                  licenseIssue: false, vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'stripe-react-native',      libraryVersion: '0.35.0',    appName: 'ShopEasy-iOS', dependencyLevel: 'Direct',     source: 'npm', license: 'MIT',                  licenseIssue: false, vulnerabilityCounts: { critical: 0, high: 0, medium: 1, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'moment',                   libraryVersion: '2.29.4',    appName: 'ShopEasy-iOS', dependencyLevel: 'Direct',     source: 'npm', license: 'MIT',                  licenseIssue: false, vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: true,  isDeprecated: false },
    { libraryName: 'react-native-firebase',    libraryVersion: '18.6.0',    appName: 'ShopEasy-iOS', dependencyLevel: 'Direct',     source: 'npm', license: 'Apache-2.0',           licenseIssue: false, vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'hermes-engine',            libraryVersion: '0.71.14',   appName: 'ShopEasy-iOS', dependencyLevel: 'Transitive', source: 'npm', license: 'MIT',                  licenseIssue: false, vulnerabilityCounts: { critical: 1, high: 1, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'jsc-android',              libraryVersion: '250231.0.0',appName: 'ShopEasy-iOS', dependencyLevel: 'Transitive', source: 'npm', license: 'BSD-2-Clause',          licenseIssue: false, vulnerabilityCounts: { critical: 0, high: 1, medium: 0, low: 0 }, notMaintained: false, isDeprecated: true  },
    { libraryName: 'nanopb',                   libraryVersion: '2.30909.0', appName: 'ShopEasy-iOS', dependencyLevel: 'Transitive', source: 'CocoaPods', license: 'Zlib',            licenseIssue: false, vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'GoogleUtilities',          libraryVersion: '7.12.0',    appName: 'ShopEasy-iOS', dependencyLevel: 'Transitive', source: 'CocoaPods', license: 'Apache-2.0',      licenseIssue: false, vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false },
    { libraryName: 'iCarousel',                libraryVersion: '1.8.3',     appName: 'ShopEasy-iOS', dependencyLevel: 'Direct',     source: 'CocoaPods', license: 'GPL-3.0',         licenseIssue: true,  vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: true,  isDeprecated: true  },
    { libraryName: 'analytics-swift',          libraryVersion: '1.5.3',     appName: 'ShopEasy-iOS', dependencyLevel: 'Direct',     source: 'Swift Package Manager', license: 'MIT', licenseIssue: false, vulnerabilityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, notMaintained: false, isDeprecated: false },
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
// Analysis
// ---------------------------------------------------------------------------

/**
 * Analyze all libraries for license compliance.
 * Returns per-app and portfolio-level compliance data.
 */
function analyzeCompliance(libs) {
  const perLib = [];
  const perApp = {};

  for (const lib of libs) {
    const licenseInfo = classifyLicense(lib.license);
    const conflicts = detectConflicts(lib, licenseInfo);

    const entry = {
      name: lib.libraryName,
      version: lib.libraryVersion,
      app: lib.appName,
      level: lib.dependencyLevel || 'Unknown',
      source: lib.source || 'Unknown',
      licenseDeclared: lib.license || '',
      licenseCategory: licenseInfo.category,
      licenseSpdx: licenseInfo.spdx,
      licenseRisk: licenseInfo.risk,
      oxLicenseIssue: !!lib.licenseIssue,
      conflicts,
      hasConflict: conflicts.length > 0,
      maxConflictSeverity: conflicts.length > 0
        ? conflicts.reduce((max, c) => {
            const order = { critical: 0, high: 1, medium: 2, low: 3 };
            return (order[c.severity] ?? 9) < (order[max] ?? 9) ? c.severity : max;
          }, 'low')
        : null,
    };

    perLib.push(entry);

    // Accumulate per-app
    if (!perApp[lib.appName]) {
      perApp[lib.appName] = {
        totalLibs: 0,
        categoryCounts: {},
        conflicts: [],
        riskScore: 0,
        grade: 'A',
        libsByCategory: {},
      };
    }
    const app = perApp[lib.appName];
    app.totalLibs++;
    app.categoryCounts[licenseInfo.category] = (app.categoryCounts[licenseInfo.category] || 0) + 1;
    if (!app.libsByCategory[licenseInfo.category]) app.libsByCategory[licenseInfo.category] = [];
    app.libsByCategory[licenseInfo.category].push(entry);
    if (conflicts.length > 0) {
      app.conflicts.push(...conflicts.map(c => ({ ...c, library: `${lib.libraryName}@${lib.libraryVersion}` })));
    }
  }

  // Compute per-app risk scores and grades
  for (const [appName, app] of Object.entries(perApp)) {
    let score = 0;
    // Strong copyleft = +30 each
    score += (app.categoryCounts['strong-copyleft'] || 0) * 30;
    // Weak copyleft = +10 each
    score += (app.categoryCounts['weak-copyleft'] || 0) * 10;
    // Unknown = +15 each (no license is risky)
    score += (app.categoryCounts['unknown'] || 0) * 15;
    // Proprietary = +20 each
    score += (app.categoryCounts['proprietary'] || 0) * 20;
    // Critical conflicts add extra
    const criticalConflicts = app.conflicts.filter(c => c.severity === 'critical').length;
    const highConflicts = app.conflicts.filter(c => c.severity === 'high').length;
    score += criticalConflicts * 15;
    score += highConflicts * 5;
    app.riskScore = Math.min(100, score);

    // Grade
    if (app.riskScore === 0) app.grade = 'A';
    else if (app.riskScore <= 10) app.grade = 'B';
    else if (app.riskScore <= 30) app.grade = 'C';
    else if (app.riskScore <= 60) app.grade = 'D';
    else app.grade = 'F';
  }

  // Portfolio summary
  const allCategories = {};
  for (const entry of perLib) {
    allCategories[entry.licenseCategory] = (allCategories[entry.licenseCategory] || 0) + 1;
  }
  const allConflicts = perLib.filter(l => l.hasConflict);
  const uniqueLicenses = [...new Set(perLib.map(l => l.licenseSpdx))].sort();

  return {
    perLib,
    perApp,
    portfolio: {
      totalLibraries: perLib.length,
      uniqueLicenses,
      categoryCounts: allCategories,
      totalConflicts: allConflicts.length,
      criticalConflicts: allConflicts.filter(l => l.maxConflictSeverity === 'critical').length,
      highConflicts: allConflicts.filter(l => l.maxConflictSeverity === 'high').length,
      mediumConflicts: allConflicts.filter(l => l.maxConflictSeverity === 'medium').length,
    },
  };
}

// ---------------------------------------------------------------------------
// Console output
// ---------------------------------------------------------------------------
function generateConsoleOutput(analysis) {
  const { perLib, perApp, portfolio } = analysis;
  const lines = [];

  lines.push('');
  lines.push('='.repeat(70));
  lines.push('  E13: License Compliance Check');
  lines.push('  Ox Security — SBOM License Analysis');
  lines.push('='.repeat(70));
  lines.push('');

  if (USE_MOCK) {
    lines.push('[Mock Mode — using realistic sample data]');
    lines.push('');
  }

  // Portfolio overview
  lines.push('Portfolio Overview');
  lines.push('-'.repeat(40));
  lines.push(`  Total libraries scanned: ${portfolio.totalLibraries}`);
  lines.push(`  Unique licenses found:   ${portfolio.uniqueLicenses.length}`);
  lines.push(`  Libraries with conflicts: ${portfolio.totalConflicts}`);
  lines.push('');

  // License distribution
  lines.push('  License categories:');
  const catOrder = ['permissive', 'public-domain', 'weak-copyleft', 'strong-copyleft', 'proprietary', 'unknown'];
  const catIcons = { permissive: '[OK]', 'public-domain': '[OK]', 'weak-copyleft': '[!!]', 'strong-copyleft': '[!!!]', proprietary: '[!!]', unknown: '[?]' };
  for (const cat of catOrder) {
    const count = portfolio.categoryCounts[cat] || 0;
    if (count > 0) {
      const pct = Math.round(count / portfolio.totalLibraries * 100);
      const bar = '\u2588'.repeat(Math.max(1, Math.round(pct / 3)));
      lines.push(`    ${catIcons[cat] || '   '} ${cat.padEnd(18)} ${bar} ${count} (${pct}%)`);
    }
  }
  lines.push('');

  // Conflict summary
  if (portfolio.totalConflicts > 0) {
    lines.push('Conflict Summary');
    lines.push('-'.repeat(40));
    if (portfolio.criticalConflicts > 0) lines.push(`  Critical: ${portfolio.criticalConflicts} — immediate action required`);
    if (portfolio.highConflicts > 0) lines.push(`  High:     ${portfolio.highConflicts} — replacement recommended`);
    if (portfolio.mediumConflicts > 0) lines.push(`  Medium:   ${portfolio.mediumConflicts} — review needed`);
    lines.push('');

    // List conflicting libraries
    const conflicting = perLib.filter(l => l.hasConflict).sort((a, b) => {
      const order = { critical: 0, high: 1, medium: 2, low: 3 };
      return (order[a.maxConflictSeverity] ?? 9) - (order[b.maxConflictSeverity] ?? 9);
    });
    const SEV_ICON = { critical: '[!!!]', high: '[!!]', medium: '[!]', low: '[.]' };
    for (const lib of conflicting) {
      lines.push(`  ${SEV_ICON[lib.maxConflictSeverity] || '   '} ${lib.name}@${lib.version} (${lib.app})`);
      lines.push(`       License: ${lib.licenseDeclared || 'MISSING'} → ${lib.licenseCategory}`);
      for (const c of lib.conflicts) {
        lines.push(`       - ${c.message}`);
      }
    }
    lines.push('');
  } else {
    lines.push('No license conflicts detected.');
    lines.push('');
  }

  // Per-app compliance grades
  lines.push('Per-App Compliance Grades');
  lines.push('-'.repeat(40));
  const GRADE_ICON = { A: '  ', B: '  ', C: ' !', D: '!!', F: '!!' };
  const sortedApps = Object.entries(perApp).sort((a, b) => b[1].riskScore - a[1].riskScore);
  for (const [appName, app] of sortedApps) {
    const conflictStr = app.conflicts.length > 0 ? ` — ${app.conflicts.length} conflict(s)` : '';
    lines.push(`  [${app.grade}] ${appName} (score: ${app.riskScore}/100, ${app.totalLibs} libs)${conflictStr}`);
    // Show category breakdown
    const cats = Object.entries(app.categoryCounts)
      .filter(([, count]) => count > 0)
      .map(([cat, count]) => `${cat}: ${count}`)
      .join(', ');
    lines.push(`      ${cats}`);
  }
  lines.push('');

  // Unique licenses
  lines.push('Licenses Found');
  lines.push('-'.repeat(40));
  lines.push(`  ${portfolio.uniqueLicenses.join(', ')}`);
  lines.push('');

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Markdown report
// ---------------------------------------------------------------------------
function generateMarkdownReport(analysis, timestamp) {
  const { perLib, perApp, portfolio } = analysis;
  const lines = [];

  lines.push('# E13: License Compliance Check');
  lines.push(`\n*Generated: ${timestamp}*`);
  if (USE_MOCK) lines.push('\n> **Mock Mode** — using realistic sample data (no OX_API_KEY configured)');
  lines.push('');

  // Overview
  lines.push('## Portfolio Overview');
  lines.push('');
  lines.push('| Metric | Value |');
  lines.push('|--------|-------|');
  lines.push(`| Total libraries scanned | ${portfolio.totalLibraries} |`);
  lines.push(`| Unique licenses | ${portfolio.uniqueLicenses.length} |`);
  lines.push(`| Libraries with conflicts | ${portfolio.totalConflicts} |`);
  lines.push(`| Critical conflicts | ${portfolio.criticalConflicts} |`);
  lines.push(`| High conflicts | ${portfolio.highConflicts} |`);
  lines.push(`| Medium conflicts | ${portfolio.mediumConflicts} |`);
  lines.push('');

  // License distribution
  lines.push('## License Distribution');
  lines.push('');
  lines.push('| Category | Count | % | Risk Level |');
  lines.push('|----------|-------|---|------------|');
  const catOrder = ['permissive', 'public-domain', 'weak-copyleft', 'strong-copyleft', 'proprietary', 'unknown'];
  const catRisk = { permissive: 'None', 'public-domain': 'None', 'weak-copyleft': 'Medium', 'strong-copyleft': 'High/Critical', proprietary: 'High', unknown: 'Medium' };
  for (const cat of catOrder) {
    const count = portfolio.categoryCounts[cat] || 0;
    if (count > 0) {
      const pct = Math.round(count / portfolio.totalLibraries * 100);
      lines.push(`| ${cat} | ${count} | ${pct}% | ${catRisk[cat]} |`);
    }
  }
  lines.push('');

  // Category explanations
  lines.push('### Category Definitions');
  lines.push('');
  lines.push('- **Permissive** (MIT, BSD, Apache, ISC) — Free to use in proprietary software with minimal requirements');
  lines.push('- **Public Domain** (CC0, Unlicense) — No restrictions at all');
  lines.push('- **Weak Copyleft** (LGPL, MPL, EPL) — File-level copyleft; requires review for iOS static linking');
  lines.push('- **Strong Copyleft** (GPL, AGPL, SSPL) — Viral copyleft; may require open-sourcing your app');
  lines.push('- **Proprietary** — Commercial license; requires license agreement');
  lines.push('- **Unknown** — No license declared; legally risky as default copyright applies');
  lines.push('');

  // Per-app compliance
  lines.push('## Per-App Compliance');
  lines.push('');
  lines.push('| App | Grade | Risk Score | Libraries | Conflicts |');
  lines.push('|-----|-------|------------|-----------|-----------|');
  const sortedApps = Object.entries(perApp).sort((a, b) => b[1].riskScore - a[1].riskScore);
  for (const [appName, app] of sortedApps) {
    lines.push(`| ${appName} | **${app.grade}** | ${app.riskScore}/100 | ${app.totalLibs} | ${app.conflicts.length} |`);
  }
  lines.push('');

  // Per-app detail
  for (const [appName, app] of sortedApps) {
    lines.push(`### ${appName} — Grade ${app.grade} (${app.riskScore}/100)`);
    lines.push('');

    // Category breakdown
    lines.push('**License breakdown:**');
    lines.push('');
    for (const cat of catOrder) {
      const count = app.categoryCounts[cat] || 0;
      if (count > 0) {
        const libNames = (app.libsByCategory[cat] || []).map(l => `${l.name}@${l.version}`).join(', ');
        lines.push(`- ${cat}: ${count} — ${libNames}`);
      }
    }
    lines.push('');

    // Conflicts
    if (app.conflicts.length > 0) {
      lines.push('**Conflicts:**');
      lines.push('');
      for (const c of app.conflicts) {
        lines.push(`- **[${c.severity.toUpperCase()}]** ${c.library}: ${c.message}`);
        if (c.detail) lines.push(`  > ${c.detail}`);
      }
      lines.push('');
    }
  }

  // Full library table
  lines.push('## Full License Inventory');
  lines.push('');
  lines.push('| Library | Version | App | License | Category | Risk | Conflicts | Ox Flag |');
  lines.push('|---------|---------|-----|---------|----------|------|-----------|---------|');
  // Sort: conflicts first, then by category risk
  const catSortOrder = { 'strong-copyleft': 0, proprietary: 1, unknown: 2, 'weak-copyleft': 3, 'public-domain': 4, permissive: 5 };
  const sortedLibs = [...perLib].sort((a, b) => {
    if (a.hasConflict !== b.hasConflict) return a.hasConflict ? -1 : 1;
    return (catSortOrder[a.licenseCategory] ?? 9) - (catSortOrder[b.licenseCategory] ?? 9);
  });
  for (const lib of sortedLibs) {
    const conflictMark = lib.hasConflict ? `**${lib.maxConflictSeverity}**` : '-';
    const oxFlag = lib.oxLicenseIssue ? 'Yes' : '-';
    lines.push(`| ${lib.name} | ${lib.version} | ${lib.app} | ${lib.licenseDeclared || '*missing*'} | ${lib.licenseCategory} | ${lib.licenseRisk} | ${conflictMark} | ${oxFlag} |`);
  }
  lines.push('');

  // iOS App Store notes
  lines.push('## iOS App Store Compliance Notes');
  lines.push('');
  lines.push('Apple\'s App Store distribution model creates unique license compliance considerations:');
  lines.push('');
  lines.push('1. **GPL Incompatibility** — The App Store\'s Terms of Service include DRM and usage restrictions');
  lines.push('   that conflict with the GPL\'s requirement to allow redistribution and modification. The FSF has');
  lines.push('   [explicitly stated](https://www.fsf.org/news/2010-05-app-store-compliance) this incompatibility.');
  lines.push('');
  lines.push('2. **LGPL Static Linking** — iOS apps commonly link dependencies statically. LGPL requires that');
  lines.push('   users can re-link with a modified version of the LGPL library. This typically requires shipping');
  lines.push('   object files or using dynamic frameworks.');
  lines.push('');
  lines.push('3. **AGPL Network Clause** — AGPL extends copyleft to network interaction. While less common in');
  lines.push('   mobile apps, any server-side component using AGPL requires source availability.');
  lines.push('');

  // Recommendations
  lines.push('## Recommendations');
  lines.push('');
  const recs = generateRecommendations(analysis);
  for (const rec of recs) {
    lines.push(`- **[${rec.priority}]** ${rec.text}`);
  }
  lines.push('');

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Recommendations
// ---------------------------------------------------------------------------
function generateRecommendations(analysis) {
  const { perLib, perApp, portfolio } = analysis;
  const recs = [];

  // Critical: strong copyleft
  const strongCopyleft = perLib.filter(l => l.licenseCategory === 'strong-copyleft');
  if (strongCopyleft.length > 0) {
    const names = [...new Set(strongCopyleft.map(l => `${l.name} (${l.licenseSpdx})`))].join(', ');
    recs.push({
      priority: 'Critical',
      text: `Replace strong-copyleft libraries: ${names}. These are likely incompatible with App Store distribution.`,
    });
  }

  // Critical: AGPL/SSPL
  const agplLibs = perLib.filter(l => l.licenseSpdx.includes('AGPL') || l.licenseSpdx.includes('SSPL'));
  if (agplLibs.length > 0) {
    const names = agplLibs.map(l => l.name).join(', ');
    recs.push({
      priority: 'Critical',
      text: `${names}: AGPL/SSPL licenses have the broadest copyleft scope. Immediate replacement required for App Store apps.`,
    });
  }

  // High: unknown/missing licenses
  const missingLicense = perLib.filter(l => l.licenseCategory === 'unknown' && l.licenseDeclared === '');
  if (missingLicense.length > 0) {
    const names = missingLicense.map(l => l.name).join(', ');
    recs.push({
      priority: 'High',
      text: `${missingLicense.length} libraries with no declared license (${names}). Contact maintainers or find alternatives with clear licensing.`,
    });
  }

  // Medium: weak copyleft
  const weakCopyleft = perLib.filter(l => l.licenseCategory === 'weak-copyleft');
  if (weakCopyleft.length > 0) {
    const names = [...new Set(weakCopyleft.map(l => `${l.name} (${l.licenseSpdx})`))].join(', ');
    recs.push({
      priority: 'Medium',
      text: `Review weak-copyleft libraries for static linking compliance: ${names}. Consider using dynamic frameworks or verify re-linking requirements are met.`,
    });
  }

  // Ox-flagged but we didn't catch
  const oxFlaggedOnly = perLib.filter(l => l.oxLicenseIssue && !l.hasConflict);
  if (oxFlaggedOnly.length > 0) {
    const names = oxFlaggedOnly.map(l => `${l.name}@${l.version}`).join(', ');
    recs.push({
      priority: 'Medium',
      text: `Ox Security flagged license issues on ${oxFlaggedOnly.length} libraries not caught by pattern matching (${names}). Manually review these licenses.`,
    });
  }

  // Apps with poor grades
  const poorApps = Object.entries(perApp).filter(([, app]) => app.grade === 'D' || app.grade === 'F');
  if (poorApps.length > 0) {
    for (const [appName, app] of poorApps) {
      recs.push({
        priority: 'High',
        text: `${appName} has compliance grade ${app.grade} (score ${app.riskScore}/100). Address ${app.conflicts.length} conflict(s) before App Store submission.`,
      });
    }
  }

  // General: license policy
  if (portfolio.totalConflicts > 0) {
    recs.push({
      priority: 'Medium',
      text: 'Establish an approved license allowlist in your CI pipeline. Block PRs that introduce strong-copyleft or unknown licenses.',
    });
  }

  return recs;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  const appFilter = process.env.OX_APP_NAME || process.argv[2] || '';
  const timestamp = new Date().toISOString();

  console.log('E13: License Compliance Check');
  console.log('Fetching SBOM data...');

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
  console.log('Analyzing license compliance...');
  const analysis = analyzeCompliance(allLibs);
  console.log(`  Unique licenses:   ${analysis.portfolio.uniqueLicenses.length}`);
  console.log(`  Conflicts found:   ${analysis.portfolio.totalConflicts}`);
  console.log('');

  // Console output
  const consoleOutput = generateConsoleOutput(analysis);
  console.log(consoleOutput);

  // Write results to experiments/
  const dateStr = timestamp.slice(0, 10);
  const outDir = resolve(process.cwd(), 'experiments', `license-check-${dateStr}`);
  mkdirSync(outDir, { recursive: true });

  // JSON export
  const jsonData = {
    timestamp,
    mockMode: USE_MOCK,
    filter: appFilter || null,
    portfolio: analysis.portfolio,
    perApp: Object.fromEntries(
      Object.entries(analysis.perApp).map(([name, app]) => [name, {
        grade: app.grade,
        riskScore: app.riskScore,
        totalLibs: app.totalLibs,
        categoryCounts: app.categoryCounts,
        conflictCount: app.conflicts.length,
        conflicts: app.conflicts,
      }])
    ),
    libraries: analysis.perLib,
  };
  writeFileSync(resolve(outDir, 'license-check.json'), JSON.stringify(jsonData, null, 2));

  // Markdown report
  const mdReport = generateMarkdownReport(analysis, timestamp);
  writeFileSync(resolve(outDir, 'license-check-report.md'), mdReport);

  console.log(`Results written to experiments/license-check-${dateStr}/`);
  console.log(`  - license-check.json       (machine-readable)`);
  console.log(`  - license-check-report.md  (human-readable)`);
}

main().catch(e => { console.error('Error:', e.message); process.exit(1); });
