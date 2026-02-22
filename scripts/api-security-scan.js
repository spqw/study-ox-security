#!/usr/bin/env node
/**
 * E09: API Security Scanner
 *
 * Uses getApiSecurityItems to map exposed API endpoints discovered across
 * iOS applications. Analyzes endpoints by severity, HTTP method, app, and
 * code location. Identifies high-risk patterns (unauthenticated routes,
 * sensitive data endpoints, deprecated API versions).
 *
 * Falls back to realistic mock data when OX_API_KEY is not configured.
 *
 * Usage:
 *   node scripts/api-security-scan.js [appFilter]
 *
 * Environment:
 *   OX_APP_NAME  — filter to a specific app name
 *   OX_LIMIT     — max items per API page (default: 500)
 */
import { writeFileSync, mkdirSync, readFileSync, existsSync } from 'fs';
import { resolve } from 'path';

const SEV_ICON = { Critical: '🔴', High: '🟠', Medium: '🟡', Low: '🔵', Info: '⚪' };
const METHOD_ICON = { GET: '🟢', POST: '🔵', PUT: '🟡', PATCH: '🟠', DELETE: '🔴', OPTIONS: '⚪', HEAD: '⚪' };

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
// Mock data — realistic iOS API endpoints for offline development
// ---------------------------------------------------------------------------
function getMockApiSecurityItems() {
  return {
    getApiSecurityItems: {
      total: 28,
      offset: 0,
      items: [
        // MyBankingApp-iOS — sensitive financial endpoints
        { id: 'api-001', method: 'POST', path: '/api/v2/auth/login', severity: 'Info',
          codeLocations: [{ filePath: 'Sources/Networking/AuthService.swift', lineNumber: 45 }],
          definitions: [{ source: 'OpenAPI', path: '/specs/auth-api.yaml' }],
          app: { id: 'app-1', name: 'MyBankingApp-iOS' } },
        { id: 'api-002', method: 'POST', path: '/api/v2/auth/refresh-token', severity: 'Low',
          codeLocations: [{ filePath: 'Sources/Networking/AuthService.swift', lineNumber: 78 }],
          definitions: [{ source: 'OpenAPI', path: '/specs/auth-api.yaml' }],
          app: { id: 'app-1', name: 'MyBankingApp-iOS' } },
        { id: 'api-003', method: 'GET', path: '/api/v2/accounts/{accountId}/balance', severity: 'High',
          codeLocations: [{ filePath: 'Sources/Networking/AccountAPI.swift', lineNumber: 32 }],
          definitions: [{ source: 'CodeAnalysis', path: null }],
          app: { id: 'app-1', name: 'MyBankingApp-iOS' } },
        { id: 'api-004', method: 'POST', path: '/api/v2/transfers/initiate', severity: 'Critical',
          codeLocations: [{ filePath: 'Sources/Networking/TransferAPI.swift', lineNumber: 55 }],
          definitions: [{ source: 'CodeAnalysis', path: null }],
          app: { id: 'app-1', name: 'MyBankingApp-iOS' } },
        { id: 'api-005', method: 'GET', path: '/api/v2/accounts/{accountId}/transactions', severity: 'High',
          codeLocations: [{ filePath: 'Sources/Networking/AccountAPI.swift', lineNumber: 67 }],
          definitions: [{ source: 'OpenAPI', path: '/specs/account-api.yaml' }],
          app: { id: 'app-1', name: 'MyBankingApp-iOS' } },
        { id: 'api-006', method: 'PUT', path: '/api/v2/profile/update', severity: 'Medium',
          codeLocations: [{ filePath: 'Sources/Networking/ProfileAPI.swift', lineNumber: 23 }],
          definitions: [{ source: 'CodeAnalysis', path: null }],
          app: { id: 'app-1', name: 'MyBankingApp-iOS' } },
        { id: 'api-007', method: 'GET', path: '/api/v1/user/settings', severity: 'Medium',
          codeLocations: [{ filePath: 'Sources/Networking/LegacyAPI.swift', lineNumber: 12 }],
          definitions: [{ source: 'CodeAnalysis', path: null }],
          app: { id: 'app-1', name: 'MyBankingApp-iOS' } },
        { id: 'api-008', method: 'POST', path: '/api/v2/payments/card/tokenize', severity: 'Critical',
          codeLocations: [{ filePath: 'Sources/Networking/PaymentAPI.swift', lineNumber: 89 }],
          definitions: [{ source: 'OpenAPI', path: '/specs/payment-api.yaml' }],
          app: { id: 'app-1', name: 'MyBankingApp-iOS' } },
        { id: 'api-009', method: 'DELETE', path: '/api/v2/accounts/{accountId}/beneficiaries/{id}', severity: 'Medium',
          codeLocations: [{ filePath: 'Sources/Networking/BeneficiaryAPI.swift', lineNumber: 41 }],
          definitions: [{ source: 'CodeAnalysis', path: null }],
          app: { id: 'app-1', name: 'MyBankingApp-iOS' } },
        { id: 'api-010', method: 'GET', path: '/api/v2/notifications', severity: 'Low',
          codeLocations: [{ filePath: 'Sources/Networking/NotificationAPI.swift', lineNumber: 15 }],
          definitions: [{ source: 'CodeAnalysis', path: null }],
          app: { id: 'app-1', name: 'MyBankingApp-iOS' } },

        // HealthTracker-iOS — health data endpoints (HIPAA-sensitive)
        { id: 'api-011', method: 'POST', path: '/api/v1/health/sync', severity: 'High',
          codeLocations: [{ filePath: 'HealthTracker/Network/HealthSyncService.swift', lineNumber: 34 }],
          definitions: [{ source: 'CodeAnalysis', path: null }],
          app: { id: 'app-2', name: 'HealthTracker-iOS' } },
        { id: 'api-012', method: 'GET', path: '/api/v1/health/records/{userId}', severity: 'Critical',
          codeLocations: [{ filePath: 'HealthTracker/Network/HealthRecordAPI.swift', lineNumber: 22 }],
          definitions: [{ source: 'OpenAPI', path: '/specs/health-api.yaml' }],
          app: { id: 'app-2', name: 'HealthTracker-iOS' } },
        { id: 'api-013', method: 'POST', path: '/api/v1/health/vitals', severity: 'High',
          codeLocations: [{ filePath: 'HealthTracker/Network/VitalsAPI.swift', lineNumber: 48 }],
          definitions: [{ source: 'CodeAnalysis', path: null }],
          app: { id: 'app-2', name: 'HealthTracker-iOS' } },
        { id: 'api-014', method: 'GET', path: '/api/v1/doctors/{doctorId}/schedule', severity: 'Low',
          codeLocations: [{ filePath: 'HealthTracker/Network/DoctorAPI.swift', lineNumber: 17 }],
          definitions: [{ source: 'CodeAnalysis', path: null }],
          app: { id: 'app-2', name: 'HealthTracker-iOS' } },
        { id: 'api-015', method: 'PUT', path: '/api/v1/health/medication/update', severity: 'Medium',
          codeLocations: [{ filePath: 'HealthTracker/Network/MedicationAPI.swift', lineNumber: 56 }],
          definitions: [{ source: 'OpenAPI', path: '/specs/health-api.yaml' }],
          app: { id: 'app-2', name: 'HealthTracker-iOS' } },
        { id: 'api-016', method: 'POST', path: '/api/v1/auth/biometric', severity: 'Medium',
          codeLocations: [{ filePath: 'HealthTracker/Network/AuthService.swift', lineNumber: 63 }],
          definitions: [{ source: 'CodeAnalysis', path: null }],
          app: { id: 'app-2', name: 'HealthTracker-iOS' } },
        { id: 'api-017', method: 'GET', path: '/api/v1/health/export/pdf', severity: 'High',
          codeLocations: [{ filePath: 'HealthTracker/Network/ExportAPI.swift', lineNumber: 29 }],
          definitions: [{ source: 'CodeAnalysis', path: null }],
          app: { id: 'app-2', name: 'HealthTracker-iOS' } },
        { id: 'api-018', method: 'DELETE', path: '/api/v1/health/records/{recordId}', severity: 'Medium',
          codeLocations: [{ filePath: 'HealthTracker/Network/HealthRecordAPI.swift', lineNumber: 78 }],
          definitions: [{ source: 'CodeAnalysis', path: null }],
          app: { id: 'app-2', name: 'HealthTracker-iOS' } },

        // ShopEasy-iOS — e-commerce endpoints
        { id: 'api-019', method: 'GET', path: '/api/v3/products', severity: 'Info',
          codeLocations: [{ filePath: 'src/api/ProductService.js', lineNumber: 18 }],
          definitions: [{ source: 'OpenAPI', path: '/specs/shop-api.yaml' }],
          app: { id: 'app-3', name: 'ShopEasy-iOS' } },
        { id: 'api-020', method: 'POST', path: '/api/v3/cart/checkout', severity: 'Critical',
          codeLocations: [{ filePath: 'src/api/CheckoutService.js', lineNumber: 45 }],
          definitions: [{ source: 'OpenAPI', path: '/specs/shop-api.yaml' }],
          app: { id: 'app-3', name: 'ShopEasy-iOS' } },
        { id: 'api-021', method: 'POST', path: '/api/v3/payments/process', severity: 'Critical',
          codeLocations: [{ filePath: 'src/api/PaymentService.js', lineNumber: 72 }],
          definitions: [{ source: 'CodeAnalysis', path: null }],
          app: { id: 'app-3', name: 'ShopEasy-iOS' } },
        { id: 'api-022', method: 'GET', path: '/api/v3/orders/{orderId}', severity: 'Medium',
          codeLocations: [{ filePath: 'src/api/OrderService.js', lineNumber: 33 }],
          definitions: [{ source: 'OpenAPI', path: '/specs/shop-api.yaml' }],
          app: { id: 'app-3', name: 'ShopEasy-iOS' } },
        { id: 'api-023', method: 'PUT', path: '/api/v3/user/address', severity: 'Low',
          codeLocations: [{ filePath: 'src/api/UserService.js', lineNumber: 89 }],
          definitions: [{ source: 'CodeAnalysis', path: null }],
          app: { id: 'app-3', name: 'ShopEasy-iOS' } },
        { id: 'api-024', method: 'GET', path: '/api/v2/search', severity: 'Info',
          codeLocations: [{ filePath: 'src/api/SearchService.js', lineNumber: 11 }],
          definitions: [{ source: 'CodeAnalysis', path: null }],
          app: { id: 'app-3', name: 'ShopEasy-iOS' } },
        { id: 'api-025', method: 'POST', path: '/api/v3/reviews', severity: 'Low',
          codeLocations: [{ filePath: 'src/api/ReviewService.js', lineNumber: 27 }],
          definitions: [{ source: 'CodeAnalysis', path: null }],
          app: { id: 'app-3', name: 'ShopEasy-iOS' } },
        { id: 'api-026', method: 'GET', path: '/api/v1/config', severity: 'Medium',
          codeLocations: [{ filePath: 'src/api/ConfigService.js', lineNumber: 5 }],
          definitions: [{ source: 'CodeAnalysis', path: null }],
          app: { id: 'app-3', name: 'ShopEasy-iOS' } },
        { id: 'api-027', method: 'POST', path: '/api/v3/user/register', severity: 'Medium',
          codeLocations: [{ filePath: 'src/api/AuthService.js', lineNumber: 38 }],
          definitions: [{ source: 'OpenAPI', path: '/specs/shop-api.yaml' }],
          app: { id: 'app-3', name: 'ShopEasy-iOS' } },
        { id: 'api-028', method: 'PATCH', path: '/api/v3/cart/items/{itemId}', severity: 'Low',
          codeLocations: [{ filePath: 'src/api/CartService.js', lineNumber: 61 }],
          definitions: [{ source: 'CodeAnalysis', path: null }],
          app: { id: 'app-3', name: 'ShopEasy-iOS' } },
      ],
    },
  };
}

function getMockFilters() {
  return {
    getApiSecurityFiltersLazy: {
      methods: [
        { name: 'GET', count: 12 }, { name: 'POST', count: 10 },
        { name: 'PUT', count: 3 }, { name: 'DELETE', count: 2 },
        { name: 'PATCH', count: 1 },
      ],
      severities: [
        { name: 'Critical', count: 5 }, { name: 'High', count: 5 },
        { name: 'Medium', count: 8 }, { name: 'Low', count: 6 },
        { name: 'Info', count: 4 },
      ],
      apps: [
        { name: 'MyBankingApp-iOS', count: 10 },
        { name: 'HealthTracker-iOS', count: 8 },
        { name: 'ShopEasy-iOS', count: 10 },
      ],
    },
  };
}

// ---------------------------------------------------------------------------
// Analysis helpers
// ---------------------------------------------------------------------------

/** Group items by a key function */
function groupBy(items, keyFn) {
  const groups = {};
  for (const item of items) {
    const key = keyFn(item);
    if (!groups[key]) groups[key] = [];
    groups[key].push(item);
  }
  return groups;
}

/** Count items by a key function, sorted descending */
function countBy(items, keyFn) {
  const counts = {};
  for (const item of items) {
    const key = keyFn(item);
    counts[key] = (counts[key] || 0) + 1;
  }
  return Object.entries(counts).sort((a, b) => b[1] - a[1]);
}

/** Severity weight for sorting (higher = more severe) */
function sevWeight(sev) {
  return { Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1 }[sev] || 0;
}

/** Detect risk patterns in an API endpoint */
function detectPatterns(item) {
  const patterns = [];
  const pathLower = item.path.toLowerCase();

  // Sensitive data patterns
  if (/\/(payment|pay|checkout|card|tokenize)/.test(pathLower))
    patterns.push({ tag: 'PAYMENT', risk: 'High', desc: 'Payment/financial data endpoint' });
  if (/\/(health|vital|medical|record)/.test(pathLower))
    patterns.push({ tag: 'HEALTH_DATA', risk: 'High', desc: 'Health/medical data endpoint (HIPAA-relevant)' });
  if (/\/(auth|login|register|token|biometric)/.test(pathLower))
    patterns.push({ tag: 'AUTH', risk: 'Medium', desc: 'Authentication/authorization endpoint' });
  if (/\/(user|profile|account)/.test(pathLower))
    patterns.push({ tag: 'PII', risk: 'Medium', desc: 'Contains personally identifiable information' });

  // Deprecated API version detection
  if (/\/api\/v1\//.test(pathLower))
    patterns.push({ tag: 'LEGACY_API', risk: 'Low', desc: 'Uses API v1 — possibly deprecated' });

  // Data exfiltration risks
  if (/\/(export|download|dump)/.test(pathLower))
    patterns.push({ tag: 'DATA_EXPORT', risk: 'High', desc: 'Data export endpoint — bulk data exfiltration risk' });

  // Destructive operations without obvious protection
  if (item.method === 'DELETE')
    patterns.push({ tag: 'DESTRUCTIVE', risk: 'Medium', desc: 'Destructive operation (DELETE)' });

  // Path with user-controlled IDs (IDOR risk)
  if (/\{(userId|accountId|recordId|orderId)\}/.test(item.path))
    patterns.push({ tag: 'IDOR_RISK', risk: 'Medium', desc: 'Path contains user-controlled resource ID (potential IDOR)' });

  // Config/settings exposure
  if (/\/(config|settings|admin)/.test(pathLower))
    patterns.push({ tag: 'CONFIG_EXPOSURE', risk: 'Medium', desc: 'Configuration/settings endpoint — may expose internal details' });

  return patterns;
}

/** Compute a risk score (0-100) for an endpoint based on severity + patterns */
function computeRiskScore(item, patterns) {
  let score = sevWeight(item.severity) * 12; // 12-60 from severity
  for (const p of patterns) {
    score += { High: 15, Medium: 8, Low: 3 }[p.risk] || 0;
  }
  // POST/PUT/DELETE are higher risk than GET
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(item.method)) score += 5;
  return Math.min(score, 100);
}

// ---------------------------------------------------------------------------
// Report generation
// ---------------------------------------------------------------------------

function generateMarkdown(items, filters, analysis, meta) {
  const lines = [];

  lines.push('# API Security Scan Report');
  lines.push(`Generated: ${meta.timestamp}`);
  if (meta.mockData) lines.push('**Note: Generated with mock data (no API key configured)**');
  lines.push(`App filter: ${meta.appFilter || 'all'}`);
  lines.push(`Total endpoints scanned: ${items.length}`);
  lines.push('');

  // Overview table
  lines.push('## Overview');
  lines.push('');
  lines.push('| Metric | Value |');
  lines.push('|--------|-------|');
  lines.push(`| Total API endpoints | ${items.length} |`);
  lines.push(`| Applications | ${analysis.appCount} |`);
  lines.push(`| Critical severity | ${analysis.bySeverity.Critical?.length || 0} |`);
  lines.push(`| High severity | ${analysis.bySeverity.High?.length || 0} |`);
  lines.push(`| Medium severity | ${analysis.bySeverity.Medium?.length || 0} |`);
  lines.push(`| Low severity | ${analysis.bySeverity.Low?.length || 0} |`);
  lines.push(`| Info | ${analysis.bySeverity.Info?.length || 0} |`);
  lines.push(`| Unique risk patterns detected | ${analysis.uniquePatternCount} |`);
  lines.push('');

  // Severity breakdown
  lines.push('## Severity Distribution');
  lines.push('');
  const maxBar = 30;
  const maxCount = Math.max(...Object.values(analysis.bySeverity).map(g => g.length), 1);
  for (const sev of ['Critical', 'High', 'Medium', 'Low', 'Info']) {
    const count = analysis.bySeverity[sev]?.length || 0;
    const bar = '█'.repeat(Math.round((count / maxCount) * maxBar));
    lines.push(`${SEV_ICON[sev] || ''} **${sev}**: ${bar} ${count}`);
  }
  lines.push('');

  // Method breakdown
  lines.push('## HTTP Method Distribution');
  lines.push('');
  lines.push('| Method | Count | Percentage |');
  lines.push('|--------|-------|------------|');
  for (const [method, count] of analysis.methodCounts) {
    const pct = ((count / items.length) * 100).toFixed(1);
    lines.push(`| ${METHOD_ICON[method] || ''} ${method} | ${count} | ${pct}% |`);
  }
  lines.push('');

  // Per-app breakdown
  lines.push('## Per-Application Summary');
  lines.push('');
  for (const [appName, appItems] of Object.entries(analysis.byApp)) {
    const appSevCounts = {};
    for (const item of appItems) {
      appSevCounts[item.severity] = (appSevCounts[item.severity] || 0) + 1;
    }
    const critHigh = (appSevCounts.Critical || 0) + (appSevCounts.High || 0);

    lines.push(`### ${appName} (${appItems.length} endpoints)`);
    lines.push('');
    lines.push(`| Severity | Count |`);
    lines.push(`|----------|-------|`);
    for (const sev of ['Critical', 'High', 'Medium', 'Low', 'Info']) {
      if (appSevCounts[sev]) lines.push(`| ${SEV_ICON[sev]} ${sev} | ${appSevCounts[sev]} |`);
    }
    if (critHigh > 0) {
      lines.push('');
      lines.push(`**Critical+High endpoints requiring attention: ${critHigh}**`);
    }
    lines.push('');

    // List endpoints for this app sorted by severity
    const sorted = [...appItems].sort((a, b) => sevWeight(b.severity) - sevWeight(a.severity));
    lines.push('| Method | Path | Severity | Source File |');
    lines.push('|--------|------|----------|-------------|');
    for (const item of sorted) {
      const loc = item.codeLocations?.[0];
      const file = loc ? `${loc.filePath}:${loc.lineNumber}` : 'N/A';
      lines.push(`| ${item.method} | \`${item.path}\` | ${SEV_ICON[item.severity]} ${item.severity} | ${file} |`);
    }
    lines.push('');
  }

  // High-risk endpoints (top N by risk score)
  lines.push('## High-Risk Endpoints (Top 10)');
  lines.push('');
  lines.push('Endpoints ranked by composite risk score (severity + pattern analysis):');
  lines.push('');
  const topRisk = analysis.scoredItems.slice(0, 10);
  for (let i = 0; i < topRisk.length; i++) {
    const { item, score, patterns } = topRisk[i];
    lines.push(`### ${i + 1}. ${item.method} \`${item.path}\` — Risk Score: ${score}/100`);
    lines.push(`- **App**: ${item.app?.name || 'N/A'}`);
    lines.push(`- **Severity**: ${SEV_ICON[item.severity]} ${item.severity}`);
    const loc = item.codeLocations?.[0];
    if (loc) lines.push(`- **Source**: ${loc.filePath}:${loc.lineNumber}`);
    const def = item.definitions?.[0];
    if (def) lines.push(`- **Discovered via**: ${def.source}${def.path ? ` (${def.path})` : ''}`);
    if (patterns.length) {
      lines.push('- **Risk patterns**:');
      for (const p of patterns) {
        lines.push(`  - \`${p.tag}\` (${p.risk}) — ${p.desc}`);
      }
    }
    lines.push('');
  }

  // Risk pattern summary
  lines.push('## Risk Pattern Analysis');
  lines.push('');
  lines.push('Patterns detected across all endpoints:');
  lines.push('');
  lines.push('| Pattern | Risk Level | Occurrences | Description |');
  lines.push('|---------|------------|-------------|-------------|');
  for (const [tag, info] of Object.entries(analysis.patternSummary)) {
    lines.push(`| \`${tag}\` | ${info.risk} | ${info.count} | ${info.desc} |`);
  }
  lines.push('');

  // API version analysis
  lines.push('## API Version Analysis');
  lines.push('');
  const versionCounts = countBy(items, item => {
    const match = item.path.match(/\/api\/(v\d+)\//);
    return match ? match[1] : 'unversioned';
  });
  lines.push('| Version | Count | Notes |');
  lines.push('|---------|-------|-------|');
  for (const [version, count] of versionCounts) {
    const note = version === 'v1' ? 'Potentially deprecated — review migration plan'
      : version === 'unversioned' ? 'No version prefix — consider versioning strategy'
      : '';
    lines.push(`| ${version} | ${count} | ${note} |`);
  }
  lines.push('');

  // Discovery source breakdown
  lines.push('## Discovery Source');
  lines.push('');
  const sourceCounts = countBy(items, item => item.definitions?.[0]?.source || 'Unknown');
  lines.push('| Source | Count | Percentage |');
  lines.push('|--------|-------|------------|');
  for (const [source, count] of sourceCounts) {
    const pct = ((count / items.length) * 100).toFixed(1);
    lines.push(`| ${source} | ${count} | ${pct}% |`);
  }
  lines.push('');

  // Recommendations
  lines.push('## Recommendations');
  lines.push('');
  const criticalEndpoints = analysis.bySeverity.Critical || [];
  const highEndpoints = analysis.bySeverity.High || [];
  const legacyEndpoints = items.filter(i => /\/api\/v1\//.test(i.path));
  const paymentEndpoints = analysis.scoredItems.filter(s => s.patterns.some(p => p.tag === 'PAYMENT'));
  const healthEndpoints = analysis.scoredItems.filter(s => s.patterns.some(p => p.tag === 'HEALTH_DATA'));
  const idorEndpoints = analysis.scoredItems.filter(s => s.patterns.some(p => p.tag === 'IDOR_RISK'));

  const recs = [];
  if (criticalEndpoints.length)
    recs.push(`1. **Immediate: Review ${criticalEndpoints.length} critical-severity endpoints** — These endpoints have the highest exposure risk and should be audited for proper authentication, authorization, input validation, and rate limiting.`);
  if (paymentEndpoints.length)
    recs.push(`${recs.length + 1}. **Payment endpoints (${paymentEndpoints.length})** — Ensure PCI DSS compliance: tokenization, no card data logging, TLS 1.2+, and certificate pinning from the mobile app.`);
  if (healthEndpoints.length)
    recs.push(`${recs.length + 1}. **Health data endpoints (${healthEndpoints.length})** — Review HIPAA compliance: encryption at rest and in transit, access logging, minimum necessary data principle.`);
  if (idorEndpoints.length)
    recs.push(`${recs.length + 1}. **IDOR-vulnerable paths (${idorEndpoints.length})** — Endpoints with user-controlled resource IDs need server-side authorization checks to prevent insecure direct object references.`);
  if (legacyEndpoints.length)
    recs.push(`${recs.length + 1}. **Deprecate legacy APIs (${legacyEndpoints.length} v1 endpoints)** — Create a migration timeline to move clients to the latest API version and sunset v1 endpoints.`);
  if (highEndpoints.length)
    recs.push(`${recs.length + 1}. **Triage ${highEndpoints.length} high-severity endpoints** — Review for missing authentication, excessive data exposure, and broken access control.`);

  if (recs.length === 0) recs.push('No critical findings — continue monitoring API surface area.');
  lines.push(recs.join('\n\n'));
  lines.push('');

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  const appFilter = process.env.OX_APP_NAME || process.argv[2] || '';
  const limit = parseInt(process.env.OX_LIMIT || '500', 10);

  console.log('Ox Security — API Security Scanner');
  console.log('='.repeat(50));
  if (USE_MOCK) {
    console.log('⚠  No API key found — running with mock data');
  }
  console.log(`App filter: ${appFilter || 'all'}`);
  console.log(`Limit: ${limit}`);
  console.log('');

  // Step 1: Fetch API security items
  console.log('Step 1: Fetching API security items...');
  let itemsData, filtersData;

  if (USE_MOCK) {
    itemsData = getMockApiSecurityItems();
    filtersData = getMockFilters();
  } else {
    const { GET_API_SECURITY_ITEMS, GET_API_SECURITY_FILTERS } = await import('../queries/api-security.js');
    const input = { getApiSecurityInput: { offset: 0, limit } };

    // Fetch items and filters in parallel
    const [itemsResult, filtersResult] = await Promise.all([
      queryFn(GET_API_SECURITY_ITEMS, input),
      queryFn(GET_API_SECURITY_FILTERS, input).catch(e => {
        console.log(`  Warning: Could not fetch filters: ${e.message}`);
        return null;
      }),
    ]);
    itemsData = itemsResult;
    filtersData = filtersResult;

    // Paginate if there are more items
    const total = itemsData.getApiSecurityItems.total;
    let fetched = itemsData.getApiSecurityItems.items.length;
    while (fetched < total) {
      console.log(`  Fetching page... (${fetched}/${total})`);
      const page = await queryFn(GET_API_SECURITY_ITEMS, {
        getApiSecurityInput: { offset: fetched, limit },
      });
      itemsData.getApiSecurityItems.items.push(...page.getApiSecurityItems.items);
      fetched += page.getApiSecurityItems.items.length;
      if (page.getApiSecurityItems.items.length === 0) break;
    }
  }

  let items = itemsData.getApiSecurityItems.items;
  const totalFromApi = itemsData.getApiSecurityItems.total;
  console.log(`  Total API endpoints from source: ${totalFromApi}`);
  console.log(`  Fetched: ${items.length}`);

  // Filter by app name
  if (appFilter) {
    items = items.filter(i => i.app?.name?.toLowerCase().includes(appFilter.toLowerCase()));
    console.log(`  After app filter ("${appFilter}"): ${items.length}`);
  }

  if (items.length === 0) {
    console.log('\nNo API endpoints match the filter criteria. Exiting.');
    return;
  }

  // Step 2: Analyze endpoints
  console.log('\nStep 2: Analyzing endpoints...');

  const bySeverity = groupBy(items, i => i.severity);
  const byApp = groupBy(items, i => i.app?.name || 'Unknown');
  const methodCounts = countBy(items, i => i.method);
  const appCount = Object.keys(byApp).length;

  // Risk scoring and pattern detection
  const scoredItems = items.map(item => {
    const patterns = detectPatterns(item);
    const score = computeRiskScore(item, patterns);
    return { item, score, patterns };
  }).sort((a, b) => b.score - a.score);

  // Aggregate pattern summary
  const patternSummary = {};
  for (const { patterns } of scoredItems) {
    for (const p of patterns) {
      if (!patternSummary[p.tag]) {
        patternSummary[p.tag] = { risk: p.risk, count: 0, desc: p.desc };
      }
      patternSummary[p.tag].count++;
    }
  }

  const uniquePatternCount = Object.keys(patternSummary).length;

  const analysis = {
    bySeverity, byApp, methodCounts, appCount,
    scoredItems, patternSummary, uniquePatternCount,
  };

  console.log(`  Apps: ${appCount}`);
  console.log(`  Severity: Critical=${bySeverity.Critical?.length || 0}, High=${bySeverity.High?.length || 0}, Medium=${bySeverity.Medium?.length || 0}, Low=${bySeverity.Low?.length || 0}, Info=${bySeverity.Info?.length || 0}`);
  console.log(`  Methods: ${methodCounts.map(([m, c]) => `${m}=${c}`).join(', ')}`);
  console.log(`  Risk patterns detected: ${uniquePatternCount}`);

  // Step 3: Generate outputs
  console.log('\nStep 3: Generating outputs...');
  const timestamp = new Date().toISOString();
  const outDir = `experiments/api-security-${timestamp.slice(0, 10)}`;
  mkdirSync(outDir, { recursive: true });

  // JSON output — full data + analysis
  const jsonOut = {
    meta: {
      timestamp,
      mockData: USE_MOCK,
      appFilter: appFilter || null,
      totalEndpoints: items.length,
      totalFromApi: totalFromApi,
    },
    filters: filtersData?.getApiSecurityFiltersLazy || null,
    summary: {
      appCount,
      severityCounts: Object.fromEntries(
        Object.entries(bySeverity).map(([k, v]) => [k, v.length])
      ),
      methodCounts: Object.fromEntries(methodCounts),
      uniquePatterns: uniquePatternCount,
    },
    riskRanking: scoredItems.map(({ item, score, patterns }) => ({
      id: item.id,
      method: item.method,
      path: item.path,
      severity: item.severity,
      app: item.app?.name,
      riskScore: score,
      patterns: patterns.map(p => p.tag),
      codeLocation: item.codeLocations?.[0] || null,
      discoverySource: item.definitions?.[0]?.source || null,
    })),
    endpoints: items,
  };
  const jsonPath = `${outDir}/api-security.json`;
  writeFileSync(jsonPath, JSON.stringify(jsonOut, null, 2));

  // Markdown report
  const meta = { timestamp, mockData: USE_MOCK, appFilter };
  const mdReport = generateMarkdown(items, filtersData, analysis, meta);
  const mdPath = `${outDir}/api-security-report.md`;
  writeFileSync(mdPath, mdReport);

  // Summary to stdout
  console.log('\n' + '='.repeat(50));
  console.log('API Security Scan Complete');
  console.log('='.repeat(50));
  console.log(`  Endpoints analyzed:    ${items.length}`);
  console.log(`  Applications:          ${appCount}`);
  console.log(`  Critical endpoints:    ${bySeverity.Critical?.length || 0}`);
  console.log(`  High endpoints:        ${bySeverity.High?.length || 0}`);
  console.log(`  Risk patterns found:   ${uniquePatternCount}`);
  console.log('');
  console.log(`  JSON: ${jsonPath}`);
  console.log(`  Report: ${mdPath}`);

  // Print top 5 riskiest endpoints
  console.log('\nTop 5 Riskiest Endpoints:');
  for (let i = 0; i < Math.min(5, scoredItems.length); i++) {
    const { item, score, patterns } = scoredItems[i];
    const tags = patterns.map(p => p.tag).join(', ') || 'none';
    console.log(`  ${i + 1}. ${SEV_ICON[item.severity]} ${item.method} ${item.path}`);
    console.log(`     App: ${item.app?.name} | Score: ${score}/100 | Patterns: ${tags}`);
  }

  // Print pattern summary
  if (Object.keys(patternSummary).length) {
    console.log('\nRisk Patterns Detected:');
    for (const [tag, info] of Object.entries(patternSummary)) {
      console.log(`  [${info.risk}] ${tag}: ${info.count} endpoint(s) — ${info.desc}`);
    }
  }
}

main().catch(e => { console.error(`\nFatal: ${e.message}`); process.exit(1); });
