#!/usr/bin/env node
/**
 * E20: Notification Script
 *
 * Generates webhook-compatible payloads for Slack and Microsoft Teams
 * when new critical/high issues appear. Can send to actual webhooks or
 * write payloads to files for testing/inspection.
 *
 * Modes:
 *   generate  — Build notification payloads and write to experiments/ (default)
 *   send      — Actually POST payloads to webhook URLs
 *   diff-notify — Compare against a saved snapshot, only notify on NEW issues
 *
 * Environment:
 *   OX_APP_NAME        — filter to matching app name
 *   OX_SEVERITY        — severities to notify on (default: "Critical,High")
 *   OX_LIMIT           — max issues to fetch (default: 200)
 *   OX_SLACK_WEBHOOK   — Slack incoming webhook URL (for send mode)
 *   OX_TEAMS_WEBHOOK   — Teams incoming webhook URL (for send mode)
 *   OX_FORMAT          — "slack", "teams", or "both" (default: "both")
 *   OX_SNAPSHOT        — path to previous snapshot for diff-notify mode
 *   OX_DRY_RUN         — set "true" to print payloads without sending (default: true)
 *
 * Usage:
 *   # Generate payloads (inspect before sending)
 *   node scripts/notify.js
 *
 *   # Generate only Slack payloads
 *   OX_FORMAT=slack node scripts/notify.js
 *
 *   # Send to Slack webhook
 *   OX_DRY_RUN=false OX_SLACK_WEBHOOK=https://hooks.slack.com/... node scripts/notify.js send
 *
 *   # Diff-notify: only alert on new issues since last snapshot
 *   OX_SNAPSHOT=experiments/snapshots/baseline.json node scripts/notify.js diff-notify
 *
 *   # Filter by app and severity
 *   OX_APP_NAME=MyBankingApp OX_SEVERITY=Critical node scripts/notify.js
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

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const MODE = process.argv[2] || 'generate';
const APP_FILTER = process.argv[3] || process.env.OX_APP_NAME || '';
const NOTIFY_SEVERITIES = (process.env.OX_SEVERITY || 'Critical,High')
  .split(',').map(s => s.trim()).filter(Boolean);
const LIMIT = parseInt(process.env.OX_LIMIT || '200', 10);
const FORMAT = process.env.OX_FORMAT || 'both';  // slack, teams, both
const DRY_RUN = process.env.OX_DRY_RUN !== 'false';
const SLACK_WEBHOOK = process.env.OX_SLACK_WEBHOOK || '';
const TEAMS_WEBHOOK = process.env.OX_TEAMS_WEBHOOK || '';
const SNAPSHOT_PATH = process.env.OX_SNAPSHOT || '';

const SEVERITY_EMOJI = { Critical: '🔴', High: '🟠', Medium: '🟡', Low: '🔵' };
const SEVERITY_COLOR = { Critical: '#dc2626', High: '#ea580c', Medium: '#eab308', Low: '#3b82f6' };
const SEVERITY_TEAMS = { Critical: 'attention', High: 'warning', Medium: 'accent', Low: 'good' };
const NOW = new Date().toISOString();

// ---------------------------------------------------------------------------
// API fetch
// ---------------------------------------------------------------------------
const GET_ISSUES = `query ($input: DashboardIssuesInput!) {
  getIssues(input: $input) {
    issues { issueId title severity originalSeverity appOxId category sourceType
      associatedApplication { appId name }
      autoFix { fixType } }
    total hasNext offset
  }
}`;

async function fetchIssues() {
  if (USE_MOCK) return getMockIssues();
  const all = [];
  let offset = 0;
  while (true) {
    const vars = {
      input: {
        severities: NOTIFY_SEVERITIES,
        limit: Math.min(LIMIT - all.length, 100),
        offset,
        ...(APP_FILTER ? { search: APP_FILTER } : {}),
      },
    };
    const data = await queryFn(GET_ISSUES, vars);
    const page = data.getIssues;
    all.push(...page.issues);
    if (!page.hasNext || all.length >= LIMIT) break;
    offset = page.offset;
  }
  return all;
}

// ---------------------------------------------------------------------------
// Snapshot diffing
// ---------------------------------------------------------------------------
function loadSnapshot(path) {
  if (!path || !existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, 'utf-8'));
  } catch { return null; }
}

function diffIssues(current, previous) {
  if (!previous) return { newIssues: current, resolvedIds: [], isFullScan: true };
  const prevIds = new Set(previous.map(i => i.issueId));
  const currIds = new Set(current.map(i => i.issueId));
  const newIssues = current.filter(i => !prevIds.has(i.issueId));
  const resolvedIds = [...prevIds].filter(id => !currIds.has(id));
  return { newIssues, resolvedIds, isFullScan: false };
}

// ---------------------------------------------------------------------------
// Slack payload builder (Block Kit)
// ---------------------------------------------------------------------------
function buildSlackPayload(issues, context) {
  const critCount = issues.filter(i => i.severity === 'Critical').length;
  const highCount = issues.filter(i => i.severity === 'High').length;

  const headerText = context.isDiff
    ? `🚨 ${issues.length} New Security Issue${issues.length !== 1 ? 's' : ''} Detected`
    : `🔍 Security Alert: ${issues.length} ${NOTIFY_SEVERITIES.join('/')} Issue${issues.length !== 1 ? 's' : ''}`;

  const blocks = [
    { type: 'header', text: { type: 'plain_text', text: headerText, emoji: true } },
    { type: 'section', text: { type: 'mrkdwn', text: [
      critCount > 0 ? `*🔴 Critical:* ${critCount}` : null,
      highCount > 0 ? `*🟠 High:* ${highCount}` : null,
      `*Apps affected:* ${context.appCount}`,
      `*Scan time:* ${NOW}`,
    ].filter(Boolean).join('\n') } },
    { type: 'divider' },
  ];

  // Top issues (max 10 to avoid payload bloat)
  const top = issues.slice(0, 10);
  for (const issue of top) {
    const emoji = SEVERITY_EMOJI[issue.severity] || '⚪';
    const app = issue.associatedApplication?.name || 'Unknown';
    const fix = issue.autoFix ? '✅ Auto-fix available' : '';
    blocks.push({
      type: 'section',
      text: { type: 'mrkdwn', text: `${emoji} *${issue.title}*\n_App:_ ${app} · _Source:_ ${issue.sourceType || 'N/A'} · _Category:_ ${issue.category || 'N/A'}${fix ? '\n' + fix : ''}` },
    });
  }

  if (issues.length > 10) {
    blocks.push({ type: 'section', text: { type: 'mrkdwn', text: `_...and ${issues.length - 10} more issues_` } });
  }

  // Per-app summary
  const appSummary = {};
  for (const i of issues) {
    const app = i.associatedApplication?.name || 'Unknown';
    if (!appSummary[app]) appSummary[app] = { Critical: 0, High: 0 };
    appSummary[app][i.severity] = (appSummary[app][i.severity] || 0) + 1;
  }
  blocks.push({ type: 'divider' });
  blocks.push({ type: 'section', text: { type: 'mrkdwn', text: '*Per-App Breakdown:*\n' +
    Object.entries(appSummary).map(([app, counts]) =>
      `• *${app}*: ${counts.Critical ? `🔴 ${counts.Critical} Critical` : ''}${counts.Critical && counts.High ? ', ' : ''}${counts.High ? `🟠 ${counts.High} High` : ''}`
    ).join('\n')
  } });

  // Resolved summary (if diff mode)
  if (context.isDiff && context.resolvedCount > 0) {
    blocks.push({ type: 'section', text: { type: 'mrkdwn', text: `✅ *${context.resolvedCount} issue${context.resolvedCount !== 1 ? 's' : ''} resolved* since last scan` } });
  }

  // Footer
  blocks.push({ type: 'context', elements: [
    { type: 'mrkdwn', text: `📊 Ox Security Scan · ${NOW}` },
  ] });

  return { blocks };
}

// ---------------------------------------------------------------------------
// MS Teams payload builder (Adaptive Card)
// ---------------------------------------------------------------------------
function buildTeamsPayload(issues, context) {
  const critCount = issues.filter(i => i.severity === 'Critical').length;
  const highCount = issues.filter(i => i.severity === 'High').length;

  const headerText = context.isDiff
    ? `🚨 ${issues.length} New Security Issues Detected`
    : `🔍 Security Alert: ${issues.length} ${NOTIFY_SEVERITIES.join('/')} Issues`;

  // Per-app summary
  const appSummary = {};
  for (const i of issues) {
    const app = i.associatedApplication?.name || 'Unknown';
    if (!appSummary[app]) appSummary[app] = { Critical: 0, High: 0 };
    appSummary[app][i.severity] = (appSummary[app][i.severity] || 0) + 1;
  }

  const factSet = [];
  if (critCount > 0) factSet.push({ title: '🔴 Critical', value: `${critCount}` });
  if (highCount > 0) factSet.push({ title: '🟠 High', value: `${highCount}` });
  factSet.push({ title: 'Apps Affected', value: `${context.appCount}` });
  factSet.push({ title: 'Scan Time', value: NOW });

  const body = [
    { type: 'TextBlock', text: headerText, weight: 'bolder', size: 'large', wrap: true,
      color: critCount > 0 ? 'attention' : 'warning' },
    { type: 'FactSet', facts: factSet },
    { type: 'TextBlock', text: '---', separator: true },
    { type: 'TextBlock', text: 'Top Issues', weight: 'bolder', size: 'medium' },
  ];

  // Top issues (max 8 for Teams card size limits)
  const top = issues.slice(0, 8);
  for (const issue of top) {
    const emoji = SEVERITY_EMOJI[issue.severity] || '⚪';
    const app = issue.associatedApplication?.name || 'Unknown';
    const fix = issue.autoFix ? ' ✅' : '';
    body.push({
      type: 'TextBlock', wrap: true,
      text: `${emoji} **${issue.title}**${fix}\n_${app}_ · ${issue.sourceType || 'N/A'} · ${issue.category || 'N/A'}`,
    });
  }

  if (issues.length > 8) {
    body.push({ type: 'TextBlock', text: `_...and ${issues.length - 8} more issues_`, isSubtle: true });
  }

  // Per-app breakdown
  body.push({ type: 'TextBlock', text: '---', separator: true });
  body.push({ type: 'TextBlock', text: 'Per-App Breakdown', weight: 'bolder', size: 'medium' });
  for (const [app, counts] of Object.entries(appSummary)) {
    const parts = [];
    if (counts.Critical) parts.push(`🔴 ${counts.Critical} Critical`);
    if (counts.High) parts.push(`🟠 ${counts.High} High`);
    body.push({ type: 'TextBlock', text: `**${app}**: ${parts.join(', ')}`, wrap: true });
  }

  if (context.isDiff && context.resolvedCount > 0) {
    body.push({ type: 'TextBlock', text: `✅ **${context.resolvedCount} issues resolved** since last scan`,
      color: 'good', wrap: true });
  }

  // Adaptive Card envelope
  return {
    type: 'message',
    attachments: [{
      contentType: 'application/vnd.microsoft.card.adaptive',
      content: {
        $schema: 'http://adaptivecards.io/schemas/adaptive-card.json',
        type: 'AdaptiveCard',
        version: '1.4',
        body,
        actions: [
          { type: 'Action.OpenUrl', title: 'Open Ox Security Dashboard', url: 'https://app.ox.security' },
        ],
      },
    }],
  };
}

// ---------------------------------------------------------------------------
// Webhook sender
// ---------------------------------------------------------------------------
async function sendWebhook(url, payload, platform) {
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const text = await res.text();
      console.error(`[${platform}] Webhook failed (${res.status}): ${text}`);
      return false;
    }
    console.error(`[${platform}] ✅ Notification sent successfully`);
    return true;
  } catch (err) {
    console.error(`[${platform}] Webhook error: ${err.message}`);
    return false;
  }
}

// ---------------------------------------------------------------------------
// Mock data
// ---------------------------------------------------------------------------
function getMockIssues() {
  return [
    { issueId: 'ISS-001', title: 'Remote Code Execution in libxml2 < 2.12.0', severity: 'Critical',
      originalSeverity: 'Critical', category: 'Vulnerability', sourceType: 'SCA',
      associatedApplication: { appId: 'app1', name: 'MyBankingApp' },
      autoFix: { fixType: 'VersionBump' } },
    { issueId: 'ISS-002', title: 'Prototype Pollution in lodash < 4.17.21', severity: 'Critical',
      originalSeverity: 'High', category: 'Vulnerability', sourceType: 'SCA',
      associatedApplication: { appId: 'app1', name: 'MyBankingApp' },
      autoFix: { fixType: 'VersionBump' } },
    { issueId: 'ISS-003', title: 'Missing Certificate Pinning in Network Layer', severity: 'High',
      originalSeverity: 'High', category: 'Mobile Security', sourceType: 'SAST',
      associatedApplication: { appId: 'app1', name: 'MyBankingApp' },
      autoFix: null },
    { issueId: 'ISS-004', title: 'Insecure Keychain Access Configuration', severity: 'High',
      originalSeverity: 'Medium', category: 'Mobile Security', sourceType: 'SAST',
      associatedApplication: { appId: 'app2', name: 'HealthTracker' },
      autoFix: null },
    { issueId: 'ISS-005', title: 'SQL Injection via unsanitized Core Data predicate', severity: 'Critical',
      originalSeverity: 'Critical', category: 'OWASP', sourceType: 'SAST',
      associatedApplication: { appId: 'app2', name: 'HealthTracker' },
      autoFix: null },
    { issueId: 'ISS-006', title: 'OpenSSL 1.1.1 End-of-Life — Multiple CVEs', severity: 'High',
      originalSeverity: 'High', category: 'Vulnerability', sourceType: 'SCA',
      associatedApplication: { appId: 'app3', name: 'ShopEasy' },
      autoFix: { fixType: 'VersionBump' } },
    { issueId: 'ISS-007', title: 'Hardcoded API Key in AppDelegate.swift', severity: 'High',
      originalSeverity: 'High', category: 'Secret Detection', sourceType: 'SecretDetection',
      associatedApplication: { appId: 'app3', name: 'ShopEasy' },
      autoFix: null },
    { issueId: 'ISS-008', title: 'React Native Hermes Engine RCE (CVE-2024-1234)', severity: 'Critical',
      originalSeverity: 'Critical', category: 'Vulnerability', sourceType: 'SCA',
      associatedApplication: { appId: 'app3', name: 'ShopEasy' },
      autoFix: { fixType: 'VersionBump' } },
  ];
}

function getMockPreviousSnapshot() {
  // Simulates a previous scan — ISS-001 to ISS-006 existed, ISS-009/ISS-010 existed but now resolved
  return [
    { issueId: 'ISS-001', title: 'Remote Code Execution in libxml2 < 2.12.0', severity: 'Critical',
      associatedApplication: { appId: 'app1', name: 'MyBankingApp' } },
    { issueId: 'ISS-002', title: 'Prototype Pollution in lodash < 4.17.21', severity: 'Critical',
      associatedApplication: { appId: 'app1', name: 'MyBankingApp' } },
    { issueId: 'ISS-003', title: 'Missing Certificate Pinning in Network Layer', severity: 'High',
      associatedApplication: { appId: 'app1', name: 'MyBankingApp' } },
    { issueId: 'ISS-004', title: 'Insecure Keychain Access Configuration', severity: 'High',
      associatedApplication: { appId: 'app2', name: 'HealthTracker' } },
    { issueId: 'ISS-005', title: 'SQL Injection via unsanitized Core Data predicate', severity: 'Critical',
      associatedApplication: { appId: 'app2', name: 'HealthTracker' } },
    { issueId: 'ISS-006', title: 'OpenSSL 1.1.1 End-of-Life — Multiple CVEs', severity: 'High',
      associatedApplication: { appId: 'app3', name: 'ShopEasy' } },
    { issueId: 'ISS-009', title: 'Weak TLS 1.0 Configuration', severity: 'High',
      associatedApplication: { appId: 'app1', name: 'MyBankingApp' } },
    { issueId: 'ISS-010', title: 'Insecure NSUserDefaults storage of auth token', severity: 'High',
      associatedApplication: { appId: 'app2', name: 'HealthTracker' } },
  ];
}

// ---------------------------------------------------------------------------
// Report generator
// ---------------------------------------------------------------------------
function generateReport(issues, slackPayload, teamsPayload, context) {
  const critCount = issues.filter(i => i.severity === 'Critical').length;
  const highCount = issues.filter(i => i.severity === 'High').length;

  const appSummary = {};
  for (const i of issues) {
    const app = i.associatedApplication?.name || 'Unknown';
    if (!appSummary[app]) appSummary[app] = { Critical: 0, High: 0, total: 0, autoFix: 0 };
    appSummary[app][i.severity] = (appSummary[app][i.severity] || 0) + 1;
    appSummary[app].total++;
    if (i.autoFix) appSummary[app].autoFix++;
  }

  let md = `# Notification Payloads — Security Alert\n\n`;
  md += `> Generated: ${NOW}\n`;
  md += `> Mode: ${context.isDiff ? 'diff-notify (new issues only)' : 'full scan'}\n`;
  md += `> Data source: ${USE_MOCK ? 'Mock data' : 'Ox Security API'}\n\n`;

  md += `## Summary\n\n`;
  md += `| Metric | Count |\n|--------|-------|\n`;
  md += `| Total alertable issues | ${issues.length} |\n`;
  md += `| 🔴 Critical | ${critCount} |\n`;
  md += `| 🟠 High | ${highCount} |\n`;
  md += `| Apps affected | ${context.appCount} |\n`;
  md += `| Auto-fixable | ${issues.filter(i => i.autoFix).length} |\n`;
  if (context.isDiff) {
    md += `| Resolved since last scan | ${context.resolvedCount} |\n`;
  }

  md += `\n## Per-App Breakdown\n\n`;
  md += `| App | Critical | High | Total | Auto-Fix |\n|-----|----------|------|-------|----------|\n`;
  for (const [app, c] of Object.entries(appSummary)) {
    md += `| ${app} | ${c.Critical || 0} | ${c.High || 0} | ${c.total} | ${c.autoFix} |\n`;
  }

  md += `\n## Issue List\n\n`;
  md += `| # | Severity | Title | App | Source | Auto-Fix |\n|---|----------|-------|-----|--------|----------|\n`;
  issues.forEach((i, idx) => {
    const emoji = SEVERITY_EMOJI[i.severity] || '';
    const app = i.associatedApplication?.name || 'Unknown';
    const fix = i.autoFix ? '✅' : '—';
    md += `| ${idx + 1} | ${emoji} ${i.severity} | ${i.title} | ${app} | ${i.sourceType} | ${fix} |\n`;
  });

  if (context.isDiff && context.resolvedCount > 0) {
    md += `\n## Resolved Issues\n\n`;
    md += `${context.resolvedCount} issue(s) from the previous scan are no longer present.\n`;
    if (context.resolvedIds?.length) {
      md += `IDs: ${context.resolvedIds.join(', ')}\n`;
    }
  }

  md += `\n## Slack Payload\n\n`;
  md += '```json\n' + JSON.stringify(slackPayload, null, 2) + '\n```\n';

  md += `\n## Teams Payload (Adaptive Card)\n\n`;
  md += '```json\n' + JSON.stringify(teamsPayload, null, 2) + '\n```\n';

  md += `\n## Integration Guide\n\n`;
  md += `### Slack Setup\n\n`;
  md += `1. Create a Slack app at https://api.slack.com/apps\n`;
  md += `2. Enable Incoming Webhooks and create one for your channel\n`;
  md += `3. Run:\n`;
  md += '```bash\n';
  md += `OX_DRY_RUN=false OX_SLACK_WEBHOOK=https://hooks.slack.com/services/T.../B.../xxx \\\n`;
  md += `  node scripts/notify.js send\n`;
  md += '```\n\n';

  md += `### Microsoft Teams Setup\n\n`;
  md += `1. In Teams, go to channel > Connectors > Incoming Webhook\n`;
  md += `2. Configure the webhook and copy the URL\n`;
  md += `3. Run:\n`;
  md += '```bash\n';
  md += `OX_DRY_RUN=false OX_TEAMS_WEBHOOK=https://outlook.office.com/webhook/... \\\n`;
  md += `  node scripts/notify.js send\n`;
  md += '```\n\n';

  md += `### CI/CD Integration (GitHub Actions)\n\n`;
  md += '```yaml\n';
  md += `- name: Notify on new critical issues\n`;
  md += `  run: node scripts/notify.js send\n`;
  md += `  env:\n`;
  md += `    OX_API_KEY: \${{ secrets.OX_API_KEY }}\n`;
  md += `    OX_SLACK_WEBHOOK: \${{ secrets.SLACK_WEBHOOK }}\n`;
  md += `    OX_SEVERITY: Critical\n`;
  md += `    OX_DRY_RUN: "false"\n`;
  md += '```\n\n';

  md += `### Diff-Notify Mode (Alert on Changes Only)\n\n`;
  md += '```bash\n';
  md += `# Save a baseline snapshot\n`;
  md += `node scripts/notify.js generate\n`;
  md += `# Later, compare against it\n`;
  md += `OX_SNAPSHOT=experiments/notify-YYYY-MM-DD/snapshot.json node scripts/notify.js diff-notify\n`;
  md += '```\n';

  return md;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  console.error(`\n🔔  E20: Notification Script`);
  console.error(`Mode: ${MODE} | Severities: ${NOTIFY_SEVERITIES.join(', ')} | Format: ${FORMAT}`);
  console.error(`Data source: ${USE_MOCK ? 'Mock data' : 'Ox Security API'}`);
  if (DRY_RUN && MODE === 'send') console.error(`⚠️  DRY_RUN=true — payloads will NOT be sent`);
  console.error('');

  // 1. Fetch current issues
  const issues = await fetchIssues();
  console.error(`Fetched ${issues.length} ${NOTIFY_SEVERITIES.join('/')} issues`);

  // 2. If diff-notify, compare against snapshot
  let diff = { newIssues: issues, resolvedIds: [], isFullScan: true };
  if (MODE === 'diff-notify') {
    const prev = SNAPSHOT_PATH ? loadSnapshot(SNAPSHOT_PATH) : (USE_MOCK ? getMockPreviousSnapshot() : null);
    if (prev) {
      diff = diffIssues(issues, prev);
      console.error(`Diff: ${diff.newIssues.length} new, ${diff.resolvedIds.length} resolved`);
    } else {
      console.error(`No previous snapshot found — treating all issues as new`);
    }
  }

  const alertIssues = MODE === 'diff-notify' ? diff.newIssues : issues;

  if (alertIssues.length === 0) {
    console.error(`\n✅ No issues to notify about. All clear!`);
    return;
  }

  // 3. Compute context
  const apps = new Set(alertIssues.map(i => i.associatedApplication?.name).filter(Boolean));
  const context = {
    appCount: apps.size,
    isDiff: MODE === 'diff-notify' && !diff.isFullScan,
    resolvedCount: diff.resolvedIds.length,
    resolvedIds: diff.resolvedIds,
  };

  // 4. Build payloads
  const slackPayload = buildSlackPayload(alertIssues, context);
  const teamsPayload = buildTeamsPayload(alertIssues, context);

  // 5. Print summaries
  const critCount = alertIssues.filter(i => i.severity === 'Critical').length;
  const highCount = alertIssues.filter(i => i.severity === 'High').length;

  console.error(`\n${'═'.repeat(60)}`);
  console.error(`  NOTIFICATION SUMMARY`);
  console.error(`${'═'.repeat(60)}`);
  console.error(`  Issues to alert:  ${alertIssues.length}`);
  console.error(`  🔴 Critical:      ${critCount}`);
  console.error(`  🟠 High:          ${highCount}`);
  console.error(`  Apps affected:    ${apps.size} (${[...apps].join(', ')})`);
  if (context.isDiff) {
    console.error(`  Resolved:         ${context.resolvedCount}`);
  }
  console.error(`${'═'.repeat(60)}\n`);

  // 6. Send or save
  if (MODE === 'send' && !DRY_RUN) {
    if ((FORMAT === 'slack' || FORMAT === 'both') && SLACK_WEBHOOK) {
      await sendWebhook(SLACK_WEBHOOK, slackPayload, 'Slack');
    }
    if ((FORMAT === 'teams' || FORMAT === 'both') && TEAMS_WEBHOOK) {
      await sendWebhook(TEAMS_WEBHOOK, teamsPayload, 'Teams');
    }
    if (!SLACK_WEBHOOK && !TEAMS_WEBHOOK) {
      console.error('⚠️  No webhook URLs configured. Set OX_SLACK_WEBHOOK and/or OX_TEAMS_WEBHOOK.');
    }
  }

  // 7. Write experiment output
  const dateStr = NOW.split('T')[0];
  const dir = resolve(process.cwd(), `experiments/notify-${dateStr}`);
  mkdirSync(dir, { recursive: true });

  // Snapshot for future diffs
  writeFileSync(resolve(dir, 'snapshot.json'), JSON.stringify(issues, null, 2));

  // Payloads
  if (FORMAT === 'slack' || FORMAT === 'both') {
    writeFileSync(resolve(dir, 'slack-payload.json'), JSON.stringify(slackPayload, null, 2));
  }
  if (FORMAT === 'teams' || FORMAT === 'both') {
    writeFileSync(resolve(dir, 'teams-payload.json'), JSON.stringify(teamsPayload, null, 2));
  }

  // Full output
  writeFileSync(resolve(dir, 'output.json'), JSON.stringify({
    timestamp: NOW,
    mode: MODE,
    format: FORMAT,
    severities: NOTIFY_SEVERITIES,
    isDiff: context.isDiff,
    issueCount: alertIssues.length,
    resolvedCount: context.resolvedCount,
    appsAffected: [...apps],
    issues: alertIssues,
    slackPayload,
    teamsPayload,
  }, null, 2));

  // Report
  const report = generateReport(alertIssues, slackPayload, teamsPayload, context);
  writeFileSync(resolve(dir, 'report.md'), report);

  console.error(`📁 Output written to ${dir}/`);
  console.error(`   • snapshot.json    — current scan state (use as OX_SNAPSHOT for future diffs)`);
  if (FORMAT === 'slack' || FORMAT === 'both') console.error(`   • slack-payload.json  — ready-to-send Slack Block Kit payload`);
  if (FORMAT === 'teams' || FORMAT === 'both') console.error(`   • teams-payload.json  — ready-to-send Teams Adaptive Card payload`);
  console.error(`   • output.json      — full analysis data`);
  console.error(`   • report.md        — detailed markdown report with integration guide`);

  // In diff-notify mode, also output just the new issues for piping
  if (MODE === 'diff-notify' && diff.newIssues.length > 0) {
    console.error(`\n📋 New issues since last scan:`);
    for (const i of diff.newIssues) {
      const emoji = SEVERITY_EMOJI[i.severity] || '';
      console.error(`   ${emoji} ${i.title} (${i.associatedApplication?.name || 'Unknown'})`);
    }
  }
}

main().catch(err => {
  console.error(`\n❌ Error: ${err.message}`);
  process.exit(2);
});
