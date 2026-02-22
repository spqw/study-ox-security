#!/usr/bin/env node
/**
 * List security issues/vulnerabilities, filterable by severity and app
 */
import { query } from '../lib/ox-client.js';
import { GET_ISSUES, GET_SINGLE_ISSUE } from '../queries/issues.js';

async function main() {
  const severity = process.argv[2] || 'all'; // critical, high, medium, low, all
  const appFilter = process.env.OX_APP_NAME || process.argv[3];
  const limit = parseInt(process.env.OX_LIMIT || '50', 10);

  console.log('Ox Security — Issues / Vulnerabilities');
  console.log('='.repeat(50));
  console.log(`Filter: severity=${severity}, app=${appFilter || 'all'}, limit=${limit}\n`);

  const filters = {};
  if (severity !== 'all') {
    filters.criticality = [severity.charAt(0).toUpperCase() + severity.slice(1)];
  }

  const data = await query(GET_ISSUES, {
    isDemo: false,
    getIssuesInput: {
      offset: 0,
      limit,
      filters,
      sort: { fields: ['Severity'], order: ['DESC'] },
    },
  });

  const issues = data.getIssues;
  console.log(`Total issues: ${issues.totalIssues}`);
  console.log(`Filtered: ${issues.totalFilteredIssues}`);
  console.log(`Resolved: ${issues.totalResolvedIssues}`);
  console.log('');

  let shown = issues.issues;
  if (appFilter) {
    shown = shown.filter(i => i.app?.name?.toLowerCase().includes(appFilter.toLowerCase()));
  }

  for (const issue of shown) {
    const sevIcon = { Critical: '🔴', High: '🟠', Medium: '🟡', Low: '🔵', Info: '⚪' };
    const icon = sevIcon[issue.severity] || '❓';
    console.log(`${icon} [${issue.severity}] ${issue.mainTitle}`);
    if (issue.secondTitle) console.log(`   ${issue.secondTitle}`);
    if (issue.app) console.log(`   App: ${issue.app.name} (${issue.app.type})`);
    if (issue.category) console.log(`   Category: ${issue.category.name}`);
    if (issue.sourceType) console.log(`   Source: ${issue.sourceType}`);
    console.log(`   Created: ${issue.created}`);
    console.log('');
  }

  // Show detail for first critical issue if present
  const firstCritical = shown.find(i => i.severity === 'Critical');
  if (firstCritical) {
    console.log('--- Detail: First Critical Issue ---');
    try {
      const detail = await query(GET_SINGLE_ISSUE, {
        getSingleIssueInput: { issueId: firstCritical.issueId },
      });
      const info = detail.getSingleIssueInfo;
      if (info.scaVulnerabilities?.length) {
        console.log('  CVEs:');
        for (const v of info.scaVulnerabilities) {
          console.log(`    ${v.cve} (${v.originalSeverity}) — fix: ${v.minorVerWithFix || v.majorVerWithFix || 'N/A'}`);
        }
      }
      if (info.autoFix) {
        console.log(`  Auto-fix: ${info.autoFix.fixTitle} — ${info.autoFix.fixDescription}`);
      }
    } catch (e) {
      console.error('Could not fetch issue detail:', e.message);
    }
  }
}

main().catch(e => { console.error(e.message); process.exit(1); });
