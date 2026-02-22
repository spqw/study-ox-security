#!/usr/bin/env node
/**
 * Generate a markdown vulnerability report focused on iOS apps
 */
import { writeFileSync } from 'fs';
import { query } from '../lib/ox-client.js';
import { GET_APPLICATIONS, GET_SINGLE_APP } from '../queries/applications.js';
import { GET_ISSUES, GET_SINGLE_ISSUE } from '../queries/issues.js';
import { GET_SBOM_LIBRARIES } from '../queries/sbom.js';

async function main() {
  const appFilter = process.env.OX_APP_NAME || process.argv[2] || '';

  console.log('Ox Security — iOS Vulnerability Report Generator');
  console.log('='.repeat(50));

  // Fetch apps
  const appsData = await query(GET_APPLICATIONS, {
    getApplicationsInput: { offset: 0, limit: 500 },
  });
  let apps = appsData.getApplications.applications;

  // Filter for iOS/mobile if specified
  if (appFilter) {
    apps = apps.filter(a => a.appName.toLowerCase().includes(appFilter.toLowerCase()));
  }

  console.log(`Found ${apps.length} matching applications`);

  // Fetch issues for these apps
  const issuesData = await query(GET_ISSUES, {
    isDemo: false,
    getIssuesInput: {
      offset: 0,
      limit: 500,
      sort: { fields: ['Severity'], order: ['DESC'] },
    },
  });

  let issues = issuesData.getIssues.issues;
  if (appFilter) {
    issues = issues.filter(i => i.app?.name?.toLowerCase().includes(appFilter.toLowerCase()));
  }

  // Build report
  const report = [];
  report.push(`# iOS App Vulnerability Report`);
  report.push(`Generated: ${new Date().toISOString()}`);
  report.push(`Filter: ${appFilter || 'all apps'}`);
  report.push('');

  // Executive summary
  report.push('## Executive Summary');
  const sevCounts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  for (const i of issues) sevCounts[i.severity] = (sevCounts[i.severity] || 0) + 1;
  report.push(`| Severity | Count |`);
  report.push(`|----------|-------|`);
  for (const [sev, count] of Object.entries(sevCounts)) {
    report.push(`| ${sev} | ${count} |`);
  }
  report.push('');

  // Per-app breakdown
  report.push('## Application Breakdown');
  for (const app of apps) {
    const s = app.issuesBySeverity || {};
    report.push(`### ${app.appName}`);
    report.push(`- Type: ${app.type}`);
    report.push(`- Risk Score: ${app.risk}`);
    report.push(`- Critical: ${s.critical || 0}, High: ${s.high || 0}, Medium: ${s.medium || 0}, Low: ${s.low || 0}`);
    report.push('');
  }

  // Detailed issues
  report.push('## Critical & High Issues');
  const critHigh = issues.filter(i => i.severity === 'Critical' || i.severity === 'High');
  for (const issue of critHigh.slice(0, 30)) {
    report.push(`### [${issue.severity}] ${issue.mainTitle}`);
    if (issue.secondTitle) report.push(`> ${issue.secondTitle}`);
    report.push(`- App: ${issue.app?.name || 'N/A'}`);
    report.push(`- Category: ${issue.category?.name || 'N/A'}`);
    report.push(`- Source: ${issue.sourceType || 'N/A'}`);
    report.push(`- Created: ${issue.created}`);

    // Try to get fix details for critical issues
    if (issue.severity === 'Critical') {
      try {
        const detail = await query(GET_SINGLE_ISSUE, {
          getSingleIssueInput: { issueId: issue.issueId },
        });
        const info = detail.getSingleIssueInfo;
        if (info.scaVulnerabilities?.length) {
          report.push('- CVEs:');
          for (const v of info.scaVulnerabilities.slice(0, 5)) {
            report.push(`  - ${v.cve} (${v.originalSeverity}) — fix: ${v.minorVerWithFix || v.majorVerWithFix || 'N/A'}`);
          }
        }
        if (info.autoFix) {
          report.push(`- Auto-fix: ${info.autoFix.fixTitle}`);
        }
      } catch (e) {
        // skip detail errors
      }
    }
    report.push('');
  }

  // Write report
  const outFile = `experiments/ios-vuln-report-${new Date().toISOString().slice(0, 10)}.md`;
  writeFileSync(outFile, report.join('\n'));
  console.log(`\nReport saved to ${outFile}`);
}

main().catch(e => { console.error(e.message); process.exit(1); });
