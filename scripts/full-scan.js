#!/usr/bin/env node
/**
 * Full vulnerability scan — pulls everything from Ox Security API
 * and writes results to experiments/ directory
 */
import { writeFileSync, mkdirSync } from 'fs';
import { query } from '../lib/ox-client.js';
import { GET_APPLICATIONS } from '../queries/applications.js';
import { GET_ISSUES, GET_ISSUE_PRIORITIZATION } from '../queries/issues.js';
import { GET_SBOM_LIBRARIES } from '../queries/sbom.js';
import { GET_ORGANIZATION, GET_CONNECTORS } from '../queries/organization.js';

async function main() {
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const outDir = `experiments/scan-${ts}`;
  mkdirSync(outDir, { recursive: true });

  console.log('Ox Security — Full Vulnerability Scan');
  console.log('='.repeat(50));
  console.log(`Output: ${outDir}\n`);

  const results = {};

  // 1. Organization info
  console.log('[1/6] Fetching organization info...');
  try {
    results.organization = await query(GET_ORGANIZATION);
    console.log(`  Org: ${results.organization.getOrganization?.name || 'N/A'}`);
  } catch (e) {
    console.log(`  Skipped: ${e.message}`);
  }

  // 2. Connectors
  console.log('[2/6] Fetching connectors...');
  try {
    results.connectors = await query(GET_CONNECTORS);
  } catch (e) {
    console.log(`  Skipped: ${e.message}`);
  }

  // 3. Applications
  console.log('[3/6] Fetching applications...');
  try {
    results.applications = await query(GET_APPLICATIONS, {
      getApplicationsInput: { offset: 0, limit: 500 },
    });
    const total = results.applications.getApplications?.total || 0;
    console.log(`  Found ${total} applications`);
  } catch (e) {
    console.log(`  Skipped: ${e.message}`);
  }

  // 4. All issues (paginated)
  console.log('[4/6] Fetching all issues...');
  try {
    const allIssues = [];
    let offset = 0;
    const pageSize = 200;
    let total = Infinity;

    while (offset < total && offset < 2000) { // cap at 2000 for safety
      const data = await query(GET_ISSUES, {
        isDemo: false,
        getIssuesInput: {
          offset,
          limit: pageSize,
          sort: { fields: ['Severity'], order: ['DESC'] },
        },
      });
      const page = data.getIssues;
      total = page.totalIssues;
      allIssues.push(...page.issues);
      offset += pageSize;
      process.stdout.write(`  Fetched ${allIssues.length}/${total}...\r`);
    }
    console.log(`  Fetched ${allIssues.length} issues total`);
    results.issues = { issues: allIssues, total };
  } catch (e) {
    console.log(`  Skipped: ${e.message}`);
  }

  // 5. Issue prioritization
  console.log('[5/6] Fetching issue prioritization...');
  try {
    results.prioritization = await query(GET_ISSUE_PRIORITIZATION, {
      getIssuesInput: {},
    });
  } catch (e) {
    console.log(`  Skipped: ${e.message}`);
  }

  // 6. SBOM
  console.log('[6/6] Fetching SBOM libraries...');
  try {
    results.sbom = await query(GET_SBOM_LIBRARIES, {
      getSbomLibrariesInput: { offset: 0, limit: 2000, filters: {}, search: '', owners: [] },
    });
    console.log(`  Found ${results.sbom.getSbomLibraries?.total || 0} libraries`);
  } catch (e) {
    console.log(`  Skipped: ${e.message}`);
  }

  // Write results
  writeFileSync(`${outDir}/scan-results.json`, JSON.stringify(results, null, 2));
  console.log(`\nResults saved to ${outDir}/scan-results.json`);

  // Generate summary
  const summary = generateSummary(results);
  writeFileSync(`${outDir}/SUMMARY.md`, summary);
  console.log(`Summary saved to ${outDir}/SUMMARY.md`);
}

function generateSummary(results) {
  const lines = ['# Ox Security Scan Summary', `Date: ${new Date().toISOString()}`, ''];

  if (results.applications?.getApplications) {
    const apps = results.applications.getApplications;
    lines.push(`## Applications (${apps.total})`);
    for (const app of apps.applications || []) {
      const s = app.issuesBySeverity || {};
      lines.push(`- **${app.appName}** (${app.type}) — Risk: ${app.risk}, C:${s.critical||0} H:${s.high||0} M:${s.medium||0}`);
    }
    lines.push('');
  }

  if (results.issues) {
    const issues = results.issues;
    lines.push(`## Issues (${issues.total})`);
    const bySeverity = {};
    for (const i of issues.issues) {
      bySeverity[i.severity] = (bySeverity[i.severity] || 0) + 1;
    }
    for (const [sev, count] of Object.entries(bySeverity)) {
      lines.push(`- ${sev}: ${count}`);
    }
    lines.push('');

    // Top 10 critical issues
    const critical = issues.issues.filter(i => i.severity === 'Critical').slice(0, 10);
    if (critical.length) {
      lines.push('### Top Critical Issues');
      for (const i of critical) {
        lines.push(`- **${i.mainTitle}** — ${i.app?.name || 'N/A'} (${i.category?.name || 'N/A'})`);
      }
      lines.push('');
    }
  }

  if (results.prioritization?.getIssuePrioritization) {
    const p = results.prioritization.getIssuePrioritization;
    lines.push('## Prioritization (Ox vs Original)');
    lines.push(`- Original critical: ${p.original?.critical || 0} → Ox critical: ${p.oxPrioritized?.critical || 0}`);
    lines.push(`- Original high: ${p.original?.high || 0} → Ox high: ${p.oxPrioritized?.high || 0}`);
    lines.push('');
  }

  if (results.sbom?.getSbomLibraries) {
    const sbom = results.sbom.getSbomLibraries;
    lines.push(`## SBOM Libraries (${sbom.total})`);
    const vulnerable = sbom.sbomLibs.filter(l => {
      const vc = l.vulnerabilityCounts || {};
      return (vc.critical || 0) + (vc.high || 0) > 0;
    });
    lines.push(`- Libraries with critical/high vulns: ${vulnerable.length}`);
    for (const lib of vulnerable.slice(0, 10)) {
      const vc = lib.vulnerabilityCounts || {};
      lines.push(`  - ${lib.libraryName}@${lib.libraryVersion} — C:${vc.critical||0} H:${vc.high||0}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

main().catch(e => { console.error(e.message); process.exit(1); });
