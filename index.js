/**
 * study-ox-security — Ox Security API client for iOS app vulnerability analysis
 *
 * Usage:
 *   node index.js                    # Interactive overview
 *   node scripts/list-apps.js        # List applications
 *   node scripts/list-issues.js      # List vulnerabilities
 *   node scripts/list-sbom.js        # List SBOM libraries
 *   node scripts/full-scan.js        # Full vulnerability scan
 *   node scripts/generate-report.js  # Generate markdown report
 */

import { query } from './lib/ox-client.js';
import { GET_APPLICATIONS } from './queries/applications.js';
import { GET_ISSUES } from './queries/issues.js';

async function main() {
  console.log('study-ox-security — Ox Security API Client');
  console.log('='.repeat(50));
  console.log('');

  try {
    // Test connectivity by fetching apps
    console.log('Fetching applications...');
    const appsData = await query(GET_APPLICATIONS, {
      getApplicationsInput: { offset: 0, limit: 10 },
    });

    const apps = appsData.getApplications;
    console.log(`Found ${apps.total} applications (showing first ${apps.applications.length}):`);
    console.log('');

    for (const app of apps.applications) {
      const sev = app.issuesBySeverity || {};
      console.log(`  ${app.appName} (${app.type})`);
      console.log(`    Risk: ${app.risk} | Critical: ${sev.critical || 0} | High: ${sev.high || 0} | Medium: ${sev.medium || 0}`);
    }

    // Fetch critical/high issues
    console.log('');
    console.log('Fetching critical + high severity issues...');
    const issuesData = await query(GET_ISSUES, {
      isDemo: false,
      getIssuesInput: {
        offset: 0,
        limit: 10,
        filters: { criticality: ['Critical', 'High'] },
        sort: { fields: ['Severity'], order: ['DESC'] },
      },
    });

    const issues = issuesData.getIssues;
    console.log(`Found ${issues.totalFilteredIssues} critical/high issues (showing first ${issues.issues.length}):`);
    console.log('');

    for (const issue of issues.issues) {
      console.log(`  [${issue.severity}] ${issue.mainTitle}`);
      if (issue.app) console.log(`    App: ${issue.app.name}`);
      if (issue.category) console.log(`    Category: ${issue.category.name}`);
    }

    console.log('');
    console.log('Run specific scripts for deeper analysis:');
    console.log('  npm run apps     — List all applications');
    console.log('  npm run issues   — Detailed issue listing');
    console.log('  npm run sbom     — SBOM library analysis');
    console.log('  npm run scan     — Full vulnerability scan');
    console.log('  npm run report   — Generate markdown report');
  } catch (err) {
    console.error('Error:', err.message);
    process.exit(1);
  }
}

main();
