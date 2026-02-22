#!/usr/bin/env node
/**
 * List all applications from Ox Security, with iOS filtering
 */
import { query } from '../lib/ox-client.js';
import { GET_APPLICATIONS, GET_SINGLE_APP } from '../queries/applications.js';

async function main() {
  const appName = process.env.OX_APP_NAME || process.argv[2];

  console.log('Ox Security — Applications');
  console.log('='.repeat(50));

  const data = await query(GET_APPLICATIONS, {
    getApplicationsInput: { offset: 0, limit: 200 },
  });

  const apps = data.getApplications.applications;
  console.log(`Total: ${data.getApplications.total} applications\n`);

  // Filter for iOS/mobile if requested
  const filtered = appName
    ? apps.filter(a => a.appName.toLowerCase().includes(appName.toLowerCase()))
    : apps;

  if (appName && filtered.length === 0) {
    console.log(`No apps matching "${appName}". Showing all:`);
  }

  const toShow = filtered.length > 0 ? filtered : apps;

  for (const app of toShow) {
    const sev = app.issuesBySeverity || {};
    const total = (sev.critical || 0) + (sev.high || 0) + (sev.medium || 0) + (sev.low || 0);
    console.log(`${app.appName}`);
    console.log(`  Type: ${app.type} | Risk: ${app.risk} | Priority: ${app.businessPriority || 'N/A'}`);
    console.log(`  Issues: ${total} total (C:${sev.critical || 0} H:${sev.high || 0} M:${sev.medium || 0} L:${sev.low || 0})`);
    if (app.appOwners?.length) {
      console.log(`  Owners: ${app.appOwners.map(o => o.name || o.email).join(', ')}`);
    }
    if (app.tags?.length) {
      console.log(`  Tags: ${app.tags.map(t => t.displayName).join(', ')}`);
    }
    console.log('');
  }

  // If a specific app is targeted, get detailed info
  if (appName && filtered.length === 1) {
    console.log('--- Detailed Info ---');
    try {
      const detail = await query(GET_SINGLE_APP, {
        getSingleApplicationInput: { applicationId: filtered[0].appId },
      });
      console.log(JSON.stringify(detail.getSingleApplicationInfo, null, 2));
    } catch (e) {
      console.error('Could not fetch details:', e.message);
    }
  }
}

main().catch(e => { console.error(e.message); process.exit(1); });
