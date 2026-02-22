#!/usr/bin/env node
/**
 * List SBOM (Software Bill of Materials) libraries and their vulnerabilities
 */
import { query } from '../lib/ox-client.js';
import { GET_SBOM_LIBRARIES, GET_SBOM_STATS } from '../queries/sbom.js';

async function main() {
  const search = process.argv[2] || '';
  const limit = parseInt(process.env.OX_LIMIT || '100', 10);

  console.log('Ox Security — SBOM Libraries');
  console.log('='.repeat(50));

  // Get stats first
  try {
    const stats = await query(GET_SBOM_STATS, {
      getSbomLibrariesInput: { offset: 0, limit: 1, filters: {}, search: '', owners: [] },
    });
    const s = stats.sbomLibStats;
    console.log(`Total libraries: ${s.totalLibraries}`);
    console.log(`Vulnerable: ${s.vulnerableLibraries}`);
    console.log(`Deprecated: ${s.deprecatedLibraries}`);
    console.log(`Not maintained: ${s.notMaintainedLibraries}`);
    console.log(`License issues: ${s.licenseIssueLibraries}`);
    console.log('');
  } catch (e) {
    console.log('(Stats not available:', e.message, ')\n');
  }

  // Get libraries
  const data = await query(GET_SBOM_LIBRARIES, {
    getSbomLibrariesInput: {
      offset: 0,
      limit,
      filters: {},
      search,
      owners: [],
    },
  });

  const libs = data.getSbomLibraries;
  console.log(`Showing ${libs.sbomLibs.length} of ${libs.total} libraries`);
  if (search) console.log(`Search: "${search}"`);
  console.log('');

  // Sort by vulnerability count (highest first)
  const sorted = [...libs.sbomLibs].sort((a, b) => {
    const countA = Object.values(a.vulnerabilityCounts || {}).reduce((s, v) => s + (v || 0), 0);
    const countB = Object.values(b.vulnerabilityCounts || {}).reduce((s, v) => s + (v || 0), 0);
    return countB - countA;
  });

  for (const lib of sorted) {
    const vc = lib.vulnerabilityCounts || {};
    const total = (vc.critical || 0) + (vc.high || 0) + (vc.medium || 0) + (vc.low || 0);
    const flags = [];
    if (lib.notMaintained) flags.push('NOT-MAINTAINED');
    if (lib.isDeprecated) flags.push('DEPRECATED');
    if (lib.licenseIssue) flags.push('LICENSE-ISSUE');

    console.log(`${lib.libraryName}@${lib.libraryVersion}`);
    console.log(`  App: ${lib.appName} | License: ${lib.license || 'N/A'} | ${lib.dependencyType} (${lib.dependencyLevel})`);
    if (total > 0) {
      console.log(`  Vulns: ${total} (C:${vc.critical || 0} H:${vc.high || 0} M:${vc.medium || 0} L:${vc.low || 0})`);
    }
    if (flags.length) console.log(`  Flags: ${flags.join(', ')}`);
    console.log('');
  }
}

main().catch(e => { console.error(e.message); process.exit(1); });
