# study-ox-security

Ox Security API client for iOS app vulnerability analysis. Uses the Ox Security GraphQL API to fetch, analyze, and report on security vulnerabilities.

## Setup

```bash
# 1. Copy env file and add your Ox Security API key
cp .env.example .env
# Edit .env and add your OX_API_KEY
# Get it from: app.ox.security > Settings > API Key Settings

# 2. Run any script directly (no npm install needed — zero external deps)
node index.js              # Overview + connectivity test
node scripts/list-apps.js  # List applications
node scripts/list-issues.js          # List all issues
node scripts/list-issues.js critical # Only critical
node scripts/list-sbom.js            # SBOM libraries
node scripts/full-scan.js            # Full scan → experiments/
node scripts/generate-report.js      # Markdown report
```

## Architecture

```
lib/ox-client.js         — GraphQL client (single endpoint, API key auth)
queries/                 — GraphQL query definitions
  applications.js        — App listing, detail, inventory
  issues.js              — Vulnerabilities, prioritization, trends
  sbom.js                — SBOM libraries, stats, filters
  api-security.js        — API endpoint security
  organization.js        — Org info, connectors, audit logs
scripts/                 — Runnable CLI tools
experiments/             — Scan results, reports, analysis output
```

## Ox Security API

All requests go to a single GraphQL endpoint:
```
POST https://api.cloud.ox.security/api/apollo-gateway
Authorization: <your-api-key>
Content-Type: application/json
```

## Ralph Loop (Autonomous Runner)

```bash
# Run for 1 hour (default)
./ralph-loop.sh

# Run for N hours
./ralph-loop.sh 2

# Check logs
ls ralph-logs/
```

The Ralph loop autonomously works through the experiment backlog in RALPH.md, building new analysis tools and improving existing ones.
