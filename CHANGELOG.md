# Changelog — study-ox-security

## Initial Setup

- **2026-02-22T00:00:00Z** — Project created with Ox Security GraphQL client, query modules, and CLI scripts
  - E01: GraphQL client (lib/ox-client.js) — auth, error handling, .env loading
  - E02: Application listing (scripts/list-apps.js) — filterable by name
  - E03: Issue explorer (scripts/list-issues.js) — filterable by severity and app
  - E04: SBOM analyzer (scripts/list-sbom.js) — sorted by vulnerability count
  - E05: Full scan (scripts/full-scan.js) — paginated fetch of all data
  - E06: Report generator (scripts/generate-report.js) — markdown vulnerability report
  - Ralph loop configured for 1-hour autonomous sessions

## E07: Issue Deep-Dive

- **2026-02-22T14:35:00Z** — E07: Issue Deep-Dive (scripts/issue-deep-dive.js)
  - Fetches all critical/high issues, enriches each with GET_SINGLE_ISSUE detail
  - Extracts: CVEs with NVD links, fix versions, severity change reasons, auto-fix info, SBOM/library context
  - Outputs both enriched JSON and detailed markdown report to experiments/deep-dive-{date}/
  - Supports filtering by severity (OX_SEVERITY) and app name (OX_APP_NAME/CLI args)
  - Bounded concurrency for API calls (OX_CONCURRENCY, default 5)
  - Report sections: prioritization overview, enrichment summary, auto-fix opportunities, severity re-prioritizations, detailed per-issue analysis
  - Falls back to realistic iOS mock data (10 issues across 3 apps) when no API key configured
  - Mock data covers: RCE, prototype pollution, keychain security, cert pinning, SQLi, OpenSSL vulns, hardcoded secrets, ATS config, React Native CVEs

## E08: Dependency Tree Mapper

- **2026-02-22T14:38:00Z** — E08: Dependency Tree Mapper (scripts/dependency-tree.js)
  - Maps SBOM dependency chains (direct → transitive) for all apps
  - Computes per-library risk scores based on vulnerability counts, maintenance status, and deprecation
  - Identifies transitive risk hotspots: transitive deps that introduce the most risk and which direct dep pulls them in
  - Generates ASCII dependency trees showing direct → transitive relationships with risk annotations
  - Per-app risk summaries with transitive risk percentage breakdown
  - Outputs JSON (full analysis), markdown report (tables + trees + recommendations), and trees.txt (quick reference)
  - Supports app filtering via OX_APP_NAME env var or CLI arg
  - Paginated API fetch for real data; realistic iOS mock data for 3 apps (33 libs, CocoaPods/SPM/npm)
  - Mock data includes known dependency edges (e.g., Ono→libxml2, react-native→hermes-engine, Alamofire→OpenSSL)
  - Report includes: overview stats, app risk table, transitive hotspots, visual trees, per-app detail tables, key findings, and remediation recommendations
