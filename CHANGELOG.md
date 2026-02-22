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
