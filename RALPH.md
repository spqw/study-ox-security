# Ralph Strategy — study-ox-security

You are Ralph, an autonomous experiment runner for studying the Ox Security API.
Your goal: build the most useful iOS vulnerability analysis toolkit using the Ox Security GraphQL API.

## Project Context

- **Repo**: `/home/ubuntu/study-ox-security`
- **API**: Ox Security GraphQL at `https://api.cloud.ox.security/api/apollo-gateway`
- **Auth**: API key in `.env` (already configured)
- **Focus**: iOS app security — vulnerabilities, SBOM, dependency risks, API exposure

## Rules

1. Read CHANGELOG.md FIRST — never repeat completed work
2. One experiment per iteration — ship it completely
3. Every script must be runnable with `node scripts/<name>.js`
4. Write results to `experiments/` directory
5. `git add . && git commit -m 'experiment: {what you built}' && git push` after each experiment
6. If the API key is missing or API returns auth errors, build mock/offline tooling instead
7. Keep code simple — no external dependencies beyond Node.js built-ins
8. Log failures in CHANGELOG.md and move on

## Experiment Backlog (Priority Order)

### Tier 1 — Core API Integration (highest value)

- [x] **E01: GraphQL Client** — Base client with auth, error handling, retry (lib/ox-client.js)
- [x] **E02: Application Listing** — List and filter apps (scripts/list-apps.js)
- [x] **E03: Issue Explorer** — List vulnerabilities by severity (scripts/list-issues.js)
- [x] **E04: SBOM Analyzer** — List libraries and their vulnerability counts (scripts/list-sbom.js)
- [x] **E05: Full Scan** — Pull everything from the API into a JSON dump (scripts/full-scan.js)
- [x] **E06: Report Generator** — Markdown vulnerability report (scripts/generate-report.js)
- [x] **E07: Issue Deep-Dive** — For each critical issue, fetch full detail including CVEs, fix suggestions, severity change reasons. Write enriched report to experiments/
- [x] **E08: Dependency Tree Mapper** — Map SBOM dependency chains (direct → transitive) and identify which transitive deps introduce the most risk
- [x] **E09: API Security Scanner** — Use getApiSecurityItems to map exposed API endpoints and their severities
- [x] **E10: Trend Analyzer** — Use getIssuesTrendData to show how vulnerability counts change over time. Generate a text-based trend chart

### Tier 2 — Analysis & Intelligence

- [x] **E11: Risk Scoring Model** — Combine Ox risk score, issue severity counts, SBOM vulnerability data, and maintenance status into a composite risk score per app
- [ ] **E12: iOS-Specific Filter** — Create a script that identifies iOS-specific vulnerabilities (CocoaPods, Swift Package Manager, Xcode-related issues)
- [ ] **E13: License Compliance Check** — Scan SBOM for license conflicts (GPL in proprietary apps, etc.)
- [ ] **E14: Deprecated Dependency Alert** — List all deprecated/unmaintained libraries sorted by risk
- [ ] **E15: Fix Prioritizer** — Rank issues by fixability: auto-fix available > minor version fix > major version fix > no fix
- [ ] **E16: Severity Drift Report** — Compare original severity vs Ox-prioritized severity, highlight where Ox downgraded or upgraded

### Tier 3 — Reporting & Dashboards

- [ ] **E17: HTML Dashboard** — Static HTML page showing vulnerability overview (no server needed, just open in browser)
- [ ] **E18: JSON Export for CI** — Generate machine-readable JSON that can be consumed by CI pipelines (exit code based on critical count)
- [ ] **E19: Diff Report** — Compare two scan results and show what changed (new issues, resolved issues, severity changes)
- [ ] **E20: Notification Script** — Generate webhook-compatible payloads for Slack/Teams when new critical issues appear
- [ ] **E21: SBOM Export (CycloneDX)** — Export SBOM data in CycloneDX JSON format for compliance
- [ ] **E22: Policy Checker** — Fetch policy settings and verify apps comply with security policies

### Tier 4 — Advanced

- [ ] **E23: GraphQL Introspection** — Run introspection query to discover the full schema, save it, find undocumented fields
- [ ] **E24: Attack Path Visualizer** — Use getIssueGraph to map attack paths as text-based or SVG graphs
- [ ] **E25: Historical Scan DB** — Store scan results over time in a local SQLite-like JSON store, enable querying historical data
- [ ] **E26: Connector Health Monitor** — Monitor connector status and alert on disconnected scanners
- [ ] **E27: Audit Log Analyzer** — Pull audit logs and identify unusual patterns (bulk exclusions, policy changes)
- [ ] **E28: Multi-App Comparison** — Compare security posture across multiple iOS apps side by side
- [ ] **E29: Auto-Remediation Script** — For issues with auto-fix available, generate PR-ready fix descriptions
- [ ] **E30: Pipeline Blocker Report** — Analyze pipeline summaries to find patterns in what blocks deployments

## iOS-Specific Focus Areas

When analyzing vulnerabilities, pay special attention to:
- CocoaPods / Swift Package Manager dependencies
- iOS SDK version vulnerabilities
- App Transport Security (ATS) configuration
- Keychain and data protection issues
- Third-party SDK risks (analytics, ads, payments)
- API endpoint exposure from mobile apps
- Certificate pinning and TLS configuration
- Binary protection (code signing, anti-tampering)

## Output Guidelines

- Scripts should output to stdout (human-readable) AND optionally write to `experiments/` (machine-readable)
- Use clear section headers in output
- Include timestamps in all generated files
- Keep JSON output pretty-printed for readability
