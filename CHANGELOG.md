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

## E09: API Security Scanner

- **2026-02-22T14:43:00Z** — E09: API Security Scanner (scripts/api-security-scan.js)
  - Uses getApiSecurityItems + getApiSecurityFiltersLazy to map all exposed API endpoints across iOS apps
  - Risk pattern detection engine identifies: PAYMENT, HEALTH_DATA, AUTH, PII, LEGACY_API, DATA_EXPORT, DESTRUCTIVE, IDOR_RISK, CONFIG_EXPOSURE
  - Composite risk scoring (0-100) combines endpoint severity, HTTP method risk, and detected patterns
  - Per-app breakdown with severity counts, endpoint tables, and critical+high attention flags
  - Top 10 high-risk endpoint ranking with code locations and discovery sources
  - API version analysis to identify legacy/deprecated API versions still in use
  - Discovery source breakdown (OpenAPI spec vs CodeAnalysis)
  - Actionable recommendations: PCI DSS for payment endpoints, HIPAA for health data, IDOR mitigation, legacy API deprecation
  - Outputs JSON (full analysis + risk ranking) and markdown report to experiments/api-security-{date}/
  - Supports app filtering via OX_APP_NAME env var or CLI arg
  - Paginated API fetch for real data; realistic iOS mock data (28 endpoints across 3 apps)
  - Mock data covers: banking APIs (transfers, card tokenization, account balance), health APIs (records, vitals, export), e-commerce APIs (checkout, payments, cart)

## E10: Trend Analyzer

- **2026-02-22T14:46:00Z** — E10: Trend Analyzer (scripts/trend-analyzer.js)
  - Uses getIssuesTrendData to fetch daily vulnerability counts by severity over time
  - ASCII trend charts: full-height area charts for total issues and per-severity (Critical, High)
  - Sparkline summaries for quick visual trend indication per severity and per app
  - 7-day moving average computation for smoothed trend analysis
  - Automated trend detection: classifies each severity and app as improving/stable/worsening
  - Notable event detection: identifies significant spikes and drops vs 7-day moving average (>20% deviation)
  - Per-application trend breakdown with individual charts and severity tables
  - Weekly summary table with avg/min/max issue counts and week-over-week direction
  - Insights & recommendations engine: flags worsening apps, rising critical counts, frequent spikes
  - Outputs JSON (full time series + analysis) and markdown report to experiments/trends-{date}/
  - Supports app filtering via OX_APP_NAME env var or CLI arg, configurable period via OX_DAYS (default 90)
  - Realistic iOS mock data: 3 apps with distinct trend profiles (improving bank app, ramping health app, steady e-commerce with dependency spike)

## E11: Risk Scoring Model

- **2026-02-22T14:50:00Z** — E11: Risk Scoring Model (scripts/risk-score.js)
  - Combines 5 risk dimensions into a weighted composite score (0-100) per app with letter grades (A-F)
  - Dimensions: Issue Risk (35%), SBOM Health (25%), Transitive Risk (15%), Maintenance Debt (15%), Ox Risk Score (10%)
  - Issue Risk: weighted severity counts (Critical*10, High*5, Medium*2, Low*0.5), normalized to 0-100
  - SBOM Health: vulnerable library density — ratio of libs with known vulns to total libs
  - Transitive Risk: what percentage of total vulnerability weight comes from transitive (indirect) dependencies
  - Maintenance Debt: deprecated, unmaintained, and license-issue library ratio
  - Ox Risk Score: Ox Security's built-in risk assessment, passed through directly
  - Risk comparison matrix with all apps side-by-side across all dimensions
  - Per-app risk profiles with ASCII bar charts showing each dimension score
  - Top risky libraries per app ranked by weighted vulnerability score
  - Recommendations engine: generates prioritized (Critical/High/Medium) actionable advice per app
  - Fleet summary: average score, highest/lowest risk apps across the portfolio
  - Outputs JSON (full scoring data + methodology) and markdown report to experiments/risk-scores-{date}/
  - Supports app filtering via OX_APP_NAME env var or CLI arg
  - Realistic iOS mock data: 3 apps (banking/health/ecommerce) with distinct risk profiles and 32 libraries

## E12: iOS-Specific Filter

- **2026-02-22T15:10:00Z** — E12: iOS-Specific Filter (scripts/ios-filter.js)
  - Multi-signal iOS classification engine combining 5 detection methods: package manager (CocoaPods/SPM/Carthage), known iOS library patterns (50+ regex), issue text pattern matching (24 iOS keyword patterns), Ox Mobile Security category, and app name heuristic
  - Each issue scored 0-100 for iOS relevance based on match weight and signal count
  - 15 iOS security categories organized into 5 groups: Dependency Management (CocoaPods, SPM, Carthage), Platform Security (ATS, Keychain, Cert Pinning, Biometrics, Code Signing), Configuration (Plist, Provisioning, Xcode, iOS SDK), Code Analysis (Swift, Obj-C, WebView, Binary), Third-Party SDKs (React Native, Firebase, HealthKit, Networking, Storage)
  - SBOM analysis identifies iOS-relevant libraries by package manager, library name pattern matching, and source indicators
  - Filters non-iOS issues (web, backend) from mixed-platform portfolios — correctly filtered 12/14 issues in mock data
  - Per-app iOS issue breakdown with severity counts and category listings
  - Vulnerable iOS library table ranked by total vulnerability count with maintenance flags
  - Recommendations engine generates prioritized advice: CocoaPods updates, ATS hardening, cert pinning, keychain config, React Native upgrades, UIWebView migration, Firebase config security
  - Outputs JSON (full classification data + categories) and markdown report to experiments/ios-filter-{date}/
  - Supports app filtering via OX_APP_NAME env var or CLI arg
  - Realistic mock data: 14 issues (12 iOS, 2 non-iOS) across 4 apps + 31 SBOM libraries with varied sources

## E13: License Compliance Check

- **2026-02-22T14:59:00Z** — E13: License Compliance Check (scripts/license-check.js)
  - Classifies every SBOM library license into 6 categories: permissive, public-domain, weak-copyleft, strong-copyleft, proprietary, unknown
  - 14 license pattern rules covering MIT, BSD, Apache, ISC, GPL, LGPL, AGPL, SSPL, MPL, EPL, CDDL, Zlib, OpenSSL, and more — ordered for correct LGPL-before-GPL matching
  - Conflict detection engine identifies: strong-copyleft in proprietary/App Store apps, AGPL/SSPL with broadest copyleft scope, weak-copyleft static linking risks on iOS, missing/unknown licenses, Ox-flagged license issues
  - iOS App Store compliance analysis: GPL/AGPL incompatibility with App Store DRM terms, LGPL static linking requirements, SSPL warnings
  - Per-app compliance grading (A-F) with composite risk scores based on copyleft count, unknown licenses, conflict severity
  - Portfolio-level overview: license distribution chart, unique license inventory, conflict summary by severity
  - Per-library inventory table sorted by risk, showing license category, SPDX identifier, conflict status, and Ox flag
  - Recommendations engine: prioritized advice for strong-copyleft replacement, missing license resolution, weak-copyleft review, CI pipeline license allowlists
  - Outputs JSON (full compliance data + per-app grades) and markdown report to experiments/license-check-{date}/
  - Supports app filtering via OX_APP_NAME env var or CLI arg
  - Realistic mock data: 31 libraries across 3 iOS apps with mixed licenses (MIT, Apache, AGPL, GPL, LGPL, BSD, Zlib, OpenSSL, missing)

## E14: Deprecated Dependency Alert

- **2026-02-22T15:03:00Z** — E14: Deprecated Dependency Alert (scripts/deprecated-deps.js)
  - Scans SBOM for all deprecated and unmaintained libraries across the iOS app portfolio
  - Composite risk scoring (0-100) per flagged library combining: status weight (deprecated/unmaintained/both), vulnerability exposure (weighted severity), dependency level (direct vs transitive), and license issues
  - Migration urgency classification: CRITICAL (80+), HIGH (60-79), MEDIUM (40-59), LOW (0-39) with actionable descriptions
  - Known alternatives database with 20+ iOS/JS library mappings (e.g., AFNetworking->Alamofire, moment->date-fns, FMDB->SQLite.swift, RNCryptor->CryptoKit)
  - Per-app dependency health ratio showing flagged-to-total library percentage with ASCII bar visualization
  - Cross-app analysis identifies libraries flagged in multiple apps for portfolio-wide improvement
  - Prioritized alert list sorted by risk score with vulnerability details, source info, and migration suggestions
  - Recommendations engine: critical vuln+deprecated combos, high-priority alternatives, shared library fixes, CI pipeline integration
  - Outputs JSON (full analysis + scoring methodology) and markdown report to experiments/deprecated-deps-{date}/
  - Supports app filtering via OX_APP_NAME env var or CLI arg
  - Realistic mock data: 36 libraries across 3 iOS apps with 4 deprecated, 7 unmaintained, and varied vulnerability profiles

## E15: Fix Prioritizer

- **2026-02-22T15:09:00Z** — E15: Fix Prioritizer (scripts/fix-prioritizer.js)
  - Classifies every issue into 5 fix tiers: Auto-Fix (T1), Minor/Patch Version Bump (T2), Major Version Upgrade (T3), Code Change Required (T4), Manual Remediation (T5)
  - ROI scoring engine: severity weight (Critical=10, High=5, Medium=2, Low=0.5) multiplied by fix ease score (100/80/50/30/10 per tier) ranks issues by highest-impact, lowest-effort first
  - Fix tier classification logic inspects autoFix field (fixType: VersionBump vs CodeChange), scaVulnerabilities (minorVerWithFix vs majorVerWithFix), and sourceType to determine effort level
  - Quick wins section highlights all Tier 1-2 issues (auto-fix + minor version) for immediate remediation
  - Breaking change warnings flag major version upgrades that may require API migration or code changes
  - Severity vs fixability matrix shows how many issues per severity level are auto-fixable, fixable (T1-3), or manual
  - Per-app remediation summary with issue counts, quick win counts, tier distribution, and average ROI per app
  - Full prioritized fix list ranked by ROI score with fix actions and version targets
  - Recommendations engine generates numbered remediation strategy based on analysis results
  - Impact projection calculates what % of severity-weighted risk is addressable by quick wins alone
  - Outputs JSON (full classification data + methodology) and markdown report to experiments/fix-priority-{date}/
  - Supports app filtering via OX_APP_NAME env var or CLI arg, severity filter via OX_SEVERITY
  - Realistic mock data: 14 issues across 3 iOS apps with varied fix availability (8 auto-fix, 1 minor, 1 major, 4 code change)

## E16: Severity Drift Report

- **2026-02-22T15:14:00Z** — E16: Severity Drift Report (scripts/severity-drift.js)
  - Compares original scanner-reported severity vs Ox-prioritized severity for every issue
  - Drift classification: upgraded (Ox raised severity), downgraded (Ox lowered), unchanged
  - Drift magnitude distribution: counts how many severity levels each issue shifted (0-4)
  - Severity drift matrix: cross-tabulation of original × Ox severity (visual heatmap-style table)
  - Aggregate prioritization comparison using getIssuePrioritization API (original vs Ox totals per severity)
  - Fetches severityChangedReason detail for all drifted issues: reason text, shortName, and changeCategory
  - Reason category analysis: groups re-prioritization drivers (Reachability, Exploitability, Business Context, Environment, Attack Vector, Impact) with occurrence counts and direction
  - Triage effort impact calculation: severity-weighted effort saved by downgrades vs effort added by upgrades, with net triage workload effect
  - Per-app drift breakdown: drift rate, upgrade/downgrade counts, and effort saved per application
  - Per-category and per-sourceType drift analysis: which issue types get re-prioritized most
  - Detailed upgraded/downgraded issue listings with full reasons and context
  - Recommendations engine: flags high-drift apps, reachability analysis value, triage efficiency gains
  - Outputs JSON (full drift data + matrix + reasons) and markdown report to experiments/severity-drift-{date}/
  - Supports app filtering via OX_APP_NAME env var or CLI arg
  - Realistic mock data: 16 issues across 3 iOS apps with 9 drifted (3 upgraded, 6 downgraded), 15 severity change reasons across 6 categories

## E17: HTML Dashboard

- **2026-02-22T15:22:00Z** — E17: HTML Dashboard (scripts/html-dashboard.js)
  - Generates a self-contained static HTML page — no server needed, just open in any browser
  - Dark-themed, responsive dashboard with 4 tabbed views: Overview, Issues, SBOM Health, Quick Fixes
  - Overview tab: KPI row (apps, issues, critical, high, auto-fixable, libraries), SVG donut chart for severity distribution, source type bar chart, per-app security posture cards with risk grades (A-F), severity mini-bars, and library stats
  - Issues tab: sortable table of top 20 issues with severity pills, app attribution, source type, and auto-fix badges
  - SBOM Health tab: library health grid (total, vulnerable, deprecated, unmaintained) with health percentage bar, most vulnerable libraries table with per-severity vulnerability counts and maintenance status badges
  - Quick Fixes tab: auto-fix opportunity table showing severity, issue, app, and fix action for immediate remediation
  - Per-app cards show: risk grade badge (A-F with score), severity bar charts (C/H/M/L), library count, vulnerable count, auto-fixable count, deprecated count
  - All CSS and JS inlined — zero external dependencies, works offline
  - Outputs dashboard.html and data.json to experiments/dashboard-{date}/
  - Supports app filtering via OX_APP_NAME env var or CLI arg
  - Falls back to realistic mock data (4 iOS apps, 16 issues, 18 libraries) when OX_API_KEY not configured
  - Fetches apps, issues, and SBOM libraries from Ox Security API when key is available

## E18: JSON Export for CI

- **2026-02-22T15:22:00Z** — E18: JSON Export for CI (scripts/ci-export.js)
  - Generates machine-readable JSON report for CI/CD pipeline integration with configurable severity gate
  - Exit codes: 0 = PASS (all thresholds met), 1 = FAIL (threshold exceeded), 2 = ERROR (script failure)
  - Configurable thresholds via environment variables: OX_MAX_CRITICAL (default: 0), OX_MAX_HIGH, OX_MAX_MEDIUM, OX_MAX_LOW, OX_MAX_TOTAL (-1 = unlimited)
  - JSON output to stdout (pipe-friendly) with status messages on stderr — works with `jq`, CI artifact collection, etc.
  - Versioned schema (1.0.0) with gate result, severity summary, source type breakdown, category breakdown, per-app risk scores, and full issue list
  - Gate evaluation: compares actual severity counts against thresholds, reports violations with exceeded-by counts
  - Per-app breakdown with individual severity counts and risk scores (0-100)
  - Risk score computation: severity-weighted issue count (Critical=10, High=5, Medium=2, Low=0.5)
  - Issues sorted by severity weight then date, with flat CI-friendly structure (id, title, severity, source_type, category, app)
  - OX_OUTPUT_FILE env var writes JSON to a specific file path for artifact collection
  - OX_QUIET=true suppresses stderr for clean piping; OX_SAVE_EXPERIMENT=false skips experiment directory output
  - Experiment output includes CI integration examples for GitHub Actions and GitLab CI in markdown report
  - Paginated API fetch for real data; realistic mock data (14 issues across 3 iOS apps) when OX_API_KEY not configured
  - Supports app filtering via OX_APP_NAME env var or CLI arg, severity filter via OX_SEVERITY
