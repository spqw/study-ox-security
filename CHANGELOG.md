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
