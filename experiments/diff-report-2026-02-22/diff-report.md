# E19: Scan Diff Report

*Generated: 2026-02-22T15:26:02.497Z*

> **Mock Mode** — using built-in sample data (no OX_API_KEY configured)

## Scan Window

| | Timestamp |
|---|---|
| **Before** | 2026-02-01T10:00:00Z |
| **After** | 2026-02-22T10:00:00Z |

## Overview

| Metric | Count |
|--------|-------|
| Issues before | 12 |
| Issues after | 11 |
| Net change | -1 |
| New issues | 2 |
| Resolved issues | 3 |
| Severity changes | 4 |
| Unchanged | 5 |
| Net risk weight change | -5 (lower) |

## Severity Distribution Shift

| Severity | Before | After | Delta |
|----------|--------|-------|-------|
| Critical | 3 | 2 | -1 ▼ |
| High | 4 | 3 | -1 ▼ |
| Medium | 3 | 3 | 0 |
| Low | 2 | 2 | 0 |
| Info | 0 | 1 | +1 ▲ |

```
Critical  Before: ██████████████████████████████ 3
          After:  ████████████████████ 2

High      Before: ██████████████████████████████ 4
          After:  ███████████████████████ 3

Medium    Before: ██████████████████████████████ 3
          After:  ██████████████████████████████ 3

Low       Before: ██████████████████████████████ 2
          After:  ██████████████████████████████ 2

Info      Before:  0
          After:  ██████████████████████████████ 1

```

## Per-App Changes

| App | Issues (before→after) | Risk (before→after) | New | Resolved | Sev Changes | Status |
|-----|----------------------|---------------------|-----|----------|-------------|--------|
| ShopEasy-iOS | 3 → 4 (+1) | 12 → 10 (-2) | 1 | 0 | 0 | Improved |
| HealthTracker-iOS | 4 → 3 (-1) | 22 → 17 (-5) | 0 | 1 | 2 | Improved |
| MyBankingApp-iOS | 5 → 4 (-1) | 55 → 27 (-28) | 1 | 2 | 2 | Improved |

## New Issues

2 new issue(s) appeared since the previous scan:

| # | Severity | Issue | App | Source | Category |
|---|----------|-------|-----|--------|----------|
| 1 | **Critical** | Weak TLS 1.0 Still Enabled in URLSession | MyBankingApp-iOS | SAST | Mobile Security |
| 2 | **Low** | Insecure Biometric Auth Fallback | ShopEasy-iOS | SAST | Mobile Security |

**New issues by source type:**
- SAST: 2

**New issues by category:**
- Mobile Security: 2

## Resolved Issues

3 issue(s) resolved since the previous scan:

| # | Severity | Issue | App | Source | Category |
|---|----------|-------|-----|--------|----------|
| 1 | ~~Critical~~ | Prototype Pollution in lodash | MyBankingApp-iOS | SCA | Vulnerable Dependency |
| 2 | ~~High~~ | Vulnerable OpenSSL in Alamofire | MyBankingApp-iOS | SCA | Vulnerable Dependency |
| 3 | ~~Low~~ | Cleartext HTTP traffic allowed in HealthKit sync | HealthTracker-iOS | SAST | Mobile Security |

**Risk weight removed:** 15.5 points

## Severity Changes

4 issue(s) had their severity re-assessed:

| # | Direction | Issue | Before | After | App |
|---|-----------|-------|--------|-------|-----|
| 1 | ▲ Upgraded | SQL Injection in SQLite Query Builder | High | Critical | HealthTracker-iOS |
| 2 | ▼ Downgraded | Remote Code Execution in libxml2 | Critical | High | MyBankingApp-iOS |
| 3 | ▼ Downgraded | Insecure Data Storage — Keychain Missing Accessibility | Critical | High | HealthTracker-iOS |
| 4 | ▼ Downgraded | Information Disclosure via Error Messages | Medium | Info | MyBankingApp-iOS |

- **Upgraded:** 1 issue(s) — increased severity requires attention
- **Downgraded:** 3 issue(s) — reduced severity frees triage effort

## Insights & Recommendations

1. Issue backlog is **shrinking** (3 resolved vs 2 new). Good progress on remediation.
2. **1 new Critical issue(s)** introduced — investigate immediately: Weak TLS 1.0 Still Enabled in URLSession
3. 1 issue(s) upgraded to higher severity — re-prioritize these in the current sprint.
4. Apps with improved posture: **ShopEasy-iOS, HealthTracker-iOS, MyBankingApp-iOS** — maintain the momentum.

## Usage

```bash
# Save a named snapshot of the current scan state
node scripts/diff-report.js snapshot baseline

# ... time passes, fixes are applied, new scans run ...

# Save another snapshot
node scripts/diff-report.js snapshot after-sprint-23

# Compare the two snapshots
node scripts/diff-report.js diff baseline after-sprint-23

# Compare arbitrary JSON files (CI export format)
OX_BEFORE=report-v1.json OX_AFTER=report-v2.json node scripts/diff-report.js

# Run demo with built-in mock data
node scripts/diff-report.js
```
