# E15: Fix Prioritizer Report

*Generated: 2026-02-22T15:09:26.725Z*

> **Mock Mode** — using realistic sample data (no OX_API_KEY configured)

## Fix Tier Methodology

Issues are classified into 5 fix tiers based on remediation effort:

| Tier | Label | Effort | Ease Score | Description |
|------|-------|--------|------------|-------------|
| ⚡ T1 | Auto-Fix Available | Minimal | 100 | Ox can auto-remediate or provides a ready-to-apply fix |
| 🔧 T2 | Minor/Patch Version Bump | Low | 80 | SCA issue fixable with a backward-compatible version bump |
| 🔨 T3 | Major Version Upgrade | Medium | 50 | SCA issue requiring a major version upgrade (may break APIs) |
| ✏️ T4 | Code Change Required | High | 30 | Requires manual code modification with guidance |
| 🔍 T5 | Manual Remediation | Very High | 10 | No fix information — requires investigation and manual remediation |

**ROI Score** = Severity Weight × Ease Score. Higher = fix first (high impact + easy fix).

Severity weights: Critical=10, High=5, Medium=2, Low=0.5

## Overview

| Metric | Value |
|--------|-------|
| Total issues | 14 |
| Auto-fixable (Tier 1) | 8 (57%) |
| Fixable (Tiers 1-3) | 10 (71%) |
| Manual remediation | 4 |
| Quick wins (Tiers 1-2) | 9 |
| Breaking changes | 3 |
| Average ROI score | 462 |

## Fix Tier Distribution

| Tier | Label | Count | % | Severities |
|------|-------|-------|---|------------|
| ⚡ T1 | Auto-Fix Available | 8 | 57% | Critical: 4, High: 3, Low: 1 |
| 🔧 T2 | Minor/Patch Version Bump | 1 | 7% | Medium: 1 |
| 🔨 T3 | Major Version Upgrade | 1 | 7% | High: 1 |
| ✏️ T4 | Code Change Required | 4 | 29% | High: 3, Medium: 1 |
| 🔍 T5 | Manual Remediation | 0 | 0% | - |

## Severity vs Fixability

| Severity | Total | Auto-Fix | Fixable (T1-3) | Manual (T4-5) |
|----------|-------|----------|----------------|---------------|
| 🔴 Critical | 4 | 4 | 4 | 0 |
| 🟠 High | 7 | 3 | 4 | 0 |
| 🟡 Medium | 2 | 0 | 1 | 0 |
| 🔵 Low | 1 | 1 | 1 | 0 |

## Per-App Remediation Summary

### HealthTracker-iOS

- **Total issues:** 4
- **Quick wins (T1-2):** 3
- **Average ROI:** 453

| Tier | Count |
|------|-------|
| ⚡ T1: Auto-Fix Available | 2 |
| 🔧 T2: Minor/Patch Version Bump | 1 |
| ✏️ T4: Code Change Required | 1 |

### MyBankingApp-iOS

- **Total issues:** 5
- **Quick wins (T1-2):** 3
- **Average ROI:** 542

| Tier | Count |
|------|-------|
| ⚡ T1: Auto-Fix Available | 3 |
| ✏️ T4: Code Change Required | 2 |

### ShopEasy-iOS

- **Total issues:** 5
- **Quick wins (T1-2):** 3
- **Average ROI:** 390

| Tier | Count |
|------|-------|
| ⚡ T1: Auto-Fix Available | 3 |
| 🔨 T3: Major Version Upgrade | 1 |
| ✏️ T4: Code Change Required | 1 |

## Prioritized Fix List

Sorted by ROI score (highest = fix first):

| Rank | ROI | Tier | Severity | App | Issue | Fix Action |
|------|-----|------|----------|-----|-------|------------|
| 1 | 1000 | ⚡ T1 | 🔴 Critical | MyBankingApp-iOS | Remote Code Execution in libxml2 (libxml2@2.11.6) | Update CocoaPods dependency to pull libxml2 >= 2.12.5 |
| 2 | 1000 | ⚡ T1 | 🔴 Critical | MyBankingApp-iOS | Prototype Pollution in lodash (lodash@4.17.19) | Run npm update lodash or pin >= 4.17.21 in package.json |
| 3 | 1000 | ⚡ T1 | 🔴 Critical | HealthTracker-iOS | SQL Injection in SQLite Query Builder | Replace string concatenation with sqlite3_bind_text() parame |
| 4 | 1000 | ⚡ T1 | 🔴 Critical | ShopEasy-iOS | Outdated React Native with Known Vulnerabilities (react-native@0.71.8) | Update react-native to >= 0.73.0. Major version upgrade — ma |
| 5 | 500 | ⚡ T1 | 🟠 High | MyBankingApp-iOS | Vulnerable OpenSSL in Alamofire (Alamofire@5.6.4) | Update Package.swift to require Alamofire >= 5.8.0 |
| 6 | 500 | ⚡ T1 | 🟠 High | HealthTracker-iOS | Denial of Service in libexpat (libexpat@2.5.0) | Update CocoaPods dependency to pull libexpat >= 2.6.4 |
| 7 | 500 | ⚡ T1 | 🟠 High | ShopEasy-iOS | Insecure App Transport Security Configuration | Set NSAllowsArbitraryLoads to NO; add exception domains only |
| 8 | 250 | 🔨 T3 | 🟠 High | ShopEasy-iOS | Buffer Overflow in hermes-engine (hermes-engine@0.71.14) | Upgrade to version 0.73.0 — breaking changes possible |
| 9 | 160 | 🔧 T2 | 🟡 Medium | HealthTracker-iOS | ReDoS in Realm Query Parser (Realm@10.44.0) | Upgrade to version 10.45.0 |
| 10 | 150 | ✏️ T4 | 🟠 High | HealthTracker-iOS | Insecure Data Storage — Keychain Missing Accessibility | SAST finding — requires manual code review and fix |
| 11 | 150 | ✏️ T4 | 🟠 High | MyBankingApp-iOS | Missing Certificate Pinning | SAST finding — requires manual code review and fix |
| 12 | 150 | ✏️ T4 | 🟠 High | ShopEasy-iOS | Hardcoded API Key in Source Code | Secret Detection finding — requires manual code review and f |
| 13 | 60 | ✏️ T4 | 🟡 Medium | MyBankingApp-iOS | Information Disclosure via Error Messages | SAST finding — requires manual code review and fix |
| 14 | 50 | ⚡ T1 | 🔵 Low | ShopEasy-iOS | Outdated follow-redirects Dependency (follow-redirects@1.15.3) | Run npm update follow-redirects |

## Quick Wins — Fix These First

These issues have auto-fix or minor version bump available and offer the best remediation ROI:

### ⚡ [Critical] Remote Code Execution in libxml2

- **Issue ID:** ISS-001
- **App:** MyBankingApp-iOS
- **ROI Score:** 1000
- **Tier:** T1 — Auto-Fix Available
- **Library:** libxml2@2.11.6 (CocoaPods)
- **CVEs:** CVE-2024-40896, CVE-2024-34459
- **Fix:** Auto-fix: Upgrade libxml2 to 2.12.5+
- **Action:** Update CocoaPods dependency to pull libxml2 >= 2.12.5

### ⚡ [Critical] Prototype Pollution in lodash

- **Issue ID:** ISS-002
- **App:** MyBankingApp-iOS
- **ROI Score:** 1000
- **Tier:** T1 — Auto-Fix Available
- **Library:** lodash@4.17.19 (npm)
- **CVEs:** CVE-2021-23337, CVE-2020-28500
- **Fix:** Auto-fix: Upgrade lodash to 4.17.21
- **Action:** Run npm update lodash or pin >= 4.17.21 in package.json

### ⚡ [Critical] SQL Injection in SQLite Query Builder

- **Issue ID:** ISS-005
- **App:** HealthTracker-iOS
- **ROI Score:** 1000
- **Tier:** T1 — Auto-Fix Available
- **Fix:** Auto-fix (code change): Use parameterized SQLite queries
- **Action:** Replace string concatenation with sqlite3_bind_text() parameterized query.

### ⚡ [Critical] Outdated React Native with Known Vulnerabilities

- **Issue ID:** ISS-010
- **App:** ShopEasy-iOS
- **ROI Score:** 1000
- **Tier:** T1 — Auto-Fix Available
- **Library:** react-native@0.71.8 (npm)
- **CVEs:** CVE-2024-21514, CVE-2024-28244
- **Fix:** Auto-fix (major upgrade): Upgrade React Native to 0.73+
- **Action:** Update react-native to >= 0.73.0. Major version upgrade — may require code changes.
- **Warning:** Breaking changes possible

### ⚡ [High] Vulnerable OpenSSL in Alamofire

- **Issue ID:** ISS-006
- **App:** MyBankingApp-iOS
- **ROI Score:** 500
- **Tier:** T1 — Auto-Fix Available
- **Library:** Alamofire@5.6.4 (Swift Package Manager)
- **CVEs:** CVE-2024-0727, CVE-2023-5678
- **Fix:** Auto-fix (major upgrade): Upgrade Alamofire to 5.8+
- **Action:** Update Package.swift to require Alamofire >= 5.8.0
- **Warning:** Breaking changes possible

### ⚡ [High] Denial of Service in libexpat

- **Issue ID:** ISS-008
- **App:** HealthTracker-iOS
- **ROI Score:** 500
- **Tier:** T1 — Auto-Fix Available
- **Library:** libexpat@2.5.0 (CocoaPods)
- **CVEs:** CVE-2024-50602
- **Fix:** Auto-fix: Upgrade libexpat to 2.6.4+
- **Action:** Update CocoaPods dependency to pull libexpat >= 2.6.4

### ⚡ [High] Insecure App Transport Security Configuration

- **Issue ID:** ISS-009
- **App:** ShopEasy-iOS
- **ROI Score:** 500
- **Tier:** T1 — Auto-Fix Available
- **Fix:** Auto-fix (code change): Remove NSAllowsArbitraryLoads from Info.plist
- **Action:** Set NSAllowsArbitraryLoads to NO; add exception domains only for required HTTP hosts.

### 🔧 [Medium] ReDoS in Realm Query Parser

- **Issue ID:** ISS-011
- **App:** HealthTracker-iOS
- **ROI Score:** 160
- **Tier:** T2 — Minor/Patch Version Bump
- **Library:** Realm@10.44.0 (CocoaPods)
- **CVEs:** CVE-2024-41110
- **Fix:** Minor/patch version fix available: 10.45.0
- **Action:** Upgrade to version 10.45.0

### ⚡ [Low] Outdated follow-redirects Dependency

- **Issue ID:** ISS-014
- **App:** ShopEasy-iOS
- **ROI Score:** 50
- **Tier:** T1 — Auto-Fix Available
- **Library:** follow-redirects@1.15.3 (npm)
- **CVEs:** CVE-2024-28849
- **Fix:** Auto-fix: Upgrade follow-redirects to 1.15.6+
- **Action:** Run npm update follow-redirects

## Breaking Change Warnings

These fixes involve major version upgrades that may require code changes:

- **Outdated React Native with Known Vulnerabilities** (ShopEasy-iOS)
  - react-native: 0.71.8 → 0.73.0
  - Auto-fix (major upgrade): Upgrade React Native to 0.73+
- **Vulnerable OpenSSL in Alamofire** (MyBankingApp-iOS)
  - Alamofire: 5.6.4 → 5.8.0
  - Auto-fix (major upgrade): Upgrade Alamofire to 5.8+
- **Buffer Overflow in hermes-engine** (ShopEasy-iOS)
  - hermes-engine: 0.71.14 → 0.73.0
  - Major version upgrade required: 0.73.0

## Recommendations

1. **Start with auto-fixes:** 8 issues (57%) can be auto-remediated. Apply these immediately for maximum risk reduction with minimal effort.
2. **Apply minor version bumps:** 1 additional issue(s) fixable with backward-compatible version updates.
3. **Plan major upgrades:** 3 issue(s) require major version upgrades. Schedule these in sprint planning with proper testing.
4. **Investigate manual fixes:** 4 issue(s) need manual investigation. Triage these by severity in code review sessions.

**Impact projection:** Fixing all quick wins (Tiers 1-2) would address 72% of the total severity-weighted risk.
