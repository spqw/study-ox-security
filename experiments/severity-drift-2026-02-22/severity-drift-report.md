# E16: Severity Drift Report

*Generated: 2026-02-22T15:14:17.905Z*

> **Mock Mode** — using realistic sample data (no OX_API_KEY configured)

## What is Severity Drift?

Ox Security re-prioritizes vulnerability severity based on contextual analysis:
reachability, exploitability, business context, environment, and attack surface.
This report compares scanner-reported (original) severity with Ox-prioritized
severity to show where and why Ox adjusts risk assessments.

- **Upgraded**: Ox raised the severity (higher real-world risk than scanner reported)
- **Downgraded**: Ox lowered the severity (lower real-world risk based on context)
- **Unchanged**: Ox agrees with the scanner's severity assessment

## Overview

| Metric | Value |
|--------|-------|
| Total issues analyzed | 16 |
| Drift rate | 56% |
| ⬆️ Upgraded | 3 (19%) |
| ⬇️ Downgraded | 6 (38%) |
| ➡️ Unchanged | 7 (44%) |
| Net triage effort change | 13.0 points saved |

## Drift Magnitude Distribution

| Magnitude | Count | % | Description |
|-----------|-------|---|-------------|
| 0 | 7 | 44% | No change — Ox agrees with scanner |
| 1 | 9 | 56% | One level shift (e.g., High → Medium) |
| 2 | 0 | 0% | Two level shift (e.g., Critical → Medium) |

## Severity Drift Matrix

Rows = original scanner severity, Columns = Ox-prioritized severity.
Diagonal = unchanged. Upper-right = upgraded. Lower-left = downgraded.

| Original \ Ox | Critical | High | Medium | Low |
|--------------|----------|----------|----------|----------|
| 🔴 Critical  |  **2**  |  3  |   .   |   .   |
| 🟠 High      |  1  |  **3**  |  2  |   .   |
| 🟡 Medium    |   .   |  1  |  **1**  |  1  |
| 🔵 Low       |   .   |   .   |  1  |  **1**  |

## Aggregate Prioritization Comparison

How the overall severity distribution shifts after Ox re-prioritization:

| Severity | Original Count | Ox-Prioritized | Delta |
|----------|---------------|----------------|-------|
| 🔴 Critical | 5 | 3 | -2 |
| 🟠 High | 5 | 6 | +1 |
| 🟡 Medium | 3 | 4 | +1 |
| 🔵 Low | 2 | 2 | 0 |
| ⚪ Info | 1 | 1 | 0 |

## Triage Effort Impact

Severity-weighted measure of how Ox re-prioritization affects triage workload.
Weights: Critical=10, High=5, Medium=2, Low=0.5, Info=0

- **Effort saved by downgrades:** 22.5 weighted points
- **Effort added by upgrades:** 9.5 weighted points
- **Net effect:** Reduced triage workload by **13.0** points

> Ox prioritization reduces your triage burden — 6 issue(s) were deprioritized, saving focus for truly critical items.

## Per-App Severity Drift

| App | Total | ⬆️ Upgraded | ⬇️ Downgraded | ➡️ Unchanged | Drift Rate | Effort Saved |
|-----|-------|-----------|-------------|------------|------------|--------------|
| HealthTracker-iOS | 5 | 0 | 3 | 2 | 60% | 11.0 |
| MyBankingApp-iOS | 6 | 1 | 3 | 2 | 67% | 11.5 |
| ShopEasy-iOS | 5 | 2 | 0 | 3 | 40% | 0.0 |

## Drift by Issue Category

| Category | Total | ⬆️ Upgraded | ⬇️ Downgraded | ➡️ Unchanged | Drift Rate |
|----------|-------|-----------|-------------|------------|------------|
| Code Vulnerability | 4 | 1 | 2 | 1 | 75% |
| Mobile Security | 3 | 1 | 1 | 1 | 67% |
| Secret Detection | 1 | 0 | 0 | 1 | 0% |
| Vulnerable Dependency | 8 | 1 | 3 | 4 | 50% |

## Drift by Source Type

| Source Type | Total | ⬆️ Upgraded | ⬇️ Downgraded | ➡️ Unchanged | Drift Rate |
|------------|-------|-----------|-------------|------------|------------|
| SAST | 7 | 2 | 3 | 2 | 71% |
| SCA | 8 | 1 | 3 | 4 | 50% |
| Secret Detection | 1 | 0 | 0 | 1 | 0% |

## Severity Change Reason Analysis

Why Ox re-prioritized severity, grouped by reason category:

### Reachability (5 occurrences)

- Upgrades driven: 1 | Downgrades driven: 4
- Specific reasons:
  - Not Reachable
  - Limited Attack Surface
  - Code Path Not Exercised
  - Directly Reachable
  - Internal Input Only

### Exploitability (3 occurrences)

- Upgrades driven: 1 | Downgrades driven: 2
- Specific reasons:
  - No Known Exploit
  - No PoC
  - Active Exploits

### Business Context (3 occurrences)

- Upgrades driven: 3 | Downgrades driven: 0
- Specific reasons:
  - Sensitive Data Exposure
  - Business Critical App
  - Auth Token Risk

### Environment (2 occurrences)

- Upgrades driven: 1 | Downgrades driven: 1
- Specific reasons:
  - Production Deployment
  - Debug Only

### Attack Vector (1 occurrences)

- Upgrades driven: 0 | Downgrades driven: 1
- Specific reasons:
  - Physical Access Required

### Impact (1 occurrences)

- Upgrades driven: 0 | Downgrades driven: 1
- Specific reasons:
  - Limited DoS Impact

## ⬆️ Upgraded Issues (Scanner Underestimated)

These issues were escalated by Ox — the real-world risk is higher than scanner severity suggested:

### 🟡 Medium → 🟠 High: Insecure App Transport Security Configuration

- **Issue ID:** ISS-009
- **App:** ShopEasy-iOS
- **Category:** Mobile Security
- **Source:** SAST
- **Drift magnitude:** +1 level(s)
- **Reasons:**
  - **Sensitive Data Exposure:** App handles payment data over HTTP connections due to ATS bypass, increasing real-world risk
  - **Production Deployment:** App is deployed to production with active users
- **Detail:** NSAllowsArbitraryLoads set to YES in Info.plist

### 🟠 High → 🔴 Critical: Outdated React Native with Known Vulnerabilities

- **Issue ID:** ISS-010
- **App:** ShopEasy-iOS
- **Category:** Vulnerable Dependency
- **Source:** SCA
- **Drift magnitude:** +1 level(s)
- **Reasons:**
  - **Business Critical App:** Public-facing e-commerce app processing financial transactions
  - **Active Exploits:** Multiple CVEs with known exploits targeting Hermes engine
  - **Directly Reachable:** Vulnerability is reachable via JavaScript execution in React Native runtime
- **Detail:** react-native 0.71.x has multiple known CVEs in Hermes engine

### 🔵 Low → 🟡 Medium: Weak Random Number Generator in SecureRandom

- **Issue ID:** ISS-015
- **App:** MyBankingApp-iOS
- **Category:** Code Vulnerability
- **Source:** SAST
- **Drift magnitude:** +1 level(s)
- **Reasons:**
  - **Auth Token Risk:** Weak RNG used in authentication token generation — predictable tokens enable session hijacking
- **Detail:** Math.random() used for token generation instead of crypto

## ⬇️ Downgraded Issues (Scanner Overestimated)

These issues were deprioritized by Ox — real-world risk is lower than scanner severity suggested:

### 🔴 Critical → 🟠 High: Remote Code Execution in libxml2

- **Issue ID:** ISS-001
- **App:** MyBankingApp-iOS
- **Category:** Vulnerable Dependency
- **Source:** SCA
- **Drift magnitude:** -1 level(s)
- **Triage effort saved:** 5.0 weighted points
- **Reasons:**
  - **Not Reachable:** The vulnerable function is not directly reachable from user-controlled input based on code analysis
  - **No Known Exploit:** No known exploit in the wild for this specific version combination
- **Detail:** CVE-2024-40896 affects libxml2 < 2.12.5 used via CocoaPods

### 🔴 Critical → 🟠 High: Insecure Data Storage — Keychain Missing Accessibility

- **Issue ID:** ISS-003
- **App:** HealthTracker-iOS
- **Category:** Mobile Security
- **Source:** SAST
- **Drift magnitude:** -1 level(s)
- **Triage effort saved:** 5.0 weighted points
- **Reasons:**
  - **Physical Access Required:** Physical device access required to exploit keychain misconfiguration
- **Detail:** Sensitive credentials stored without kSecAttrAccessibleWhenUnlockedThisDeviceOnly

### 🔴 Critical → 🟠 High: Vulnerable OpenSSL in Alamofire

- **Issue ID:** ISS-006
- **App:** MyBankingApp-iOS
- **Category:** Vulnerable Dependency
- **Source:** SCA
- **Drift magnitude:** -1 level(s)
- **Triage effort saved:** 5.0 weighted points
- **Reasons:**
  - **Limited Attack Surface:** OpenSSL vulnerability requires specific TLS handshake conditions not typical in mobile apps
  - **Code Path Not Exercised:** Alamofire usage pattern does not expose vulnerable code path
- **Detail:** Alamofire 5.6.x bundles OpenSSL with known CVEs

### 🟠 High → 🟡 Medium: Denial of Service in libexpat

- **Issue ID:** ISS-008
- **App:** HealthTracker-iOS
- **Category:** Vulnerable Dependency
- **Source:** SCA
- **Drift magnitude:** -1 level(s)
- **Triage effort saved:** 3.0 weighted points
- **Reasons:**
  - **Limited DoS Impact:** DoS impact is limited to app crash (self-recovering) rather than service disruption
  - **No PoC:** No proof of concept exploit available
- **Detail:** CVE-2024-50602 — libexpat before 2.6.4 allows DoS

### 🟠 High → 🟡 Medium: Path Traversal in File Handler

- **Issue ID:** ISS-016
- **App:** HealthTracker-iOS
- **Category:** Code Vulnerability
- **Source:** SAST
- **Drift magnitude:** -1 level(s)
- **Triage effort saved:** 3.0 weighted points
- **Reasons:**
  - **Internal Input Only:** Path traversal input comes from local app storage, not external user input
- **Detail:** File path constructed from user input without sanitization

### 🟡 Medium → 🔵 Low: Information Disclosure via Error Messages

- **Issue ID:** ISS-012
- **App:** MyBankingApp-iOS
- **Category:** Code Vulnerability
- **Source:** SAST
- **Drift magnitude:** -1 level(s)
- **Triage effort saved:** 1.5 weighted points
- **Reasons:**
  - **Debug Only:** Stack traces only present in debug builds, not in production release configuration
- **Detail:** Detailed stack traces returned in API error responses

## Recommendations

1. **Prioritize upgraded issues:** 3 issue(s) were escalated by Ox. These represent hidden risks that scanners alone would underestimate. Review these first.
2. **Defer downgraded issues:** 6 issue(s) were deprioritized. Use Ox severity for sprint planning rather than raw scanner severity to reduce noise.
3. **High drift rate (56%):** Scanner severity alone is unreliable for this portfolio. Rely on Ox-prioritized severity for triage decisions.
4. **Apps with high drift:** HealthTracker-iOS, MyBankingApp-iOS have >40% severity drift. These apps benefit most from Ox contextual analysis.
5. **Reachability analysis is key:** 5 re-prioritization(s) were driven by reachability analysis. Ensure code-level scanning is connected for best results.
6. **Triage efficiency gained:** Ox prioritization saves 13.0 severity-weighted triage points. This translates to less time spent on false-positive critical findings.
