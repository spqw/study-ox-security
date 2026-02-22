# Issue Deep-Dive Report
Generated: 2026-02-22T14:35:15.115Z
**Note: Generated with mock data (no API key configured)**
Filter: severities=Critical,High, app=all
Issues analyzed: 10

## Severity Prioritization Overview

How Ox Security re-prioritized issues vs original scanner severity:

| Severity | Original | Ox Prioritized | Delta |
|----------|----------|----------------|-------|
| Critical | 5 | 4 | -1 |
| High | 12 | 10 | -2 |
| Medium | 45 | 38 | -7 |
| Low | 67 | 72 | +5 |
| Info | 18 | 23 | +5 |

## Enrichment Summary

| Metric | Count |
|--------|-------|
| Total issues analyzed | 10 |
| Issues with CVE data | 5 |
| Issues with auto-fix | 7 |
| Severity re-prioritized | 4 |
| Issues with library context | 5 |
| Failed to enrich | 0 |

## Auto-Fix Opportunities

These issues have automated fixes available — highest ROI for remediation:

### 🔴 [Critical] Remote Code Execution in libxml2
> CVE-2024-40896 affects libxml2 < 2.12.5 used via CocoaPods
- **Fix type**: VersionBump
- **Fix**: Upgrade libxml2 to 2.12.5+
- **Details**: Update the Ono CocoaPods dependency to a version that bundles libxml2 >= 2.12.5
- **Library**: libxml2@2.11.6 (CocoaPods)

### 🔴 [Critical] Prototype Pollution in lodash
> lodash < 4.17.21 allows prototype pollution via merge/zipObjectDeep
- **Fix type**: VersionBump
- **Fix**: Upgrade lodash to 4.17.21
- **Details**: Run npm update lodash or update package.json to pin lodash >= 4.17.21
- **Library**: lodash@4.17.19 (npm)

### 🔴 [Critical] SQL Injection in SQLite Query Builder
> User input concatenated directly into SQLite query in DataManager.swift
- **Fix type**: CodeChange
- **Fix**: Use parameterized SQLite queries
- **Details**: Replace string concatenation with sqlite3_bind_text() parameterized query to prevent SQL injection. Change: let query = "SELECT * FROM records WHERE name = '\(searchText)'" to use ? placeholder with bound parameter.

### 🟠 [High] Vulnerable OpenSSL in Alamofire
> Alamofire 5.6.x bundles OpenSSL with known CVEs
- **Fix type**: VersionBump
- **Fix**: Upgrade Alamofire to 5.8+
- **Details**: Update Package.swift to require Alamofire >= 5.8.0 which bundles patched OpenSSL
- **Library**: Alamofire@5.6.4 (Swift Package Manager)

### 🟠 [High] Denial of Service in libexpat
> CVE-2024-50602 — libexpat before 2.6.4 allows DoS via XML parsing
- **Fix type**: VersionBump
- **Fix**: Upgrade libexpat to 2.6.4+
- **Details**: Update the CocoaPods dependency to pull libexpat >= 2.6.4
- **Library**: libexpat@2.5.0 (CocoaPods)

### 🟠 [High] Insecure App Transport Security Configuration
> NSAllowsArbitraryLoads set to YES in Info.plist
- **Fix type**: CodeChange
- **Fix**: Remove NSAllowsArbitraryLoads from Info.plist
- **Details**: Set NSAllowsArbitraryLoads to NO and add exception domains only for hosts that require HTTP (e.g., legacy internal APIs)

### 🔴 [Critical] Outdated React Native with Known Vulnerabilities
> react-native 0.71.x has multiple known CVEs in bundled Hermes engine
- **Fix type**: VersionBump
- **Fix**: Upgrade React Native to 0.73+
- **Details**: Update react-native to >= 0.73.0 in package.json. This is a major version upgrade that may require code changes for breaking API changes.
- **Library**: react-native@0.71.8 (npm)

## Severity Re-Prioritizations

Issues where Ox adjusted severity from the original scanner assessment:

- **Insecure Data Storage — Keychain Missing Accessibility**: Critical → High
  - Reason: Ox determined this issue is exploitable only with physical device access, reducing effective severity (Exploitability)
- **Vulnerable OpenSSL in Alamofire**: Critical → High
  - Reason: The OpenSSL vulnerabilities in this context are limited to denial of service; no remote code execution is possible through Alamofire usage pattern (Exploitability)
- **Insecure App Transport Security Configuration**: Medium → High
  - Reason: Ox elevated severity because the app handles payment data, making cleartext traffic a higher risk (Business Impact)
- **Outdated React Native with Known Vulnerabilities**: High → Critical
  - Reason: Ox elevated from High to Critical because the app processes payment card data and the Hermes RCE could lead to credential theft (Business Impact)

## Detailed Issue Analysis

### 🔴 Critical Issues (4)

#### Remote Code Execution in libxml2
> CVE-2024-40896 affects libxml2 < 2.12.5 used via CocoaPods

- **Issue ID**: ISS-001
- **App**: MyBankingApp-iOS (iOS)
- **Category**: Vulnerable Dependency
- **Created**: 2025-12-15T10:30:00Z
- **Owners**: ios-team
- **Description**: libxml2 before 2.12.5 has a use-after-free in xmlXIncludeAddNode that can be triggered by crafted XML documents, leading to remote code execution. This library is pulled in transitively through the Ono CocoaPods dependency used for HTML/XML parsing.
- **Library**: libxml2@2.11.6
  - Package manager: CocoaPods
  - License: MIT
- **CVEs** (2):
  - **CVE-2024-40896** (Critical) — minor fix: 2.12.5 [link](https://nvd.nist.gov/vuln/detail/CVE-2024-40896)
  - **CVE-2024-34459** (High) — minor fix: 2.12.7 [link](https://nvd.nist.gov/vuln/detail/CVE-2024-34459)
- **Auto-fix available**: Upgrade libxml2 to 2.12.5+ (VersionBump)
  - Update the Ono CocoaPods dependency to a version that bundles libxml2 >= 2.12.5
- **Policy**: Critical SCA Policy

#### Prototype Pollution in lodash
> lodash < 4.17.21 allows prototype pollution via merge/zipObjectDeep

- **Issue ID**: ISS-002
- **App**: MyBankingApp-iOS (iOS)
- **Category**: Vulnerable Dependency
- **Created**: 2025-11-20T08:00:00Z
- **Owners**: ios-team
- **Description**: lodash versions prior to 4.17.21 are vulnerable to Prototype Pollution via the set, setWith, and zipObjectDeep functions, potentially allowing attackers to modify object prototypes and inject malicious properties.
- **Library**: lodash@4.17.19
  - Package manager: npm
  - License: MIT
- **CVEs** (2):
  - **CVE-2021-23337** (Critical) — minor fix: 4.17.21 [link](https://nvd.nist.gov/vuln/detail/CVE-2021-23337)
  - **CVE-2020-28500** (Medium) — minor fix: 4.17.21 [link](https://nvd.nist.gov/vuln/detail/CVE-2020-28500)
- **Auto-fix available**: Upgrade lodash to 4.17.21 (VersionBump)
  - Run npm update lodash or update package.json to pin lodash >= 4.17.21
- **Policy**: Critical SCA Policy

#### SQL Injection in SQLite Query Builder
> User input concatenated directly into SQLite query in DataManager.swift

- **Issue ID**: ISS-005
- **App**: HealthTracker-iOS (iOS)
- **Category**: Code Vulnerability
- **Created**: 2026-01-18T16:45:00Z
- **Owners**: ios-team
- **Description**: In DataManager.swift line 142, user-supplied search text is concatenated directly into a SQLite query string without parameterized queries. This allows SQL injection that could read or modify the local SQLite database containing health records.
- **Auto-fix available**: Use parameterized SQLite queries (CodeChange)
  - Replace string concatenation with sqlite3_bind_text() parameterized query to prevent SQL injection. Change: let query = "SELECT * FROM records WHERE name = '\(searchText)'" to use ? placeholder with bound parameter.
- **Policy**: Critical SAST Policy

#### Outdated React Native with Known Vulnerabilities
> react-native 0.71.x has multiple known CVEs in bundled Hermes engine

- **Issue ID**: ISS-010
- **App**: ShopEasy-iOS (iOS)
- **Category**: Vulnerable Dependency
- **Created**: 2026-02-10T09:00:00Z
- **Owners**: mobile-platform
- **Description**: ShopEasy uses React Native 0.71.8 which includes the Hermes JavaScript engine with known vulnerabilities. The Hermes engine has buffer overflow and type confusion issues that could allow code execution through crafted JavaScript.
- **Severity changed**: High → Critical
  - Reason: Ox elevated from High to Critical because the app processes payment card data and the Hermes RCE could lead to credential theft
- **Library**: react-native@0.71.8
  - Package manager: npm
  - License: MIT
- **CVEs** (3):
  - **CVE-2024-21514** (High) — major fix: 0.73.0 [link](https://nvd.nist.gov/vuln/detail/CVE-2024-21514)
  - **CVE-2024-28244** (High) — major fix: 0.73.0 [link](https://nvd.nist.gov/vuln/detail/CVE-2024-28244)
  - **CVE-2023-49relative** (Medium) — major fix: 0.72.0
- **Auto-fix available**: Upgrade React Native to 0.73+ (VersionBump)
  - Update react-native to >= 0.73.0 in package.json. This is a major version upgrade that may require code changes for breaking API changes.
- **Policy**: Critical SCA Policy

### 🟠 High Issues (6)

#### Insecure Data Storage — Keychain Missing Accessibility
> Sensitive credentials stored without kSecAttrAccessibleWhenUnlockedThisDeviceOnly

- **Issue ID**: ISS-003
- **App**: HealthTracker-iOS (iOS)
- **Category**: Mobile Security
- **Created**: 2026-01-05T14:20:00Z
- **Owners**: ios-security
- **Description**: The app stores sensitive authentication tokens in the iOS Keychain without specifying the kSecAttrAccessibleWhenUnlockedThisDeviceOnly attribute. This means data may be accessible when the device is locked and could be included in unencrypted backups.
- **Severity changed**: Critical → High
  - Reason: Ox determined this issue is exploitable only with physical device access, reducing effective severity
- **Policy**: iOS Security Policy

#### Missing Certificate Pinning
> App does not implement SSL/TLS certificate pinning for API connections

- **Issue ID**: ISS-004
- **App**: MyBankingApp-iOS (iOS)
- **Category**: Mobile Security
- **Created**: 2026-01-10T09:15:00Z
- **Owners**: ios-team
- **Description**: The banking application communicates with backend APIs over HTTPS but does not implement certificate pinning. An attacker with network access (e.g., rogue Wi-Fi) could perform a man-in-the-middle attack using a forged certificate trusted by the device.
- **Policy**: iOS Security Policy

#### Vulnerable OpenSSL in Alamofire
> Alamofire 5.6.x bundles OpenSSL with known CVEs

- **Issue ID**: ISS-006
- **App**: MyBankingApp-iOS (iOS)
- **Category**: Vulnerable Dependency
- **Created**: 2025-10-22T11:30:00Z
- **Owners**: ios-team
- **Description**: Alamofire 5.6.4 depends on an OpenSSL version with multiple known vulnerabilities including CVE-2024-0727 (denial of service) and CVE-2023-5678 (excessive time in DH key generation). Upgrading to Alamofire 5.8+ resolves these.
- **Severity changed**: Critical → High
  - Reason: The OpenSSL vulnerabilities in this context are limited to denial of service; no remote code execution is possible through Alamofire usage pattern
- **Library**: Alamofire@5.6.4
  - Package manager: Swift Package Manager
  - License: MIT
- **CVEs** (2):
  - **CVE-2024-0727** (High) — major fix: 5.8.0 [link](https://nvd.nist.gov/vuln/detail/CVE-2024-0727)
  - **CVE-2023-5678** (Medium) — major fix: 5.8.0 [link](https://nvd.nist.gov/vuln/detail/CVE-2023-5678)
- **Auto-fix available**: Upgrade Alamofire to 5.8+ (VersionBump)
  - Update Package.swift to require Alamofire >= 5.8.0 which bundles patched OpenSSL
- **Policy**: Critical SCA Policy

#### Hardcoded API Key in Source Code
> Firebase API key found in GoogleService-Info.plist committed to repo

- **Issue ID**: ISS-007
- **App**: ShopEasy-iOS (iOS)
- **Category**: Secret Detection
- **Created**: 2026-02-01T13:00:00Z
- **Owners**: ios-security
- **Description**: A Firebase API key is hardcoded in GoogleService-Info.plist which is committed to the repository. While Firebase API keys are generally not secret, this plist also contains the database URL and storage bucket which could be used to enumerate resources.
- **Policy**: Secrets Policy

#### Denial of Service in libexpat
> CVE-2024-50602 — libexpat before 2.6.4 allows DoS via XML parsing

- **Issue ID**: ISS-008
- **App**: HealthTracker-iOS (iOS)
- **Category**: Vulnerable Dependency
- **Created**: 2026-01-25T10:00:00Z
- **Owners**: ios-team
- **Description**: libexpat before version 2.6.4 has a vulnerability where XML_ResumeParser can crash when called after XML_StopParser, leading to a denial of service. This affects iOS apps using any XML parsing that depends on libexpat.
- **Library**: libexpat@2.5.0
  - Package manager: CocoaPods
  - License: MIT
- **CVEs** (1):
  - **CVE-2024-50602** (High) — minor fix: 2.6.4 [link](https://nvd.nist.gov/vuln/detail/CVE-2024-50602)
- **Auto-fix available**: Upgrade libexpat to 2.6.4+ (VersionBump)
  - Update the CocoaPods dependency to pull libexpat >= 2.6.4
- **Policy**: High SCA Policy

#### Insecure App Transport Security Configuration
> NSAllowsArbitraryLoads set to YES in Info.plist

- **Issue ID**: ISS-009
- **App**: ShopEasy-iOS (iOS)
- **Category**: Mobile Security
- **Created**: 2026-02-05T15:30:00Z
- **Owners**: ios-team
- **Description**: The app's Info.plist has NSAllowsArbitraryLoads set to YES under NSAppTransportSecurity, disabling App Transport Security for all connections. This allows unencrypted HTTP traffic which can be intercepted.
- **Severity changed**: Medium → High
  - Reason: Ox elevated severity because the app handles payment data, making cleartext traffic a higher risk
- **Auto-fix available**: Remove NSAllowsArbitraryLoads from Info.plist (CodeChange)
  - Set NSAllowsArbitraryLoads to NO and add exception domains only for hosts that require HTTP (e.g., legacy internal APIs)
- **Policy**: iOS Security Policy
