# E12: iOS-Specific Vulnerability Filter

*Generated: 2026-02-22T14:55:19.212Z*

> **Mock Mode** — using realistic sample data (no OX_API_KEY configured)

## Overview

| Metric | Value |
|--------|-------|
| Total issues scanned | 14 |
| iOS-relevant issues | 12 (86%) |
| iOS SBOM libraries | 29 |
| iOS categories detected | 15 |

## Detection Methodology

Issues and SBOM libraries are classified as iOS-relevant using multiple signals:

1. **Package Manager** — CocoaPods, Swift Package Manager, Carthage
2. **Library Name** — Known iOS/Apple-platform libraries (Alamofire, KeychainAccess, etc.)
3. **Issue Text** — Pattern matching for iOS keywords (ATS, Keychain, Xcode, .swift, etc.)
4. **Ox Category** — Mobile Security category from Ox Security
5. **App Name** — Apps with "iOS" in their name (low confidence fallback)

Each match contributes to an iOS relevance score (0-100). Higher scores indicate stronger iOS-specific signals.

## Severity Breakdown

| Severity | Count |
|----------|-------|
| Critical | 4 |
| High | 6 |
| Medium | 2 |

## iOS Security Categories

### Dependency Management (3 issues)

| Category | Issues | Critical | High | Medium | Low |
|----------|--------|----------|------|--------|-----|
| CocoaPods | 2 | 1 | 1 | 0 | 0 |
| Swift Package Manager | 1 | 0 | 1 | 0 | 0 |

### Platform Security (4 issues)

| Category | Issues | Critical | High | Medium | Low |
|----------|--------|----------|------|--------|-----|
| App Transport Security | 1 | 0 | 1 | 0 | 0 |
| Keychain Security | 1 | 0 | 1 | 0 | 0 |
| Certificate Pinning | 1 | 0 | 1 | 0 | 0 |
| Biometrics | 1 | 0 | 0 | 1 | 0 |

### Configuration (2 issues)

| Category | Issues | Critical | High | Medium | Low |
|----------|--------|----------|------|--------|-----|
| Plist Configuration | 2 | 0 | 2 | 0 | 0 |

### Code Analysis (2 issues)

| Category | Issues | Critical | High | Medium | Low |
|----------|--------|----------|------|--------|-----|
| Swift Code | 1 | 1 | 0 | 0 | 0 |
| WebView Security | 1 | 0 | 0 | 1 | 0 |

### Third-Party SDKs (3 issues)

| Category | Issues | Critical | High | Medium | Low |
|----------|--------|----------|------|--------|-----|
| React Native (iOS) | 1 | 1 | 0 | 0 | 0 |
| Firebase SDK | 1 | 0 | 1 | 0 | 0 |
| iOS Networking | 1 | 0 | 1 | 0 | 0 |

### Other iOS Signals (21 issues)

| Category | Issues | Critical | High | Medium | Low |
|----------|--------|----------|------|--------|-----|
| iOS Library | 4 | 2 | 2 | 0 | 0 |
| iOS App Context | 12 | 4 | 6 | 2 | 0 |
| Mobile Security | 5 | 0 | 3 | 2 | 0 |

## iOS-Specific Issues

| Severity | Issue | App | iOS Category | Score | Library |
|----------|-------|-----|-------------|-------|---------|
| **Critical** | Remote Code Execution in libxml2 | MyBankingApp-iOS | CocoaPods | 100 | libxml2@2.11.6 |
| **Critical** | Outdated React Native with Known Vulnerabilities | ShopEasy-iOS | iOS Library | 95 | react-native@0.71.8 |
| **Critical** | SQL Injection in SQLite Query Builder | HealthTracker-iOS | Swift Code | 75 | - |
| **Critical** | Prototype Pollution in lodash | MyBankingApp-iOS | iOS App Context | 30 | lodash@4.17.19 |
| **High** | Insecure Data Storage — Keychain Missing Accessibility | HealthTracker-iOS | Keychain Security | 100 | - |
| **High** | Missing Certificate Pinning | MyBankingApp-iOS | Certificate Pinning | 100 | - |
| **High** | Vulnerable OpenSSL in Alamofire | MyBankingApp-iOS | Swift Package Manager | 100 | Alamofire@5.6.4 |
| **High** | Denial of Service in libexpat | HealthTracker-iOS | CocoaPods | 100 | libexpat@2.5.0 |
| **High** | Insecure App Transport Security Configuration | ShopEasy-iOS | App Transport Security | 100 | - |
| **High** | Hardcoded API Key in Source Code | ShopEasy-iOS | Plist Configuration | 95 | - |
| **Medium** | UIWebView Deprecated Usage | HealthTracker-iOS | WebView Security | 90 | - |
| **Medium** | Biometric Authentication Bypass | MyBankingApp-iOS | Biometrics | 90 | - |

## Vulnerable iOS Libraries

| Library | Version | App | Level | C | H | M | L | Flags |
|---------|---------|-----|-------|---|---|---|---|-------|
| Alamofire | 5.6.4 | MyBankingApp-iOS | Direct | 0 | 2 | 1 | 0 | - |
| react-native | 0.71.8 | ShopEasy-iOS | Direct | 1 | 2 | 0 | 0 | - |
| lodash | 4.17.19 | MyBankingApp-iOS | Direct | 1 | 0 | 1 | 0 | - |
| libxml2 | 2.11.6 | MyBankingApp-iOS | Transitive | 1 | 1 | 0 | 0 | - |
| OpenSSL | 1.1.1w | MyBankingApp-iOS | Transitive | 0 | 1 | 1 | 0 | - |
| RealmCore | 13.26.0 | HealthTracker-iOS | Transitive | 0 | 0 | 1 | 1 | - |
| hermes-engine | 0.71.14 | ShopEasy-iOS | Transitive | 1 | 1 | 0 | 0 | - |
| CryptoSwift | 1.7.2 | MyBankingApp-iOS | Direct | 0 | 0 | 1 | 0 | - |
| BoringSSL-GRPC | 0.0.27 | MyBankingApp-iOS | Transitive | 0 | 0 | 0 | 1 | - |
| Realm | 10.44.0 | HealthTracker-iOS | Direct | 0 | 0 | 1 | 0 | - |
| libexpat | 2.5.0 | HealthTracker-iOS | Transitive | 0 | 1 | 0 | 0 | - |
| libuv | 1.44.2 | HealthTracker-iOS | Transitive | 0 | 0 | 1 | 0 | - |
| stripe-react-native | 0.35.0 | ShopEasy-iOS | Direct | 0 | 0 | 1 | 0 | - |
| jsc-android | 250231.0.0 | ShopEasy-iOS | Transitive | 0 | 1 | 0 | 0 | Deprecated |

## Full iOS SBOM

Total iOS-relevant libraries: 29

### MyBankingApp-iOS (10 iOS libs)

| Library | Version | Level | Source | Vulns | Confidence |
|---------|---------|-------|--------|-------|------------|
| Alamofire | 5.6.4 | Direct | Swift Package Manager | 3 | high |
| Ono | 2.5.0 | Direct | CocoaPods | 0 | high |
| KeychainAccess | 4.2.2 | Direct | Swift Package Manager | 0 | high |
| CryptoSwift | 1.7.2 | Direct | Swift Package Manager | 1 | high |
| lodash | 4.17.19 | Direct | npm | 2 | low |
| SwiftLint | 0.54.0 | Direct | Swift Package Manager | 0 | high |
| libxml2 | 2.11.6 | Transitive | CocoaPods | 2 | high |
| OpenSSL | 1.1.1w | Transitive | CocoaPods | 2 | high |
| BoringSSL-GRPC | 0.0.27 | Transitive | CocoaPods | 1 | high |
| CFNetwork | 0.0.0 | Transitive | iOS SDK | 0 | high |

### HealthTracker-iOS (9 iOS libs)

| Library | Version | Level | Source | Vulns | Confidence |
|---------|---------|-------|--------|-------|------------|
| SQLite.swift | 0.14.1 | Direct | Swift Package Manager | 0 | high |
| Charts | 5.0.0 | Direct | Swift Package Manager | 0 | high |
| Realm | 10.44.0 | Direct | CocoaPods | 1 | high |
| HealthKit | 17.0 | Direct | iOS SDK | 0 | high |
| SnapKit | 5.6.0 | Direct | Swift Package Manager | 0 | high |
| libexpat | 2.5.0 | Transitive | CocoaPods | 1 | high |
| RealmCore | 13.26.0 | Transitive | CocoaPods | 2 | high |
| libuv | 1.44.2 | Transitive | CocoaPods | 1 | high |
| sqlite3 | 3.42.0 | Transitive | CocoaPods | 0 | high |

### ShopEasy-iOS (10 iOS libs)

| Library | Version | Level | Source | Vulns | Confidence |
|---------|---------|-------|--------|-------|------------|
| react-native | 0.71.8 | Direct | npm | 3 | high |
| react | 18.2.0 | Direct | npm | 0 | low |
| @react-navigation/native | 6.1.9 | Direct | npm | 0 | low |
| stripe-react-native | 0.35.0 | Direct | npm | 1 | high |
| moment | 2.29.4 | Direct | npm | 0 | low |
| react-native-firebase | 18.6.0 | Direct | npm | 0 | high |
| hermes-engine | 0.71.14 | Transitive | npm | 2 | high |
| jsc-android | 250231.0.0 | Transitive | npm | 1 | high |
| nanopb | 2.30909.0 | Transitive | CocoaPods | 0 | high |
| GoogleUtilities | 7.12.0 | Transitive | CocoaPods | 0 | high |

## Recommendations

- **[Critical]** 1 critical vulnerabilities in CocoaPods dependencies. Run `pod update` and verify transitive dependency versions.
- **[High]** App Transport Security is misconfigured. Remove NSAllowsArbitraryLoads and use exception domains only for specific legacy hosts.
- **[High]** Certificate pinning is missing. Implement TrustKit or URLSession certificate pinning for all API connections, especially for financial/health data.
- **[High]** Keychain accessibility attributes are not properly set. Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly for sensitive credentials.
- **[High]** React Native version has known vulnerabilities in the Hermes engine. Upgrade to the latest stable React Native release.
- **[Medium]** Migrate from deprecated UIWebView to WKWebView. Apple may reject App Store submissions using UIWebView.
- **[Medium]** Review biometric authentication implementation. Ensure fallback passcode does not bypass biometric requirement without delay.
- **[Medium]** Firebase configuration files (GoogleService-Info.plist) should not be committed to source control. Use environment-specific configs.
- **[Medium]** 2 unmaintained iOS libraries detected (Ono, moment). Plan migration to actively maintained alternatives.
- **[Medium]** 1 deprecated iOS libraries (jsc-android). Replace with current alternatives to avoid unpatched vulnerabilities.
- **[High]** Code vulnerabilities detected in Swift source files. Review parameterized query usage and input validation patterns.
