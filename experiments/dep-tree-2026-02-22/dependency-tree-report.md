# Dependency Tree Analysis Report
Generated: 2026-02-22T14:38:57.604Z
**Note: Generated with mock data (no API key configured)**

## Overview

| Metric | Count |
|--------|-------|
| Apps analyzed | 3 |
| Total libraries | 33 |
| Direct dependencies | 18 |
| Transitive dependencies | 15 |
| Transitive risk hotspots | 11 |

## App Risk Summary

| App | Direct | Transitive | Total Risk | Transitive Risk % | Vulns (D/T) |
|-----|--------|------------|------------|-------------------|-------------|
| ShopEasy-iOS | 7 | 7 | 52.1 | 52% | 4/5 |
| MyBankingApp-iOS | 6 | 4 | 52 | 44% | 6/5 |
| HealthTracker-iOS | 5 | 4 | 12 | 83% | 1/4 |

## Transitive Risk Hotspots

These transitive dependencies introduce the most risk and are not under your direct control:

### libxml2@2.11.6 (Risk: 15)
- **App**: MyBankingApp-iOS
- **Introduced by**: Ono
- **Reason**: Ono uses libxml2 for HTML/XML parsing
- **Vulnerabilities**: C:1 H:1 M:0 L:0
- **Source**: CocoaPods
- **Remediation**: Update or replace `Ono` to pull a patched version of `libxml2`

### hermes-engine@0.71.14 (Risk: 15)
- **App**: ShopEasy-iOS
- **Introduced by**: react-native
- **Reason**: React Native bundles Hermes JS engine
- **Vulnerabilities**: C:1 H:1 M:0 L:0
- **Source**: npm
- **Remediation**: Update or replace `react-native` to pull a patched version of `hermes-engine`

### jsc-android@250231.0.0 (Risk: 9)
- **App**: ShopEasy-iOS
- **Introduced by**: react-native
- **Reason**: Fallback JavaScriptCore engine
- **Vulnerabilities**: C:0 H:1 M:0 L:0
- **Source**: npm
- **Flags**: DEPRECATED
- **Remediation**: Update or replace `react-native` to pull a patched version of `jsc-android`

### OpenSSL@1.1.1w (Risk: 7)
- **App**: MyBankingApp-iOS
- **Introduced by**: Alamofire
- **Reason**: Alamofire 5.6.x bundles OpenSSL for TLS
- **Vulnerabilities**: C:0 H:1 M:1 L:0
- **Source**: CocoaPods
- **Remediation**: Update or replace `Alamofire` to pull a patched version of `OpenSSL`

### libexpat@2.5.0 (Risk: 5)
- **App**: HealthTracker-iOS
- **Introduced by**: Charts
- **Reason**: Charts uses XML for config/data import
- **Vulnerabilities**: C:0 H:1 M:0 L:0
- **Source**: CocoaPods
- **Remediation**: Update or replace `Charts` to pull a patched version of `libexpat`

### RealmCore@13.26.0 (Risk: 3)
- **App**: HealthTracker-iOS
- **Introduced by**: Realm
- **Reason**: Realm Swift wraps RealmCore C++ engine
- **Vulnerabilities**: C:0 H:0 M:1 L:1
- **Source**: CocoaPods
- **Remediation**: Update or replace `Realm` to pull a patched version of `RealmCore`

### libuv@1.44.2 (Risk: 2)
- **App**: HealthTracker-iOS
- **Introduced by**: Realm
- **Reason**: RealmCore uses libuv for async I/O
- **Vulnerabilities**: C:0 H:0 M:1 L:0
- **Source**: CocoaPods
- **Remediation**: Update or replace `Realm` to pull a patched version of `libuv`

### metro@0.76.8 (Risk: 2)
- **App**: ShopEasy-iOS
- **Introduced by**: react-native
- **Reason**: Metro bundler for JS compilation
- **Vulnerabilities**: C:0 H:0 M:1 L:0
- **Source**: npm
- **Remediation**: Update or replace `react-native` to pull a patched version of `metro`

### BoringSSL-GRPC@0.0.27 (Risk: 1)
- **App**: MyBankingApp-iOS
- **Introduced by**: Alamofire
- **Reason**: gRPC plugin uses BoringSSL
- **Vulnerabilities**: C:0 H:0 M:0 L:1
- **Source**: CocoaPods
- **Remediation**: Update or replace `Alamofire` to pull a patched version of `BoringSSL-GRPC`

### follow-redirects@1.15.3 (Risk: 1)
- **App**: ShopEasy-iOS
- **Introduced by**: axios
- **Reason**: axios uses follow-redirects for HTTP
- **Vulnerabilities**: C:0 H:0 M:0 L:1
- **Source**: npm
- **Remediation**: Update or replace `axios` to pull a patched version of `follow-redirects`

### abseil-cpp@1.20230802.0 (Risk: 0.1)
- **App**: ShopEasy-iOS
- **Introduced by**: react-native-firebase
- **Reason**: Firebase depends on abseil C++ lib
- **Vulnerabilities**: C:0 H:0 M:0 L:0
- **Source**: CocoaPods
- **Remediation**: Update or replace `react-native-firebase` to pull a patched version of `abseil-cpp`

## Dependency Trees

Visual representation of direct → transitive dependency chains:

```
MyBankingApp-iOS
  |-- Alamofire@5.6.4 (Swift Package Manager) [RISK: 12]
  |   |-- OpenSSL@1.1.1w (CocoaPods) [RISK: 7]
  |   |-- CFNetwork@0.0.0 (System)
  |   +-- BoringSSL-GRPC@0.0.27 (CocoaPods) [RISK: 1]
  |-- lodash@4.17.19 (npm) [RISK: 12]
  |-- Ono@2.5.0 (CocoaPods) [RISK: 3] {NOT-MAINTAINED}
  |   +-- libxml2@2.11.6 (CocoaPods) [RISK: 15]
  |-- CryptoSwift@1.7.2 (Swift Package Manager) [RISK: 2]
  |-- KeychainAccess@4.2.2 (CocoaPods)
  +-- SwiftLint@0.54.0 (Swift Package Manager)
```

```
HealthTracker-iOS
  |-- Realm@10.44.0 (CocoaPods) [RISK: 2]
  |   |-- RealmCore@13.26.0 (CocoaPods) [RISK: 3]
  |   +-- libuv@1.44.2 (CocoaPods) [RISK: 2]
  |-- SQLite.swift@0.14.1 (CocoaPods)
  |   +-- sqlite3@3.42.0 (System)
  |-- Charts@5.0.0 (CocoaPods)
  |   +-- libexpat@2.5.0 (CocoaPods) [RISK: 5]
  |-- HealthKit@17.0 (System)
  +-- SnapKit@5.6.0 (CocoaPods)
```

```
ShopEasy-iOS
  |-- react-native@0.71.8 (npm) [RISK: 20]
  |   |-- hermes-engine@0.71.14 (npm) [RISK: 15]
  |   |-- jsc-android@250231.0.0 (npm) [RISK: 9] {DEPRECATED}
  |   +-- metro@0.76.8 (npm) [RISK: 2]
  |-- moment@2.29.4 (npm) [RISK: 3] {NOT-MAINTAINED}
  |-- stripe-react-native@0.35.0 (npm) [RISK: 2]
  |-- react@18.2.0 (npm)
  |-- @react-navigation/native@6.1.9 (npm)
  |-- axios@1.6.0 (npm)
  |   +-- follow-redirects@1.15.3 (npm) [RISK: 1]
  +-- react-native-firebase@18.6.0 (npm)
      |-- nanopb@2.30909.0 (CocoaPods)
      |-- GoogleUtilities@7.12.0 (CocoaPods)
      +-- abseil-cpp@1.20230802.0 (CocoaPods) [RISK: 0.1]
```

## Per-App Detailed Analysis

### ShopEasy-iOS

- **Dependencies**: 7 direct, 7 transitive
- **Total risk score**: 52.1 (52% from transitive deps)
- **Vulnerabilities**: 9 total (4 direct, 5 transitive)
- **Flagged libraries**: 2
- **Riskiest direct dep**: react-native@0.71.8 (risk: 20)
- **Riskiest transitive dep**: hermes-engine@0.71.14 (risk: 15)

#### Direct Dependencies

| Library | Version | Source | Risk | Vulns | Flags |
|---------|---------|--------|------|-------|-------|
| react-native | 0.71.8 | npm | 20 | 3 | - |
| moment | 2.29.4 | npm | 3 | 0 | NOT-MAINTAINED |
| stripe-react-native | 0.35.0 | npm | 2 | 1 | - |
| react | 18.2.0 | npm | 0 | 0 | - |
| @react-navigation/native | 6.1.9 | npm | 0 | 0 | - |
| axios | 1.6.0 | npm | 0 | 0 | - |
| react-native-firebase | 18.6.0 | npm | 0 | 0 | - |

#### Transitive Dependencies

| Library | Version | Source | Risk | Vulns | Introduced By | Flags |
|---------|---------|--------|------|-------|---------------|-------|
| hermes-engine | 0.71.14 | npm | 15 | 2 | react-native | - |
| jsc-android | 250231.0.0 | npm | 9 | 1 | react-native | DEPRECATED |
| metro | 0.76.8 | npm | 2 | 1 | react-native | - |
| follow-redirects | 1.15.3 | npm | 1 | 1 | axios | - |
| abseil-cpp | 1.20230802.0 | CocoaPods | 0.1 | 0 | react-native-firebase | - |
| nanopb | 2.30909.0 | CocoaPods | 0 | 0 | react-native-firebase | - |
| GoogleUtilities | 7.12.0 | CocoaPods | 0 | 0 | react-native-firebase | - |

### MyBankingApp-iOS

- **Dependencies**: 6 direct, 4 transitive
- **Total risk score**: 52 (44% from transitive deps)
- **Vulnerabilities**: 11 total (6 direct, 5 transitive)
- **Flagged libraries**: 1
- **Riskiest direct dep**: Alamofire@5.6.4 (risk: 12)
- **Riskiest transitive dep**: libxml2@2.11.6 (risk: 15)

#### Direct Dependencies

| Library | Version | Source | Risk | Vulns | Flags |
|---------|---------|--------|------|-------|-------|
| Alamofire | 5.6.4 | Swift Package Manager | 12 | 3 | - |
| lodash | 4.17.19 | npm | 12 | 2 | - |
| Ono | 2.5.0 | CocoaPods | 3 | 0 | NOT-MAINTAINED |
| CryptoSwift | 1.7.2 | Swift Package Manager | 2 | 1 | - |
| KeychainAccess | 4.2.2 | CocoaPods | 0 | 0 | - |
| SwiftLint | 0.54.0 | Swift Package Manager | 0 | 0 | - |

#### Transitive Dependencies

| Library | Version | Source | Risk | Vulns | Introduced By | Flags |
|---------|---------|--------|------|-------|---------------|-------|
| libxml2 | 2.11.6 | CocoaPods | 15 | 2 | Ono | - |
| OpenSSL | 1.1.1w | CocoaPods | 7 | 2 | Alamofire | - |
| BoringSSL-GRPC | 0.0.27 | CocoaPods | 1 | 1 | Alamofire | - |
| CFNetwork | 0.0.0 | System | 0 | 0 | Alamofire | - |

### HealthTracker-iOS

- **Dependencies**: 5 direct, 4 transitive
- **Total risk score**: 12 (83% from transitive deps)
- **Vulnerabilities**: 5 total (1 direct, 4 transitive)
- **Flagged libraries**: 0
- **Riskiest direct dep**: Realm@10.44.0 (risk: 2)
- **Riskiest transitive dep**: libexpat@2.5.0 (risk: 5)

#### Direct Dependencies

| Library | Version | Source | Risk | Vulns | Flags |
|---------|---------|--------|------|-------|-------|
| Realm | 10.44.0 | CocoaPods | 2 | 1 | - |
| SQLite.swift | 0.14.1 | CocoaPods | 0 | 0 | - |
| Charts | 5.0.0 | CocoaPods | 0 | 0 | - |
| HealthKit | 17.0 | System | 0 | 0 | - |
| SnapKit | 5.6.0 | CocoaPods | 0 | 0 | - |

#### Transitive Dependencies

| Library | Version | Source | Risk | Vulns | Introduced By | Flags |
|---------|---------|--------|------|-------|---------------|-------|
| libexpat | 2.5.0 | CocoaPods | 5 | 1 | Charts | - |
| RealmCore | 13.26.0 | CocoaPods | 3 | 2 | Realm | - |
| libuv | 1.44.2 | CocoaPods | 2 | 1 | Realm | - |
| sqlite3 | 3.42.0 | System | 0 | 0 | SQLite.swift | - |

## Key Findings

### Direct Dependencies Introducing Most Transitive Risk

These direct dependencies pull in the most risky transitive deps:

| Direct Dep | Risky Transitive Deps | Total Transitive Risk | Transitive Vulns |
|------------|----------------------|----------------------|------------------|
| react-native | 3 | 26 | 4 |
| Ono | 1 | 15 | 2 |
| Alamofire | 2 | 8 | 3 |
| Charts | 1 | 5 | 1 |
| Realm | 2 | 5 | 3 |
| axios | 1 | 1 | 1 |
| react-native-firebase | 1 | 0.1 | 0 |

### Recommendations

1. **Update risky direct deps** to pull patched transitive versions
   - `react-native` introduces 3 risky transitive dep(s) with risk score 26
   - `Ono` introduces 1 risky transitive dep(s) with risk score 15
   - `Alamofire` introduces 2 risky transitive dep(s) with risk score 8
2. **Monitor unmaintained/deprecated deps** for available alternatives
3. **Consider replacing** direct deps that transitively pull known-vulnerable C/C++ libs
4. **Use lockfiles** (Podfile.lock, Package.resolved) to pin transitive versions
