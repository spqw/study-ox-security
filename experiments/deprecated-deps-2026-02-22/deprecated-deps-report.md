# E14: Deprecated Dependency Alert

*Generated: 2026-02-22T15:03:49.257Z*

> **Mock Mode** — using realistic sample data (no OX_API_KEY configured)

## Portfolio Summary

| Metric | Value |
|--------|-------|
| Total libraries scanned | 36 |
| Deprecated libraries | 4 |
| Unmaintained libraries | 7 |
| Unique flagged libraries | 10 |
| Flagged with active vulnerabilities | 6 |
| Known alternatives available | 10 |
| Apps affected | 3/3 |
| Critical urgency | 0 |
| High urgency | 2 |

## Scoring Methodology

Each deprecated/unmaintained library receives a risk score (0-100):

| Factor | Max Points | Description |
|--------|-----------|-------------|
| Status | 40 | Deprecated+unmaintained=40, deprecated=35, unmaintained=25 |
| Vulnerabilities | 40 | Weighted: Critical*10, High*5, Medium*2, Low*0.5 |
| Dependency Level | 10 | Direct=10, Transitive=3 |
| License Issue | 10 | Ox-flagged license problem=10 |

**Migration Urgency:**

| Score Range | Urgency | Action |
|-------------|---------|--------|
| 80-100 | CRITICAL | Immediate replacement required |
| 60-79 | HIGH | Plan replacement within 1 sprint |
| 40-59 | MEDIUM | Schedule replacement this quarter |
| 0-39 | LOW | Monitor and replace when convenient |

## Deprecated / Unmaintained Library Alerts

| # | Library | Version | App | Level | Status | Vulns | Risk | Urgency | Alternative |
|---|---------|---------|-----|-------|--------|-------|------|---------|-------------|
| 1 | **AFNetworking** | 4.0.1 | MyBankingApp-iOS | Direct | Deprecated | C:0 H:1 M:2 L:0 | **63**/100 | HIGH | Alamofire |
| 2 | **iCarousel** | 1.8.3 | ShopEasy-iOS | Direct | Deprecated, Unmaintained, License | - | **60**/100 | HIGH | UICollectionView compositional layout |
| 3 | **jsc-android** | 250231.0.0 | ShopEasy-iOS | Transitive | Deprecated | C:0 H:1 M:0 L:0 | **48**/100 | MEDIUM | hermes-engine |
| 4 | **RNCryptor** | 5.1.0 | HealthTracker-iOS | Direct | Deprecated | - | **45**/100 | MEDIUM | CryptoKit |
| 5 | **OpenSSL** | 1.1.1w | MyBankingApp-iOS | Transitive | Unmaintained | C:0 H:1 M:1 L:0 | **42**/100 | MEDIUM | BoringSSL or Apple Security framework |
| 6 | **CocoaAsyncSocket** | 7.6.5 | MyBankingApp-iOS | Direct | Unmaintained | C:0 H:0 M:1 L:1 | **40**/100 | MEDIUM | Network.framework (NWConnection) |
| 7 | **Ono** | 2.5.0 | MyBankingApp-iOS | Direct | Unmaintained | C:0 H:0 M:1 L:0 | **39**/100 | LOW | SWXMLHash or XMLCoder |
| 8 | **FMDB** | 2.7.5 | HealthTracker-iOS | Direct | Unmaintained | C:0 H:0 M:0 L:1 | **36**/100 | LOW | SQLite.swift or GRDB.swift |
| 9 | **AsyncDisplayKit** | 3.1.0 | HealthTracker-iOS | Direct | Unmaintained | - | **35**/100 | LOW | SwiftUI or UICollectionView diffable data sources |
| 10 | **moment** | 2.29.4 | ShopEasy-iOS | Direct | Unmaintained | - | **35**/100 | LOW | date-fns or luxon |

### Migration Alternatives

#### AFNetworking -> Alamofire

- **Current:** AFNetworking@4.0.1
- **Recommended:** Alamofire
- **Reason:** AFNetworking is deprecated; Alamofire is the standard Swift networking library
- **Urgency:** HIGH (score 63/100)

#### iCarousel -> UICollectionView compositional layout

- **Current:** iCarousel@1.8.3
- **Recommended:** UICollectionView compositional layout
- **Reason:** iCarousel is unmaintained; use UIKit's built-in compositional layouts
- **Urgency:** HIGH (score 60/100)

#### jsc-android -> hermes-engine

- **Current:** jsc-android@250231.0.0
- **Recommended:** hermes-engine
- **Reason:** JSC for Android is deprecated; Hermes is the default RN JS engine since RN 0.70
- **Urgency:** MEDIUM (score 48/100)

#### RNCryptor -> CryptoKit

- **Current:** RNCryptor@5.1.0
- **Recommended:** CryptoKit
- **Reason:** Apple's CryptoKit (iOS 13+) provides native encryption APIs
- **Urgency:** MEDIUM (score 45/100)

#### OpenSSL -> BoringSSL or Apple Security framework

- **Current:** OpenSSL@1.1.1w
- **Recommended:** BoringSSL or Apple Security framework
- **Reason:** OpenSSL 1.1.x is EOL; use BoringSSL or Apple's native crypto
- **Urgency:** MEDIUM (score 42/100)

#### CocoaAsyncSocket -> Network.framework (NWConnection)

- **Current:** CocoaAsyncSocket@7.6.5
- **Recommended:** Network.framework (NWConnection)
- **Reason:** Apple's Network framework replaces third-party socket libraries
- **Urgency:** MEDIUM (score 40/100)

#### Ono -> SWXMLHash or XMLCoder

- **Current:** Ono@2.5.0
- **Recommended:** SWXMLHash or XMLCoder
- **Reason:** Ono is unmaintained since 2019; SWXMLHash is actively maintained pure Swift
- **Urgency:** LOW (score 39/100)

#### FMDB -> SQLite.swift or GRDB.swift

- **Current:** FMDB@2.7.5
- **Recommended:** SQLite.swift or GRDB.swift
- **Reason:** FMDB is an Obj-C wrapper with declining maintenance; modern Swift alternatives exist
- **Urgency:** LOW (score 36/100)

#### AsyncDisplayKit -> SwiftUI or UICollectionView diffable data sources

- **Current:** AsyncDisplayKit@3.1.0
- **Recommended:** SwiftUI or UICollectionView diffable data sources
- **Reason:** AsyncDisplayKit (Texture) has minimal maintenance
- **Urgency:** LOW (score 35/100)

#### moment -> date-fns or luxon

- **Current:** moment@2.29.4
- **Recommended:** date-fns or luxon
- **Reason:** moment.js is officially in maintenance mode since 2020; date-fns is tree-shakeable
- **Urgency:** LOW (score 35/100)

## Per-App Dependency Health

| App | Health | Total Libs | Deprecated | Unmaintained | Vulns in Flagged |
|-----|--------|-----------|------------|--------------|-----------------|
| MyBankingApp-iOS | 67% | 12 | 1 | 3 | 8 |
| HealthTracker-iOS | 70% | 10 | 1 | 2 | 1 |
| ShopEasy-iOS | 71% | 14 | 2 | 2 | 1 |

### MyBankingApp-iOS — 67% Health

- **AFNetworking@4.0.1** (Direct) — Deprecated — Risk: 63/100 HIGH
  - Vulnerabilities: 3 (C:0 H:1 M:2 L:0)
  - Migrate to: **Alamofire** — AFNetworking is deprecated; Alamofire is the standard Swift networking library
- **OpenSSL@1.1.1w** (Transitive) — Unmaintained — Risk: 42/100 MEDIUM
  - Vulnerabilities: 2 (C:0 H:1 M:1 L:0)
  - Migrate to: **BoringSSL or Apple Security framework** — OpenSSL 1.1.x is EOL; use BoringSSL or Apple's native crypto
- **CocoaAsyncSocket@7.6.5** (Direct) — Unmaintained — Risk: 40/100 MEDIUM
  - Vulnerabilities: 2 (C:0 H:0 M:1 L:1)
  - Migrate to: **Network.framework (NWConnection)** — Apple's Network framework replaces third-party socket libraries
- **Ono@2.5.0** (Direct) — Unmaintained — Risk: 39/100 LOW
  - Vulnerabilities: 1 (C:0 H:0 M:1 L:0)
  - Migrate to: **SWXMLHash or XMLCoder** — Ono is unmaintained since 2019; SWXMLHash is actively maintained pure Swift

### HealthTracker-iOS — 70% Health

- **RNCryptor@5.1.0** (Direct) — Deprecated — Risk: 45/100 MEDIUM
  - Migrate to: **CryptoKit** — Apple's CryptoKit (iOS 13+) provides native encryption APIs
- **FMDB@2.7.5** (Direct) — Unmaintained — Risk: 36/100 LOW
  - Vulnerabilities: 1 (C:0 H:0 M:0 L:1)
  - Migrate to: **SQLite.swift or GRDB.swift** — FMDB is an Obj-C wrapper with declining maintenance; modern Swift alternatives exist
- **AsyncDisplayKit@3.1.0** (Direct) — Unmaintained — Risk: 35/100 LOW
  - Migrate to: **SwiftUI or UICollectionView diffable data sources** — AsyncDisplayKit (Texture) has minimal maintenance

### ShopEasy-iOS — 71% Health

- **iCarousel@1.8.3** (Direct) — Deprecated, Unmaintained — Risk: 60/100 HIGH
  - Migrate to: **UICollectionView compositional layout** — iCarousel is unmaintained; use UIKit's built-in compositional layouts
- **jsc-android@250231.0.0** (Transitive) — Deprecated — Risk: 48/100 MEDIUM
  - Vulnerabilities: 1 (C:0 H:1 M:0 L:0)
  - Migrate to: **hermes-engine** — JSC for Android is deprecated; Hermes is the default RN JS engine since RN 0.70
- **moment@2.29.4** (Direct) — Unmaintained — Risk: 35/100 LOW
  - Migrate to: **date-fns or luxon** — moment.js is officially in maintenance mode since 2020; date-fns is tree-shakeable

## Recommendations

- **[High]** Replace AFNetworking@4.0.1 with Alamofire. AFNetworking is deprecated; Alamofire is the standard Swift networking library
- **[High]** Replace iCarousel@1.8.3 with UICollectionView compositional layout. iCarousel is unmaintained; use UIKit's built-in compositional layouts
- **[Medium]** MyBankingApp-iOS has a dependency health ratio of 67% (1 deprecated, 3 unmaintained out of 12 total). Consider a dedicated dependency cleanup sprint.
- **[Medium]** HealthTracker-iOS has a dependency health ratio of 70% (1 deprecated, 2 unmaintained out of 10 total). Consider a dedicated dependency cleanup sprint.
- **[Medium]** ShopEasy-iOS has a dependency health ratio of 71% (2 deprecated, 2 unmaintained out of 14 total). Consider a dedicated dependency cleanup sprint.
- **[Medium]** Add deprecated dependency checks to your CI pipeline. Block PRs that introduce new deprecated or unmaintained dependencies.
