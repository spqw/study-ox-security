# E13: License Compliance Check

*Generated: 2026-02-22T14:59:40.234Z*

> **Mock Mode** — using realistic sample data (no OX_API_KEY configured)

## Portfolio Overview

| Metric | Value |
|--------|-------|
| Total libraries scanned | 31 |
| Unique licenses | 11 |
| Libraries with conflicts | 4 |
| Critical conflicts | 1 |
| High conflicts | 3 |
| Medium conflicts | 0 |

## License Distribution

| Category | Count | % | Risk Level |
|----------|-------|---|------------|
| permissive | 27 | 87% | None |
| weak-copyleft | 1 | 3% | Medium |
| strong-copyleft | 2 | 6% | High/Critical |
| unknown | 1 | 3% | Medium |

### Category Definitions

- **Permissive** (MIT, BSD, Apache, ISC) — Free to use in proprietary software with minimal requirements
- **Public Domain** (CC0, Unlicense) — No restrictions at all
- **Weak Copyleft** (LGPL, MPL, EPL) — File-level copyleft; requires review for iOS static linking
- **Strong Copyleft** (GPL, AGPL, SSPL) — Viral copyleft; may require open-sourcing your app
- **Proprietary** — Commercial license; requires license agreement
- **Unknown** — No license declared; legally risky as default copyright applies

## Per-App Compliance

| App | Grade | Risk Score | Libraries | Conflicts |
|-----|-------|------------|-----------|-----------|
| MyBankingApp-iOS | **F** | 75/100 | 10 | 4 |
| ShopEasy-iOS | **D** | 35/100 | 12 | 1 |
| HealthTracker-iOS | **C** | 20/100 | 9 | 2 |

### MyBankingApp-iOS — Grade F (75/100)

**License breakdown:**

- permissive: 8 — Alamofire@5.6.4, Ono@2.5.0, KeychainAccess@4.2.2, lodash@4.17.19, SwiftLint@0.54.0, libxml2@2.11.6, OpenSSL@1.1.1w, BoringSSL-GRPC@0.0.27
- weak-copyleft: 1 — FFmpeg-iOS@4.4.3
- strong-copyleft: 1 — CryptoSwift@1.7.2

**Conflicts:**

- **[CRITICAL]** CryptoSwift@1.7.2: AGPL-3.0 license on CryptoSwift — strong copyleft may require open-sourcing your app
  > GPL/AGPL are widely considered incompatible with Apple App Store distribution. The App Store's DRM and distribution terms conflict with GPL's freedom-to-redistribute requirement.
- **[CRITICAL]** CryptoSwift@1.7.2: AGPL-3.0 is likely incompatible with Apple App Store distribution
  > AGPL requires source distribution for network interaction. Combined with App Store incompatibility, this is a critical compliance risk.
- **[MEDIUM]** FFmpeg-iOS@4.4.3: LGPL-2.1 on FFmpeg-iOS — review required for iOS static linking compliance
  > iOS apps typically link libraries statically. LGPL requires allowing re-linking, which may need special build configuration.
- **[HIGH]** FFmpeg-iOS@4.4.3: Ox Security flagged license issue on FFmpeg-iOS@4.4.3 (LGPL-2.1)
  > Ox Security's compliance engine detected a license issue with this library.

### ShopEasy-iOS — Grade D (35/100)

**License breakdown:**

- permissive: 11 — react-native@0.71.8, react@18.2.0, @react-navigation/native@6.1.9, stripe-react-native@0.35.0, moment@2.29.4, react-native-firebase@18.6.0, hermes-engine@0.71.14, jsc-android@250231.0.0, nanopb@2.30909.0, GoogleUtilities@7.12.0, analytics-swift@1.5.3
- strong-copyleft: 1 — iCarousel@1.8.3

**Conflicts:**

- **[HIGH]** iCarousel@1.8.3: GPL-3.0 license on iCarousel — strong copyleft may require open-sourcing your app
  > GPL/AGPL are widely considered incompatible with Apple App Store distribution. The App Store's DRM and distribution terms conflict with GPL's freedom-to-redistribute requirement.

### HealthTracker-iOS — Grade C (20/100)

**License breakdown:**

- permissive: 8 — SQLite.swift@0.14.1, Charts@5.0.0, Realm@10.44.0, SnapKit@5.6.0, libexpat@2.5.0, RealmCore@13.26.0, libuv@1.44.2, OpenCV@4.8.0
- unknown: 1 — FMDB@2.7.5

**Conflicts:**

- **[MEDIUM]** FMDB@2.7.5: No license declared for FMDB@2.7.5
  > Missing license means uncertain legal standing. The default copyright applies — you may not have rights to use this code.
- **[HIGH]** FMDB@2.7.5: Ox Security flagged license issue on FMDB@2.7.5 (unknown license)
  > Ox Security's compliance engine detected a license issue with this library.

## Full License Inventory

| Library | Version | App | License | Category | Risk | Conflicts | Ox Flag |
|---------|---------|-----|---------|----------|------|-----------|---------|
| CryptoSwift | 1.7.2 | MyBankingApp-iOS | AGPL-3.0 | strong-copyleft | critical | **critical** | Yes |
| iCarousel | 1.8.3 | ShopEasy-iOS | GPL-3.0 | strong-copyleft | high | **high** | Yes |
| FMDB | 2.7.5 | HealthTracker-iOS | *missing* | unknown | medium | **high** | Yes |
| FFmpeg-iOS | 4.4.3 | MyBankingApp-iOS | LGPL-2.1 | weak-copyleft | medium | **high** | Yes |
| Alamofire | 5.6.4 | MyBankingApp-iOS | MIT | permissive | none | - | - |
| Ono | 2.5.0 | MyBankingApp-iOS | MIT | permissive | none | - | - |
| KeychainAccess | 4.2.2 | MyBankingApp-iOS | MIT | permissive | none | - | - |
| lodash | 4.17.19 | MyBankingApp-iOS | MIT | permissive | none | - | - |
| SwiftLint | 0.54.0 | MyBankingApp-iOS | MIT | permissive | none | - | - |
| libxml2 | 2.11.6 | MyBankingApp-iOS | MIT | permissive | none | - | - |
| OpenSSL | 1.1.1w | MyBankingApp-iOS | OpenSSL/SSLeay | permissive | none | - | - |
| BoringSSL-GRPC | 0.0.27 | MyBankingApp-iOS | ISC | permissive | none | - | - |
| SQLite.swift | 0.14.1 | HealthTracker-iOS | MIT | permissive | none | - | - |
| Charts | 5.0.0 | HealthTracker-iOS | Apache-2.0 | permissive | none | - | - |
| Realm | 10.44.0 | HealthTracker-iOS | Apache-2.0 | permissive | none | - | - |
| SnapKit | 5.6.0 | HealthTracker-iOS | MIT | permissive | none | - | - |
| libexpat | 2.5.0 | HealthTracker-iOS | MIT | permissive | none | - | - |
| RealmCore | 13.26.0 | HealthTracker-iOS | Apache-2.0 | permissive | none | - | - |
| libuv | 1.44.2 | HealthTracker-iOS | MIT | permissive | none | - | - |
| OpenCV | 4.8.0 | HealthTracker-iOS | BSD-3-Clause | permissive | none | - | - |
| react-native | 0.71.8 | ShopEasy-iOS | MIT | permissive | none | - | - |
| react | 18.2.0 | ShopEasy-iOS | MIT | permissive | none | - | - |
| @react-navigation/native | 6.1.9 | ShopEasy-iOS | MIT | permissive | none | - | - |
| stripe-react-native | 0.35.0 | ShopEasy-iOS | MIT | permissive | none | - | - |
| moment | 2.29.4 | ShopEasy-iOS | MIT | permissive | none | - | - |
| react-native-firebase | 18.6.0 | ShopEasy-iOS | Apache-2.0 | permissive | none | - | - |
| hermes-engine | 0.71.14 | ShopEasy-iOS | MIT | permissive | none | - | - |
| jsc-android | 250231.0.0 | ShopEasy-iOS | BSD-2-Clause | permissive | none | - | - |
| nanopb | 2.30909.0 | ShopEasy-iOS | Zlib | permissive | none | - | - |
| GoogleUtilities | 7.12.0 | ShopEasy-iOS | Apache-2.0 | permissive | none | - | - |
| analytics-swift | 1.5.3 | ShopEasy-iOS | MIT | permissive | none | - | - |

## iOS App Store Compliance Notes

Apple's App Store distribution model creates unique license compliance considerations:

1. **GPL Incompatibility** — The App Store's Terms of Service include DRM and usage restrictions
   that conflict with the GPL's requirement to allow redistribution and modification. The FSF has
   [explicitly stated](https://www.fsf.org/news/2010-05-app-store-compliance) this incompatibility.

2. **LGPL Static Linking** — iOS apps commonly link dependencies statically. LGPL requires that
   users can re-link with a modified version of the LGPL library. This typically requires shipping
   object files or using dynamic frameworks.

3. **AGPL Network Clause** — AGPL extends copyleft to network interaction. While less common in
   mobile apps, any server-side component using AGPL requires source availability.

## Recommendations

- **[Critical]** Replace strong-copyleft libraries: CryptoSwift (AGPL-3.0), iCarousel (GPL-3.0). These are likely incompatible with App Store distribution.
- **[Critical]** CryptoSwift: AGPL/SSPL licenses have the broadest copyleft scope. Immediate replacement required for App Store apps.
- **[High]** 1 libraries with no declared license (FMDB). Contact maintainers or find alternatives with clear licensing.
- **[Medium]** Review weak-copyleft libraries for static linking compliance: FFmpeg-iOS (LGPL-2.1). Consider using dynamic frameworks or verify re-linking requirements are met.
- **[High]** MyBankingApp-iOS has compliance grade F (score 75/100). Address 4 conflict(s) before App Store submission.
- **[High]** ShopEasy-iOS has compliance grade D (score 35/100). Address 1 conflict(s) before App Store submission.
- **[Medium]** Establish an approved license allowlist in your CI pipeline. Block PRs that introduce strong-copyleft or unknown licenses.
