# E11: Composite Risk Scoring Model

*Generated: 2026-02-22T14:50:27.322Z*

> **Mock Mode** — using realistic sample data (no OX_API_KEY configured)

## Scoring Methodology

Five risk dimensions are independently scored 0-100 (higher = more risk), then combined with weighted averaging:

| Dimension | Weight | Description |
|-----------|--------|-------------|
| Issue Risk | 35% | Weighted severity counts (C*10, H*5, M*2, L*0.5) |
| SBOM Health | 25% | Ratio of vulnerable libraries to total libraries |
| Transitive Risk | 15% | Percentage of total risk coming from transitive dependencies |
| Maintenance Debt | 15% | Deprecated, unmaintained, and license-issue libraries |
| Ox Risk Score | 10% | Ox Security's built-in risk assessment |

**Grades:** A (0-20 Excellent) | B (21-40 Good) | C (41-60 Moderate) | D (61-80 Poor) | F (81-100 Critical)

## Risk Comparison Matrix

| App | Composite | Grade | Issue Risk | SBOM | Transitive | Maint Debt | Ox Risk | Priority |
|-----|-----------|-------|------------|------|------------|------------|---------|----------|
| MyBankingApp-iOS | **79**/100 | **D** Poor | 100 | 100 | 46 | 33 | 72 | Critical |
| ShopEasy-iOS | **76**/100 | **D** Poor | 82 | 92 | 51 | 64 | 68 | Medium |
| HealthTracker-iOS | **60**/100 | **C** Moderate | 57 | 89 | 83 | 0 | 55 | High |

## Per-App Risk Profiles

### MyBankingApp-iOS — Grade D (79/100)

- **Type:** Mobile
- **Business Priority:** Critical
- **Owners:** Alice Chen
- **Tags:** ios, fintech
- **Issues:** Critical: 3, High: 8, Medium: 14, Low: 25
- **SBOM:** 10 libraries (6 direct, 4 transitive)
- **Vulnerable libraries:** 6/10
- **Flags:** 0 deprecated, 1 unmaintained, 0 license issues

#### Dimension Scores

```
  Issue Risk         ██████████████████████████████ 100/100
  SBOM Health        ██████████████████████████████ 100/100
  Transitive Risk    ██████████████░░░░░░░░░░░░░░░░  46/100
  Maintenance Debt   ██████████░░░░░░░░░░░░░░░░░░░░  33/100
  Ox Risk Score      ██████████████████████░░░░░░░░  72/100
```

#### Top Risky Libraries

| Library | Version | Level | C | H | M | L | Risk Weight |
|---------|---------|-------|---|---|---|---|-------------|
| libxml2 | 2.11.6 | Transitive | 1 | 1 | 0 | 0 | 15 |
| Alamofire | 5.6.4 | Direct | 0 | 2 | 1 | 0 | 12 |
| lodash | 4.17.19 | Direct | 1 | 0 | 1 | 0 | 12 |
| OpenSSL | 1.1.1w | Transitive | 0 | 1 | 1 | 0 | 7 |
| CryptoSwift | 1.7.2 | Direct | 0 | 0 | 1 | 0 | 2 |

### ShopEasy-iOS — Grade D (76/100)

- **Type:** Mobile
- **Business Priority:** Medium
- **Owners:** Carol Li
- **Tags:** ios, ecommerce
- **Issues:** Critical: 2, High: 6, Medium: 11, Low: 20
- **SBOM:** 13 libraries (7 direct, 6 transitive)
- **Vulnerable libraries:** 6/13
- **Flags:** 1 deprecated, 1 unmaintained, 0 license issues

#### Dimension Scores

```
  Issue Risk         █████████████████████████░░░░░  82/100
  SBOM Health        ████████████████████████████░░  92/100
  Transitive Risk    ███████████████░░░░░░░░░░░░░░░  51/100
  Maintenance Debt   ███████████████████░░░░░░░░░░░  64/100
  Ox Risk Score      ████████████████████░░░░░░░░░░  68/100
```

#### Top Risky Libraries

| Library | Version | Level | C | H | M | L | Risk Weight |
|---------|---------|-------|---|---|---|---|-------------|
| react-native | 0.71.8 | Direct | 1 | 2 | 0 | 0 | 20 |
| hermes-engine | 0.71.14 | Transitive | 1 | 1 | 0 | 0 | 15 |
| jsc-android | 250231.0.0 | Transitive | 0 | 1 | 0 | 0 | 5 |
| stripe-react-native | 0.35.0 | Direct | 0 | 0 | 1 | 0 | 2 |
| metro | 0.76.8 | Transitive | 0 | 0 | 1 | 0 | 2 |

### HealthTracker-iOS — Grade C (60/100)

- **Type:** Mobile
- **Business Priority:** High
- **Owners:** Bob Park
- **Tags:** ios, healthcare
- **Issues:** Critical: 1, High: 4, Medium: 9, Low: 18
- **SBOM:** 9 libraries (5 direct, 4 transitive)
- **Vulnerable libraries:** 4/9

#### Dimension Scores

```
  Issue Risk         █████████████████░░░░░░░░░░░░░  57/100
  SBOM Health        ███████████████████████████░░░  89/100
  Transitive Risk    █████████████████████████░░░░░  83/100
  Maintenance Debt   ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░   0/100
  Ox Risk Score      █████████████████░░░░░░░░░░░░░  55/100
```

#### Top Risky Libraries

| Library | Version | Level | C | H | M | L | Risk Weight |
|---------|---------|-------|---|---|---|---|-------------|
| libexpat | 2.5.0 | Transitive | 0 | 1 | 0 | 0 | 5 |
| RealmCore | 13.26.0 | Transitive | 0 | 0 | 1 | 1 | 2.5 |
| Realm | 10.44.0 | Direct | 0 | 0 | 1 | 0 | 2 |
| libuv | 1.44.2 | Transitive | 0 | 0 | 1 | 0 | 2 |

## Recommendations

- 🔴 **[Critical]** **MyBankingApp-iOS**: Very high issue burden (score 100/100). Focus on resolving critical and high severity issues first.
- 🔴 **[Critical]** **ShopEasy-iOS**: Very high issue burden (score 82/100). Focus on resolving critical and high severity issues first.
- 🟠 **[High]** **MyBankingApp-iOS**: 6/10 libraries have known vulnerabilities (score 100/100). Run dependency updates.
- 🟠 **[High]** **MyBankingApp-iOS**: Highest-risk library is libxml2@2.11.6 (risk weight 15). Check for available updates.
- 🟠 **[High]** **ShopEasy-iOS**: 6/13 libraries have known vulnerabilities (score 92/100). Run dependency updates.
- 🟠 **[High]** **ShopEasy-iOS**: Highest-risk library is react-native@0.71.8 (risk weight 20). Check for available updates.
- 🟠 **[High]** **HealthTracker-iOS**: 4/9 libraries have known vulnerabilities (score 89/100). Run dependency updates.
- 🟠 **[High]** **HealthTracker-iOS**: Highest-risk library is libexpat@2.5.0 (risk weight 5). Check for available updates.
- 🟡 **[Medium]** **ShopEasy-iOS**: Maintenance debt detected — 1 deprecated, 1 unmaintained libraries. Plan migration.
- 🟡 **[Medium]** **HealthTracker-iOS**: 83% of vulnerability risk comes from transitive dependencies. Review direct deps that pull in risky transitive deps.

## Fleet Summary

| Metric | Value |
|--------|-------|
| Apps analyzed | 3 |
| Average composite score | 72/100 [D] Poor |
| Highest risk | MyBankingApp-iOS (79/100) |
| Lowest risk | HealthTracker-iOS (60/100) |
