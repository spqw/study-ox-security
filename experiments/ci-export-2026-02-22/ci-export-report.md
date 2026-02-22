# E18: CI Export Report

*Generated: 2026-02-22T15:22:06.680Z*

> **Mock Mode** — using realistic sample data (no OX_API_KEY configured)

## Gate Result: **FAIL**

### Thresholds

| Severity | Threshold | Actual | Status |
|----------|-----------|--------|--------|
| Critical | 0 | 1 | FAIL (+1) |
| High | 3 | 2 | PASS |
| Medium | unlimited | 1 | - |
| Low | unlimited | 0 | - |
| Total | unlimited | 4 | - |

### Summary

- **Total issues:** 4
- **Risk score:** 22/100
- **Apps scanned:** 1

### Issues by Severity

- **Critical:** 1
- **High:** 2
- **Medium:** 1

### Per-App Breakdown

| App | Critical | High | Medium | Low | Total | Risk |
|-----|----------|------|--------|-----|-------|------|
| HealthTracker-iOS | 1 | 2 | 1 | 0 | 4 | 22 |

### CI Integration

```yaml
# GitHub Actions example
- name: Ox Security Gate
  run: node scripts/ci-export.js > scan-results.json
  env:
    OX_API_KEY: ${{ secrets.OX_API_KEY }}
    OX_MAX_CRITICAL: 0
    OX_MAX_HIGH: 5
```

```yaml
# GitLab CI example
security_gate:
  script:
    - node scripts/ci-export.js > scan-results.json
  variables:
    OX_API_KEY: $OX_API_KEY
    OX_MAX_CRITICAL: "0"
    OX_MAX_HIGH: "5"
  artifacts:
    paths:
      - scan-results.json
    when: always
```

Exit codes: `0` = PASS, `1` = FAIL (threshold exceeded), `2` = ERROR
