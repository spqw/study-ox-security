# API Security Scan Report
Generated: 2026-02-22T14:42:37.243Z
**Note: Generated with mock data (no API key configured)**
App filter: HealthTracker
Total endpoints scanned: 8

## Overview

| Metric | Value |
|--------|-------|
| Total API endpoints | 8 |
| Applications | 1 |
| Critical severity | 1 |
| High severity | 3 |
| Medium severity | 3 |
| Low severity | 1 |
| Info | 0 |
| Unique risk patterns detected | 6 |

## Severity Distribution

🔴 **Critical**: ██████████ 1
🟠 **High**: ██████████████████████████████ 3
🟡 **Medium**: ██████████████████████████████ 3
🔵 **Low**: ██████████ 1
⚪ **Info**:  0

## HTTP Method Distribution

| Method | Count | Percentage |
|--------|-------|------------|
| 🔵 POST | 3 | 37.5% |
| 🟢 GET | 3 | 37.5% |
| 🟡 PUT | 1 | 12.5% |
| 🔴 DELETE | 1 | 12.5% |

## Per-Application Summary

### HealthTracker-iOS (8 endpoints)

| Severity | Count |
|----------|-------|
| 🔴 Critical | 1 |
| 🟠 High | 3 |
| 🟡 Medium | 3 |
| 🔵 Low | 1 |

**Critical+High endpoints requiring attention: 4**

| Method | Path | Severity | Source File |
|--------|------|----------|-------------|
| GET | `/api/v1/health/records/{userId}` | 🔴 Critical | HealthTracker/Network/HealthRecordAPI.swift:22 |
| POST | `/api/v1/health/sync` | 🟠 High | HealthTracker/Network/HealthSyncService.swift:34 |
| POST | `/api/v1/health/vitals` | 🟠 High | HealthTracker/Network/VitalsAPI.swift:48 |
| GET | `/api/v1/health/export/pdf` | 🟠 High | HealthTracker/Network/ExportAPI.swift:29 |
| PUT | `/api/v1/health/medication/update` | 🟡 Medium | HealthTracker/Network/MedicationAPI.swift:56 |
| POST | `/api/v1/auth/biometric` | 🟡 Medium | HealthTracker/Network/AuthService.swift:63 |
| DELETE | `/api/v1/health/records/{recordId}` | 🟡 Medium | HealthTracker/Network/HealthRecordAPI.swift:78 |
| GET | `/api/v1/doctors/{doctorId}/schedule` | 🔵 Low | HealthTracker/Network/DoctorAPI.swift:17 |

## High-Risk Endpoints (Top 10)

Endpoints ranked by composite risk score (severity + pattern analysis):

### 1. GET `/api/v1/health/records/{userId}` — Risk Score: 86/100
- **App**: HealthTracker-iOS
- **Severity**: 🔴 Critical
- **Source**: HealthTracker/Network/HealthRecordAPI.swift:22
- **Discovered via**: OpenAPI (/specs/health-api.yaml)
- **Risk patterns**:
  - `HEALTH_DATA` (High) — Health/medical data endpoint (HIPAA-relevant)
  - `LEGACY_API` (Low) — Uses API v1 — possibly deprecated
  - `IDOR_RISK` (Medium) — Path contains user-controlled resource ID (potential IDOR)

### 2. GET `/api/v1/health/export/pdf` — Risk Score: 81/100
- **App**: HealthTracker-iOS
- **Severity**: 🟠 High
- **Source**: HealthTracker/Network/ExportAPI.swift:29
- **Discovered via**: CodeAnalysis
- **Risk patterns**:
  - `HEALTH_DATA` (High) — Health/medical data endpoint (HIPAA-relevant)
  - `LEGACY_API` (Low) — Uses API v1 — possibly deprecated
  - `DATA_EXPORT` (High) — Data export endpoint — bulk data exfiltration risk

### 3. DELETE `/api/v1/health/records/{recordId}` — Risk Score: 75/100
- **App**: HealthTracker-iOS
- **Severity**: 🟡 Medium
- **Source**: HealthTracker/Network/HealthRecordAPI.swift:78
- **Discovered via**: CodeAnalysis
- **Risk patterns**:
  - `HEALTH_DATA` (High) — Health/medical data endpoint (HIPAA-relevant)
  - `LEGACY_API` (Low) — Uses API v1 — possibly deprecated
  - `DESTRUCTIVE` (Medium) — Destructive operation (DELETE)
  - `IDOR_RISK` (Medium) — Path contains user-controlled resource ID (potential IDOR)

### 4. POST `/api/v1/health/sync` — Risk Score: 71/100
- **App**: HealthTracker-iOS
- **Severity**: 🟠 High
- **Source**: HealthTracker/Network/HealthSyncService.swift:34
- **Discovered via**: CodeAnalysis
- **Risk patterns**:
  - `HEALTH_DATA` (High) — Health/medical data endpoint (HIPAA-relevant)
  - `LEGACY_API` (Low) — Uses API v1 — possibly deprecated

### 5. POST `/api/v1/health/vitals` — Risk Score: 71/100
- **App**: HealthTracker-iOS
- **Severity**: 🟠 High
- **Source**: HealthTracker/Network/VitalsAPI.swift:48
- **Discovered via**: CodeAnalysis
- **Risk patterns**:
  - `HEALTH_DATA` (High) — Health/medical data endpoint (HIPAA-relevant)
  - `LEGACY_API` (Low) — Uses API v1 — possibly deprecated

### 6. PUT `/api/v1/health/medication/update` — Risk Score: 59/100
- **App**: HealthTracker-iOS
- **Severity**: 🟡 Medium
- **Source**: HealthTracker/Network/MedicationAPI.swift:56
- **Discovered via**: OpenAPI (/specs/health-api.yaml)
- **Risk patterns**:
  - `HEALTH_DATA` (High) — Health/medical data endpoint (HIPAA-relevant)
  - `LEGACY_API` (Low) — Uses API v1 — possibly deprecated

### 7. POST `/api/v1/auth/biometric` — Risk Score: 52/100
- **App**: HealthTracker-iOS
- **Severity**: 🟡 Medium
- **Source**: HealthTracker/Network/AuthService.swift:63
- **Discovered via**: CodeAnalysis
- **Risk patterns**:
  - `AUTH` (Medium) — Authentication/authorization endpoint
  - `LEGACY_API` (Low) — Uses API v1 — possibly deprecated

### 8. GET `/api/v1/doctors/{doctorId}/schedule` — Risk Score: 27/100
- **App**: HealthTracker-iOS
- **Severity**: 🔵 Low
- **Source**: HealthTracker/Network/DoctorAPI.swift:17
- **Discovered via**: CodeAnalysis
- **Risk patterns**:
  - `LEGACY_API` (Low) — Uses API v1 — possibly deprecated

## Risk Pattern Analysis

Patterns detected across all endpoints:

| Pattern | Risk Level | Occurrences | Description |
|---------|------------|-------------|-------------|
| `HEALTH_DATA` | High | 6 | Health/medical data endpoint (HIPAA-relevant) |
| `LEGACY_API` | Low | 8 | Uses API v1 — possibly deprecated |
| `IDOR_RISK` | Medium | 2 | Path contains user-controlled resource ID (potential IDOR) |
| `DATA_EXPORT` | High | 1 | Data export endpoint — bulk data exfiltration risk |
| `DESTRUCTIVE` | Medium | 1 | Destructive operation (DELETE) |
| `AUTH` | Medium | 1 | Authentication/authorization endpoint |

## API Version Analysis

| Version | Count | Notes |
|---------|-------|-------|
| v1 | 8 | Potentially deprecated — review migration plan |

## Discovery Source

| Source | Count | Percentage |
|--------|-------|------------|
| CodeAnalysis | 6 | 75.0% |
| OpenAPI | 2 | 25.0% |

## Recommendations

1. **Immediate: Review 1 critical-severity endpoints** — These endpoints have the highest exposure risk and should be audited for proper authentication, authorization, input validation, and rate limiting.

2. **Health data endpoints (6)** — Review HIPAA compliance: encryption at rest and in transit, access logging, minimum necessary data principle.

3. **IDOR-vulnerable paths (2)** — Endpoints with user-controlled resource IDs need server-side authorization checks to prevent insecure direct object references.

4. **Deprecate legacy APIs (8 v1 endpoints)** — Create a migration timeline to move clients to the latest API version and sunset v1 endpoints.

5. **Triage 3 high-severity endpoints** — Review for missing authentication, excessive data exposure, and broken access control.
