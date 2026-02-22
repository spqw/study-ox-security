/**
 * Organization & audit-related GraphQL queries for Ox Security
 */

export const GET_ORGANIZATION = `
query GetOrganization {
  getOrganization {
    name
    tier
    developersCount
    trialStartDate
    trialEndDate
    users { name email role }
  }
}`;

export const GET_ORG_SCAN_INFO = `
query GetOrgScanInfo($fetchDashboardInput: FetchDashboardInput) {
  getOrgScanInfo(fetchDashboardInput: $fetchDashboardInput) {
    totalIssues
    severities { critical high medium low info }
    lastScanDate
    systems { name status }
  }
}`;

export const GET_CONNECTORS = `
query GetConnectorsByFamily {
  getConnectorsByFamily {
    family
    connectors {
      name
      type
      status
      lastScan
    }
  }
}`;

export const GET_PIPELINE_SUMMARY = `
query GetPipelineSummary($getPipelineSummaryInput: GetPipelineSummaryInput) {
  getPipelineSummary(getPipelineSummaryInput: $getPipelineSummaryInput) {
    pipelines {
      id
      name
      status
      duration
      blockingIssues
      result
    }
    total
    offset
  }
}`;

export const GET_AUDIT_LOGS = `
query GetLogs($getLogsInput: GetLogsInput) {
  getLogs(getLogsInput: $getLogsInput) {
    logs {
      timestamp
      type
      user
      action
      details
    }
    total
  }
}`;

export const GET_ALL_TAGS = `
query GetAllTags {
  getAllTags {
    tagId
    name
    displayName
    type
    createdBy
  }
}`;
