/**
 * Issue/vulnerability-related GraphQL queries for Ox Security
 */

export const GET_ISSUES = `
query GetIssues($isDemo: Boolean, $getIssuesInput: IssuesInput) {
  getIssues(isDemo: $isDemo, getIssuesInput: $getIssuesInput) {
    issues {
      id
      issueId
      mainTitle
      secondTitle
      severity
      originalSeverity
      owners
      created
      app {
        id
        name
        type
      }
      category {
        name
      }
      policy {
        name
        detailedDescription
      }
      sourceType
    }
    totalIssues
    totalFilteredIssues
    totalResolvedIssues
    offset
  }
}`;

export const GET_SINGLE_ISSUE = `
query GetSingleIssueInfo($getSingleIssueInput: SingleIssueInput) {
  getSingleIssueInfo(getSingleIssueInput: $getSingleIssueInput) {
    id
    issueId
    mainTitle
    secondTitle
    severity
    originalSeverity
    description
    owners
    created
    app { id name type }
    category { name }
    policy { name detailedDescription }
    sbom {
      libraryName
      libraryVersion
      license
      packageManager
    }
    scaVulnerabilities {
      cve
      cveLink
      originalSeverity
      minorVerWithFix
      majorVerWithFix
    }
    severityChangedReason {
      reason
      shortName
      changeCategory
    }
    autoFix {
      fixType
      fixTitle
      fixDescription
    }
  }
}`;

export const GET_ISSUE_PRIORITIZATION = `
query GetIssuePrioritization($getIssuesInput: IssuesInput) {
  getIssuePrioritization(getIssuesInput: $getIssuesInput) {
    original { critical high medium low info }
    oxPrioritized { critical high medium low info }
    aggregated { critical high medium low info }
  }
}`;

export const GET_ISSUES_TREND = `
query GetIssuesTrendData($getIssuesInput: IssuesInput) {
  getIssuesTrendData(getIssuesInput: $getIssuesInput) {
    trendData {
      date
      count
      severity
    }
  }
}`;

export const GET_ISSUE_FILTERS = `
query GetIssuesFilters($getIssuesInput: IssuesInput) {
  getIssuesFilters(getIssuesInput: $getIssuesInput) {
    categories { name count }
    severities { name count }
    sourceTypes { name count }
    apps { name count }
  }
}`;
