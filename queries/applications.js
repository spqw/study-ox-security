/**
 * Application-related GraphQL queries for Ox Security
 */

export const GET_APPLICATIONS = `
query GetApplications($getApplicationsInput: GetApplicationsInput) {
  getApplications(getApplicationsInput: $getApplicationsInput) {
    applications {
      appId
      appName
      risk
      type
      businessPriority
      issuesBySeverity {
        critical
        high
        medium
        low
        info
      }
      appOwners {
        name
        email
      }
      tags {
        tagId
        displayName
      }
    }
    offset
    total
    totalFilteredApps
  }
}`;

export const GET_SINGLE_APP = `
query GetSingleApplicationInfo($getSingleApplicationInput: SingleApplicationInput) {
  getSingleApplicationInfo(getSingleApplicationInput: $getSingleApplicationInput) {
    appId
    appName
    risk
    type
    businessPriority
    languages
    appOwners { name email }
    issuesBySeverity { critical high medium low info }
    securityInfrastructure { name type status }
    tags { tagId displayName }
  }
}`;

export const GET_INVENTORY = `
query GetInventoryResult($fetchDashboardInput: FetchDashboardInput) {
  getInventoryResult(fetchDashboardInput: $fetchDashboardInput) {
    applicationsCount
    appsByType { type count }
  }
}`;
