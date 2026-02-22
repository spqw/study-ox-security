/**
 * API Security GraphQL queries for Ox Security
 */

export const GET_API_SECURITY_ITEMS = `
query GetApiSecurityItems($getApiSecurityInput: GetApiSecurityInput) {
  getApiSecurityItems(getApiSecurityInput: $getApiSecurityInput) {
    items {
      id
      method
      path
      severity
      codeLocations {
        filePath
        lineNumber
      }
      definitions {
        source
        path
      }
      app {
        id
        name
      }
    }
    total
    offset
  }
}`;

export const GET_API_SECURITY_FILTERS = `
query GetApiSecurityFiltersLazy($getApiSecurityInput: GetApiSecurityInput) {
  getApiSecurityFiltersLazy(getApiSecurityInput: $getApiSecurityInput) {
    methods { name count }
    severities { name count }
    apps { name count }
  }
}`;
