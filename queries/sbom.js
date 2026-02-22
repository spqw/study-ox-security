/**
 * SBOM (Software Bill of Materials) GraphQL queries for Ox Security
 */

export const GET_SBOM_LIBRARIES = `
query GetSbomLibraries($getSbomLibrariesInput: GetApplicationsSbom) {
  getSbomLibraries(getApplicationsSbom: $getSbomLibrariesInput) {
    sbomLibs {
      libraryName
      libraryVersion
      license
      appName
      dependencyType
      dependencyLevel
      source
      vulnerabilityCounts {
        critical
        high
        medium
        low
        info
      }
      notMaintained
      isDeprecated
      licenseIssue
    }
    offset
    total
    totalFilteredSbomLibs
  }
}`;

export const GET_SBOM_FILTERS = `
query GetSbomFilters($getSbomLibrariesInput: GetApplicationsSbom) {
  sbomFilters(getApplicationsSbom: $getSbomLibrariesInput) {
    licenses { name count }
    sources { name count }
    apps { name count }
  }
}`;

export const GET_SBOM_STATS = `
query GetSbomLibStats($getSbomLibrariesInput: GetApplicationsSbom) {
  sbomLibStats(getApplicationsSbom: $getSbomLibrariesInput) {
    totalLibraries
    vulnerableLibraries
    deprecatedLibraries
    notMaintainedLibraries
    licenseIssueLibraries
  }
}`;
