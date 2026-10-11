export const scanId = 'ff4599e5-4e9f-44c7-bbc2-e02db78bc008';
export const completedScan = {
  scan_id: scanId,
  image_reference: 'docker.io/library/alpine:3.20.0',
  status: 'completed',
  created_at: '2026-10-09T19:29:47.963557Z',
  started_at: '2026-10-09T19:29:48.992129Z',
  completed_at: '2026-10-09T19:29:58.036873Z',
  digest:
    'sha256:216266c86fc4dcef5619930bd394245824c2af52fd21ba7c6fa0e618657d4c3b',
  platform: 'linux/amd64',
  scanner_name: 'trivy',
  scanner_version: '0.75.0',
  scanner_database_metadata: {
    Version: 2,
    UpdatedAt: '2026-10-09T19:06:47.421531537Z',
  },
  error_details: null,
  mock: false,
};

export const availableSbom = {
  scan_id: scanId,
  status: 'available',
  format: 'CycloneDX',
  format_version: '1.7',
  scanner_version: '0.75.0',
  pinned_reference: 'docker.io/library/alpine@' + completedScan.digest,
  digest: completedScan.digest,
  platform: 'linux/amd64',
  size_bytes: 25482,
  sha256: '7fea9c7426f5309f8e0621e738c2a19af694817b8ccd113aac00ece1afb18742',
  created_at: completedScan.completed_at,
  error_code: null,
  error_details: null,
};
export const emptySbom = {
  ...availableSbom,
  status: 'not_generated',
  format: null,
  format_version: null,
  scanner_version: null,
  pinned_reference: null,
  digest: null,
  platform: null,
  size_bytes: null,
  sha256: null,
  created_at: null,
};
export const sampleFinding = {
  vulnerability_id: 'CVE-2023-42364',
  package_name: 'busybox',
  installed_version: '1.36.1-r15',
  fixed_version: null,
  severity: 'MEDIUM',
  title: 'Example finding',
};

// Shared endpoint fixtures keep full-page tests on valid, independent responses.
export function evidenceFixture(url: string): unknown | undefined {
  if (url.includes('/sbom/metadata')) return emptySbom;
  if (url.includes('/findings?'))
    return {
      items: [sampleFinding],
      total: 1,
      limit: 20,
      offset: 0,
      mock: false,
    };
  return undefined;
}
