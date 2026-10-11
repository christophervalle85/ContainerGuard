import { parseResponse, requestJson, requestDownload } from './client';
import { sbomMetadataSchema } from './types';
import type { SbomMetadata } from './types';
export function getSbomMetadata(
  id: string,
  signal?: AbortSignal,
): Promise<SbomMetadata> {
  return requestJson(
    `/api/v1/scans/${encodeURIComponent(id)}/sbom/metadata`,
    { signal },
    (value) => parseResponse(sbomMetadataSchema, value),
  );
}
export function downloadSbom(id: string, signal?: AbortSignal): Promise<Blob> {
  return requestDownload(`/api/v1/scans/${encodeURIComponent(id)}/sbom`, {
    signal,
  });
}
