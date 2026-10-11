import { parseResponse, pageQuery, requestJson } from './client';
import {
  scanAcceptedSchema,
  scanDetailsSchema,
  scanHistorySchema,
  findingPageSchema,
} from './types';
import type {
  ScanAccepted,
  ScanDetails,
  ScanHistory,
  ScanSubmission,
  FindingPage,
  PageRequest,
  Severity,
} from './types';
export function submitScan(
  body: ScanSubmission,
  signal?: AbortSignal,
): Promise<ScanAccepted> {
  return requestJson(
    '/api/v1/scans',
    { method: 'POST', body: JSON.stringify(body), signal },
    (value) => parseResponse(scanAcceptedSchema, value),
  );
}
export function listScans(
  page: PageRequest,
  signal?: AbortSignal,
): Promise<ScanHistory> {
  return requestJson(`/api/v1/scans?${pageQuery(page)}`, { signal }, (value) =>
    parseResponse(scanHistorySchema, value),
  );
}
export function getScan(
  id: string,
  signal?: AbortSignal,
): Promise<ScanDetails> {
  return requestJson(
    `/api/v1/scans/${encodeURIComponent(id)}`,
    { signal },
    (value) => parseResponse(scanDetailsSchema, value),
  );
}
export function listFindings(
  id: string,
  page: PageRequest & { severity?: Severity },
  signal?: AbortSignal,
): Promise<FindingPage> {
  const query =
    pageQuery(page) +
    (page.severity ? `&severity=${encodeURIComponent(page.severity)}` : '');
  return requestJson(
    `/api/v1/scans/${encodeURIComponent(id)}/findings?${query}`,
    { signal },
    (value) => parseResponse(findingPageSchema, value),
  );
}
