import { parseResponse, pageQuery, requestJson } from './client';
import { evaluationSchema, evaluationPageSchema } from './types';
import type {
  PageRequest,
  EvaluationRequest,
  EvaluationRecord,
  EvaluationPage,
} from './types';
export function evaluateScan(
  id: string,
  body: EvaluationRequest,
  signal?: AbortSignal,
): Promise<EvaluationRecord> {
  return requestJson(
    `/api/v1/scans/${encodeURIComponent(id)}/evaluations`,
    { method: 'POST', body: JSON.stringify(body), signal },
    (value) => parseResponse(evaluationSchema, value),
  );
}
export function listEvaluations(
  id: string,
  page: PageRequest,
  signal?: AbortSignal,
): Promise<EvaluationPage> {
  return requestJson(
    `/api/v1/scans/${encodeURIComponent(id)}/evaluations?${pageQuery(page)}`,
    { signal },
    (value) => parseResponse(evaluationPageSchema, value),
  );
}
