import { parseResponse, pageQuery, requestJson } from './client';
import {
  policyPageSchema,
  policyVersionPageSchema,
  policyVersionSchema,
} from './types';
import type {
  PageRequest,
  PolicyCreate,
  PolicyVersionCreate,
  PolicyPage,
  PolicyVersionPage,
  PolicyVersionRecord,
} from './types';
export function listPolicies(
  page: PageRequest,
  signal?: AbortSignal,
): Promise<PolicyPage> {
  return requestJson(
    `/api/v1/policies?${pageQuery(page)}`,
    { signal },
    (value) => parseResponse(policyPageSchema, value),
  );
}
export function createPolicy(
  body: PolicyCreate,
  signal?: AbortSignal,
): Promise<PolicyVersionRecord> {
  return requestJson(
    '/api/v1/policies',
    { method: 'POST', body: JSON.stringify(body), signal },
    (value) => parseResponse(policyVersionSchema, value),
  );
}
export function listPolicyVersions(
  id: string,
  page: PageRequest,
  signal?: AbortSignal,
): Promise<PolicyVersionPage> {
  return requestJson(
    `/api/v1/policies/${encodeURIComponent(id)}/versions?${pageQuery(page)}`,
    { signal },
    (value) => parseResponse(policyVersionPageSchema, value),
  );
}
export function createPolicyVersion(
  id: string,
  body: PolicyVersionCreate,
  signal?: AbortSignal,
): Promise<PolicyVersionRecord> {
  return requestJson(
    `/api/v1/policies/${encodeURIComponent(id)}/versions`,
    { method: 'POST', body: JSON.stringify(body), signal },
    (value) => parseResponse(policyVersionSchema, value),
  );
}
