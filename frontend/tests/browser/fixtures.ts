import type { PolicyRecord, PolicyVersionRecord } from '../../src/api/types';
import { test as base, expect, type Route } from '@playwright/test';
import {
  completedScan,
  scanId,
  availableSbom,
  sampleFinding,
} from '../fixtures';
import { policy, version, secondVersion } from '../policyFixtures';
export { completedScan, scanId, policy, version, secondVersion };
export const sbomBytes = '{ "bomFormat": "CycloneDX", "specVersion": "1.7" }\n';
export const evaluation = {
  evaluation_id: 'db57c3d1-222f-47d5-a392-08081c878668',
  scan_id: scanId,
  policy_id: policy.policy_id,
  policy_version_id: version.policy_version_id,
  version_number: 1,
  rule_snapshot: version.rules,
  evaluator_version: 1,
  outcome: 'failed',
  counts: { CRITICAL: 2, HIGH: 21, MEDIUM: 20, LOW: 27, UNKNOWN: 0 },
  rules: [
    {
      rule_id: 'max_critical',
      passed: false,
      actual: 2,
      expected: 0,
      reason: 'CRITICAL count exceeds the allowed maximum.',
    },
    {
      rule_id: 'max_high',
      passed: false,
      actual: 21,
      expected: 5,
      reason: 'HIGH count exceeds the allowed maximum.',
    },
  ],
  created_at: version.created_at,
  error_code: null,
  error_details: null,
};
export interface ApiState {
  progressStartedAt: number | null;
  progress: boolean;
  posts: { path: string; body: unknown }[];
  error:
    | 'malformed'
    | 'unavailable'
    | 'missing'
    | 'sbom'
    | 'evaluation'
    | 'capacity'
    | null;
  policies: PolicyRecord[];
  versions: PolicyVersionRecord[];
  offPage: boolean;
}
export const test = base.extend<{ api: ApiState }>({
  api: async ({ page }, use) => {
    const state: ApiState = {
      progressStartedAt: null,
      progress: false,
      posts: [],
      error: null,
      policies: [policy],
      versions: [secondVersion, version],
      offPage: false,
    };
    const unhandled: string[] = [];
    await page.route('**/api/v1/**', async (route: Route) => {
      const request = route.request();
      const url = new URL(request.url());
      const path = url.pathname;
      const offset = Number(url.searchParams.get('offset') ?? 0);
      const limit = Number(url.searchParams.get('limit') ?? 20);
      const send = (body: unknown, status = 200) =>
        route.fulfill({
          status,
          contentType: 'application/json',
          body: JSON.stringify(body),
        });
      const paged = (items: unknown[], total = items.length) =>
        send({ items, total, limit, offset });
      if (request.method() === 'POST')
        state.posts.push({ path, body: request.postDataJSON() });
      if (state.error === 'unavailable')
        return route.fulfill({
          status: 502,
          contentType: 'text/html',
          body: 'Proxy unavailable',
        });
      if (path === `/api/v1/scans/${scanId}`) {
        if (state.error === 'missing')
          return send({ detail: 'Not found' }, 404);
        if (state.error === 'malformed') return send({ status: 'completed' });
        if (state.progress && state.progressStartedAt === null)
          state.progressStartedAt = Date.now();
        const elapsed = Date.now() - (state.progressStartedAt ?? Date.now());
        const status = state.progress
          ? elapsed < 1000
            ? 'queued'
            : elapsed < 4500
              ? 'running'
              : 'completed'
          : 'completed';
        return send({ ...completedScan, status });
      }
      if (path === '/api/v1/scans') {
        if (request.method() === 'POST' && state.error === 'capacity')
          return send(
            { detail: 'Scan queue is full. Try again shortly.' },
            429,
          );
        if (request.method() === 'POST')
          return send(
            {
              scan_id: scanId,
              status: 'queued',
              status_url: `/api/v1/scans/${scanId}`,
            },
            202,
          );
        return paged([
          {
            scan_id: scanId,
            image_reference: completedScan.image_reference,
            status: 'completed',
          },
        ]);
      }
      if (path === `/api/v1/scans/${scanId}/findings`) {
        const severity = url.searchParams.get('severity');
        return send({
          items: [
            {
              ...sampleFinding,
              package_name: offset ? 'second-package' : 'first-package',
              severity: severity ?? 'HIGH',
            },
          ],
          total: severity ? 1 : 21,
          limit,
          offset,
          mock: false,
        });
      }
      if (path === `/api/v1/scans/${scanId}/sbom/metadata`)
        return send({
          ...availableSbom,
          ...(state.error === 'sbom'
            ? {
                status: 'failed',
                error_code: 'generation_failed',
                error_details: 'SBOM generation failed',
              }
            : {}),
        });
      if (path === `/api/v1/scans/${scanId}/sbom`)
        return route.fulfill({
          contentType: 'application/json',
          body: sbomBytes,
        });
      if (path === `/api/v1/scans/${scanId}/evaluations`) {
        const record =
          state.error === 'evaluation'
            ? {
                ...evaluation,
                outcome: 'error',
                error_code: 'invalid_evidence',
                error_details: 'Saved evidence is invalid.',
              }
            : evaluation;
        return request.method() === 'POST' ? send(record) : paged([record]);
      }
      if (path === '/api/v1/policies') {
        if (request.method() === 'POST') {
          const body = request.postDataJSON();
          state.policies = [{ ...policy, name: body.name }];
          state.versions = [{ ...version, rules: body.rules }];
          return send(state.versions[0], 201);
        }
        return state.offPage
          ? paged(offset ? state.policies : [], 21)
          : paged(state.policies);
      }
      if (path === `/api/v1/policies/${policy.policy_id}/versions`) {
        if (request.method() === 'POST') {
          const record = {
            ...secondVersion,
            rules: request.postDataJSON().rules,
          };
          state.versions = [record, ...state.versions];
          return send(record, 201);
        }
        return state.offPage
          ? paged(offset ? [version] : [secondVersion], 21)
          : paged(state.versions);
      }
      unhandled.push(path);
      return route.abort();
    });
    await use(state);
    expect(
      unhandled,
      'Unexpected API calls must not reach live services',
    ).toEqual([]);
  },
});
export { expect };
