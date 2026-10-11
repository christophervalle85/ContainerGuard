export const policyId = 'c99b9979-2114-43a3-8e2d-c88f5d743988';
export const otherPolicyId = '8269d321-ba64-4208-8341-f07f072a9475';
export const rules = {
  max_critical: 0,
  max_high: 5,
  require_sbom: true,
  unknown_severity_action: 'fail',
} as const;
export const version = {
  policy_id: policyId,
  policy_version_id: 'c2ea44ec-35c9-4420-b584-739070f4da6f',
  version_number: 1,
  rules,
  created_at: '2026-10-09T20:20:41.792469Z',
};
export const secondVersion = {
  ...version,
  policy_version_id: '2bf31ff8-1f02-4c00-9764-c7af39387c07',
  version_number: 2,
  rules: { ...rules, max_high: 0 },
};
export const policy = {
  policy_id: policyId,
  name: 'Release gate',
  created_at: version.created_at,
};
export const otherPolicy = {
  ...policy,
  policy_id: otherPolicyId,
  name: 'Other gate',
};
export function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
export function page(
  items: unknown[],
  total = items.length,
  limit = 20,
  offset = 0,
) {
  return json({ items, total, limit, offset });
}
export function deferred() {
  let resolve!: (r: Response) => void;
  const promise = new Promise<Response>((yes) => {
    resolve = yes;
  });
  return { promise, resolve };
}
