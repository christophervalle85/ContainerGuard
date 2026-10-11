import { useEffect, useState } from 'react';
import { ApiError } from '../../api/client';
import { listPolicies } from '../../api/policies';
import type { PolicyPage } from '../../api/types';
import { Pagination } from '../../components/Pagination';
interface Props {
  limit: number;
  offset: number;
  revision: number;
  selectedId: string | null;
  onSelect: (id: string) => void;
  onPageChange: (offset: number, limit?: number) => void;
}
type Result = { key: string; data?: PolicyPage; error?: string };
export function PolicyList({
  limit,
  offset,
  revision,
  selectedId,
  onSelect,
  onPageChange,
}: Props) {
  const key = `${limit}/${offset}/${revision}`;
  const [result, setResult] = useState<Result | null>(null);
  const current = result?.key === key ? result : null;
  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    listPolicies({ limit, offset }, controller.signal).then(
      (data) => {
        if (active) setResult({ key, data });
      },
      (error) => {
        if (active && !controller.signal.aborted)
          setResult({
            key,
            error:
              error instanceof ApiError
                ? error.message
                : 'Policies could not be loaded.',
          });
      },
    );
    return () => {
      active = false;
      controller.abort();
    };
  }, [key, limit, offset]);
  const data = current?.data;
  return (
    <section
      className="evidence-section"
      aria-labelledby="saved-policies-heading"
    >
      <h2 id="saved-policies-heading">Saved policies</h2>
      <div className="findings-controls">
        <div>
          <label htmlFor="policy-limit">Policies per page</label>
          <select
            id="policy-limit"
            value={limit}
            onChange={(event) => onPageChange(0, Number(event.target.value))}
          >
            {![20, 50, 100].includes(limit) && (
              <option value={limit}>{limit}</option>
            )}
            <option value={20}>20</option>
            <option value={50}>50</option>
            <option value={100}>100</option>
          </select>
        </div>
      </div>
      {!current && <p role="status">Loading policies…</p>}
      {current?.error && (
        <p role="alert" className="inline-error">
          {current.error}
        </p>
      )}
      {data && (
        <>
          {data.items.length === 0 ? (
            <p className="history-notice">
              {offset === 0 && data.total === 0
                ? 'No saved policies yet.'
                : 'No policies on this page.'}
            </p>
          ) : (
            <ul className="policy-list">
              {data.items.map((policy) => (
                <li key={policy.policy_id}>
                  <button
                    className="policy-select"
                    type="button"
                    aria-pressed={selectedId === policy.policy_id}
                    onClick={() => onSelect(policy.policy_id)}
                  >
                    {policy.name}
                  </button>
                  <code>{policy.policy_id}</code>
                  <p className="field-help">
                    Created{' '}
                    <time dateTime={policy.created_at}>
                      {new Date(policy.created_at)
                        .toISOString()
                        .replace('T', ' ')
                        .replace('Z', ' UTC')}
                    </time>
                  </p>
                </li>
              ))}
            </ul>
          )}
          <Pagination
            limit={data.limit}
            offset={data.offset}
            total={data.total}
            onPageChange={onPageChange}
          />
        </>
      )}
    </section>
  );
}
