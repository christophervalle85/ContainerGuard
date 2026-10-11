import { useEffect, useState } from 'react';
import { ApiError } from '../../api/client';
import { listPolicyVersions } from '../../api/policies';
import type { PolicyVersionPage } from '../../api/types';
import { Pagination } from '../../components/Pagination';
import { RuleSummary } from './RuleSummary';
interface Props {
  policyId: string;
  limit: number;
  offset: number;
  revision: number;
  selectedVersionId: string | null;
  onPageChange: (offset: number, limit?: number) => void;
}
type Result = { key: string; data?: PolicyVersionPage; error?: string };
export function VersionHistory({
  policyId,
  limit,
  offset,
  revision,
  selectedVersionId,
  onPageChange,
}: Props) {
  const key = `${policyId}/${limit}/${offset}/${revision}`;
  const [result, setResult] = useState<Result | null>(null);
  const current = result?.key === key ? result : null;
  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    listPolicyVersions(policyId, { limit, offset }, controller.signal).then(
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
                : 'Version history could not be loaded.',
          });
      },
    );
    return () => {
      active = false;
      controller.abort();
    };
  }, [key, policyId, limit, offset]);
  const data = current?.data;
  return (
    <section className="evidence-section" aria-labelledby="versions-heading">
      <h2 id="versions-heading">Version history</h2>
      <p className="field-help">
        Saved rules are immutable. Every version has a separate identity.
      </p>
      <div className="findings-controls">
        <div>
          <label htmlFor="version-limit">Versions per page</label>
          <select
            id="version-limit"
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
      {!current && <p role="status">Loading versions…</p>}
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
                ? 'No saved versions yet.'
                : 'No versions on this page.'}
            </p>
          ) : (
            data.items.map((version) => (
              <article
                className={`policy-version${selectedVersionId === version.policy_version_id ? ' policy-version-selected' : ''}`}
                key={version.policy_version_id}
                aria-labelledby={`version-${version.policy_version_id}`}
              >
                <h3 id={`version-${version.policy_version_id}`}>
                  Version {version.version_number}
                </h3>
                {selectedVersionId === version.policy_version_id && (
                  <p className="field-help">Selected version</p>
                )}
                <p className="version-id">
                  <code>{version.policy_version_id}</code>
                </p>
                <p className="field-help">
                  Created{' '}
                  <time dateTime={version.created_at}>
                    {new Date(version.created_at)
                      .toISOString()
                      .replace('T', ' ')
                      .replace('Z', ' UTC')}
                  </time>
                </p>
                <RuleSummary rules={version.rules} />
              </article>
            ))
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
