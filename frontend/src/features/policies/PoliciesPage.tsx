import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router';
import { z } from 'zod';
import type { PolicyVersionRecord } from '../../api/types';
import { PolicyForm } from './PolicyForm';
import { PolicyList } from './PolicyList';
import { VersionHistory } from './VersionHistory';
function integer(
  value: string | null,
  fallback: number,
  min: number,
  max: number,
) {
  if (value === null || !/^\d+$/.test(value)) return fallback;
  const number = Number(value);
  return Number.isSafeInteger(number) && number >= min && number <= max
    ? number
    : fallback;
}
function uuid(value: string | null) {
  const result = z.uuid().safeParse(value);
  return result.success ? result.data : null;
}
export function PoliciesPage() {
  const [params, setParams] = useSearchParams();
  const [creating, setCreating] = useState(false);
  const [policyRevision, setPolicyRevision] = useState(0);
  const [versionRevision, setVersionRevision] = useState(0);
  const limit = integer(params.get('limit'), 20, 1, 100);
  const offset = integer(params.get('offset'), 0, 0, Number.MAX_SAFE_INTEGER);
  const versionLimit = integer(params.get('version_limit'), 20, 1, 100);
  const versionOffset = integer(
    params.get('version_offset'),
    0,
    0,
    Number.MAX_SAFE_INTEGER,
  );
  const policyId = uuid(params.get('policy'));
  const versionId = policyId ? uuid(params.get('version')) : null;
  useEffect(() => {
    const normalized = new URLSearchParams(params);
    normalized.set('limit', String(limit));
    normalized.set('offset', String(offset));
    normalized.set('version_limit', String(versionLimit));
    normalized.set('version_offset', String(versionOffset));
    if (policyId) normalized.set('policy', policyId);
    else normalized.delete('policy');
    if (versionId) normalized.set('version', versionId);
    else normalized.delete('version');
    if (normalized.toString() !== params.toString())
      setParams(normalized, { replace: true });
  }, [
    params,
    setParams,
    limit,
    offset,
    versionLimit,
    versionOffset,
    policyId,
    versionId,
  ]);
  function select(id: string) {
    const next = new URLSearchParams(params);
    next.set('policy', id);
    next.set('version_offset', '0');
    next.delete('version');
    setParams(next);
  }
  function changePage(nextOffset: number, nextLimit = limit) {
    const next = new URLSearchParams(params);
    next.set('limit', String(nextLimit));
    next.set('offset', String(nextOffset));
    setParams(next);
  }
  function changeVersionPage(nextOffset: number, nextLimit = versionLimit) {
    const next = new URLSearchParams(params);
    next.set('version_limit', String(nextLimit));
    next.set('version_offset', String(nextOffset));
    setParams(next);
  }
  function created(record: PolicyVersionRecord, isNewPolicy: boolean) {
    const next = new URLSearchParams(params);
    next.set('policy', record.policy_id);
    next.set('version', record.policy_version_id);
    next.set('version_offset', '0');
    if (isNewPolicy) {
      next.set('offset', '0');
      setPolicyRevision((value) => value + 1);
      setCreating(false);
    }
    setVersionRevision((value) => value + 1);
    setParams(next);
  }
  return (
    <section>
      <div className="section-heading">
        <div>
          <p className="eyebrow">Security rules</p>
          <h1>Policies</h1>
        </div>
        <button
          className="button-secondary"
          type="button"
          onClick={() => setCreating((value) => !value)}
        >
          {creating ? 'Cancel new policy' : 'Create policy'}
        </button>
      </div>
      <p className="page-description">
        Define scan acceptance rules and keep a record of every saved version.
      </p>
      {creating && (
        <PolicyForm
          onCreated={(record) => created(record, true)}
          onCheckHistory={() => setPolicyRevision((value) => value + 1)}
        />
      )}
      <div className="policies-workspace">
        <PolicyList
          limit={limit}
          offset={offset}
          revision={policyRevision}
          selectedId={policyId}
          onSelect={select}
          onPageChange={changePage}
        />
        <div className="policy-details">
          {policyId ? (
            <>
              <p className="selected-policy-id">
                Selected policy: <code>{policyId}</code>
              </p>
              <VersionHistory
                policyId={policyId}
                limit={versionLimit}
                offset={versionOffset}
                revision={versionRevision}
                selectedVersionId={versionId}
                onPageChange={changeVersionPage}
              />
              {!creating && (
                <PolicyForm
                  key={policyId}
                  policyId={policyId}
                  onCreated={(record) => created(record, false)}
                  onCheckHistory={() =>
                    setVersionRevision((value) => value + 1)
                  }
                />
              )}
            </>
          ) : (
            <p className="history-notice">
              Select a policy to view its saved versions or create a new
              version.
            </p>
          )}
        </div>
      </div>
    </section>
  );
}
