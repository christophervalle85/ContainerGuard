import { useEffect, useState } from 'react';
import { listPolicies, listPolicyVersions } from '../../api/policies';
import type {
  PolicyPage,
  PolicyVersionPage,
  PolicyVersionRecord,
} from '../../api/types';
import { Pagination } from '../../components/Pagination';
import { RuleSummary } from '../policies/RuleSummary';
export function PolicyVersionPicker({
  selected,
  onSelect,
}: {
  selected: PolicyVersionRecord | null;
  onSelect: (value: PolicyVersionRecord | null) => void;
}) {
  const [policyId, setPolicyId] = useState('');
  const [policyOffset, setPolicyOffset] = useState(0);
  const [versionOffset, setVersionOffset] = useState(0);
  const [policies, setPolicies] = useState<{
    key: number;
    data?: PolicyPage;
    error?: string;
  } | null>(null);
  const [versions, setVersions] = useState<{
    key: string;
    data?: PolicyVersionPage;
    error?: string;
  } | null>(null);
  const versionKey = `${policyId}/${versionOffset}`;
  const policyData = policies?.key === policyOffset ? policies : null;
  const versionData = versions?.key === versionKey ? versions : null;
  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    listPolicies({ limit: 20, offset: policyOffset }, controller.signal).then(
      (data) => {
        if (active) setPolicies({ key: policyOffset, data });
      },
      () => {
        if (active)
          setPolicies({
            key: policyOffset,
            error:
              'Policies could not be loaded. Reload the page to try again.',
          });
      },
    );
    return () => {
      active = false;
      controller.abort();
    };
  }, [policyOffset]);
  useEffect(() => {
    if (!policyId) return;
    const controller = new AbortController();
    let active = true;
    listPolicyVersions(
      policyId,
      { limit: 20, offset: versionOffset },
      controller.signal,
    ).then(
      (data) => {
        if (active) setVersions({ key: versionKey, data });
      },
      () => {
        if (active)
          setVersions({
            key: versionKey,
            error:
              'Policy versions could not be loaded. Reload the page to try again.',
          });
      },
    );
    return () => {
      active = false;
      controller.abort();
    };
  }, [policyId, versionOffset, versionKey]);
  return (
    <div className="evaluation-picker">
      <section aria-label="Choose evaluation policy">
        <label htmlFor="evaluation-policy">Evaluation policy</label>
        <select
          id="evaluation-policy"
          value={policyId}
          onChange={(e) => {
            setPolicyId(e.target.value);
            setVersionOffset(0);
            onSelect(null);
          }}
        >
          <option value="">Choose a policy</option>
          {policyId &&
            !policyData?.data?.items.some((p) => p.policy_id === policyId) && (
              <option value={policyId}>Selected policy · {policyId}</option>
            )}
          {policyData?.data?.items.map((p) => (
            <option key={p.policy_id} value={p.policy_id}>
              {p.name} · {p.policy_id}
            </option>
          ))}
        </select>
        {!policyData && <p role="status">Loading policies…</p>}
        {policyData?.error && <p role="alert">{policyData.error}</p>}
        {policyData?.data && (
          <>
            <p>
              {policyData.data.total === 0
                ? 'No policies saved yet. Create one in Policies.'
                : ''}
            </p>
            <Pagination {...policyData.data} onPageChange={setPolicyOffset} />
          </>
        )}
      </section>
      {policyId && (
        <section aria-label="Choose policy version">
          <label htmlFor="evaluation-version">Policy version</label>
          <select
            id="evaluation-version"
            value={selected?.policy_version_id ?? ''}
            onChange={(e) =>
              onSelect(
                versionData?.data?.items.find(
                  (v) => v.policy_version_id === e.target.value,
                ) ?? null,
              )
            }
          >
            <option value="">Choose a version explicitly</option>
            {selected &&
              !versionData?.data?.items.some(
                (v) => v.policy_version_id === selected.policy_version_id,
              ) && (
                <option value={selected.policy_version_id}>
                  Version {selected.version_number} ·{' '}
                  {selected.policy_version_id}
                </option>
              )}
            {versionData?.data?.items.map((v) => (
              <option key={v.policy_version_id} value={v.policy_version_id}>
                Version {v.version_number} · {v.policy_version_id}
              </option>
            ))}
          </select>
          {!versionData && <p role="status">Loading policy versions…</p>}
          {versionData?.error && <p role="alert">{versionData.error}</p>}
          {versionData?.data && (
            <>
              <p>
                {versionData.data.total === 0
                  ? 'No versions on this page.'
                  : ''}
              </p>
              <Pagination
                {...versionData.data}
                onPageChange={setVersionOffset}
              />
            </>
          )}
        </section>
      )}
      {selected && (
        <section aria-label="Selected rules">
          <h3>Selected rules · version {selected.version_number}</h3>
          <code>{selected.policy_version_id}</code>
          <RuleSummary rules={selected.rules} />
        </section>
      )}
    </div>
  );
}
