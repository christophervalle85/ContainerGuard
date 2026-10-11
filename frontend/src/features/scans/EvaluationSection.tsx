import { useEffect, useRef, useState } from 'react';
import { ApiError } from '../../api/client';
import { evaluateScan, listEvaluations } from '../../api/evaluations';
import type {
  EvaluationPage,
  EvaluationRecord,
  PolicyVersionRecord,
  ScanDetails,
} from '../../api/types';
import { Pagination } from '../../components/Pagination';
import { EvaluationResult } from './EvaluationResult';
import { PolicyVersionPicker } from './PolicyVersionPicker';
export function EvaluationSection({ scan }: { scan: ScanDetails }) {
  const eligible =
    scan.status === 'completed' &&
    !scan.mock &&
    !!scan.digest &&
    !!scan.platform;
  const [selected, setSelected] = useState<PolicyVersionRecord | null>(null);
  const [submitted, setSubmitted] = useState<EvaluationRecord | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [offset, setOffset] = useState(0);
  const [revision, setRevision] = useState(0);
  const key = `${scan.scan_id}/${offset}/${revision}`;
  const [history, setHistory] = useState<{
    key: string;
    data?: EvaluationPage;
    error?: string;
  } | null>(null);
  const current = history?.key === key ? history : null;
  const pending = useRef<AbortController | null>(null);
  useEffect(
    () => () => {
      pending.current?.abort();
      pending.current = null;
    },
    [scan.scan_id],
  );
  useEffect(() => {
    if (!eligible) return;
    const controller = new AbortController();
    let active = true;
    listEvaluations(
      scan.scan_id,
      { limit: 20, offset },
      controller.signal,
    ).then(
      (data) => {
        if (active) setHistory({ key, data });
      },
      () => {
        if (active)
          setHistory({
            key,
            error:
              'Saved evaluations could not be loaded. Reload or check history again.',
          });
      },
    );
    return () => {
      active = false;
      controller.abort();
    };
  }, [scan.scan_id, eligible, offset, revision, key]);
  async function submit() {
    if (!eligible || !selected || pending.current) return;
    const controller = new AbortController();
    pending.current = controller;
    setBusy(true);
    setError('');
    const versionId = selected.policy_version_id;
    try {
      const result = await evaluateScan(
        scan.scan_id,
        { policy_version_id: versionId },
        controller.signal,
      );
      if (controller.signal.aborted) return;
      if (
        result.scan_id !== scan.scan_id ||
        result.policy_version_id !== versionId
      )
        throw new ApiError(
          'The returned evaluation does not match the requested scan and version.',
          null,
          [],
          'invalid_response',
        );
      setSubmitted(result);
      setOffset(0);
      setRevision((r) => r + 1);
    } catch (cause) {
      if (!controller.signal.aborted) {
        const api = cause instanceof ApiError ? cause : null;
        setError(
          (api?.message ?? 'Evaluation could not be requested.') +
            (!api?.status || api.status >= 500
              ? ' The decision may have been saved. Check saved evaluations before submitting again.'
              : ''),
        );
      }
    } finally {
      if (pending.current === controller) {
        pending.current = null;
        if (!controller.signal.aborted) setBusy(false);
      }
    }
  }
  return (
    <section className="evidence-section" aria-label="Policy evaluation">
      <h2 id="evaluations-heading">Policy evaluation</h2>
      <p>
        Evaluate saved evidence against one explicit, immutable policy version.
        Selecting rules does not submit a request.
      </p>
      {!eligible ? (
        <p className="history-notice">
          Evaluation requires a completed, real scan with a resolved image
          digest and platform. Pending, failed, fictional, or incomplete records
          cannot be evaluated.
        </p>
      ) : (
        <>
          <PolicyVersionPicker selected={selected} onSelect={setSelected} />
          <button
            type="button"
            disabled={!selected || busy}
            aria-busy={busy}
            onClick={() => void submit()}
          >
            {busy ? 'Evaluating…' : 'Evaluate scan'}
          </button>
          {error && (
            <p className="inline-error" role="alert">
              {error}
            </p>
          )}
          {submitted?.scan_id === scan.scan_id && (
            <section aria-label="Submitted decision">
              <EvaluationResult evaluation={submitted} />
            </section>
          )}
          <section aria-label="Saved evaluations">
            {submitted &&
              current?.data?.items.some(
                (e) => e.evaluation_id === submitted.evaluation_id,
              ) && (
                <p className="muted">
                  The submitted decision is shown above and is included in this
                  history page.
                </p>
              )}
            <div className="section-heading">
              <h3>Saved evaluations</h3>
              <button
                type="button"
                className="button-secondary"
                onClick={() => setRevision((r) => r + 1)}
              >
                Check evaluation history
              </button>
            </div>
            <p>
              Repeated evaluation of the same scan and policy version returns
              the same saved decision, ID, and timestamp.
            </p>
            {!current && <p role="status">Loading saved evaluations…</p>}
            {current?.error && <p role="alert">{current.error}</p>}
            {current?.data && (
              <>
                {current.data.items.length === 0 && (
                  <p>No saved evaluations on this page.</p>
                )}
                {current.data.items
                  .filter((e) => e.evaluation_id !== submitted?.evaluation_id)
                  .map((e) => (
                    <EvaluationResult key={e.evaluation_id} evaluation={e} />
                  ))}
                <Pagination {...current.data} onPageChange={setOffset} />
              </>
            )}
          </section>
        </>
      )}
    </section>
  );
}
