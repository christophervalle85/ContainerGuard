import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router';
import { ScanForm } from './ScanForm';
import { ScanHistory } from './ScanHistory';

function integer(
  value: string | null,
  fallback: number,
  min: number,
  max: number,
): number {
  if (value === null || !/^\d+$/.test(value)) return fallback;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= min && parsed <= max
    ? parsed
    : fallback;
}
export function ScansPage() {
  const [params, setParams] = useSearchParams();
  const [revision, setRevision] = useState(0);
  const limit = integer(params.get('limit'), 20, 1, 100);
  const offset = integer(params.get('offset'), 0, 0, Number.MAX_SAFE_INTEGER);
  useEffect(() => {
    if (
      params.get('limit') !== String(limit) ||
      params.get('offset') !== String(offset)
    ) {
      const normalized = new URLSearchParams(params);
      normalized.set('limit', String(limit));
      normalized.set('offset', String(offset));
      setParams(normalized, { replace: true });
    }
  }, [params, setParams, limit, offset]);
  function page(nextOffset: number, nextLimit = limit) {
    const next = new URLSearchParams(params);
    next.set('limit', String(nextLimit));
    next.set('offset', String(nextOffset));
    setParams(next);
  }
  const refresh = () => setRevision((value) => value + 1);
  return (
    <section aria-labelledby="scans-heading">
      <p className="eyebrow">Image security</p>
      <h1 id="scans-heading">Scans</h1>
      <p className="page-description">
        Submit an image and review its saved scan results.
      </p>
      <ScanForm onHistoryRefresh={refresh} />
      <ScanHistory
        limit={limit}
        offset={offset}
        revision={revision}
        onRefresh={refresh}
        onPageChange={page}
        onPageSizeChange={(nextLimit) => page(0, nextLimit)}
      />
    </section>
  );
}
