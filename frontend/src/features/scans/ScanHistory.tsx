import { useEffect, useState } from 'react';
import { Link } from 'react-router';
import { ApiError } from '../../api/client';
import { listScans } from '../../api/scans';
import type { ScanHistory as HistoryPage } from '../../api/types';
import { Pagination } from '../../components/Pagination';
import { StatusLabel } from '../../components/StatusLabel';

interface HistoryProps {
  limit: number;
  offset: number;
  revision: number;
  onRefresh: () => void;
  onPageChange: (offset: number) => void;
  onPageSizeChange: (limit: number) => void;
}
type Result =
  | { key: string; data: HistoryPage; error?: never }
  | { key: string; error: string; data?: never };
export function ScanHistory({
  limit,
  offset,
  revision,
  onRefresh,
  onPageChange,
  onPageSizeChange,
}: HistoryProps) {
  const key = `${limit}/${offset}/${revision}`;
  const [result, setResult] = useState<Result | null>(null);
  const current = result?.key === key ? result : null;
  const loading = current === null;
  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    listScans({ limit, offset }, controller.signal).then(
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
                : 'Scan history could not be loaded.',
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
    <section className="history-section" aria-labelledby="scan-history">
      <div className="section-heading">
        <div>
          <h2 id="scan-history" tabIndex={-1}>
            Scan history
          </h2>
          <p className="field-help">
            Saved submissions, newest first. Refresh to check current statuses.
          </p>
        </div>
        <button
          type="button"
          className="button-secondary"
          onClick={onRefresh}
          disabled={loading}
        >
          Refresh history
        </button>
      </div>
      <div className="history-controls">
        <label htmlFor="history-limit">Scans per page</label>
        <select
          id="history-limit"
          value={limit}
          onChange={(event) => onPageSizeChange(Number(event.target.value))}
        >
          {![20, 50, 100].includes(limit) && (
            <option value={limit}>{limit}</option>
          )}
          <option value={20}>20</option>
          <option value={50}>50</option>
          <option value={100}>100</option>
        </select>
      </div>
      {loading && (
        <p className="history-notice" role="status">
          Loading scan history…
        </p>
      )}
      {current?.error && (
        <p className="inline-error" role="alert">
          {current.error}
        </p>
      )}
      {data && (
        <>
          {data.items.length === 0 ? (
            <p className="history-notice">
              {data.total === 0 && offset === 0
                ? 'No saved scans yet.'
                : 'No scans on this page.'}
            </p>
          ) : (
            <div
              className="table-scroll"
              role="region"
              aria-label="Saved scans"
              tabIndex={0}
            >
              <table>
                <caption className="sr-only">Saved scan history</caption>
                <thead>
                  <tr>
                    <th scope="col">Image</th>
                    <th scope="col">Scan ID</th>
                    <th scope="col">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((scan) => (
                    <tr key={scan.scan_id}>
                      <td>
                        <Link to={`/scans/${encodeURIComponent(scan.scan_id)}`}>
                          {scan.image_reference}
                        </Link>
                      </td>
                      <td>
                        <code>{scan.scan_id}</code>
                      </td>
                      <td>
                        <StatusLabel status={scan.status} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <Pagination
            limit={limit}
            offset={offset}
            total={data.total}
            onPageChange={onPageChange}
          />
        </>
      )}
    </section>
  );
}
