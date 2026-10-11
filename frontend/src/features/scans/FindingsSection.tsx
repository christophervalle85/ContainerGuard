import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router';
import { ApiError } from '../../api/client';
import { listFindings } from '../../api/scans';
import { severitySchema } from '../../api/types';
import type { ScanDetails, FindingPage } from '../../api/types';
import { Pagination } from '../../components/Pagination';

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
type Result = { key: string; data?: FindingPage; error?: string };
export function FindingsSection({ scan }: { scan: ScanDetails }) {
  const [params, setParams] = useSearchParams();
  const limit = integer(params.get('limit'), 20, 1, 100);
  const offset = integer(params.get('offset'), 0, 0, Number.MAX_SAFE_INTEGER);
  const parsedSeverity = severitySchema.safeParse(params.get('severity'));
  const severity = parsedSeverity.success ? parsedSeverity.data : undefined;
  const ready = scan.status === 'completed';
  const key = `${scan.scan_id}/${scan.status}/${limit}/${offset}/${severity ?? ''}`;
  const [result, setResult] = useState<Result | null>(null);
  const current = result?.key === key ? result : null;
  useEffect(() => {
    if (
      params.get('limit') === String(limit) &&
      params.get('offset') === String(offset) &&
      (params.get('severity') ?? undefined) === severity
    )
      return;
    const normalized = new URLSearchParams(params);
    normalized.set('limit', String(limit));
    normalized.set('offset', String(offset));
    if (severity) normalized.set('severity', severity);
    else normalized.delete('severity');
    setParams(normalized, { replace: true });
  }, [params, setParams, limit, offset, severity]);
  useEffect(() => {
    if (!ready) return;
    let active = true;
    const controller = new AbortController();
    listFindings(
      scan.scan_id,
      { limit, offset, severity },
      controller.signal,
    ).then(
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
                : 'Findings could not be loaded.',
          });
      },
    );
    return () => {
      active = false;
      controller.abort();
    };
  }, [scan.scan_id, ready, key, limit, offset, severity]);
  function changePage(
    nextOffset: number,
    nextLimit = limit,
    nextSeverity = severity,
  ) {
    const next = new URLSearchParams(params);
    next.set('limit', String(nextLimit));
    next.set('offset', String(nextOffset));
    if (nextSeverity) next.set('severity', nextSeverity);
    else next.delete('severity');
    setParams(next);
  }
  const data = current?.data;
  return (
    <section className="evidence-section" aria-labelledby="findings-heading">
      <h2 id="findings-heading">Findings</h2>
      <p className="field-help">
        Saved vulnerability occurrences. A CVE can affect more than one package.
      </p>
      {!ready ? (
        <p className="history-notice">
          {scan.status === 'failed'
            ? 'Findings are unavailable because scan execution failed.'
            : 'Findings will be available after the scan completes.'}
        </p>
      ) : (
        <>
          <div className="findings-controls">
            <div>
              <label htmlFor="findings-severity">Severity</label>
              <select
                id="findings-severity"
                value={severity ?? ''}
                onChange={(event) => {
                  const parsed = severitySchema.safeParse(event.target.value);
                  const next = new URLSearchParams(params);
                  next.set('limit', String(limit));
                  next.set('offset', '0');
                  if (parsed.success) next.set('severity', parsed.data);
                  else next.delete('severity');
                  setParams(next);
                }}
              >
                <option value="">All severities</option>
                {severitySchema.options.map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label htmlFor="findings-limit">Findings per page</label>
              <select
                id="findings-limit"
                value={limit}
                onChange={(event) => changePage(0, Number(event.target.value))}
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
          {!current && (
            <p role="status" className="history-notice">
              Loading findings…
            </p>
          )}
          {current?.error && (
            <p className="inline-error" role="alert">
              {current.error}
            </p>
          )}
          {data && (
            <>
              {(scan.mock || data.mock) && (
                <p className="notice-message">
                  Fictional sample findings. These are demonstration records.
                </p>
              )}
              <p>
                {data.total} matching finding{' '}
                {data.total === 1 ? 'occurrence' : 'occurrences'}.
              </p>
              {data.items.length === 0 ? (
                <p className="history-notice">
                  {offset >= data.total && offset > 0
                    ? 'No findings on this page.'
                    : severity
                      ? 'No findings match this severity.'
                      : 'No vulnerability findings were recorded for this scan.'}
                </p>
              ) : (
                <div
                  className="table-scroll"
                  role="region"
                  aria-label="Vulnerability results"
                  tabIndex={0}
                >
                  <table className="findings-table">
                    <caption className="sr-only">
                      Vulnerability findings
                    </caption>
                    <thead>
                      <tr>
                        <th scope="col">Vulnerability</th>
                        <th scope="col">Package</th>
                        <th scope="col">Installed</th>
                        <th scope="col">Fixed version</th>
                        <th scope="col">Severity</th>
                        <th scope="col">Title</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.items.map((finding, index) => (
                        <tr
                          key={`${offset + index}/${finding.vulnerability_id}/${finding.package_name}`}
                        >
                          <td>
                            <code>{finding.vulnerability_id}</code>
                          </td>
                          <td>{finding.package_name}</td>
                          <td>{finding.installed_version}</td>
                          <td>{finding.fixed_version ?? 'No known fix'}</td>
                          <td>
                            <span
                              className={`severity-label severity-${finding.severity.toLowerCase()}`}
                            >
                              {finding.severity}
                            </span>
                          </td>
                          <td>{finding.title}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              <Pagination
                limit={data.limit}
                offset={data.offset}
                total={data.total}
                onPageChange={changePage}
              />
            </>
          )}
        </>
      )}
    </section>
  );
}
