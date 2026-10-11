import { useEffect, useRef, useState } from 'react';
import { ApiError } from '../../api/client';
import { getSbomMetadata, downloadSbom } from '../../api/sboms';
import type { ScanDetails, SbomMetadata } from '../../api/types';

type Result = { key: string; data?: SbomMetadata; error?: string };
type DownloadState = {
  key: string;
  pending?: boolean;
  error?: string;
  success?: boolean;
};
export function SbomSection({ scan }: { scan: ScanDetails }) {
  const key = `${scan.scan_id}/${scan.status}`;
  const [result, setResult] = useState<Result | null>(null);
  const [download, setDownload] = useState<DownloadState | null>(null);
  const request = useRef<AbortController | null>(null);
  const current = result?.key === key ? result : null;
  const action = download?.key === key ? download : null;
  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    getSbomMetadata(scan.scan_id, controller.signal).then(
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
                : 'SBOM metadata could not be loaded.',
          });
      },
    );
    return () => {
      active = false;
      controller.abort();
      request.current?.abort();
      request.current = null;
    };
  }, [scan.scan_id, key]);
  async function save() {
    if (request.current || current?.data?.status !== 'available') return;
    const controller = new AbortController();
    request.current = controller;
    setDownload({ key, pending: true });
    try {
      const blob = await downloadSbom(scan.scan_id, controller.signal);
      if (controller.signal.aborted || request.current !== controller) return;
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      try {
        link.href = url;
        link.download = `${scan.scan_id}.cdx.json`;
        document.body.append(link);
        link.click();
      } finally {
        link.remove();
        URL.revokeObjectURL(url);
      }
      setDownload({ key, success: true });
    } catch (error) {
      if (!controller.signal.aborted && request.current === controller)
        setDownload({
          key,
          error:
            error instanceof ApiError
              ? error.message
              : 'The SBOM download could not be started.',
        });
    } finally {
      if (request.current === controller) request.current = null;
    }
  }
  const data = current?.data;
  return (
    <section className="evidence-section" aria-labelledby="sbom-heading">
      <h2 id="sbom-heading">SBOM</h2>
      <p className="field-help">
        The software bill of materials lists components recorded for the scanned
        image.
      </p>
      {!current && (
        <p role="status" className="history-notice">
          Loading SBOM metadata…
        </p>
      )}
      {current?.error && (
        <p className="inline-error" role="alert">
          {current.error}
        </p>
      )}
      {data?.status === 'pending' && (
        <p className="history-notice">
          The SBOM is still being prepared. Its status will be checked when scan
          execution finishes.
        </p>
      )}
      {data?.status === 'not_generated' && (
        <p className="history-notice">No SBOM was generated for this scan.</p>
      )}
      {data?.status === 'failed' && (
        <div className="inline-error" role="alert">
          <h3>SBOM generation failed</h3>
          <p>{data.error_details ?? 'The artifact could not be generated.'}</p>
          {data.error_code && (
            <p>
              <code>{data.error_code}</code>
            </p>
          )}
          <p>This is separate from vulnerability collection.</p>
        </div>
      )}
      {data?.status === 'available' && (
        <>
          <p className="artifact-status">Available</p>
          <dl className="identity-grid sbom-metadata">
            <div>
              <dt>Format</dt>
              <dd>{data.format ?? 'Not recorded'}</dd>
            </div>
            <div>
              <dt>Format version</dt>
              <dd>{data.format_version ?? 'Not recorded'}</dd>
            </div>
            <div>
              <dt>Scanner version</dt>
              <dd>{data.scanner_version ?? 'Not recorded'}</dd>
            </div>
            <div>
              <dt>Platform</dt>
              <dd>{data.platform ?? 'Not recorded'}</dd>
            </div>
            <div>
              <dt>Size</dt>
              <dd>
                {data.size_bytes === null
                  ? 'Not recorded'
                  : `${data.size_bytes.toLocaleString('en-US')} bytes`}
              </dd>
            </div>
            <div>
              <dt>Created</dt>
              <dd>
                {data.created_at ? (
                  <time dateTime={data.created_at}>
                    {new Date(data.created_at)
                      .toISOString()
                      .replace('T', ' ')
                      .replace('Z', ' UTC')}
                  </time>
                ) : (
                  'Not recorded'
                )}
              </dd>
            </div>
            <div className="identity-wide">
              <dt>Pinned image reference</dt>
              <dd>
                <code>{data.pinned_reference ?? 'Not recorded'}</code>
              </dd>
            </div>
            <div className="identity-wide">
              <dt>SHA-256 checksum</dt>
              <dd>
                <code>{data.sha256 ?? 'Not recorded'}</code>
              </dd>
            </div>
          </dl>
          <p className="field-help">
            Download the original saved JSON bytes. The checksum can verify the
            downloaded file.
          </p>
          <button
            type="button"
            className="button-secondary sbom-download"
            disabled={action?.pending}
            onClick={() => {
              void save();
            }}
          >
            {action?.pending ? 'Downloading…' : 'Download SBOM'}
          </button>
        </>
      )}
      {action?.error && (
        <p className="inline-error" role="alert">
          {action.error}
        </p>
      )}
      {action?.success && (
        <p role="status">Download started. Check your browser downloads.</p>
      )}
    </section>
  );
}
