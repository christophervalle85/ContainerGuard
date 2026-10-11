import { useState } from 'react';
import type { ScanDetails } from '../../api/types';

function CopyValue({ label, value }: { label: string; value: string }) {
  const [feedback, setFeedback] = useState('');
  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setFeedback('Copied.');
    } catch {
      setFeedback('Copy failed. Select and copy the value above.');
    }
  }
  return (
    <div className="copy-value">
      <code>{value}</code>
      <div className="copy-controls">
        <button
          type="button"
          className="button-secondary button-compact"
          aria-label={`Copy ${label}`}
          onClick={() => {
            void copy();
          }}
        >
          Copy
        </button>
        <span role="status">{feedback}</span>
      </div>
    </div>
  );
}
function Timestamp({ value }: { value: string | null }) {
  return value ? (
    <time dateTime={value}>
      {new Date(value).toISOString().replace('T', ' ').replace('Z', ' UTC')}
    </time>
  ) : (
    <>Not recorded</>
  );
}
export function ScanIdentity({ scan }: { scan: ScanDetails }) {
  const unfinished = scan.status === 'queued' || scan.status === 'running';
  return (
    <section className="scan-identity" aria-labelledby="identity-heading">
      <h2 id="identity-heading">Image and scan record</h2>
      <dl className="identity-grid">
        <div className="identity-wide">
          <dt>Image reference</dt>
          <dd>
            <code>{scan.image_reference}</code>
          </dd>
        </div>
        <div className="identity-wide">
          <dt>Scan ID</dt>
          <dd>
            <CopyValue
              key={scan.scan_id}
              label="scan ID"
              value={scan.scan_id}
            />
          </dd>
        </div>
        <div className="identity-wide">
          <dt>Resolved digest</dt>
          <dd>
            {scan.digest ? (
              <CopyValue key={scan.digest} label="digest" value={scan.digest} />
            ) : unfinished ? (
              'Not yet resolved'
            ) : (
              'Not recorded'
            )}
          </dd>
        </div>
        <div>
          <dt>Platform</dt>
          <dd>{scan.platform ?? 'Not recorded'}</dd>
        </div>
        <div>
          <dt>Scanner</dt>
          <dd>{scan.scanner_name ?? 'Not recorded'}</dd>
        </div>
        <div>
          <dt>Scanner version</dt>
          <dd>{scan.scanner_version ?? 'Not recorded'}</dd>
        </div>
        <div>
          <dt>Created</dt>
          <dd>
            <Timestamp value={scan.created_at} />
          </dd>
        </div>
        <div>
          <dt>Started</dt>
          <dd>
            <Timestamp value={scan.started_at} />
          </dd>
        </div>
        <div>
          <dt>Completed</dt>
          <dd>
            <Timestamp value={scan.completed_at} />
          </dd>
        </div>
      </dl>
      {scan.scanner_database_metadata ? (
        <details className="database-metadata">
          <summary>Scanner database metadata</summary>
          <pre>{JSON.stringify(scan.scanner_database_metadata, null, 2)}</pre>
        </details>
      ) : (
        <p className="muted">No database metadata recorded.</p>
      )}
    </section>
  );
}
