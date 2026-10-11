import { Link, useParams } from 'react-router';
import { StatusLabel } from '../../components/StatusLabel';
import { EvaluationSection } from './EvaluationSection';
import { FindingsSection } from './FindingsSection';
import { SbomSection } from './SbomSection';
import { ScanIdentity } from './ScanIdentity';
import { useScanDetails } from './useScanDetails';

export function ScanDetailsPage() {
  const { scanId = '' } = useParams();
  const { detail, loading, error, observationPaused, checkedAt } =
    useScanDetails(scanId);
  const unfinished =
    detail?.status === 'queued' || detail?.status === 'running';
  return (
    <section>
      <Link className="back-link" to="/scans">
        Back to scans
      </Link>
      <div className="section-heading">
        <div>
          <p className="eyebrow">Saved scan</p>
          <h1>Scan details</h1>
          {detail && <p className="detail-image">{detail.image_reference}</p>}
        </div>
      </div>
      {loading && <p role="status">Loading scan status…</p>}
      {error && (
        <div className="inline-error" role="alert">
          <h2>
            {error.status === 404
              ? 'Scan not found'
              : 'Could not load scan status'}
          </h2>
          <p>{error.message}</p>
          <p>
            {detail ? 'The last loaded record remains below. ' : ''}Automatic
            checks have stopped. Reload the page to try again. Reloading does
            not submit another scan.
          </p>
        </div>
      )}
      {detail && (
        <>
          {detail.mock && (
            <div className="notice-message">
              <h2>Fictional sample scan</h2>
              <p>This is legacy demonstration data, not a real image scan.</p>
            </div>
          )}
          <div className="scan-progress" aria-live="polite" aria-atomic="true">
            <StatusLabel status={detail.status} />
            {detail.status === 'queued' && (
              <p>Waiting for a worker to start the scan.</p>
            )}
            {detail.status === 'running' && (
              <p>The worker is processing this image.</p>
            )}
          </div>
          {detail.status === 'failed' && (
            <div className="inline-error" role="alert">
              <h2>Scan execution failed</h2>
              <p>
                {detail.error_details ?? 'The scan could not be completed.'}
              </p>
            </div>
          )}
        </>
      )}
      {observationPaused === 'deadline' && (
        <p className="notice-message">
          Automatic status checks stopped after 10 minutes. This does not cancel
          the server job. Reload the page to check again. Reloading resumes
          observation without submitting another scan.
        </p>
      )}
      {observationPaused === 'hidden' && (
        <p className="muted">
          Status checks are paused while this tab is hidden. The 10-minute
          observation limit still applies.
        </p>
      )}
      {unfinished && !observationPaused && (
        <p className="muted">
          Checking status every 3 seconds after each response, for up to 10
          minutes.
        </p>
      )}
      {checkedAt && (
        <p className="muted checked-at">
          Last checked:{' '}
          <time dateTime={checkedAt.toISOString()}>
            {checkedAt.toISOString().replace('T', ' ').replace('Z', ' UTC')}
          </time>
        </p>
      )}
      {detail && (
        <>
          <nav className="detail-navigation" aria-label="Scan sections">
            <a href="#identity-heading">Overview</a>
            <a href="#findings-heading">Findings</a>
            <a href="#sbom-heading">SBOM</a>
            <a href="#evaluations-heading">Evaluations</a>
          </nav>
          <ScanIdentity key={detail.scan_id} scan={detail} />
          <FindingsSection key={`findings/${detail.scan_id}`} scan={detail} />
          <SbomSection key={`sbom/${detail.scan_id}`} scan={detail} />
          <EvaluationSection
            key={`evaluation/${detail.scan_id}`}
            scan={detail}
          />
        </>
      )}
    </section>
  );
}
