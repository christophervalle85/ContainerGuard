import type { ScanStatus } from '../api/types';
const labels: Record<ScanStatus, string> = {
  queued: 'Queued',
  running: 'Running',
  completed: 'Completed',
  failed: 'Failed',
};
export function StatusLabel({ status }: { status: ScanStatus }) {
  return (
    <span className={`status-label status-${status}`}>{labels[status]}</span>
  );
}
