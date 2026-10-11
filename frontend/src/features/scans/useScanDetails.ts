import { useEffect, useState, useSyncExternalStore } from 'react';
import { ApiError } from '../../api/client';
import { getScan } from '../../api/scans';
import type { ScanDetails } from '../../api/types';

const POLL_DELAY_MS = 3000;
const OBSERVATION_LIMIT_MS = 600000;
type PauseReason = 'hidden' | 'deadline' | 'error' | null;
interface Snapshot {
  scanId: string;
  detail: ScanDetails | null;
  error: ApiError | null;
  pause: PauseReason;
  checkedAt: Date | null;
}
function subscribeVisibility(notify: () => void) {
  document.addEventListener('visibilitychange', notify);
  return () => document.removeEventListener('visibilitychange', notify);
}
function isHidden() {
  return document.visibilityState === 'hidden';
}
function isTerminal(detail: ScanDetails | null) {
  return detail?.status === 'completed' || detail?.status === 'failed';
}

export function useScanDetails(scanId: string) {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const hidden = useSyncExternalStore(
    subscribeVisibility,
    isHidden,
    () => false,
  );

  useEffect(() => {
    let active = true;
    let stopped = false;
    let controller: AbortController | null = null;
    let pollTimer: ReturnType<typeof setTimeout> | undefined;
    const expiresAt = Date.now() + OBSERVATION_LIMIT_MS;

    function cancelPending() {
      clearTimeout(pollTimer);
      controller?.abort();
      controller = null;
    }
    function stop() {
      stopped = true;
      cancelPending();
      clearTimeout(deadlineTimer);
    }
    function finishWindow() {
      if (!active || stopped) return;
      stop();
      setSnapshot((previous) => ({
        scanId,
        detail: previous?.scanId === scanId ? previous.detail : null,
        checkedAt: previous?.scanId === scanId ? previous.checkedAt : null,
        error: null,
        pause: 'deadline',
      }));
    }
    async function load() {
      if (!active || stopped || isHidden() || controller) return;
      if (Date.now() >= expiresAt) {
        finishWindow();
        return;
      }
      const current = new AbortController();
      controller = current;
      try {
        const detail = await getScan(scanId, current.signal);
        if (
          !active ||
          stopped ||
          controller !== current ||
          current.signal.aborted
        )
          return;
        if (Date.now() >= expiresAt) {
          finishWindow();
          return;
        }
        controller = null;
        setSnapshot({
          scanId,
          detail,
          error: null,
          pause: null,
          checkedAt: new Date(),
        });
        if (isTerminal(detail)) stop();
        else
          pollTimer = setTimeout(() => {
            void load();
          }, POLL_DELAY_MS);
      } catch (error) {
        if (
          !active ||
          stopped ||
          controller !== current ||
          current.signal.aborted
        )
          return;
        if (Date.now() >= expiresAt) {
          finishWindow();
          return;
        }
        controller = null;
        stop();
        const safeError =
          error instanceof ApiError
            ? error
            : new ApiError('Could not load the scan status.');
        setSnapshot((previous) => ({
          scanId,
          detail: previous?.scanId === scanId ? previous.detail : null,
          checkedAt: previous?.scanId === scanId ? previous.checkedAt : null,
          error: safeError,
          pause: 'error',
        }));
      }
    }
    function visibilityChanged() {
      if (!active || stopped) return;
      if (Date.now() >= expiresAt) finishWindow();
      else if (isHidden()) cancelPending();
      else void load();
    }
    const deadlineTimer = setTimeout(finishWindow, OBSERVATION_LIMIT_MS);
    document.addEventListener('visibilitychange', visibilityChanged);
    void load();
    return () => {
      active = false;
      stop();
      document.removeEventListener('visibilitychange', visibilityChanged);
    };
  }, [scanId]);

  // Keep the latest observed record, but never carry it to another scan.
  const current = snapshot?.scanId === scanId ? snapshot : null;
  const detail = current?.detail ?? null;
  const error = current?.error ?? null;
  const pause = current?.pause ?? null;
  const observationPaused: PauseReason =
    pause ?? (hidden && !isTerminal(detail) ? 'hidden' : null);
  return {
    detail,
    loading: !detail && !error && !pause,
    error,
    observationPaused,
    checkedAt: current?.checkedAt ?? null,
  };
}
