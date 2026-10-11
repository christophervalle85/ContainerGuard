import { act, renderHook } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { useScanDetails } from './useScanDetails';
import { completedScan, scanId } from '../../../tests/fixtures';
import type { ScanStatus } from '../../api/types';

const otherId = '8269d321-ba64-4208-8341-f07f072a9475';
const START = Date.parse('2026-10-10T20:00:00Z');
let visibility: 'visible' | 'hidden';
beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(START);
  visibility = 'visible';
  vi.spyOn(document, 'visibilityState', 'get').mockImplementation(
    () => visibility,
  );
});
function report(status: ScanStatus = 'queued', id = scanId) {
  return {
    ...completedScan,
    scan_id: id,
    status,
    completed_at: ['completed', 'failed'].includes(status)
      ? completedScan.completed_at
      : null,
  };
}
function response(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
function serve(
  handler?: (url: string, options: RequestInit) => Response | Promise<Response>,
) {
  const fetcher = vi.fn(
    async (url: string, options: RequestInit) =>
      handler?.(url, options) ?? response(report()),
  );
  vi.stubGlobal('fetch', fetcher);
  return fetcher;
}
async function flush() {
  await act(async () => {});
}
async function advance(ms: number) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}
async function visible(value: 'visible' | 'hidden') {
  await act(async () => {
    visibility = value;
    document.dispatchEvent(new Event('visibilitychange'));
  });
}
function deferred() {
  let resolve!: (response: Response) => void;
  const promise = new Promise<Response>((yes) => {
    resolve = yes;
  });
  return { promise, resolve };
}

describe('bounded scan observation', () => {
  it('follows queued to running to completed with three seconds between completed requests', async () => {
    let count = 0;
    const fetcher = serve(() =>
      response(report((['queued', 'running', 'completed'] as const)[count++])),
    );
    const { result } = renderHook(() => useScanDetails(scanId));
    await flush();
    expect(result.current.detail?.status).toBe('queued');
    await advance(2999);
    expect(fetcher).toHaveBeenCalledTimes(1);
    await advance(1);
    expect(result.current.detail?.status).toBe('running');
    await advance(3000);
    expect(result.current.detail?.status).toBe('completed');
    await advance(600000);
    expect(fetcher).toHaveBeenCalledTimes(3);
    expect(vi.getTimerCount()).toBe(0);
    expect(
      fetcher.mock.calls.every(
        ([url, options]) =>
          url === `/api/v1/scans/${scanId}` && options.method !== 'POST',
      ),
    ).toBe(true);
  });
  it.each(['completed', 'failed'] as const)(
    'stops immediately after terminal status %s',
    async (status) => {
      const fetcher = serve(() => response(report(status)));
      const { result } = renderHook(() => useScanDetails(scanId));
      await flush();
      expect(result.current.detail?.status).toBe(status);
      await advance(600000);
      expect(fetcher).toHaveBeenCalledTimes(1);
      expect(result.current.observationPaused).toBeNull();
      expect(vi.getTimerCount()).toBe(0);
    },
  );
  it('waits for a slow request before starting the three-second delay', async () => {
    const pending = deferred();
    let count = 0;
    const fetcher = serve(() =>
      ++count === 1 ? pending.promise : response(report('completed')),
    );
    renderHook(() => useScanDetails(scanId));
    await flush();
    await advance(10000);
    expect(fetcher).toHaveBeenCalledTimes(1);
    await act(async () => pending.resolve(response(report('running'))));
    await advance(2999);
    expect(fetcher).toHaveBeenCalledTimes(1);
    await advance(1);
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
  it('stops on an API error, retains the last response, and does not retry after visibility changes', async () => {
    let count = 0;
    const fetcher = serve(() =>
      ++count === 1
        ? response(report())
        : response({ detail: 'unavailable' }, 503),
    );
    const { result } = renderHook(() => useScanDetails(scanId));
    await flush();
    await advance(3000);
    expect(result.current.error?.status).toBe(503);
    expect(result.current.detail?.status).toBe('queued');
    expect(result.current.observationPaused).toBe('error');
    await visible('hidden');
    await visible('visible');
    await advance(600000);
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
  it('stops after the shared fifteen-second request timeout', async () => {
    const fetcher = serve(
      (_url, options) =>
        new Promise((_resolve, reject) =>
          options.signal?.addEventListener(
            'abort',
            () => reject(new DOMException('Aborted', 'AbortError')),
            { once: true },
          ),
        ),
    );
    const { result } = renderHook(() => useScanDetails(scanId));
    await flush();
    await advance(15000);
    expect(result.current.error?.kind).toBe('timeout');
    expect(result.current.observationPaused).toBe('error');
    await advance(600000);
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it('bounds elapsed observation to ten minutes without changing server status', async () => {
    const fetcher = serve(() => response(report('running')));
    const { result } = renderHook(() => useScanDetails(scanId));
    await flush();
    await advance(599999);
    const before = fetcher.mock.calls.length;
    expect(result.current.observationPaused).toBeNull();
    await advance(1);
    expect(result.current.observationPaused).toBe('deadline');
    expect(result.current.detail?.status).toBe('running');
    expect(fetcher).toHaveBeenCalledTimes(before);
    await advance(60000);
    expect(fetcher).toHaveBeenCalledTimes(before);
    expect(vi.getTimerCount()).toBe(0);
  });
  it('starts a fresh bounded observation window after remounting the page', async () => {
    const fetcher = serve(() => response(report('running')));
    const first = renderHook(() => useScanDetails(scanId));
    await flush();
    await advance(600000);
    expect(first.result.current.observationPaused).toBe('deadline');
    first.unmount();
    const before = fetcher.mock.calls.length;
    const second = renderHook(() => useScanDetails(scanId));
    await flush();
    expect(second.result.current.observationPaused).toBeNull();
    expect(fetcher).toHaveBeenCalledTimes(before + 1);
    expect(second.result.current.detail?.status).toBe('running');
  });
  it('pauses hidden tabs and resumes with one request on return', async () => {
    const fetcher = serve();
    const { result } = renderHook(() => useScanDetails(scanId));
    await flush();
    await visible('hidden');
    expect(result.current.observationPaused).toBe('hidden');
    await advance(9000);
    expect(fetcher).toHaveBeenCalledTimes(1);
    await visible('visible');
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(result.current.observationPaused).toBeNull();
  });
  it('counts hidden time toward the same ten-minute deadline', async () => {
    const fetcher = serve();
    await visible('hidden');
    const { result } = renderHook(() => useScanDetails(scanId));
    await flush();
    expect(fetcher).not.toHaveBeenCalled();
    expect(result.current.observationPaused).toBe('hidden');
    await advance(590000);
    await visible('visible');
    expect(fetcher).toHaveBeenCalledTimes(1);
    await advance(10000);
    expect(result.current.observationPaused).toBe('deadline');
  });
  it('does not resume automatically if its deadline expired while hidden', async () => {
    const fetcher = serve();
    const { result } = renderHook(() => useScanDetails(scanId));
    await flush();
    await visible('hidden');
    await advance(600000);
    await visible('visible');
    expect(result.current.observationPaused).toBe('deadline');
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it('cancels a hidden-tab request and ignores its late response after resuming', async () => {
    const pending = deferred();
    let count = 0;
    const fetcher = serve(() =>
      ++count === 1 ? pending.promise : response(report('running')),
    );
    const { result } = renderHook(() => useScanDetails(scanId));
    await flush();
    const signal = fetcher.mock.calls[0][1].signal;
    await visible('hidden');
    expect(signal?.aborted).toBe(true);
    await visible('visible');
    expect(result.current.detail?.status).toBe('running');
    await act(async () => pending.resolve(response(report('completed'))));
    expect(result.current.detail?.status).toBe('running');
  });
  it('aborts a request still in progress when the observation deadline arrives', async () => {
    const pending = deferred();
    const fetcher = serve(() =>
      Date.now() >= START + 597000
        ? pending.promise
        : response(report('running')),
    );
    const { result } = renderHook(() => useScanDetails(scanId));
    await flush();
    await advance(599999);
    const signal = fetcher.mock.calls.at(-1)?.[1].signal;
    expect(signal?.aborted).toBe(false);
    await advance(1);
    expect(signal?.aborted).toBe(true);
    expect(result.current.observationPaused).toBe('deadline');
    await act(async () => pending.resolve(response(report('completed'))));
    expect(result.current.detail?.status).toBe('running');
    expect(result.current.error).toBeNull();
  });
  it('cancels and ignores responses from a previous scan ID', async () => {
    const pending = deferred();
    const fetcher = serve((url) =>
      url.endsWith(scanId)
        ? pending.promise
        : response(report('completed', otherId)),
    );
    const { result, rerender } = renderHook(({ id }) => useScanDetails(id), {
      initialProps: { id: scanId },
    });
    await flush();
    const signal = fetcher.mock.calls[0][1].signal;
    rerender({ id: otherId });
    await flush();
    expect(signal?.aborted).toBe(true);
    expect(result.current.detail?.scan_id).toBe(otherId);
    await act(async () => pending.resolve(response(report('completed'))));
    expect(result.current.detail?.scan_id).toBe(otherId);
  });
  it('never displays the old scan identity while a new ID is loading', async () => {
    const pending = deferred();
    serve((url) =>
      url.endsWith(scanId) ? response(report('completed')) : pending.promise,
    );
    const { result, rerender } = renderHook(({ id }) => useScanDetails(id), {
      initialProps: { id: scanId },
    });
    await flush();
    expect(result.current.detail?.scan_id).toBe(scanId);
    rerender({ id: otherId });
    expect(result.current.detail).toBeNull();
    expect(result.current.loading).toBe(true);
    await act(async () =>
      pending.resolve(response(report('completed', otherId))),
    );
    expect(result.current.detail?.scan_id).toBe(otherId);
  });
  it('cleans up the active request and timers on unmount', async () => {
    const pending = deferred();
    const fetcher = serve(() => pending.promise);
    const { unmount } = renderHook(() => useScanDetails(scanId));
    await flush();
    unmount();
    expect(fetcher.mock.calls[0][1].signal?.aborted).toBe(true);
    await act(async () => pending.resolve(response(report('completed'))));
    expect(vi.getTimerCount()).toBe(0);
    await advance(600000);
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it('leaves one polling loop after a StrictMode development remount', async () => {
    const fetcher = serve();
    const { result, unmount } = renderHook(() => useScanDetails(scanId), {
      reactStrictMode: true,
    });
    await flush();
    expect(result.current.detail?.status).toBe('queued');
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(fetcher.mock.calls[0][1].signal?.aborted).toBe(true);
    await advance(3000);
    expect(fetcher).toHaveBeenCalledTimes(3);
    unmount();
    expect(vi.getTimerCount()).toBe(0);
  });
  it('stops when an unfinished scan transitions to execution failure', async () => {
    let count = 0;
    const fetcher = serve(() =>
      response(report(++count === 1 ? 'running' : 'failed')),
    );
    const { result } = renderHook(() => useScanDetails(scanId));
    await flush();
    await advance(3000);
    expect(result.current.detail?.status).toBe('failed');
    expect(result.current.error).toBeNull();
    await advance(600000);
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(vi.getTimerCount()).toBe(0);
  });
  it('honors elapsed time even if a response arrives before a delayed deadline timer runs', async () => {
    const pending = deferred();
    let count = 0;
    serve(() =>
      ++count === 1 ? response(report('running')) : pending.promise,
    );
    const { result } = renderHook(() => useScanDetails(scanId));
    await flush();
    await advance(3000);
    vi.setSystemTime(START + 600001);
    await act(async () => pending.resolve(response(report('completed'))));
    expect(result.current.observationPaused).toBe('deadline');
    expect(result.current.detail?.status).toBe('running');
    expect(vi.getTimerCount()).toBe(0);
  });
  it('recovers from an API error after page remount without submitting work', async () => {
    let count = 0;
    const fetcher = serve(() =>
      ++count === 1
        ? response({ detail: 'unavailable' }, 503)
        : response(report('completed')),
    );
    const first = renderHook(() => useScanDetails(scanId));
    await flush();
    expect(first.result.current.error?.status).toBe(503);
    first.unmount();
    const second = renderHook(() => useScanDetails(scanId));
    await flush();
    expect(second.result.current.error).toBeNull();
    expect(second.result.current.detail?.status).toBe('completed');
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
});
