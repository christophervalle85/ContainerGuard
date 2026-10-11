import { describe, expect, it, vi } from 'vitest';
import { ApiError, requestDownload, requestJson } from './client';
import { getScan, listScans } from './scans';
import { completedScan, scanId } from '../../tests/fixtures';

function respond(body: unknown, status = 200) {
  const fetcher = vi.fn().mockResolvedValue(
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    }),
  );
  vi.stubGlobal('fetch', fetcher);
  return fetcher;
}
function stalledFetch() {
  const fetcher = vi.fn(
    (_path, options: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        options.signal?.addEventListener(
          'abort',
          () => reject(new DOMException('Aborted', 'AbortError')),
          { once: true },
        );
      }),
  );
  vi.stubGlobal('fetch', fetcher);
  return fetcher;
}

describe('API boundary', () => {
  it('requests the relative API URL and returns validated persisted scan details', async () => {
    const fetcher = respond(completedScan);
    await expect(getScan(scanId)).resolves.toMatchObject({
      scan_id: scanId,
      status: 'completed',
      mock: false,
      platform: 'linux/amd64',
    });
    expect(fetcher.mock.calls[0][0]).toBe(
      '/api/v1/scans/ff4599e5-4e9f-44c7-bbc2-e02db78bc008',
    );
  });
  it.each([404, 409, 422, 502, 503, 504])(
    'reports a safe HTTP %s error without raw server text',
    async (status) => {
      respond({ detail: 'INTERNAL database password=secret' }, status);
      const error = await requestJson('/api/v1/scans').catch((e) => e);
      if (!(error instanceof ApiError))
        throw new Error('Expected an API error');
      expect(error).toBeInstanceOf(ApiError);
      expect(error.status).toBe(status);
      expect(error.message).not.toMatch(/INTERNAL|password|secret/);
      expect(error.message.length).toBeGreaterThan(10);
      if ([502, 503, 504].includes(status))
        expect(error.message).toMatch(/temporarily unavailable/);
    },
  );
  it('keeps validation field locations without exposing rejected input', async () => {
    respond(
      {
        detail: [
          {
            loc: ['body', 'image_reference'],
            msg: 'secret raw diagnostic',
            type: 'value_error',
            input: 'secret',
          },
        ],
      },
      422,
    );
    const error = await requestJson('/api/v1/scans').catch((e) => e);
    if (!(error instanceof ApiError)) throw new Error('Expected an API error');
    expect(error.fields).toEqual([
      { field: 'image_reference', message: 'Invalid value.' },
    ]);
    expect(JSON.stringify(error.fields)).not.toContain('secret');
  });
  it('never retries a failed POST', async () => {
    const fetcher = respond({ detail: 'Unavailable' }, 503);
    await expect(
      requestJson('/api/v1/scans', {
        method: 'POST',
        body: JSON.stringify({ image_reference: 'alpine:3.20' }),
      }),
    ).rejects.toMatchObject({ status: 503 });
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(fetcher.mock.calls[0][1]).toMatchObject({
      method: 'POST',
      body: '{"image_reference":"alpine:3.20"}',
    });
  });
  it.each([
    'https://other.example/api/v1/scans',
    '//other.example/api/v1/scans',
    '/api/v1/../../secrets',
    '/docs',
  ])('rejects a URL outside the API boundary: %s', async (path) => {
    const fetcher = respond({});
    await expect(requestJson(path)).rejects.toBeInstanceOf(ApiError);
    expect(fetcher).not.toHaveBeenCalled();
  });
  it('rejects malformed JSON rather than treating it as an empty success', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response('{broken', {
          headers: { 'Content-Type': 'application/json' },
        }),
      ),
    );
    await expect(requestJson('/api/v1/scans')).rejects.toBeInstanceOf(ApiError);
  });
  it('rejects an HTML fallback response', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response('<html>SPA</html>', {
          headers: { 'Content-Type': 'text/html' },
        }),
      ),
    );
    await expect(requestJson('/api/v1/scans')).rejects.toBeInstanceOf(ApiError);
  });
  it.each([
    { ...completedScan, status: 'unrecognized' },
    { ...completedScan, mock: 'false' },
    { ...completedScan, created_at: null },
    { ...completedScan, digest: 'not-a-digest' },
  ])('rejects an invalid scan contract', async (body) => {
    respond(body);
    await expect(getScan(scanId)).rejects.toBeInstanceOf(ApiError);
  });
  it('does not invent a missing history total or accept negative totals', async () => {
    respond({ items: [], limit: 20, offset: 0 });
    await expect(listScans({ limit: 20, offset: 0 })).rejects.toBeInstanceOf(
      ApiError,
    );
    respond({ items: [], total: -1, limit: 20, offset: 0 });
    await expect(listScans({ limit: 20, offset: 0 })).rejects.toBeInstanceOf(
      ApiError,
    );
  });
  it('aborts a request after fifteen seconds', async () => {
    vi.useFakeTimers();
    const fetcher = stalledFetch();
    const result = requestJson('/api/v1/scans').catch((error) => error);
    await vi.advanceTimersByTimeAsync(14999);
    expect(fetcher.mock.calls[0][1].signal?.aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(await result).toMatchObject({ kind: 'timeout' });
    expect(fetcher.mock.calls[0][1].signal?.aborted).toBe(true);
  });
  it('preserves caller cancellation and clears its deadline', async () => {
    vi.useFakeTimers();
    stalledFetch();
    const caller = new AbortController();
    const result = requestJson('/api/v1/scans', {
      signal: caller.signal,
    }).catch((error) => error);
    caller.abort();
    expect(await result).toMatchObject({ name: 'AbortError' });
    expect(vi.getTimerCount()).toBe(0);
  });
  it('does not send a request when the caller is already aborted', async () => {
    const fetcher = respond({});
    const caller = new AbortController();
    caller.abort();
    await expect(
      requestJson('/api/v1/scans', { signal: caller.signal }),
    ).rejects.toMatchObject({ name: 'AbortError' });
    expect(fetcher).not.toHaveBeenCalled();
  });
  it('clears the deadline after success and reports network failure safely', async () => {
    vi.useFakeTimers();
    respond({ ok: true });
    await requestJson('/api/v1/scans');
    expect(vi.getTimerCount()).toBe(0);
    vi.stubGlobal(
      'fetch',
      vi.fn().mockRejectedValue(new TypeError('secret diagnostic')),
    );
    const error = await requestJson('/api/v1/scans').catch((e) => e);
    if (!(error instanceof ApiError)) throw new Error('Expected an API error');
    expect(error).toMatchObject({ kind: 'network' });
    expect(error.message).not.toContain('secret');
  });
  it('returns original download bytes without JSON decoding', async () => {
    const raw = ' { "bomFormat" : "CycloneDX" }\n';
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(raw, {
          headers: { 'Content-Type': 'application/json' },
        }),
      ),
    );
    const blob = await requestDownload(`/api/v1/scans/${scanId}/sbom`);
    expect(await blob.text()).toBe(raw);
  });
  it('does not download an HTTP error body as an artifact', async () => {
    respond({ detail: 'No available SBOM' }, 404);
    await expect(
      requestDownload(`/api/v1/scans/${scanId}/sbom`),
    ).rejects.toMatchObject({ status: 404 });
  });
});
