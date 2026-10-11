import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, it, expect, vi } from 'vitest';
import { SbomSection } from './SbomSection';
import {
  availableSbom,
  emptySbom,
  completedScan,
  scanId,
} from '../../../tests/fixtures';
import type { ScanDetails } from '../../api/types';
const scan: ScanDetails = { ...completedScan, status: 'completed' };
const payload = '{ "bomFormat" : "CycloneDX", "components": [] }\n';
let saved: { href: string; filename: string }[];
let created: ReturnType<typeof vi.fn<(blob: Blob | MediaSource) => string>>;
let revoked: ReturnType<typeof vi.fn<(url: string) => void>>;
beforeEach(() => {
  saved = [];
  created = vi.fn<(blob: Blob | MediaSource) => string>(
    () => 'blob:fixture-sbom',
  );
  revoked = vi.fn<(url: string) => void>();
  const OriginalURL = URL;
  vi.stubGlobal(
    'URL',
    class extends OriginalURL {
      static createObjectURL = created;
      static revokeObjectURL = revoked;
    },
  );
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
    this: HTMLAnchorElement,
  ) {
    saved.push({ href: this.href, filename: this.download });
  });
});
function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
function server(
  metadata: unknown = availableSbom,
  download?: () => Response | Promise<Response>,
) {
  const fetcher = vi.fn(async (url: string) =>
    url.endsWith('/metadata')
      ? json(metadata)
      : (download?.() ??
        new Response(payload, {
          headers: { 'Content-Type': 'application/json' },
        })),
  );
  vi.stubGlobal('fetch', fetcher);
  return fetcher;
}
function deferred() {
  let resolve!: (r: Response) => void;
  const promise = new Promise<Response>((yes) => {
    resolve = yes;
  });
  return { promise, resolve };
}
describe('saved SBOM', () => {
  it('shows recorded metadata without downloading the payload', async () => {
    const fetcher = server();
    render(<SbomSection scan={scan} />);
    await screen.findByText('Available');
    expect(screen.getByText('CycloneDX')).toBeInTheDocument();
    expect(screen.getByText('1.7')).toBeInTheDocument();
    expect(screen.getByText('25,482 bytes')).toBeInTheDocument();
    expect(screen.getByText(availableSbom.sha256)).toBeInTheDocument();
    expect(
      screen.getByText(availableSbom.pinned_reference),
    ).toBeInTheDocument();
    expect(screen.getByText('linux/amd64')).toBeInTheDocument();
    expect(screen.getByText('0.75.0')).toBeInTheDocument();
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(fetcher.mock.calls[0][0]).toBe(
      `/api/v1/scans/${scanId}/sbom/metadata`,
    );
    expect(created).not.toHaveBeenCalled();
  });
  it.each([
    ['pending', /still being prepared/i],
    ['not_generated', /no SBOM was generated/i],
    ['failed', /SBOM generation failed/i],
  ] as const)(
    'explains %s without offering a download',
    async (status, message) => {
      server({
        ...emptySbom,
        status,
        error_code: status === 'failed' ? 'sbom_failed' : null,
        error_details:
          status === 'failed' ? 'SBOM could not be generated' : null,
      });
      render(<SbomSection scan={scan} />);
      expect(await screen.findByText(message)).toBeInTheDocument();
      expect(
        screen.queryByRole('button', { name: 'Download SBOM' }),
      ).not.toBeInTheDocument();
      expect(
        screen.queryByText(/scan execution failed/i),
      ).not.toBeInTheDocument();
    },
  );
  it('downloads only on request using the UUID filename and original bytes, then releases the URL', async () => {
    const fetcher = server();
    render(<SbomSection scan={scan} />);
    await screen.findByText('Available');
    await userEvent
      .setup()
      .click(screen.getByRole('button', { name: 'Download SBOM' }));
    await screen.findByText(/download started/i);
    expect(fetcher.mock.calls.at(-1)?.[0]).toBe(`/api/v1/scans/${scanId}/sbom`);
    expect(saved).toEqual([
      { href: 'blob:fixture-sbom', filename: `${scanId}.cdx.json` },
    ]);
    expect(await (created.mock.calls[0][0] as Blob).text()).toBe(payload);
    expect(revoked).toHaveBeenCalledWith('blob:fixture-sbom');
    expect(document.querySelector('a[download]')).toBeNull();
  });
  it.each([409, 404, 500])(
    'handles HTTP %s download failure while preserving metadata',
    async (status) => {
      const fetcher = server(availableSbom, () =>
        json({ detail: 'secret artifact diagnostic' }, status),
      );
      render(<SbomSection scan={scan} />);
      await screen.findByText('Available');
      await userEvent
        .setup()
        .click(screen.getByRole('button', { name: 'Download SBOM' }));
      expect(await screen.findByRole('alert')).toBeInTheDocument();
      expect(screen.getByText(availableSbom.sha256)).toBeInTheDocument();
      expect(
        screen.queryByText(/secret artifact diagnostic/),
      ).not.toBeInTheDocument();
      expect(saved).toHaveLength(0);
      expect(fetcher).toHaveBeenCalledTimes(2);
    },
  );
  it('handles a network download failure without automatic retry', async () => {
    const fetcher = server(availableSbom, () =>
      Promise.reject(new TypeError('network')),
    );
    render(<SbomSection scan={scan} />);
    await screen.findByText('Available');
    await userEvent
      .setup()
      .click(screen.getByRole('button', { name: 'Download SBOM' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      /could not reach/i,
    );
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(saved).toHaveLength(0);
  });
  it('disables duplicate downloads while the original request is pending', async () => {
    const pending = deferred();
    const fetcher = server(availableSbom, () => pending.promise);
    render(<SbomSection scan={scan} />);
    await screen.findByText('Available');
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Download SBOM' }));
    const button = screen.getByRole('button', { name: 'Downloading…' });
    expect(button).toBeDisabled();
    await user.click(button);
    expect(fetcher).toHaveBeenCalledTimes(2);
    await act(async () =>
      pending.resolve(
        new Response(payload, {
          headers: { 'Content-Type': 'application/json' },
        }),
      ),
    );
    expect(saved).toHaveLength(1);
  });
  it('cancels an in-flight download on navigation without creating an object URL', async () => {
    const pending = deferred();
    let signal: AbortSignal | null | undefined;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string, init: RequestInit) => {
        if (url.endsWith('/metadata')) return json(availableSbom);
        signal = init.signal;
        return pending.promise;
      }),
    );
    const { unmount } = render(<SbomSection scan={scan} />);
    await screen.findByText('Available');
    await userEvent
      .setup()
      .click(screen.getByRole('button', { name: 'Download SBOM' }));
    unmount();
    expect(signal?.aborted).toBe(true);
    await act(async () =>
      pending.resolve(
        new Response(payload, {
          headers: { 'Content-Type': 'application/json' },
        }),
      ),
    );
    expect(created).not.toHaveBeenCalled();
  });
  it('releases an object URL even if the browser cannot start the download', async () => {
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {
      throw new Error('blocked');
    });
    server();
    render(<SbomSection scan={scan} />);
    await screen.findByText('Available');
    await userEvent
      .setup()
      .click(screen.getByRole('button', { name: 'Download SBOM' }));
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(revoked).toHaveBeenCalledWith('blob:fixture-sbom');
    expect(document.querySelector('a[download]')).toBeNull();
  });
  it('shows metadata request errors independently of scan execution', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => json({ detail: 'private detail' }, 503)),
    );
    render(<SbomSection scan={scan} />);
    expect(await screen.findByRole('alert')).toHaveTextContent(
      /temporarily unavailable/i,
    );
    expect(
      screen.queryByText(/private detail|scan execution failed/i),
    ).not.toBeInTheDocument();
  });
  it('reloads metadata on the shared terminal transition without its own polling loop', async () => {
    const fetcher = server({ ...emptySbom, status: 'pending' });
    const { rerender } = render(
      <SbomSection scan={{ ...scan, status: 'running' }} />,
    );
    await screen.findByText(/still being prepared/i);
    server();
    rerender(<SbomSection scan={scan} />);
    await screen.findByText('Available');
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
});
