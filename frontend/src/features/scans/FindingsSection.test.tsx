import { act, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, useLocation } from 'react-router';
import { describe, it, expect, vi } from 'vitest';
import { FindingsSection } from './FindingsSection';
import { completedScan, scanId, sampleFinding } from '../../../tests/fixtures';
import type { ScanDetails } from '../../api/types';
const scan: ScanDetails = { ...completedScan, status: 'completed' };
function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
function page(
  items: unknown[] = [sampleFinding],
  total = items.length,
  limit = 20,
  offset = 0,
  mock = false,
) {
  return json({ items, total, limit, offset, mock });
}
function server(
  get?: (url: string, init: RequestInit) => Response | Promise<Response>,
) {
  const fetcher = vi.fn(
    async (url: string, init: RequestInit) => get?.(url, init) ?? page(),
  );
  vi.stubGlobal('fetch', fetcher);
  return fetcher;
}
function Location() {
  return <span data-testid="location">{useLocation().search}</span>;
}
function open(search = '', record = scan) {
  return render(
    <MemoryRouter initialEntries={[`/scans/${scanId}${search}`]}>
      <FindingsSection scan={record} />
      <Location />
    </MemoryRouter>,
  );
}
function deferred() {
  let resolve!: (r: Response) => void;
  const promise = new Promise<Response>((yes) => {
    resolve = yes;
  });
  return { promise, resolve };
}
describe('saved findings', () => {
  it('renders occurrence rows without deduplicating repeated CVEs and labels an absent fix', async () => {
    server(() =>
      page([
        sampleFinding,
        {
          ...sampleFinding,
          package_name: 'busybox-binsh',
          fixed_version: '1.36.1-r29',
        },
      ]),
    );
    open();
    const table = await screen.findByRole('table', {
      name: 'Vulnerability findings',
    });
    expect(within(table).getAllByText('CVE-2023-42364')).toHaveLength(2);
    expect(within(table).getByText('No known fix')).toBeInTheDocument();
    expect(within(table).getByText('1.36.1-r29')).toBeInTheDocument();
    expect(
      screen.getByText(/2 matching finding occurrences/i),
    ).toBeInTheDocument();
  });
  it('restores server-side severity and pagination from a direct URL', async () => {
    const fetcher = server(() => page([sampleFinding], 44, 20, 20));
    open('?severity=MEDIUM&limit=20&offset=20');
    await screen.findByText('busybox');
    expect(fetcher.mock.calls[0][0]).toBe(
      `/api/v1/scans/${scanId}/findings?limit=20&offset=20&severity=MEDIUM`,
    );
    expect(screen.getByRole('combobox', { name: 'Severity' })).toHaveValue(
      'MEDIUM',
    );
    expect(screen.getByText('21–40 of 44')).toBeInTheDocument();
  });
  it('changes severity on the server, resets offset, and shows the matching total', async () => {
    const fetcher = server((url) =>
      url.includes('severity=HIGH')
        ? page([{ ...sampleFinding, severity: 'HIGH' }], 1)
        : page([sampleFinding], 44, 20, 20),
    );
    open('?limit=20&offset=20&policy=keep');
    await screen.findByText('busybox');
    await userEvent
      .setup()
      .selectOptions(screen.getByLabelText('Severity'), 'HIGH');
    expect(
      await screen.findByText(/1 matching finding occurrence/i),
    ).toBeInTheDocument();
    expect(fetcher.mock.calls.at(-1)?.[0]).toBe(
      `/api/v1/scans/${scanId}/findings?limit=20&offset=0&severity=HIGH`,
    );
    expect(screen.getByTestId('location')).toHaveTextContent('offset=0');
    expect(screen.getByTestId('location')).toHaveTextContent('policy=keep');
  });
  it('requests the next page without loading the full result set', async () => {
    const fetcher = server((url) =>
      url.includes('offset=20')
        ? page([{ ...sampleFinding, package_name: 'next-package' }], 21, 20, 20)
        : page([sampleFinding], 21),
    );
    open();
    await screen.findByText('busybox');
    await userEvent
      .setup()
      .click(screen.getByRole('button', { name: 'Next page' }));
    expect(await screen.findByText('next-package')).toBeInTheDocument();
    expect(screen.queryByText('busybox')).not.toBeInTheDocument();
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
  it('resets pagination when the page size changes', async () => {
    const fetcher = server((url) =>
      url.includes('limit=50')
        ? page([sampleFinding], 80, 50)
        : page([sampleFinding], 80, 20, 20),
    );
    open('?limit=20&offset=20');
    await screen.findByText('busybox');
    await userEvent
      .setup()
      .selectOptions(screen.getByLabelText('Findings per page'), '50');
    await screen.findByText('1–50 of 80');
    expect(fetcher.mock.calls.at(-1)?.[0]).toContain('limit=50&offset=0');
  });
  it('normalizes invalid query values before requesting data', async () => {
    const fetcher = server();
    open('?severity=INVALID&limit=999&offset=-2');
    await screen.findByText('busybox');
    expect(fetcher.mock.calls[0][0]).toBe(
      `/api/v1/scans/${scanId}/findings?limit=20&offset=0`,
    );
    expect(screen.getByTestId('location')).not.toHaveTextContent('INVALID');
  });
  it('discards a slow response for the previous severity and cancels its request', async () => {
    const pending = deferred();
    const fetcher = server((url) =>
      url.includes('severity=HIGH')
        ? page([
            {
              ...sampleFinding,
              package_name: 'current-package',
              severity: 'HIGH',
            },
          ])
        : pending.promise,
    );
    open();
    await userEvent
      .setup()
      .selectOptions(screen.getByLabelText('Severity'), 'HIGH');
    await screen.findByText('current-package');
    expect(fetcher.mock.calls[0][1].signal?.aborted).toBe(true);
    await act(async () =>
      pending.resolve(
        page([{ ...sampleFinding, package_name: 'old-package' }]),
      ),
    );
    expect(screen.queryByText('old-package')).not.toBeInTheDocument();
  });
  it.each(['queued', 'running', 'failed'] as const)(
    'does not present %s execution as zero vulnerabilities',
    async (status) => {
      const fetcher = server();
      open('', { ...scan, status });
      expect(
        screen.getByText(
          status === 'failed'
            ? /unavailable because scan execution failed/i
            : /available after the scan completes/i,
        ),
      ).toBeInTheDocument();
      expect(fetcher).not.toHaveBeenCalled();
      expect(screen.queryByText(/no findings/i)).not.toBeInTheDocument();
    },
  );
  it('loads findings once when shared scan state changes to completed', async () => {
    const fetcher = server();
    const { rerender } = render(
      <MemoryRouter>
        <FindingsSection scan={{ ...scan, status: 'running' }} />
      </MemoryRouter>,
    );
    expect(fetcher).not.toHaveBeenCalled();
    rerender(
      <MemoryRouter>
        <FindingsSection scan={scan} />
      </MemoryRouter>,
    );
    await screen.findByText('busybox');
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it('distinguishes a completed empty result from a filtered empty result', async () => {
    server(() => page([], 0));
    open('?severity=CRITICAL');
    expect(
      await screen.findByText(/no findings match this severity/i),
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Next page' })).toBeDisabled();
  });
  it('labels a completed unfiltered zero result without claiming the image is safe', async () => {
    server(() => page([], 0));
    open();
    expect(
      await screen.findByText(/no vulnerability findings were recorded/i),
    ).toBeInTheDocument();
    expect(screen.queryByText(/image is safe/i)).not.toBeInTheDocument();
  });
  it('lets a past-end page return to previous results', async () => {
    server(() => page([], 1, 20, 40));
    open('?limit=20&offset=40');
    expect(
      await screen.findByText(/no findings on this page/i),
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Previous page' })).toBeEnabled();
  });
  it('labels fictional findings and presents API errors without raw diagnostics', async () => {
    server(() => page([sampleFinding], 1, 20, 0, true));
    open('', { ...scan, mock: true });
    expect(
      await screen.findByText(/fictional sample findings/i),
    ).toBeInTheDocument();
  });
  it('shows a failed findings request without inventing an empty result', async () => {
    server(() => json({ detail: 'secret diagnostic' }, 503));
    open();
    expect(await screen.findByRole('alert')).toHaveTextContent(
      /temporarily unavailable/i,
    );
    expect(
      screen.queryByText(/secret diagnostic|no vulnerability findings/i),
    ).not.toBeInTheDocument();
  });
  it('cancels a pending request on unmount and ignores its result', async () => {
    const pending = deferred();
    const fetcher = server(() => pending.promise);
    const { unmount } = open();
    unmount();
    expect(fetcher.mock.calls[0][1].signal?.aborted).toBe(true);
    await act(async () => pending.resolve(page()));
  });
});
