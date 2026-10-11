import { act, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router';
import { describe, expect, it, vi } from 'vitest';
import { App } from '../../app/App';
import {
  completedScan,
  scanId,
  evidenceFixture,
} from '../../../tests/fixtures';

function response(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
function serve(body: unknown = completedScan, status = 200) {
  const fetcher = vi.fn().mockImplementation(async (url: string) => {
    const evidence = evidenceFixture(url);
    return evidence === undefined ? response(body, status) : response(evidence);
  });
  vi.stubGlobal('fetch', fetcher);
  return fetcher;
}
function open() {
  return render(
    <MemoryRouter initialEntries={[`/scans/${scanId}`]}>
      <App />
    </MemoryRouter>,
  );
}
describe('scan detail workspace', () => {
  it('shows durable image identity, tool information, and explicitly UTC timestamps', async () => {
    const fetcher = serve();
    open();
    expect(await screen.findByText(completedScan.digest)).toBeInTheDocument();
    expect(screen.getByText(scanId)).toBeInTheDocument();
    expect(
      screen.getByText(completedScan.image_reference, { selector: 'code' }),
    ).toBeInTheDocument();
    expect(screen.getByText('linux/amd64')).toBeInTheDocument();
    expect(screen.getByText('trivy')).toBeInTheDocument();
    expect(screen.getByText('0.75.0')).toBeInTheDocument();
    expect(screen.getByText('2026-10-09 19:29:47.963 UTC')).toHaveAttribute(
      'datetime',
      completedScan.created_at,
    );
    expect(screen.getByText('2026-10-09 19:29:48.992 UTC')).toHaveAttribute(
      'datetime',
      completedScan.started_at,
    );
    expect(screen.getByText('2026-10-09 19:29:58.036 UTC')).toHaveAttribute(
      'datetime',
      completedScan.completed_at,
    );
    expect(
      fetcher.mock.calls.filter(([url]) => url === `/api/v1/scans/${scanId}`),
    ).toHaveLength(1);
    expect(fetcher.mock.calls[0][0]).toBe(`/api/v1/scans/${scanId}`);
  });
  it('exposes recorded scanner database metadata without inventing missing values', async () => {
    serve();
    open();
    await screen.findByText(completedScan.digest);
    await userEvent
      .setup()
      .click(screen.getByText('Scanner database metadata'));
    expect(
      screen.getByText(/"UpdatedAt": "2026-10-09T19:06:47.421531537Z"/),
    ).toBeInTheDocument();
  });
  it('copies complete scan IDs and digests', async () => {
    const user = userEvent.setup();
    serve();
    open();
    await screen.findByText(completedScan.digest);
    await user.click(screen.getByRole('button', { name: 'Copy scan ID' }));
    expect(await navigator.clipboard.readText()).toBe(scanId);
    await user.click(screen.getByRole('button', { name: 'Copy digest' }));
    expect(await navigator.clipboard.readText()).toBe(completedScan.digest);
  });
  it('keeps the full value visible when clipboard access fails', async () => {
    const user = userEvent.setup();
    vi.spyOn(navigator.clipboard, 'writeText').mockRejectedValue(
      new Error('denied'),
    );
    serve();
    open();
    await screen.findByText(completedScan.digest);
    await user.click(screen.getByRole('button', { name: 'Copy digest' }));
    expect(await screen.findByText(/copy failed/i)).toBeInTheDocument();
    expect(screen.getByText(completedScan.digest)).toBeInTheDocument();
  });
  it('labels unresolved fields and absent metadata in an unfinished scan', async () => {
    serve({
      ...completedScan,
      status: 'queued',
      started_at: null,
      completed_at: null,
      digest: null,
      platform: null,
      scanner_version: null,
      scanner_database_metadata: null,
    });
    open();
    expect(await screen.findByText('Queued')).toBeInTheDocument();
    expect(screen.getByText('Not yet resolved')).toBeInTheDocument();
    expect(
      screen.getByText('No database metadata recorded.'),
    ).toBeInTheDocument();
    expect(screen.getByText(/every 3 seconds/i)).toBeInTheDocument();
    expect(screen.queryByText(completedScan.digest)).not.toBeInTheDocument();
  });
  it('clearly identifies a legacy fictional sample', async () => {
    serve({
      ...completedScan,
      mock: true,
      scanner_name: null,
      scanner_version: null,
      scanner_database_metadata: null,
      digest: null,
      platform: null,
      started_at: null,
    });
    open();
    expect(
      await screen.findByText('Fictional sample scan'),
    ).toBeInTheDocument();
    expect(screen.getByText(/not a real image scan/i)).toBeInTheDocument();
  });
  it('shows scan execution failure separately from a successful response', async () => {
    serve({
      ...completedScan,
      status: 'failed',
      digest: null,
      platform: null,
      error_details: 'resolution_failed: Image reference could not be resolved',
    });
    open();
    expect(
      await screen.findByRole('heading', { name: 'Scan execution failed' }),
    ).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent(
      'resolution_failed: Image reference could not be resolved',
    );
    expect(screen.queryByText(/Scan completed\./)).not.toBeInTheDocument();
  });
  it('shows completed execution without repeated status copy or a security pass', async () => {
    const fetcher = serve();
    open();
    expect(
      await screen.findByText('Completed', { selector: '.status-label' }),
    ).toBeInTheDocument();
    expect(
      screen.queryByText(
        /Scan completed\.|Processing finished|security verdict/i,
      ),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText(/0 findings|image is safe|policy passed/i),
    ).not.toBeInTheDocument();
    expect(
      fetcher.mock.calls.filter(([url]) => url === `/api/v1/scans/${scanId}`),
    ).toHaveLength(1);
  });
  it('shows a missing scan as an API lookup error with a return path', async () => {
    serve({ detail: 'Scan not found' }, 404);
    open();
    expect(
      await screen.findByRole('heading', { name: 'Scan not found' }),
    ).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Back to scans' })).toHaveAttribute(
      'href',
      '/scans',
    );
    expect(
      screen.queryByRole('heading', { name: 'Scan execution failed' }),
    ).not.toBeInTheDocument();
  });
  it('distinguishes an unavailable API from a failed scan', async () => {
    serve({ detail: 'secret database diagnostic' }, 503);
    open();
    expect(await screen.findByRole('alert')).toHaveTextContent(
      /temporarily unavailable/i,
    );
    expect(screen.queryByText(/secret database/)).not.toBeInTheDocument();
    expect(
      screen.queryByRole('heading', { name: 'Scan execution failed' }),
    ).not.toBeInTheDocument();
  });
  it('rejects an unknown status rather than presenting a false completion', async () => {
    serve({ ...completedScan, status: 'unknown' });
    open();
    expect(await screen.findByRole('alert')).toHaveTextContent(
      /unexpected response/i,
    );
    expect(screen.queryByText('Completed')).not.toBeInTheDocument();
  });
  it('preserves visible details and keyboard focus during status updates', async () => {
    vi.useFakeTimers();
    let count = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) =>
        evidenceFixture(url) === undefined
          ? response({
              ...completedScan,
              status: ++count === 1 ? 'running' : 'completed',
            })
          : response(evidenceFixture(url)),
      ),
    );
    open();
    await act(async () => {});
    const anchor = screen.getByRole('link', { name: 'Findings' });
    anchor.focus();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000);
    });
    expect(
      screen.getByText('Completed', { selector: '.status-label' }),
    ).toBeInTheDocument();
    expect(anchor).toHaveFocus();
    expect(screen.getByText(completedScan.digest)).toBeInTheDocument();
  });
  it('uses section links without a manual status refresh control', async () => {
    serve();
    open();
    await screen.findByText(completedScan.digest);
    expect(
      screen.queryByRole('button', { name: 'Refresh status' }),
    ).not.toBeInTheDocument();
    for (const label of ['Findings', 'SBOM', 'Evaluations'])
      expect(screen.getByRole('link', { name: label })).toHaveAttribute(
        'href',
        label === 'Findings'
          ? '#findings-heading'
          : label === 'SBOM'
            ? '#sbom-heading'
            : '#evaluations-heading',
      );
  });
  it('explains that observation stopping does not cancel the server job', async () => {
    vi.useFakeTimers();
    serve({ ...completedScan, status: 'running' });
    open();
    await act(async () => {});
    await act(async () => {
      await vi.advanceTimersByTimeAsync(600000);
    });
    expect(screen.getByText(/stopped after 10 minutes/i)).toBeInTheDocument();
    expect(
      screen.getByText(/Reload the page to check again/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/does not cancel the server job/i),
    ).toBeInTheDocument();
    expect(
      within(screen.getByRole('main')).getByText('Running'),
    ).toBeInTheDocument();
  });
});
