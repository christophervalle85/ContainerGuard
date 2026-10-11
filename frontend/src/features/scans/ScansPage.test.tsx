import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, useLocation, useNavigate } from 'react-router';
import { describe, expect, it, vi } from 'vitest';
import { App } from '../../app/App';
import {
  completedScan,
  scanId,
  evidenceFixture,
} from '../../../tests/fixtures';

const secondId = '8269d321-ba64-4208-8341-f07f072a9475';
const first = {
  scan_id: scanId,
  image_reference: 'docker.io/library/alpine:3.20.0',
  status: 'completed',
};
const second = {
  scan_id: secondId,
  image_reference: 'docker.io/library/alpine:3.20',
  status: 'queued',
};
function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
function history(
  items: unknown[] = [],
  total = items.length,
  limit = 20,
  offset = 0,
) {
  return json({ items, total, limit, offset });
}
function Observe() {
  const location = useLocation();
  const navigate = useNavigate();
  return (
    <>
      <span data-testid="location">{location.pathname + location.search}</span>
      <button onClick={() => navigate(-1)}>Browser back</button>
    </>
  );
}
function open(path = '/scans') {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <App />
      <Observe />
    </MemoryRouter>,
  );
}
function server(
  post?: (options: RequestInit) => Response | Promise<Response>,
  get?: (url: string, options: RequestInit) => Response | Promise<Response>,
) {
  const fetcher = vi.fn(async (input: string, options: RequestInit) =>
    options.method === 'POST'
      ? (post?.(options) ??
        json(
          {
            scan_id: scanId,
            status: 'queued',
            status_url: `/api/v1/scans/${scanId}`,
          },
          202,
        ))
      : evidenceFixture(input) !== undefined
        ? json(evidenceFixture(input))
        : input === `/api/v1/scans/${scanId}`
          ? json(completedScan)
          : (get?.(input, options) ?? history()),
  );
  vi.stubGlobal('fetch', fetcher);
  return fetcher;
}
function deferred() {
  let resolve!: (response: Response) => void;
  const promise = new Promise<Response>((yes) => {
    resolve = yes;
  });
  return { promise, resolve };
}
async function enterImage(value = 'docker.io/library/alpine:3.20.0') {
  const user = userEvent.setup();
  await user.type(
    screen.getByRole('textbox', { name: 'Image reference' }),
    value,
  );
  return user;
}

describe('scan submission', () => {
  it('labels the input, states supported scope, and navigates using the accepted UUID', async () => {
    const fetcher = server();
    open();
    const user = await enterImage();
    expect(screen.getByText(/public Docker Hub images/i)).toBeInTheDocument();
    expect(screen.getByText(/linux\/amd64/i)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Submit scan' }));
    expect(
      await screen.findByRole('heading', { name: 'Scan details' }),
    ).toBeInTheDocument();
    expect(screen.getByTestId('location')).toHaveTextContent(
      `/scans/${scanId}`,
    );
    const posts = fetcher.mock.calls.filter(
      ([, options]) => options.method === 'POST',
    );
    expect(posts).toHaveLength(1);
    expect(posts[0][0]).toBe('/api/v1/scans');
    expect(JSON.parse(String(posts[0][1].body))).toEqual({
      image_reference: 'docker.io/library/alpine:3.20.0',
    });
  });
  it('disables submission while the request is pending and prevents duplicate POSTs', async () => {
    const pending = deferred();
    const fetcher = server(() => pending.promise);
    open();
    const user = await enterImage();
    await user.click(screen.getByRole('button', { name: 'Submit scan' }));
    expect(screen.getByRole('button', { name: 'Submitting…' })).toBeDisabled();
    expect(
      screen.getByRole('textbox', { name: 'Image reference' }),
    ).toBeDisabled();
    fireEvent.submit(
      screen.getByRole('form', { name: 'Submit an image scan' }),
    );
    expect(
      fetcher.mock.calls.filter(([, options]) => options.method === 'POST'),
    ).toHaveLength(1);
    await act(async () =>
      pending.resolve(
        json(
          {
            scan_id: scanId,
            status: 'queued',
            status_url: `/api/v1/scans/${scanId}`,
          },
          202,
        ),
      ),
    );
    await screen.findByRole('heading', { name: 'Scan details' });
  });
  it('keeps rejected input and associates validation feedback with the input', async () => {
    server(() =>
      json(
        {
          detail: [
            {
              loc: ['body', 'image_reference'],
              msg: 'secret server diagnostic',
              type: 'value_error',
              input: 'bad image',
            },
          ],
        },
        422,
      ),
    );
    open();
    const user = await enterImage('bad image');
    await user.click(screen.getByRole('button', { name: 'Submit scan' }));
    await screen.findByRole('alert');
    expect(
      screen.getByRole('textbox', { name: 'Image reference' }),
    ).toHaveValue('bad image');
    expect(
      screen.getByRole('textbox', { name: 'Image reference' }),
    ).toHaveAttribute('aria-invalid', 'true');
    expect(
      screen.getByRole('textbox', { name: 'Image reference' }),
    ).toHaveAccessibleDescription(/check|invalid/i);
    expect(
      screen.queryByText(/secret server diagnostic/),
    ).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Submit scan' })).toBeEnabled();
  });
  it('keeps the image after a lost response and suggests history without retrying', async () => {
    const fetcher = server(() =>
      Promise.reject(new TypeError('secret socket error')),
    );
    open();
    const user = await enterImage();
    await user.click(screen.getByRole('button', { name: 'Submit scan' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      /check scan history before submitting again/i,
    );
    expect(
      screen.getByRole('textbox', { name: 'Image reference' }),
    ).toHaveValue('docker.io/library/alpine:3.20.0');
    expect(screen.queryByText(/secret socket/)).not.toBeInTheDocument();
    vi.useFakeTimers();
    await act(async () => vi.advanceTimersByTimeAsync(60000));
    expect(
      fetcher.mock.calls.filter(([, options]) => options.method === 'POST'),
    ).toHaveLength(1);
  });
  it('lets the user check history after an uncertain submission', async () => {
    let gets = 0;
    server(
      () => Promise.reject(new TypeError('lost response')),
      () => {
        gets++;
        return history(gets > 1 ? [second] : []);
      },
    );
    open();
    const user = await enterImage();
    await user.click(screen.getByRole('button', { name: 'Submit scan' }));
    await user.click(
      await screen.findByRole('link', { name: 'Check scan history' }),
    );
    expect(
      await screen.findByRole('link', { name: second.image_reference }),
    ).toHaveAttribute('href', `/scans/${secondId}`);
  });
  it('does not redirect to a server-supplied external status URL', async () => {
    server(() =>
      json(
        {
          scan_id: scanId,
          status: 'queued',
          status_url: 'https://evil.example/collect',
        },
        202,
      ),
    );
    open();
    const user = await enterImage();
    await user.click(screen.getByRole('button', { name: 'Submit scan' }));
    await screen.findByRole('alert');
    expect(screen.getByTestId('location')).toHaveTextContent(
      '/scans?limit=20&offset=0',
    );
    expect(
      screen.getByRole('textbox', { name: 'Image reference' }),
    ).toHaveValue('docker.io/library/alpine:3.20.0');
  });
  it('uses the returned UUID even if the supplied relative status URL names another scan', async () => {
    server(() =>
      json(
        {
          scan_id: scanId,
          status: 'queued',
          status_url: `/api/v1/scans/${secondId}`,
        },
        202,
      ),
    );
    open();
    const user = await enterImage();
    await user.click(screen.getByRole('button', { name: 'Submit scan' }));
    await screen.findByRole('heading', { name: 'Scan details' });
    expect(screen.getByTestId('location')).toHaveTextContent(
      `/scans/${scanId}`,
    );
  });
  it('cancels an in-flight submission on navigation and ignores its late response', async () => {
    const pending = deferred();
    const fetcher = server(() => pending.promise);
    open();
    const user = await enterImage();
    await user.click(screen.getByRole('button', { name: 'Submit scan' }));
    const signal = fetcher.mock.calls.find(
      ([, options]) => options.method === 'POST',
    )?.[1].signal;
    await user.click(screen.getByRole('link', { name: 'Policies' }));
    expect(signal?.aborted).toBe(true);
    await act(async () =>
      pending.resolve(
        json(
          {
            scan_id: scanId,
            status: 'queued',
            status_url: `/api/v1/scans/${scanId}`,
          },
          202,
        ),
      ),
    );
    expect(
      screen.getByRole('heading', { name: 'Policies' }),
    ).toBeInTheDocument();
  });
});

describe('saved scan history', () => {
  it('shows a loading state before an empty page', async () => {
    const pending = deferred();
    server(undefined, () => pending.promise);
    open();
    expect(screen.getByRole('status')).toHaveTextContent(
      /loading scan history/i,
    );
    await act(async () => pending.resolve(history()));
    expect(await screen.findByText('No saved scans yet.')).toBeInTheDocument();
  });
  it('shows a service error instead of pretending history is empty and can refresh', async () => {
    let fail = true;
    server(undefined, () =>
      fail ? json({ detail: 'INTERNAL diagnostic' }, 503) : history([first]),
    );
    open();
    expect(await screen.findByRole('alert')).toHaveTextContent(
      /temporarily unavailable/i,
    );
    expect(screen.queryByText('No saved scans yet.')).not.toBeInTheDocument();
    fail = false;
    await userEvent
      .setup()
      .click(screen.getByRole('button', { name: 'Refresh history' }));
    expect(
      await screen.findByRole('link', { name: first.image_reference }),
    ).toBeInTheDocument();
  });
  it('shows saved identities and text statuses without per-row detail requests or polling', async () => {
    const fetcher = server(undefined, () => history([first, second]));
    open();
    expect(
      await screen.findByRole('link', { name: first.image_reference }),
    ).toHaveAttribute('href', `/scans/${scanId}`);
    expect(screen.getByText(scanId)).toBeInTheDocument();
    expect(screen.getByText('Completed')).toBeInTheDocument();
    expect(screen.getByText('Queued')).toBeInTheDocument();
    vi.useFakeTimers();
    await act(async () => vi.advanceTimersByTimeAsync(60000));
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(fetcher.mock.calls[0][0]).toBe('/api/v1/scans?limit=20&offset=0');
  });
  it('requests server pages, updates the URL, and disables controls at the boundaries', async () => {
    const fetcher = server(undefined, (url) =>
      url.includes('offset=20')
        ? history([second], 21, 20, 20)
        : history([first], 21),
    );
    open();
    await screen.findByRole('link', { name: first.image_reference });
    expect(
      screen.getByRole('button', { name: 'Previous page' }),
    ).toBeDisabled();
    await userEvent
      .setup()
      .click(screen.getByRole('button', { name: 'Next page' }));
    expect(
      await screen.findByRole('link', { name: second.image_reference }),
    ).toBeInTheDocument();
    expect(screen.getByTestId('location')).toHaveTextContent(
      '/scans?limit=20&offset=20',
    );
    expect(screen.getByRole('button', { name: 'Next page' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Previous page' })).toBeEnabled();
    expect(fetcher.mock.calls[1][0]).toBe('/api/v1/scans?limit=20&offset=20');
  });
  it('resets the offset when page size changes', async () => {
    const fetcher = server(undefined, (url) =>
      url.includes('limit=50')
        ? history([], 60, 50, 0)
        : history([first], 60, 20, 20),
    );
    open('/scans?limit=20&offset=20');
    await screen.findByRole('link', { name: first.image_reference });
    await userEvent
      .setup()
      .selectOptions(
        screen.getByRole('combobox', { name: 'Scans per page' }),
        '50',
      );
    await waitFor(() =>
      expect(fetcher.mock.calls.at(-1)?.[0]).toBe(
        '/api/v1/scans?limit=50&offset=0',
      ),
    );
    expect(screen.getByTestId('location')).toHaveTextContent(
      '/scans?limit=50&offset=0',
    );
  });
  it.each([
    'limit=0&offset=-1',
    'limit=101&offset=1.5',
    'limit=abc&offset=9007199254740992',
  ])('normalizes invalid URL pagination: %s', async (query) => {
    const fetcher = server();
    open(`/scans?${query}`);
    await screen.findByText('No saved scans yet.');
    expect(screen.getByTestId('location')).toHaveTextContent(
      '/scans?limit=20&offset=0',
    );
    expect(fetcher.mock.calls[0][0]).toBe('/api/v1/scans?limit=20&offset=0');
  });
  it('honors a directly linked valid page when refreshing', async () => {
    const fetcher = server(undefined, () => history([first], 150, 50, 100));
    open('/scans?limit=50&offset=100');
    await screen.findByRole('link', { name: first.image_reference });
    await userEvent
      .setup()
      .click(screen.getByRole('button', { name: 'Refresh history' }));
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
    expect(
      fetcher.mock.calls.every(
        ([url]) => url === '/api/v1/scans?limit=50&offset=100',
      ),
    ).toBe(true);
  });
  it('ignores a late page response after the user goes back', async () => {
    const pending = deferred();
    const fetcher = server(undefined, (url) =>
      url.includes('offset=20') ? pending.promise : history([first], 40),
    );
    open();
    await screen.findByRole('link', { name: first.image_reference });
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Next page' }));
    const oldSignal = fetcher.mock.calls.find(([url]) =>
      url.includes('offset=20'),
    )?.[1].signal;
    await user.click(screen.getByRole('button', { name: 'Browser back' }));
    await screen.findByRole('link', { name: first.image_reference });
    expect(oldSignal?.aborted).toBe(true);
    await act(async () => pending.resolve(history([second], 40, 20, 20)));
    expect(
      screen.queryByRole('link', { name: second.image_reference }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole('link', { name: first.image_reference }),
    ).toBeInTheDocument();
    expect(screen.getByTestId('location')).toHaveTextContent(
      '/scans?limit=20&offset=0',
    );
  });
  it('keeps a previous-page path when the requested page is beyond current history', async () => {
    server(undefined, () => history([], 1, 20, 20));
    open('/scans?limit=20&offset=20');
    expect(
      await screen.findByText('No scans on this page.'),
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Previous page' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Next page' })).toBeDisabled();
  });
});
