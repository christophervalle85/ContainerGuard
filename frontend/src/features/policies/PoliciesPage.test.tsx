import { act, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, useLocation } from 'react-router';
import { describe, it, expect, vi } from 'vitest';
import { App } from '../../app/App';
import {
  policyId,
  otherPolicyId,
  policy,
  otherPolicy,
  version,
  secondVersion,
  page,
  json,
  deferred,
} from '../../../tests/policyFixtures';
function server(
  handler?: (url: string, init: RequestInit) => Response | Promise<Response>,
) {
  const fetcher = vi.fn(
    async (url: string, init: RequestInit) =>
      handler?.(url, init) ??
      (url.includes('/versions?')
        ? page([version])
        : page([policy, otherPolicy])),
  );
  vi.stubGlobal('fetch', fetcher);
  return fetcher;
}
function Location() {
  return <span data-testid="location">{useLocation().search}</span>;
}
function open(search = '') {
  return render(
    <MemoryRouter initialEntries={['/policies' + search]}>
      <App />
      <Location />
    </MemoryRouter>,
  );
}
function region(name: string) {
  return screen.getByRole('region', { name });
}
describe('policy workspace', () => {
  it('shows only the new-policy form while creating from an existing selection', async () => {
    server();
    open(`?policy=${policyId}`);
    await screen.findByText('Version 1');
    await userEvent
      .setup()
      .click(screen.getByRole('button', { name: 'Create policy' }));
    expect(screen.getAllByLabelText('Maximum HIGH findings')).toHaveLength(1);
    expect(
      screen.queryByRole('button', { name: 'Create new version' }),
    ).not.toBeInTheDocument();
    expect(screen.getByText('Version 1')).toBeInTheDocument();
  });

  it('lists policies and waits for an explicit selection before fetching versions', async () => {
    const fetcher = server();
    open();
    await screen.findByRole('button', { name: 'Release gate' });
    expect(screen.getByText(/select a policy to view/i)).toBeInTheDocument();
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(fetcher.mock.calls[0][0]).toBe('/api/v1/policies?limit=20&offset=0');
  });
  it('selects a policy and renders full saved version identity and rules', async () => {
    server();
    open();
    await userEvent
      .setup()
      .click(await screen.findByRole('button', { name: 'Release gate' }));
    const history = await screen.findByRole('region', {
      name: 'Version history',
    });
    await within(history).findByText('Version 1');
    expect(
      within(history).getByText(version.policy_version_id),
    ).toBeInTheDocument();
    expect(within(history).getByText('5')).toBeInTheDocument();
    expect(within(history).getByText('Fail')).toBeInTheDocument();
    expect(screen.getByTestId('location')).toHaveTextContent(
      `policy=${policyId}`,
    );
    expect(
      screen.queryByRole('button', { name: /edit|delete/i }),
    ).not.toBeInTheDocument();
  });
  it('paginates the policy list beyond the first page', async () => {
    const fetcher = server((url) =>
      url.includes('offset=20')
        ? page([otherPolicy], 21, 20, 20)
        : page([policy], 21),
    );
    open();
    await screen.findByRole('button', { name: 'Release gate' });
    await userEvent.setup().click(
      within(region('Saved policies')).getByRole('button', {
        name: 'Next page',
      }),
    );
    await screen.findByRole('button', { name: 'Other gate' });
    expect(
      screen.queryByRole('button', { name: 'Release gate' }),
    ).not.toBeInTheDocument();
    expect(fetcher.mock.calls.at(-1)?.[0]).toBe(
      '/api/v1/policies?limit=20&offset=20',
    );
  });
  it('restores a policy and independent version page from the URL', async () => {
    const fetcher = server((url) =>
      url.includes('/versions?')
        ? page([version], 21, 20, 20)
        : page([policy], 30, 20, 20),
    );
    open(
      `?policy=${policyId}&limit=20&offset=20&version_limit=20&version_offset=20`,
    );
    await screen.findByText('Version 1');
    expect(fetcher.mock.calls.map(([url]) => url)).toContain(
      `/api/v1/policies/${policyId}/versions?limit=20&offset=20`,
    );
    expect(
      within(region('Version history')).getByText('21–21 of 21'),
    ).toBeInTheDocument();
  });
  it('paginates versions without refetching the policy list', async () => {
    const fetcher = server((url) =>
      url.includes('/versions?')
        ? url.includes('offset=20')
          ? page([version], 21, 20, 20)
          : page([secondVersion], 21)
        : page([policy]),
    );
    open(`?policy=${policyId}`);
    await screen.findByText('Version 2');
    await userEvent.setup().click(
      within(region('Version history')).getByRole('button', {
        name: 'Next page',
      }),
    );
    await screen.findByText('Version 1');
    expect(
      fetcher.mock.calls.filter(([url]) => url.startsWith('/api/v1/policies?')),
    ).toHaveLength(1);
  });
  it('resets version pagination and cancels stale results when selecting another policy', async () => {
    const pending = deferred();
    const fetcher = server((url) =>
      url.includes(`/${policyId}/versions`)
        ? pending.promise
        : url.includes(`/${otherPolicyId}/versions`)
          ? page([{ ...secondVersion, policy_id: otherPolicyId }])
          : page([policy, otherPolicy]),
    );
    open(`?policy=${policyId}&version_offset=20`);
    await screen.findByRole('button', { name: 'Other gate' });
    const old = fetcher.mock.calls.find(([url]) =>
      url.includes(`/${policyId}/versions`),
    );
    await userEvent
      .setup()
      .click(screen.getByRole('button', { name: 'Other gate' }));
    await screen.findByText('Version 2');
    expect(old?.[1].signal?.aborted).toBe(true);
    expect(screen.getByTestId('location')).toHaveTextContent(
      'version_offset=0',
    );
    await act(async () => pending.resolve(page([version], 21, 20, 20)));
    expect(screen.queryByText('Version 1')).not.toBeInTheDocument();
  });
  it('validates query parameters and never sends an invalid policy ID', async () => {
    const fetcher = server();
    open(
      '?policy=invalid&limit=999&offset=-1&version_limit=0&version_offset=abc',
    );
    await screen.findByRole('button', { name: 'Release gate' });
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(fetcher.mock.calls[0][0]).toBe('/api/v1/policies?limit=20&offset=0');
    expect(screen.getByTestId('location')).not.toHaveTextContent('invalid');
  });
  it('shows loading, empty policies and an empty version history accurately', async () => {
    const pending = deferred();
    server(() => pending.promise);
    open();
    expect(screen.getByText('Loading policies…')).toBeInTheDocument();
    await act(async () => pending.resolve(page([])));
    expect(screen.getByText('No saved policies yet.')).toBeInTheDocument();
  });
  it('shows a missing selected policy without erasing the saved policy list', async () => {
    server((url) =>
      url.includes('/versions?')
        ? json({ detail: 'missing' }, 404)
        : page([otherPolicy]),
    );
    open(`?policy=${policyId}`);
    expect(await screen.findByRole('alert')).toHaveTextContent(/not found/i);
    expect(
      screen.getByRole('button', { name: 'Other gate' }),
    ).toBeInTheDocument();
  });
  it('shows list errors without exposing raw server diagnostics', async () => {
    server(() => json({ detail: 'private database host' }, 503));
    open();
    expect(await screen.findByRole('alert')).toHaveTextContent(
      /temporarily unavailable/i,
    );
    expect(screen.queryByText(/private database/)).not.toBeInTheDocument();
  });
  it('creates a policy and opens its returned version identity', async () => {
    let created = false;
    const fetcher = server((url, init) => {
      if (init.method === 'POST') {
        created = true;
        return json(version, 201);
      }
      return url.includes('/versions?')
        ? page([version])
        : page(created ? [policy] : []);
    });
    open();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Create policy' }));
    await user.type(screen.getByLabelText('Policy name'), 'Release gate');
    await user.selectOptions(
      screen.getByLabelText('Unknown severity action'),
      'fail',
    );
    await user.click(screen.getByRole('button', { name: 'Create policy' }));
    await screen.findByText('Version 1');
    expect(screen.getByTestId('location')).toHaveTextContent(
      `policy=${policyId}`,
    );
    expect(screen.getByTestId('location')).toHaveTextContent(
      `version=${version.policy_version_id}`,
    );
    expect(
      fetcher.mock.calls.filter(([, init]) => init.method === 'POST'),
    ).toHaveLength(1);
  });
  it('adds a version, preserves earlier rules, and refreshes only version history', async () => {
    let added = false;
    const fetcher = server((url, init) => {
      if (init.method === 'POST') {
        added = true;
        return json(secondVersion, 201);
      }
      return url.includes('/versions?')
        ? page(added ? [secondVersion, version] : [version])
        : page([policy]);
    });
    open(`?policy=${policyId}`);
    await screen.findByText('Version 1');
    const user = userEvent.setup();
    await user.selectOptions(
      screen.getByLabelText('Unknown severity action'),
      'fail',
    );
    await user.clear(screen.getByLabelText('Maximum HIGH findings'));
    await user.type(screen.getByLabelText('Maximum HIGH findings'), '0');
    await user.click(
      screen.getByRole('button', { name: 'Create new version' }),
    );
    await screen.findByText('Version 2');
    const history = region('Version history');
    expect(within(history).getByText('5')).toBeInTheDocument();
    expect(
      within(history).getByText(version.policy_version_id),
    ).toBeInTheDocument();
    expect(
      within(history).getByText(secondVersion.policy_version_id),
    ).toBeInTheDocument();
    expect(
      fetcher.mock.calls.filter(([url]) => url.startsWith('/api/v1/policies?')),
    ).toHaveLength(1);
    expect(screen.getByTestId('location')).toHaveTextContent(
      `version=${secondVersion.policy_version_id}`,
    );
  });
});
