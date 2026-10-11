import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';
import { completedScan, evidenceFixture } from '../../tests/fixtures';

beforeEach(() => {
  vi.stubGlobal(
    'fetch',
    vi.fn(
      async (url: string) =>
        new Response(
          JSON.stringify(
            evidenceFixture(url) ??
              (url.startsWith('/api/v1/scans/')
                ? completedScan
                : { items: [], total: 0, limit: 20, offset: 0 }),
          ),
          { headers: { 'Content-Type': 'application/json' } },
        ),
    ),
  );
});

function open(path = '/') {
  render(
    <MemoryRouter initialEntries={[path]}>
      <App />
    </MemoryRouter>,
  );
}

describe('dashboard shell', () => {
  it('redirects the root to the scans workspace and marks its navigation', () => {
    open();
    expect(screen.getByRole('heading', { name: 'Scans' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Scans' })).toHaveAttribute(
      'aria-current',
      'page',
    );
    expect(
      screen.getByRole('navigation', { name: 'Main navigation' }),
    ).toBeInTheDocument();
  });
  it('lets a keyboard user skip navigation and move between workspaces', async () => {
    const user = userEvent.setup();
    open('/scans');
    await user.tab();
    expect(screen.getByRole('link', { name: 'Skip to content' })).toHaveFocus();
    const policies = screen.getByRole('link', { name: 'Policies' });
    policies.focus();
    await user.keyboard('{Enter}');
    expect(
      screen.getByRole('heading', { name: 'Policies' }),
    ).toBeInTheDocument();
    expect(policies).toHaveAttribute('aria-current', 'page');
  });
  it('provides a directly addressable scan details workspace', async () => {
    open('/scans/ff4599e5-4e9f-44c7-bbc2-e02db78bc008');
    await screen.findByText(completedScan.digest);
    expect(
      screen.getByRole('heading', { name: 'Scan details' }),
    ).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Back to scans' })).toHaveAttribute(
      'href',
      '/scans',
    );
  });
  it('shows a recovery link for an unknown UI route', () => {
    open('/missing');
    expect(
      screen.getByRole('heading', { name: 'Page not found' }),
    ).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Go to scans' })).toHaveAttribute(
      'href',
      '/scans',
    );
  });
});
