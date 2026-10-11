import { render, screen, within, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect, vi } from 'vitest';
import { EvaluationSection } from './EvaluationSection';
import { completedScan as savedScan, scanId } from '../../../tests/fixtures';
import {
  policy,
  version,
  secondVersion,
  json,
  page,
  deferred,
} from '../../../tests/policyFixtures';
const completedScan = { ...savedScan, status: 'completed' as const };
const decision = {
  evaluation_id: 'db57c3d1-222f-47d5-a392-08081c878668',
  scan_id: scanId,
  policy_id: policy.policy_id,
  policy_version_id: version.policy_version_id,
  version_number: 1,
  rule_snapshot: version.rules,
  evaluator_version: 1,
  outcome: 'failed',
  counts: { CRITICAL: 2, HIGH: 21, MEDIUM: 20, LOW: 27, UNKNOWN: 0 },
  rules: [
    {
      rule_id: 'max_high',
      passed: false,
      actual: 21,
      expected: 5,
      reason: 'HIGH count exceeds the allowed maximum.',
    },
  ],
  created_at: version.created_at,
  error_code: null,
  error_details: null,
};
function setup(post = () => Promise.resolve(json(decision))) {
  const fetch = vi.fn((input: string, init?: RequestInit) => {
    if (init?.method === 'POST') return post();
    if (input.includes('/evaluations'))
      return Promise.resolve(page([decision]));
    if (input.includes('/versions'))
      return Promise.resolve(page([secondVersion, version]));
    return Promise.resolve(page([policy]));
  });
  vi.stubGlobal('fetch', fetch);
  render(<EvaluationSection scan={completedScan} />);
  return fetch;
}
async function choose() {
  const user = userEvent.setup();
  await user.selectOptions(
    await screen.findByLabelText('Evaluation policy'),
    policy.policy_id,
  );
  await user.selectOptions(
    await screen.findByLabelText('Policy version'),
    version.policy_version_id,
  );
  return user;
}
describe('policy evaluation', () => {
  it('requires explicit version selection and submit, with rule preview', async () => {
    const fetch = setup();
    const user = userEvent.setup();
    const submit = screen.getByRole('button', { name: 'Evaluate scan' });
    expect(submit).toBeDisabled();
    await user.selectOptions(
      await screen.findByLabelText('Evaluation policy'),
      policy.policy_id,
    );
    await screen.findByRole('option', { name: /Version 1/ });
    expect(submit).toBeDisabled();
    await user.selectOptions(
      screen.getByLabelText('Policy version'),
      version.policy_version_id,
    );
    expect(
      screen.getByRole('region', { name: 'Selected rules' }),
    ).toHaveTextContent('5');
    expect(
      fetch.mock.calls.filter((c) => c[1]?.method === 'POST'),
    ).toHaveLength(0);
    await user.click(submit);
    await screen.findByRole('region', { name: 'Submitted decision' });
    expect(
      JSON.parse(
        String(
          fetch.mock.calls.find((c) => c[1]?.method === 'POST')?.[1]?.body,
        ),
      ),
    ).toEqual({ policy_version_id: version.policy_version_id });
  });
  it.each(['queued', 'running', 'failed'] as const)(
    'explains disabled %s scans',
    (status) => {
      vi.stubGlobal('fetch', vi.fn());
      render(<EvaluationSection scan={{ ...completedScan, status }} />);
      expect(
        screen.getByText(/Evaluation requires a completed, real scan/),
      ).toBeInTheDocument();
      expect(
        screen.queryByRole('button', { name: 'Evaluate scan' }),
      ).not.toBeInTheDocument();
    },
  );
  it.each([{ mock: true }, { digest: null }, { platform: null }])(
    'rejects missing real evidence %j',
    (change) => {
      vi.stubGlobal('fetch', vi.fn());
      render(<EvaluationSection scan={{ ...completedScan, ...change }} />);
      expect(
        screen.getByText(/Evaluation requires a completed, real scan/),
      ).toBeInTheDocument();
    },
  );
  it.each(['passed', 'failed', 'error'] as const)(
    'renders HTTP200 %s independently of transport',
    async (outcome) => {
      setup(() =>
        Promise.resolve(
          json({
            ...decision,
            outcome,
            error_code: outcome === 'error' ? 'invalid_evidence' : null,
          }),
        ),
      );
      const user = await choose();
      await user.click(screen.getByRole('button', { name: 'Evaluate scan' }));
      const result = await screen.findByRole('region', {
        name: 'Submitted decision',
      });
      expect(result).toHaveTextContent(
        outcome === 'error'
          ? 'Evaluation error'
          : outcome === 'passed'
            ? 'Policy passed'
            : 'Policy failed',
      );
      expect(result).toHaveTextContent(decision.evaluation_id);
      expect(result).toHaveTextContent('HIGH count exceeds');
      for (const severity of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'])
        expect(within(result).getByText(severity)).toBeInTheDocument();
      expect(
        within(result).getByRole('region', { name: 'Saved rule snapshot' }),
      ).toHaveTextContent('5');
    },
  );
  it.each([404, 409])(
    'reports authoritative HTTP%s without a fabricated decision',
    async (status) => {
      setup(() =>
        Promise.resolve(json({ detail: 'private internals' }, status)),
      );
      const user = await choose();
      await user.click(screen.getByRole('button', { name: 'Evaluate scan' }));
      await screen.findByRole('alert');
      expect(
        screen.queryByRole('region', { name: 'Submitted decision' }),
      ).not.toBeInTheDocument();
      expect(screen.getByRole('alert')).not.toHaveTextContent(
        'private internals',
      );
    },
  );
  it('does not automatically repeat a lost POST', async () => {
    const fetch = setup(() => Promise.reject(new TypeError('lost')));
    const user = await choose();
    await user.click(screen.getByRole('button', { name: 'Evaluate scan' }));
    await screen.findByRole('alert');
    expect(screen.getByRole('alert')).toHaveTextContent('may have been saved');
    expect(
      fetch.mock.calls.filter((c) => c[1]?.method === 'POST'),
    ).toHaveLength(1);
  });
  it('keeps returned identity when selection changes during submission and reuses saved identity', async () => {
    const pending = deferred();
    setup(() => pending.promise);
    const user = await choose();
    await user.click(screen.getByRole('button', { name: 'Evaluate scan' }));
    await user.selectOptions(
      screen.getByLabelText('Policy version'),
      secondVersion.policy_version_id,
    );
    pending.resolve(json(decision));
    const result = await screen.findByRole('region', {
      name: 'Submitted decision',
    });
    expect(result).toHaveTextContent(version.policy_version_id);
    expect(result).not.toHaveTextContent(secondVersion.policy_version_id);
    expect(result).toHaveTextContent(decision.created_at);
  });
  it('pages policies, versions and saved evaluations independently', async () => {
    const fetch = vi.fn((input: string) => {
      const url = new URL(input, 'http://local');
      const offset = Number(url.searchParams.get('offset'));
      if (input.includes('/evaluations'))
        return Promise.resolve(page(offset ? [decision] : [], 21, 20, offset));
      if (input.includes('/versions'))
        return Promise.resolve(
          page(offset ? [version] : [secondVersion], 21, 20, offset),
        );
      return Promise.resolve(page(offset ? [policy] : [], 21, 20, offset));
    });
    vi.stubGlobal('fetch', fetch);
    render(<EvaluationSection scan={completedScan} />);
    const user = userEvent.setup();
    const policies = screen.getByRole('region', {
      name: 'Choose evaluation policy',
    });
    await waitFor(() =>
      expect(
        within(policies).getByRole('button', { name: 'Next page' }),
      ).toBeEnabled(),
    );
    await user.click(
      within(policies).getByRole('button', { name: 'Next page' }),
    );
    await user.selectOptions(
      await screen.findByLabelText('Evaluation policy'),
      policy.policy_id,
    );
    const versions = await screen.findByRole('region', {
      name: 'Choose policy version',
    });
    await waitFor(() =>
      expect(
        within(versions).getByRole('button', { name: 'Next page' }),
      ).toBeEnabled(),
    );
    await user.click(
      within(versions).getByRole('button', { name: 'Next page' }),
    );
    await screen.findByRole('option', { name: /Version 1/ });
    await user.selectOptions(
      screen.getByLabelText('Policy version'),
      version.policy_version_id,
    );
    const history = screen.getByRole('region', { name: 'Saved evaluations' });
    await user.click(
      within(history).getByRole('button', { name: 'Next page' }),
    );
    await within(history).findByText(decision.evaluation_id);
    expect(
      fetch.mock.calls.some(([url]) =>
        url.includes('/versions?limit=20&offset=20'),
      ),
    ).toBe(true);
    expect(
      fetch.mock.calls.some(([url]) =>
        url.includes('/evaluations?limit=20&offset=20'),
      ),
    ).toBe(true);
    expect(
      screen.getByRole('region', { name: 'Selected rules' }),
    ).toHaveTextContent(version.policy_version_id);
  });
  it('ignores stale version responses after changing policy', async () => {
    const pending = deferred();
    const other = { ...policy, policy_id: scanId, name: 'Other policy' };
    vi.stubGlobal(
      'fetch',
      vi.fn((input: string) => {
        if (input.includes('/evaluations')) return Promise.resolve(page([]));
        if (input.includes(policy.policy_id + '/versions'))
          return pending.promise;
        if (input.includes('/versions'))
          return Promise.resolve(
            page([{ ...secondVersion, policy_id: scanId }]),
          );
        return Promise.resolve(page([policy, other]));
      }),
    );
    render(<EvaluationSection scan={completedScan} />);
    const user = userEvent.setup();
    await user.selectOptions(
      await screen.findByLabelText('Evaluation policy'),
      policy.policy_id,
    );
    await user.selectOptions(
      screen.getByLabelText('Evaluation policy'),
      scanId,
    );
    await screen.findByRole('option', { name: /Version 2/ });
    pending.resolve(page([version]));
    await waitFor(() =>
      expect(
        screen.queryByRole('option', { name: /Version 1/ }),
      ).not.toBeInTheDocument(),
    );
  });
  it('rejects a response for a different requested version', async () => {
    setup(() =>
      Promise.resolve(
        json({
          ...decision,
          policy_version_id: secondVersion.policy_version_id,
        }),
      ),
    );
    const user = await choose();
    await user.click(screen.getByRole('button', { name: 'Evaluate scan' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'does not match',
    );
    expect(
      screen.queryByRole('region', { name: 'Submitted decision' }),
    ).not.toBeInTheDocument();
  });
  it('retains saved identity and timestamp across repeated submissions', async () => {
    const fetch = setup();
    const user = await choose();
    await user.click(screen.getByRole('button', { name: 'Evaluate scan' }));
    await screen.findByRole('region', { name: 'Submitted decision' });
    await user.click(screen.getByRole('button', { name: 'Evaluate scan' }));
    await waitFor(() =>
      expect(
        fetch.mock.calls.filter((c) => c[1]?.method === 'POST'),
      ).toHaveLength(2),
    );
    const result = screen.getByRole('region', { name: 'Submitted decision' });
    expect(result).toHaveTextContent(decision.evaluation_id);
    expect(result).toHaveTextContent(decision.created_at);
    expect(
      within(result).getByRole('region', { name: 'Saved rule snapshot' }),
    ).toHaveTextContent('5');
  });
  it('shows the submitted decision once while retaining its history count', async () => {
    setup();
    const user = await choose();
    await user.click(screen.getByRole('button', { name: 'Evaluate scan' }));
    const result = await screen.findByRole('region', {
      name: 'Submitted decision',
    });
    await user.click(
      within(result).getByText('Saved rules and evaluation record'),
    );
    await waitFor(() =>
      expect(screen.getAllByText(decision.evaluation_id)).toHaveLength(1),
    );
    expect(
      screen.getByRole('region', { name: 'Saved evaluations' }),
    ).toHaveTextContent('1–1 of 1');
    expect(
      screen.getByRole('region', { name: 'Saved evaluations' }),
    ).toHaveTextContent('shown above');
  });
});
