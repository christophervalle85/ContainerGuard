import { act, fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect, vi } from 'vitest';
import { PolicyForm } from './PolicyForm';
import {
  policyId,
  rules,
  version,
  secondVersion,
  json,
  deferred,
} from '../../../tests/policyFixtures';
function server(
  handler?: (url: string, options: RequestInit) => Response | Promise<Response>,
) {
  const fetcher = vi.fn(
    async (url: string, options: RequestInit) =>
      handler?.(url, options) ?? json(version, 201),
  );
  vi.stubGlobal('fetch', fetcher);
  return fetcher;
}
async function fill(name = '  Release gate  ') {
  const user = userEvent.setup();
  if (screen.queryByLabelText('Policy name'))
    await user.type(screen.getByLabelText('Policy name'), name);
  await user.selectOptions(
    screen.getByLabelText('Unknown severity action'),
    'fail',
  );
  return user;
}
function change(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}
describe('strict policy form', () => {
  it('trims the policy name and submits explicit numeric and boolean rules', async () => {
    const fetcher = server();
    const onCreated = vi.fn();
    render(<PolicyForm onCreated={onCreated} />);
    const user = await fill();
    await user.click(screen.getByRole('button', { name: 'Create policy' }));
    expect(onCreated).toHaveBeenCalledWith(version);
    expect(JSON.parse(String(fetcher.mock.calls[0][1].body))).toEqual({
      name: 'Release gate',
      rules,
    });
    expect(fetcher.mock.calls[0][0]).toBe('/api/v1/policies');
  });
  it('requires an explicit UNKNOWN action rather than silently choosing one', async () => {
    const fetcher = server();
    render(<PolicyForm onCreated={() => {}} />);
    change('Policy name', 'Release gate');
    expect(screen.getByLabelText('Unknown severity action')).toHaveValue('');
    await userEvent
      .setup()
      .click(screen.getByRole('button', { name: 'Create policy' }));
    expect(fetcher).not.toHaveBeenCalled();
    expect(screen.getByLabelText('Unknown severity action')).toHaveAttribute(
      'aria-invalid',
      'true',
    );
  });
  it.each(['0', '2147483647'])(
    'accepts the threshold boundary %s',
    async (value) => {
      const fetcher = server();
      render(<PolicyForm onCreated={() => {}} />);
      const user = await fill();
      change('Maximum CRITICAL findings', value);
      change('Maximum HIGH findings', value);
      await user.click(screen.getByRole('button', { name: 'Create policy' }));
      const body = JSON.parse(String(fetcher.mock.calls[0][1].body));
      expect(body.rules.max_critical).toBe(Number(value));
      expect(body.rules.max_high).toBe(Number(value));
    },
  );
  it.each(['', '-1', '1.5', '2147483648', '1e2', 'true', ' 1 '])(
    'rejects invalid threshold %j without sending it',
    async (value) => {
      const fetcher = server();
      render(<PolicyForm onCreated={() => {}} />);
      const user = await fill();
      change('Maximum CRITICAL findings', value);
      change('Maximum HIGH findings', value);
      await user.click(screen.getByRole('button', { name: 'Create policy' }));
      expect(fetcher).not.toHaveBeenCalled();
      expect(
        screen.getByLabelText('Maximum CRITICAL findings'),
      ).toHaveAttribute('aria-invalid', 'true');
      expect(screen.getByLabelText('Maximum HIGH findings')).toHaveAttribute(
        'aria-invalid',
        'true',
      );
    },
  );
  it.each(['   ', 'a'.repeat(101)])(
    'rejects an invalid policy name',
    async (name) => {
      const fetcher = server();
      render(<PolicyForm onCreated={() => {}} />);
      await fill('x');
      change('Policy name', name);
      await userEvent
        .setup()
        .click(screen.getByRole('button', { name: 'Create policy' }));
      expect(fetcher).not.toHaveBeenCalled();
      expect(screen.getByLabelText('Policy name')).toHaveAttribute(
        'aria-invalid',
        'true',
      );
    },
  );
  it('accepts a 100-character name and explicit ignore/false values', async () => {
    const fetcher = server();
    render(<PolicyForm onCreated={() => {}} />);
    const user = await fill('a'.repeat(100));
    await user.selectOptions(
      screen.getByLabelText('Unknown severity action'),
      'ignore',
    );
    await user.click(screen.getByLabelText('Require an SBOM'));
    await user.click(screen.getByRole('button', { name: 'Create policy' }));
    expect(JSON.parse(String(fetcher.mock.calls[0][1].body))).toEqual({
      name: 'a'.repeat(100),
      rules: {
        ...rules,
        require_sbom: false,
        unknown_severity_action: 'ignore',
      },
    });
  });
  it('creates a new immutable version without submitting a policy name', async () => {
    const fetcher = server(() => json(secondVersion, 201));
    const onCreated = vi.fn();
    render(<PolicyForm policyId={policyId} onCreated={onCreated} />);
    expect(screen.queryByLabelText('Policy name')).not.toBeInTheDocument();
    const user = await fill();
    change('Maximum HIGH findings', '0');
    await user.click(
      screen.getByRole('button', { name: 'Create new version' }),
    );
    expect(fetcher.mock.calls[0][0]).toBe(
      `/api/v1/policies/${policyId}/versions`,
    );
    expect(JSON.parse(String(fetcher.mock.calls[0][1].body))).toEqual({
      rules: { ...rules, max_high: 0 },
    });
    expect(onCreated).toHaveBeenCalledWith(secondVersion);
  });
  it('preserves fields and associates duplicate-name feedback with the name', async () => {
    server(() => json({ detail: 'private conflict data' }, 409));
    render(<PolicyForm onCreated={() => {}} />);
    const user = await fill('Release gate');
    await user.click(screen.getByRole('button', { name: 'Create policy' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      /name already exists/i,
    );
    expect(screen.getByLabelText('Policy name')).toHaveValue('Release gate');
    expect(screen.getByLabelText('Policy name')).toHaveAttribute(
      'aria-invalid',
      'true',
    );
    expect(screen.queryByText(/private conflict/)).not.toBeInTheDocument();
  });
  it('associates backend validation feedback with the affected rule', async () => {
    server(() =>
      json(
        { detail: [{ loc: ['body', 'rules', 'max_high'], msg: 'private' }] },
        422,
      ),
    );
    render(<PolicyForm onCreated={() => {}} />);
    const user = await fill();
    await user.click(screen.getByRole('button', { name: 'Create policy' }));
    await screen.findByRole('alert');
    expect(screen.getByLabelText('Maximum HIGH findings')).toHaveAttribute(
      'aria-invalid',
      'true',
    );
    expect(screen.getByLabelText('Maximum HIGH findings')).toHaveValue('5');
  });
  it('disables fields and duplicate submissions while pending', async () => {
    const pending = deferred();
    const fetcher = server(() => pending.promise);
    render(<PolicyForm onCreated={() => {}} />);
    const user = await fill();
    await user.click(screen.getByRole('button', { name: 'Create policy' }));
    expect(screen.getByLabelText('Maximum HIGH findings')).toBeDisabled();
    expect(screen.getByLabelText('Policy name')).toBeDisabled();
    const button = screen.getByRole('button', { name: 'Saving…' });
    expect(button).toBeDisabled();
    await user.click(button);
    expect(fetcher).toHaveBeenCalledTimes(1);
    await act(async () => pending.resolve(json(version, 201)));
  });
  it('keeps uncertain submissions visible without automatically repeating the POST', async () => {
    const fetcher = server(() =>
      Promise.reject(new TypeError('lost response')),
    );
    const check = vi.fn();
    render(<PolicyForm onCreated={() => {}} onCheckHistory={check} />);
    const user = await fill('Release gate');
    await user.click(screen.getByRole('button', { name: 'Create policy' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      /may have been saved/i,
    );
    expect(screen.getByLabelText('Policy name')).toHaveValue('Release gate');
    await user.click(
      screen.getByRole('button', { name: 'Check saved policies and versions' }),
    );
    expect(check).toHaveBeenCalledTimes(1);
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it('cancels an in-flight POST on unmount and ignores its late response', async () => {
    const pending = deferred();
    const fetcher = server(() => pending.promise);
    const onCreated = vi.fn();
    const { unmount } = render(<PolicyForm onCreated={onCreated} />);
    const user = await fill();
    await user.click(screen.getByRole('button', { name: 'Create policy' }));
    unmount();
    expect(fetcher.mock.calls[0][1].signal?.aborted).toBe(true);
    await act(async () => pending.resolve(json(version, 201)));
    expect(onCreated).not.toHaveBeenCalled();
  });
});
