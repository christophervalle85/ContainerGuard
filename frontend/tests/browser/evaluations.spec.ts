import { test, expect, scanId, policy, version, evaluation } from './fixtures';
test('explicit off-first-page selection preserves saved decisions', async ({
  page,
  api,
}) => {
  api.offPage = true;
  await page.goto('/scans/' + scanId);
  const policies = page.getByRole('region', {
    name: 'Choose evaluation policy',
    exact: true,
  });
  await policies.getByRole('button', { name: 'Next page' }).click();
  await page
    .getByLabel('Evaluation policy', { exact: true })
    .selectOption(policy.policy_id);
  await expect(
    page.getByRole('button', { name: 'Evaluate scan', exact: true }),
  ).toBeDisabled();
  const versions = page.getByRole('region', {
    name: 'Choose policy version',
    exact: true,
  });
  await versions.getByRole('button', { name: 'Next page' }).click();
  await page
    .getByLabel('Policy version', { exact: true })
    .selectOption(version.policy_version_id);
  expect(api.posts).toHaveLength(0);
  await expect(
    page.getByRole('region', { name: 'Selected rules', exact: true }),
  ).toContainText('5');
  await page
    .getByRole('button', { name: 'Evaluate scan', exact: true })
    .click();
  const result = page.getByRole('region', {
    name: 'Submitted decision',
    exact: true,
  });
  await expect(
    result.getByRole('heading', { name: 'Policy failed', exact: true }),
  ).toBeVisible();
  await expect(result).toContainText('HIGH count exceeds the allowed maximum.');
  await result
    .getByText('Saved rules and evaluation record', { exact: true })
    .click();
  await expect(
    result.getByText(evaluation.evaluation_id, { exact: true }),
  ).toBeVisible();
  await page
    .getByRole('button', { name: 'Evaluate scan', exact: true })
    .click();
  await expect(result).toContainText(evaluation.created_at);
  expect(api.posts).toHaveLength(2);
  await page.reload();
  await expect(
    page.getByRole('region', { name: 'Saved evaluations', exact: true }),
  ).toContainText(evaluation.evaluation_id);
});
test('evaluation error is distinct from a policy rejection', async ({
  page,
  api,
}) => {
  api.error = 'evaluation';
  await page.goto('/scans/' + scanId);
  await expect(
    page.getByRole('heading', { name: 'Evaluation error', exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText(
      'The saved evidence could not be evaluated. This is not a policy rejection.',
      { exact: true },
    ),
  ).toBeVisible();
  await expect(
    page.getByRole('heading', { name: 'Policy failed', exact: true }),
  ).toHaveCount(0);
});
