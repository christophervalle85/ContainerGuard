import { test, expect, version } from './fixtures';
test('creates a policy and a new immutable version', async ({ page, api }) => {
  await page.goto('/policies');
  await page
    .getByRole('button', { name: 'Create policy', exact: true })
    .click();
  await page.getByLabel('Policy name').fill('Browser gate');
  await page.getByLabel('Unknown severity action').selectOption('fail');
  await page
    .getByRole('button', { name: 'Create policy', exact: true })
    .last()
    .click();
  await expect(
    page.getByRole('heading', { name: 'Version 1', exact: true }),
  ).toBeVisible();
  await page.getByLabel('Maximum HIGH findings').fill('0');
  await page.getByLabel('Unknown severity action').selectOption('ignore');
  await page
    .getByRole('button', { name: 'Create new version', exact: true })
    .click();
  await expect(
    page.getByRole('heading', { name: 'Version 2', exact: true }),
  ).toBeVisible();
  expect(api.posts).toHaveLength(2);
  expect(api.posts[1].body).toEqual({
    rules: {
      max_critical: 0,
      max_high: 0,
      require_sbom: true,
      unknown_severity_action: 'ignore',
    },
  });
  const history = page.getByRole('region', {
    name: 'Version history',
    exact: true,
  });
  const old = history.getByRole('article').filter({
    has: page.getByRole('heading', { name: 'Version 1', exact: true }),
  });
  await expect(old).toContainText(version.policy_version_id);
  await expect(old).toContainText('5');
});
