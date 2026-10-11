import { test, expect, scanId } from './fixtures';
test('keyboard skip link reaches the main content and form controls are labeled', async ({
  page,
  api,
}) => {
  void api;
  await page.goto('/scans');
  await page.keyboard.press('Tab');
  await expect(
    page.getByRole('link', { name: 'Skip to content' }),
  ).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.locator('#main-content')).toBeFocused();
  await page.getByLabel('Image reference').focus();
  await expect(page.getByLabel('Image reference')).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(
    page.getByRole('button', { name: 'Submit scan', exact: true }),
  ).toBeFocused();
});
test('scan evidence stays within a narrow viewport', async ({ page, api }) => {
  void api;
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/scans/' + scanId);
  await expect(
    page.getByRole('heading', { name: 'Policy evaluation', exact: true }),
  ).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  const table = page.getByRole('region', {
    name: 'Vulnerability results',
    exact: true,
  });
  await expect(table).toHaveAttribute('tabindex', '0');
});

test('desktop scan overview leaves room for evidence and section navigation stays reachable', async ({
  page,
  api,
}) => {
  void api;
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto('/scans/' + scanId);
  const overview = page.getByRole('region', {
    name: 'Image and scan record',
    exact: true,
  });
  await expect(overview).toBeVisible();
  await expect
    .poll(async () =>
      overview.evaluate((element) => element.getBoundingClientRect().height),
    )
    .toBeLessThan(420);
  const navigation = page.getByRole('navigation', {
    name: 'Scan sections',
    exact: true,
  });
  await navigation
    .getByRole('link', { name: 'Evaluations', exact: true })
    .click();
  await expect
    .poll(async () =>
      navigation.evaluate((element) => element.getBoundingClientRect().top),
    )
    .toBeGreaterThanOrEqual(0);
  await expect
    .poll(async () =>
      navigation.evaluate((element) => element.getBoundingClientRect().bottom),
    )
    .toBeLessThan(100);
  const heading = page.locator('#evaluations-heading');
  await expect
    .poll(async () =>
      heading.evaluate((element) => element.getBoundingClientRect().top),
    )
    .toBeGreaterThanOrEqual(50);
  await navigation.getByRole('link', { name: 'Overview', exact: true }).click();
  await page.getByRole('button', { name: 'Copy scan ID', exact: true }).focus();
  await expect(
    page.getByRole('button', { name: 'Copy scan ID', exact: true }),
  ).toBeFocused();
  expect(api.posts).toHaveLength(0);
});
