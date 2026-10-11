import { readFile } from 'node:fs/promises';
import { test, expect, scanId, sbomBytes } from './fixtures';
test('submits an image and follows queued/running/completed automatically', async ({
  page,
  api,
}) => {
  api.progress = true;
  await page.goto('/scans');
  await page
    .getByLabel('Image reference')
    .fill('docker.io/library/alpine:3.20.0');
  await page.getByRole('button', { name: 'Submit scan', exact: true }).click();
  await expect(page).toHaveURL(new RegExp('/scans/' + scanId));
  await expect(
    page.getByText('Waiting for a worker to start the scan.', { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText('The worker is processing this image.', { exact: true }),
  ).toBeVisible();
  await expect(
    page.locator('.scan-progress').getByText('Completed', { exact: true }),
  ).toBeVisible({ timeout: 10000 });
  expect(api.posts).toEqual([
    {
      path: '/api/v1/scans',
      body: { image_reference: 'docker.io/library/alpine:3.20.0' },
    },
  ]);
});
test('filters and pages findings, reloads a direct route and downloads exact bytes', async ({
  page,
  api,
}) => {
  void api;
  await page.goto('/scans/' + scanId);
  const findings = page.getByRole('region', { name: 'Findings', exact: true });
  await findings.getByRole('button', { name: 'Next page' }).click();
  await expect(page).toHaveURL(/offset=20/);
  await expect(
    findings.getByText('second-package', { exact: true }),
  ).toBeVisible();
  await findings
    .getByLabel('Severity', { exact: true })
    .selectOption('CRITICAL');
  await expect(page).toHaveURL(/offset=0.*severity=CRITICAL/);
  await expect(
    findings.getByText('1 matching finding occurrence.', { exact: true }),
  ).toBeVisible();
  await page.reload();
  await expect(
    page.getByRole('heading', { name: 'Scan details', exact: true }),
  ).toBeVisible();
  const downloadEvent = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download SBOM' }).click();
  const download = await downloadEvent;
  expect(download.suggestedFilename()).toBe(scanId + '.cdx.json');
  expect(await readFile((await download.path())!, 'utf8')).toBe(sbomBytes);
});
for (const error of ['malformed', 'unavailable', 'missing'] as const) {
  test('shows ' + error + ' API failure', async ({ page, api }) => {
    api.error = error;
    await page.goto('/scans/' + scanId);
    await expect(page.getByRole('alert')).toBeVisible();
    await expect(
      page.getByRole('heading', {
        name:
          error === 'missing' ? 'Scan not found' : 'Could not load scan status',
        exact: true,
      }),
    ).toBeVisible();
    await expect(
      page.getByRole('region', { name: 'Findings', exact: true }),
    ).toHaveCount(0);
  });
}
test('SBOM failure does not hide findings or scan identity', async ({
  page,
  api,
}) => {
  api.error = 'sbom';
  await page.goto('/scans/' + scanId);
  await expect(
    page.getByRole('region', { name: 'SBOM', exact: true }),
  ).toContainText('failed');
  await expect(page.getByText('first-package', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Download SBOM' })).toHaveCount(
    0,
  );
});

test('section navigation scrolls to findings without submitting a scan', async ({
  page,
  api,
}) => {
  await page.goto('/scans/' + scanId);
  await page.getByRole('link', { name: 'Findings', exact: true }).click();
  await expect(page).toHaveURL(/#findings-heading$/);
  await expect
    .poll(async () =>
      page
        .locator('#findings-heading')
        .evaluate((element) => element.getBoundingClientRect().top),
    )
    .toBeLessThan(100);
  expect(api.posts).toHaveLength(0);
});
