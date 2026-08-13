import { expect, test } from '@playwright/test';

test('generates a key, creates SubjectDN, and keeps DerEditor read-only', async ({ page }) => {
  const externalRequests: string[] = [];
  page.on('request', (request) => {
    const url = new URL(request.url());
    if (url.hostname !== '127.0.0.1') externalRequests.push(request.url());
  });
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));

  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Key Gadgets' })).toBeVisible();
  await expect(page.locator('#algorithmSelect')).not.toHaveValue('');
  await page.locator('#algorithmSelect').selectOption('ecdsa-p-256');
  await page.getByRole('button', { name: 'Generate' }).click();
  await expect(page.getByRole('button', { name: 'Private Key' })).toBeVisible();
  await expect(page.locator('#keyDetails')).toContainText('EC');

  await page.locator('#subjectDn').fill('CN=e2e.test, O=PKI Studio, C=US');
  await page.getByRole('button', { name: 'Add SubjectDN' }).click();
  await expect(page.getByRole('button', { name: 'CN=e2e.test, O=PKI Studio, C=US' })).toBeVisible();
  await expect(page.locator('#status')).toContainText('SubjectDN created');

  const viewer = page.locator('#derEditorMount');
  await expect(viewer).toContainText('SEQUENCE');
  await expect(viewer.locator('[data-node-action="edit"]')).toBeHidden();
  await expect(viewer.getByRole('button', { name: 'Save', exact: true })).toBeDisabled();
  expect(externalRequests).toEqual([]);
  expect(errors).toEqual([]);
});

test('creates a CSR and self-signed certificate from the selected SubjectDN', async ({ page }) => {
  await page.goto('/');
  await page.locator('#algorithmSelect').selectOption('ecdsa-p-256');
  await page.getByRole('button', { name: 'Generate' }).click();
  await page.locator('#subjectDn').fill('CN=certificate.test, O=PKI Studio, C=US');
  await page.getByRole('button', { name: 'Add SubjectDN' }).click();

  await page.getByRole('button', { name: 'Create CSR' }).click();
  await expect(page.getByRole('button', { name: /CSR: CN=certificate\.test/ })).toBeVisible();
  await page.getByRole('button', { name: 'Create self-signed certificate' }).click();
  await expect(page.getByRole('button', { name: 'Certificate', exact: true })).toBeVisible();
  await expect(page.locator('#status')).toContainText('Self-signed certificate created');
});
