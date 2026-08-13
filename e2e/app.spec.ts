import { expect, test } from '@playwright/test';
import { readFile } from 'node:fs/promises';

test('generates a key, creates SubjectDN, and keeps DerEditor read-only', async ({ page }) => {
  const externalRequests: string[] = [];
  page.on('request', (request) => {
    const url = new URL(request.url());
    if (url.hostname !== '127.0.0.1') externalRequests.push(request.url());
  });
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));

  await page.goto('/');
  await expect(page.locator('.toolbar')).toContainText('Key Gadgets');
  await expect(page.locator('#algorithmSelect')).not.toHaveValue('');
  await page.getByRole('button', { name: 'New', exact: true }).click();
  await page.getByRole('menuitem', { name: 'EC P-256' }).click();
  await expect(page.getByRole('button', { name: 'Private Key', exact: true })).toBeVisible();
  await expect(page.locator('#keyDetails')).toContainText('EC');

  await page.getByRole('button', { name: 'Actions', exact: true }).click();
  await page.getByRole('menuitem', { name: 'New SubjectDN' }).click();
  await page.locator('#subjectDn').fill('CN=e2e.test, O=PKI Studio, C=US');
  await page.getByRole('button', { name: 'Create', exact: true }).click();
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
  await page.getByRole('button', { name: 'New', exact: true }).click();
  await page.getByRole('menuitem', { name: 'EC P-256' }).click();
  await page.getByRole('button', { name: 'Actions', exact: true }).click();
  await page.getByRole('menuitem', { name: 'New SubjectDN' }).click();
  await page.locator('#subjectDn').fill('CN=certificate.test, O=PKI Studio, C=US');
  await page.getByRole('button', { name: 'Create', exact: true }).click();

  await page.getByRole('button', { name: 'Actions', exact: true }).click();
  await page.getByRole('menuitem', { name: 'New CSR' }).click();
  await page.locator('#csrDialog').getByRole('button', { name: 'Create' }).click();
  await expect(page.getByRole('button', { name: /CSR: CN=certificate\.test/ })).toBeVisible();
  await page.getByRole('button', { name: 'Actions', exact: true }).click();
  await page.getByRole('menuitem', { name: 'New self-signed Cert' }).click();
  await page.locator('#certificateDialog').getByRole('button', { name: 'Create' }).click();
  await expect(page.getByRole('button', { name: 'Certificate', exact: true })).toBeVisible();
  await expect(page.locator('#status')).toContainText('Self-signed certificate created');

  await page.getByRole('button', { name: 'Actions', exact: true }).click();
  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('menuitem', { name: 'Save selected item' }).click();
  const certificateDownload = await downloadPromise;
  const certificatePath = await certificateDownload.path();
  expect(certificatePath).not.toBeNull();

  await page.getByRole('button', { name: 'Actions', exact: true }).click();
  page.once('dialog', (dialog) => void dialog.accept());
  await page.locator('#actionsMenu').getByRole('menuitem', { name: 'Delete' }).click();
  await expect(page.getByRole('button', { name: 'Certificate', exact: true })).toHaveCount(0);

  await page.getByRole('button', { name: 'EC P-256 actions' }).click();
  const parentMenu = page.locator('#parentContextMenu');
  await parentMenu.getByRole('menuitem', { name: 'Load Certificate' }).hover();
  const chooserPromise = page.waitForEvent('filechooser');
  await parentMenu.getByRole('menuitem', { name: 'from File' }).click();
  const chooser = await chooserPromise;
  await chooser.setFiles(certificatePath!);
  await expect(page.getByRole('button', { name: 'Certificate', exact: true })).toBeVisible();
  await expect(page.locator('#status')).toContainText('Loaded certificate');

  const certificatePem = await readFile(certificatePath!, 'utf8');
  await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.getByRole('button', { name: 'Actions', exact: true }).click();
  page.once('dialog', (dialog) => void dialog.accept());
  await page.locator('#actionsMenu').getByRole('menuitem', { name: 'Delete' }).click();
  await page.evaluate((pem) => navigator.clipboard.writeText(pem), certificatePem);
  await page.getByRole('button', { name: 'EC P-256 actions' }).click();
  await page.locator('#parentContextMenu').getByRole('menuitem', { name: 'Load Certificate' }).hover();
  await page.locator('#parentContextMenu').getByRole('menuitem', { name: 'from Clipboard as PEM' }).click();
  await expect(page.getByRole('button', { name: 'Certificate', exact: true })).toBeVisible();

  await page.getByRole('button', { name: 'Actions', exact: true }).click();
  page.once('dialog', (dialog) => void dialog.accept());
  await page.locator('#actionsMenu').getByRole('menuitem', { name: 'Delete' }).click();
  const certificateHex = Buffer.from(certificatePem.replace(/-----[^-]+-----|\s/g, ''), 'base64').toString('hex');
  await page.evaluate((hex) => navigator.clipboard.writeText(hex), certificateHex);
  await page.getByRole('button', { name: 'EC P-256 actions' }).click();
  await page.locator('#parentContextMenu').getByRole('menuitem', { name: 'Load Certificate' }).hover();
  await page.locator('#parentContextMenu').getByRole('menuitem', { name: 'from Clipboard as HEX' }).click();
  await expect(page.getByRole('button', { name: 'Certificate', exact: true })).toBeVisible();
  await expect(page.locator('#status')).toContainText('clipboard HEX');
});

test('opens tree icon menus without toggling tree nodes and runs shared actions', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'New', exact: true }).click();
  await page.getByRole('menuitem', { name: 'EC P-256' }).click();

  const rootNode = page.locator('#keyTree > details').first();
  await expect(rootNode).toHaveAttribute('open', '');
  await page.getByRole('button', { name: 'EC P-256 actions' }).click();
  await expect(rootNode).toHaveAttribute('open', '');

  const parentMenu = page.locator('#parentContextMenu');
  await expect(parentMenu).toBeVisible();
  await expect(parentMenu.getByRole('menuitem', { name: 'Load Certificate' })).toBeVisible();
  await parentMenu.getByRole('menuitem', { name: 'Load Certificate' }).hover();
  await expect(parentMenu.getByRole('menuitem', { name: 'from File' })).toBeVisible();
  await expect(parentMenu.getByRole('menuitem', { name: 'from Clipboard as PEM' })).toBeVisible();
  await expect(parentMenu.getByRole('menuitem', { name: 'from Clipboard as HEX' })).toBeVisible();
  await parentMenu.getByRole('menuitem', { name: 'New SubjectDN' }).click();
  await page.locator('#subjectDn').fill('CN=tree-menu.test, O=PKI Studio, C=US');
  await page.locator('#subjectDialog').getByRole('button', { name: 'Create' }).click();

  const privateLeaf = page.getByRole('button', { name: 'Private Key actions' }).locator('xpath=ancestor::details[1]');
  await expect(privateLeaf).not.toHaveAttribute('open', '');
  await page.getByRole('button', { name: 'Private Key actions' }).click();
  await expect(privateLeaf).not.toHaveAttribute('open', '');
  const privateMenu = page.locator('#privateKeyContextMenu');
  await expect(privateMenu.getByRole('menuitem', { name: 'New CSR' })).toBeVisible();
  await expect(privateMenu.getByRole('menuitem', { name: 'New self-signed Cert' })).toBeVisible();
  await expect(privateMenu.getByRole('menuitem', { name: 'Delete' })).toBeVisible();
  await privateMenu.getByRole('menuitem', { name: 'New CSR' }).click();
  await page.locator('#csrDialog').getByRole('button', { name: 'Create' }).click();
  await expect(page.getByRole('button', { name: /CSR: CN=tree-menu\.test/ })).toBeVisible();

  await page.getByRole('button', { name: 'Public Key actions' }).click();
  const publicMenu = page.locator('#publicKeyContextMenu');
  await expect(publicMenu.getByRole('menuitem', { name: 'Delete' })).toBeVisible();
  page.once('dialog', (dialog) => void dialog.accept());
  await publicMenu.getByRole('menuitem', { name: 'Delete' }).click();
  await expect(page.getByRole('button', { name: 'Public Key', exact: true })).toHaveCount(0);

  await page.getByRole('button', { name: 'EC P-256 actions' }).click();
  page.once('dialog', (dialog) => void dialog.accept());
  await page.locator('#parentContextMenu').getByRole('menuitem', { name: 'Delete' }).click();
  await expect(page.locator('#keyTree')).toHaveText('No key generated yet.');
});
