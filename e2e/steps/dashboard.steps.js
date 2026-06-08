import { expect } from '@playwright/test';
import { When, Then } from './fixtures.js';

const SUMMARY = {
  'Blocked Today': 'stat-blocked-today',
  'Block Rate': 'stat-block-rate',
};
const CARD = { 'Top Queried Domains': 'top-domains-card' };

Then('I see the {string} summary card', async ({ page }, name) => {
  const id = SUMMARY[name];
  expect(id, `unknown summary card: ${name}`).toBeTruthy();
  await expect(page.getByTestId(id)).toBeVisible();
});

Then('I see the {string} card', async ({ page }, name) => {
  const id = CARD[name];
  expect(id, `unknown card: ${name}`).toBeTruthy();
  await expect(page.getByTestId(id)).toBeVisible();
});

Then('I see the {string} metric', async ({ page }, name) => {
  await expect(
    page.getByTestId('db-health-card').getByText(name, { exact: false }).first(),
  ).toBeVisible();
});

Then('live updates are active', async ({ page }) => {
  await expect(page.getByTestId('live-toggle')).toContainText('LIVE');
});

Then('live updates are paused', async ({ page }) => {
  await expect(page.getByTestId('live-toggle')).toContainText('PAUSED');
});

When('I toggle live mode', async ({ page }) => {
  await page.getByTestId('live-toggle').click();
});
