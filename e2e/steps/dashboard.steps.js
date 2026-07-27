import { expect } from '@playwright/test';
import { Given, When, Then } from './fixtures.js';

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

// A shell that fails to unregister its window listener leaves nothing visibly
// broken — the handler keeps running harmlessly against its own detached
// subtree — so the leak is only observable by counting registrations. Wrap
// add/removeEventListener and track the net hashchange count across a rebuild:
// the outgoing shell must remove exactly what the incoming one adds.
Given('I am counting hashchange listener registrations', async ({ page }) => {
  await page.evaluate(() => {
    window.__hashDelta = 0;
    const add = window.addEventListener.bind(window);
    const remove = window.removeEventListener.bind(window);
    window.addEventListener = (type, fn, opts) => {
      if (type === 'hashchange') window.__hashDelta++;
      return add(type, fn, opts);
    };
    window.removeEventListener = (type, fn, opts) => {
      if (type === 'hashchange') window.__hashDelta--;
      return remove(type, fn, opts);
    };
  });
});

// 'login-success' is the event the login page dispatches on a successful
// sign-in; showApp() listens for it and swaps in a brand-new app-shell. Firing
// it directly reproduces that teardown/rebuild without a second login.
When('the app shell is rebuilt as it is after a fresh sign-in', async ({ page }) => {
  const shell = page.getByTestId('app-shell');
  await expect(shell).toBeVisible();
  await page.evaluate(() => window.dispatchEvent(new CustomEvent('login-success')));
  await expect(shell).toBeVisible();
  await expect(page.getByTestId('nav-dashboard')).toBeVisible();
});

Then('no hashchange listener was left behind', async ({ page }) => {
  const delta = await page.evaluate(() => window.__hashDelta);
  expect(delta, 'net hashchange listeners added across the shell rebuild').toBe(0);
});

Then('exactly one app shell is mounted', async ({ page }) => {
  await expect(page.locator('app-shell')).toHaveCount(1);
});
