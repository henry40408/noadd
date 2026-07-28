import { expect } from '@playwright/test';
import { Given, When, Then, NAV, ensureSignedIn } from './fixtures.js';

async function goToTab(page, tab) {
  const id = NAV[tab];
  expect(id, `unknown tab: ${tab}`).toBeTruthy();
  await page.getByTestId(id).click();
  await expect(page.getByTestId(id)).toHaveClass(/active/);
}

Given('I am signed in to the admin UI', async ({ page }) => {
  await ensureSignedIn(page);
});

When('I go to the {string} tab', async ({ page }, tab) => {
  await goToTab(page, tab);
});

Given('I am on the {string} tab', async ({ page }, tab) => {
  await goToTab(page, tab);
});

// Shared by the dashboard ("Database Health") and filters ("Filter Lists") features.
Then('I see the {string} section', async ({ page }, name) => {
  await expect(page.getByText(name, { exact: false }).first()).toBeVisible();
});

// Catches errors that break no visible state on their own — a handler left
// behind by a detached component, for instance, which throws on every later
// interaction while the page still looks fine.
Given('I am recording uncaught page errors', async ({ page, testState }) => {
  testState.pageErrors = [];
  page.on('pageerror', (err) => testState.pageErrors.push(err.message));
});

Then('no uncaught page errors were recorded', async ({ testState }) => {
  expect(testState.pageErrors, 'uncaught page errors').toEqual([]);
});

// --- Dropped query-log warning (shell-level, so it lives here) ---
// Saturating the real logger from a browser test is impractical, so the count
// is injected into the health response. Everything else in the payload is left
// as the server sent it, since bootstrap reads needs_setup from the same call.
Given('the health endpoint reports {int} dropped log events', async ({ page }, count) => {
  await page.route('**/api/health', async (route) => {
    const response = await route.fetch();
    const body = await response.json();
    await route.fulfill({ json: { ...body, dropped_log_count: count } });
  });
});

// The banner is mounted by the app shell and reads health on mount, so the
// stub has to be in place before the shell is built — reload rather than wait
// out the poll interval.
Given('the admin UI is reloaded', async ({ page }) => {
  await page.reload();
  await expect(page.getByTestId('app-shell')).toBeVisible();
});

Then('I see a warning that query logging is incomplete', async ({ page }) => {
  await expect(page.getByTestId('log-drop-banner')).toBeVisible();
  await expect(page.getByTestId('log-drop-banner')).toContainText('statistics under-report');
});

Then('the warning reports {int} dropped log events', async ({ page }, count) => {
  await expect(page.getByTestId('log-drop-banner-count')).toContainText(String(count));
});

Then('no warning about query logging is shown', async ({ page }) => {
  await expect(page.getByTestId('log-drop-banner')).toHaveCount(0);
});
