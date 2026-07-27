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
