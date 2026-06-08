import { test as base, createBdd } from 'playwright-bdd';
import { expect } from '@playwright/test';

// Admin password used across setup and sign-in flows.
export const ADMIN_PASSWORD = 'correct horse battery staple';
// Where the authenticated session for the @app instance is persisted.
export const STORAGE_STATE = '.auth/app.json';

// Maps the human nav label used in features to its data-testid.
export const NAV = {
  Dashboard: 'nav-dashboard',
  Statistics: 'nav-stats',
  'Query Log': 'nav-logs',
  Filters: 'nav-filters',
  Settings: 'nav-settings',
};

// `testState` is a per-scenario scratchpad for carrying values between steps
// (e.g. the domain a scenario is currently testing).
export const test = base.extend({
  testState: async ({}, use) => {
    await use({});
  },
});

export const { Given, When, Then } = createBdd(test);

// Drive the boot screen to a signed-in app shell, regardless of whether the
// instance starts unconfigured (setup), configured-but-logged-out (login), or
// already authenticated (storageState).
export async function ensureSignedIn(page) {
  await page.goto('/');
  const shell = page.getByTestId('app-shell');
  const setupPw = page.getByTestId('setup-password');
  const loginPw = page.getByTestId('login-password');
  await expect(shell.or(setupPw).or(loginPw).first()).toBeVisible();

  if (await setupPw.isVisible()) {
    await setupPw.fill(ADMIN_PASSWORD);
    await page.getByTestId('setup-password-confirm').fill(ADMIN_PASSWORD);
    await page.getByTestId('setup-submit').click();
  } else if (await loginPw.isVisible()) {
    await loginPw.fill(ADMIN_PASSWORD);
    await page.getByTestId('login-submit').click();
  }
  await expect(shell).toBeVisible();
}

// Locator for a filter-list row by its visible name.
export function listRow(page, name) {
  return page.locator(`[data-testid="filter-list-row"][data-name="${name}"]`);
}
