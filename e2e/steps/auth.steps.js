import { expect } from '@playwright/test';
import { Given, When, Then } from './fixtures.js';

Given('the admin UI has never been configured', async ({ page, baseURL }) => {
  const res = await page.request.get(`${baseURL}/api/health`);
  const body = await res.json();
  expect(body.needs_setup, 'expected a fresh, unconfigured instance').toBe(true);
});

When('I open the admin UI', async ({ page }) => {
  await page.goto('/');
});

Then('I am shown the first-run setup screen', async ({ page }) => {
  await expect(page.getByTestId('setup-password')).toBeVisible();
});

When('I enter {string} as the new password', async ({ page }, pw) => {
  await page.getByTestId('setup-password').fill(pw);
});

When('I enter {string} as the confirmation', async ({ page }, pw) => {
  await page.getByTestId('setup-password-confirm').fill(pw);
});

When('I submit the setup form', async ({ page }) => {
  await page.getByTestId('setup-submit').click();
});

Then('I see a setup error about the passwords not matching', async ({ page }) => {
  await expect(page.getByTestId('setup-error')).toContainText(/do not match/i);
});

Then('the admin password has still not been set', async ({ page, baseURL }) => {
  const res = await page.request.get(`${baseURL}/api/health`);
  const body = await res.json();
  expect(body.needs_setup).toBe(true);
});

Then('I land on the dashboard', async ({ page }) => {
  await expect(page.getByTestId('app-shell')).toBeVisible();
  await expect(page.getByTestId('nav-dashboard')).toBeVisible();
});

Given('the admin password has been set to {string}', async ({ page, baseURL }, pw) => {
  // Idempotent: 409 means a password is already configured, which is fine.
  const res = await page.request.post(`${baseURL}/api/auth/setup`, {
    data: { password: pw },
  });
  expect([200, 409]).toContain(res.status());
});

When('I sign in with the password {string}', async ({ page }, pw) => {
  await page.getByTestId('login-password').fill(pw);
  await page.getByTestId('login-submit').click();
});

Then('I remain on the sign-in screen', async ({ page }) => {
  await expect(page.getByTestId('login-submit')).toBeVisible();
});

Then('I see a sign-in error telling me the password is incorrect', async ({ page }) => {
  const err = page.getByTestId('login-error');
  await expect(err).toBeVisible();
  await expect(err).toContainText(/incorrect password/i);
});

When('I revoke all sessions', async ({ page }) => {
  page.once('dialog', (d) => d.accept());
  await page.getByTestId('revoke-sessions').click();
});

Then('I am returned to the sign-in screen', async ({ page }) => {
  await expect(page.getByTestId('login-submit')).toBeVisible();
});

Then('reloading the admin UI still shows the sign-in screen', async ({ page }) => {
  await page.reload();
  await expect(page.getByTestId('login-submit')).toBeVisible();
});
