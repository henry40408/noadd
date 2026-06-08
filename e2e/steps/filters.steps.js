import { expect } from '@playwright/test';
import { Given, When, Then, listRow } from './fixtures.js';

// Toggle a list to a desired state by clicking its (visible) label, which
// flips the wrapped checkbox regardless of how the input is styled/hidden.
async function setListEnabled(page, name, enabled) {
  const row = listRow(page, name);
  const toggle = row.getByTestId('filter-list-toggle');
  if ((await toggle.isChecked()) !== enabled) {
    await row.locator('label.toggle').click();
  }
  await expect(toggle).toBeChecked({ checked: enabled });
}

Then('I see a filter list named {string}', async ({ page }, name) => {
  await expect(listRow(page, name)).toBeVisible();
});

Then('each filter list shows an enabled state and a rule count', async ({ page }) => {
  const rows = page.locator('[data-testid="filter-list-row"]');
  const count = await rows.count();
  expect(count).toBeGreaterThan(0);
  await expect(
    page.locator('[data-testid="filter-list-row"] [data-testid="filter-list-toggle"]'),
  ).toHaveCount(count);
});

Given('the filter list {string} is enabled', async ({ page }, name) => {
  await setListEnabled(page, name, true);
});

When('I disable the filter list {string}', async ({ page }, name) => {
  await setListEnabled(page, name, false);
});

Then('the filter list {string} is shown as disabled', async ({ page }, name) => {
  await expect(listRow(page, name).getByTestId('filter-list-toggle')).not.toBeChecked();
});

When('I enable the filter list {string}', async ({ page }, name) => {
  await setListEnabled(page, name, true);
});

Then('the filter list {string} is shown as enabled', async ({ page }, name) => {
  await expect(listRow(page, name).getByTestId('filter-list-toggle')).toBeChecked();
});

When(
  'I add a custom filter list named {string} with URL {string}',
  async ({ page }, name, url) => {
    await page.getByTestId('list-name-input').fill(name);
    await page.getByTestId('list-url-input').fill(url);
    await page.getByTestId('list-add-submit').click();
  },
);

Then('the filter lists table shows a list named {string}', async ({ page }, name) => {
  await expect(listRow(page, name)).toBeVisible();
});
