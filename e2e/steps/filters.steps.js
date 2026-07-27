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

// The registry modal is the only thing binding document-level keydown, so a
// running net count of those registrations tracks exactly its Escape handler.
Given('I am counting document keydown listeners', async ({ page }) => {
  await page.evaluate(() => {
    window.__keydownDelta = 0;
    const add = document.addEventListener.bind(document);
    const remove = document.removeEventListener.bind(document);
    document.addEventListener = (type, fn, opts) => {
      if (type === 'keydown') window.__keydownDelta++;
      return add(type, fn, opts);
    };
    document.removeEventListener = (type, fn, opts) => {
      if (type === 'keydown') window.__keydownDelta--;
      return remove(type, fn, opts);
    };
  });
});

When('I open the registry browser', async ({ page }) => {
  await page.locator('#browse-registry').click();
  await expect(page.locator('.registry-overlay')).toBeVisible();
});

When('I dismiss the registry browser with the Escape key', async ({ page }) => {
  await page.keyboard.press('Escape');
});

// Removal that does not go through close(): the teardown contract has to hold
// for any path that detaches the element, not just the button that calls close.
When('the registry browser is removed without being closed', async ({ page }) => {
  await page.evaluate(() => document.querySelector('registry-modal').remove());
  await expect(page.locator('registry-modal')).toHaveCount(0);
});

Then('the registry browser is gone', async ({ page }) => {
  await expect(page.locator('registry-modal')).toHaveCount(0);
});

Then('no document keydown listener was left behind', async ({ page }) => {
  const delta = await page.evaluate(() => window.__keydownDelta);
  expect(delta, 'net document keydown listeners after the modal went away').toBe(0);
});
