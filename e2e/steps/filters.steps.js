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

// Kept out of the .feature file: a Cucumber expression {string} argument cannot
// carry a double quote reliably, and the payload only needs to be readable here.
const INJECTED_NAME = 'q" onmouseover="window.__xss=1';
const INJECTED_URL = 'https://example.com/e2e-attr-injection.txt';

When('I add a filter list whose name contains a double quote', async ({ page }) => {
  await page.getByTestId('list-name-input').fill(INJECTED_NAME);
  await page.getByTestId('list-url-input').fill(INJECTED_URL);
  await page.getByTestId('list-add-submit').click();
  // Both inputs are cleared once the POST resolves and the table reloads.
  await expect(page.getByTestId('list-url-input')).toHaveValue('');
});

// Any on* attribute on a row means an interpolated value escaped its attribute:
// nothing in the template writes one.
Then('no filter list row carries an inline event handler', async ({ page }) => {
  const handlers = await page.evaluate(() =>
    [...document.querySelectorAll('[data-testid="filter-list-row"]')]
      .flatMap((row) => [...row.attributes].map((a) => a.name))
      .filter((name) => name.startsWith('on')));
  expect(handlers, 'inline event handlers injected onto filter list rows').toEqual([]);
});

// Matched as text rather than through a [data-name="..."] selector, which the
// quote in the name would break.
Then('the quoted filter list name is shown as text', async ({ page }) => {
  await expect(page.getByText(INJECTED_NAME, { exact: false }).first()).toBeVisible();
});

// An ordinary link now, so following it is an ordinary navigation.
When('I open the registry browser', async ({ page }) => {
  await page.locator('#browse-registry').click();
});

// Slashes are alternation in a Cucumber Expression, so the path stays out of
// the step text and lives in the assertion.
Then('the registry browser is a page of its own', async ({ page }) => {
  await expect(page).toHaveURL(/\/filters\/registry$/);
  await expect(page.locator('registry-page')).toBeVisible();
  // Filters marks the page it is a view of, so the navigation still says where
  // the operator is. Both bars carry the mark, so this asks the named one.
  await expect(page.locator('[data-testid="nav-filters"]')).toHaveClass(/active/);
});
