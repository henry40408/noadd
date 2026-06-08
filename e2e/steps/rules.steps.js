import { expect } from '@playwright/test';
import { Given, When, Then } from './fixtures.js';

async function addRule(page, rule) {
  await page.getByTestId('rule-input').fill(rule);
  await page.getByTestId('rule-submit').click();
}

When(/^I (?:add|have added) the custom rule "(.*)"$/, async ({ page }, rule) => {
  await addRule(page, rule);
});

Then(
  /^the custom rules list shows an? "(allow|block)" rule for "(.*)"$/,
  async ({ page }, type, domain) => {
    const row = page
      .locator(`[data-testid="rule-row"][data-type="${type}"]`)
      .filter({ hasText: domain });
    await expect(row).toBeVisible();
  },
);

When('I delete the rule for {string}', async ({ page }, domain) => {
  const row = page.locator('[data-testid="rule-row"]').filter({ hasText: domain });
  await row.getByTestId('rule-delete').click();
});

Then('the custom rules list no longer shows {string}', async ({ page }, domain) => {
  await expect(
    page.locator('[data-testid="rule-row"]').filter({ hasText: domain }),
  ).toHaveCount(0);
});

Given('the filter engine has finished rebuilding', async ({ page, baseURL }) => {
  // Adding a rule kicks off an async rebuild; wait for any in-flight one to settle.
  await expect
    .poll(
      async () => {
        const r = await page.request.get(`${baseURL}/api/filter/rebuild-status`);
        return (await r.json()).rebuilding;
      },
      { timeout: 10_000, intervals: [200, 300, 500] },
    )
    .toBe(false);
});

When('I run a domain test for {string}', async ({ page, testState }, domain) => {
  testState.testDomain = domain;
  await page.getByTestId('domain-test-input').fill(domain);
  await page.getByTestId('domain-test-submit').click();
});

Then('the domain test reports the domain as {string}', async ({ page }, verdict) => {
  const result = page.getByTestId('domain-test-result');
  // Re-run the check while polling to absorb the async filter rebuild.
  await expect
    .poll(
      async () => {
        await page.getByTestId('domain-test-submit').click();
        return (await result.textContent()) || '';
      },
      { timeout: 10_000, intervals: [300, 500, 800] },
    )
    .toContain(verdict);
});

Then('the domain test result mentions {string}', async ({ page }, text) => {
  await expect(page.getByTestId('domain-test-result')).toContainText(text);
});
