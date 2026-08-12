import { expect } from '@playwright/test';
import { Given, When, Then, NAV } from './fixtures.js';

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

Then('every stat card marker matches its value colour', async ({ page }) => {
  await expect(page.locator('.stat-card').first()).toBeVisible();
  const mismatches = await page.evaluate(() => {
    const root = getComputedStyle(document.documentElement);
    // Resolve a custom property to the same rgb() form getComputedStyle returns.
    const rgb = (name) => {
      const d = document.createElement('div');
      d.style.color = root.getPropertyValue(name).trim();
      document.body.appendChild(d);
      const v = getComputedStyle(d).color;
      d.remove();
      return v;
    };
    const out = [];
    for (const card of document.querySelectorAll('.stat-card')) {
      const value = card.querySelector('.stat-value');
      const label = card.querySelector('.stat-label');
      if (!value || !label) continue;
      const cl = value.classList;
      const expected = cl.contains('red') || cl.contains('text-red') ? rgb('--red')
        : cl.contains('text-orange') ? rgb('--orange')
          : rgb('--green');
      const actual = getComputedStyle(label, '::before').color;
      if (actual !== expected) {
        out.push(`${label.textContent.trim()} [${value.className}]: marker ${actual}, expected ${expected}`);
      }
    }
    return out;
  });
  expect(mismatches, 'stat markers not matching their value colour').toEqual([]);
});

When('I visit every tab', async ({ page, testState }) => {
  const leaked = [];
  for (const [label, testId] of Object.entries(NAV)) {
    await page.getByTestId(testId).click();
    await expect(page.getByTestId(testId)).toHaveClass(/active/);
    // Each page fetches on connect; let those renders land before looking.
    await page.waitForLoadState('networkidle');
    const hits = await page.evaluate(() =>
      (function () {
        // The admin UI is one file, so its own <script> body lives in the DOM
        // and would match everything; only rendered text counts.
        const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
          acceptNode(node) {
            const tag = node.parentElement && node.parentElement.tagName;
            return (tag === 'SCRIPT' || tag === 'STYLE')
              ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT;
          },
        });
        // Named tags rather than any identifier: copy legitimately contains
        // placeholders like "Authorization: Bearer <token>".
        const TAG = /<\/?(span|div|a|button|code|td|tr|table|tbody|thead|th|svg|path|input|label|p|br|strong|em|ul|li|select|option)\b[^<>]*>/i;
        const out = [];
        while (walker.nextNode()) {
          const text = walker.currentNode.nodeValue || '';
          if (TAG.test(text)) out.push(text.trim().slice(0, 100));
        }
        return out;
      })());
    leaked.push(...hits.map((h) => `${label}: ${h}`));
  }
  testState.leakedMarkup = leaked;
});

Then('no tab showed raw markup as text', async ({ testState }) => {
  expect(testState.leakedMarkup, 'markup rendered as visible text').toEqual([]);
});

// --- Throughput card ---
// Driving the real 60-second window from a browser test would mean generating
// live DNS traffic and racing the logger's flush, so the two rates are injected
// instead. They are deliberately chosen to differ: 120/60 = 2.00 q/s live
// against 86400/86400 = 1.00 q/s for the day, so a card still reading the
// daily mean shows 1.00 and fails rather than coincidentally matching.
Given(
  'the summary reports {int} queries in the last minute and {int} today',
  async ({ page }, queries1m, today) => {
    await page.route('**/api/stats/summary', async (route) => {
      const response = await route.fetch();
      const body = await response.json();
      await route.fulfill({
        json: { ...body, queries_1m: queries1m, total_today: today },
      });
    });
  },
);

// The slash is escaped because a bare `/` is alternation in a Cucumber expression.
Then('the Throughput card reads {string} q\\/s', async ({ page }, value) => {
  await expect(page.getByTestId('stat-throughput-value')).toHaveText(`${value}q/s`);
});

Then('the Throughput card shows a 24h mean of {string}', async ({ page }, value) => {
  await expect(page.getByTestId('stat-throughput')).toContainText(`24h: ${value}`);
});
