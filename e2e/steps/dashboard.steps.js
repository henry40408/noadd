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

// The dashboard is the only component polling on a 10s period, so tracking the
// live interval ids registered at that period isolates its poll timer from the
// banners' (2s/3s) and the log ticker's (1s).
const DASHBOARD_POLL_MS = 10000;

Given('I am counting dashboard poll timers', async ({ page }) => {
  await page.evaluate((ms) => {
    window.__polls = new Set();
    const setI = window.setInterval.bind(window);
    const clearI = window.clearInterval.bind(window);
    window.setInterval = (fn, period, ...rest) => {
      const id = setI(fn, period, ...rest);
      if (period === ms) window.__polls.add(id);
      return id;
    };
    window.clearInterval = (id) => {
      window.__polls.delete(id);
      return clearI(id);
    };
  }, DASHBOARD_POLL_MS);
});

// Holds /api/server-info open so the dashboard's connectedCallback parks on its
// first await while the scenario navigates away underneath it.
Given('the server-info request is delayed', async ({ page }) => {
  await page.route('**/api/server-info', async (route) => {
    await new Promise((resolve) => setTimeout(resolve, 1500));
    await route.continue();
  });
});

When('the delayed request has arrived', async ({ page }) => {
  // Outlast the route delay so the parked callback has resumed and done
  // whatever it was going to do before the assertion looks.
  await page.waitForTimeout(2500);
});

Then('no dashboard poll timer is left running', async ({ page }) => {
  const live = await page.evaluate(() => window.__polls.size);
  expect(live, 'dashboard poll timers still running after navigating away').toBe(0);
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
