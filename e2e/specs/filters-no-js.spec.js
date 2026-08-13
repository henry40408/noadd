// e2e/specs/filters-no-js.spec.js
// The filters page with JavaScript switched off entirely. Everything on it is a
// real form, so the page has to keep working: add a rule, delete it, add a
// list, toggle it, edit it, remove it, test a domain. `app.js` never loads
// here, which is the point — what these exercise is the markup the server sent,
// not the enhancement layered over it.
//
// Its own noadd instance on dedicated ports, like the other specs here: it
// mutates the very lists and rules the shared instance's scenarios assert on,
// and it signs in for itself.
import { test, expect } from '@playwright/test';
import { spawn } from 'node:child_process';
import { mkdirSync, rmSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ADMIN_USERNAME, ADMIN_PASSWORD } from '../screenshots/seed.mjs';

const E2E_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = process.env.NOADD_BIN || resolve(E2E_DIR, '../target/debug/noadd');
const DB = resolve(E2E_DIR, '.tmp/filters-no-js.db');
const HTTP = 14107, DNS = 15107;
const BASE = `http://127.0.0.1:${HTTP}`;

function startNoadd() {
  const child = spawn(BIN, [
    '--db-path', DB,
    '--http-addr', `127.0.0.1:${HTTP}`,
    '--dns-addr', `127.0.0.1:${DNS}`,
    '--log-format', 'json',
  ], { stdio: ['ignore', 'ignore', 'inherit'] });
  child.exited = new Promise((res) => child.once('exit', res));
  return child;
}
async function waitHealthy(timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try { if ((await fetch(`${BASE}/api/health`)).ok) return; } catch {}
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error('noadd did not become healthy in time');
}
async function stopNoadd(child) {
  if (!child) return;
  child.kill('SIGTERM');
  const killer = setTimeout(() => child.kill('SIGKILL'), 10_000);
  await child.exited;
  clearTimeout(killer);
}

let server;
let sessionToken;

test.beforeAll(async () => {
  mkdirSync(resolve(E2E_DIR, '.tmp'), { recursive: true });
  for (const suffix of ['', '-wal', '-shm']) rmSync(`${DB}${suffix}`, { force: true });
  server = startNoadd();
  await waitHealthy();
  const res = await fetch(`${BASE}/api/auth/setup`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: ADMIN_USERNAME, password: ADMIN_PASSWORD }),
  });
  if (!res.ok) throw new Error(`setup failed: ${res.status}`);

  const login = await fetch(`${BASE}/api/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: ADMIN_USERNAME, password: ADMIN_PASSWORD }),
  });
  if (!login.ok) throw new Error(`login failed: ${login.status}`);
  sessionToken = /session=([^;]+)/.exec(login.headers.get('set-cookie') || '')?.[1];
  if (!sessionToken) throw new Error('no session cookie in the login response');
});

test.afterAll(async () => { await stopNoadd(server); });

test.use({ baseURL: BASE, javaScriptEnabled: false });

// One login for the whole file, replayed as a cookie: a UI sign-in per test
// would spend the five-per-minute budget on setup rather than on what is under
// test. The sign-in form's own no-JS behaviour is covered by the auth feature.
async function gotoFilters(page, context, query = '') {
  await context.addCookies([{
    name: 'session', value: sessionToken, domain: '127.0.0.1', path: '/',
  }]);
  await page.goto(`${BASE}/filters${query}`);
  await expect(page.getByTestId('app-shell')).toBeVisible();
}

// Submitting with Enter from a text field, which is how HTML submits a form
// that has a submit button in it — a real path, and the one a keyboard user
// takes.
//
// It is also the one that does not depend on where the button happens to sit.
// The status bar is fixed to the bottom of the viewport, so on a short enough
// window a control near the foot of the page is underneath it and a click
// lands on the status bar instead ("intercepts pointer events"). That is a
// genuine constraint of the layout rather than a test artefact — which is why
// `:root` now carries `scroll-padding-bottom` — but it makes clicking those
// particular buttons a function of the window height, and these tests are
// about the forms, not the furniture.
async function submitAddList(page) {
  await page.getByTestId('list-name-input').press('Enter');
}

async function submitAddRule(page) {
  await page.getByTestId('rule-input').press('Enter');
}

// For the row controls, which have no text field to press Enter in. `force`
// skips the hit-target check that the fixed status bar can fail; every one of
// these is followed by an assertion that only passes if the POST landed, so a
// button that genuinely did nothing still fails the test.
async function clickRowControl(locator) {
  await locator.click({ force: true });
}

test.describe('The filters page works with no JavaScript', () => {
  test('the page renders its lists, rules and controls from the server', async ({ page, context }) => {
    await gotoFilters(page, context);
    await expect(page.getByTestId('rules-list')).toBeVisible();
    await expect(page.locator('[data-testid="nav-filters"]')).toHaveClass(/active/);
    // The registry browser used to be the one control that needed a client, so
    // it shipped hidden. It is a page of its own now, and this is a link.
    await expect(page.locator('#browse-registry')).toBeVisible();
    await expect(page.locator('#browse-registry')).toHaveAttribute('href', '/filters/registry');
  });

  test('a custom rule can be added and deleted through the forms', async ({ page, context }) => {
    await gotoFilters(page, context);
    await page.getByTestId('rule-input').fill('||nojs-added.example.com^');
    await submitAddRule(page);

    const row = page.locator('[data-testid="rule-row"]').filter({ hasText: 'nojs-added.example.com' });
    await expect(row).toBeVisible();
    await expect(row).toHaveAttribute('data-type', 'block');
    // The POST redirected, so the URL is the page and not the endpoint — a
    // refresh here re-renders rather than re-submitting.
    await expect(page).toHaveURL(/\/filters$/);

    await clickRowControl(row.getByTestId('rule-delete'));
    await expect(
      page.locator('[data-testid="rule-row"]').filter({ hasText: 'nojs-added.example.com' }),
    ).toHaveCount(0);
  });

  test('a rule that does not parse comes back in the field with a reason', async ({ page, context }) => {
    await gotoFilters(page, context);
    await page.getByTestId('rule-input').fill('   ');
    await submitAddRule(page);

    await expect(page.getByTestId('rule-add-error')).toContainText('Not a rule noadd understands');
    // Still the filters page, with the navigation knowing it, even though the
    // POST arrived on `/filters/rules`.
    await expect(page.locator('[data-testid="nav-filters"]')).toHaveClass(/active/);
  });

  test('a list can be added, toggled off, edited and deleted', async ({ page, context }) => {
    await gotoFilters(page, context);
    await page.getByTestId('list-name-input').fill('No JS List');
    await page.getByTestId('list-url-input').fill('https://example.com/no-js.txt');
    await submitAddList(page);

    const row = page.locator('[data-testid="filter-list-row"][data-name="No JS List"]');
    await expect(row).toBeVisible();
    await expect(row.getByTestId('filter-list-toggle')).toBeChecked();

    // Untick, then submit — two steps without a script, which is the trade the
    // no-JS path makes. The submit is the button `app.js` would have removed.
    await clickRowControl(row.locator('label.toggle'));
    await clickRowControl(row.locator('.nojs-only'));
    await expect(
      page.locator('[data-testid="filter-list-row"][data-name="No JS List"]')
        .getByTestId('filter-list-toggle'),
    ).not.toBeChecked();

    // Edit expands the row on the server rather than opening a dialog.
    await clickRowControl(
      page.locator('[data-testid="filter-list-row"][data-name="No JS List"] .edit-list'),
    );
    await expect(page.getByTestId('filter-list-edit-row')).toBeVisible();
    await expect(page.getByTestId('list-edit-name')).toHaveValue('No JS List');
    await page.getByTestId('list-edit-name').fill('Renamed Without JS');
    await page.getByTestId('list-edit-name').press('Enter');

    const renamed = page.locator('[data-testid="filter-list-row"][data-name="Renamed Without JS"]');
    await expect(renamed).toBeVisible();

    await clickRowControl(renamed.locator('.del-list'));
    await expect(
      page.locator('[data-testid="filter-list-row"][data-name="Renamed Without JS"]'),
    ).toHaveCount(0);
  });

  test('a list with no URL comes back with the name still typed', async ({ page, context }) => {
    await gotoFilters(page, context);
    await page.getByTestId('list-name-input').fill('Missing URL');
    await submitAddList(page);

    await expect(page.getByTestId('list-add-error')).toContainText('URL is required');
    await expect(page.getByTestId('list-name-input')).toHaveValue('Missing URL');
    await expect(
      page.locator('[data-testid="filter-list-row"][data-name="Missing URL"]'),
    ).toHaveCount(0);
  });

  test('a domain test is answered in the page and stays in the URL', async ({ page, context }) => {
    await gotoFilters(page, context);
    await page.getByTestId('rule-input').fill('||nojs-tested.example.com^');
    await submitAddRule(page);

    // The verdict comes from the live engine, which a background rebuild
    // refreshes; re-run the GET until the rule has landed.
    await expect.poll(async () => {
      await page.goto(`${BASE}/filters?test=nojs-tested.example.com`);
      return (await page.getByTestId('domain-test-result').textContent()) || '';
    }, { timeout: 10_000, intervals: [200, 300, 500] }).toContain('Blocked');

    await expect(page).toHaveURL(/test=nojs-tested\.example\.com/);
    // Refreshable and linkable: the domain came back in the field too.
    await expect(page.getByTestId('domain-test-input')).toHaveValue('nojs-tested.example.com');
  });

  test('Browse Registry is a link that reaches its page', async ({ page, context }) => {
    await gotoFilters(page, context);
    // This was the one control here that did nothing without JavaScript.
    await clickRowControl(page.locator('#browse-registry'));
    await expect(page).toHaveURL(/\/filters\/registry$/);
    await expect(page.locator('registry-page')).toBeVisible();
    // What the page then says depends on whether the third-party registry is
    // reachable from wherever this is running, and both answers are the page
    // working: entries to tick, or an explanation and a retry.
    await expect(
      page.locator('#registry-form, [data-testid="registry-unavailable"]').first(),
    ).toBeVisible();
  });
});
