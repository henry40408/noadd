import dgram from 'node:dgram';
import { expect } from '@playwright/test';
import { When, Then } from './fixtures.js';

// --- Shared with @auth (setup-and-auth.feature) ---------------------------

Then('I see a setup error about the password being too short', async ({ page }) => {
  await expect(page.getByTestId('setup-error')).toContainText(/at least 8|too short/i);
});

Then('I see a welcome message confirming the setup is complete', async ({ page }) => {
  await expect(page.getByTestId('setup-welcome')).toBeVisible();
});

// --- Next-step banner (both feature files) --------------------------------

Then(
  'I see the next-step banner explaining how to point a device at noadd',
  async ({ page }) => {
    await expect(page.getByTestId('next-step-banner')).toBeVisible();
  },
);

When('I dismiss the next-step banner', async ({ page }) => {
  await page.getByTestId('next-step-banner-dismiss').click();
});

Then('the next-step banner is no longer shown', async ({ page }) => {
  await expect(page.getByTestId('next-step-banner')).toHaveCount(0);
});

Then('reloading the admin UI does not show the next-step banner again', async ({ page }) => {
  await page.reload();
  await expect(page.getByTestId('next-step-banner')).toHaveCount(0);
});

// --- Dashboard / Query-log empty-state guidance ---------------------------

Then(
  'I see onboarding guidance explaining how to point a device at noadd',
  async ({ page }) => {
    await expect(page.getByTestId('dashboard-empty-state')).toBeVisible();
  },
);

Then("the guidance shows this server's DNS address", async ({ page, baseURL }) => {
  // The empty-state should print where to point a device. baseURL is the HTTP
  // origin, but its hostname (127.0.0.1) is the same address noadd serves DNS
  // on, so assert the guidance surfaces that host.
  const host = new URL(baseURL).hostname;
  await expect(page.getByTestId('dashboard-empty-state')).toContainText(host);
});

Then(
  'I see onboarding guidance explaining that no DNS queries have been logged yet',
  async ({ page }) => {
    await expect(page.getByTestId('logs-empty-state')).toBeVisible();
  },
);

// --- Filters: all-disabled warning ----------------------------------------

When('I disable every filter list', async ({ page }) => {
  const toggles = page.getByTestId('filter-list-toggle');
  const count = await toggles.count();
  expect(count, 'expected at least one filter list to disable').toBeGreaterThan(0);
  for (let i = 0; i < count; i += 1) {
    const toggle = toggles.nth(i);
    if (await toggle.isChecked()) {
      // Click the wrapping label (the input itself is visually hidden), which
      // flips the toggle and fires api.put('/api/lists/:id',{enabled:false}).
      const row = page.locator('[data-testid="filter-list-row"]').nth(i);
      await row.locator('label.toggle').click();
      // Awaiting the unchecked state lets the PUT settle without a flaky
      // explicit response-wait.
      await expect(toggle).not.toBeChecked();
    }
  }
});

Then('I see a warning that no filter list is enabled', async ({ page }) => {
  await expect(page.getByTestId('filters-all-disabled-warning')).toBeVisible();
});

Then('the warning offers a way to enable a recommended list', async ({ page }) => {
  await expect(page.getByTestId('filters-enable-recommended')).toBeVisible();
});

// --- Real DNS query against the onboarding instance -----------------------

// Build a minimal DNS A-record query packet for the given name. No EDNS, one
// question, recursion-desired set. Returns a Buffer ready to send over UDP.
function buildDnsQuery(name) {
  const id = Math.floor(Math.random() * 0x10000);
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0); // transaction id
  header.writeUInt16BE(0x0100, 2); // flags: standard query, RD=1
  header.writeUInt16BE(1, 4); // QDCOUNT = 1
  // ANCOUNT / NSCOUNT / ARCOUNT remain 0.

  const labels = name.split('.');
  const parts = [];
  for (const label of labels) {
    const buf = Buffer.from(label, 'ascii');
    parts.push(Buffer.from([buf.length]), buf);
  }
  parts.push(Buffer.from([0])); // root terminator
  const qname = Buffer.concat(parts);

  const qtail = Buffer.alloc(4);
  qtail.writeUInt16BE(1, 0); // QTYPE = A
  qtail.writeUInt16BE(1, 2); // QCLASS = IN

  return Buffer.concat([header, qname, qtail]);
}

When('noadd resolves a real DNS query', async () => {
  // 15102 == ONBOARDING.dns in playwright.config.js. These MUST stay in sync.
  const DNS_PORT = 15102;
  const packet = buildDnsQuery('onboarding-probe.example');
  const socket = dgram.createSocket('udp4');
  await new Promise((resolve, reject) => {
    socket.send(packet, DNS_PORT, '127.0.0.1', (err) => {
      socket.close();
      if (err) reject(err);
      else resolve();
    });
  });
  // noadd logs every handled query and the logger flushes ~every 1s; the
  // subsequent "next-step banner is no longer shown" assertion polls under the
  // 10s expect timeout, absorbing that flush window. No response is needed.
});
