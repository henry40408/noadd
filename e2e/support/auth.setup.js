import { test as setup, expect } from '@playwright/test';
import { ADMIN_PASSWORD, STORAGE_STATE } from '../steps/fixtures.js';

// Configure the shared @app instance once and persist the authenticated
// session. Tolerates a re-used server that is already configured (409).
setup('authenticate against the app instance', async ({ request }) => {
  const res = await request.post('/api/auth/setup', {
    data: { password: ADMIN_PASSWORD },
  });
  expect(
    [200, 409],
    `unexpected /api/auth/setup status ${res.status()}`,
  ).toContain(res.status());

  const login = await request.post('/api/auth/login', {
    data: { password: ADMIN_PASSWORD },
  });
  expect(login.ok(), 'login during setup failed').toBeTruthy();

  await request.storageState({ path: STORAGE_STATE });
});
