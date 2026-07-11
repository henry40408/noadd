import { defineConfig, devices } from '@playwright/test';
import { defineBddProject } from 'playwright-bdd';

// Path to the noadd binary that serves the embedded admin UI. CI builds the
// debug binary first; locally the default points at the cargo debug output.
const BIN = process.env.NOADD_BIN || '../target/debug/noadd';

// Two isolated instances, each on its own HTTP + DNS port and SQLite file:
//   - app:  shared, pre-authenticated instance for the read/write @app features
//   - auth: dedicated fresh-DB instance for the destructive @auth lifecycle
const APP = { http: 14100, dns: 15100 };
const AUTH = { http: 14101, dns: 15101 };
// Dedicated fresh-DB instance for the @onboarding new-install guidance flow.
// ONBOARDING.dns (15102) is also hardcoded in steps/onboarding.steps.js, where
// the "noadd resolves a real DNS query" step sends a UDP packet to that port.
// These two MUST stay in sync.
const ONBOARDING = { http: 14102, dns: 15102 };
const APP_URL = `http://127.0.0.1:${APP.http}`;
const AUTH_URL = `http://127.0.0.1:${AUTH.http}`;
const ONBOARDING_URL = `http://127.0.0.1:${ONBOARDING.http}`;
const STORAGE_STATE = '.auth/app.json';

// Start a fresh noadd instance: wipe its DB so every run begins unconfigured,
// then exec the binary on the given ports.
const server = (name, ports) =>
  `sh -c 'mkdir -p .tmp && rm -f .tmp/${name}.db* && exec ${BIN} ` +
  `--db-path .tmp/${name}.db --http-addr 127.0.0.1:${ports.http} ` +
  `--dns-addr 127.0.0.1:${ports.dns} --log-format json'`;

export default defineConfig({
  // Serial across the board: both servers hold mutable SQLite state that
  // scenarios share, so parallel workers would race.
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  timeout: 30_000,
  expect: { timeout: 10_000 },
  reporter: process.env.CI
    ? [['github'], ['html', { open: 'never' }]]
    : [['list']],

  webServer: [
    {
      command: server('app', APP),
      url: `${APP_URL}/api/health`,
      reuseExistingServer: !process.env.CI,
      timeout: 60_000,
    },
    {
      // Always fresh: the @auth scenarios depend on starting unconfigured.
      command: server('auth', AUTH),
      url: `${AUTH_URL}/api/health`,
      reuseExistingServer: false,
      timeout: 60_000,
    },
    {
      // Always fresh: the @onboarding scenarios depend on a pristine instance
      // that has served zero DNS queries (empty states + banner), so it must
      // never be reused across runs.
      command: server('onboarding', ONBOARDING),
      url: `${ONBOARDING_URL}/api/health`,
      reuseExistingServer: false,
      timeout: 60_000,
    },
  ],

  projects: [
    {
      // Sets the admin password on the app instance and saves the authenticated
      // session to storageState, reused by every @app feature.
      name: 'setup-app',
      testDir: 'support',
      testMatch: /auth\.setup\.js$/,
      use: { ...devices['Desktop Chrome'], baseURL: APP_URL },
    },
    {
      ...defineBddProject({
        name: 'auth',
        features: 'features/setup-and-auth.feature',
        steps: 'steps/*.js',
        outputDir: '.features-gen/auth',
      }),
      use: { ...devices['Desktop Chrome'], baseURL: AUTH_URL },
    },
    {
      // No storageState and no setup dependency: each onboarding scenario sets
      // the password (idempotent) and signs in fresh against its own instance.
      ...defineBddProject({
        name: 'onboarding',
        features: 'features/onboarding.feature',
        steps: 'steps/*.js',
        outputDir: '.features-gen/onboarding',
      }),
      use: { ...devices['Desktop Chrome'], baseURL: ONBOARDING_URL },
    },
    {
      ...defineBddProject({
        name: 'app',
        features: [
          'features/dashboard.feature',
          'features/custom-rules.feature',
          'features/filter-lists.feature',
        ],
        steps: 'steps/*.js',
        outputDir: '.features-gen/app',
      }),
      dependencies: ['setup-app'],
      use: {
        ...devices['Desktop Chrome'],
        baseURL: APP_URL,
        storageState: STORAGE_STATE,
      },
    },
    {
      // Mobile touch interaction for the Statistics charts. Plain Playwright
      // spec (not BDD): it seeds and drives its own noadd instance, so it needs
      // no shared server, storageState, or webServer entry. Runs in a Pixel 5
      // (hasTouch) context so tap()/touchscreen dispatch real touch events.
      name: 'touch',
      testDir: 'specs',
      testMatch: /chart-touch\.spec\.js$/,
      use: { ...devices['Pixel 5'] },
    },
    {
      // Settings-page auto-save model regression. Plain Playwright spec that
      // seeds and drives its own noadd instance (dedicated ports 14104/15104),
      // like `touch`; needs no shared server, storageState, or webServer entry.
      name: 'settings',
      testDir: 'specs',
      testMatch: /settings-autosave\.spec\.js$/,
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});
