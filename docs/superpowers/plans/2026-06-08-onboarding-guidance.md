# Onboarding Guidance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Improve noadd's first-run onboarding so a new admin knows what to do after setup — via a dismissable next-step banner, empty-state guidance, an all-lists-disabled warning, a stronger password floor, and a welcome message — all driven by the already-committed BDD specs.

**Architecture:** Backend changes are minimal (Rust/axum: an 8-char password floor on `POST /api/auth/setup`, and exposing one settings key). All UI lives in a single embedded vanilla-JS Web Components SPA (`admin-ui/dist/index.html`), so frontend work edits that one file and the Rust binary must be rebuilt (`cargo build`) for the embedded copy to update. Acceptance tests are Playwright-BDD in `e2e/`, with a new dedicated `@onboarding` instance that starts pristine and is fed a real DNS query to prove the banner auto-clears.

**Tech Stack:** Rust 2024 (axum, rusqlite), vanilla-JS Web Components, Playwright + playwright-bdd, `cargo nextest`.

---

## Cross-Cutting Notes (read before starting)

- **`include_dir` rebuild:** `admin-ui/dist/index.html` is embedded into the binary at compile time. Any UI edit is invisible to the e2e harness (which launches `../target/debug/noadd`) until you run `cargo build` from the repo root. Every frontend task ends with a rebuild.
- **Port coupling:** the `@onboarding` instance's DNS port `15102` appears in BOTH `e2e/playwright.config.js` (`ONBOARDING.dns`) and `e2e/steps/onboarding.steps.js` (`DNS_PORT`). They must stay in sync; both carry a cross-reference comment.
- **Task order matters for red→green:** Task 1 (backend) and Task 2 (e2e harness) land first as the executable spec (Task 2 runs red). Tasks 3–5 turn scenarios green. Task 6 verifies everything together.
- **Two tasks edit `AppShell` in `index.html`** (welcome strip in Task 3, `<next-step-banner>` tag in Task 4) at adjacent-but-distinct locations. Apply them sequentially (subagent-driven or batched executing-plans); no overlap.
- **Project rules:** `cargo nextest run` (not `cargo test`); `cargo fmt` before committing Rust; stage files explicitly by name (never `git add -A`/`.`); GPG-signed commits; commit messages end with the `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>` trailer. Do not stage the untracked `localhost*.pem` files.

## File Structure

- `src/admin/api.rs` — setup handler (password floor + JSON error body); `get_settings` key list (+ `onboarding_banner_dismissed`).
- `tests/admin_api_test.rs` — refactor the test app builder to allow an unconfigured app; three new setup tests.
- `e2e/playwright.config.js` — new `ONBOARDING` instance + `onboarding` BDD project.
- `e2e/steps/onboarding.steps.js` (new) — all new step definitions (shared `@auth` + `@onboarding` phrases live here).
- `admin-ui/dist/index.html` — `SetupPage` (8-char floor), `AppShell` (welcome strip + `<next-step-banner>`), `NextStepBanner` (new component), `DashboardPage`/`LogsPage`/`FiltersPage` (empty states + all-disabled warning).

---

### Task 1: Backend — enforce minimum password length and expose banner-dismissed setting

**Files:**
- Modify: `src/admin/api.rs:258-287` (add `MIN_PASSWORD_LENGTH` const + `SetupErrorResponse` struct + rewrite `setup()` handler), `src/admin/api.rs:351-357` (add `onboarding_banner_dismissed` key)
- Refactor test helper + add tests: `tests/admin_api_test.rs:29-87`

Ordering decision: **409-if-configured first, then 400-if-too-short.** This preserves the existing security property (an already-configured instance never reveals password policy and can never be re-setup). The 400 path returns a JSON body `{ "error": "..." }` so the frontend can display it; 409/500 keep their existing bare-status behavior (the frontend keys 409 off the status code).

- [ ] **Step 1: Refactor the test helper to allow an unconfigured app.** In `tests/admin_api_test.rs`, replace `setup_inner` (lines 29-87) so password-setting is conditional, and add an `unconfigured_app()` helper:

```rust
async fn setup_inner(registry_url: &str) -> (axum::Router, String) {
    build_app(registry_url, true).await
}

/// Build a router whose admin password is NOT set, so `/api/auth/setup`
/// does not short-circuit with 409. Returns only the router (no session
/// token is meaningful before setup).
#[allow(dead_code)]
async fn unconfigured_app() -> axum::Router {
    build_app("http://127.0.0.1:1/filters.json", false).await.0
}

async fn build_app(registry_url: &str, set_password: bool) -> (axum::Router, String) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db");
    let path_str = path.to_str().unwrap().to_string();
    std::mem::forget(dir);

    let db = Database::open(&path_str).await.unwrap();
    let sessions = new_session_store();
    let token = create_session(&sessions);
    let filter = Arc::new(ArcSwap::from_pointee(FilterEngine::new(
        vec![],
        vec![],
        vec![],
    )));
    let cache = DnsCache::new(100);
    let rate_limiter = Arc::new(RateLimiter::new(5, 60));
    let forwarder = Arc::new(UpstreamForwarder::new(UpstreamConfig::default()).await);
    let (log_tx, _log_rx) = mpsc::channel(64);
    let handler = Arc::new(DnsHandler::new(
        filter.clone(),
        cache.clone(),
        forwarder.clone(),
        log_tx,
    ));

    // Set admin password (skipped for unconfigured apps that test setup)
    if set_password {
        let hash = hash_password("admin").unwrap();
        db.set_setting("admin_password_hash", &hash).await.unwrap();
    }

    let list_manager = Arc::new(noadd::filter::lists::ListManager::new(
        db.clone(),
        filter.clone(),
    ));
    let rebuild = noadd::filter::rebuild::RebuildCoordinator::new();
    let registry = noadd::registry::RegistryClient::new(
        registry_url.to_string(),
        std::time::Duration::from_secs(3600),
    );

    let router = admin_router(AppState {
        db,
        sessions,
        filter,
        cache,
        rate_limiter,
        forwarder,
        handler,
        server_info: ServerInfo {
            dns_addr: "127.0.0.1:53".into(),
            http_addr: "127.0.0.1:3000".into(),
            tls_enabled: false,
        },
        list_manager,
        rebuild,
        registry,
        trusted_proxies: std::sync::Arc::new(noadd::net::TrustedProxies::default()),
    });
    (router, token)
}
```

Existing callers `setup()` (20-22) and `setup_with_registry_url()` (24-27) still call `setup_inner`, which now delegates to `build_app(.., true)` and sets `"admin"` exactly as before.

- [ ] **Step 2: Write the failing tests.** Append to the end of `tests/admin_api_test.rs`:

```rust
#[tokio::test]
async fn setup_rejects_short_password_with_400() {
    let app = unconfigured_app().await;
    let req = Request::builder()
        .method("POST")
        .uri("/api/auth/setup")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"password":"1234567"}"#)) // 7 chars
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        body.get("error").and_then(|v| v.as_str()).is_some(),
        "expected a JSON error body, got: {body}"
    );
}

#[tokio::test]
async fn setup_accepts_eight_char_password_with_200() {
    let app = unconfigured_app().await;
    let req = Request::builder()
        .method("POST")
        .uri("/api/auth/setup")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"password":"12345678"}"#)) // 8 chars
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body.get("success").and_then(|v| v.as_bool()), Some(true));
}

#[tokio::test]
async fn setup_already_configured_returns_409() {
    // `setup()` builds an app with the admin password already set.
    let (app, _token) = setup().await;
    let req = Request::builder()
        .method("POST")
        .uri("/api/auth/setup")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"password":"another-long-pw"}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}
```

- [ ] **Step 3: Run the tests, expect FAIL.**

```
pwd   # must be /home/nixos/Develop/claude/noadd
cargo nextest run --test admin_api_test
```

Expected: `setup_already_configured_returns_409` and `setup_accepts_eight_char_password_with_200` PASS; `setup_rejects_short_password_with_400` FAILS (current handler stores the 7-char password and returns 200 → `left: 200, right: 400`).

- [ ] **Step 4: Add the const + error struct.** In `src/admin/api.rs`, insert immediately above `SetupRequest` (line 253):

```rust
/// Minimum length for the admin password set via `POST /api/auth/setup`.
const MIN_PASSWORD_LENGTH: usize = 8;

#[derive(Serialize)]
struct SetupErrorResponse {
    error: String,
}
```

- [ ] **Step 5: Rewrite the `setup` handler** (replace lines 263-287):

```rust
async fn setup(
    State(state): State<AppState>,
    Json(body): Json<SetupRequest>,
) -> Result<Json<SetupResponse>, (StatusCode, Json<SetupErrorResponse>)> {
    // Only allow setup if no password exists (check this first so a
    // configured instance never reveals password-policy details).
    let existing = state.db.get_setting("admin_password_hash").await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(SetupErrorResponse {
                error: "internal error".to_string(),
            }),
        )
    })?;

    if existing.is_some() {
        return Err((
            StatusCode::CONFLICT,
            Json(SetupErrorResponse {
                error: "already configured".to_string(),
            }),
        ));
    }

    if body.password.chars().count() < MIN_PASSWORD_LENGTH {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(SetupErrorResponse {
                error: format!(
                    "password must be at least {MIN_PASSWORD_LENGTH} characters"
                ),
            }),
        ));
    }

    let hash = hash_password(&body.password).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(SetupErrorResponse {
                error: "internal error".to_string(),
            }),
        )
    })?;

    state.db.set_setting("admin_password_hash", &hash).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(SetupErrorResponse {
                error: "internal error".to_string(),
            }),
        )
    })?;

    Ok(Json(SetupResponse { success: true }))
}
```

`chars().count()` counts characters, not UTF-8 bytes. The 409 path now also carries a JSON body; the frontend keys off the status code, so this is additive. Imports already include `Json`, `Serialize`, `StatusCode`, `IntoResponse` (lines 6-13) — `(StatusCode, Json<T>)` implements `IntoResponse`.

- [ ] **Step 6: Expose `onboarding_banner_dismissed` in `get_settings`.** In `src/admin/api.rs`, change the `keys` array (lines 351-357) to append `"onboarding_banner_dismissed"`:

```rust
    let keys = [
        "upstream_servers",
        "upstream_strategy",
        "log_retention_days",
        "doh_access_policy",
        "public_url",
        "onboarding_banner_dismissed",
    ];
```

`put_settings` (375-398) has no whitelist and already accepts arbitrary keys — no change needed for writes.

- [ ] **Step 7: Run the tests, expect PASS.**

```
pwd   # must be /home/nixos/Develop/claude/noadd
cargo nextest run --test admin_api_test
```

Expected: all three new tests PASS; all pre-existing tests still PASS (`0 failed`).

- [ ] **Step 8: Format.**

```
pwd   # must be /home/nixos/Develop/claude/noadd
cargo fmt
```

- [ ] **Step 9: Stage explicitly and commit (GPG-signed).**

```
git add src/admin/api.rs tests/admin_api_test.rs
git commit -S -m "feat(admin): enforce 8-char minimum admin password and expose onboarding_banner_dismissed

Reject setup passwords shorter than 8 characters with HTTP 400 and a JSON
error body (after the existing 409 already-configured check), and surface
the onboarding_banner_dismissed setting via GET /api/settings so the
frontend can read its dismissal state.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: E2E harness — `@onboarding` project and step definitions

**Files:**
- Modify: `e2e/playwright.config.js` — add a fresh `ONBOARDING={http:14102,dns:15102}` instance (webServer + `defineBddProject` named `onboarding`, no storageState).
- Create: `e2e/steps/onboarding.steps.js` — all new `@onboarding` step defs plus the two new `@auth` step defs ("password too short", "welcome message"). The `steps:'steps/*.js'` glob is loaded by every BDD project, so one new file serves both tags. Do NOT touch `auth.steps.js`.

**Verified non-collisions** (already defined — MUST NOT redefine): every phrase in `auth.steps.js`, plus `common.steps.js`'s "I am signed in to the admin UI", "I go to the {string} tab", "I am on the {string} tab", "I see the {string} section". The next-step-banner phrases appear in BOTH feature files but are defined only once below.

- [ ] **Step 1a: Add instance constants** to `e2e/playwright.config.js` — after the `AUTH` block (lines 11-14):

BEFORE:
```js
const APP = { http: 14100, dns: 15100 };
const AUTH = { http: 14101, dns: 15101 };
const APP_URL = `http://127.0.0.1:${APP.http}`;
const AUTH_URL = `http://127.0.0.1:${AUTH.http}`;
const STORAGE_STATE = '.auth/app.json';
```
AFTER:
```js
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
```

- [ ] **Step 1b: Add the webServer entry** — append after the `auth` webServer entry (after line 50, before the closing `]`):

```js
    {
      // Always fresh: the @onboarding scenarios depend on a pristine instance
      // that has served zero DNS queries (empty states + banner), so it must
      // never be reused across runs.
      command: server('onboarding', ONBOARDING),
      url: `${ONBOARDING_URL}/api/health`,
      reuseExistingServer: false,
      timeout: 60_000,
    },
```

- [ ] **Step 1c: Add the project** — append after the `app` project (after line 88, before the closing `]`):

```js
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
```

- [ ] **Step 2: Create `e2e/steps/onboarding.steps.js`** (full file):

```js
import dgram from 'node:dgram';
import { expect } from '@playwright/test';
import { Given, When, Then } from './fixtures.js';

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
```

- [ ] **Step 3: Build the binary, then run, expect FAIL (red).** The webServer runs `../target/debug/noadd` (embeds `admin-ui/dist` via `include_dir`).

```
pwd   # /home/nixos/Develop/claude/noadd
cargo build
cd e2e && npx bddgen && npx playwright test --project=onboarding --project=auth
```

Expected: `bddgen` succeeds (no undefined steps). Assertions fail on missing testids: every `@onboarding` scenario fails (no `dashboard-empty-state`/`logs-empty-state`/`next-step-banner`/`filters-all-disabled-warning`), and the two new `@auth` scenarios fail (`setup-error` copy / `setup-welcome`). Pre-existing `@auth` scenarios (mismatch, wrong password, successful sign-in, revoke) still PASS — proving the new file did not break step resolution.

- [ ] **Step 4: Commit.**

```
git add e2e/playwright.config.js e2e/steps/onboarding.steps.js
git commit -S -m "test(e2e): add @onboarding project and onboarding step defs

Add a fresh-DB onboarding instance (http 14102 / dns 15102) plus an
onboarding BDD project to playwright.config, and define every new step
for onboarding.feature and the setup-and-auth.feature additions. These
fail until the admin UI gains the onboarding testids (executable spec).

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Frontend — setup password minimum (8) and post-setup welcome message

**Files:**
- Modify: `admin-ui/dist/index.html:1499-1502` (SetupPage `doSetup` min-length check)
- Modify: `admin-ui/dist/index.html:1509-1517` (SetupPage `doSetup` success path)
- Modify: `admin-ui/dist/index.html:1560-1597` (AppShell `connectedCallback` — welcome strip)

Acceptance tests: `e2e/features/setup-and-auth.feature` scenarios "Setup rejects a password shorter than the minimum length" (asserts `setup-error` matches /at least 8|too short/i; the UI must block sub-8 **before** any API call) and "First-run setup creates the admin password and signs in" (asserts `setup-welcome` visible after landing on the dashboard).

- [ ] **Step 1: Raise client-side minimum to 8.** Replace lines 1499-1502.

OLD:
```js
      if (!pw.value || pw.value.length < 4) {
        err.textContent = 'Password must be at least 4 characters';
        err.style.display = 'block';
        return;
      }
```
NEW:
```js
      if (!pw.value || pw.value.length < 8) {
        err.textContent = 'Password must be at least 8 characters';
        err.style.display = 'block';
        return;
      }
```

This runs before both `api.post('/api/auth/setup', ...)` and `api.post('/api/auth/login', ...)`, so a 7-char password returns early and never hits the API.

- [ ] **Step 2: Set the just-set-up flag on successful setup.** Replace lines 1509-1517.

OLD:
```js
      try {
        await api.post('/api/auth/setup', { password: pw.value });
        // Auto-login after setup
        await api.post('/api/auth/login', { password: pw.value });
        this.dispatchEvent(new CustomEvent('login-success', { bubbles: true }));
      } catch (e) {
        err.textContent = 'Setup failed. A password may already be set.';
        err.style.display = 'block';
      }
```
NEW:
```js
      try {
        await api.post('/api/auth/setup', { password: pw.value });
        // Auto-login after setup
        await api.post('/api/auth/login', { password: pw.value });
        // Mark this session as just-set-up so the dashboard shows a one-time
        // welcome message. Set before dispatching so AppShell sees it on render.
        try { sessionStorage.setItem('noadd_just_setup', '1'); } catch (e) {}
        this.dispatchEvent(new CustomEvent('login-success', { bubbles: true }));
      } catch (e) {
        err.textContent = 'Setup failed. A password may already be set.';
        err.style.display = 'block';
      }
```

- [ ] **Step 3: Render the one-time welcome strip in `AppShell`.** Leave the `<main class="main-content">` template (lines 1577-1580) unchanged. Append the welcome-injection logic at the end of `connectedCallback`, right after the existing `updateActive();` (line 1594).

OLD:
```js
    window.addEventListener('hashchange', updateActive);
    updateActive();
  }

  get pageContent() { return this.querySelector('#page-content'); }
```
NEW:
```js
    window.addEventListener('hashchange', updateActive);
    updateActive();

    // One-time post-setup welcome strip. Shown once for the session that just
    // completed first-run setup (flag set in SetupPage.doSetup), then cleared
    // so it never reappears on later logins.
    let justSetUp = false;
    try {
      justSetUp = sessionStorage.getItem('noadd_just_setup') === '1';
      if (justSetUp) sessionStorage.removeItem('noadd_just_setup');
    } catch (e) {}
    if (justSetUp) {
      const main = this.querySelector('.main-content');
      const welcome = document.createElement('div');
      welcome.className = 'rebuild-banner show done';
      welcome.setAttribute('data-testid', 'setup-welcome');
      welcome.innerHTML = `
        <div class="icon">${icons.check || ''}</div>
        <div class="text">
          <span class="label">Setup complete — welcome to noadd!</span>
          <span class="meta">Your admin password is set and you're signed in.</span>
        </div>
        <button class="btn btn-secondary" data-testid="setup-welcome-dismiss"
                style="margin-left:auto" aria-label="Dismiss">Dismiss</button>`;
      welcome.querySelector('[data-testid="setup-welcome-dismiss"]').onclick = () => welcome.remove();
      main.insertBefore(welcome, main.firstChild);
    }
  }

  get pageContent() { return this.querySelector('#page-content'); }
```

Reuses the existing `.rebuild-banner.show.done` strip styling. `setup-welcome` is static text (no `esc()` needed). The flag is read-and-cleared inside the guard, so it shows exactly once.

- [ ] **Step 4: Rebuild the binary.**

```
pwd   # /home/nixos/Develop/claude/noadd
cargo build
```

- [ ] **Step 5: Run the auth scenarios, expect PASS.**

```
cd e2e && npx bddgen && npx playwright test --project=auth
```

Expect both target scenarios green and no regression in the other auth scenarios. (The "next-step banner can be dismissed" auth scenario stays red until Task 4.)

- [ ] **Step 6: Commit.**

```
git add admin-ui/dist/index.html
git commit -S -m "feat: enforce 8-char min password and add post-setup welcome message

Raise client-side setup password minimum from 4 to 8, blocking sub-8
passwords before any API call. After successful first-run setup, show a
one-time dismissible welcome strip (data-testid=setup-welcome) gated by a
sessionStorage flag so it appears once and not on later logins.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Frontend — next-step onboarding banner

**Files:**
- Modify: `admin-ui/dist/index.html:1577-1580` (add `<next-step-banner></next-step-banner>` inside `AppShell`'s `<main class="main-content">`, sibling of `<rebuild-banner>`)
- Modify: `admin-ui/dist/index.html:1663-1664` (define `NextStepBanner` + `customElements.define` after `customElements.define('rebuild-banner', RebuildBanner)`)

Depends on Task 1 (the `onboarding_banner_dismissed` key in `GET /api/settings`). Verified endpoints: `GET /api/server-info` → `{ dns_addr, http_addr, tls_enabled }` (`dns_addr` like `"0.0.0.0:53"`); `GET /api/stats/summary` → `total_today`/`total_7d`/`total_30d`; `GET`/`PUT /api/settings`. `icons.close` (X glyph) confirmed at `index.html:1468`.

Acceptance tests: "The next-step banner can be dismissed and stays dismissed" (`@auth`), "The next-step banner is shown on a fresh install" and "The next-step banner disappears once noadd serves a real query" (`@onboarding`).

- [ ] **Step 1: Add the `<next-step-banner>` tag in `AppShell`.** Insert one line so the block (lines 1577-1580) reads:

```
        <main class="main-content">
          <rebuild-banner></rebuild-banner>
          <next-step-banner></next-step-banner>
          <div id="page-content"></div>
        </main>
```

(Insert between the existing `<rebuild-banner>` line and `<div id="page-content">`. Do not touch the `setup-welcome` injection from Task 3.)

- [ ] **Step 2: Define the `NextStepBanner` component.** Immediately after `customElements.define('rebuild-banner', RebuildBanner);` (line 1663) and before the `// --- Registry Modal ---` comment (line 1665), insert:

```javascript
// --- Next-Step Onboarding Banner ---
// On a fresh install, tells the admin how to point a device's DNS at noadd
// and shows the server's DNS address. Auto-hides once a real DNS query has
// been served (polls /api/stats/summary every 3s). Can be dismissed; the
// dismissal persists server-side via PUT /api/settings.
class NextStepBanner extends HTMLElement {
  connectedCallback() {
    this.timer = null;
    this.dnsAddr = '';
    this.innerHTML = '';   // render nothing until init decides
    this.init();
  }
  disconnectedCallback() {
    if (this.timer) { clearInterval(this.timer); this.timer = null; }
  }
  async init() {
    // 1) Respect a prior dismissal — if dismissed, never show or poll.
    let settings;
    try {
      settings = await api.get('/api/settings');
    } catch (e) {
      return;
    }
    if (settings && settings.onboarding_banner_dismissed === 'true') {
      return;
    }
    // 2) Resolve the DNS address to display: location.hostname + the port
    //    parsed from server-info's dns_addr (e.g. "0.0.0.0:53" -> "53").
    try {
      const info = await api.get('/api/server-info');
      const raw = (info && info.dns_addr) || '';
      const port = raw.includes(':') ? raw.slice(raw.lastIndexOf(':') + 1) : raw;
      this.dnsAddr = `${window.location.hostname}:${port}`;
    } catch (e) {
      return;
    }
    // 3) If a query was already served, stay hidden; otherwise show + poll.
    if (await this.hasQueries()) {
      return;
    }
    this.show();
    this.timer = setInterval(() => this.poll(), 3000);
  }
  async hasQueries() {
    try {
      const s = await api.get('/api/stats/summary');
      return ((s.total_today || 0) + (s.total_7d || 0) + (s.total_30d || 0)) > 0;
    } catch (e) {
      return false;
    }
  }
  async poll() {
    if (await this.hasQueries()) {
      if (this.timer) { clearInterval(this.timer); this.timer = null; }
      this.innerHTML = '';
    }
  }
  show() {
    this.innerHTML = `
      <div class="rebuild-banner show" role="status" aria-live="polite" data-testid="next-step-banner">
        <span class="icon">${icons.dashboard}</span>
        <span class="text">
          <span class="label">Point a device's DNS at noadd to start blocking — set its DNS server to <strong data-testid="next-step-banner-addr">${esc(this.dnsAddr)}</strong>.</span>
        </span>
        <button class="btn btn-ghost" data-testid="next-step-banner-dismiss" title="Dismiss" style="margin-left:auto">${icons.close}</button>
      </div>`;
    const dismiss = this.querySelector('[data-testid="next-step-banner-dismiss"]');
    dismiss.onclick = () => this.dismiss();
  }
  async dismiss() {
    if (this.timer) { clearInterval(this.timer); this.timer = null; }
    this.innerHTML = '';
    try {
      await api.put('/api/settings', { onboarding_banner_dismissed: 'true' });
    } catch (e) {
      // best-effort; UI already hidden for this session
    }
  }
}
customElements.define('next-step-banner', NextStepBanner);
```

Renders nothing when dismissed or when queries exist; auto-hide polls every 3000ms (within Playwright's 10s timeout given the 1s log flush); the address is wrapped in `<strong>` so the step can assert it contains the hostname.

- [ ] **Step 3: Rebuild the binary.**

```
pwd   # /home/nixos/Develop/claude/noadd
cargo build
```

- [ ] **Step 4: Run the banner scenarios, expect PASS.**

```
cd e2e && npx bddgen && npx playwright test --project=onboarding --project=auth
```

The three banner scenarios must now pass (shown on fresh install; disappears after a real query via the 3s poll; dismiss persists across reload on the @auth instance, which never serves DNS).

- [ ] **Step 5: Commit.**

```
git add admin-ui/dist/index.html
git commit -S -m "feat(ui): add next-step onboarding banner

Adds a <next-step-banner> custom element to the app shell that shows the
server's DNS address on a fresh install, auto-hides once a real DNS query
is served (polls /api/stats/summary every 3s), and can be dismissed
(persisted via PUT /api/settings onboarding_banner_dismissed).

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Frontend — onboarding empty states and all-disabled warning

**Files:**
- Modify: `admin-ui/dist/index.html` (DashboardPage `:1887-2127`; LogsPage `:2557-2718`; FiltersPage `:2721-2905`)

Verified facts: `/api/server-info`'s `dns_addr` is the bind address (e.g. `0.0.0.0:53`), so substitute `window.location.hostname` and reuse only its port — satisfies "text contains the DNS address (the host)". The toggle `cb.onchange` PUTs but does NOT re-render, so the warning is recomputed from live checkbox state via `_refreshAllDisabledWarning()`.

Acceptance tests (`@onboarding`): "The dashboard guides a new user…" (`dashboard-empty-state` visible + contains the host), "The query log explains…" (`logs-empty-state` visible), "Filters warns when every list is disabled" (`filters-all-disabled-warning` + `filters-enable-recommended`).

- [ ] **Step 1: Dashboard — add a DNS-address field.** Replace lines 1888-1897.

OLD:
```js
  constructor() {
    super();
    this._pollTimer = null;
    this._live = true;
    this._prevStats = null;
    this._prevChart = null;
    this._prevDomains = null;
    this._prevClients = null;
    this._prevUpstreams = null;
  }
```
NEW:
```js
  constructor() {
    super();
    this._pollTimer = null;
    this._live = true;
    this._prevStats = null;
    this._prevChart = null;
    this._prevDomains = null;
    this._prevClients = null;
    this._prevUpstreams = null;
    this._dnsAddr = '';
  }
```

- [ ] **Step 2: Dashboard — add the empty-state div to the template.** Replace lines 1904-1905.

OLD:
```js
      </div>
      <div class="stat-grid fade-in" id="stats"></div>
```
NEW:
```js
      </div>
      <div class="card fade-in" id="onboard-empty" data-testid="dashboard-empty-state" style="display:none"></div>
      <div class="stat-grid fade-in" id="stats"></div>
```

- [ ] **Step 3: Dashboard — fetch server-info before the first `_fetchAll`.** Replace lines 1936-1937.

OLD:
```js
      await this._fetchAll();
      this._startPolling();
```
NEW:
```js
      try {
        const info = await api.get('/api/server-info');
        const port = (info && info.dns_addr ? String(info.dns_addr) : '').split(':').pop();
        this._dnsAddr = port ? `${window.location.hostname}:${port}` : window.location.hostname;
      } catch (e) { this._dnsAddr = window.location.hostname; }

      await this._fetchAll();
      this._startPolling();
```

- [ ] **Step 4: Dashboard — toggle the empty state at the end of `renderStats`.** Replace lines 2010-2025.

OLD:
```js
      // Flash cards that changed (skip on first render)
      if (prevVals) {
        statsEl.querySelectorAll('.stat-card').forEach(card => {
          const i = parseInt(card.dataset.i);
          if (String(vals[i]) !== String(prevVals[i])) {
            card.classList.add('flash');
            requestAnimationFrame(() => {
              requestAnimationFrame(() => {
                card.classList.remove('flash');
              });
            });
          }
        });
      }
    }
```
NEW:
```js
      // Flash cards that changed (skip on first render)
      if (prevVals) {
        statsEl.querySelectorAll('.stat-card').forEach(card => {
          const i = parseInt(card.dataset.i);
          if (String(vals[i]) !== String(prevVals[i])) {
            card.classList.add('flash');
            requestAnimationFrame(() => {
              requestAnimationFrame(() => {
                card.classList.remove('flash');
              });
            });
          }
        });
      }

      this._renderOnboarding(s);
    }

    _renderOnboarding(s) {
      const hasQueries = ((s.total_today || 0) + (s.total_7d || 0) + (s.total_30d || 0)) > 0;
      const box = this.querySelector('#onboard-empty');
      const chart = this.querySelector('#chart-card');
      if (!box) return;
      if (hasQueries) {
        box.style.display = 'none';
        if (chart) chart.style.display = '';
        return;
      }
      box.innerHTML = `
        <div class="card-title">Point a device at noadd to get started</div>
        <p style="color:var(--text-secondary);font-size:0.9rem;margin:8px 0">
          noadd hasn't served any DNS queries yet. To start filtering, configure a device or
          router to use this server as its DNS resolver, then send some traffic.
        </p>
        <p style="color:var(--text-secondary);font-size:0.9rem;margin:8px 0">
          Set the device's DNS server to:
          <code class="mono" style="color:var(--text-primary)">${esc(this._dnsAddr)}</code>
        </p>`;
      box.style.display = '';
      if (chart) chart.style.display = 'none';
    }
```

(`_renderOnboarding` is inserted as a new method between `renderStats` and `renderChart`; the other render methods are unchanged.)

- [ ] **Step 5: Query Log — empty-state guidance in `renderLogs` (desktop).** Replace lines 2642-2648.

OLD:
```js
  renderLogs(logs) {
    // Desktop table
    const body = this.querySelector('#log-body');
    if (!logs.length) {
      body.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-dim)">No logs found</td></tr>';
    } else {
      body.innerHTML = logs.map(l => `<tr>
```
NEW:
```js
  renderLogs(logs) {
    const noFilters = !this.search && !this.actionFilter && !this.tokenFilter && !this.typeFilter;
    const emptyGuide = `<div data-testid="logs-empty-state" style="text-align:center;color:var(--text-secondary);padding:24px 12px">
        <div style="color:var(--text-primary);font-weight:600;margin-bottom:6px">No DNS queries logged yet</div>
        <div style="font-size:0.9rem">Once a device uses noadd as its DNS resolver, its queries will appear here.</div>
      </div>`;
    // Desktop table
    const body = this.querySelector('#log-body');
    if (!logs.length) {
      body.innerHTML = (!logs.length && noFilters)
        ? `<tr><td colspan="8" style="padding:0">${emptyGuide}</td></tr>`
        : '<tr><td colspan="8" style="text-align:center;color:var(--text-dim)">No logs found</td></tr>';
    } else {
      body.innerHTML = logs.map(l => `<tr>
```

- [ ] **Step 6: Query Log — same guidance in the mobile cards path.** Replace lines 2660-2663.

OLD:
```js
      // Mobile card list
      const cards = this.querySelector('#log-cards');
      if (!logs.length) {
        cards.innerHTML = '<p style="color:var(--text-dim);text-align:center;padding:16px">No logs found</p>';
      } else {
```
NEW:
```js
      // Mobile card list
      const cards = this.querySelector('#log-cards');
      if (!logs.length) {
        cards.innerHTML = noFilters
          ? emptyGuide
          : '<p style="color:var(--text-dim);text-align:center;padding:16px">No logs found</p>';
      } else {
```

(Only one `logs-empty-state` is visible per viewport — desktop table is `hide-mobile-block`, mobile cards are `show-mobile`.)

- [ ] **Step 7: Filters — add hidden all-disabled warning markup.** Replace lines 2734-2740.

OLD:
```js
        <div class="card fade-in" style="animation-delay:0.05s">
          <div class="card-title">Filter Lists</div>
          <div class="filters-row" style="margin-bottom:12px;display:flex;gap:8px;flex-wrap:wrap">
            <button class="btn btn-primary btn-sm" id="update-all">${icons.refresh} Update All</button>
            <button class="btn btn-sm" id="browse-registry">${icons.search} Browse Registry</button>
          </div>
          <div class="table-wrap hide-mobile-block"><table><thead><tr>
```
NEW:
```js
        <div class="card fade-in" style="animation-delay:0.05s">
          <div class="card-title">Filter Lists</div>
          <div data-testid="filters-all-disabled-warning" style="display:none;margin-bottom:12px;padding:12px;border-radius:8px;background:var(--bg-secondary);border:1px solid var(--red)">
            <div style="color:var(--text-primary);font-weight:600;margin-bottom:4px">No filter list is enabled</div>
            <div style="color:var(--text-secondary);font-size:0.9rem;margin-bottom:8px">Every filter list is turned off, so noadd is not blocking anything. Enable a recommended list to start filtering.</div>
            <button class="btn btn-primary btn-sm" data-testid="filters-enable-recommended" id="enable-recommended">Enable AdGuard DNS filter</button>
          </div>
          <div class="filters-row" style="margin-bottom:12px;display:flex;gap:8px;flex-wrap:wrap">
            <button class="btn btn-primary btn-sm" id="update-all">${icons.refresh} Update All</button>
            <button class="btn btn-sm" id="browse-registry">${icons.search} Browse Registry</button>
          </div>
          <div class="table-wrap hide-mobile-block"><table><thead><tr>
```

- [ ] **Step 8: Filters — keep `this._lists`, recompute on toggle (no refetch), add helpers.**

(8a) Replace lines 2842-2845:

OLD:
```js
  async loadLists() {
    try {
      const lists = await api.get('/api/lists');

      // Desktop table
      const body = this.querySelector('#lists-body');
```
NEW:
```js
  async loadLists() {
    try {
      const lists = await api.get('/api/lists');
      this._lists = lists;

      // Desktop table
      const body = this.querySelector('#lists-body');
```

(8b) Replace lines 2884-2889 (toggle binding):

OLD:
```js
      // Bind toggles and delete buttons (both table and cards)
      this.querySelectorAll('#lists-body input[type=checkbox], #lists-cards input[type=checkbox]').forEach(cb => {
        cb.onchange = async () => {
          await api.put(`/api/lists/${cb.dataset.id}`, { enabled: cb.checked });
        };
      });
```
NEW:
```js
      // Bind toggles and delete buttons (both table and cards)
      this.querySelectorAll('#lists-body input[type=checkbox], #lists-cards input[type=checkbox]').forEach(cb => {
        cb.onchange = async () => {
          await api.put(`/api/lists/${cb.dataset.id}`, { enabled: cb.checked });
          this._refreshAllDisabledWarning();
        };
      });
```

(8c) Replace lines 2900-2904 (end of `loadLists`) and add the two helper methods:

OLD:
```js
      this.querySelectorAll('.edit-list').forEach(btn => {
        btn.onclick = () => this.showEditDialog(btn.dataset.id, btn.dataset.name, btn.dataset.url);
      });
    } catch (e) { console.error(e); }
  }
```
NEW:
```js
      this.querySelectorAll('.edit-list').forEach(btn => {
        btn.onclick = () => this.showEditDialog(btn.dataset.id, btn.dataset.name, btn.dataset.url);
      });

      this._refreshAllDisabledWarning();
    } catch (e) { console.error(e); }
  }

  _refreshAllDisabledWarning() {
    const warn = this.querySelector('[data-testid="filters-all-disabled-warning"]');
    if (!warn) return;
    const boxes = this.querySelectorAll('#lists-body input[type=checkbox]');
    const allDisabled = boxes.length > 0 && Array.from(boxes).every(cb => !cb.checked);
    warn.style.display = allDisabled ? '' : 'none';
  }

  async enableRecommended() {
    const lists = this._lists || [];
    if (!lists.length) return;
    const pick = lists.find(l => l.name === 'AdGuard DNS filter') || lists[0];
    try {
      await api.put(`/api/lists/${pick.id}`, { enabled: true });
      await this.loadLists();
    } catch (e) { console.error(e); }
  }
```

- [ ] **Step 9: Filters — bind the CTA button in `connectedCallback`.** Replace lines 2794-2799.

OLD:
```js
      this.querySelector('#browse-registry').onclick = () => {
        const modal = document.createElement('registry-modal');
        modal.addEventListener('batch-added', () => this.loadLists());
        document.body.appendChild(modal);
        modal.open();
      };
```
NEW:
```js
      this.querySelector('#browse-registry').onclick = () => {
        const modal = document.createElement('registry-modal');
        modal.addEventListener('batch-added', () => this.loadLists());
        document.body.appendChild(modal);
        modal.open();
      };

      this.querySelector('#enable-recommended').onclick = () => this.enableRecommended();
```

- [ ] **Step 10: Rebuild the binary.**

```
pwd   # /home/nixos/Develop/claude/noadd
cargo build
```

- [ ] **Step 11: Run the onboarding scenarios, expect PASS.**

```
cd e2e && npx bddgen && npx playwright test --project=onboarding
```

Expect the dashboard/query-log empty-state and Filters all-disabled scenarios green.

- [ ] **Step 12: Commit.**

```
git add admin-ui/dist/index.html
git commit -S -m "feat(admin-ui): add onboarding empty states and all-disabled filter warning

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Full verification and branch finalization

**Files:** none (verification only).

- [ ] **Step 1: Rebuild from clean and run the whole Rust suite.**

```
pwd   # /home/nixos/Develop/claude/noadd
cargo build
cargo nextest run
cargo fmt --check
```

Expected: build OK, `0 failed`, fmt clean.

- [ ] **Step 2: Run the entire e2e suite (all projects).**

```
cd e2e && npx bddgen && npx playwright test
```

Expected: all `@auth`, `@app`, and `@onboarding` scenarios pass.

- [ ] **Step 3: Finalize the branch.** Use the superpowers:finishing-a-development-branch skill to choose merge/PR. CI must be green and the user must confirm before any merge. Per repo rules: squash-merge feature branches into `main` and delete the source branch; verify CI with `gh pr checks` first.

---

## Self-Review

**Spec coverage** (against the two committed feature files):
- "Setup rejects a mismatched password confirmation" — pre-existing, unchanged. ✓
- "Setup rejects a password shorter than the minimum length" — Task 3 (frontend block) + Task 1 (backend 400). ✓
- "First-run setup creates the admin password and signs in" + welcome — Task 3. ✓
- "Sign in fails / succeeds" — pre-existing. ✓
- "The next-step banner can be dismissed and stays dismissed" — Task 4 + Task 1 (settings key). ✓
- "Revoking all sessions…" — pre-existing. ✓
- onboarding "dashboard guides a new user" + "shows DNS address" — Task 5. ✓
- onboarding "query log explains no queries" — Task 5. ✓
- onboarding "next-step banner shown on fresh install" — Task 4. ✓
- onboarding "Filters warns when every list is disabled" — Task 5. ✓
- onboarding "next-step banner disappears once a real query is served" — Task 4 (poll) + Task 2 (dgram step). ✓

**Type/name consistency:** testids match across steps and UI — `setup-error`, `setup-welcome`, `next-step-banner`, `next-step-banner-dismiss`, `dashboard-empty-state`, `logs-empty-state`, `filters-all-disabled-warning`, `filters-enable-recommended`, `filter-list-toggle`, `filter-list-row`. Settings key `onboarding_banner_dismissed` is identical in backend (`get_settings`), banner read (`GET /api/settings`), and write (`PUT /api/settings`). Port `15102` is paired between `playwright.config.js` and `onboarding.steps.js`.

**Placeholders:** none — every code step shows full code.
