# Merge Filters Page + Domain Test Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Merge Filter Lists and Custom Rules into a single "Filters" page, and add a domain test feature.

**Architecture:** Add a `POST /api/filter/check` endpoint that wraps the existing `FilterEngine::check()`. Replace the two separate UI pages (`ListsPage`, `RulesPage`) with a single `FiltersPage` web component. Update sidebar navigation and router.

**Tech Stack:** Rust, axum, vanilla JS Web Components

---

### File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `src/admin/api.rs` | Modify | Add `/api/filter/check` endpoint and route |
| `admin-ui/dist/index.html` | Modify | Replace ListsPage+RulesPage with FiltersPage, update sidebar+router |
| `tests/admin_api_test.rs` | Modify | Add filter check endpoint tests |

---

### Task 1: Filter check API endpoint

**Files:**
- Modify: `src/admin/api.rs`

- [ ] **Step 1: Add the request/response types and handler**

In `src/admin/api.rs`, find the `// --- Upstream Health ---` comment (around line 613). Before it, add:

```rust
// --- Filter Check ---

#[derive(Deserialize)]
struct FilterCheckRequest {
    domain: String,
}

async fn filter_check(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<FilterCheckRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    require_auth(&state, &jar)?;
    let domain = body.domain.trim().trim_end_matches('.');
    let filter = state.filter.load();
    let result = filter.check(domain);
    match result {
        crate::filter::engine::FilterResult::Blocked { rule, list } => {
            Ok(Json(serde_json::json!({
                "action": "blocked",
                "rule": rule,
                "list": list,
            })))
        }
        crate::filter::engine::FilterResult::Allowed => {
            Ok(Json(serde_json::json!({
                "action": "allowed",
            })))
        }
    }
}
```

- [ ] **Step 2: Register the route**

In the `admin_router` function, add this line after the rules routes block (after `.route("/api/rules/blocklist/{id}", delete(delete_blocklist_rule))`):

```rust
        // Filter check
        .route("/api/filter/check", post(filter_check))
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check`
Expected: success

- [ ] **Step 4: Commit**

```bash
git add src/admin/api.rs
git commit -m "feat: add POST /api/filter/check endpoint"
```

---

### Task 2: Integration tests for filter check

**Files:**
- Modify: `tests/admin_api_test.rs`

- [ ] **Step 1: Add test for blocked domain**

The test `setup()` function creates an empty filter engine with no rules, so all domains are allowed. To test a blocked domain, we need to add a custom blocklist rule first via the API, then trigger a filter rebuild, then check. Add at the end of `tests/admin_api_test.rs`:

```rust
#[tokio::test]
async fn test_filter_check_allowed() {
    let (app, token) = setup().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/filter/check")
                .header("content-type", "application/json")
                .header("cookie", format!("session={token}"))
                .body(Body::from(r#"{"domain":"example.com"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["action"], "allowed");
}

#[tokio::test]
async fn test_filter_check_requires_auth() {
    let (app, _token) = setup().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/filter/check")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"domain":"example.com"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
```

- [ ] **Step 2: Run the tests**

Run: `cargo nextest run test_filter_check`
Expected: PASS (2 tests)

- [ ] **Step 3: Run full test suite**

Run: `cargo nextest run`
Expected: all tests PASS

- [ ] **Step 4: Commit**

```bash
git add tests/admin_api_test.rs
git commit -m "test: add filter check endpoint tests"
```

---

### Task 3: Merge UI into FiltersPage

**Files:**
- Modify: `admin-ui/dist/index.html`

This is the largest task. You are replacing two web components (`ListsPage` and `RulesPage`) with a single `FiltersPage`, updating the sidebar nav, and updating the router.

- [ ] **Step 1: Update sidebar navigation**

In the `AppShell` class `connectedCallback`, find these two lines:

```html
            <button class="nav-item" data-route="#lists">${icons.filter}<span>Filter Lists</span></button>
            <button class="nav-item" data-route="#rules">${icons.rules}<span>Custom Rules</span></button>
```

Replace them with a single line:

```html
            <button class="nav-item" data-route="#filters">${icons.filter}<span>Filters</span></button>
```

- [ ] **Step 2: Replace ListsPage and RulesPage with FiltersPage**

Delete everything from `class ListsPage extends HTMLElement {` through `customElements.define('rules-page', RulesPage);` (lines 1139-1300 approximately).

Replace with the new `FiltersPage` component:

```javascript
class FiltersPage extends HTMLElement {
  connectedCallback() {
    this.innerHTML = `
      <div class="page-header fade-in"><h2>Filters</h2><p>Domain test, filter lists, and custom rules</p></div>
      <div class="card fade-in">
        <div class="card-title">Domain Test</div>
        <p style="color:var(--text-secondary);font-size:0.85rem;margin-bottom:8px">Check whether a domain is allowed or blocked by your current filters.</p>
        <div class="input-row">
          <input type="text" id="test-domain" placeholder="ads.example.com">
          <button class="btn btn-primary btn-sm" id="test-btn">${icons.refresh} Test</button>
        </div>
        <div id="test-result" style="margin-top:12px"></div>
      </div>
      <div class="card fade-in" style="animation-delay:0.05s">
        <div class="card-title">Filter Lists</div>
        <div class="filters-row" style="margin-bottom:12px">
          <button class="btn btn-primary btn-sm" id="update-all">${icons.refresh} Update All</button>
        </div>
        <div class="table-wrap"><table><thead><tr>
          <th>Enabled</th><th>Name</th><th>Rules</th><th>Updated</th><th></th>
        </tr></thead><tbody id="lists-body"></tbody></table></div>
        <div class="card-title" style="margin-top:16px">Add Custom List</div>
        <div class="input-row">
          <input type="text" id="list-name" placeholder="List name">
          <input type="url" id="list-url" placeholder="https://...">
          <button class="btn btn-primary btn-sm" id="add-list">${icons.plus} Add</button>
        </div>
      </div>
      <div class="card fade-in" style="animation-delay:0.1s">
        <div class="card-title">Custom Rules</div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
          <div>
            <div class="card-title" style="font-size:0.85rem">Blocklist</div>
            <div class="input-row">
              <input type="text" id="block-rule" placeholder="||ads.example.com^">
              <button class="btn btn-primary btn-sm" id="add-block">${icons.plus}</button>
            </div>
            <div id="blocklist"></div>
          </div>
          <div>
            <div class="card-title" style="font-size:0.85rem">Allowlist</div>
            <div class="input-row">
              <input type="text" id="allow-rule" placeholder="@@||safe.example.com^">
              <button class="btn btn-primary btn-sm" id="add-allow">${icons.plus}</button>
            </div>
            <div id="allowlist"></div>
          </div>
        </div>
        <div style="margin-top:16px;padding:12px;background:var(--bg-secondary);border-radius:8px;font-size:0.8rem;color:var(--text-dim)">
          <strong style="color:var(--text-secondary)">Syntax Reference</strong>
          <table style="margin-top:8px;width:100%">
            <tr><td style="font-family:var(--font-mono);color:var(--text-secondary);padding:2px 12px 2px 0">||ads.example.com^</td><td>Block domain and all subdomains</td></tr>
            <tr><td style="font-family:var(--font-mono);color:var(--text-secondary);padding:2px 12px 2px 0">@@||safe.example.com^</td><td>Allow domain and all subdomains</td></tr>
            <tr><td style="font-family:var(--font-mono);color:var(--text-secondary);padding:2px 12px 2px 0">example.com</td><td>Block exact domain only</td></tr>
            <tr><td style="font-family:var(--font-mono);color:var(--text-secondary);padding:2px 12px 2px 0">0.0.0.0 example.com</td><td>Block exact domain (hosts format)</td></tr>
          </table>
        </div>
      </div>`;

    // --- Domain Test ---
    this.querySelector('#test-btn').onclick = () => this.testDomain();
    this.querySelector('#test-domain').onkeydown = (e) => { if (e.key === 'Enter') this.testDomain(); };

    // --- Filter Lists ---
    this.querySelector('#update-all').onclick = async () => {
      const btn = this.querySelector('#update-all');
      btn.disabled = true;
      btn.innerHTML = icons.refresh + ' Updating...';
      try { await api.post('/api/lists/update'); } catch (e) { console.error(e); }
      btn.disabled = false;
      btn.innerHTML = icons.refresh + ' Update All';
      this.loadLists();
    };

    this.querySelector('#add-list').onclick = async () => {
      const name = this.querySelector('#list-name').value.trim();
      const url = this.querySelector('#list-url').value.trim();
      if (!name || !url) return;
      await api.post('/api/lists', { name, url });
      this.querySelector('#list-name').value = '';
      this.querySelector('#list-url').value = '';
      this.loadLists();
    };

    // --- Custom Rules ---
    this.querySelector('#add-block').onclick = async () => {
      const v = this.querySelector('#block-rule').value.trim();
      if (!v) return;
      await api.post('/api/rules/blocklist', { rule: v });
      this.querySelector('#block-rule').value = '';
      this.loadRules();
    };
    this.querySelector('#block-rule').onkeydown = (e) => { if (e.key === 'Enter') this.querySelector('#add-block').click(); };

    this.querySelector('#add-allow').onclick = async () => {
      const v = this.querySelector('#allow-rule').value.trim();
      if (!v) return;
      await api.post('/api/rules/allowlist', { rule: v });
      this.querySelector('#allow-rule').value = '';
      this.loadRules();
    };
    this.querySelector('#allow-rule').onkeydown = (e) => { if (e.key === 'Enter') this.querySelector('#add-allow').click(); };

    this.loadLists();
    this.loadRules();
  }

  async testDomain() {
    const domain = this.querySelector('#test-domain').value.trim();
    if (!domain) return;
    const el = this.querySelector('#test-result');
    try {
      const res = await api.post('/api/filter/check', { domain });
      if (res.action === 'blocked') {
        el.innerHTML = `<span class="badge badge-blocked">Blocked</span>
          <span style="color:var(--text-secondary);font-size:0.85rem;margin-left:8px">
            Rule: <code style="color:var(--text-primary)">${esc(res.rule)}</code>
            &middot; List: <code style="color:var(--text-primary)">${esc(res.list)}</code>
          </span>`;
      } else {
        el.innerHTML = '<span class="badge badge-allowed">Allowed</span>';
      }
    } catch (e) {
      el.innerHTML = '<span style="color:var(--red)">Error checking domain</span>';
    }
  }

  async loadLists() {
    try {
      const lists = await api.get('/api/lists');
      const body = this.querySelector('#lists-body');
      body.innerHTML = lists.map(l => `<tr>
        <td>
          <label class="toggle">
            <input type="checkbox" ${l.enabled ? 'checked' : ''} data-id="${l.id}">
            <div class="toggle-track"></div>
            <div class="toggle-thumb"></div>
          </label>
        </td>
        <td style="color:var(--text-primary)">${esc(l.name)}</td>
        <td>${formatNum(l.rule_count)}</td>
        <td>${l.last_updated ? timeAgo(l.last_updated) : 'never'}</td>
        <td><button class="btn btn-danger btn-sm del-list" data-id="${l.id}">${icons.trash} Delete</button></td>
      </tr>`).join('');

      body.querySelectorAll('input[type=checkbox]').forEach(cb => {
        cb.onchange = async () => {
          await api.put(`/api/lists/${cb.dataset.id}`, { enabled: cb.checked });
        };
      });

      body.querySelectorAll('.del-list').forEach(btn => {
        btn.onclick = async () => {
          if (confirm('Delete this list?')) {
            await api.del(`/api/lists/${btn.dataset.id}`);
            this.loadLists();
          }
        };
      });
    } catch (e) { console.error(e); }
  }

  async loadRules() {
    try {
      const [block, allow] = await Promise.all([
        api.get('/api/rules/blocklist'),
        api.get('/api/rules/allowlist'),
      ]);
      this.renderRules('#blocklist', block, 'blocklist');
      this.renderRules('#allowlist', allow, 'allowlist');
    } catch (e) { console.error(e); }
  }

  renderRules(sel, rules, type) {
    const el = this.querySelector(sel);
    if (!rules.length) { el.innerHTML = '<p style="color:var(--text-dim);font-size:0.85rem">No rules</p>'; return; }
    let html = '<table><tbody>';
    for (const r of rules) {
      html += `<tr>
        <td style="color:var(--text-primary)">${esc(r.rule)}</td>
        <td style="width:40px"><button class="btn btn-danger btn-sm del-rule" data-id="${r.id}" data-type="${type}">${icons.trash}</button></td>
      </tr>`;
    }
    html += '</tbody></table>';
    el.innerHTML = html;
    el.querySelectorAll('.del-rule').forEach(btn => {
      btn.onclick = async () => {
        await api.del(`/api/rules/${btn.dataset.type}/${btn.dataset.id}`);
        this.loadRules();
      };
    });
  }
}
customElements.define('filters-page', FiltersPage);
```

- [ ] **Step 3: Update router registrations**

Find the router block:

```javascript
router
  .on('#dashboard', () => setPage('dashboard-page'))
  .on('#logs', () => setPage('logs-page'))
  .on('#lists', () => setPage('lists-page'))
  .on('#rules', () => setPage('rules-page'))
  .on('#settings', () => setPage('settings-page'));
```

Replace with:

```javascript
router
  .on('#dashboard', () => setPage('dashboard-page'))
  .on('#logs', () => setPage('logs-page'))
  .on('#filters', () => setPage('filters-page'))
  .on('#settings', () => setPage('settings-page'));
```

- [ ] **Step 4: Verify it compiles**

Run: `cargo check`
Expected: success (the HTML is bundled via `include_dir!`)

- [ ] **Step 5: Commit**

```bash
git add admin-ui/dist/index.html
git commit -m "feat: merge lists and rules into unified Filters page with domain test"
```

---

### Task 4: Final verification

- [ ] **Step 1: Run full test suite**

Run: `cargo nextest run`
Expected: all tests PASS

- [ ] **Step 2: Run clippy**

Run: `cargo clippy -- -D warnings`
Expected: no warnings

- [ ] **Step 3: Fix any issues found**

Address any compilation errors, test failures, or clippy warnings.

- [ ] **Step 4: Final commit if any fixes were needed**

```bash
git add -u
git commit -m "fix: address clippy warnings"
```
