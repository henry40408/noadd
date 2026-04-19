# Browse Filter Lists Registry — Pick from AdGuard HostlistsRegistry

## Overview

Today users can only add filter lists by typing a URL manually on the Filters page. This spec adds a "Browse Registry" modal that lets users pick filter lists from the AdGuard HostlistsRegistry (`https://adguardteam.github.io/HostlistsRegistry/assets/filters.json`), multi-select, and batch-add them.

Because rebuilding the filter engine takes ~70 s on a Raspberry Pi, this spec also introduces a detached, serialised rebuild pattern with an observable status endpoint and a global "Rebuilding filter engine…" banner, so UI flows never block on rebuild.

This is Task B on branch `feat/browse-filter-lists-registry`. Task A (trim `DEFAULT_LISTS` to a two-entry seed) is already committed at `61add80` on the same branch.

## Non-Goals

- No scheduled background refresh of the registry cache; runtime fetch with a 1-hour in-memory TTL is sufficient.
- No change to `/api/lists` (single-URL manual add remains).
- No new CLI flags, no new DB tables.
- No progress stream / SSE / WebSocket for batch downloads; the batch endpoint returns once all downloads finish, and rebuild is detached.
- No UI to edit or favourite registry entries; the modal is purely a picker.

## Architecture

Three new units, plus a cross-cutting rebuild coordinator:

```
┌──────────────────────────────┐   GET  /api/registry/filters       ┌────────────────────┐
│ admin-ui: <registry-modal>   │◄──────────────────────────────────►│ RegistryClient     │
│                              │   POST /api/lists/batch            │ (in-memory 1h TTL) │
│ admin-ui: <rebuild-banner>   │   GET  /api/filter/rebuild-status  └──────────┬─────────┘
└──────────────────────────────┘                                               │
                                                                               ▼ HTTPS
                                                         adguardteam.github.io/HostlistsRegistry

┌─────────────────────────────────────────────────────────────────────────────────────────┐
│  POST /api/lists/batch handler                                                          │
│    1. for each item, concurrency=4: fetch → db.add_filter_list → set_content → stats    │
│    2. rebuild.spawn(manager)    ← returns immediately (detached)                        │
│    3. respond { added: [...], failed: [...] }                                           │
└─────────────────────────────────────────────────────────────────────────────────────────┘

         RebuildCoordinator (Arc<_> in AppState)
         ├── Mutex<()>  — serialises rebuilds
         └── RebuildState { rebuilding, started_at, last_completed_at, last_duration_ms }

  GET /api/filter/rebuild-status  reads RebuildState and returns JSON snapshot.
```

## Backend — Registry Client

New module `src/registry.rs`:

```rust
pub struct RegistryClient {
    http: reqwest::Client,
    cache: tokio::sync::RwLock<Option<CachedEntry>>,
    ttl: std::time::Duration,
    url: String,
}

struct CachedEntry {
    fetched_at: std::time::Instant,
    data: RegistryData,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RegistryData {
    pub filters: Vec<RegistryFilter>,
    pub groups: Vec<RegistryGroup>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RegistryFilter {
    pub filter_id: i64,
    pub name: String,
    pub description: String,
    pub homepage: Option<String>,
    pub download_url: String,
    pub group_id: i64,
    pub deprecated: bool,
    pub time_updated: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RegistryGroup {
    pub group_id: i64,
    pub group_name: String,
}
```

Behaviour:

- `RegistryClient::new(url, ttl)` — constructor; no network call.
- `pub async fn list(&self) -> Result<RegistryData, RegistryError>`:
  - Fast path (read lock): if `cache` is `Some` and `Instant::now() - fetched_at < ttl`, clone and return.
  - Slow path (write lock): fetch `filters.json` with 30 s timeout, parse into `RegistryData` keeping only the fields above, store, return clone.
- Upstream JSON uses camelCase (`filterId`, `downloadUrl`, etc.); `serde(rename_all = "camelCase")` handles mapping. `tags`, `languages`, `expires`, `version`, `subscriptionUrl`, `filterKey`, `timeAdded`, `displayNumber` are ignored.
- Default URL: `https://adguardteam.github.io/HostlistsRegistry/assets/filters.json`. Overridable via the constructor (used by tests).
- Default TTL: 1 hour.

Error type:

```rust
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("parse error: {0}")]
    Parse(#[from] serde_json::Error),
}
```

Instantiation in `main.rs`: `let registry = Arc::new(RegistryClient::new(default_url, Duration::from_secs(3600)));` placed into `AppState`.

## Backend — Registry Endpoint

`GET /api/registry/filters`:

- `require_auth(&state, &jar)?`
- `state.registry.list().await` → 200 with the `RegistryData` JSON.
- On `RegistryError` → 502 Bad Gateway (upstream failure) with JSON `{ "error": "<msg>" }`.

No query params. Filtering happens client-side; payload is small (<200 KB).

## Backend — Rebuild Coordinator

New module `src/filter/rebuild.rs`:

```rust
pub struct RebuildCoordinator {
    lock: tokio::sync::Mutex<()>,
    state: Arc<RebuildState>,
}

pub struct RebuildState {
    pub rebuilding:        std::sync::atomic::AtomicBool,
    pub started_at:        std::sync::atomic::AtomicI64,
    pub last_completed_at: std::sync::atomic::AtomicI64,
    pub last_duration_ms:  std::sync::atomic::AtomicU64,
}
```

- `pub fn new() -> Arc<Self>` — zero-init state.
- `pub fn state(&self) -> Arc<RebuildState>` — exposed to the status endpoint.
- `pub fn spawn(self: Arc<Self>, manager: Arc<ListManager>)` — fires `tokio::spawn`:
  1. `let _guard = self.lock.lock().await;` (serialises; next rebuild queues)
  2. `state.started_at = now_unix(); state.rebuilding = true;`
  3. `let t = Instant::now(); let result = manager.rebuild_filter().await;`
  4. Always: `state.last_duration_ms = t.elapsed().as_millis() as u64; state.last_completed_at = now_unix(); state.rebuilding = false;`
  5. Log error if `result` is `Err`.

`ListManager` is already `Clone`-able via `db` and `filter` fields, but it's not wrapped in `Arc` today; wrap it (`Arc<ListManager>`) and store a single shared instance in `AppState` to avoid re-constructing per request (three call sites do this today).

### Rebuild Call-Site Changes

| Call site | File:line (current) | New behaviour |
|-----------|---------------------|---------------|
| Startup | `main.rs:65` | **Unchanged**: await `manager.rebuild_filter()` synchronously before listeners start. |
| `update_list` | `api.rs:481-485` | Replace `ListManager::new(...).rebuild_filter().await` with `state.rebuild.clone().spawn(state.list_manager.clone())`. |
| `delete_list` | `api.rs:559-563` | Same. |
| `trigger_list_update` | `api.rs:579-…` | Split `ListManager::update_all_lists` into a download-only phase and a separate rebuild: the handler `await`s `update_all_lists_no_rebuild` (downloads sequentially with existing per-list logging) and then calls `state.rebuild.clone().spawn(state.list_manager.clone())`. Response returns once downloads finish; banner reflects the subsequent rebuild. |
| Batch add (new) | — | Same detached spawn after downloads. |

Returning from these handlers no longer implies the filter engine reflects the change; banner + status endpoint inform the user.

## Backend — Rebuild Status Endpoint

`GET /api/filter/rebuild-status`:

- `require_auth(&state, &jar)?`
- Reads `state.rebuild.state()` atomics (relaxed ordering), returns:

```json
{
  "rebuilding": false,
  "started_at": 1713546000,
  "last_completed_at": 1713546072,
  "last_duration_ms": 72104
}
```

`0` means "never". Atomics keep the endpoint lock-free and cheap.

## Backend — Batch Add Endpoint

`POST /api/lists/batch`:

Request:

```json
{ "items": [{ "name": "AdGuard DNS filter", "url": "https://.../filter_1.txt" }, ...] }
```

Handler (`admin/api.rs`):

1. `require_auth`.
2. Validate `items` non-empty and `<= 50` entries (cap to prevent abuse).
3. Build a `reqwest::Client` with 60 s timeout, matching `download_and_update_list`.
4. `futures::stream::iter(items).map(fetch_and_store).buffer_unordered(4).collect::<Vec<_>>()`.
5. Per-item `fetch_and_store`:
   - Normalise URL (trim).
   - `db.add_filter_list(name, url, true)` — if this returns a unique-constraint error (URL already present) or other DB error, wrap as failed entry.
   - Otherwise, `GET url`, read body. On HTTP error / timeout, **roll back this row** (`db.delete_filter_list(id)`) and mark failed.
   - On success: `set_filter_list_content(id, &content)`, compute `rule_count = parse_list(&content).len()`, `update_filter_list_stats(id, now_unix, rule_count)`.
   - Return `Ok(AddedEntry { id, name, url, rule_count })` or `Err(FailedEntry { name, url, error: String })`.
6. After all items settle, `state.rebuild.clone().spawn(state.list_manager.clone())`.
7. Respond 200:

```json
{
  "added":  [{ "id": 7, "name": "...", "url": "...", "rule_count": 12345 }],
  "failed": [{ "name": "...", "url": "...", "error": "timeout" }]
}
```

Error modes:

- Unauthenticated → 401.
- Empty items / > 50 items → 400.
- All items failed is still 200 with empty `added` and populated `failed`; client decides how to present.

## Frontend — Registry Modal

`admin-ui/dist/index.html`: new `<registry-modal>` web component, opened by a new `Browse Registry` button on the Filter Lists card (next to `Update All`).

Data flow on open:

1. Show spinner.
2. `Promise.all([api.get('/api/registry/filters'), api.get('/api/lists')])`.
3. Build `existingUrls = new Set(lists.map(l => l.url))` and `groupsById = Map(groups)`.
4. Render rows; for each filter set `alreadyAdded = existingUrls.has(filter.download_url)`.

Controls:

- Search box — client-side filter on `name` + `description`, case-insensitive.
- Group dropdown — `All | General | Other | Regional | Security` (from the `groups` response).
- `Show deprecated` checkbox — default off; when off, `filter.deprecated === true` rows hidden.

Row layout (concrete styling handled by `frontend-design` skill during implementation):

- Checkbox (disabled + `Added` pill when `alreadyAdded`).
- Name, group badge, description (truncated with ellipsis / expandable), `homepage` link opens new tab with `rel="noopener noreferrer"`.

Footer:

- `N selected` counter.
- `Add Selected` button (disabled when `N === 0`) — on click: disable, show spinner, `POST /api/lists/batch { items }`.
  - On all-success response: close modal, call `this.closest('filters-page').loadLists()`.
  - On any failed: keep modal open, render a summary line per failure, replace `Cancel` with `Close`, still call `loadLists()`.
- `Cancel` / `Close` — dismiss modal, clear selection.

Caching: the component holds the registry data in a property after first load; reopening the modal uses the cached data without refetching. A `Retry` button on the error state triggers a fresh fetch.

## Frontend — Global Rebuild Banner

`admin-ui/dist/index.html`: new `<rebuild-banner>` mounted in the app shell, visible on every page.

- On `connectedCallback`: `setInterval(poll, 2000)`, plus immediate `poll()`.
- `poll()` calls `GET /api/filter/rebuild-status`; silently ignores 401 (user logged out) and network errors.
- State transitions:
  - `rebuilding === true` → show banner `Rebuilding filter engine… (Xs elapsed)` with spinner; `X = now - started_at`.
  - `true → false` transition → briefly show `Filter engine updated in Ys` for 3 s, then hide.
  - Steady `false` → hidden (display: none so it doesn't reserve space).
- `disconnectedCallback` clears the interval.

## Testing

**Unit / integration tests (new files):**

- `tests/registry_test.rs`:
  - `fetch_populates_cache`: first call hits mocked upstream, second call within TTL does not.
  - `cache_expires_after_ttl`: force TTL 0, two calls hit upstream twice.
  - `parse_ignores_unknown_fields`: snapshot of a representative `filters.json` parses without error, preserving the seven fields we care about.
  - `upstream_error_surfaces`: mock returns 500, client returns `RegistryError::Http`.
- `tests/rebuild_coordinator_test.rs`:
  - `rebuild_state_transitions`: start false → spawn → true → done → false with non-zero `last_duration_ms`.
  - `concurrent_spawns_serialised`: fire two `spawn` calls quickly; second runs strictly after first (observe via timestamps).
  - `failed_rebuild_clears_flag`: a rebuild that returns `Err` still resets `rebuilding=false`.

**Extensions to `tests/admin_api_test.rs`:**

- `registry_filters_unauthenticated_returns_401`.
- `registry_filters_returns_cached_data` (mocked upstream).
- `batch_add_all_success` (mocked upstream for two URLs).
- `batch_add_partial_failure` (one URL returns 404; that item is absent from DB and listed in `failed`).
- `batch_add_rejects_empty_and_oversized` (0 items → 400; > 50 items → 400).
- `batch_add_unauthenticated_returns_401`.
- `rebuild_status_unauthenticated_returns_401`.
- `rebuild_status_reflects_in_flight_rebuild` (trigger a rebuild via batch endpoint, poll status until `rebuilding=false`).

**Test-helper impact:**

Some existing tests in `admin_api_test.rs` assert that after `PUT /api/lists/:id` or `DELETE /api/lists/:id` the filter engine reflects the change synchronously. With detached rebuild, those must either:

1. Poll `/api/filter/rebuild-status` until `rebuilding=false && last_completed_at > before_call`, or
2. Call `state.list_manager.rebuild_filter().await` directly in test setup.

A small helper `async fn wait_for_rebuild(client, before: i64)` is added to the test harness for option 1.

## Risks and Open Questions

- **Registry JSON schema drift**: AdGuard could rename fields. Mitigation: `#[serde(deny_unknown_fields = false)]` (the default) keeps ignoring extras; missing required fields surface as parse errors and the endpoint returns 502. Snapshot test guards the fields we depend on.
- **Upstream mirror gone**: `downloadUrl` points at `adguardteam.github.io`. If ever removed, saved lists 404 on update. Same risk as today's one-entry seed. Not addressed here.
- **Long in-flight rebuild + shutdown**: detached `tokio::spawn` runs until the runtime is dropped. Graceful shutdown already cancels the runtime; a half-completed rebuild is dropped safely because `ArcSwap::store` only happens at the end.
- **Atomics and observability**: `Relaxed` ordering is fine because all four fields are only inspected by the status endpoint, which tolerates a brief window of inconsistency.
- **UI accessibility**: modal + banner must be keyboard dismissable and screen-reader labelled. Handled during `frontend-design` skill work.

## Rollout

No migration. New endpoints are additive. Existing `POST /api/lists` still works. Existing DBs are unchanged. Users who never open the modal see exactly today's behaviour, except that list edits (toggle / delete / manual update) now return instantly and the banner appears while the engine rebuilds in the background — a pure UX improvement.
