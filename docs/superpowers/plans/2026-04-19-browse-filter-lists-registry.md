# Browse Filter Lists Registry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a modal that browses AdGuard's HostlistsRegistry and batch-adds selected lists, underpinned by a detached + serialised rebuild coordinator and a global "rebuilding" banner so the UI never blocks on the ~70 s filter engine rebuild.

**Architecture:** Backend gains `RegistryClient` (in-memory 1h TTL) and `RebuildCoordinator` (tokio mutex + atomics). Three new endpoints: `GET /api/registry/filters`, `POST /api/lists/batch`, `GET /api/filter/rebuild-status`. Existing list-mutation endpoints switch to detached rebuild via the coordinator. Frontend adds two web components: a global `<rebuild-banner>` that polls the status endpoint, and a `<registry-modal>` opened from the Filter Lists card.

**Tech Stack:** Rust 2024, axum 0.8, tokio 1 (`sync`, `rt-multi-thread`), reqwest 0.13, serde/serde_json, thiserror; vanilla-JS web components in `admin-ui/dist/index.html`.

**Spec:** `docs/superpowers/specs/2026-04-19-browse-filter-lists-registry-design.md`

---

## File Structure

**Create:**
- `src/filter/rebuild.rs` — `RebuildCoordinator`, `RebuildState`, `now_unix()` helper.
- `src/registry.rs` — `RegistryClient`, `RegistryData`, `RegistryFilter`, `RegistryGroup`, `RegistryError`.
- `tests/rebuild_coordinator_test.rs` — unit tests for the coordinator.
- `tests/registry_test.rs` — unit tests for the registry client (with a real tiny axum fake upstream).
- `tests/test_support/mod.rs` (if not present, otherwise extend) — `spawn_fake_http_server` helper reused by registry + batch tests.

**Modify:**
- `Cargo.toml` — no new dependencies (we use `tokio::task::JoinSet` + `tokio::sync::Semaphore` for concurrency; fake upstreams are built with axum which is already a dep).
- `src/lib.rs` — add `pub mod registry;`.
- `src/filter/mod.rs` — add `pub mod rebuild;`.
- `src/filter/lists.rs` — split `update_all_lists` into `update_all_lists_no_rebuild` + keep the old name as a thin wrapper for the background scheduler, wrap `ListManager` in `Arc` at usage sites.
- `src/admin/api.rs` — extend `AppState` with `list_manager`, `rebuild`, `registry`; register three new routes; switch `update_list`, `delete_list`, `trigger_list_update` to use the coordinator; add `batch_add_lists`, `get_registry_filters`, `get_rebuild_status` handlers.
- `src/main.rs` — construct the new `AppState` fields and share them.
- `admin-ui/dist/index.html` — add `<rebuild-banner>`, `<registry-modal>`, and the `Browse Registry` button on the Filter Lists card.
- `tests/admin_api_test.rs` — update `setup()` for the new `AppState` fields; add tests for the new endpoints; add `wait_for_rebuild` helper.
- `tests/filter_lists_test.rs` — add a test for `update_all_lists_no_rebuild`.

---

### Task 1: RebuildCoordinator module (unit-tested)

**Files:**
- Create: `src/filter/rebuild.rs`
- Create: `tests/rebuild_coordinator_test.rs`
- Modify: `src/filter/mod.rs`

- [ ] **Step 1: Expose the new module**

Add a line to `src/filter/mod.rs`:

```rust
pub mod rebuild;
```

- [ ] **Step 2: Write the failing tests**

Create `tests/rebuild_coordinator_test.rs`:

```rust
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use noadd::filter::rebuild::RebuildCoordinator;

#[tokio::test]
async fn rebuild_state_transitions() {
    let coord = RebuildCoordinator::new();
    let state = coord.state();
    assert!(!state.rebuilding.load(Ordering::Relaxed));
    assert_eq!(state.started_at.load(Ordering::Relaxed), 0);
    assert_eq!(state.last_completed_at.load(Ordering::Relaxed), 0);

    let handle = coord
        .clone()
        .spawn_raw(|| async {
            tokio::time::sleep(Duration::from_millis(30)).await;
            Ok::<_, std::io::Error>(())
        });

    // Give the spawn a tick to start.
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert!(state.rebuilding.load(Ordering::Relaxed));
    assert!(state.started_at.load(Ordering::Relaxed) > 0);

    handle.await.unwrap();
    assert!(!state.rebuilding.load(Ordering::Relaxed));
    assert!(state.last_completed_at.load(Ordering::Relaxed) > 0);
    assert!(state.last_duration_ms.load(Ordering::Relaxed) >= 30);
}

#[tokio::test]
async fn concurrent_spawns_serialised() {
    let coord = RebuildCoordinator::new();
    let h1 = coord
        .clone()
        .spawn_raw(|| async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            Ok::<_, std::io::Error>(())
        });
    let h2 = coord
        .clone()
        .spawn_raw(|| async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            Ok::<_, std::io::Error>(())
        });
    let t = std::time::Instant::now();
    h1.await.unwrap();
    h2.await.unwrap();
    assert!(t.elapsed() >= Duration::from_millis(95));
}

#[tokio::test]
async fn failed_rebuild_clears_flag() {
    let coord = RebuildCoordinator::new();
    let state = coord.state();
    coord
        .clone()
        .spawn_raw(|| async {
            Err::<(), _>(std::io::Error::other("boom"))
        })
        .await
        .unwrap();
    assert!(!state.rebuilding.load(Ordering::Relaxed));
    assert!(state.last_completed_at.load(Ordering::Relaxed) > 0);
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo nextest run --test rebuild_coordinator_test`
Expected: FAIL (module does not exist).

- [ ] **Step 4: Implement the coordinator**

Create `src/filter/rebuild.rs`:

```rust
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::Mutex;
use tokio::task::JoinHandle;

pub struct RebuildCoordinator {
    lock: Mutex<()>,
    state: Arc<RebuildState>,
}

#[derive(Default)]
pub struct RebuildState {
    pub rebuilding: AtomicBool,
    pub started_at: AtomicI64,
    pub last_completed_at: AtomicI64,
    pub last_duration_ms: AtomicU64,
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl RebuildCoordinator {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            lock: Mutex::new(()),
            state: Arc::new(RebuildState::default()),
        })
    }

    pub fn state(&self) -> Arc<RebuildState> {
        self.state.clone()
    }

    /// Spawn a rebuild-like async task, serialised against any other in-flight
    /// spawn. The closure returns a `Result`; errors are logged but still
    /// reset the state flags.
    pub fn spawn_raw<F, Fut, E>(self: Arc<Self>, f: F) -> JoinHandle<()>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), E>> + Send,
        E: std::fmt::Display + Send + 'static,
    {
        tokio::spawn(async move {
            let _guard = self.lock.lock().await;
            self.state.started_at.store(now_unix(), Ordering::Relaxed);
            self.state.rebuilding.store(true, Ordering::Relaxed);
            let t = Instant::now();
            let result = f().await;
            let duration_ms = t.elapsed().as_millis() as u64;
            self.state
                .last_duration_ms
                .store(duration_ms, Ordering::Relaxed);
            self.state
                .last_completed_at
                .store(now_unix(), Ordering::Relaxed);
            self.state.rebuilding.store(false, Ordering::Relaxed);
            if let Err(e) = result {
                tracing::error!(error = %e, "rebuild task failed");
            }
        })
    }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo nextest run --test rebuild_coordinator_test`
Expected: PASS (3 tests).

- [ ] **Step 6: Format + clippy + commit**

Run:

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
```

Expected: no warnings.

Commit:

```bash
git add src/filter/rebuild.rs src/filter/mod.rs tests/rebuild_coordinator_test.rs
git commit -S -m "feat(filter): add RebuildCoordinator for detached, serialised rebuilds"
```

---

### Task 2: Share `ListManager` via `Arc`, extend `AppState`

**Files:**
- Modify: `src/admin/api.rs:26-43` (AppState)
- Modify: `src/main.rs:63-65`, `152-170` (construct Arc<ListManager> + background scheduler)
- Modify: `tests/admin_api_test.rs:20-56` (setup helper)

This task is a pure refactor with no behaviour change. The shared `ListManager` is needed by the rebuild coordinator and the batch endpoint.

- [ ] **Step 1: Update `AppState`**

In `src/admin/api.rs`, change the struct:

```rust
use crate::filter::lists::ListManager;
use crate::filter::rebuild::RebuildCoordinator;

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub sessions: SessionStore,
    pub filter: Arc<ArcSwap<FilterEngine>>,
    pub cache: DnsCache,
    pub rate_limiter: Arc<RateLimiter>,
    pub forwarder: Arc<UpstreamForwarder>,
    pub handler: Arc<DnsHandler>,
    pub server_info: ServerInfo,
    pub list_manager: Arc<ListManager>,
    pub rebuild: Arc<RebuildCoordinator>,
}
```

(`registry` is added in Task 6.)

- [ ] **Step 2: Update `main.rs`**

Change the seed/rebuild block (lines 62-65) to:

```rust
// 5. Seed default lists + rebuild filter
let list_manager = Arc::new(ListManager::new(db.clone(), filter.clone()));
list_manager.seed_default_lists().await?;
list_manager.rebuild_filter().await?;
let rebuild = noadd::filter::rebuild::RebuildCoordinator::new();
```

Change the `admin_router` call (lines 137-146) to include the new fields:

```rust
let admin_routes = admin_router(AppState {
    db: db.clone(),
    sessions: session_store,
    filter: filter.clone(),
    cache: cache.clone(),
    rate_limiter,
    forwarder: forwarder.clone(),
    handler: handler.clone(),
    server_info,
    list_manager: list_manager.clone(),
    rebuild: rebuild.clone(),
});
```

Change the background scheduler (lines 152-170) to reuse `list_manager` and `rebuild`:

```rust
// 15. Background list update scheduler (every 24h)
let update_manager = list_manager.clone();
let update_rebuild = rebuild.clone();
let mut shutdown_rx = shutdown_tx.subscribe();
tokio::spawn(async move {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(86400));
    interval.tick().await; // skip first immediate tick
    loop {
        tokio::select! {
            _ = interval.tick() => {
                if let Err(e) = update_manager.update_all_lists_no_rebuild().await {
                    tracing::error!(error = %e, "failed to update filter lists");
                }
                let mgr = update_manager.clone();
                update_rebuild.clone().spawn_raw(move || async move {
                    mgr.rebuild_filter().await
                });
            }
            _ = shutdown_rx.recv() => break,
        }
    }
});
```

Note: `update_all_lists_no_rebuild` is added in Task 3.

- [ ] **Step 3: Update test setup**

In `tests/admin_api_test.rs` `setup()`, after constructing `filter`, add:

```rust
let list_manager = Arc::new(noadd::filter::lists::ListManager::new(db.clone(), filter.clone()));
let rebuild = noadd::filter::rebuild::RebuildCoordinator::new();
```

And extend the `AppState` literal:

```rust
let router = admin_router(AppState {
    db,
    sessions,
    filter,
    cache,
    rate_limiter,
    forwarder,
    handler,
    server_info: ServerInfo { /* unchanged */ },
    list_manager,
    rebuild,
});
```

- [ ] **Step 4: Run the existing test suite**

Run: `cargo nextest run`
Expected: PASS (all 157 tests). `update_all_lists_no_rebuild` compile error is expected — it is added in Task 3.

If the compile error appears, proceed to Task 3 before running nextest; otherwise do not commit yet (this task chains into Task 3).

- [ ] **Step 5: Stage changes (do NOT commit yet)**

Stage but do not commit. Task 3 adds `update_all_lists_no_rebuild` and the commit covers both:

```bash
git add src/admin/api.rs src/main.rs tests/admin_api_test.rs
```

---

### Task 3: Split `update_all_lists`

**Files:**
- Modify: `src/filter/lists.rs:145-165`
- Modify: `tests/filter_lists_test.rs` (add coverage)

- [ ] **Step 1: Write the failing test**

Append to `tests/filter_lists_test.rs`:

```rust
#[tokio::test]
async fn test_update_all_lists_no_rebuild_does_not_rebuild() {
    let (db, manager, filter) = setup_with_filter().await;

    // Insert a custom block rule so rebuild would notice it.
    db.add_custom_rule("||ads.example.com^", "block")
        .await
        .unwrap();

    // Sanity: before any rebuild, engine does not know the rule.
    assert!(matches!(
        filter.load().check("ads.example.com"),
        noadd::filter::engine::FilterResult::Allowed { .. }
    ));

    // update_all_lists_no_rebuild must leave engine untouched.
    manager.update_all_lists_no_rebuild().await.unwrap();
    assert!(matches!(
        filter.load().check("ads.example.com"),
        noadd::filter::engine::FilterResult::Allowed { .. }
    ));

    // A direct rebuild_filter call still works.
    manager.rebuild_filter().await.unwrap();
    assert!(matches!(
        filter.load().check("ads.example.com"),
        noadd::filter::engine::FilterResult::Blocked { .. }
    ));
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo nextest run --test filter_lists_test test_update_all_lists_no_rebuild_does_not_rebuild`
Expected: FAIL (method not found).

- [ ] **Step 3: Split `update_all_lists`**

In `src/filter/lists.rs`, replace the existing `update_all_lists`:

```rust
/// Download all enabled lists. Does **not** rebuild the filter engine.
pub async fn update_all_lists_no_rebuild(&self) -> Result<(), ListError> {
    let lists = self.db.get_filter_lists().await?;

    for list in &lists {
        if !list.enabled {
            continue;
        }
        match self.download_and_update_list(list.id).await {
            Ok(rule_count) => {
                tracing::info!(list_id = list.id, name = %list.name, rule_count, "updated filter list");
            }
            Err(e) => {
                tracing::error!(list_id = list.id, name = %list.name, error = %e, "failed to download list");
            }
        }
    }

    Ok(())
}

/// Download all enabled lists and rebuild the filter.
pub async fn update_all_lists(&self) -> Result<(), ListError> {
    self.update_all_lists_no_rebuild().await?;
    self.rebuild_filter().await?;
    Ok(())
}
```

- [ ] **Step 4: Run the filter_lists_test suite**

Run: `cargo nextest run --test filter_lists_test`
Expected: PASS (all tests including the new one).

- [ ] **Step 5: Run the full suite**

Run: `cargo nextest run`
Expected: PASS (all previously passing tests still pass).

- [ ] **Step 6: Format + clippy + commit**

Run:

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
```

Expected: no warnings.

Commit (includes Task 2's staged changes):

```bash
git add src/filter/lists.rs tests/filter_lists_test.rs
git commit -S -m "refactor(filter): split update_all_lists and share ListManager via Arc"
```

---

### Task 4: Detached rebuild at existing list-mutation endpoints

**Files:**
- Modify: `src/admin/api.rs:457-488` (`update_list`), `546-566` (`delete_list`), `573-588` (`trigger_list_update`)

- [ ] **Step 1: Update `update_list`**

Replace the rebuild block (lines 481-485):

```rust
let manager = state.list_manager.clone();
state.rebuild.clone().spawn_raw(move || async move {
    manager.rebuild_filter().await
});

Ok(StatusCode::OK)
```

Remove the now-unused local `ListManager::new(...)` construction at line 481.

- [ ] **Step 2: Update `delete_list`**

Replace the rebuild block (lines 559-563) with the same detached-spawn pattern as above, and remove the local `ListManager::new(...)` at line 559.

- [ ] **Step 3: Update `trigger_list_update`**

Replace the whole body after `require_auth`:

```rust
state
    .list_manager
    .update_all_lists_no_rebuild()
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

let manager = state.list_manager.clone();
state.rebuild.clone().spawn_raw(move || async move {
    manager.rebuild_filter().await
});

Ok(Json(ListUpdateResponse {
    message: "All lists downloaded; rebuild in progress".to_string(),
}))
```

- [ ] **Step 4: Add `wait_for_rebuild` helper in `tests/admin_api_test.rs`**

Add near the top of the file (after `setup()`):

```rust
async fn wait_for_rebuild(app: &axum::Router, token: &str, before: i64) {
    use std::time::Duration;
    for _ in 0..50 {
        let req = Request::builder()
            .uri("/api/filter/rebuild-status")
            .header("cookie", format!("session={}", token))
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let rebuilding = body.get("rebuilding").and_then(|v| v.as_bool()).unwrap_or(false);
        let last_completed_at = body.get("last_completed_at").and_then(|v| v.as_i64()).unwrap_or(0);
        if !rebuilding && last_completed_at > before {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("rebuild did not complete within 1s");
}
```

This helper is used by later tasks. The endpoint it calls is added in Task 5.

- [ ] **Step 5: Update tests that expected synchronous rebuild**

Search for assertions in `tests/admin_api_test.rs` that poke the filter engine right after a PUT/DELETE/POST-update of lists. For each such site, insert `wait_for_rebuild(&app, &token, before).await;` before the assertion, where `before` is captured via `noadd::filter::rebuild::now_unix()` just before the mutation.

Run: `cargo nextest run --test admin_api_test`

If any test fails, port it to use `wait_for_rebuild`.

- [ ] **Step 6: Do not commit yet**

This task is incomplete without Task 5's endpoint. Stage:

```bash
git add src/admin/api.rs tests/admin_api_test.rs
```

---

### Task 5: `GET /api/filter/rebuild-status`

**Files:**
- Modify: `src/admin/api.rs` (new handler + route)
- Modify: `tests/admin_api_test.rs` (new tests)

- [ ] **Step 1: Write the failing tests**

Append to `tests/admin_api_test.rs`:

```rust
#[tokio::test]
async fn rebuild_status_unauthenticated_returns_401() {
    let (app, _token) = setup().await;
    let req = Request::builder()
        .uri("/api/filter/rebuild-status")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rebuild_status_initial_is_idle() {
    let (app, token) = setup().await;
    let req = Request::builder()
        .uri("/api/filter/rebuild-status")
        .header("cookie", format!("session={}", token))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body.get("rebuilding").and_then(|v| v.as_bool()), Some(false));
    assert_eq!(body.get("started_at").and_then(|v| v.as_i64()), Some(0));
    assert_eq!(body.get("last_completed_at").and_then(|v| v.as_i64()), Some(0));
    assert_eq!(body.get("last_duration_ms").and_then(|v| v.as_u64()), Some(0));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo nextest run --test admin_api_test rebuild_status`
Expected: FAIL (route missing → 404 instead of 200/401).

- [ ] **Step 3: Add the handler and route**

In `src/admin/api.rs`, add near the other route registrations (after `.route("/api/lists/update", post(trigger_list_update))`):

```rust
.route("/api/filter/rebuild-status", get(get_rebuild_status))
```

And add the handler alongside the other `async fn`s:

```rust
#[derive(Serialize)]
struct RebuildStatusResponse {
    rebuilding: bool,
    started_at: i64,
    last_completed_at: i64,
    last_duration_ms: u64,
}

async fn get_rebuild_status(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<RebuildStatusResponse>, StatusCode> {
    require_auth(&state, &jar)?;
    let s = state.rebuild.state();
    Ok(Json(RebuildStatusResponse {
        rebuilding: s.rebuilding.load(std::sync::atomic::Ordering::Relaxed),
        started_at: s.started_at.load(std::sync::atomic::Ordering::Relaxed),
        last_completed_at: s.last_completed_at.load(std::sync::atomic::Ordering::Relaxed),
        last_duration_ms: s.last_duration_ms.load(std::sync::atomic::Ordering::Relaxed),
    }))
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo nextest run --test admin_api_test`
Expected: PASS (including the two new tests and any earlier tests that used `wait_for_rebuild`).

- [ ] **Step 5: Format + clippy + commit**

Run:

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
```

Expected: no warnings.

Commit (includes Task 4's staged changes):

```bash
git add src/admin/api.rs tests/admin_api_test.rs
git commit -S -m "feat(admin): detach filter rebuild and expose /api/filter/rebuild-status"
```

---

### Task 6: Registry client module

**Files:**
- Create: `src/registry.rs`
- Create: `tests/registry_test.rs`
- Create: `tests/common/mod.rs` — shared `spawn_fake_upstream` helper
- Modify: `src/lib.rs`

- [ ] **Step 1: Add module to `lib.rs`**

```rust
pub mod registry;
```

- [ ] **Step 2: Create the shared fake-upstream helper**

Create `tests/common/mod.rs`:

```rust
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::routing::get;
use tokio::net::TcpListener;

/// Spawn an ephemeral HTTP server that serves a fixed response body at `path`
/// with the given content-type. Returns the `http://127.0.0.1:PORT` base URL.
pub async fn spawn_fake_upstream(path: &'static str, body: String, content_type: &'static str) -> String {
    let body = Arc::new(body);
    let handler = {
        let body = body.clone();
        move || {
            let body = body.clone();
            async move {
                (
                    axum::http::StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, content_type)],
                    (*body).clone(),
                )
            }
        }
    };
    let app = Router::new().route(path, get(handler));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{}", addr)
}

/// Variant that serves a given HTTP status code (for 404/500 tests).
pub async fn spawn_fake_upstream_status(path: &'static str, status: u16) -> String {
    let app = Router::new().route(path, get(move || async move {
        axum::http::StatusCode::from_u16(status).unwrap()
    }));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{}", addr)
}
```

Note: put `#[path = "common/mod.rs"] mod common;` at the top of each integration test that uses it.

- [ ] **Step 3: Write the failing tests**

Create `tests/registry_test.rs`:

```rust
use std::time::Duration;

use noadd::registry::RegistryClient;

#[path = "common/mod.rs"]
mod common;

fn sample_json() -> &'static str {
    r#"{
      "filters": [
        {
          "filterKey": "adguard_dns",
          "filterId": 1,
          "groupId": 1,
          "name": "AdGuard DNS filter",
          "description": "Desc 1",
          "homepage": "https://example.com/1",
          "deprecated": false,
          "tags": [1],
          "languages": [],
          "version": "1",
          "expires": 345600,
          "displayNumber": 1,
          "downloadUrl": "https://example.com/filter_1.txt",
          "subscriptionUrl": "https://example.com/sub_1",
          "timeAdded": "2021-01-01T00:00:00+0000",
          "timeUpdated": "2026-04-19T00:00:00+0000"
        }
      ],
      "groups": [
        { "groupId": 1, "groupName": "General" }
      ],
      "tags": []
    }"#
}

#[tokio::test]
async fn fetch_populates_cache() {
    let base = common::spawn_fake_upstream(
        "/filters.json",
        sample_json().to_string(),
        "application/json",
    ).await;
    let client = RegistryClient::new(format!("{base}/filters.json"), Duration::from_secs(3600));
    let data = client.list().await.unwrap();
    assert_eq!(data.filters.len(), 1);
    assert_eq!(data.filters[0].name, "AdGuard DNS filter");
    assert_eq!(data.filters[0].download_url, "https://example.com/filter_1.txt");
    assert_eq!(data.groups.len(), 1);
    assert_eq!(data.groups[0].group_name, "General");
    // Second call served from cache — returns the same data even if upstream changes.
    let data2 = client.list().await.unwrap();
    assert_eq!(data2.filters[0].name, "AdGuard DNS filter");
}

#[tokio::test]
async fn cache_expires_after_ttl() {
    let base = common::spawn_fake_upstream(
        "/filters.json",
        sample_json().to_string(),
        "application/json",
    ).await;
    let client = RegistryClient::new(format!("{base}/filters.json"), Duration::from_millis(1));
    client.list().await.unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    // Second call — TTL expired. Must still succeed.
    let data2 = client.list().await.unwrap();
    assert_eq!(data2.filters.len(), 1);
}

#[tokio::test]
async fn upstream_error_surfaces() {
    let base = common::spawn_fake_upstream_status("/filters.json", 500).await;
    let client = RegistryClient::new(format!("{base}/filters.json"), Duration::from_secs(3600));
    let err = client.list().await.unwrap_err();
    assert!(format!("{err}").to_lowercase().contains("http") || format!("{err}").contains("500"));
}
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `cargo nextest run --test registry_test`
Expected: FAIL (module does not exist).

- [ ] **Step 5: Implement the registry client**

Create `src/registry.rs`:

```rust
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("parse error: {0}")]
    Parse(#[from] serde_json::Error),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RegistryFilter {
    pub filter_id: i64,
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub homepage: Option<String>,
    pub download_url: String,
    pub group_id: i64,
    pub deprecated: bool,
    pub time_updated: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RegistryGroup {
    pub group_id: i64,
    pub group_name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RegistryData {
    pub filters: Vec<RegistryFilter>,
    pub groups: Vec<RegistryGroup>,
}

struct CachedEntry {
    fetched_at: Instant,
    data: RegistryData,
}

pub struct RegistryClient {
    http: reqwest::Client,
    cache: RwLock<Option<CachedEntry>>,
    ttl: Duration,
    url: String,
}

pub const DEFAULT_REGISTRY_URL: &str =
    "https://adguardteam.github.io/HostlistsRegistry/assets/filters.json";

impl RegistryClient {
    pub fn new(url: impl Into<String>, ttl: Duration) -> Arc<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(crate::user_agent())
            .build()
            .expect("reqwest client build");
        Arc::new(Self {
            http,
            cache: RwLock::new(None),
            ttl,
            url: url.into(),
        })
    }

    pub async fn list(&self) -> Result<RegistryData, RegistryError> {
        {
            let guard = self.cache.read().await;
            if let Some(ref entry) = *guard
                && entry.fetched_at.elapsed() < self.ttl
            {
                return Ok(entry.data.clone());
            }
        }

        let body = self
            .http
            .get(&self.url)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        let data: RegistryData = serde_json::from_str(&body)?;

        let mut guard = self.cache.write().await;
        *guard = Some(CachedEntry {
            fetched_at: Instant::now(),
            data: data.clone(),
        });
        Ok(data)
    }
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo nextest run --test registry_test`
Expected: PASS (3 tests).

- [ ] **Step 7: Format + clippy + commit**

Run:

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
```

Expected: no warnings.

Commit:

```bash
git add src/registry.rs src/lib.rs tests/registry_test.rs tests/common/mod.rs
git commit -S -m "feat(registry): add HostlistsRegistry client with 1h in-memory TTL"
```

---

### Task 7: `GET /api/registry/filters`

**Files:**
- Modify: `src/admin/api.rs` — `AppState`, route, handler.
- Modify: `src/main.rs` — construct `RegistryClient` and pass in.
- Modify: `tests/admin_api_test.rs` — two tests.

- [ ] **Step 1: Extend `AppState`**

```rust
use crate::registry::RegistryClient;

// In AppState:
pub registry: Arc<RegistryClient>,
```

- [ ] **Step 2: Update `main.rs`**

After the `rebuild` construction, add:

```rust
let registry = noadd::registry::RegistryClient::new(
    noadd::registry::DEFAULT_REGISTRY_URL,
    std::time::Duration::from_secs(3600),
);
```

Add `registry: registry.clone()` to the `AppState` struct literal.

- [ ] **Step 3: Update `setup()` in `tests/admin_api_test.rs`**

Add:

```rust
let registry = noadd::registry::RegistryClient::new(
    "http://127.0.0.1:1/filters.json", // never hit in tests that do not use it
    std::time::Duration::from_secs(3600),
);
```

And `registry` in the `AppState` literal.

- [ ] **Step 4: Write the failing tests**

Append to `tests/admin_api_test.rs`:

```rust
#[tokio::test]
async fn registry_filters_unauthenticated_returns_401() {
    let (app, _token) = setup().await;
    let req = Request::builder()
        .uri("/api/registry/filters")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
```

Ensure the file has a single `#[path = "common/mod.rs"] mod common;` at the top (outside any function). Then for the success path add:

```rust
#[tokio::test]
async fn registry_filters_returns_cached_data() {
    let base = common::spawn_fake_upstream(
        "/filters.json",
        r#"{"filters":[{"filterKey":"k","filterId":1,"groupId":1,"name":"N","description":"D","homepage":null,"downloadUrl":"http://example.com/f.txt","deprecated":false,"tags":[],"languages":[],"version":"1","expires":1,"displayNumber":1,"subscriptionUrl":"","timeAdded":"","timeUpdated":""}],"groups":[{"groupId":1,"groupName":"General"}],"tags":[]}"#.to_string(),
        "application/json",
    ).await;

    // build custom state with a registry pointing at the fake upstream
    let (app, token) = setup_with_registry_url(format!("{base}/filters.json")).await;

    let req = Request::builder()
        .uri("/api/registry/filters")
        .header("cookie", format!("session={}", token))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["filters"].as_array().unwrap().len(), 1);
    assert_eq!(body["groups"][0]["group_name"], "General");
}
```

Refactor `setup()` into a private `setup_inner(registry_url: &str) -> (...)` that `setup()` and `setup_with_registry_url()` both delegate to. Concretely, change the top of the test file so `setup_inner` takes the registry URL, and add:

```rust
async fn setup_with_registry_url(url: String) -> (axum::Router, String) {
    setup_inner(&url).await
}
async fn setup() -> (axum::Router, String) {
    setup_inner("http://127.0.0.1:1/filters.json").await
}
```

Inside `setup_inner`, build the `RegistryClient` from the passed URL.

- [ ] **Step 5: Run tests to verify they fail**

Run: `cargo nextest run --test admin_api_test registry`
Expected: FAIL (route missing → 404).

- [ ] **Step 6: Add the handler and route**

In `src/admin/api.rs`:

```rust
.route("/api/registry/filters", get(get_registry_filters))
```

Handler:

```rust
async fn get_registry_filters(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<crate::registry::RegistryData>, StatusCode> {
    require_auth(&state, &jar)?;
    match state.registry.list().await {
        Ok(data) => Ok(Json(data)),
        Err(e) => {
            tracing::error!(error = %e, "registry fetch failed");
            Err(StatusCode::BAD_GATEWAY)
        }
    }
}
```

- [ ] **Step 7: Run the tests**

Run: `cargo nextest run --test admin_api_test registry`
Expected: PASS (2 tests).

- [ ] **Step 8: Format + clippy + commit**

Run:

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
```

Expected: no warnings.

Commit:

```bash
git add src/admin/api.rs src/main.rs tests/admin_api_test.rs
git commit -S -m "feat(admin): add GET /api/registry/filters proxying HostlistsRegistry"
```

---

### Task 8: `POST /api/lists/batch`

**Files:**
- Modify: `src/admin/api.rs` — types, handler, route.
- Modify: `tests/admin_api_test.rs` — tests.

- [ ] **Step 1: Write the failing tests**

Append to `tests/admin_api_test.rs`:

```rust
#[tokio::test]
async fn batch_add_unauthenticated_returns_401() {
    let (app, _token) = setup().await;
    let req = Request::builder()
        .method("POST")
        .uri("/api/lists/batch")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"items":[]}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn batch_add_rejects_empty() {
    let (app, token) = setup().await;
    let req = Request::builder()
        .method("POST")
        .uri("/api/lists/batch")
        .header("content-type", "application/json")
        .header("cookie", format!("session={}", token))
        .body(Body::from(r#"{"items":[]}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn batch_add_rejects_oversized() {
    let (app, token) = setup().await;
    let items: Vec<serde_json::Value> = (0..51)
        .map(|i| serde_json::json!({"name": format!("n{i}"), "url": format!("http://x/{i}")}))
        .collect();
    let body = serde_json::json!({"items": items});
    let req = Request::builder()
        .method("POST")
        .uri("/api/lists/batch")
        .header("content-type", "application/json")
        .header("cookie", format!("session={}", token))
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn batch_add_all_success() {
    use noadd::filter::rebuild::now_unix;

    let base = common::spawn_fake_upstream(
        "/filter_a.txt",
        "||ads.example.com^\n".to_string(),
        "text/plain",
    ).await;

    let (app, token) = setup().await;
    let before = now_unix();
    let body = serde_json::json!({"items":[
        {"name":"A","url": format!("{base}/filter_a.txt")}
    ]});
    let req = Request::builder()
        .method("POST")
        .uri("/api/lists/batch")
        .header("content-type", "application/json")
        .header("cookie", format!("session={}", token))
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["added"].as_array().unwrap().len(), 1);
    assert_eq!(v["failed"].as_array().unwrap().len(), 0);
    assert_eq!(v["added"][0]["name"], "A");
    assert!(v["added"][0]["rule_count"].as_i64().unwrap() >= 1);

    wait_for_rebuild(&app, &token, before).await;
}

#[tokio::test]
async fn batch_add_partial_failure() {
    let ok_base = common::spawn_fake_upstream(
        "/ok.txt",
        "||ok.example.com^\n".to_string(),
        "text/plain",
    ).await;
    let bad_base = common::spawn_fake_upstream_status("/bad.txt", 404).await;

    let (app, token) = setup().await;
    let body = serde_json::json!({"items":[
        {"name":"OK","url": format!("{ok_base}/ok.txt")},
        {"name":"BAD","url": format!("{bad_base}/bad.txt")}
    ]});
    let req = Request::builder()
        .method("POST")
        .uri("/api/lists/batch")
        .header("content-type", "application/json")
        .header("cookie", format!("session={}", token))
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let added = v["added"].as_array().unwrap();
    let failed = v["failed"].as_array().unwrap();
    assert_eq!(added.len(), 1);
    assert_eq!(failed.len(), 1);
    assert_eq!(added[0]["name"], "OK");
    assert_eq!(failed[0]["name"], "BAD");

    // OK list exists; BAD list was rolled back and is absent.
    let lists_req = Request::builder()
        .uri("/api/lists")
        .header("cookie", format!("session={}", token))
        .body(Body::empty())
        .unwrap();
    let lists_resp = app.oneshot(lists_req).await.unwrap();
    let bytes = axum::body::to_bytes(lists_resp.into_body(), usize::MAX).await.unwrap();
    let lists: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let arr = lists.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["name"], "OK");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo nextest run --test admin_api_test batch_add`
Expected: FAIL (route missing).

- [ ] **Step 3: Add types, handler, and route**

In `src/admin/api.rs`:

```rust
.route("/api/lists/batch", post(batch_add_lists))
```

Add types and the handler:

```rust
#[derive(Deserialize)]
pub struct BatchAddRequest {
    pub items: Vec<BatchAddItem>,
}

#[derive(Deserialize)]
pub struct BatchAddItem {
    pub name: String,
    pub url: String,
}

#[derive(Serialize)]
pub struct BatchAddedEntry {
    pub id: i64,
    pub name: String,
    pub url: String,
    pub rule_count: i64,
}

#[derive(Serialize)]
pub struct BatchFailedEntry {
    pub name: String,
    pub url: String,
    pub error: String,
}

#[derive(Serialize)]
pub struct BatchAddResponse {
    pub added: Vec<BatchAddedEntry>,
    pub failed: Vec<BatchFailedEntry>,
}

async fn batch_add_lists(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<BatchAddRequest>,
) -> Result<Json<BatchAddResponse>, StatusCode> {
    require_auth(&state, &jar)?;
    if body.items.is_empty() || body.items.len() > 50 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .user_agent(crate::user_agent())
        .build()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let sem = Arc::new(tokio::sync::Semaphore::new(4));
    let mut set = tokio::task::JoinSet::new();
    for item in body.items {
        let permit = sem.clone().acquire_owned().await.unwrap();
        let db = state.db.clone();
        let http = client.clone();
        set.spawn(async move {
            let _permit = permit;
            let name = item.name.trim().to_string();
            let url = item.url.trim().to_string();
            let id = match db.add_filter_list(&name, &url, true).await {
                Ok(id) => id,
                Err(e) => {
                    return Err(BatchFailedEntry {
                        name,
                        url,
                        error: format!("{e}"),
                    });
                }
            };
            match http.get(&url).send().await.and_then(|r| r.error_for_status()) {
                Ok(resp) => {
                    let content = match resp.text().await {
                        Ok(c) => c,
                        Err(e) => {
                            let _ = db.delete_filter_list(id).await;
                            return Err(BatchFailedEntry {
                                name,
                                url,
                                error: format!("{e}"),
                            });
                        }
                    };
                    let rule_count = crate::filter::parser::parse_list(&content).len() as i64;
                    if let Err(e) = db.set_filter_list_content(id, &content).await {
                        let _ = db.delete_filter_list(id).await;
                        return Err(BatchFailedEntry {
                            name,
                            url,
                            error: format!("{e}"),
                        });
                    }
                    let now = crate::filter::rebuild::now_unix();
                    let _ = db.update_filter_list_stats(id, now, rule_count).await;
                    Ok(BatchAddedEntry {
                        id,
                        name,
                        url,
                        rule_count,
                    })
                }
                Err(e) => {
                    let _ = db.delete_filter_list(id).await;
                    Err(BatchFailedEntry {
                        name,
                        url,
                        error: format!("{e}"),
                    })
                }
            }
        });
    }

    let mut added = Vec::new();
    let mut failed = Vec::new();
    while let Some(res) = set.join_next().await {
        match res {
            Ok(Ok(a)) => added.push(a),
            Ok(Err(f)) => failed.push(f),
            Err(e) => failed.push(BatchFailedEntry {
                name: String::new(),
                url: String::new(),
                error: format!("task join error: {e}"),
            }),
        }
    }

    let manager = state.list_manager.clone();
    state.rebuild.clone().spawn_raw(move || async move {
        manager.rebuild_filter().await
    });

    Ok(Json(BatchAddResponse { added, failed }))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo nextest run --test admin_api_test batch_add`
Expected: PASS (5 tests).

- [ ] **Step 5: Run full suite**

Run: `cargo nextest run`
Expected: PASS (all tests).

- [ ] **Step 6: Format + clippy + commit**

Run:

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
```

Expected: no warnings.

Commit:

```bash
git add src/admin/api.rs tests/admin_api_test.rs
git commit -S -m "feat(admin): add POST /api/lists/batch for registry-driven multi-add"
```

---

### Task 9: `<rebuild-banner>` global component

**Files:**
- Modify: `admin-ui/dist/index.html`

This is a UI task. **REQUIRED:** invoke the `frontend-design` skill for visual polish before finalising. The skill handles colours, spacing, typography, motion, and accessibility.

- [ ] **Step 1: Invoke `frontend-design` skill**

Ask it to design a global, non-blocking status banner that sits at the very top of the admin shell (above existing nav), with:

- Variant 1: in-flight rebuild — spinner + text `Rebuilding filter engine… (Xs elapsed)`.
- Variant 2: transient success — subtle check + `Filter engine updated in Ys` for 3 s.
- Variant 3: hidden (display:none, does not reserve vertical space).

Colour tokens: use the existing CSS custom properties in `admin-ui/dist/index.html`. Responsive at mobile widths.

- [ ] **Step 2: Add the component**

In `admin-ui/dist/index.html`, register a new web component `<rebuild-banner>` that:

- Polls `GET /api/filter/rebuild-status` every 2000 ms via `api.get`.
- Tracks `prev` rebuild state; on `true → false` transitions shows the success variant for 3000 ms.
- On `disconnectedCallback`, clears the interval.
- Renders nothing (or `display:none`) when steady-state idle.

Mount the banner in the app shell so every page sees it. The exact shell insertion point is in the template that wraps page routing; add `<rebuild-banner></rebuild-banner>` as the first child of the main shell container.

- [ ] **Step 3: Manual smoke test**

Start the dev server:

```bash
RUST_LOG=noadd=debug cargo run -- --dns-addr 127.0.0.1:5353 --http-addr 127.0.0.1:3000
```

1. Log in to the admin UI.
2. Click `Update All` on Filter Lists; confirm the banner appears and the button returns immediately.
3. Wait for rebuild to finish; confirm banner transitions to "updated in Ys" for ~3 s, then hides.

- [ ] **Step 4: Commit**

```bash
git add admin-ui/dist/index.html
git commit -S -m "feat(admin-ui): add global rebuild-banner with status polling"
```

---

### Task 10: `<registry-modal>` + `Browse Registry` button

**Files:**
- Modify: `admin-ui/dist/index.html` — new modal component, new button on Filter Lists card.

**REQUIRED:** invoke the `frontend-design` skill for visual design.

- [ ] **Step 1: Invoke `frontend-design` skill**

Ask it to design a modal picker for filter lists, informed by the interaction behaviour already locked in the spec:

- Header: title `Browse filter registry` + close button.
- Toolbar: text search input, group dropdown (`All / General / Other / Regional / Security`), `Show deprecated` checkbox (off by default).
- Row: checkbox (disabled + `Added` pill when already in the user's lists), name, group badge, truncated description, homepage external-link icon.
- Footer: `N selected` counter + `Add Selected` primary button + `Cancel` / `Close` secondary.
- States: loading spinner, error + `Retry`, empty-search, batch-progress (button loading), batch-result summary (on partial failure).

Mobile: modal is full-screen at narrow widths; rows collapse to two-line layout.

- [ ] **Step 2: Add the `Browse Registry` trigger**

Inside the Filter Lists card toolbar in `admin-ui/dist/index.html` (next to `Update All`), add a button:

```html
<button class="btn btn-secondary btn-sm" id="browse-registry">${icons.search} Browse Registry</button>
```

Wire its handler in `connectedCallback`:

```js
this.querySelector('#browse-registry').onclick = () => {
  const modal = document.createElement('registry-modal');
  modal.addEventListener('batch-added', () => this.loadLists());
  document.body.appendChild(modal);
  modal.open();
};
```

- [ ] **Step 3: Implement `<registry-modal>`**

Register a web component with these responsibilities:

1. `open()` — inserts the modal shell + starts data load.
2. Data load — `Promise.all([api.get('/api/registry/filters'), api.get('/api/lists')])`; memoises registry data across re-opens on the same component instance.
3. Filtering — text search on `name+description`, group filter, `show deprecated`.
4. Row rendering — mark `alreadyAdded` via the existing URL set; disable checkbox and show `Added` pill in that case.
5. `Add Selected` — `POST /api/lists/batch { items }`, disable controls during the request.
6. On all-success: dispatch `batch-added` event, close.
7. On partial: render summary, swap `Cancel` → `Close`, dispatch `batch-added` regardless (so the Filters page refreshes).

- [ ] **Step 4: Manual smoke test**

Start the dev server, log in, open the modal:

1. See spinner then rendered list of registry filters.
2. Search box filters live.
3. Group dropdown filters live.
4. `Show deprecated` toggles deprecated entries.
5. Any entry whose URL already exists shows `Added`.
6. Select 2–3, click `Add Selected`. Modal closes, Filter Lists refreshes, rebuild banner appears, then hides.
7. Edit an entry's URL to 404, try batch add: summary appears, failed entry is listed, OK entries are added.

- [ ] **Step 5: Commit**

```bash
git add admin-ui/dist/index.html
git commit -S -m "feat(admin-ui): browse-registry modal for picking filter lists"
```

---

### Task 11: Wrap-up — format, clippy, nextest, branch check

- [ ] **Step 1: Full verification**

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo nextest run
```

All three must succeed with no warnings and all tests passing.

- [ ] **Step 2: Review commit history**

```bash
git log --oneline main..HEAD
```

Expected commits on `feat/browse-filter-lists-registry` (in order):

1. `refactor(filter): trim default filter lists to minimal seed` (Task A, already present as `61add80`)
2. `docs: add spec for browse-filter-lists-registry feature`
3. `feat(filter): add RebuildCoordinator for detached, serialised rebuilds`
4. `refactor(filter): split update_all_lists and share ListManager via Arc`
5. `feat(admin): detach filter rebuild and expose /api/filter/rebuild-status`
6. `feat(registry): add HostlistsRegistry client with 1h in-memory TTL`
7. `feat(admin): add GET /api/registry/filters proxying HostlistsRegistry`
8. `feat(admin): add POST /api/lists/batch for registry-driven multi-add`
9. `feat(admin-ui): add global rebuild-banner with status polling`
10. `feat(admin-ui): browse-registry modal for picking filter lists`

- [ ] **Step 3: Do not push or open PR in this plan**

The user will decide when to push and open the PR.
