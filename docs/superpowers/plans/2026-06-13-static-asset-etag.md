# Static Asset ETag Caching Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Serve every embedded admin-UI static asset with a content-hash `ETag` and `Cache-Control: no-cache`, returning `304 Not Modified` on conditional requests, so reloads stop re-transferring ~146 KB while UI/favicon changes still take effect immediately.

**Architecture:** All assets are served from `src/admin/api.rs` — `serve_static` (matched files + SPA `index.html` fallback) and `serve_apple_touch_icon`. Add a small content-hash ETag helper (`std::hash::DefaultHasher`, deterministic, zero new deps), a conditional-request check, and unified headers. `apple-touch-icon.png` drops its `max-age=86400` and joins the same scheme.

**Tech Stack:** Rust 2024, axum 0.8, include_dir 0.7. Tests via `tower::ServiceExt::oneshot` (existing pattern in `tests/admin_api_test.rs`). Run tests with `cargo nextest run`.

Spec: `docs/superpowers/specs/2026-06-13-static-asset-etag-design.md`

---

## File Structure

- **Modify** `src/admin/api.rs`
  - Add ETag/conditional helpers (`etag_for`, `if_none_match_matches`, `ui_etags`, `apple_touch_icon_etag`, `static_response`).
  - Rewrite `serve_static` to take `HeaderMap` and emit ETag + `no-cache` + handle `304` on both branches.
  - Rewrite `serve_apple_touch_icon` to take `HeaderMap`, emit ETag + `no-cache` (drop `max-age`), handle `304`.
  - Fix imports: add `File` to the `include_dir` use; remove now-unused `Html`; add std hashing imports.
- **Modify** `tests/admin_api_test.rs` — add ETag/304 tests (reuse existing `setup()` + `oneshot` pattern).
- **Modify** `ARCHITECTURE.md` — one sentence on ETag revalidation in the admin-UI serving paragraph (~line 93).

CI runs `cargo clippy -- -D warnings`, so unused imports/vars are build failures — the `Html` import MUST be removed in the same task that stops using it.

---

## Task 1: ETag helpers + conditional handling in `serve_static`

**Files:**
- Modify: `src/admin/api.rs` (imports near top; helpers + handlers near `serve_static`, lines ~119-164)
- Test: `tests/admin_api_test.rs` (append new `#[tokio::test]` fns)

- [ ] **Step 1: Write the failing tests**

Append to `tests/admin_api_test.rs`:

```rust
#[tokio::test]
async fn test_index_served_with_etag_and_no_cache() {
    let (app, _token) = setup().await;

    let response = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let etag = response
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(etag.starts_with('"') && etag.ends_with('"'), "etag not quoted: {etag}");
    let cc = response
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(cc, "no-cache");
}

#[tokio::test]
async fn test_index_conditional_request_returns_304() {
    let (app, _token) = setup().await;

    // First request to learn the ETag.
    let first = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let etag = first
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();

    // Second request carrying the ETag must 304 with an empty body.
    let second = app
        .oneshot(
            Request::builder()
                .uri("/")
                .header("if-none-match", &etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(second.status(), StatusCode::NOT_MODIFIED);
    let body = axum::body::to_bytes(second.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(body.is_empty(), "304 body should be empty, got {} bytes", body.len());
}

#[tokio::test]
async fn test_favicon_svg_has_etag() {
    let (app, _token) = setup().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/favicon.svg")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("etag").is_some(), "favicon.svg missing etag");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo nextest run -E 'test(test_index_served_with_etag) + test(test_index_conditional_request) + test(test_favicon_svg_has_etag)'`
Expected: FAIL — no `etag`/`cache-control` headers yet; conditional test gets `200` not `304`.

- [ ] **Step 3: Update imports in `src/admin/api.rs`**

Change the include_dir import (line 12) from:

```rust
use include_dir::{Dir, include_dir};
```

to:

```rust
use include_dir::{Dir, File, include_dir};
```

Change the response import (line 7) from:

```rust
use axum::response::{Html, IntoResponse};
```

to:

```rust
use axum::response::{IntoResponse, Response};
```

Add these std imports below the existing `use std::...` lines (top of file):

```rust
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::OnceLock;
```

- [ ] **Step 4: Add the ETag helpers**

Insert directly after the `static ADMIN_UI: Dir = ...;` line (line ~119):

```rust
/// Strong, quoted ETag derived from a content hash. `DefaultHasher` seeds with
/// fixed keys, so the digest is deterministic across process restarts of the
/// same binary — exactly what a content-addressed validator needs, and with no
/// extra dependency.
fn etag_for(bytes: &[u8]) -> String {
    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    format!("\"{:016x}\"", hasher.finish())
}

/// Per-path ETags for the embedded admin UI, computed once. Assets are fixed at
/// compile time, so the map never needs invalidation.
fn ui_etags() -> &'static HashMap<PathBuf, String> {
    static ETAGS: OnceLock<HashMap<PathBuf, String>> = OnceLock::new();
    ETAGS.get_or_init(|| {
        ADMIN_UI
            .files()
            .map(|f| (f.path().to_path_buf(), etag_for(f.contents())))
            .collect()
    })
}

/// True when `If-None-Match` lists the given ETag (browsers echo back exactly
/// what we sent; we also tolerate a comma-separated list).
fn if_none_match_matches(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get(axum::http::header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(',').any(|t| t.trim() == etag))
        .unwrap_or(false)
}

/// Build a `200` (with body) or `304` response for an embedded file, always
/// carrying an `ETag` and `Cache-Control: no-cache`.
fn static_response(file: &File<'_>, headers: &HeaderMap) -> Response {
    let etag = ui_etags()
        .get(file.path())
        .cloned()
        .unwrap_or_else(|| etag_for(file.contents()));

    if if_none_match_matches(headers, &etag) {
        return (
            StatusCode::NOT_MODIFIED,
            [
                ("etag", etag),
                ("cache-control", "no-cache".to_string()),
            ],
        )
            .into_response();
    }

    let mime = mime_guess::from_path(file.path()).first_or_octet_stream();
    (
        StatusCode::OK,
        [
            ("content-type", mime.to_string()),
            ("etag", etag),
            ("cache-control", "no-cache".to_string()),
        ],
        file.contents().to_vec(),
    )
        .into_response()
}
```

- [ ] **Step 5: Rewrite `serve_static`**

Replace the whole `serve_static` function (lines ~134-164) with:

```rust
async fn serve_static(uri: Uri, headers: HeaderMap) -> impl IntoResponse {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    match ADMIN_UI.get_file(path) {
        Some(file) => static_response(file, &headers),
        None => {
            // Only fall back to index.html for extension-less paths (SPA
            // client-side routes like /dashboard, /settings). Requests for
            // missing assets (favicon.ico, robots.txt, *.map, etc.) must
            // 404 so the browser doesn't try to parse HTML as the asset.
            if std::path::Path::new(path).extension().is_some() {
                return (StatusCode::NOT_FOUND, "not found").into_response();
            }
            match ADMIN_UI.get_file("index.html") {
                Some(file) => static_response(file, &headers),
                None => (StatusCode::NOT_FOUND, "not found").into_response(),
            }
        }
    }
}
```

- [ ] **Step 6: Run the new tests + existing static tests**

Run: `cargo nextest run -E 'test(test_index_served_with_etag) + test(test_index_conditional_request) + test(test_favicon_svg_has_etag) + test(test_missing_asset_returns_404) + test(test_existing_asset_served_with_correct_mime) + test(test_spa_route_still_serves_index_html)'`
Expected: PASS — all six. (The three existing tests confirm 404 / mime / SPA fallback still behave.)

- [ ] **Step 7: Clippy + fmt**

Run: `cargo fmt && cargo clippy -- -D warnings`
Expected: no errors (confirms `Html` removal left no dangling references and no unused imports).

- [ ] **Step 8: Commit**

```bash
git add src/admin/api.rs tests/admin_api_test.rs
git commit -m "feat(admin-ui): serve static assets with content-hash ETag revalidation"
```

---

## Task 2: ETag + `304` for `apple-touch-icon.png`

**Files:**
- Modify: `src/admin/api.rs` (`serve_apple_touch_icon`, lines ~123-132)
- Test: `tests/admin_api_test.rs`

- [ ] **Step 1: Write the failing tests**

Append to `tests/admin_api_test.rs`:

```rust
#[tokio::test]
async fn test_apple_touch_icon_has_etag_and_no_cache() {
    let (app, _token) = setup().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/apple-touch-icon.png")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("etag").is_some(), "missing etag");
    let cc = response
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(cc, "no-cache");
}

#[tokio::test]
async fn test_apple_touch_icon_conditional_request_returns_304() {
    let (app, _token) = setup().await;

    let first = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/apple-touch-icon.png")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let etag = first
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();

    let second = app
        .oneshot(
            Request::builder()
                .uri("/apple-touch-icon.png")
                .header("if-none-match", &etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(second.status(), StatusCode::NOT_MODIFIED);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo nextest run -E 'test(test_apple_touch_icon_has_etag) + test(test_apple_touch_icon_conditional_request)'`
Expected: FAIL — current handler sends `cache-control: public, max-age=86400` and no `etag`; conditional request returns `200`.

- [ ] **Step 3: Add the apple-touch-icon ETag accessor**

Insert after the `static APPLE_TOUCH_ICON: &[u8] = ...;` line (line ~121):

```rust
fn apple_touch_icon_etag() -> &'static str {
    static ETAG: OnceLock<String> = OnceLock::new();
    ETAG.get_or_init(|| etag_for(APPLE_TOUCH_ICON))
}
```

- [ ] **Step 4: Rewrite `serve_apple_touch_icon`**

Replace the whole function (lines ~123-132) with:

```rust
async fn serve_apple_touch_icon(headers: HeaderMap) -> impl IntoResponse {
    let etag = apple_touch_icon_etag();
    if if_none_match_matches(&headers, etag) {
        return (
            StatusCode::NOT_MODIFIED,
            [("etag", etag), ("cache-control", "no-cache")],
        )
            .into_response();
    }
    (
        StatusCode::OK,
        [
            ("content-type", "image/png"),
            ("etag", etag),
            ("cache-control", "no-cache"),
        ],
        APPLE_TOUCH_ICON,
    )
        .into_response()
}
```

- [ ] **Step 5: Run new + existing apple-touch-icon tests**

Run: `cargo nextest run -E 'test(test_apple_touch_icon)'`
Expected: PASS — new ETag/304 tests plus the existing `test_apple_touch_icon_served_as_png` (PNG magic bytes still served on the unconditional request).

- [ ] **Step 6: Clippy + fmt**

Run: `cargo fmt && cargo clippy -- -D warnings`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add src/admin/api.rs tests/admin_api_test.rs
git commit -m "feat(admin-ui): revalidate apple-touch-icon via ETag instead of max-age"
```

---

## Task 3: Document the caching behaviour

**Files:**
- Modify: `ARCHITECTURE.md` (admin-UI serving paragraph, ~line 93)

- [ ] **Step 1: Read the current paragraph**

Run: `sed -n '90,96p' ARCHITECTURE.md`
Expected: the "single `index.html` ... Embedded in the binary at compile time via `include_dir`." paragraph.

- [ ] **Step 2: Append one sentence**

Add to the end of that paragraph:

```markdown
Embedded assets are served with a content-hash `ETag` and `Cache-Control: no-cache`, so browsers revalidate on each load and receive `304 Not Modified` when nothing changed — reloads avoid re-transferring the ~146 KB page, while a rebuilt binary (new content, new ETag) updates clients immediately.
```

- [ ] **Step 3: Commit**

```bash
git add ARCHITECTURE.md
git commit -m "docs: note static-asset ETag revalidation in architecture"
```

---

## Final Verification

- [ ] **Run the full admin API suite**

Run: `cargo nextest run -E 'test(admin_api)'` (or the whole suite: `cargo nextest run`)
Expected: all green, including pre-existing static-serving tests.

- [ ] **Confirm clippy is clean**

Run: `cargo clippy -- -D warnings`
Expected: no warnings (matches CI gate).
