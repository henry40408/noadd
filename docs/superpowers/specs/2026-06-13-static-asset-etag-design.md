# Static Asset ETag Caching — Design

Date: 2026-06-13
Branch: `feat/static-asset-etag`

## Problem

The admin UI is a single hand-written `index.html` (~146 KB, all CSS/JS inlined,
no build step) embedded in the binary via `include_dir!` and served by
`serve_static` in `src/admin/api.rs`. The static serving currently sends **no
cache-validation headers at all**, so every full page load / hard reload
re-downloads and re-parses the entire 146 KB. The only asset with any cache
header is `apple-touch-icon.png` (`Cache-Control: public, max-age=86400`), which
is hard-cached for a day and therefore does **not** pick up a redesigned favicon
promptly.

## Goal

Reduce redundant downloads on reload while keeping updates on-demand:

- A reload should not re-transfer 146 KB when nothing changed.
- When the UI (or favicon) changes, the new content must reach the browser
  immediately — no manual cache-busting, no version bookkeeping.

## Non-goals

- **No file splitting.** Extracting CSS/JS into separate hashed files was
  considered and rejected: the benefit is marginal for a LAN-local self-hosted
  tool, and content-hashed filenames would require a build step, contradicting
  the project's deliberate "no build step, no framework" design
  (ARCHITECTURE.md). Caching is achieved without splitting.
- No compression (gzip/brotli) work — separate concern.
- No CDN.

## Approach

Add a strong `ETag` plus revalidation to every embedded static asset. The
browser then sends a conditional request on reload and receives a tiny
`304 Not Modified` instead of the full body. Because the ETag is derived from
the content, any change to the asset changes the ETag and the browser
automatically fetches the new `200` — this is the on-demand update.

### ETag source

Content hash via `std::hash::DefaultHasher` (SipHash with fixed keys →
deterministic, reproducible across process restarts of the same binary).
**Zero new dependencies.** Assets are fixed at compile time, so each file's ETag
is computed once and memoized (`OnceLock`). Format: `"<hex>"` (strong validator,
quoted).

Rejected alternative: ETag derived from `GIT_VERSION`. Simpler (one constant),
but in local dev with a `-dirty` tree the version string does not change between
edits, so `no-cache` revalidation would return stale `304`s after editing the
UI. Content hash avoids this footgun and is only marginally more code.

### Headers

All embedded assets (`index.html`, `favicon.svg`, `apple-touch-icon.png`):

- `ETag: "<content-hash>"`
- `Cache-Control: no-cache`

Note: `no-cache` does **not** mean "do not store" — it means "store but
revalidate every time". Combined with the ETag this yields a conditional request
on each load that 304s when unchanged.

`apple-touch-icon.png` drops its current `Cache-Control: public, max-age=86400`
and joins the unified scheme, so a redesigned favicon takes effect immediately,
matching `favicon.svg`'s behaviour.

### Conditional handling

`serve_static` gains a `HeaderMap` extractor. On each request it reads
`If-None-Match`; if the value matches the resolved file's ETag, it returns
`304 Not Modified` with the `ETag` header and an empty body. This applies to
both the matched-file path and the SPA `index.html` fallback path.

`serve_apple_touch_icon` gets the same `If-None-Match` → `304` handling.

## Components touched

- `src/admin/api.rs`
  - `serve_static(uri: Uri)` → `serve_static(uri: Uri, headers: HeaderMap)`:
    compute/lookup per-file ETag, emit `ETag` + `Cache-Control: no-cache`,
    honour `If-None-Match` with `304`, on both the matched-file and fallback
    branches.
  - `serve_apple_touch_icon` → take `HeaderMap`, emit `ETag` + `no-cache`
    (drop `max-age`), honour `If-None-Match`.
  - A small helper to compute a quoted strong ETag from bytes, plus a memoized
    per-path ETag lookup over the embedded `Dir`.

## Error handling / edge cases

- Missing asset: unchanged 404 behaviour (and unchanged SPA fallback to
  `index.html` for extension-less paths).
- A request without `If-None-Match`: full `200` with `ETag` set (populates the
  cache).
- Strong validator only; weak ETags not needed (no transformation/compression
  layer in front).

## Testing

Extend the existing HTTP integration tests under `tests/`:

1. `GET /` returns `200` with a non-empty `ETag` header and
   `Cache-Control: no-cache`.
2. A second `GET /` carrying `If-None-Match` equal to that ETag returns `304`
   with an empty body.
3. `GET /apple-touch-icon.png` returns an `ETag`; a conditional re-request
   returns `304` (regression guard for the removed `max-age`).

## Documentation

ARCHITECTURE.md (the admin-UI serving paragraph, ~line 93): add a sentence that
embedded static assets are served with content-hash ETags and revalidated via
`no-cache`, so reloads 304 and UI/favicon changes take effect immediately.
