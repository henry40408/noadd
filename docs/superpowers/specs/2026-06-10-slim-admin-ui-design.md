# Design: Systematic slimming of admin UI CSS/JS

Date: 2026-06-10
Status: Approved

## Background

The entire admin UI is a single self-contained file, `admin-ui/dist/index.html`
(~131 KB / 3,463 lines: ~1,330 lines of CSS in one `<style>` block, ~2,110 lines
of JS in one `<script>` block). It is embedded into the Rust binary at build
time. Analysis shows very little true dead code; the main slimming opportunity
is consolidating duplicated patterns.

## Goal

Remove dead code and merge duplicated CSS/JS patterns with **zero change in
behavior and appearance**, reducing line count and maintenance cost. No
minification — the file stays human-readable.

## Scope

- Only `admin-ui/dist/index.html`.
- No changes to e2e test logic or the Rust side.

## Plan of work

All work happens on branch `refactor/slim-admin-ui`, with each phase verified
independently.

### Phase 1 — Baseline

Run the Playwright e2e suite to confirm green, and record the current line and
byte counts for comparison.

### Phase 2 — CSS audit and cleanup

- Audit every selector against usage in HTML markup and JS strings (including
  dynamically generated HTML). Delete selectors verified dead. Known
  candidates: `.badge-on`, `.rules-grid`.
- Handle `.btn-secondary` / `.btn-ghost` (used in HTML, no matching CSS rule):
  confirm JS does not use them as query selectors; if they have no functional
  purpose, remove the class names from the HTML.
- Merge the three near-identical tooltip rule sets (`.chart-tooltip`,
  `.heatmap-tooltip`, `.rate-tooltip`, ~90 lines) into a shared base plus
  per-tooltip differences. Merge the duplicated declarations across the three
  registry pill styles.
- All merges use grouped selectors / shared classes only, preserving
  declaration order and specificity so the cascade is unchanged.

### Phase 3 — JS audit and consolidation

- Extract a shared `renderTopTable` helper to consolidate the three
  identical-logic methods `renderTopDomains` / `renderTopClients` /
  `renderTopUpstreams` (~50 duplicated lines).
- Extract helpers for form error display and card flash detection (boilerplate
  repeated in several places).
- Re-check every function for dead code; before any deletion, search the whole
  file with `rg`, covering string references such as `onclick="..."`.

### Phase 4 — Verification and measurement

Run the e2e suite after each phase; report the final line/byte reduction.

## Expected outcome

Roughly −115 lines / −2 KB (~1.6%). The main benefit is maintainability:
eliminating three copies of the same logic and unifying tooltip/pill styles.

## Risks and mitigations

- CSS merges could change cascade order → use grouped selectors only and do
  not move rules around.
- JS may reference identifiers via strings → search the whole file before
  every deletion.
- The e2e suite is the final safety net.

## Testing

This is a behavior-preserving refactor; verification relies on the existing
Playwright e2e suite. No new tests are added.
