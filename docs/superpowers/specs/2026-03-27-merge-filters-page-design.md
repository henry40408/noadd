# Merge Filters Page + Domain Test

## Overview

Merge the separate "Filter Lists" and "Custom Rules" pages into a single "Filters" page, and add a domain test feature that checks whether a domain is allowed or blocked by the current filter configuration.

## UI Changes

### Sidebar

Remove the `#lists` and `#rules` nav entries. Replace with a single `#filters` entry labeled "Filters".

### Filters Page Layout (top to bottom)

1. **Domain Test card** — Text input + "Test" button. Calls `POST /api/filter/check`. Displays result:
   - Allowed: green `badge-allowed` badge
   - Blocked: red `badge-blocked` badge + matched rule text + source list name

2. **Filter Lists card** — Existing ListsPage content: table with enabled toggle, name, rule count, last updated. "Update All" button. "Add Custom List" form (name + URL).

3. **Custom Rules card** — Existing RulesPage content: two-column grid with Blocklist (left) and Allowlist (right). Each has an input to add rules and a table of existing rules with delete buttons.

### Navigation

- Route: `#filters` → `FiltersPage`
- Remove `#lists` and `#rules` routes
- Sidebar icon: use the existing lists icon (or rules icon — reuse whichever fits better)

## API Changes

### New Endpoint

`POST /api/filter/check` (requires auth)

Request body:
```json
{ "domain": "ads.example.com" }
```

Response (blocked):
```json
{ "action": "blocked", "rule": "||ads.example.com^", "list": "EasyList" }
```

Response (allowed):
```json
{ "action": "allowed" }
```

Implementation: load the current `FilterEngine` from `ArcSwap`, call `engine.check(domain)`, serialize `FilterResult` to JSON.

## Backend / DB

No schema changes. All existing API endpoints for lists and rules remain unchanged. Only the UI consolidates them into one page.

## Cleanup

- Delete `ListsPage` web component class and `customElements.define('lists-page', ListsPage)`
- Delete `RulesPage` web component class and `customElements.define('rules-page', RulesPage)`
- Create `FiltersPage` web component combining both
- Update `AppShell` sidebar nav items
- Update router registrations

## Testing

- Unit test: `POST /api/filter/check` returns correct result for blocked and allowed domains
- Integration: existing lists and rules API tests continue to pass (endpoints unchanged)
