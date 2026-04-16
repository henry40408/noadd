# Database Reader Connection — Isolate Admin Reads from Log Writes

## Overview

Under multi-client load (target ~10–30 home devices), admin dashboard queries such as `latency_summary_since`, `hourly_heatmap_since`, and `timeline_multi_since` perform full scans over `query_logs` and block the async query logger's batched `insert_query_logs` writes. Root cause: `Database` holds a single `tokio_rusqlite::Connection`, which serialises every DB call onto one background thread regardless of operation type.

Fix: give `Database` a second, read-only `tokio_rusqlite::Connection` against the same SQLite file. SQLite's WAL journal mode allows the reader to run concurrently with the writer without blocking, removing the contention point.

This is P1 #6 in the `feat/dns-concurrency-limit` multi-client hardening roadmap and the last item on that branch before PR.

## Non-Goals

- No change to flush batch size (stays 500) or interval (stays 1s).
- No change to mpsc channel capacity (stays 10 000).
- No new CLI flags; no new observability endpoints.
- No connection pool / multiple readers; a single dedicated reader connection is sufficient for the target deployment size.

## Architecture

`Database` retains a single public struct holding **two** `tokio_rusqlite::Connection` instances:

- `write_conn` — the existing connection. Owns schema initialisation, migrations, and every `INSERT` / `UPDATE` / `DELETE`.
- `read_conn` — newly added. Opened with `rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | SQLITE_OPEN_NO_MUTEX | SQLITE_OPEN_URI` against the same DB file. Executes all pure-SELECT methods.

Open order in `Database::open`:

1. Open `write_conn`.
2. Run `init_schema` (sets `journal_mode = WAL`, `synchronous = NORMAL`, runs migrations).
3. Open `read_conn` — because `journal_mode = WAL` is persisted at the database file level, the read connection inherits it.
4. Set per-connection PRAGMAs on `read_conn`: `busy_timeout = 5000`, `cache_size = -20000`, `temp_store = MEMORY`. (`journal_mode` and `synchronous` are DB-file scope and do not need to be re-applied.)

If `read_conn` fails to open, `Database::open` returns the error. The service refuses to start; no silent fallback to single-connection mode.

## Method Routing

Routing rule: **pure `SELECT` goes to `read_conn`, everything else stays on `write_conn`.** Concretely:

### Methods routed to `read_conn`

- `list_tables`
- `get_setting`
- `query_logs`, `count_logs`, `earliest_log_timestamp`, `total_log_count`
- `count_queries_since`, `count_queries_multi_since`
- `cache_stats_since`, `cache_stats_multi_since`
- `top_domains_since`, `top_clients_since`, `top_upstreams_since`
- `timeline_since`, `timeline_multi_since`
- `hourly_heatmap_since`, `query_type_breakdown_since`, `outcome_breakdown_since`
- `unique_domains_since`, `latency_summary_since`
- `db_file_size`
- `get_filter_lists`, `get_filter_list_content`
- `has_custom_rule`, `get_all_custom_rules`, `get_custom_rules_by_type`
- `get_doh_tokens`, `validate_doh_token`, `has_doh_tokens`

### Methods staying on `write_conn`

- Schema: `init_schema`, `run_migrations`
- `set_setting`
- `insert_query_logs`, `delete_all_logs`, `prune_logs_before`
- `add_filter_list`, `update_filter_list`, `update_filter_list_enabled`, `update_filter_list_stats`, `delete_filter_list`
- `set_filter_list_content`
- `add_custom_rule`, `delete_custom_rule`
- `add_doh_token`, `delete_doh_token`

## Data Flow

Example: admin HTTP request for the dashboard timeline.

1. `GET /api/stats/timeline` arrives on the admin Axum router.
2. Handler calls `db.timeline_multi_since(since, bucket)`.
3. `timeline_multi_since` dispatches via `self.read_conn.call(...)`.
4. The SELECT runs on the read connection's background thread.
5. In parallel, the `QueryLogger` task calls `db.insert_query_logs(&buffer)`, which dispatches via `self.write_conn.call(...)` on the write connection's background thread.
6. WAL lets both proceed without blocking each other. The admin stats scan no longer delays log flush; log flush no longer delays the admin response.

## Error Handling

- `Database::open` returns the existing `DbError::Sqlite` if `read_conn` fails to open. Startup aborts. Justification: a half-initialised `Database` that silently funnels reads back through `write_conn` would re-introduce exactly the contention this change removes, while hiding it from operators.
- No new `DbError` variants. `tokio_rusqlite::Error` and `rusqlite::Error` propagate the same way for both connections.
- Attempts to execute write SQL via `read_conn` are rejected by SQLite (the connection is opened with `SQLITE_OPEN_READ_ONLY`). This is a defence-in-depth runtime guard; the primary guarantee is the routing discipline in the code itself.

## Testing

A new integration test file `tests/db_concurrency_test.rs` covers the concurrency behaviour. Existing tests (`tests/logger_test.rs`, `tests/integration_test.rs`, inline unit tests in `src/db.rs` if any) continue to pass without modification because `Database`'s public API is unchanged.

### `tests/db_concurrency_test.rs`

1. **smoke** — open `Database` against a fresh temp file, insert one `QueryLogEntry`, read it back via `query_logs`. Asserts that both connections are wired up and both can reach data written through the write connection.
2. **concurrent reads and writes** (core test) — open `Database` against a temp file, pre-populate ~10 000 rows via a single `insert_query_logs` call. Then concurrently:
   - **Writer task**: 10 iterations of `insert_query_logs` (500 rows each) with 10 ms sleep between iterations.
   - **Reader task**: 10 iterations of `latency_summary_since` (the heaviest window-function stats query).
   - Use `tokio::join!` to await both. Assert: both complete within 5 s wall clock, neither returns an error. The test does **not** assert a speedup target — that would be machine-dependent and flaky. The assertion is existence (both paths complete independently); speedup is the natural consequence of WAL reader–writer isolation.

## Files Changed

- `src/db.rs` — add `read_conn` field, `open_read_conn` helper, re-route read methods (~40 LOC net).
- `tests/db_concurrency_test.rs` — new file, ~80 LOC.

No frontend changes. No CLI flag changes. No changes to `ARCHITECTURE.md` (the document describes the async logger pattern at a level unaffected by this change).

## Roadmap Context

After this lands, the `feat/dns-concurrency-limit` branch will have all P0/P1 items complete:

- P0 #1–3: concurrency semaphore, real-client-IP admin rate limiter, log-drop counter
- P1 #4: per-IP DNS token-bucket rate limiter
- P1 #5: single-flight upstream coalescing
- P1 #6: this change — reader connection isolation

The branch is then ready to push and PR as one bundle (user preference per project memory).
