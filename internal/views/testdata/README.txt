Golden HTML of every SSR page, rendered by the Rust image ghcr.io/henry40408/noadd:0.41.1, then
normalised with normalize.json (RE2 regexes, applied in order; the Go test applies the same list to
its own output). Volatile parts replaced: timeago data-ts and "N seconds ago" text, API key secrets,
latency numbers, the version string. Captured with Host 127.0.0.1:19080 (shown in the status bar) and
client address 192.168.215.1 (Docker bridge; shown in the logs table), over plain HTTP.

Names: <page>_empty (fresh DB), <page>_data (rust-v17.sqlite3 state in ../../db/testdata), then
variants: logs_filtered/logs_wildcard/logs_bad_page, filters_edit/filters_test_*, registry_search,
registry_load_failed (registry host forced unreachable), account_confirm_delete, stats_30d,
flash_<name> (all nine flashes on the dashboard, plus the page that owns each flash),
login_error, setup_*_error*, settings_error, filters_*_error, account_*_error, account_api_key_created.
The registry pages used the live AdGuard registry; the exact JSON is
../../server/testdata/rust/registry-filters.json (66 filters). Feed it to the Go registry in tests.
Non-HTML responses (redirects, statuses, headers) are in ../../server/testdata/rust/pages_*.json.
