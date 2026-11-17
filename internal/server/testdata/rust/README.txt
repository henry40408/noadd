HTTP responses recorded from the Rust image ghcr.io/henry40408/noadd:0.41.1 (api_*.json for /api and
DoH, pages_*.json for SSR pages and form posts). Each file: status, headers (date dropped, cookie values
replaced by <COOKIE>), body (JSON bodies have timestamps/latencies replaced by <TS>/<MS> and API key
secrets by <APIKEY>) or body_golden (path of the HTML golden) or body_b64.
State: rust-v17.sqlite3 (../../../db/testdata). Operator admin / correct horse battery.
Covered: every /api route with at least one success and, where applicable, an error; /api/stats/v2/*
with tz_offset, an unknown-parameter 400 and a bad-range 400; DoH 415/400/403 (bad token, deny policy);
static file ETag + 304; the first bytes of the SSE stream (events_head); mobileconfig full text and 404;
unauthenticated 401s; API-key bearer auth. openapi.json and docs.html are in ../../ (raw bytes).
registry-filters.json: the registry JSON that was live at capture time.
