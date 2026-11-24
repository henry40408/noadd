Rust fixtures for the database port. Everything here was produced by the released Rust
image ghcr.io/henry40408/noadd:0.41.1 (linux/arm64, run under Docker; no cargo). Test
data only: every password and token below is public and must never be used elsewhere.

rust-v17.sqlite3  (PRAGMA user_version = 17, journal_mode WAL, single file, checkpointed)
  Built by the Rust binary over HTTP/DNS (capture scripts: $CLAUDE_JOB_DIR/tmp/noadd-capture,
  stage2.py). Not committed: the scripts. Rows per table (rust-v17.dump.json has the
  non-secret columns of every row; hashes are left out of the dump on purpose):
    settings 8, query_logs 201, filter_lists 5, filter_list_content 2, custom_rules 3,
    doh_tokens 2, users 3, sessions 1, api_keys 3, query_stats_quarter 3,
    query_stats_domain_hour 12, query_stats_client_hour 3, query_stats_upstream_hour 1,
    query_stats_metrics_hour 12.
  Operators (username / plaintext password):
    admin       / correct horse battery
    second      / another long passphrase 42
    cjk-user    / 這是一個很長的中文密碼測試用的密碼
  API keys: ci-expiring (expires_at 4102444800), ci-forever (expires_at NULL), ui-key (created
    through the SSR form, expires 2100-01-01).  Plaintext tokens: rustTokenVectors in ../../auth/password_test.go
    and $CLAUDE_JOB_DIR/tmp/noadd-capture/out/raw/info.json.
  DoH tokens: alpha-token, beta-token.
  Custom rules: ads.example.com (block), @@||ok.ads.example.com^ (allow), ||tracker.example.net^ (block).
  Lists: 1 and 2 are the seeded AdGuard/AdAway lists (disabled; seed 1 is enabled on a fresh DB and
    was disabled over the API), 3 "list one" and 4 "list two" (enabled, 3 rules each, last_updated set,
    URL http://host.docker.internal:18091/...), 5 "list three" (disabled, never fetched).
  Settings changed: upstream_servers=0.250.250.254:15353, upstream_strategy=sequential,
    block_mode=null_ip, log_retention_days=30, public_url=https://dns.example.test,
    doh_access_policy=allow. session_log_salt is random per database.
  query_logs: 201 rows over DoH (GET/POST, with and without a token, with and without EDNS), blocked 80,
    cached 111, doh_token NULL 100, result NULL 26. Timestamps are milliseconds. client_ip is the Docker
    bridge address 192.168.215.1. NULL combinations NOT covered: upstream NULL with cached=0 and
    blocked=0 (every forwarded row names the one fake upstream), rate-limited rows, a forward-auth
    account (users.password_hash = NO_PASSWORD_SENTINEL), a session without ip/user_agent.

rust-v0 / v4 / v8 / v15.sqlite3  (hand-written SQL, scripts: mk-legacy.sh)
  v0   schema batch of a fresh database (all tables but sessions) with user_version 0.
  v4   oldest shape Rust 0.41.1 can still open: query_logs has cached/doh_token/upstream/result but no
       authenticated_data/has_result, legacy idx_query_logs_domain, settings rows admin_password_hash
       and sessions (removed by migration 6).
  v8   users + sessions with the plaintext `token` column + api_keys.
  v15  hashed sessions, has_result, the v10-v15 statistics indexes, query_log_count, no rollups.
  Deviation from the plan: the plan asked for v0/v8/v15. A true pre-v1 database (user_version 0 with the
  original query_logs lacking doh_token) cannot be opened by Rust 0.41.1: the schema batch indexes
  doh_token before migrations run ("no such column: doh_token"). So v0 is the batch schema and v4 was
  added for the legacy-domain-index case.
  Each file was opened by the Rust binary (container started, then stopped): all four end at
  user_version 17 with a schema identical (pragma table_xinfo / index_xinfo) to rust-v17.sqlite3.
  rust-vN.migrated.dump.json is the non-secret content after that migration (legacy session rows are
  gone, rollups are backfilled from the surviving query_logs, query_log_count is rewritten).
  The legacy files have WAL journal mode; copy them to a t.TempDir() before opening.
