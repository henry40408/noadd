-- Statistics read the rollups, so the timestamp-first statistics indexes go. What
-- is left to index is the query log's filters. On large databases the freed pages
-- cross the vacuum threshold, so the first maintenance after upgrading rewrites
-- the file once.
DROP INDEX IF EXISTS idx_query_logs_ts_metrics;
DROP INDEX IF EXISTS idx_query_logs_ts_upstream;
DROP INDEX IF EXISTS idx_query_logs_ts_domain_client;
CREATE INDEX IF NOT EXISTS idx_query_logs_token_ts ON query_logs(doh_token, timestamp);
CREATE INDEX IF NOT EXISTS idx_query_logs_blocked_ts ON query_logs(blocked, timestamp);
CREATE INDEX IF NOT EXISTS idx_query_logs_type_blocked_ts ON query_logs(query_type, blocked, timestamp);
ANALYZE;
