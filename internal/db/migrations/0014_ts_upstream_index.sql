CREATE INDEX IF NOT EXISTS idx_query_logs_ts_upstream ON query_logs(timestamp, upstream, response_ms) WHERE upstream IS NOT NULL;
ANALYZE;
