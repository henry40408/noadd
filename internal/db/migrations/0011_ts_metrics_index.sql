CREATE INDEX IF NOT EXISTS idx_query_logs_ts_metrics ON query_logs(timestamp, blocked, cached, response_ms, query_type);
ANALYZE;
