-- Versions 10, 11, 12, 14 and 15 add indexes for statistics that now read the
-- rollups; version 17 drops them again.
CREATE INDEX IF NOT EXISTS idx_query_logs_client_ts ON query_logs(client_ip, doh_token, timestamp);
ANALYZE;
