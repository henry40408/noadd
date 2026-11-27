-- The domain index stays: the query log's domain search seeks it by prefix.
DROP INDEX IF EXISTS idx_query_logs_client_ts;
CREATE INDEX IF NOT EXISTS idx_query_logs_ts_domain_client ON query_logs(timestamp, domain, client_ip, doh_token);
ANALYZE;
