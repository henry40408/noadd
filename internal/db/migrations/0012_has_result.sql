-- A VIRTUAL generated column costs no table space, and the planner would not
-- treat an index on the bare expression as covering.
ALTER TABLE query_logs ADD COLUMN has_result INTEGER GENERATED ALWAYS AS (result IS NOT NULL AND result != '') VIRTUAL;
DROP INDEX IF EXISTS idx_query_logs_ts_metrics;
CREATE INDEX idx_query_logs_ts_metrics ON query_logs(timestamp, blocked, cached, response_ms, query_type, has_result);
ANALYZE;
