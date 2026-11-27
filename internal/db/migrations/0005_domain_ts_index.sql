DROP INDEX IF EXISTS idx_query_logs_domain;
CREATE INDEX IF NOT EXISTS idx_query_logs_domain_ts ON query_logs(domain, timestamp);
-- ANALYZE is required after every index change: with stale sqlite_stat1 the
-- planner keeps the old plan.
ANALYZE;
