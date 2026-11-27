-- Seed the maintained row count; COUNT(*) walks a whole index. "WHERE true" stops
-- the parser reading ON CONFLICT as part of the SELECT.
INSERT INTO settings (key, value) SELECT 'query_log_count', COUNT(*) FROM query_logs WHERE true
    ON CONFLICT(key) DO UPDATE SET value = excluded.value;
