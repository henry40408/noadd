-- The statistics rollups and the trigger that maintains them on insert. See
-- ARCHITECTURE.md, Rollups, for the design.
CREATE TABLE IF NOT EXISTS query_stats_quarter (
    quarter INTEGER NOT NULL,
    blocked INTEGER NOT NULL,
    cached INTEGER NOT NULL,
    count INTEGER NOT NULL,
    sum_ms INTEGER NOT NULL,
    PRIMARY KEY (quarter, blocked, cached)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS query_stats_domain_hour (
    hour INTEGER NOT NULL,
    domain TEXT NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY (hour, domain)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS query_stats_client_hour (
    hour INTEGER NOT NULL,
    client_ip TEXT NOT NULL,
    doh_token TEXT NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY (hour, client_ip, doh_token)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS query_stats_upstream_hour (
    hour INTEGER NOT NULL,
    upstream TEXT NOT NULL,
    count INTEGER NOT NULL,
    sum_ms INTEGER NOT NULL,
    PRIMARY KEY (hour, upstream)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS query_stats_metrics_hour (
    hour INTEGER NOT NULL,
    blocked INTEGER NOT NULL,
    cached INTEGER NOT NULL,
    has_result INTEGER NOT NULL,
    query_type TEXT NOT NULL,
    response_ms INTEGER NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY (hour, blocked, cached, has_result, query_type, response_ms)
) WITHOUT ROWID;
CREATE TRIGGER IF NOT EXISTS query_logs_maintain_stats AFTER INSERT ON query_logs BEGIN
    INSERT INTO query_stats_quarter (quarter, blocked, cached, count, sum_ms)
        VALUES (NEW.timestamp / 900000, NEW.blocked, NEW.cached, 1, NEW.response_ms)
        ON CONFLICT DO UPDATE SET count = count + 1, sum_ms = sum_ms + excluded.sum_ms;
    INSERT INTO query_stats_domain_hour (hour, domain, count)
        VALUES (NEW.timestamp / 3600000, NEW.domain, 1)
        ON CONFLICT DO UPDATE SET count = count + 1;
    INSERT INTO query_stats_client_hour (hour, client_ip, doh_token, count)
        VALUES (NEW.timestamp / 3600000, NEW.client_ip, COALESCE(NEW.doh_token, ''), 1)
        ON CONFLICT DO UPDATE SET count = count + 1;
    INSERT INTO query_stats_upstream_hour (hour, upstream, count, sum_ms)
        SELECT NEW.timestamp / 3600000, NEW.upstream, 1, NEW.response_ms
        WHERE NEW.upstream IS NOT NULL
        ON CONFLICT DO UPDATE SET count = count + 1, sum_ms = sum_ms + excluded.sum_ms;
    INSERT INTO query_stats_metrics_hour
        (hour, blocked, cached, has_result, query_type, response_ms, count)
        VALUES (NEW.timestamp / 3600000, NEW.blocked, NEW.cached,
                NEW.result IS NOT NULL AND NEW.result != '',
                NEW.query_type, NEW.response_ms, 1)
        ON CONFLICT DO UPDATE SET count = count + 1;
END;

-- Fill the rollups from the existing query_logs. The upsert replaces rather than
-- adds, so running it again does not double a count.
INSERT INTO query_stats_quarter (quarter, blocked, cached, count, sum_ms)
    SELECT timestamp / 900000, blocked, cached, COUNT(*), SUM(response_ms)
    FROM query_logs WHERE true GROUP BY 1, 2, 3
    ON CONFLICT DO UPDATE SET count = excluded.count, sum_ms = excluded.sum_ms;
INSERT INTO query_stats_domain_hour (hour, domain, count)
    SELECT timestamp / 3600000, domain, COUNT(*)
    FROM query_logs WHERE true GROUP BY 1, 2
    ON CONFLICT DO UPDATE SET count = excluded.count;
INSERT INTO query_stats_client_hour (hour, client_ip, doh_token, count)
    SELECT timestamp / 3600000, client_ip, COALESCE(doh_token, ''), COUNT(*)
    FROM query_logs WHERE true GROUP BY 1, 2, 3
    ON CONFLICT DO UPDATE SET count = excluded.count;
INSERT INTO query_stats_upstream_hour (hour, upstream, count, sum_ms)
    SELECT timestamp / 3600000, upstream, COUNT(*), SUM(response_ms)
    FROM query_logs WHERE upstream IS NOT NULL GROUP BY 1, 2
    ON CONFLICT DO UPDATE SET count = excluded.count, sum_ms = excluded.sum_ms;
INSERT INTO query_stats_metrics_hour
    (hour, blocked, cached, has_result, query_type, response_ms, count)
    SELECT timestamp / 3600000, blocked, cached, result IS NOT NULL AND result != '',
           query_type, response_ms, COUNT(*)
    FROM query_logs WHERE true GROUP BY 1, 2, 3, 4, 5, 6
    ON CONFLICT DO UPDATE SET count = excluded.count;
