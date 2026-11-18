CREATE TABLE settings (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    );
CREATE TABLE query_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp INTEGER NOT NULL,
                        domain TEXT NOT NULL,
                        query_type TEXT NOT NULL,
                        client_ip TEXT NOT NULL,
                        blocked INTEGER NOT NULL DEFAULT 0,
                        cached INTEGER NOT NULL DEFAULT 0,
                        response_ms INTEGER NOT NULL DEFAULT 0,
                        upstream TEXT,
                        doh_token TEXT,
                        result TEXT,
                        authenticated_data INTEGER NOT NULL DEFAULT 0,
                        has_result INTEGER GENERATED ALWAYS AS (result IS NOT NULL AND result != '') VIRTUAL
                    );
CREATE TABLE sqlite_sequence(name,seq);
CREATE INDEX idx_query_logs_timestamp ON query_logs(timestamp);
CREATE INDEX idx_query_logs_domain_ts ON query_logs(domain, timestamp);
CREATE INDEX idx_query_logs_token_ts ON query_logs(doh_token, timestamp);
CREATE INDEX idx_query_logs_blocked_ts ON query_logs(blocked, timestamp);
CREATE INDEX idx_query_logs_type_blocked_ts ON query_logs(query_type, blocked, timestamp);
CREATE TABLE filter_lists (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        url TEXT NOT NULL,
                        enabled INTEGER NOT NULL DEFAULT 1,
                        last_updated INTEGER NOT NULL DEFAULT 0,
                        rule_count INTEGER NOT NULL DEFAULT 0
                    );
CREATE TABLE custom_rules (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        rule TEXT NOT NULL,
                        rule_type TEXT NOT NULL
                    );
CREATE TABLE filter_list_content (
                        list_id INTEGER PRIMARY KEY,
                        content TEXT NOT NULL
                    );
CREATE TABLE doh_tokens (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        token TEXT NOT NULL UNIQUE
                    );
CREATE TABLE users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL UNIQUE,
                        -- NO_PASSWORD_SENTINEL for forward-auth accounts.
                        password_hash TEXT NOT NULL,
                        created_at INTEGER NOT NULL
                    );
CREATE TABLE api_keys (
                        id           INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        name         TEXT    NOT NULL,
                        token_hash   TEXT    NOT NULL UNIQUE,
                        prefix       TEXT    NOT NULL,
                        created_at   INTEGER NOT NULL,
                        last_used_at INTEGER,
                        expires_at   INTEGER
                    );
CREATE INDEX idx_api_keys_user ON api_keys(user_id);
CREATE TABLE sqlite_stat1(tbl,idx,stat);
CREATE TABLE sqlite_stat4(tbl,idx,neq,nlt,ndlt,sample);
CREATE TABLE sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_hash TEXT NOT NULL UNIQUE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            ip TEXT,
            user_agent TEXT
        );
CREATE TABLE query_stats_quarter (
        quarter INTEGER NOT NULL,
        blocked INTEGER NOT NULL,
        cached INTEGER NOT NULL,
        count INTEGER NOT NULL,
        sum_ms INTEGER NOT NULL,
        PRIMARY KEY (quarter, blocked, cached)
    ) WITHOUT ROWID;
CREATE TABLE query_stats_domain_hour (
        hour INTEGER NOT NULL,
        domain TEXT NOT NULL,
        count INTEGER NOT NULL,
        PRIMARY KEY (hour, domain)
    ) WITHOUT ROWID;
CREATE TABLE query_stats_client_hour (
        hour INTEGER NOT NULL,
        client_ip TEXT NOT NULL,
        doh_token TEXT NOT NULL,
        count INTEGER NOT NULL,
        PRIMARY KEY (hour, client_ip, doh_token)
    ) WITHOUT ROWID;
CREATE TABLE query_stats_upstream_hour (
        hour INTEGER NOT NULL,
        upstream TEXT NOT NULL,
        count INTEGER NOT NULL,
        sum_ms INTEGER NOT NULL,
        PRIMARY KEY (hour, upstream)
    ) WITHOUT ROWID;
CREATE TABLE query_stats_metrics_hour (
        hour INTEGER NOT NULL,
        blocked INTEGER NOT NULL,
        cached INTEGER NOT NULL,
        has_result INTEGER NOT NULL,
        query_type TEXT NOT NULL,
        response_ms INTEGER NOT NULL,
        count INTEGER NOT NULL,
        PRIMARY KEY (hour, blocked, cached, has_result, query_type, response_ms)
    ) WITHOUT ROWID;
CREATE TRIGGER query_logs_maintain_stats AFTER INSERT ON query_logs BEGIN
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
