-- The schema of the first release, which stored user_version 4: this file stands
-- for versions 1 to 4, so there is no 0002, 0003 or 0004.

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS query_logs (
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
    result TEXT
);
CREATE INDEX IF NOT EXISTS idx_query_logs_timestamp ON query_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_query_logs_domain ON query_logs(domain);

CREATE TABLE IF NOT EXISTS filter_lists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    last_updated INTEGER NOT NULL DEFAULT 0,
    rule_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS custom_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule TEXT NOT NULL,
    rule_type TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS filter_list_content (
    list_id INTEGER PRIMARY KEY,
    content TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS doh_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL UNIQUE
);
