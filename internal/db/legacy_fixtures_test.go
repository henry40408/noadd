package db

// legacySQL builds the databases the migration tests open, keyed by the name
// the tests ask copyFixture for. The Rust server 0.41.1 opened these shapes and
// migrated them; rustMigratedDumps is what it left. The statements are the
// ones the legacy files held: sqlite_sequence follows from the explicit ids
// and sqlite_stat1 is written as the file held it.
var legacySQL = map[string]string{
	"rust-v0.sqlite3": `PRAGMA user_version = 0;
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO settings VALUES('block_mode','null_ip');
CREATE TABLE query_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, domain TEXT NOT NULL, query_type TEXT NOT NULL,
    client_ip TEXT NOT NULL, blocked INTEGER NOT NULL DEFAULT 0, cached INTEGER NOT NULL DEFAULT 0,
    response_ms INTEGER NOT NULL DEFAULT 0, upstream TEXT, doh_token TEXT, result TEXT,
    authenticated_data INTEGER NOT NULL DEFAULT 0,
    has_result INTEGER GENERATED ALWAYS AS (result IS NOT NULL AND result != '') VIRTUAL);
INSERT INTO query_logs VALUES(1,1794910000000,'a.test','A','10.0.0.1',1,0,0,NULL,NULL,'0.0.0.0',0);
INSERT INTO query_logs VALUES(2,1794910001000,'ok.example.com','AAAA','10.0.0.2',0,1,3,'1.1.1.1:53','legacy-token',NULL,1);
CREATE TABLE filter_lists (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, url TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1, last_updated INTEGER NOT NULL DEFAULT 0, rule_count INTEGER NOT NULL DEFAULT 0);
INSERT INTO filter_lists VALUES(1,'v0 list','http://example.test/a.txt',1,0,0);
CREATE TABLE custom_rules (id INTEGER PRIMARY KEY AUTOINCREMENT, rule TEXT NOT NULL, rule_type TEXT NOT NULL);
CREATE TABLE filter_list_content (list_id INTEGER PRIMARY KEY, content TEXT NOT NULL);
CREATE TABLE doh_tokens (id INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT NOT NULL UNIQUE);
CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE api_keys (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, prefix TEXT NOT NULL, created_at INTEGER NOT NULL, last_used_at INTEGER, expires_at INTEGER);
CREATE INDEX idx_query_logs_timestamp ON query_logs(timestamp);
CREATE INDEX idx_query_logs_domain_ts ON query_logs(domain, timestamp);
CREATE INDEX idx_query_logs_token_ts ON query_logs(doh_token, timestamp);
CREATE INDEX idx_query_logs_blocked_ts ON query_logs(blocked, timestamp);
CREATE INDEX idx_query_logs_type_blocked_ts ON query_logs(query_type, blocked, timestamp);
CREATE INDEX idx_api_keys_user ON api_keys(user_id);`,
	"rust-v4.sqlite3": `PRAGMA user_version = 4;
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO settings VALUES('block_mode','nxdomain');
INSERT INTO settings VALUES('admin_password_hash','$argon2id$legacy');
INSERT INTO settings VALUES('sessions','[]');
INSERT INTO settings VALUES('upstream_servers','1.1.1.1:53');
CREATE TABLE query_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, domain TEXT NOT NULL, query_type TEXT NOT NULL,
    client_ip TEXT NOT NULL, blocked INTEGER NOT NULL DEFAULT 0, cached INTEGER NOT NULL DEFAULT 0,
    response_ms INTEGER NOT NULL DEFAULT 0, upstream TEXT, doh_token TEXT, result TEXT);
INSERT INTO query_logs VALUES(1,1794910000000,'a.test','A','10.0.0.1',1,0,0,NULL,NULL,'0.0.0.0');
INSERT INTO query_logs VALUES(2,1794910001000,'ok.example.com','AAAA','10.0.0.2',0,1,12,'1.1.1.1:53','legacy-token',NULL);
INSERT INTO query_logs VALUES(3,1794913600000,'a.test','A','10.0.0.1',1,0,0,NULL,NULL,NULL);
CREATE TABLE filter_lists (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, url TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1, last_updated INTEGER NOT NULL DEFAULT 0, rule_count INTEGER NOT NULL DEFAULT 0);
INSERT INTO filter_lists VALUES(1,'legacy list','http://example.test/a.txt',1,1794910000,2);
INSERT INTO filter_lists VALUES(2,'off list','http://example.test/b.txt',0,0,0);
CREATE TABLE custom_rules (id INTEGER PRIMARY KEY AUTOINCREMENT, rule TEXT NOT NULL, rule_type TEXT NOT NULL);
INSERT INTO custom_rules VALUES(1,'ads.example.com','block');
INSERT INTO custom_rules VALUES(2,'@@||ok.example.com^','allow');
CREATE TABLE filter_list_content (list_id INTEGER PRIMARY KEY, content TEXT NOT NULL);
INSERT INTO filter_list_content VALUES(1,'0.0.0.0 a.test
0.0.0.0 b.test
');
CREATE TABLE doh_tokens (id INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT NOT NULL UNIQUE);
INSERT INTO doh_tokens VALUES(1,'legacy-token');
CREATE INDEX idx_query_logs_timestamp ON query_logs(timestamp);
CREATE INDEX idx_query_logs_domain ON query_logs(domain);`,
	"rust-v8.sqlite3": `PRAGMA user_version = 8;
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO settings VALUES('block_mode','null_ip');
INSERT INTO settings VALUES('dnssec_disabled','false');
CREATE TABLE query_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, domain TEXT NOT NULL, query_type TEXT NOT NULL,
    client_ip TEXT NOT NULL, blocked INTEGER NOT NULL DEFAULT 0, cached INTEGER NOT NULL DEFAULT 0,
    response_ms INTEGER NOT NULL DEFAULT 0, upstream TEXT, doh_token TEXT, result TEXT,
    authenticated_data INTEGER NOT NULL DEFAULT 0);
INSERT INTO query_logs VALUES(1,1794910000000,'a.test','A','10.0.0.1',1,0,0,NULL,NULL,'0.0.0.0',0);
INSERT INTO query_logs VALUES(2,1794910001000,'ok.example.com','AAAA','10.0.0.2',0,1,3,'1.1.1.1:53','legacy-token',NULL,1);
INSERT INTO query_logs VALUES(3,1794913600000,'ok.example.com','A','10.0.0.2',0,0,25,'9.9.9.9:53',NULL,'',0);
INSERT INTO query_logs VALUES(4,1794917200000,'a.test','MX','10.0.0.3',1,0,0,NULL,'legacy-token',NULL,0);
CREATE TABLE filter_lists (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, url TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1, last_updated INTEGER NOT NULL DEFAULT 0, rule_count INTEGER NOT NULL DEFAULT 0);
INSERT INTO filter_lists VALUES(1,'v8 list','http://example.test/a.txt',1,1794910000,2);
CREATE TABLE custom_rules (id INTEGER PRIMARY KEY AUTOINCREMENT, rule TEXT NOT NULL, rule_type TEXT NOT NULL);
INSERT INTO custom_rules VALUES(1,'ads.example.com','block');
CREATE TABLE filter_list_content (list_id INTEGER PRIMARY KEY, content TEXT NOT NULL);
INSERT INTO filter_list_content VALUES(1,'0.0.0.0 a.test
');
CREATE TABLE doh_tokens (id INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT NOT NULL UNIQUE);
INSERT INTO doh_tokens VALUES(1,'legacy-token');
CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at INTEGER NOT NULL);
INSERT INTO users VALUES(1,'admin','$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaA',1794910000);
INSERT INTO users VALUES(2,'op2','$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaA',1700000100);
CREATE TABLE sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL, ip TEXT, user_agent TEXT);
INSERT INTO sessions VALUES(1,'plaintext-session-token',1,1794910000,1700000500,'10.0.0.1','curl/8');
INSERT INTO sessions VALUES(2,'another-token',2,1700000100,1700000200,NULL,NULL);
CREATE TABLE api_keys (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, prefix TEXT NOT NULL, created_at INTEGER NOT NULL, last_used_at INTEGER, expires_at INTEGER);
INSERT INTO api_keys VALUES(1,1,'k1','h1','noadd_ab',1794910000,NULL,NULL);
INSERT INTO api_keys VALUES(2,1,'k2','h2','noadd_cd',1794910000,1700000300,1900000000);
ANALYZE sqlite_schema;
DROP TABLE IF EXISTS sqlite_stat4;
DELETE FROM sqlite_stat1;
INSERT INTO sqlite_stat1 VALUES('sessions','sqlite_autoindex_sessions_1','2 1');
INSERT INTO sqlite_stat1 VALUES('users','sqlite_autoindex_users_1','2 1');
INSERT INTO sqlite_stat1 VALUES('doh_tokens','sqlite_autoindex_doh_tokens_1','1 1');
INSERT INTO sqlite_stat1 VALUES('filter_list_content',NULL,'1');
INSERT INTO sqlite_stat1 VALUES('api_keys','idx_api_keys_user','2 2');
INSERT INTO sqlite_stat1 VALUES('api_keys','sqlite_autoindex_api_keys_1','2 1');
INSERT INTO sqlite_stat1 VALUES('custom_rules',NULL,'1');
INSERT INTO sqlite_stat1 VALUES('filter_lists',NULL,'1');
INSERT INTO sqlite_stat1 VALUES('settings','sqlite_autoindex_settings_1','2 1');
INSERT INTO sqlite_stat1 VALUES('query_logs','idx_query_logs_domain_ts','4 2 1');
INSERT INTO sqlite_stat1 VALUES('query_logs','idx_query_logs_timestamp','4 1');
CREATE INDEX idx_query_logs_timestamp ON query_logs(timestamp);
CREATE INDEX idx_query_logs_domain_ts ON query_logs(domain, timestamp);
CREATE INDEX idx_api_keys_user ON api_keys(user_id);`,
	"rust-v15.sqlite3": `PRAGMA user_version = 15;
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO settings VALUES('block_mode','refused');
INSERT INTO settings VALUES('dnssec_disabled','true');
INSERT INTO settings VALUES('query_log_count','5');
CREATE TABLE query_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, domain TEXT NOT NULL, query_type TEXT NOT NULL,
    client_ip TEXT NOT NULL, blocked INTEGER NOT NULL DEFAULT 0, cached INTEGER NOT NULL DEFAULT 0,
    response_ms INTEGER NOT NULL DEFAULT 0, upstream TEXT, doh_token TEXT, result TEXT,
    authenticated_data INTEGER NOT NULL DEFAULT 0,
    has_result INTEGER GENERATED ALWAYS AS (result IS NOT NULL AND result != '') VIRTUAL);
INSERT INTO query_logs VALUES(1,1794910000000,'a.test','A','10.0.0.1',1,0,0,NULL,NULL,'0.0.0.0',0);
INSERT INTO query_logs VALUES(2,1794910001000,'ok.example.com','AAAA','10.0.0.2',0,1,3,'1.1.1.1:53','legacy-token',NULL,1);
INSERT INTO query_logs VALUES(3,1794913600000,'ok.example.com','A','10.0.0.2',0,0,25,'9.9.9.9:53',NULL,'',0);
INSERT INTO query_logs VALUES(4,1794917200000,'a.test','MX','10.0.0.3',1,0,0,NULL,'legacy-token',NULL,0);
INSERT INTO query_logs VALUES(5,1794920800000,'b.test','A','10.0.0.1',1,0,0,NULL,NULL,'0.0.0.0',0);
CREATE TABLE filter_lists (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, url TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1, last_updated INTEGER NOT NULL DEFAULT 0, rule_count INTEGER NOT NULL DEFAULT 0);
INSERT INTO filter_lists VALUES(1,'v15 list','http://example.test/a.txt',1,1794910000,2);
INSERT INTO filter_lists VALUES(2,'v15 off','http://example.test/b.txt',0,0,0);
CREATE TABLE custom_rules (id INTEGER PRIMARY KEY AUTOINCREMENT, rule TEXT NOT NULL, rule_type TEXT NOT NULL);
INSERT INTO custom_rules VALUES(1,'ads.example.com','block');
INSERT INTO custom_rules VALUES(2,'@@||ok.example.com^','allow');
CREATE TABLE filter_list_content (list_id INTEGER PRIMARY KEY, content TEXT NOT NULL);
INSERT INTO filter_list_content VALUES(1,'0.0.0.0 a.test
');
CREATE TABLE doh_tokens (id INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT NOT NULL UNIQUE);
INSERT INTO doh_tokens VALUES(1,'legacy-token');
CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at INTEGER NOT NULL);
INSERT INTO users VALUES(1,'admin','$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaA',1794910000);
CREATE TABLE sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, token_hash TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL, ip TEXT, user_agent TEXT);
INSERT INTO sessions VALUES(1,'0123abcd',1,1794910000,1700000500,'10.0.0.1','curl/8');
CREATE TABLE api_keys (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, prefix TEXT NOT NULL, created_at INTEGER NOT NULL, last_used_at INTEGER, expires_at INTEGER);
INSERT INTO api_keys VALUES(1,1,'k1','h1','noadd_ab',1794910000,NULL,NULL);
ANALYZE sqlite_schema;
DROP TABLE IF EXISTS sqlite_stat4;
DELETE FROM sqlite_stat1;
INSERT INTO sqlite_stat1 VALUES('sessions','sqlite_autoindex_sessions_1','1 1');
INSERT INTO sqlite_stat1 VALUES('users','sqlite_autoindex_users_1','1 1');
INSERT INTO sqlite_stat1 VALUES('doh_tokens','sqlite_autoindex_doh_tokens_1','1 1');
INSERT INTO sqlite_stat1 VALUES('filter_list_content',NULL,'1');
INSERT INTO sqlite_stat1 VALUES('api_keys','idx_api_keys_user','1 1');
INSERT INTO sqlite_stat1 VALUES('api_keys','sqlite_autoindex_api_keys_1','1 1');
INSERT INTO sqlite_stat1 VALUES('custom_rules',NULL,'2');
INSERT INTO sqlite_stat1 VALUES('filter_lists',NULL,'2');
INSERT INTO sqlite_stat1 VALUES('settings','sqlite_autoindex_settings_1','3 1');
INSERT INTO sqlite_stat1 VALUES('query_logs','idx_query_logs_ts_domain_client','5 1 1 1 1');
INSERT INTO sqlite_stat1 VALUES('query_logs','idx_query_logs_ts_upstream','2 1 1 1');
INSERT INTO sqlite_stat1 VALUES('query_logs','idx_query_logs_ts_metrics','5 1 1 1 1 1 1');
INSERT INTO sqlite_stat1 VALUES('query_logs','idx_query_logs_domain_ts','5 2 1');
INSERT INTO sqlite_stat1 VALUES('query_logs','idx_query_logs_timestamp','5 1');
CREATE INDEX idx_query_logs_timestamp ON query_logs(timestamp);
CREATE INDEX idx_query_logs_domain_ts ON query_logs(domain, timestamp);
CREATE INDEX idx_query_logs_ts_metrics ON query_logs(timestamp, blocked, cached, response_ms, query_type, has_result);
CREATE INDEX idx_query_logs_ts_upstream ON query_logs(timestamp, upstream, response_ms) WHERE upstream IS NOT NULL;
CREATE INDEX idx_query_logs_ts_domain_client ON query_logs(timestamp, domain, client_ip, doh_token);
CREATE INDEX idx_api_keys_user ON api_keys(user_id);`,
}

// rustMigratedDumps is the non-secret content of each legacy database after
// the Rust server migrated it: user_version and, per table, columns and rows.
var rustMigratedDumps = map[string]string{
	"v0": `{"user_version":17,"tables":{"api_keys":{"columns":["id","user_id","name","prefix","created_at","last_used_at","expires_at"],
"rows":[]},
"custom_rules":{"columns":["id","rule","rule_type"],
"rows":[]},
"doh_tokens":{"columns":["id","token"],
"rows":[]},
"filter_list_content":{"columns":["list_id"],
"rows":[]},
"filter_lists":{"columns":["id","name","url","enabled","last_updated","rule_count"],
"rows":[[1,"v0 list","http://example.test/a.txt",1,0,0]]},
"query_logs":{"columns":["id","timestamp","domain","query_type","client_ip","blocked","cached","response_ms","upstream","doh_token","result","authenticated_data"],
"rows":[[1,1794910000000,"a.test","A","10.0.0.1",1,0,0,null,null,"0.0.0.0",0],[2,1794910001000,"ok.example.com","AAAA","10.0.0.2",0,1,3,"1.1.1.1:53","legacy-token",null,1]]},
"query_stats_client_hour":{"columns":["hour","client_ip","doh_token","count"],
"rows":[[498586,"10.0.0.1","",1],[498586,"10.0.0.2","legacy-token",1]]},
"query_stats_domain_hour":{"columns":["hour","domain","count"],
"rows":[[498586,"a.test",1],[498586,"ok.example.com",1]]},
"query_stats_metrics_hour":{"columns":["hour","blocked","cached","query_type","response_ms","count"],
"rows":[[498586,0,1,"AAAA",3,1],[498586,1,0,"A",0,1]]},
"query_stats_quarter":{"columns":["quarter","blocked","cached","count","sum_ms"],
"rows":[[1994344,0,1,1,3],[1994344,1,0,1,0]]},
"query_stats_upstream_hour":{"columns":["hour","upstream","count","sum_ms"],
"rows":[[498586,"1.1.1.1:53",1,3]]},
"sessions":{"columns":["id","user_id","created_at","last_seen","ip","user_agent"],
"rows":[]},
"settings":{"columns":["key","value"],
"rows":[["block_mode","null_ip"],["query_log_count","2"],["session_log_salt","c8662bf39286ba906cae53a6966cf88f"]]},
"users":{"columns":["id","username","created_at"],
"rows":[]}},
"indexes":["idx_api_keys_user","idx_query_logs_blocked_ts","idx_query_logs_domain_ts","idx_query_logs_timestamp","idx_query_logs_token_ts","idx_query_logs_type_blocked_ts"]}`,
	"v4": `{"user_version":17,"tables":{"api_keys":{"columns":["id","user_id","name","prefix","created_at","last_used_at","expires_at"],
"rows":[]},
"custom_rules":{"columns":["id","rule","rule_type"],
"rows":[[1,"ads.example.com","block"],[2,"@@||ok.example.com^","allow"]]},
"doh_tokens":{"columns":["id","token"],
"rows":[[1,"legacy-token"]]},
"filter_list_content":{"columns":["list_id"],
"rows":[[1]]},
"filter_lists":{"columns":["id","name","url","enabled","last_updated","rule_count"],
"rows":[[1,"legacy list","http://example.test/a.txt",1,1794910000,2],[2,"off list","http://example.test/b.txt",0,0,0]]},
"query_logs":{"columns":["id","timestamp","domain","query_type","client_ip","blocked","cached","response_ms","upstream","doh_token","result","authenticated_data"],
"rows":[[1,1794910000000,"a.test","A","10.0.0.1",1,0,0,null,null,"0.0.0.0",0],[2,1794910001000,"ok.example.com","AAAA","10.0.0.2",0,1,12,"1.1.1.1:53","legacy-token",null,0],[3,1794913600000,"a.test","A","10.0.0.1",1,0,0,null,null,null,0]]},
"query_stats_client_hour":{"columns":["hour","client_ip","doh_token","count"],
"rows":[[498586,"10.0.0.1","",1],[498586,"10.0.0.2","legacy-token",1],[498587,"10.0.0.1","",1]]},
"query_stats_domain_hour":{"columns":["hour","domain","count"],
"rows":[[498586,"a.test",1],[498586,"ok.example.com",1],[498587,"a.test",1]]},
"query_stats_metrics_hour":{"columns":["hour","blocked","cached","query_type","response_ms","count"],
"rows":[[498586,0,1,"AAAA",12,1],[498586,1,0,"A",0,1],[498587,1,0,"A",0,1]]},
"query_stats_quarter":{"columns":["quarter","blocked","cached","count","sum_ms"],
"rows":[[1994344,0,1,1,12],[1994344,1,0,1,0],[1994348,1,0,1,0]]},
"query_stats_upstream_hour":{"columns":["hour","upstream","count","sum_ms"],
"rows":[[498586,"1.1.1.1:53",1,12]]},
"sessions":{"columns":["id","user_id","created_at","last_seen","ip","user_agent"],
"rows":[]},
"settings":{"columns":["key","value"],
"rows":[["block_mode","nxdomain"],["query_log_count","3"],["session_log_salt","5f2c7d7adc7e67a2efcb25691a51708d"],["upstream_servers","1.1.1.1:53"]]},
"users":{"columns":["id","username","created_at"],
"rows":[]}},
"indexes":["idx_api_keys_user","idx_query_logs_blocked_ts","idx_query_logs_domain_ts","idx_query_logs_timestamp","idx_query_logs_token_ts","idx_query_logs_type_blocked_ts"]}`,
	"v8": `{"user_version":17,"tables":{"api_keys":{"columns":["id","user_id","name","prefix","created_at","last_used_at","expires_at"],
"rows":[[1,1,"k1","noadd_ab",1794910000,null,null],[2,1,"k2","noadd_cd",1794910000,1700000300,1900000000]]},
"custom_rules":{"columns":["id","rule","rule_type"],
"rows":[[1,"ads.example.com","block"]]},
"doh_tokens":{"columns":["id","token"],
"rows":[[1,"legacy-token"]]},
"filter_list_content":{"columns":["list_id"],
"rows":[[1]]},
"filter_lists":{"columns":["id","name","url","enabled","last_updated","rule_count"],
"rows":[[1,"v8 list","http://example.test/a.txt",1,1794910000,2]]},
"query_logs":{"columns":["id","timestamp","domain","query_type","client_ip","blocked","cached","response_ms","upstream","doh_token","result","authenticated_data"],
"rows":[[1,1794910000000,"a.test","A","10.0.0.1",1,0,0,null,null,"0.0.0.0",0],[2,1794910001000,"ok.example.com","AAAA","10.0.0.2",0,1,3,"1.1.1.1:53","legacy-token",null,1],[3,1794913600000,"ok.example.com","A","10.0.0.2",0,0,25,"9.9.9.9:53",null,"",0],[4,1794917200000,"a.test","MX","10.0.0.3",1,0,0,null,"legacy-token",null,0]]},
"query_stats_client_hour":{"columns":["hour","client_ip","doh_token","count"],
"rows":[[498586,"10.0.0.1","",1],[498586,"10.0.0.2","legacy-token",1],[498587,"10.0.0.2","",1],[498588,"10.0.0.3","legacy-token",1]]},
"query_stats_domain_hour":{"columns":["hour","domain","count"],
"rows":[[498586,"a.test",1],[498586,"ok.example.com",1],[498587,"ok.example.com",1],[498588,"a.test",1]]},
"query_stats_metrics_hour":{"columns":["hour","blocked","cached","query_type","response_ms","count"],
"rows":[[498586,0,1,"AAAA",3,1],[498586,1,0,"A",0,1],[498587,0,0,"A",25,1],[498588,1,0,"MX",0,1]]},
"query_stats_quarter":{"columns":["quarter","blocked","cached","count","sum_ms"],
"rows":[[1994344,0,1,1,3],[1994344,1,0,1,0],[1994348,0,0,1,25],[1994352,1,0,1,0]]},
"query_stats_upstream_hour":{"columns":["hour","upstream","count","sum_ms"],
"rows":[[498586,"1.1.1.1:53",1,3],[498587,"9.9.9.9:53",1,25]]},
"sessions":{"columns":["id","user_id","created_at","last_seen","ip","user_agent"],
"rows":[]},
"settings":{"columns":["key","value"],
"rows":[["block_mode","null_ip"],["dnssec_disabled","false"],["query_log_count","4"],["session_log_salt","3fe143cd1b72b53e4c0ed8cbf30228de"]]},
"users":{"columns":["id","username","created_at"],
"rows":[[1,"admin",1794910000],[2,"op2",1700000100]]}},
"indexes":["idx_api_keys_user","idx_query_logs_blocked_ts","idx_query_logs_domain_ts","idx_query_logs_timestamp","idx_query_logs_token_ts","idx_query_logs_type_blocked_ts"]}`,
	"v15": `{"user_version":17,"tables":{"api_keys":{"columns":["id","user_id","name","prefix","created_at","last_used_at","expires_at"],
"rows":[[1,1,"k1","noadd_ab",1794910000,null,null]]},
"custom_rules":{"columns":["id","rule","rule_type"],
"rows":[[1,"ads.example.com","block"],[2,"@@||ok.example.com^","allow"]]},
"doh_tokens":{"columns":["id","token"],
"rows":[[1,"legacy-token"]]},
"filter_list_content":{"columns":["list_id"],
"rows":[[1]]},
"filter_lists":{"columns":["id","name","url","enabled","last_updated","rule_count"],
"rows":[[1,"v15 list","http://example.test/a.txt",1,1794910000,2],[2,"v15 off","http://example.test/b.txt",0,0,0]]},
"query_logs":{"columns":["id","timestamp","domain","query_type","client_ip","blocked","cached","response_ms","upstream","doh_token","result","authenticated_data"],
"rows":[[1,1794910000000,"a.test","A","10.0.0.1",1,0,0,null,null,"0.0.0.0",0],[2,1794910001000,"ok.example.com","AAAA","10.0.0.2",0,1,3,"1.1.1.1:53","legacy-token",null,1],[3,1794913600000,"ok.example.com","A","10.0.0.2",0,0,25,"9.9.9.9:53",null,"",0],[4,1794917200000,"a.test","MX","10.0.0.3",1,0,0,null,"legacy-token",null,0],[5,1794920800000,"b.test","A","10.0.0.1",1,0,0,null,null,"0.0.0.0",0]]},
"query_stats_client_hour":{"columns":["hour","client_ip","doh_token","count"],
"rows":[[498586,"10.0.0.1","",1],[498586,"10.0.0.2","legacy-token",1],[498587,"10.0.0.2","",1],[498588,"10.0.0.3","legacy-token",1],[498589,"10.0.0.1","",1]]},
"query_stats_domain_hour":{"columns":["hour","domain","count"],
"rows":[[498586,"a.test",1],[498586,"ok.example.com",1],[498587,"ok.example.com",1],[498588,"a.test",1],[498589,"b.test",1]]},
"query_stats_metrics_hour":{"columns":["hour","blocked","cached","query_type","response_ms","count"],
"rows":[[498586,0,1,"AAAA",3,1],[498586,1,0,"A",0,1],[498587,0,0,"A",25,1],[498588,1,0,"MX",0,1],[498589,1,0,"A",0,1]]},
"query_stats_quarter":{"columns":["quarter","blocked","cached","count","sum_ms"],
"rows":[[1994344,0,1,1,3],[1994344,1,0,1,0],[1994348,0,0,1,25],[1994352,1,0,1,0],[1994356,1,0,1,0]]},
"query_stats_upstream_hour":{"columns":["hour","upstream","count","sum_ms"],
"rows":[[498586,"1.1.1.1:53",1,3],[498587,"9.9.9.9:53",1,25]]},
"sessions":{"columns":["id","user_id","created_at","last_seen","ip","user_agent"],
"rows":[]},
"settings":{"columns":["key","value"],
"rows":[["block_mode","refused"],["dnssec_disabled","true"],["query_log_count","5"],["session_log_salt","4386fdd1de5d8da1fdc472ce44f9e17f"]]},
"users":{"columns":["id","username","created_at"],
"rows":[[1,"admin",1794910000]]}},
"indexes":["idx_api_keys_user","idx_query_logs_blocked_ts","idx_query_logs_domain_ts","idx_query_logs_timestamp","idx_query_logs_token_ts","idx_query_logs_type_blocked_ts"]}`,
}
