package db

// legacySQL builds the databases the tests open, keyed by the name the tests
// ask copyFixture for. rust-v17.sqlite3 is the database the Rust server 0.41.1
// wrote (over DoH, with two flows through the admin forms); the rest are
// hand-written older shapes that server opened and migrated, and
// rustMigratedDumps is what it left. The statements are the ones the files
// held: sqlite_sequence follows from the explicit ids, and the sqlite_stat
// rows are written as the files held them. In v17 the rollup rows are
// inserted before the trigger exists, so the trigger does not count them twice.
//
// v17 holds no row for these cases: upstream NULL with cached=0 and blocked=0,
// a rate-limited query, a forward-auth account (NO_PASSWORD_SENTINEL), a
// session without ip and user agent. The passwords and API tokens of its
// accounts are in rustPasswordVectors and rustTokenVectors (internal/auth).
//
// The older shapes: v0 is the schema batch of a fresh database without a
// version, which is refused (nothing says which migrations it has had); v4 is
// the oldest version that opens, with the legacy domain index and the
// admin_password_hash and sessions settings; v8 has users, api_keys and
// sessions with a plaintext token column; v15 has hashed sessions, has_result,
// query_log_count and no rollups.
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
	"rust-v17.sqlite3": `PRAGMA user_version = 17;
CREATE TABLE settings (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    );
INSERT INTO settings VALUES('query_log_count','201');
INSERT INTO settings VALUES('session_log_salt','757cc044f0b07c98e916ea38a87e2ebc');
INSERT INTO settings VALUES('block_mode','null_ip');
INSERT INTO settings VALUES('log_retention_days','30');
INSERT INTO settings VALUES('public_url','https://dns.example.test');
INSERT INTO settings VALUES('doh_access_policy','allow');
INSERT INTO settings VALUES('upstream_strategy','sequential');
INSERT INTO settings VALUES('upstream_servers','0.250.250.254:15353');
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
INSERT INTO query_logs VALUES(1,1794929367159,'allowed.example.com','A','192.168.215.1',0,0,1,'0.250.250.254:15353','alpha-token','93.184.216.34, 93.184.216.35',0);
INSERT INTO query_logs VALUES(2,1794929367162,'allowed.example.com','AAAA','192.168.215.1',0,0,1,'0.250.250.254:15353',NULL,'2001:db8::1',0);
INSERT INTO query_logs VALUES(3,1794929367164,'allowed.example.com','MX','192.168.215.1',0,0,0,'0.250.250.254:15353','beta-token','10 mail.example.com.',0);
INSERT INTO query_logs VALUES(4,1794929367166,'ads.example.com','A','192.168.215.1',1,0,0,NULL,NULL,'0.0.0.0',0);
INSERT INTO query_logs VALUES(5,1794929367167,'ads.example.com','AAAA','192.168.215.1',1,0,0,NULL,'alpha-token','::',0);
INSERT INTO query_logs VALUES(6,1794929367168,'tracker.example.net','A','192.168.215.1',1,0,0,NULL,NULL,'0.0.0.0',0);
INSERT INTO query_logs VALUES(7,1794929367169,'ads.list-one.test','A','192.168.215.1',1,0,0,NULL,'beta-token','0.0.0.0',0);
INSERT INTO query_logs VALUES(8,1794929367169,'adserver.list-two.test','A','192.168.215.1',1,0,0,NULL,NULL,'0.0.0.0',0);
INSERT INTO query_logs VALUES(9,1794929367171,'ok.list-two.test','A','192.168.215.1',0,0,0,'0.250.250.254:15353','alpha-token','198.51.100.1',0);
INSERT INTO query_logs VALUES(10,1794929367172,'nxd.example.com','A','192.168.215.1',0,0,0,'0.250.250.254:15353',NULL,NULL,0);
INSERT INTO query_logs VALUES(11,1794929367174,'nodata.example.com','A','192.168.215.1',0,0,0,'0.250.250.254:15353','beta-token',NULL,0);
INSERT INTO query_logs VALUES(12,1794929367175,'cname.example.com','A','192.168.215.1',0,0,0,'0.250.250.254:15353',NULL,'target.example.com., 192.0.2.7',0);
INSERT INTO query_logs VALUES(13,1794929367178,'dnssec.example.com','A','192.168.215.1',0,0,1,'0.250.250.254:15353','alpha-token','192.0.2.9',1);
INSERT INTO query_logs VALUES(14,1794929367180,'ok.ads.example.com','A','192.168.215.1',0,0,1,'0.250.250.254:15353',NULL,'198.51.100.1',0);
INSERT INTO query_logs VALUES(15,1794929367181,'telemetry.list-one.test','AAAA','192.168.215.1',1,0,0,NULL,'beta-token','::',0);
INSERT INTO query_logs VALUES(16,1794929367182,'allowed.example.com','A','192.168.215.1',0,1,0,NULL,NULL,'93.184.216.34, 93.184.216.35',0);
INSERT INTO query_logs VALUES(17,1794929367183,'allowed.example.com','AAAA','192.168.215.1',0,1,0,NULL,'alpha-token','2001:db8::1',0);
INSERT INTO query_logs VALUES(18,1794929367184,'allowed.example.com','MX','192.168.215.1',0,1,0,NULL,NULL,'10 mail.example.com.',0);
INSERT INTO query_logs VALUES(19,1794929367185,'ads.example.com','A','192.168.215.1',1,0,0,NULL,'beta-token','0.0.0.0',0);
INSERT INTO query_logs VALUES(20,1794929367186,'ads.example.com','AAAA','192.168.215.1',1,0,0,NULL,NULL,'::',0);
INSERT INTO query_logs VALUES(21,1794929367187,'tracker.example.net','A','192.168.215.1',1,0,0,NULL,'alpha-token','0.0.0.0',0);
INSERT INTO query_logs VALUES(22,1794929367188,'ads.list-one.test','A','192.168.215.1',1,0,0,NULL,NULL,'0.0.0.0',0);
INSERT INTO query_logs VALUES(23,1794929367188,'adserver.list-two.test','A','192.168.215.1',1,0,0,NULL,'beta-token','0.0.0.0',0);
INSERT INTO query_logs VALUES(24,1794929367189,'ok.list-two.test','A','192.168.215.1',0,1,0,NULL,NULL,'198.51.100.1',0);
INSERT INTO query_logs VALUES(25,1794929367190,'nxd.example.com','A','192.168.215.1',0,1,0,NULL,'alpha-token',NULL,0);
INSERT INTO query_logs VALUES(26,1794929367190,'nodata.example.com','A','192.168.215.1',0,1,0,NULL,NULL,NULL,0);
INSERT INTO query_logs VALUES(27,1794929367191,'cname.example.com','A','192.168.215.1',0,1,0,NULL,'beta-token','target.example.com., 192.0.2.7',0);
INSERT INTO query_logs VALUES(28,1794929367192,'dnssec.example.com','A','192.168.215.1',0,1,0,NULL,NULL,'192.0.2.9',1);
INSERT INTO query_logs VALUES(29,1794929367192,'ok.ads.example.com','A','192.168.215.1',0,1,0,NULL,'alpha-token','198.51.100.1',0);
INSERT INTO query_logs VALUES(30,1794929367193,'telemetry.list-one.test','AAAA','192.168.215.1',1,0,0,NULL,NULL,'::',0);
INSERT INTO query_logs VALUES(31,1794929367194,'allowed.example.com','A','192.168.215.1',0,1,0,NULL,'beta-token','93.184.216.34, 93.184.216.35',0);
INSERT INTO query_logs VALUES(32,1794929367194,'allowed.example.com','AAAA','192.168.215.1',0,1,0,NULL,NULL,'2001:db8::1',0);
INSERT INTO query_logs VALUES(33,1794929367195,'allowed.example.com','MX','192.168.215.1',0,1,0,NULL,'alpha-token','10 mail.example.com.',0);
INSERT INTO query_logs VALUES(34,1794929367195,'ads.example.com','A','192.168.215.1',1,0,0,NULL,NULL,'0.0.0.0',0);
INSERT INTO query_logs VALUES(35,1794929367196,'ads.example.com','AAAA','192.168.215.1',1,0,0,NULL,'beta-token','::',0);
INSERT INTO query_logs VALUES(36,1794929367196,'tracker.example.net','A','192.168.215.1',1,0,0,NULL,NULL,'0.0.0.0',0);
INSERT INTO query_logs VALUES(37,1794929367197,'ads.list-one.test','A','192.168.215.1',1,0,0,NULL,'alpha-token','0.0.0.0',0);
INSERT INTO query_logs VALUES(38,1794929367197,'adserver.list-two.test','A','192.168.215.1',1,0,0,NULL,NULL,'0.0.0.0',0);
INSERT INTO query_logs VALUES(39,1794929367198,'ok.list-two.test','A','192.168.215.1',0,1,0,NULL,'beta-token','198.51.100.1',0);
INSERT INTO query_logs VALUES(40,1794929367198,'nxd.example.com','A','192.168.215.1',0,1,0,NULL,NULL,NULL,0);
INSERT INTO query_logs VALUES(41,1794929367199,'nodata.example.com','A','192.168.215.1',0,1,0,NULL,'alpha-token',NULL,0);
INSERT INTO query_logs VALUES(42,1794929367200,'cname.example.com','A','192.168.215.1',0,1,0,NULL,NULL,'target.example.com., 192.0.2.7',0);
INSERT INTO query_logs VALUES(43,1794929367200,'dnssec.example.com','A','192.168.215.1',0,1,0,NULL,'beta-token','192.0.2.9',1);
INSERT INTO query_logs VALUES(44,1794929367201,'ok.ads.example.com','A','192.168.215.1',0,1,0,NULL,NULL,'198.51.100.1',0);
INSERT INTO query_logs VALUES(45,1794929367201,'telemetry.list-one.test','AAAA','192.168.215.1',1,0,0,NULL,'alpha-token','::',0);
INSERT INTO query_logs VALUES(46,1794929367202,'allowed.example.com','A','192.168.215.1',0,1,0,NULL,NULL,'93.184.216.34, 93.184.216.35',0);
INSERT INTO query_logs VALUES(47,1794929367202,'allowed.example.com','AAAA','192.168.215.1',0,1,0,NULL,'beta-token','2001:db8::1',0);
INSERT INTO query_logs VALUES(48,1794929367203,'allowed.example.com','MX','192.168.215.1',0,1,0,NULL,NULL,'10 mail.example.com.',0);
INSERT INTO query_logs VALUES(49,1794929367203,'ads.example.com','A','192.168.215.1',1,0,0,NULL,'alpha-token','0.0.0.0',0);
INSERT INTO query_logs VALUES(50,1794929367203,'ads.example.com','AAAA','192.168.215.1',1,0,0,NULL,NULL,'::',0);
INSERT INTO query_logs VALUES(51,1794929367204,'tracker.example.net','A','192.168.215.1',1,0,0,NULL,'beta-token','0.0.0.0',0);
INSERT INTO query_logs VALUES(52,1794929367204,'ads.list-one.test','A','192.168.215.1',1,0,0,NULL,NULL,'0.0.0.0',0);
INSERT INTO query_logs VALUES(53,1794929367205,'adserver.list-two.test','A','192.168.215.1',1,0,0,NULL,'alpha-token','0.0.0.0',0);
INSERT INTO query_logs VALUES(54,1794929367205,'ok.list-two.test','A','192.168.215.1',0,1,0,NULL,NULL,'198.51.100.1',0);
INSERT INTO query_logs VALUES(55,1794929367206,'nxd.example.com','A','192.168.215.1',0,1,0,NULL,'beta-token',NULL,0);
INSERT INTO query_logs VALUES(56,1794929367206,'nodata.example.com','A','192.168.215.1',0,1,0,NULL,NULL,NULL,0);
INSERT INTO query_logs VALUES(57,1794929367207,'cname.example.com','A','192.168.215.1',0,1,0,NULL,'alpha-token','target.example.com., 192.0.2.7',0);
INSERT INTO query_logs VALUES(58,1794929367208,'dnssec.example.com','A','192.168.215.1',0,1,0,NULL,NULL,'192.0.2.9',1);
INSERT INTO query_logs VALUES(59,1794929367208,'ok.ads.example.com','A','192.168.215.1',0,1,0,NULL,'beta-token','198.51.100.1',0);
INSERT INTO query_logs VALUES(60,1794929367209,'telemetry.list-one.test','AAAA','192.168.215.1',1,0,0,NULL,NULL,'::',0);
INSERT INTO query_logs VALUES(61,1794929367209,'allowed.example.com','A','192.168.215.1',0,1,0,NULL,'alpha-token','93.184.216.34, 93.184.216.35',0);
INSERT INTO query_logs VALUES(62,1794929367210,'allowed.example.com','AAAA','192.168.215.1',0,1,0,NULL,NULL,'2001:db8::1',0);
INSERT INTO query_logs VALUES(63,1794929367210,'allowed.example.com','MX','192.168.215.1',0,1,0,NULL,'beta-token','10 mail.example.com.',0);
INSERT INTO query_logs VALUES(64,1794929367211,'ads.example.com','A','192.168.215.1',1,0,0,NULL,NULL,'0.0.0.0',0);
INSERT INTO query_logs VALUES(65,1794929367211,'ads.example.com','AAAA','192.168.215.1',1,0,0,NULL,'alpha-token','::',0);
INSERT INTO query_logs VALUES(66,1794929367212,'tracker.example.net','A','192.168.215.1',1,0,0,NULL,NULL,'0.0.0.0',0);
INSERT INTO query_logs VALUES(67,1794929367212,'ads.list-one.test','A','192.168.215.1',1,0,0,NULL,'beta-token','0.0.0.0',0);
INSERT INTO query_logs VALUES(68,1794929367213,'adserver.list-two.test','A','192.168.215.1',1,0,0,NULL,NULL,'0.0.0.0',0);
INSERT INTO query_logs VALUES(69,1794929367213,'ok.list-two.test','A','192.168.215.1',0,1,0,NULL,'alpha-token','198.51.100.1',0);
INSERT INTO query_logs VALUES(70,1794929367214,'nxd.example.com','A','192.168.215.1',0,1,0,NULL,NULL,NULL,0);
INSERT INTO query_logs VALUES(71,1794929367214,'nodata.example.com','A','192.168.215.1',0,1,0,NULL,'beta-token',NULL,0);
INSERT INTO query_logs VALUES(72,1794929367214,'cname.example.com','A','192.168.215.1',0,1,0,NULL,NULL,'target.example.com., 192.0.2.7',0);
INSERT INTO query_logs VALUES(73,1794929367215,'dnssec.example.com','A','192.168.215.1',0,1,0,NULL,'alpha-token','192.0.2.9',1);
INSERT INTO query_logs VALUES(74,1794929367215,'ok.ads.example.com','A','192.168.215.1',0,1,0,NULL,NULL,'198.51.100.1',0);
INSERT INTO query_logs VALUES(75,1794929367216,'telemetry.list-one.test','AAAA','192.168.215.1',1,0,0,NULL,'beta-token','::',0);
INSERT INTO query_logs VALUES(76,1794929367216,'allowed.example.com','A','192.168.215.1',0,1,0,NULL,NULL,'93.184.216.34, 93.184.216.35',0);
INSERT INTO query_logs VALUES(77,1794929367217,'allowed.example.com','AAAA','192.168.215.1',0,1,0,NULL,'alpha-token','2001:db8::1',0);
INSERT INTO query_logs VALUES(78,1794929367217,'allowed.example.com','MX','192.168.215.1',0,1,0,NULL,NULL,'10 mail.example.com.',0);
INSERT INTO query_logs VALUES(79,1794929367218,'ads.example.com','A','192.168.215.1',1,0,0,NULL,'beta-token','0.0.0.0',0);
INSERT INTO query_logs VALUES(80,1794929367218,'ads.example.com','AAAA','192.168.215.1',1,0,0,NULL,NULL,'::',0);
INSERT INTO query_logs VALUES(81,1794929367219,'tracker.example.net','A','192.168.215.1',1,0,0,NULL,'alpha-token','0.0.0.0',0);
INSERT INTO query_logs VALUES(82,1794929367219,'ads.list-one.test','A','192.168.215.1',1,0,0,NULL,NULL,'0.0.0.0',0);
INSERT INTO query_logs VALUES(83,1794929367220,'adserver.list-two.test','A','192.168.215.1',1,0,0,NULL,'beta-token','0.0.0.0',0);
INSERT INTO query_logs VALUES(84,1794929367220,'ok.list-two.test','A','192.168.215.1',0,1,0,NULL,NULL,'198.51.100.1',0);
INSERT INTO query_logs VALUES(85,1794929367221,'nxd.example.com','A','192.168.215.1',0,1,0,NULL,'alpha-token',NULL,0);
INSERT INTO query_logs VALUES(86,1794929367221,'nodata.example.com','A','192.168.215.1',0,1,0,NULL,NULL,NULL,0);
INSERT INTO query_logs VALUES(87,1794929367222,'cname.example.com','A','192.168.215.1',0,1,0,NULL,'beta-token','target.example.com., 192.0.2.7',0);
INSERT INTO query_logs VALUES(88,1794929367222,'dnssec.example.com','A','192.168.215.1',0,1,0,NULL,NULL,'192.0.2.9',1);
INSERT INTO query_logs VALUES(89,1794929367223,'ok.ads.example.com','A','192.168.215.1',0,1,0,NULL,'alpha-token','198.51.100.1',0);
INSERT INTO query_logs VALUES(90,1794929367223,'telemetry.list-one.test','AAAA','192.168.215.1',1,0,0,NULL,NULL,'::',0);
INSERT INTO query_logs VALUES(91,1794929367224,'allowed.example.com','A','192.168.215.1',0,1,0,NULL,'beta-token','93.184.216.34, 93.184.216.35',0);
INSERT INTO query_logs VALUES(92,1794929367224,'allowed.example.com','AAAA','192.168.215.1',0,1,0,NULL,NULL,'2001:db8::1',0);
INSERT INTO query_logs VALUES(93,1794929367225,'allowed.example.com','MX','192.168.215.1',0,1,0,NULL,'alpha-token','10 mail.example.com.',0);
INSERT INTO query_logs VALUES(94,1794929367226,'ads.example.com','A','192.168.215.1',1,0,0,NULL,NULL,'0.0.0.0',0);
INSERT INTO query_logs VALUES(95,1794929367226,'ads.example.com','AAAA','192.168.215.1',1,0,0,NULL,'beta-token','::',0);
INSERT INTO query_logs VALUES(96,1794929367226,'tracker.example.net','A','192.168.215.1',1,0,0,NULL,NULL,'0.0.0.0',0);
INSERT INTO query_logs VALUES(97,1794929367227,'ads.list-one.test','A','192.168.215.1',1,0,0,NULL,'alpha-token','0.0.0.0',0);
INSERT INTO query_logs VALUES(98,1794929367227,'adserver.list-two.test','A','192.168.215.1',1,0,0,NULL,NULL,'0.0.0.0',0);
INSERT INTO query_logs VALUES(99,1794929367228,'ok.list-two.test','A','192.168.215.1',0,1,0,NULL,'beta-token','198.51.100.1',0);
INSERT INTO query_logs VALUES(100,1794929367228,'nxd.example.com','A','192.168.215.1',0,1,0,NULL,NULL,NULL,0);
INSERT INTO query_logs VALUES(101,1794929367229,'nodata.example.com','A','192.168.215.1',0,1,0,NULL,'alpha-token',NULL,0);
INSERT INTO query_logs VALUES(102,1794929367229,'cname.example.com','A','192.168.215.1',0,1,0,NULL,NULL,'target.example.com., 192.0.2.7',0);
INSERT INTO query_logs VALUES(103,1794929367230,'dnssec.example.com','A','192.168.215.1',0,1,0,NULL,'beta-token','192.0.2.9',1);
INSERT INTO query_logs VALUES(104,1794929367230,'ok.ads.example.com','A','192.168.215.1',0,1,0,NULL,NULL,'198.51.100.1',0);
INSERT INTO query_logs VALUES(105,1794929367231,'telemetry.list-one.test','AAAA','192.168.215.1',1,0,0,NULL,'alpha-token','::',0);
INSERT INTO query_logs VALUES(106,1794929367231,'allowed.example.com','A','192.168.215.1',0,1,0,NULL,NULL,'93.184.216.34, 93.184.216.35',0);
INSERT INTO query_logs VALUES(107,1794929367232,'allowed.example.com','AAAA','192.168.215.1',0,1,0,NULL,'beta-token','2001:db8::1',0);
INSERT INTO query_logs VALUES(108,1794929367232,'allowed.example.com','MX','192.168.215.1',0,1,0,NULL,NULL,'10 mail.example.com.',0);
INSERT INTO query_logs VALUES(109,1794929367232,'ads.example.com','A','192.168.215.1',1,0,0,NULL,'alpha-token','0.0.0.0',0);
INSERT INTO query_logs VALUES(110,1794929367233,'ads.example.com','AAAA','192.168.215.1',1,0,0,NULL,NULL,'::',0);
INSERT INTO query_logs VALUES(111,1794929367233,'tracker.example.net','A','192.168.215.1',1,0,0,NULL,'beta-token','0.0.0.0',0);
INSERT INTO query_logs VALUES(112,1794929367234,'ads.list-one.test','A','192.168.215.1',1,0,0,NULL,NULL,'0.0.0.0',0);
INSERT INTO query_logs VALUES(113,1794929367234,'adserver.list-two.test','A','192.168.215.1',1,0,0,NULL,'alpha-token','0.0.0.0',0);
INSERT INTO query_logs VALUES(114,1794929367234,'ok.list-two.test','A','192.168.215.1',0,1,0,NULL,NULL,'198.51.100.1',0);
INSERT INTO query_logs VALUES(115,1794929367235,'nxd.example.com','A','192.168.215.1',0,1,0,NULL,'beta-token',NULL,0);
INSERT INTO query_logs VALUES(116,1794929367235,'nodata.example.com','A','192.168.215.1',0,1,0,NULL,NULL,NULL,0);
INSERT INTO query_logs VALUES(117,1794929367236,'cname.example.com','A','192.168.215.1',0,1,0,NULL,'alpha-token','target.example.com., 192.0.2.7',0);
INSERT INTO query_logs VALUES(118,1794929367236,'dnssec.example.com','A','192.168.215.1',0,1,0,NULL,NULL,'192.0.2.9',1);
INSERT INTO query_logs VALUES(119,1794929367236,'ok.ads.example.com','A','192.168.215.1',0,1,0,NULL,'beta-token','198.51.100.1',0);
INSERT INTO query_logs VALUES(120,1794929367237,'telemetry.list-one.test','AAAA','192.168.215.1',1,0,0,NULL,NULL,'::',0);
INSERT INTO query_logs VALUES(121,1794929367237,'allowed.example.com','A','192.168.215.1',0,1,0,NULL,'alpha-token','93.184.216.34, 93.184.216.35',0);
INSERT INTO query_logs VALUES(122,1794929367238,'allowed.example.com','AAAA','192.168.215.1',0,1,0,NULL,NULL,'2001:db8::1',0);
INSERT INTO query_logs VALUES(123,1794929367238,'allowed.example.com','MX','192.168.215.1',0,1,0,NULL,'beta-token','10 mail.example.com.',0);
INSERT INTO query_logs VALUES(124,1794929367239,'ads.example.com','A','192.168.215.1',1,0,0,NULL,NULL,'0.0.0.0',0);
INSERT INTO query_logs VALUES(125,1794929367239,'ads.example.com','AAAA','192.168.215.1',1,0,0,NULL,'alpha-token','::',0);
INSERT INTO query_logs VALUES(126,1794929367239,'tracker.example.net','A','192.168.215.1',1,0,0,NULL,NULL,'0.0.0.0',0);
INSERT INTO query_logs VALUES(127,1794929367240,'ads.list-one.test','A','192.168.215.1',1,0,0,NULL,'beta-token','0.0.0.0',0);
INSERT INTO query_logs VALUES(128,1794929367240,'adserver.list-two.test','A','192.168.215.1',1,0,0,NULL,NULL,'0.0.0.0',0);
INSERT INTO query_logs VALUES(129,1794929367240,'ok.list-two.test','A','192.168.215.1',0,1,0,NULL,'alpha-token','198.51.100.1',0);
INSERT INTO query_logs VALUES(130,1794929367241,'nxd.example.com','A','192.168.215.1',0,1,0,NULL,NULL,NULL,0);
INSERT INTO query_logs VALUES(131,1794929367241,'nodata.example.com','A','192.168.215.1',0,1,0,NULL,'beta-token',NULL,0);
INSERT INTO query_logs VALUES(132,1794929367242,'cname.example.com','A','192.168.215.1',0,1,0,NULL,NULL,'target.example.com., 192.0.2.7',0);
INSERT INTO query_logs VALUES(133,1794929367242,'dnssec.example.com','A','192.168.215.1',0,1,0,NULL,'alpha-token','192.0.2.9',1);
INSERT INTO query_logs VALUES(134,1794929367242,'ok.ads.example.com','A','192.168.215.1',0,1,0,NULL,NULL,'198.51.100.1',0);
INSERT INTO query_logs VALUES(135,1794929367243,'telemetry.list-one.test','AAAA','192.168.215.1',1,0,0,NULL,'beta-token','::',0);
INSERT INTO query_logs VALUES(136,1794929367243,'allowed.example.com','A','192.168.215.1',0,1,0,NULL,NULL,'93.184.216.34, 93.184.216.35',0);
INSERT INTO query_logs VALUES(137,1794929367243,'allowed.example.com','AAAA','192.168.215.1',0,1,0,NULL,'alpha-token','2001:db8::1',0);
INSERT INTO query_logs VALUES(138,1794929367244,'allowed.example.com','MX','192.168.215.1',0,1,0,NULL,NULL,'10 mail.example.com.',0);
INSERT INTO query_logs VALUES(139,1794929367244,'ads.example.com','A','192.168.215.1',1,0,0,NULL,'beta-token','0.0.0.0',0);
INSERT INTO query_logs VALUES(140,1794929367244,'ads.example.com','AAAA','192.168.215.1',1,0,0,NULL,NULL,'::',0);
INSERT INTO query_logs VALUES(141,1794929367245,'tracker.example.net','A','192.168.215.1',1,0,0,NULL,'alpha-token','0.0.0.0',0);
INSERT INTO query_logs VALUES(142,1794929367245,'ads.list-one.test','A','192.168.215.1',1,0,0,NULL,NULL,'0.0.0.0',0);
INSERT INTO query_logs VALUES(143,1794929367245,'adserver.list-two.test','A','192.168.215.1',1,0,0,NULL,'beta-token','0.0.0.0',0);
INSERT INTO query_logs VALUES(144,1794929367246,'ok.list-two.test','A','192.168.215.1',0,1,0,NULL,NULL,'198.51.100.1',0);
INSERT INTO query_logs VALUES(145,1794929367246,'nxd.example.com','A','192.168.215.1',0,1,0,NULL,'alpha-token',NULL,0);
INSERT INTO query_logs VALUES(146,1794929367247,'nodata.example.com','A','192.168.215.1',0,1,0,NULL,NULL,NULL,0);
INSERT INTO query_logs VALUES(147,1794929367247,'cname.example.com','A','192.168.215.1',0,1,0,NULL,'beta-token','target.example.com., 192.0.2.7',0);
INSERT INTO query_logs VALUES(148,1794929367247,'dnssec.example.com','A','192.168.215.1',0,1,0,NULL,NULL,'192.0.2.9',1);
INSERT INTO query_logs VALUES(149,1794929367248,'ok.ads.example.com','A','192.168.215.1',0,1,0,NULL,'alpha-token','198.51.100.1',0);
INSERT INTO query_logs VALUES(150,1794929367248,'telemetry.list-one.test','AAAA','192.168.215.1',1,0,0,NULL,NULL,'::',0);
INSERT INTO query_logs VALUES(151,1794929367248,'allowed.example.com','A','192.168.215.1',0,1,0,NULL,'beta-token','93.184.216.34, 93.184.216.35',0);
INSERT INTO query_logs VALUES(152,1794929367249,'allowed.example.com','AAAA','192.168.215.1',0,1,0,NULL,NULL,'2001:db8::1',0);
INSERT INTO query_logs VALUES(153,1794929367249,'allowed.example.com','MX','192.168.215.1',0,1,0,NULL,'alpha-token','10 mail.example.com.',0);
INSERT INTO query_logs VALUES(154,1794929367250,'ads.example.com','A','192.168.215.1',1,0,0,NULL,NULL,'0.0.0.0',0);
INSERT INTO query_logs VALUES(155,1794929367250,'ads.example.com','AAAA','192.168.215.1',1,0,0,NULL,'beta-token','::',0);
INSERT INTO query_logs VALUES(156,1794929367250,'tracker.example.net','A','192.168.215.1',1,0,0,NULL,NULL,'0.0.0.0',0);
INSERT INTO query_logs VALUES(157,1794929367251,'ads.list-one.test','A','192.168.215.1',1,0,0,NULL,'alpha-token','0.0.0.0',0);
INSERT INTO query_logs VALUES(158,1794929367251,'adserver.list-two.test','A','192.168.215.1',1,0,0,NULL,NULL,'0.0.0.0',0);
INSERT INTO query_logs VALUES(159,1794929367251,'ok.list-two.test','A','192.168.215.1',0,1,0,NULL,'beta-token','198.51.100.1',0);
INSERT INTO query_logs VALUES(160,1794929367252,'nxd.example.com','A','192.168.215.1',0,1,0,NULL,NULL,NULL,0);
INSERT INTO query_logs VALUES(161,1794929367252,'nodata.example.com','A','192.168.215.1',0,1,0,NULL,'alpha-token',NULL,0);
INSERT INTO query_logs VALUES(162,1794929367253,'cname.example.com','A','192.168.215.1',0,1,0,NULL,NULL,'target.example.com., 192.0.2.7',0);
INSERT INTO query_logs VALUES(163,1794929367253,'dnssec.example.com','A','192.168.215.1',0,1,0,NULL,'beta-token','192.0.2.9',1);
INSERT INTO query_logs VALUES(164,1794929367253,'ok.ads.example.com','A','192.168.215.1',0,1,0,NULL,NULL,'198.51.100.1',0);
INSERT INTO query_logs VALUES(165,1794929367254,'telemetry.list-one.test','AAAA','192.168.215.1',1,0,0,NULL,'alpha-token','::',0);
INSERT INTO query_logs VALUES(166,1794929367254,'allowed.example.com','A','192.168.215.1',0,1,0,NULL,NULL,'93.184.216.34, 93.184.216.35',0);
INSERT INTO query_logs VALUES(167,1794929367254,'allowed.example.com','AAAA','192.168.215.1',0,1,0,NULL,'beta-token','2001:db8::1',0);
INSERT INTO query_logs VALUES(168,1794929367255,'allowed.example.com','MX','192.168.215.1',0,1,0,NULL,NULL,'10 mail.example.com.',0);
INSERT INTO query_logs VALUES(169,1794929367255,'ads.example.com','A','192.168.215.1',1,0,0,NULL,'alpha-token','0.0.0.0',0);
INSERT INTO query_logs VALUES(170,1794929367255,'ads.example.com','AAAA','192.168.215.1',1,0,0,NULL,NULL,'::',0);
INSERT INTO query_logs VALUES(171,1794929367256,'tracker.example.net','A','192.168.215.1',1,0,0,NULL,'beta-token','0.0.0.0',0);
INSERT INTO query_logs VALUES(172,1794929367256,'ads.list-one.test','A','192.168.215.1',1,0,0,NULL,NULL,'0.0.0.0',0);
INSERT INTO query_logs VALUES(173,1794929367256,'adserver.list-two.test','A','192.168.215.1',1,0,0,NULL,'alpha-token','0.0.0.0',0);
INSERT INTO query_logs VALUES(174,1794929367257,'ok.list-two.test','A','192.168.215.1',0,1,0,NULL,NULL,'198.51.100.1',0);
INSERT INTO query_logs VALUES(175,1794929367257,'nxd.example.com','A','192.168.215.1',0,1,0,NULL,'beta-token',NULL,0);
INSERT INTO query_logs VALUES(176,1794929367257,'nodata.example.com','A','192.168.215.1',0,1,0,NULL,NULL,NULL,0);
INSERT INTO query_logs VALUES(177,1794929367258,'cname.example.com','A','192.168.215.1',0,1,0,NULL,'alpha-token','target.example.com., 192.0.2.7',0);
INSERT INTO query_logs VALUES(178,1794929367258,'dnssec.example.com','A','192.168.215.1',0,1,0,NULL,NULL,'192.0.2.9',1);
INSERT INTO query_logs VALUES(179,1794929367258,'ok.ads.example.com','A','192.168.215.1',0,1,0,NULL,'beta-token','198.51.100.1',0);
INSERT INTO query_logs VALUES(180,1794929367259,'telemetry.list-one.test','AAAA','192.168.215.1',1,0,0,NULL,NULL,'::',0);
INSERT INTO query_logs VALUES(181,1794929367259,'allowed.example.com','A','192.168.215.1',0,1,0,NULL,'alpha-token','93.184.216.34, 93.184.216.35',0);
INSERT INTO query_logs VALUES(182,1794929367259,'allowed.example.com','AAAA','192.168.215.1',0,1,0,NULL,NULL,'2001:db8::1',0);
INSERT INTO query_logs VALUES(183,1794929367260,'allowed.example.com','MX','192.168.215.1',0,1,0,NULL,'beta-token','10 mail.example.com.',0);
INSERT INTO query_logs VALUES(184,1794929367260,'ads.example.com','A','192.168.215.1',1,0,0,NULL,NULL,'0.0.0.0',0);
INSERT INTO query_logs VALUES(185,1794929367260,'ads.example.com','AAAA','192.168.215.1',1,0,0,NULL,'alpha-token','::',0);
INSERT INTO query_logs VALUES(186,1794929367260,'tracker.example.net','A','192.168.215.1',1,0,0,NULL,NULL,'0.0.0.0',0);
INSERT INTO query_logs VALUES(187,1794929367261,'ads.list-one.test','A','192.168.215.1',1,0,0,NULL,'beta-token','0.0.0.0',0);
INSERT INTO query_logs VALUES(188,1794929367261,'adserver.list-two.test','A','192.168.215.1',1,0,0,NULL,NULL,'0.0.0.0',0);
INSERT INTO query_logs VALUES(189,1794929367261,'ok.list-two.test','A','192.168.215.1',0,1,0,NULL,'alpha-token','198.51.100.1',0);
INSERT INTO query_logs VALUES(190,1794929367262,'nxd.example.com','A','192.168.215.1',0,1,0,NULL,NULL,NULL,0);
INSERT INTO query_logs VALUES(191,1794929367262,'nodata.example.com','A','192.168.215.1',0,1,0,NULL,'beta-token',NULL,0);
INSERT INTO query_logs VALUES(192,1794929367262,'cname.example.com','A','192.168.215.1',0,1,0,NULL,NULL,'target.example.com., 192.0.2.7',0);
INSERT INTO query_logs VALUES(193,1794929367262,'dnssec.example.com','A','192.168.215.1',0,1,0,NULL,'alpha-token','192.0.2.9',1);
INSERT INTO query_logs VALUES(194,1794929367263,'ok.ads.example.com','A','192.168.215.1',0,1,0,NULL,NULL,'198.51.100.1',0);
INSERT INTO query_logs VALUES(195,1794929367263,'telemetry.list-one.test','AAAA','192.168.215.1',1,0,0,NULL,'beta-token','::',0);
INSERT INTO query_logs VALUES(196,1794929367263,'allowed.example.com','A','192.168.215.1',0,1,0,NULL,NULL,'93.184.216.34, 93.184.216.35',0);
INSERT INTO query_logs VALUES(197,1794929367264,'allowed.example.com','AAAA','192.168.215.1',0,1,0,NULL,'alpha-token','2001:db8::1',0);
INSERT INTO query_logs VALUES(198,1794929367264,'allowed.example.com','MX','192.168.215.1',0,1,0,NULL,NULL,'10 mail.example.com.',0);
INSERT INTO query_logs VALUES(199,1794929367264,'ads.example.com','A','192.168.215.1',1,0,0,NULL,'beta-token','0.0.0.0',0);
INSERT INTO query_logs VALUES(200,1794929367265,'ads.example.com','AAAA','192.168.215.1',1,0,0,NULL,NULL,'::',0);
INSERT INTO query_logs VALUES(201,1794929382782,'allowed.example.com','A','192.168.215.1',0,0,2,'0.250.250.254:15353','alpha-token','93.184.216.34, 93.184.216.35',0);
CREATE TABLE filter_lists (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        url TEXT NOT NULL,
                        enabled INTEGER NOT NULL DEFAULT 1,
                        last_updated INTEGER NOT NULL DEFAULT 0,
                        rule_count INTEGER NOT NULL DEFAULT 0
                    );
INSERT INTO filter_lists VALUES(1,'AdGuard DNS filter','https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt',0,0,0);
INSERT INTO filter_lists VALUES(2,'AdAway Default Blocklist','https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt',0,0,0);
INSERT INTO filter_lists VALUES(3,'list one','http://host.docker.internal:18091/one.txt',1,1794929365,3);
INSERT INTO filter_lists VALUES(4,'list two','http://host.docker.internal:18091/two.txt',1,1794929365,3);
INSERT INTO filter_lists VALUES(5,'list three','http://host.docker.internal:18091/three.txt',0,0,0);
CREATE TABLE custom_rules (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        rule TEXT NOT NULL,
                        rule_type TEXT NOT NULL
                    );
INSERT INTO custom_rules VALUES(1,'ads.example.com','block');
INSERT INTO custom_rules VALUES(2,'@@||ok.ads.example.com^','allow');
INSERT INTO custom_rules VALUES(3,'||tracker.example.net^','block');
CREATE TABLE filter_list_content (
                        list_id INTEGER PRIMARY KEY,
                        content TEXT NOT NULL
                    );
INSERT INTO filter_list_content VALUES(3,'0.0.0.0 ads.list-one.test
0.0.0.0 tracker.list-one.test
127.0.0.1 telemetry.list-one.test
# comment
');
INSERT INTO filter_list_content VALUES(4,'||adserver.list-two.test^
||banner.list-two.test^
@@||ok.list-two.test^
! comment
');
CREATE TABLE doh_tokens (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        token TEXT NOT NULL UNIQUE
                    );
INSERT INTO doh_tokens VALUES(1,'alpha-token');
INSERT INTO doh_tokens VALUES(2,'beta-token');
CREATE TABLE users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL UNIQUE,
                        -- NO_PASSWORD_SENTINEL for forward-auth accounts.
                        password_hash TEXT NOT NULL,
                        created_at INTEGER NOT NULL
                    );
INSERT INTO users VALUES(1,'admin','$argon2id$v=19$m=19456,t=2,p=1$a6HbvUBHXd81hVLaT7XBKA$IQ38bNVwFOCsLh0vem2N1oYI3GTv/qbAYs7Bg8qhWgQ',1794929365);
INSERT INTO users VALUES(2,'second','$argon2id$v=19$m=19456,t=2,p=1$hLp14PeCkaRxg/at+jJlsg$NPvrGiWQ5rZcFaozvkf2YbSNqULTWM3WuPWbw7jkUKk',1794929365);
INSERT INTO users VALUES(3,'cjk-user','$argon2id$v=19$m=19456,t=2,p=1$X5Fj3nRFvDUl6f3Pxgu40g$neKymKhsfJZwYCeFzhNGzahJWp/JZB4cU7baBPWjpJA',1794929365);
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
INSERT INTO api_keys VALUES(1,1,'ci-expiring','208bf4513fafc42e3de165f4b95c1aa035b4a212ef807f2dc4c2dc3c5a704976e6d53d14e7136c54e89300cc0e6934309ec1403756e47617671021b286865d48','noadd_CifG',1794929365,NULL,4102444800);
INSERT INTO api_keys VALUES(2,1,'ci-forever','12a998c60382c04f3f8dc68efbc590d67340c7cff74a954781532c307d02849b89d25d95ae57cf98a48e3270210ebf436efa8ebc9fe1f63feb3dd59879e3539d','noadd_O3lQ',1794929365,1794929365,NULL);
INSERT INTO api_keys VALUES(3,1,'ui-key','f49fe7795db448c1082d6b87e4a8964041b7828d49f44fffa6e91c2bc9728e517380ad3abb5da37450b8ac3a28cac08f7685b1eed818c4f32f182e2a4dca66dc','noadd_Rzfm',1794929382,NULL,4102531199);
ANALYZE sqlite_schema;
DELETE FROM sqlite_stat1;
DELETE FROM sqlite_stat4;
INSERT INTO sqlite_stat1 VALUES('settings','sqlite_autoindex_settings_1','1 1');
INSERT INTO sqlite_stat4 VALUES('settings','sqlite_autoindex_settings_1','1 1','0 0','0 0',x'032b0971756572795f6c6f675f636f756e74');
CREATE TABLE sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_hash TEXT NOT NULL UNIQUE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            ip TEXT,
            user_agent TEXT
        );
INSERT INTO sessions VALUES(1,'dbb68cc1180435602de30284d84182d2acf30ad6904a13a9789494932d1b3928725d00a1fc15b031663986c39b756109bb925e94f359038b922dc3c1525d7df8',1,1794929365,1794929365,'192.168.215.1',NULL);
CREATE TABLE query_stats_quarter (
        quarter INTEGER NOT NULL,
        blocked INTEGER NOT NULL,
        cached INTEGER NOT NULL,
        count INTEGER NOT NULL,
        sum_ms INTEGER NOT NULL,
        PRIMARY KEY (quarter, blocked, cached)
    ) WITHOUT ROWID;
INSERT INTO query_stats_quarter VALUES(1994365,0,0,10,6);
INSERT INTO query_stats_quarter VALUES(1994365,0,1,111,0);
INSERT INTO query_stats_quarter VALUES(1994365,1,0,80,0);
CREATE TABLE query_stats_domain_hour (
        hour INTEGER NOT NULL,
        domain TEXT NOT NULL,
        count INTEGER NOT NULL,
        PRIMARY KEY (hour, domain)
    ) WITHOUT ROWID;
INSERT INTO query_stats_domain_hour VALUES(498591,'ads.example.com',28);
INSERT INTO query_stats_domain_hour VALUES(498591,'ads.list-one.test',13);
INSERT INTO query_stats_domain_hour VALUES(498591,'adserver.list-two.test',13);
INSERT INTO query_stats_domain_hour VALUES(498591,'allowed.example.com',43);
INSERT INTO query_stats_domain_hour VALUES(498591,'cname.example.com',13);
INSERT INTO query_stats_domain_hour VALUES(498591,'dnssec.example.com',13);
INSERT INTO query_stats_domain_hour VALUES(498591,'nodata.example.com',13);
INSERT INTO query_stats_domain_hour VALUES(498591,'nxd.example.com',13);
INSERT INTO query_stats_domain_hour VALUES(498591,'ok.ads.example.com',13);
INSERT INTO query_stats_domain_hour VALUES(498591,'ok.list-two.test',13);
INSERT INTO query_stats_domain_hour VALUES(498591,'telemetry.list-one.test',13);
INSERT INTO query_stats_domain_hour VALUES(498591,'tracker.example.net',13);
CREATE TABLE query_stats_client_hour (
        hour INTEGER NOT NULL,
        client_ip TEXT NOT NULL,
        doh_token TEXT NOT NULL,
        count INTEGER NOT NULL,
        PRIMARY KEY (hour, client_ip, doh_token)
    ) WITHOUT ROWID;
INSERT INTO query_stats_client_hour VALUES(498591,'192.168.215.1','',100);
INSERT INTO query_stats_client_hour VALUES(498591,'192.168.215.1','alpha-token',51);
INSERT INTO query_stats_client_hour VALUES(498591,'192.168.215.1','beta-token',50);
CREATE TABLE query_stats_upstream_hour (
        hour INTEGER NOT NULL,
        upstream TEXT NOT NULL,
        count INTEGER NOT NULL,
        sum_ms INTEGER NOT NULL,
        PRIMARY KEY (hour, upstream)
    ) WITHOUT ROWID;
INSERT INTO query_stats_upstream_hour VALUES(498591,'0.250.250.254:15353',10,6);
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
INSERT INTO query_stats_metrics_hour VALUES(498591,0,0,0,'A',0,2);
INSERT INTO query_stats_metrics_hour VALUES(498591,0,0,1,'A',0,2);
INSERT INTO query_stats_metrics_hour VALUES(498591,0,0,1,'A',1,3);
INSERT INTO query_stats_metrics_hour VALUES(498591,0,0,1,'A',2,1);
INSERT INTO query_stats_metrics_hour VALUES(498591,0,0,1,'AAAA',1,1);
INSERT INTO query_stats_metrics_hour VALUES(498591,0,0,1,'MX',0,1);
INSERT INTO query_stats_metrics_hour VALUES(498591,0,1,0,'A',0,24);
INSERT INTO query_stats_metrics_hour VALUES(498591,0,1,1,'A',0,61);
INSERT INTO query_stats_metrics_hour VALUES(498591,0,1,1,'AAAA',0,13);
INSERT INTO query_stats_metrics_hour VALUES(498591,0,1,1,'MX',0,13);
INSERT INTO query_stats_metrics_hour VALUES(498591,1,0,1,'A',0,53);
INSERT INTO query_stats_metrics_hour VALUES(498591,1,0,1,'AAAA',0,27);
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
CREATE INDEX idx_query_logs_timestamp ON query_logs(timestamp);
CREATE INDEX idx_query_logs_domain_ts ON query_logs(domain, timestamp);
CREATE INDEX idx_query_logs_token_ts ON query_logs(doh_token, timestamp);
CREATE INDEX idx_query_logs_blocked_ts ON query_logs(blocked, timestamp);
CREATE INDEX idx_query_logs_type_blocked_ts ON query_logs(query_type, blocked, timestamp);
CREATE INDEX idx_api_keys_user ON api_keys(user_id);`,
}

// rustMigratedDumps is the non-secret content of each legacy database after
// the Rust server migrated it: user_version and, per table, columns and rows.
var rustMigratedDumps = map[string]string{
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
