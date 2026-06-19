package db

const schema = `
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    domain TEXT NOT NULL UNIQUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- 新 records 表，使用规则字段替代 region
CREATE TABLE IF NOT EXISTS records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id INTEGER NOT NULL,
    rule_type TEXT NOT NULL,          -- 'default', 'continent', 'china_other', 'china'
    continent TEXT,                   -- 当 rule_type='continent'
    isp TEXT,                         -- 当 rule_type='china'
    province TEXT,                    -- 当 rule_type='china'
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    ttl INTEGER NOT NULL DEFAULT 600,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_records_domain_id ON records(domain_id);
CREATE INDEX IF NOT EXISTS idx_domains_domain ON domains(domain);
`

const pragmas = `
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
`
