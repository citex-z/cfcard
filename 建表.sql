CREATE TABLE IF NOT EXISTS admin (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS apps (
  app_id TEXT PRIMARY KEY,
  app_name TEXT NOT NULL,
  status INTEGER DEFAULT 1,
  notice TEXT DEFAULT '',
  sig_md5 TEXT DEFAULT '',
  sig_sha1 TEXT DEFAULT '',
  sig_sha256 TEXT DEFAULT '',
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS bindings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id TEXT NOT NULL DEFAULT '',
  card_key TEXT NOT NULL,
  device_id TEXT DEFAULT '',
  bind_date TEXT DEFAULT '',
  banned INTEGER DEFAULT 0,
  expiry_date TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS api_tokens (
  token_hash TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_bindings_app ON bindings(app_id);
CREATE INDEX IF NOT EXISTS idx_bindings_key ON bindings(app_id, card_key);
