CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    -- `COLLATE NOCASE` keeps emails unique and comparable case-insensitively,
    -- as a second line of defence next to `domain::account::normalize_email`.
    email TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    is_verified INTEGER NOT NULL DEFAULT 0,
    -- Bumped whenever credentials change (password reset), so previously
    -- issued access tokens stop working immediately.
    token_version INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_account_name ON accounts(name);
CREATE INDEX IF NOT EXISTS idx_account_email ON accounts(email);
