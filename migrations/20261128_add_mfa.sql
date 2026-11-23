-- TOTP credentials. One per account; `confirmed_at` stays NULL while the user
-- has not proven that their authenticator app produces valid codes yet, so an
-- unfinished enrolment can never lock anybody out.
CREATE TABLE IF NOT EXISTS totp_credentials (
    account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    -- Base32 secret, encrypted at rest (AES-256-GCM) with a key derived from
    -- PASSWORD_PEPPER.
    secret TEXT NOT NULL,
    confirmed_at INTEGER,
    -- Last accepted TOTP step, so a code cannot be replayed inside the skew
    -- window.
    last_used_step INTEGER,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Single-use recovery codes. Only the SHA-256 hash is stored.
CREATE TABLE IF NOT EXISTS recovery_codes (
    code_hash TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    used_at INTEGER,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_recovery_codes_account_id ON recovery_codes(account_id);

-- Short-lived ticket handed out after a correct password, exchanged for tokens
-- once the second factor is verified.
CREATE TABLE IF NOT EXISTS mfa_challenges (
    token_hash TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_account_id ON mfa_challenges(account_id);
