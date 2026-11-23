-- Refresh tokens become sessions: every token belongs to a rotation family, so
-- a replayed token can revoke the whole lineage instead of only failing once.
ALTER TABLE refresh_tokens ADD COLUMN family_id TEXT NOT NULL DEFAULT '';
ALTER TABLE refresh_tokens ADD COLUMN user_agent TEXT;
ALTER TABLE refresh_tokens ADD COLUMN ip TEXT;
ALTER TABLE refresh_tokens ADD COLUMN last_used_at INTEGER;
-- Set when the token was exchanged for a newer one. The row is kept so a replay
-- can be detected.
ALTER TABLE refresh_tokens ADD COLUMN rotated_at INTEGER;

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family_id ON refresh_tokens(family_id);

-- Tokens issued before this migration have no family. Give each its own, so
-- existing sessions can be listed and revoked individually.
UPDATE refresh_tokens
SET family_id = lower(hex(randomblob(16)))
WHERE family_id = '';
