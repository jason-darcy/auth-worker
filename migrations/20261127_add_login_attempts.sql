-- Failed sign-in tracking. Once `failed_login_attempts` reaches the limit the
-- account is locked until `locked_until` (Unix seconds), which stops online
-- password guessing that spreads across many IPs.
ALTER TABLE accounts ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE accounts ADD COLUMN locked_until INTEGER;
