set dotenv-load

dev:
    rm -rf .cloudflare/state/v3/d1
    cf d1 migrations apply $DB_UUID --local
    cf dev

migrate:
    cf d1 migrations apply $DB_UUID

deploy: migrate
    cf deploy --secrets-file .env

test:
    cargo test --workspace --all-features --locked

fmt:
    cargo fmt

check:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
