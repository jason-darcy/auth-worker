set dotenv-load

dev:
    rm -rf .cloudflare/state/v3/d1
    cf d1 migrations apply $DB_UUID --local
    cf dev

migrate:
    cf d1 migrations apply $DB_UUID

deploy: migrate
    cf deploy --secrets-file .env
