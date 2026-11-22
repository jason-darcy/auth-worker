set dotenv-load

dev:
    cf dev

migrate:
    cf d1 migrations apply $DB_UUID

deploy: migrate
    cf deploy
