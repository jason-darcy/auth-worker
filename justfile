set dotenv-load

wrangler-dev:
    wrangler dev --config wrangler.local.toml

cf-dev:
    cf dev

wrangler-migrate:
    wrangler d1 migrations apply auth-worker --remote

cf-migrate:
    cf d1 migrations apply $DB_UUID

wrangler-deploy: wrangler-migrate
    wrangler deploy --config wrangler.local.toml

cf-deploy: cf-migrate
    cf deploy

