wrangler-dev:
    wrangler dev --config wrangler.local.toml

cf-dev:
    cf dev

wrangler-deploy:
    wrangler deploy --config wrangler.local.toml

cf-deploy:
    cf deploy

wrangler-migrate mode:
    wrangler d1 migrations apply auth-worker --{{mode}}

cf-migrate mode:
    cf d1 migrations apply auth-worker --{{mode}}
