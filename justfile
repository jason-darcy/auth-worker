wrangler-dev:
    wrangler dev --config wrangler.local.toml

cf-dev:
    cf dev --mode dev

wrangler-deploy:
    wrangler deploy --config wrangler.prod.toml

cf-deploy:
    cf deploy --mode production

wrangler-migrate:
    rm -rf .wrangler/state/v3/d1
    wrangler d1 migrations apply dev-auth --local

cf-migrate:
    rm -rf .wrangler/state/v3/d1
    cf d1 migrations apply dev-auth -m local
