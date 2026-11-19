dev:
    wrangler dev

deploy:
    wrangler deploy --env production

db:
    wrangler d1 create dev-auth
    wrangler d1 create pro-auth

create-migrations:
    wrangler d1 migrations create dev-auth create_user_table -y

migrate:
    rm -rf .wrangler/state/v3/d1
    wrangler d1 migrations apply dev-auth --local
