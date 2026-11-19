# Auth API by workers-rs

A self-hosted auth api for your products.

The best way to deploy on your cloudflare woker is clicking the button.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.com/?url=https://github.com/jason-darcy/auth-worker)

You can choose cloudflare-cf cli (new cli, recommended) or wrangler cli (old cli) for local development and local deploy.

## Local development

for cf cli users (recommended)

```sh
cp .env.dev.example .env.dev
```

for wrangler cli users

```sh
cp wrangler.dev.toml.example wrangler.dev.toml
```

Run the following commands to fill in the blank in your config files (.env.dev or wrangler.dev.toml)

for cf cli users (recommended)

```sh
cf d1 create dev-auth
cf d1 migrations apply dev-auth -m local
```

for wrangler cli users

```sh
wrangler d1 create dev-auth
wrangler d1 migrations apply dev-auth --local
```

Run the project

for cf cli users (recommended)

```sh
just cf-dev
```

for wrangler cli users

```sh
just wrangler-dev
```

## Local Deploy

for cf cli users (recommended)

```sh
cp .env.prod.example .env.prod
```

for wrangler cli users

```sh
cp wrangler.prod.toml.example wrangler.prod.toml
```

Run the following commands to fill in the blank in your config files (.env.prod or wrangler.prod.toml)

for cf cli users (recommended)

```sh
cf d1 create prod-auth
cf d1 migrations apply prod-auth -m production
```

for wrangler cli users

```sh
wrangler d1 create prod-auth
wrangler d1 migrations apply prod-auth --remote
```

Deploy the project

for cf cli users (recommended)

```sh
just cf-deploy
```

for wrangler cli users

```sh
just wrangler-deploy
```

## License

See [LICENSE](LICENSE).
