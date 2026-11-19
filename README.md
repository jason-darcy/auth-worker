# Auth API with workers-rs

A self-hosted auth api for your products.

The best way to deploy on your cloudflare woker is clicking the button.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/jason-darcy/auth-worker)

You can choose cloudflare-cf cli (new cli, recommended) or wrangler cli (old cli) for local development and local deploy.

## Local development

for cf cli users (recommended)

```sh
cp .env.example .env
```

for wrangler cli users

```sh
cp wrangler.toml wrangler.local.toml
```

Run the following commands to fill in the blank in your config files (.env or wrangler.local.toml)

for cf cli users (recommended)

```sh
cf d1 create --name auth-worker
cf d1 migrations apply <DATABASE_ID> --local
```

for wrangler cli users

```sh
wrangler d1 create auth-worker
wrangler d1 migrations apply auth-worker --local
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
cf d1 migrations apply auth-worker
```

for wrangler cli users

```sh
wrangler d1 migrations apply auth-worker --remote
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
