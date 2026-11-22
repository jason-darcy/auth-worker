# Auth API with workers-rs

A self-hosted auth api for your products.

The best way to deploy on your cloudflare woker is clicking the button.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/jason-darcy/auth-worker)

## Configuration

```sh
cp .env.example .env
```

```sh
cf d1 create --name auth-worker
cf d1 migrations apply <DATABASE_ID> --local
```

Configure DOMAIN and DB_UUID in .env

## Local development

Run the project

```sh
just dev
```

## Local Deploy

```sh
just deploy
```

## License

See [LICENSE](LICENSE).
