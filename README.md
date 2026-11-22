# Auth API with workers-rs

A self-hosted auth api for your products.

The best way to deploy on your cloudflare woker is clicking the button.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/jason-darcy/auth-worker)

## Configuration

```sh
mise bootstrap
```

```sh
cp .env.example .env
```

Run the following command to get DB_UUID

```sh
cf d1 create --name auth-worker
```

Configure DOMAIN and DB_UUID in .env

```sh
cf d1 migrations apply $DB_UUID --local
```

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
