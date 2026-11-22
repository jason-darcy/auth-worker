# Auth API with workers-rs

A self-hosted auth api for your products.

The best way to deploy on your cloudflare woker is clicking the button.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/jason-darcy/auth-worker)

## Configuration (Only when you want to develop or deploy locally)

```sh
mise bootstrap
```

```sh
cp .env.example .env
```

Follow the instructions in your .env and configure your .env

Run the following command to get DB_UUID and set DB_UUID in .env

```sh
cf d1 create --name auth-worker
```

Migrate tables in your local d1 database

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
