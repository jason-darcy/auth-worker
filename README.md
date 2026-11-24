# Auth API with workers-rs

A self-hosted auth api for your products.

The best way to deploy on your cloudflare woker is clicking the button.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/jason-darcy/auth-worker)

## Configuration (Only when you want to develop or deploy locally)

Install [mise](https://mise.jdx.dev/installing-mise.html) on your device

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

## API

All responses use the same envelope, including `404`/`405` and malformed
bodies:

```json
{ "success": true, "errors": [], "messages": ["..."], "results": {} }
```

| Method | Path | Description |
| --- | --- | --- |
| GET | `/api/v1/health` | Liveness probe |
| POST | `/api/v1/signup` | Create an account |
| POST | `/api/v1/signin` | Verify credentials and return the account |

`POST /signup` takes `{ "name", "email", "password", "confirm_password" }` and
answers `409` when the email is already registered.

`POST /signin` takes `{ "email", "password" }` and returns the account
(`id`, `name`, `email`, `created_at`). There is no token: the worker only
authenticates the caller.

Passwords must be 8–64 characters; the upper bound only exists so a request
cannot feed an unbounded input to Argon2.

### CORS

Browser clients are blocked by default. Set `CORS_ORIGINS` to a comma
separated list of origins (`https://app.example.com,http://localhost:5173`) or
to `*` to allow every origin.

## License

See [LICENSE](LICENSE).
