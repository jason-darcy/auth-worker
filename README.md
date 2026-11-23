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

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| GET | `/api/v1/health` | — | Liveness probe |
| POST | `/api/v1/signup` | — | Create an account and email a verification link |
| POST | `/api/v1/signin` | — | Exchange credentials for an access + refresh token pair |
| POST | `/api/v1/resend-verification` | — | Email a new verification link (no account enumeration) |
| POST | `/api/v1/refresh` | — | Rotate a refresh token for a new token pair |
| POST | `/api/v1/signout` | — | Revoke the session of the refresh token in the body (idempotent) |
| POST | `/api/v1/forgot-password` | — | Email a password reset link |
| GET/POST | `/api/v1/reset-password` | — | Render the reset form / perform the reset |
| GET | `/api/v1/verify-email?token=...` | — | Render the confirmation page (does not consume the token) |
| POST | `/api/v1/verify-email` | — | Confirm an email address; body `{ "token": "..." }` |
| GET | `/api/v1/account/me` | Bearer | The caller's account |
| DELETE | `/api/v1/account/me` | Bearer | Delete the account; body `{ "password": "..." }` |
| GET | `/api/v1/account/{id}` | Bearer | A single account (self only) |
| POST | `/api/v1/change-password` | Bearer | Replace the password; requires the current one |
| GET | `/api/v1/sessions` | Bearer | List the caller's live sessions (devices) |
| DELETE | `/api/v1/sessions/{id}` | Bearer | Revoke one session of the caller |
| POST | `/api/v1/signout-all` | Bearer | Revoke every session and invalidate access tokens |
| GET | `/api/v1/mfa` | Bearer | Whether MFA is enabled, and how many recovery codes are left |
| POST | `/api/v1/mfa/totp/setup` | Bearer | Start a TOTP enrolment, returns the secret and `otpauth://` URI |
| POST | `/api/v1/mfa/totp/confirm` | Bearer | Activate the enrolment; returns the recovery codes once |
| POST | `/api/v1/mfa/disable` | Bearer | Turn MFA off; requires the password and a valid code |
| POST | `/api/v1/mfa/recovery-codes` | Bearer | Reissue the recovery codes; requires the password and a valid code |
| POST | `/api/v1/mfa/verify` | — | Exchange the sign-in challenge and a code for tokens |
| GET | `/api/v1/openapi.json` | — | The OpenAPI 3.1 contract (local development only) |
| GET | `/swagger-ui` | — | Swagger UI rendering that contract (local development only) |

Authenticated endpoints expect `Authorization: Bearer <access_token>`.

Changing the password or deleting the account requires the current password in
the body, plus a valid `mfa_code` when the account has MFA enabled, so a stolen
access token alone cannot take over the account. A successful password change
revokes every session, including the caller's: sign in again afterwards.

`PASSWORD_PEPPER` and `JWT_SECRET` are mandatory. The worker fails the affected
request instead of falling back to an empty secret when either is missing.

### Sessions and refresh token rotation

Every sign-in opens a session; its refresh token is the only one that can be
exchanged, and each exchange rotates it. Presenting an already rotated token is
treated as a replay: the whole session is revoked instead of the request just
failing. Sessions are listed by `GET /sessions` (the caller's own entry has
`"current": true`) and can be revoked one by one, which is also how "sign out
this device" works.

### Abuse protection

- Sign-in: 10 consecutive failures lock the account for 15 minutes. A locked
  account answers exactly like a wrong password (same status, same Argon2 cost).
- Verification and reset emails: at most one per account per minute. A throttled
  request answers exactly like a delivered one.
- Every auth endpoint is rate limited per client IP through the Cloudflare
  rate limiting binding.

Passwords must be 8–64 characters; the upper bound only exists so a request
cannot feed an unbounded input to Argon2.

### Multi-factor authentication (TOTP)

MFA is per account and opt-in:

1. `POST /mfa/totp/setup` stores a **pending** secret and returns it with an
   `otpauth://` URI. Nothing is enforced yet, so an abandoned enrolment can never
   lock the account out.
2. `POST /mfa/totp/confirm` with the first 6-digit code activates it and returns
   10 recovery codes. They are shown **once**; only SHA-256 hashes are stored.
3. From then on `POST /signin` returns `{ "mfa_required": true, "challenge_token": ... }`
   instead of tokens. Exchange that ticket plus a code at `POST /mfa/verify`.

Details that matter:

- The challenge ticket is single use and expires after 5 minutes. Five wrong
  codes destroy it, so the password has to be entered again.
- TOTP accepts ±30 s of clock drift. A code can only be used once: the last
  accepted step is stored, so a replay inside the window is rejected.
- A recovery code works once and is marked used. A wrong second factor never
  reveals whether the account exists.
- Disabling MFA and reissuing recovery codes need the password **and** a valid
  second factor.

**Step-up on sensitive endpoints.** Once MFA is enabled, `POST /change-password`
and `DELETE /account/me` also require a `mfa_code` in the body. Without it they
answer `403` (a code is required), with a wrong one `401`. Accounts without MFA
are unaffected, so the change is invisible to existing clients.
- TOTP secrets are encrypted at rest (AES-256-GCM) with a key derived from
  `PASSWORD_PEPPER`, so a database dump alone does not expose them. Rotating
  `PASSWORD_PEPPER` invalidates existing enrolments along with every password.

### Email verification is a two-step flow

`GET /verify-email?token=...` only renders a confirmation page; the token is
consumed by `POST /verify-email`. Mail scanners and link previews fetch every
URL in a message, and consuming the token on `GET` would verify (or burn) it
before the recipient ever clicked.

Clients that used to call `GET /verify-email` to verify must switch to the
`POST` with `{ "token": "..." }`.

### Maintenance

A cron trigger (`0 * * * *`, see `cloudflare.config.ts`) runs the `scheduled`
handler in `src/lib.rs`, which deletes expired verification, reset and refresh
tokens plus expired MFA challenges. Expiry is enforced on every use regardless,
so this only reclaims space.

### Response headers

Every API response is sent with `Cache-Control: no-store` (the OpenAPI document
and the Swagger UI assets use `no-cache`), and the server-rendered pages
additionally carry
`X-Content-Type-Options`, `Referrer-Policy: no-referrer` and a restrictive
`Content-Security-Policy`.

### API documentation

The contract is generated from the Rust types by
[`utoipa`](https://docs.rs/utoipa): every handler carries a `#[utoipa::path]`
attribute and every request/response type derives `ToSchema`, so a handler
change and its documentation cannot drift apart. There is no checked-in
`openapi.json` to keep in sync.

- `GET /api/v1/openapi.json` — the raw document (OpenAPI 3.1)
- `GET /swagger-ui` — Swagger UI rendering it

**Both are served to loopback clients only.** In production they answer the same
`404` as an unknown path, so the API surface is not discoverable and Swagger UI
adds no attack surface. Nothing has to be configured for that: Cloudflare sets
`cf-connecting-ip` at the edge and overwrites whatever the client sent, so only
`cf dev` can look like a local request. To check the deployed behaviour locally:

```sh
curl -H 'cf-connecting-ip: 203.0.113.7' http://localhost:8787/api/v1/openapi.json
# {"errors":null,"messages":["route not found"],"results":[],"success":false}
```

The UI assets are embedded in the worker via `utoipa-swagger-ui`'s `vendored`
feature, which means a build never has to reach GitHub. The cost is size: the
wasm grows by about 5.7 MB (1.3 MB gzipped), from ~2.5 MB to ~8.2 MB. That is
well inside the paid plan's 10 MiB limit but a large share of the free plan's
3 MiB. If that matters, drop the `utoipa-swagger-ui` dependency and the
`SwaggerUi` merge in `src/presentation/http/routes.rs`; the generated document
keeps working.

### CORS

Browser clients are blocked by default. Set `CORS_ORIGINS` to a comma
separated list of origins (`https://app.example.com,http://localhost:5173`) or
to `*` to allow every origin. The API authenticates with a bearer header, so
credentialed CORS is never used.

## License

See [LICENSE](LICENSE).
