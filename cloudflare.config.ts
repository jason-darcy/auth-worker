import { bindings, defineConfig } from "cf/config";

/**
 * Wrangler environments are selected through ctx.mode and the cf --mode flag.
 * @see https://developers.cloudflare.com/workers/wrangler/environments/
 */

const domain = process.env.DOMAIN?.trim();
const dbUuid = process.env.DB_UUID?.trim();
const emailFrom = process.env.EMAIL_FROM?.trim() || "no-reply@example.com";

export default defineConfig(() => {
  return {
    worker: {
      name: "auth-worker",
      compatibilityDate: "2026-11-18",
      entrypoint: "build/index.js",
      ...(domain ? { domains: [domain] } : {}),
      observability: {
        "enabled": true,
        "logs": {
          "enabled": true,
          "invocationLogs": true,
          "headSamplingRate": 1
        },
        "traces": {
          "enabled": true,
          "headSamplingRate": 1
        }
      },
      env: {
        PASSWORD_PEPPER: bindings.secret(),
        JWT_SECRET: bindings.secret(),
        "auth-worker": bindings.d1({
          name: "auth-worker",
          ...(dbUuid ? { id: dbUuid } : {}),
        }),
        EMAIL: bindings.sendEmail({}),
        EMAIL_FROM: bindings.text(emailFrom),
        DOMAIN: bindings.text(domain ?? ""),
        RATE_LIMITER: bindings.rateLimit({
          namespace: "auth-worker",
          simple: { limit: 10, period: 60 },
        }),
      },
    },
  };
});
