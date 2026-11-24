import { bindings, defineConfig } from "cf/config";

/**
 * Wrangler environments are selected through ctx.mode and the cf --mode flag.
 * @see https://developers.cloudflare.com/workers/wrangler/environments/
 */

const dbUuid = process.env.DB_UUID?.trim();
// Comma separated browser origins allowed to call the API, e.g.
// "https://app.example.com,https://admin.example.com". Empty disables CORS.
const corsOrigins = process.env.CORS_ORIGINS?.trim() || "";

export default defineConfig(() => {
  return {
    worker: {
      name: "auth-worker",
      compatibilityDate: "2026-11-18",
      entrypoint: "build/index.js",
      // Workers Logs and traces stay off: nothing is sampled, stored or shown
      // in the dashboard for this worker.
      observability: { enabled: false },
      env: {
        DB: bindings.d1({
          name: "auth-worker",
          ...(dbUuid ? { id: dbUuid } : {}),
        }),
        CORS_ORIGINS: bindings.text(corsOrigins),
      },
    },
  };
});
