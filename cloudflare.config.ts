import { bindings, defineConfig } from "cf/config";

/**
 * Wrangler environments are selected through ctx.mode and the cf --mode flag.
 * @see https://developers.cloudflare.com/workers/wrangler/environments/
 */

export default defineConfig((ctx) => {
	return {
		worker: {
			name: "auth",
			compatibilityDate: "2026-11-18",
			entrypoint: "build/index.js",
			env: {
				auth: bindings.d1({
					name: "prod-auth",
					id: process.env.PROD_D1_DATABASE_ID,
				}),
			},
		},
	};
});
