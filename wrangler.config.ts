import { defineWranglerConfig } from "wrangler/experimental-config";

export default defineWranglerConfig((ctx) => {
	switch (ctx.mode) {
		case "production": {
			return {
				build: {
					command: "cargo install -q \"worker-build@^0.9\" && worker-build --release --panic-unwind",
				},
			};
		}
		default: {
			return {
				build: {
					command: "cargo install -q \"worker-build@^0.9\" && worker-build --release --panic-unwind",
				},
			};
		}
	}
});
