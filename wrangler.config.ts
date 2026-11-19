import { defineWranglerConfig } from "wrangler/experimental-config";

export default defineWranglerConfig((ctx) => {
 	return {
		build: {
 			command: "cargo install -q \"worker-build@^0.9\" && worker-build --release --panic-unwind",
		},
 	};
});
