import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		globals: true,
		environment: "node",
		include: ["test/unit/**/*.test.ts"],
		env: {
			DATABASE_URL: "postgresql://oauth21:oauth21_dev_password@localhost:5432/oauth21",
		},
		coverage: {
			provider: "v8",
			include: ["src/**/*.ts"],
		},
	},
});
