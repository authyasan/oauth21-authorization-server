import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		globals: true,
		environment: "node",
		include: ["test/integration/**/*.test.ts"],
		// 各ファイルが同じDBを初期化するため、ファイル間の並列実行を避ける。
		fileParallelism: false,
		testTimeout: 30000,
		hookTimeout: 30000,
		env: {
			DATABASE_URL: "postgresql://oauth21:oauth21_dev_password@localhost:5432/oauth21",
		},
		coverage: {
			provider: "v8",
			include: ["src/**/*.ts"],
		},
	},
});
