import { defineConfig } from "vitest/config";
import {
	assertIntegrationDatabaseUrl,
	DEFAULT_INTEGRATION_DATABASE_URL,
} from "./test/integration/db-guard.js";

// 通常起動用のDATABASE_URLは引き継がず、結合テスト専用の設定を使う。
const databaseUrl = process.env.INTEGRATION_DATABASE_URL ?? DEFAULT_INTEGRATION_DATABASE_URL;
assertIntegrationDatabaseUrl(databaseUrl);

export default defineConfig({
	test: {
		globals: true,
		environment: "node",
		include: ["test/integration/**/*.test.ts"],
		// 各ファイルが同じDBを初期化するため、ファイル間の並列実行を避ける。
		fileParallelism: false,
		setupFiles: ["./test/integration/setup.ts"],
		testTimeout: 30000,
		hookTimeout: 30000,
		env: {
			DATABASE_URL: databaseUrl,
		},
		coverage: {
			provider: "v8",
			include: ["src/**/*.ts"],
		},
	},
});
