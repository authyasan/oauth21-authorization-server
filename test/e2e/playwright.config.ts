import { fileURLToPath } from "node:url";
import { defineConfig, devices } from "@playwright/test";
import { AS_ORIGIN, CONTROL_ORIGIN, E2E_DATABASE_URL, HOSTS } from "./config.js";

// hostsを変更せずに、テスト用のホスト名をブラウザ内だけで 127.0.0.1 に向ける。
const hostResolverRules = [HOSTS.as, HOSTS.client, HOSTS.other, HOSTS.sub, HOSTS.evil]
	.map((h) => `MAP ${h} 127.0.0.1`)
	.join(", ");

export default defineConfig({
	testDir: ".",
	// サーバーのメモリ上のセッションとDBを共有するので、直列に実行する。
	workers: 1,
	fullyParallel: false,
	retries: 0,
	reporter: [["list"]],
	// 失敗時のトレースは作業ツリーの外に出す。
	outputDir: `${process.env.TMPDIR ?? "/tmp"}/oauth21-e2e-results`,
	use: {
		baseURL: AS_ORIGIN,
		// テスト専用の自己署名証明書のため、このテストのcontextに限って証明書検証を省略する。
		// Cookie・SameSite・CSPなどの仕組みには手を加えない。
		ignoreHTTPSErrors: true,
		launchOptions: { args: [`--host-resolver-rules=${hostResolverRules}`] },
		trace: "retain-on-failure",
	},
	projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
	webServer: {
		command: "npx tsx test/e2e/server.ts",
		// どこから実行しても同じになるよう、リポジトリのルートを絶対パスで指定する。
		cwd: fileURLToPath(new URL("../..", import.meta.url)),
		url: `${CONTROL_ORIGIN}/health`,
		reuseExistingServer: false,
		timeout: 60_000,
		env: {
			NODE_ENV: "production",
			ISSUER: AS_ORIGIN,
			DATABASE_URL: E2E_DATABASE_URL,
		},
		stdout: "pipe",
		stderr: "pipe",
	},
});
