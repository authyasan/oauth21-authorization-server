/**
 * E2Eの /reset が E2E 専用DB以外を削除しないことの回帰テスト。
 * ブラウザは使わない。削除処理そのものは実行せず、呼ばれたかどうかだけを記録する。
 * 通常のDB（結合テスト用・開発用）に対して削除を試すことはしない。
 */
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { expect, test } from "@playwright/test";
import postgres from "postgres";
import { E2E_DATABASE_URL } from "./config.js";
import { assertE2eDatabaseUrl, E2E_DATABASE_NAME, resetIfE2eDatabase } from "./db-guard.js";

/** E2E用の接続先URLのうち、DB名だけを差し替える。 */
function withDatabase(name: string): string {
	const url = new URL(E2E_DATABASE_URL);
	url.pathname = `/${name}`;
	return url.toString();
}

/**
 * E2E専用ではない実在のDB。削除してはいけない接続先の例として使う。
 * PostgreSQLが標準で作る postgres データベースなので、追加の準備なしに存在する。
 * 接続して current_database() を読むだけで、データは変更しない。
 */
const NON_E2E_DATABASE = "postgres";

test.describe("DATABASE_URL のDB名の確認", () => {
	test("E2E専用DBの名前と完全一致すれば通す", () => {
		expect(() => assertE2eDatabaseUrl(E2E_DATABASE_URL)).not.toThrow();
		expect(() => assertE2eDatabaseUrl(withDatabase(E2E_DATABASE_NAME))).not.toThrow();
	});

	const rejected: Array<[string, string | undefined]> = [
		["未設定", undefined],
		["URLでない", "oauth21_e2e_test"],
		[
			"パスワードにだけ含まれる",
			`postgresql://oauth21:${E2E_DATABASE_NAME}@127.0.0.1:5493/oauth21`,
		],
		["ユーザー名にだけ含まれる", `postgresql://${E2E_DATABASE_NAME}:x@127.0.0.1:5493/oauth21`],
		["ホスト名にだけ含まれる", `postgresql://oauth21:x@${E2E_DATABASE_NAME}.local:5493/oauth21`],
		[
			"クエリにだけ含まれる",
			`postgresql://oauth21:x@127.0.0.1:5493/oauth21?dbname=${E2E_DATABASE_NAME}`,
		],
		["DB名は正しいがクエリ付き", `${withDatabase(E2E_DATABASE_NAME)}?options=x`],
		["後ろに文字が続く", withDatabase(`${E2E_DATABASE_NAME}_old`)],
		["前に文字が付く", withDatabase(`x${E2E_DATABASE_NAME}`)],
		["大文字違い", withDatabase(E2E_DATABASE_NAME.toUpperCase())],
		["DB名なし", "postgresql://oauth21:x@127.0.0.1:5493/"],
		["postgres以外のスキーム", `mysql://oauth21:x@127.0.0.1:3306/${E2E_DATABASE_NAME}`],
	];
	for (const [label, url] of rejected) {
		test(`拒否する: ${label}`, () => {
			expect(() => assertE2eDatabaseUrl(url)).toThrow();
		});
	}
});

test.describe("削除の直前に実際の接続先を確かめる", () => {
	async function currentDatabaseOf(url: string) {
		const sql = postgres(url, { max: 1 });
		return {
			current: async () => (await sql`select current_database() as name`)[0].name as string,
			close: () => sql.end(),
		};
	}

	test("実際の接続先がE2E専用DBでなければ、削除処理を呼ばずに例外を投げる", async () => {
		const other = await currentDatabaseOf(withDatabase(NON_E2E_DATABASE));
		const e2e = await currentDatabaseOf(E2E_DATABASE_URL);
		let resetCalls = 0;
		try {
			// 対照として、E2E専用DBの接続と並べても1つでも違えば止まる。
			for (const currentDatabases of [[other.current], [e2e.current, other.current]]) {
				await expect(
					resetIfE2eDatabase({
						currentDatabases,
						reset: async () => {
							resetCalls++;
						},
					}),
				).rejects.toThrow(NON_E2E_DATABASE);
			}
			expect(resetCalls).toBe(0);
		} finally {
			await other.close();
			await e2e.close();
		}
	});

	test("実際の接続先がE2E専用DBなら削除処理へ進む（対照）", async () => {
		const e2e = await currentDatabaseOf(E2E_DATABASE_URL);
		let resetCalls = 0;
		try {
			await resetIfE2eDatabase({
				currentDatabases: [e2e.current],
				reset: async () => {
					resetCalls++;
				},
			});
			expect(resetCalls).toBe(1);
		} finally {
			await e2e.close();
		}
	});
});

test("E2Eサーバーは、DB名が一致しない DATABASE_URL では接続を作る前に起動を中止する", () => {
	// パスワードにだけE2E専用DBの名前を含め、実際の接続先は別のDBにした設定。
	const url = new URL(withDatabase(NON_E2E_DATABASE));
	url.password = E2E_DATABASE_NAME;
	const result = spawnSync("npx", ["tsx", "test/e2e/server.ts"], {
		cwd: fileURLToPath(new URL("../..", import.meta.url)),
		env: { ...process.env, NODE_ENV: "production", DATABASE_URL: url.toString() },
		encoding: "utf8",
		timeout: 60_000,
	});
	expect(result.status).not.toBe(0);
	expect(result.stderr).toContain("E2E専用DB");
	// 認証エラー等（接続を試みた痕跡）ではなく、DB名の確認で止まっている。
	expect(result.stderr).not.toMatch(/password authentication failed|ECONNREFUSED/);
});
