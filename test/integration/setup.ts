import { sql } from "drizzle-orm";
import { beforeAll } from "vitest";
import { db } from "../../src/db/connection.js";
import { assertIntegrationDatabaseConnections } from "./db-guard.js";
import { testDb } from "./helpers.js";

// 各テストファイルの初期化・データ削除より先に、両方の実際の接続先を確認する。
beforeAll(async () => {
	await assertIntegrationDatabaseConnections(
		[db, testDb].map((connection) => async () => {
			const rows = await connection.execute<{ name: string }>(
				sql`select current_database() as name`,
			);
			return rows[0]?.name ?? "";
		}),
	);
});
