import "dotenv/config";
import { hashPassword } from "../utils/password.js";
import { client, db } from "./connection.js";
import { users } from "./schema.js";

// 開発用シードデータ
// パスワードハッシュはbcryptを使用

async function seed() {
	console.log("シードデータを投入します...");

	// テストユーザーの作成
	const testUserHash = await hashPassword("password123");
	const adminHash = await hashPassword("admin123");

	await db
		.insert(users)
		.values([
			{
				username: "testuser",
				passwordHash: testUserHash,
			},
			{
				username: "admin",
				passwordHash: adminHash,
			},
		])
		.onConflictDoNothing();

	console.log("シードデータの投入が完了しました。");
	await client.end();
}

seed().catch((err) => {
	console.error("シードデータの投入に失敗しました:", err);
	process.exit(1);
});
