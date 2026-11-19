import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import * as schema from "./schema.js";

// 接続先の指定漏れを起動時に検出する。
const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
	throw new Error("DATABASE_URL環境変数が設定されていません");
}

const client = postgres(connectionString);
export const db = drizzle(client, { schema });

export { client };

/** Drizzleのデータベースハンドル型 */
export type Database = typeof db;

/** db.transaction コールバックに渡されるトランザクションハンドル型 */
export type Transaction = Parameters<Parameters<Database["transaction"]>[0]>[0];

/**
 * リポジトリ関数をトランザクション内外から共通に呼び出すための型。
 */
export type Executor = Database | Transaction;
