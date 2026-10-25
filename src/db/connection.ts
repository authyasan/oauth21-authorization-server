import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import * as schema from "./schema.js";

// postgres.jsクライアントの作成
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
 * クエリ実行体。通常の db ハンドルとトランザクションハンドルの両方を受け付ける。
 * リポジトリ関数がトランザクション内外どちらからも呼べるようにするための型。
 */
export type Executor = Database | Transaction;
