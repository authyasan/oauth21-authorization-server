/**
 * E2Eサーバーの最初に読み込み、DBに接続するモジュールより前に設定を確かめる。
 * ESMは import を書いた順に評価するので、server.ts の先頭で読み込めばアプリやテスト用の接続より先に実行される。
 */
import { assertE2eDatabaseUrl } from "./db-guard.js";

// E2Eは本番相当（__Host-sid・Secure）で動かす。
if (process.env.NODE_ENV !== "production") {
	throw new Error("NODE_ENV=production で起動してください");
}
// /reset は全テーブルを削除するので、DB名を完全一致で確かめる。
assertE2eDatabaseUrl(process.env.DATABASE_URL);
