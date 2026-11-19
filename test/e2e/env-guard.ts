/**
 * E2Eサーバーの最初に読み込み、DBに接続するモジュールより前に設定を確かめる。
 * server.tsから最初に読み込み、このモジュールと参照先にはDB接続の依存を持たせない。
 */
import { assertE2eDatabaseUrl } from "./db-guard.js";

// E2Eは本番相当（__Host-sid・Secure）で動かす。
if (process.env.NODE_ENV !== "production") {
	throw new Error("NODE_ENV=production で起動してください");
}
// /resetはテストデータを削除するため、接続先のDB名がE2E専用の名前と完全一致することを確認する。
assertE2eDatabaseUrl(process.env.DATABASE_URL);
