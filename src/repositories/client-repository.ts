import { getClient } from "../config/clients.js";
import type { ClientConfig } from "../types/client.js";

/**
 * client_idからクライアント設定を取得する。
 * クライアントは設定ファイル（clients.json）で管理する（動的登録なし）。
 */
export function findClientById(clientId: string): ClientConfig | undefined {
	return getClient(clientId);
}
