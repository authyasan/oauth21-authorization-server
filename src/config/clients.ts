import type { ClientConfig } from "../types/client.js";
import { isAllowedRedirectUriScheme } from "../utils/validation.js";
import clientsData from "./clients.json" with { type: "json" };
import { getAudienceForScopes } from "./resource-server.js";

// 動的登録はスコープ外のため、設定読み込み時に登録URIを検証する。
// HTTPSの受信先が正規クライアントの管理下にあることは、管理者が登録前に確認する。
export function createClientMap(clients: ClientConfig[]): Map<string, ClientConfig> {
	const clientMap = new Map<string, ClientConfig>();
	for (const client of clients) {
		if (clientMap.has(client.clientId)) {
			throw new Error(`クライアントID重複: ${client.clientId}`);
		}

		// [SECURITY] 同意画面に表示する名前が空だと、ユーザーは誰に許可するのか判断できない
		// （OAuth 2.1 draft-16 §7.9）。設定の誤りとして起動を拒否する。
		for (const field of ["clientName", "organizationName"] as const) {
			if (typeof client[field] !== "string" || client[field].trim() === "") {
				throw new Error(`${field}が設定されていません: ${client.clientId}`);
			}
		}

		// [SECURITY] 不正な登録URIが設定されていたら、起動を拒否する。
		for (const redirectUri of client.redirectUris) {
			try {
				// 絶対URLとして解析できるかを確認する。生成されたオブジェクトは使わない。
				new URL(redirectUri);
			} catch {
				throw new Error(
					`redirect_uriをURLとして解析できません: ${client.clientId} / ${redirectUri}`,
				);
			}
			if (redirectUri.includes("#")) {
				throw new Error(
					`redirect_uri にフラグメントを含めることはできません（RFC 6749 §3.1.2）: ${client.clientId} / ${redirectUri}`,
				);
			}
			// URLとして解析できても、本書で許可するスキーム・ホストとは限らない。
			if (!isAllowedRedirectUriScheme(redirectUri)) {
				throw new Error(
					`redirect_uriのスキームが許可されていません: ${client.clientId} / ${redirectUri}`,
				);
			}
		}
		// [SECURITY] アクセストークンの aud はスコープから逆引きする。どのリソースサーバーにも
		// 対応しないスコープだけを要求されると aud が空になり、RFC 9068 §2.2 が必須とする
		// aud を持たないトークンを発行してしまう。設定の誤りとして起動を拒否する。
		for (const scope of client.allowedScopes) {
			if (getAudienceForScopes([scope]).length === 0) {
				throw new Error(
					`allowedScopesのスコープがどのリソースサーバーにも対応していません: ${client.clientId} / ${scope}`,
				);
			}
		}
		clientMap.set(client.clientId, client);
	}
	return clientMap;
}

const clientMap = createClientMap(clientsData as ClientConfig[]);

export function getClient(clientId: string): ClientConfig | undefined {
	return clientMap.get(clientId);
}
