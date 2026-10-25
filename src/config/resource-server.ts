import type { ResourceServerConfig } from "../types/resource-server.js";
import resourcesData from "./resource-server.json" with { type: "json" };

// リソースサーバー設定を読み込む
// クライアント設定（clients.json）とは明示的に分離する。
// OAuthにおいてクライアントとリソースサーバーは異なる役割であるため。
const resourceServerMap = new Map<string, ResourceServerConfig>();

for (const rs of resourcesData as ResourceServerConfig[]) {
	if (resourceServerMap.has(rs.resourceServerId)) {
		throw new Error(`リソースサーバーID重複: ${rs.resourceServerId}`);
	}
	resourceServerMap.set(rs.resourceServerId, rs);
}

export function getResourceServer(resourceServerId: string): ResourceServerConfig | undefined {
	return resourceServerMap.get(resourceServerId);
}

/**
 * 指定されたスコープに関連するリソースサーバーのIDリストを返す。
 * スコープとリソースサーバーの紐づけは resource-server.json の protectedScopes に基づく。
 */
export function getAudienceForScopes(scopes: string[]): string[] {
	const audiences: string[] = [];
	for (const rs of resourceServerMap.values()) {
		if (scopes.some((scope) => rs.protectedScopes.includes(scope))) {
			audiences.push(rs.resourceServerId);
		}
	}
	return audiences;
}
