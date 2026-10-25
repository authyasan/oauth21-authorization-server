import { getResourceServer } from "../config/resource-server.js";
import type { ResourceServerConfig } from "../types/resource-server.js";
import { constantTimeEqual, sha256 } from "../utils/crypto.js";
import { logger } from "../utils/logger.js";

/**
 * リソースサーバー認証サービス。
 *
 * イントロスペクションエンドポイントで使用する。
 * クライアント認証（client-auth-service）とは分離している。
 * OAuthにおいてクライアントとリソースサーバーは異なる役割であるため。
 *
 * 認証方式はBasic認証のみ対応。
 * リソースサーバーは常にバックエンドサービスであり、Basic認証で十分。
 * RFC 7662は認証方式を規定していないため、実装の裁量で選択している。
 */

export interface ResourceServerAuthResult {
	resourceServer: ResourceServerConfig;
}

/**
 * リソースサーバーを認証する。
 *
 * @param authorizationHeader Authorizationヘッダーの値（Basic認証）
 * @returns 認証成功時はリソースサーバー情報、失敗時はnull
 */
// #@range_begin(rs-auth) ※書籍掲載用の範囲マーカー
export function authenticateResourceServer(
	authorizationHeader: string | undefined,
): ResourceServerAuthResult | null {
	if (!authorizationHeader?.startsWith("Basic ")) {
		logger.warn("リソースサーバー認証: Basic認証ヘッダーがない");
		return null;
	}

	const encoded = authorizationHeader.slice(6);
	let decoded: string;
	try {
		decoded = Buffer.from(encoded, "base64").toString("utf-8");
	} catch {
		logger.warn("リソースサーバー認証: Basic認証のBase64デコードに失敗");
		return null;
	}

	const colonIndex = decoded.indexOf(":");
	if (colonIndex === -1) {
		logger.warn("リソースサーバー認証: Basic認証の形式が不正");
		return null;
	}

	const resourceServerId = decodeURIComponent(decoded.slice(0, colonIndex));
	const secret = decodeURIComponent(decoded.slice(colonIndex + 1));

	const resourceServer = getResourceServer(resourceServerId);
	if (!resourceServer) {
		logger.warn("リソースサーバー認証: 不明なリソースサーバーID", {
			resourceServerId,
		});
		return null;
	}

	// [SECURITY] 定数時間比較: シークレットのSHA-256ハッシュを比較
	const providedHash = sha256(secret);
	if (!constantTimeEqual(providedHash, resourceServer.secretHash)) {
		logger.warn("リソースサーバー認証: シークレットが不一致", {
			resourceServerId,
		});
		return null;
	}

	return { resourceServer };
}
// #@range_end(rs-auth)
