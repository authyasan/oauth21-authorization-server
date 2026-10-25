import { serverConfig } from "../config/server.js";
import { findAccessTokenByJti } from "../repositories/token-repository.js";
import { logger } from "../utils/logger.js";

/**
 * イントロスペクションサービス。
 * RFC 7662に準拠したトークン検証を行う。
 *
 * イントロスペクションエンドポイントは、認証済みのリソースサーバーからの照会だけを受け付ける。
 * JWTペイロードと同等のクレームを返す。
 * アクセストークンのみ対応（リフレッシュトークンは非対応）。
 * Cache-Control: no-store を付ける。
 * 照会元リソースサーバーがトークンのaudに含まれない場合、active: false を返す。
 */

/** イントロスペクションレスポンスの型 */
export interface IntrospectionResponse {
	active: boolean;
	// active=trueの場合のみ以下のクレームを含む
	scope?: string;
	client_id?: string;
	sub?: string;
	exp?: number;
	iat?: number;
	jti?: string;
	iss?: string;
	aud?: string | string[];
	token_type?: string;
}

/**
 * トークンをイントロスペクションする。
 *
 * JWTのjtiを使ってDB上のトークン情報を検索し、有効性を返す。
 * 無効なトークン（存在しない、期限切れ、リボーク済み）は active: false を返す。
 * 照会元リソースサーバーがトークンのaudに含まれない場合も active: false を返す。
 *
 * @param jti JWTから取得したトークン識別子
 * @param requestingResourceServerId Basic認証で特定済みの、照会元リソースサーバーのID
 * @returns イントロスペクションレスポンス
 */
// #@range_begin(introspect-token) ※書籍掲載用の範囲マーカー
export async function introspectToken(
	jti: string,
	requestingResourceServerId: string,
): Promise<IntrospectionResponse> {
	const tokenRecord = await findAccessTokenByJti(jti);

	// トークンが存在しない
	if (!tokenRecord) {
		logger.info("イントロスペクション: トークンが存在しない", { jti });
		return { active: false };
	}

	// [SECURITY] リボーク済みチェック
	if (tokenRecord.revokedAt) {
		logger.info("イントロスペクション: リボーク済みトークン", { jti });
		return { active: false };
	}

	// [SECURITY] 有効期限チェック
	if (tokenRecord.expiresAt < new Date()) {
		logger.info("イントロスペクション: 有効期限切れトークン", { jti });
		return { active: false };
	}

	// JWTペイロードと同等のクレームを返す
	// [SECURITY] audは発行時にJWTへ入れてDBに保存した値を使う。現在のscope→RS設定から
	// 計算し直すと、設定変更後にJWTのaudと照会結果・照会元の判定が食い違う。
	// 単一の場合は文字列、複数の場合は配列で返す（JWT 発行ロジックと一致させる）。
	const audiences = tokenRecord.audience;

	// [SECURITY] 照会元RSがaudに含まれないトークンはactive:falseにする。
	// RFC 7662 §4は、トークンが特定のRSでしか使えない場合、照会元RSで使えるかの判定をMUSTで課している。
	// この検証がないと、あるRSのクレデンシャルで他RS宛トークンの状態とクレーム（sub/scope等）を照会できてしまう。
	if (!audiences.includes(requestingResourceServerId)) {
		logger.warn("イントロスペクション: 照会元RSがaudに含まれない", {
			jti,
			requestingResourceServerId,
			aud: audiences,
		});
		return { active: false };
	}

	const aud = audiences.length === 1 ? audiences[0] : audiences;

	return {
		active: true,
		scope: tokenRecord.scope,
		client_id: tokenRecord.clientId,
		sub: tokenRecord.userId,
		exp: Math.floor(tokenRecord.expiresAt.getTime() / 1000),
		iat: Math.floor(tokenRecord.createdAt.getTime() / 1000),
		jti: tokenRecord.jti,
		iss: serverConfig.issuer,
		aud,
		token_type: "Bearer",
	};
}
// #@range_end(introspect-token)
