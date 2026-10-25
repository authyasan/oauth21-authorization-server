import { jwtVerify } from "jose";
import { getPublicKey } from "../config/keys.js";
import { revokeGrant } from "../repositories/grant-repository.js";
import {
	findAccessTokenByJti,
	findRefreshTokenByHash,
	revokeAccessTokenByJti,
} from "../repositories/token-repository.js";
import { sha256 } from "../utils/crypto.js";
import { logger } from "../utils/logger.js";

/**
 * トークンリボケーションサービス。
 * RFC 7009に準拠したトークン無効化を行う。
 *
 * パブリッククライアントにもリボケーションを許可。
 * JWT署名検証あり、有効期限チェックなし。
 * リフレッシュトークンリボーク時のみカスケード。
 * token_type_hintを優先し、見つからなければ他方を検索。
 */

/**
 * トークンをリボークする。
 *
 * RFC 7009: 無効なトークン・存在しないトークンでもエラーにしない（200を返す）。
 * クライアントにトークンの有効性を推測させないため。
 *
 * @param token リボーク対象のトークン文字列
 * @param tokenTypeHint トークン種類のヒント（access_token | refresh_token）
 * @param clientId リクエスト元のクライアントID
 */
// #@range_begin(revoke-token-hint) ※書籍掲載用の範囲マーカー
export async function revokeToken(params: {
	token: string;
	tokenTypeHint?: string;
	clientId: string;
}): Promise<void> {
	const { token, tokenTypeHint, clientId } = params;

	// ヒントを優先的に使い、見つからなければもう一方を検索
	if (tokenTypeHint === "refresh_token") {
		const revoked = await tryRevokeRefreshToken(token, clientId);
		if (!revoked) {
			await tryRevokeAccessToken(token, clientId);
		}
	} else {
		// token_type_hint=access_token、未知のヒント値、ヒントなしの場合
		const revoked = await tryRevokeAccessToken(token, clientId);
		if (!revoked) {
			await tryRevokeRefreshToken(token, clientId);
		}
	}
}
// #@range_end(revoke-token-hint)

/**
 * アクセストークン（JWT）のリボークを試みる。
 *
 * 署名検証あり、有効期限チェックなし。
 * 改ざんされたJWTから偽のjtiを取り出すことを防ぐ。
 *
 * @returns リボークに成功した（またはトークンが見つかった）場合はtrue
 */
// #@range_begin(revoke-access-token) ※書籍掲載用の範囲マーカー
async function tryRevokeAccessToken(token: string, clientId: string): Promise<boolean> {
	// [SECURITY] JWT署名検証（有効期限チェックはスキップ）
	let jti: string;
	try {
		const publicKey = await getPublicKey();
		const { payload } = await jwtVerify(token, publicKey, {
			// 有効期限切れトークンもリボーク可能にするため、
			// 現在時刻をUNIXエポック(0)に設定して有効期限チェックを実質無効化する
			currentDate: new Date(0),
			// [SECURITY] アルゴリズムを RS256 に固定（多層防御）
			algorithms: ["RS256"],
		});

		if (!payload.jti) {
			logger.warn("リボケーション: JWTにjtiがない", { clientId });
			return false;
		}
		jti = payload.jti;
	} catch {
		// JWT署名検証に失敗 → アクセストークンではない
		return false;
	}

	// DB上でトークンの存在確認
	const tokenRecord = await findAccessTokenByJti(jti);
	if (!tokenRecord) {
		return false;
	}

	// クライアントID一致チェック
	if (tokenRecord.clientId !== clientId) {
		logger.warn("リボケーション: アクセストークンのclient_idが一致しない", {
			expected: tokenRecord.clientId,
			actual: clientId,
		});
		return false;
	}

	// すでにリボーク済みの場合は何もしない（200を返す）
	if (tokenRecord.revokedAt) {
		return true;
	}

	await revokeAccessTokenByJti(jti);
	logger.info("リボケーション: アクセストークンをリボーク", {
		jti,
		clientId,
	});
	return true;
}
// #@range_end(revoke-access-token)

/**
 * リフレッシュトークンのリボークを試みる。
 *
 * リフレッシュトークンリボーク時は関連するアクセストークンもカスケードリボークする。
 *
 * @returns リボークに成功した（またはトークンが見つかった）場合はtrue
 */
// #@range_begin(revoke-refresh-token) ※書籍掲載用の範囲マーカー
async function tryRevokeRefreshToken(token: string, clientId: string): Promise<boolean> {
	// [SECURITY] SHA-256ハッシュでDB検索（平文はDBに保存していない）
	const tokenHash = sha256(token);

	// 使用済み・失効済み・期限切れのいずれも除外せずに検索する。
	// ローテーションで一世代前になったリフレッシュトークンを提示された場合も
	// grant のカスケード失効まで進める。
	const tokenRecord = await findRefreshTokenByHash(tokenHash);
	if (!tokenRecord) {
		return false;
	}

	// クライアントID一致チェック
	if (tokenRecord.clientId !== clientId) {
		logger.warn("リボケーション: リフレッシュトークンのclient_idが一致しない", {
			expected: tokenRecord.clientId,
			actual: clientId,
		});
		return false;
	}

	// [SECURITY] リフレッシュトークンのリボークは grant 単位の失効として扱う。
	// revokeGrant が grants.revoked_at をセットし、配下の AT / RT（このRTを含む）を
	// 連動失効させる（カスケード）。
	await revokeGrant(tokenRecord.grantId);
	logger.info("リボケーション: リフレッシュトークンを起点に grant をカスケード失効", {
		clientId,
		grantId: tokenRecord.grantId,
	});

	return true;
}
// #@range_end(revoke-refresh-token)
