import {
	type AuthorizationCodeRecord,
	findAuthorizationCodeByHash,
} from "../repositories/authorization-code-repository.js";
import { sha256 } from "../utils/crypto.js";
import { logger } from "../utils/logger.js";
import { verifyCodeChallenge } from "./pkce-service.js";

/**
 * 認可コード検証サービス。
 *
 * コードの存在と、発行先のクライアント・リダイレクトURI・PKCEを検証する。
 * 使用済み・期限切れの判定とトークン発行はexchangeAuthorizationCodeに委ねる。
 *
 * 使用済みコード再使用時のトークン無効化は、リクエストの
 * 他のパラメータ（client_id, 指定時のredirect_uri, code_verifier）がすべて正しい
 * 場合に限る（OAuth 2.1 draft-16 §7.5.3のDoS対策）。本関数の事前検証を全て通過することが、
 * その前提条件になる。不正なパラメータはここで拒否し、コードの消費もトークンの無効化も
 * 起こさない。
 */

export interface VerifiedAuthorizationCode {
	codeRecord: AuthorizationCodeRecord;
}

/**
 * 認可コードを検証する（読み取り専用の事前検証）。
 *
 * 使用済み・有効期限の判定はここでは行わない。原子的消費
 * （consumeAuthorizationCodeIfFresh）の UPDATE 条件
 * （used_at IS NULL AND expires_at >= now()）に委ねることで、SELECT と UPDATE の
 * 時間差による取りこぼし（TOCTOU）を避ける。
 *
 * @returns 検証成功時はコードレコード、失敗時はnull
 */
export async function verifyAuthorizationCode(params: {
	code: string;
	clientId: string;
	redirectUri?: string;
	codeVerifier: string;
}): Promise<VerifiedAuthorizationCode | null> {
	const { code, clientId, redirectUri, codeVerifier } = params;

	// [SECURITY] コードのSHA-256ハッシュでDB検索（平文はDBに保存していない）
	const codeHash = sha256(code);
	const codeRecord = await findAuthorizationCodeByHash(codeHash);

	if (!codeRecord) {
		logger.warn("認可コード検証: コードが存在しない", { clientId });
		return null;
	}

	// 発行先のクライアント以外によるコードの利用を拒否する。
	if (codeRecord.clientId !== clientId) {
		logger.warn("認可コード検証: client_idが一致しない", {
			expected: codeRecord.clientId,
			actual: clientId,
		});
		return null;
	}

	// [SECURITY] redirect_uriは指定時だけ完全一致で照合する。
	// トークンエンドポイントで空値を省略に正規化してから、この事前検証に渡す。
	if (redirectUri !== undefined && codeRecord.redirectUri !== redirectUri) {
		logger.warn("認可コード検証: redirect_uriが一致しない", {
			clientId,
		});
		return null;
	}

	// [SECURITY] 認可コードだけを入手した第三者による交換を防ぐ。
	if (
		!verifyCodeChallenge(codeVerifier, codeRecord.codeChallenge, codeRecord.codeChallengeMethod)
	) {
		logger.warn("認可コード検証: PKCE検証に失敗", { clientId });
		return null;
	}

	return { codeRecord };
}
