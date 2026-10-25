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
 * ここでは「認可コードが構造的に正当か」だけを判定する（読み取り専用）。
 * 認可コードの一回限り消費・再利用検知・期限切れ判定・トークン発行は、原子性のため
 * exchangeAuthorizationCode（token-service）が消費と同一トランザクションで行う。
 *
 * 使用済みコード再使用時のトークン無効化は、リクエストの
 * 他のパラメータ（client_id, 指定時のredirect_uri, code_verifier）が全て valid な
 * 場合に限る（OAuth 2.1 draft-16 §7.5.3のDoS対策）。本関数の事前検証を全て通過することが、
 * その「valid な再使用」の前提条件になる。不正パラメータはここで弾かれ、消費も失効も
 * 起こさない。
 */

export interface VerifiedAuthorizationCode {
	codeRecord: AuthorizationCodeRecord;
}

/**
 * 認可コードを検証する（読み取り専用の事前検証）。
 *
 * 検証順序:
 * 1. コードの存在確認（SHA-256ハッシュでDB検索）
 * 2. client_id一致チェック
 * 3. redirect_uriが指定されている場合だけ一致チェック
 * 4. PKCE検証（code_verifier → SHA-256 → Base64URL → code_challenge一致）
 *
 * 使用済み・有効期限の判定はここでは行わない。原子的消費
 * （consumeAuthorizationCodeIfFresh）の UPDATE 条件
 * （used_at IS NULL AND expires_at >= now()）に委ねることで、SELECT と UPDATE の
 * 時間差による取りこぼし（TOCTOU）を避ける。
 *
 * @returns 検証成功時はコードレコード、失敗時はnull
 */
// #@range_begin(verify-authorization-code) ※書籍掲載用の範囲マーカー
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

	// 1. 存在確認
	if (!codeRecord) {
		logger.warn("認可コード検証: コードが存在しない", { clientId });
		return null;
	}

	// 2. client_id一致チェック
	if (codeRecord.clientId !== clientId) {
		logger.warn("認可コード検証: client_idが一致しない", {
			expected: codeRecord.clientId,
			actual: clientId,
		});
		return null;
	}

	// 3. [SECURITY] redirect_uriは指定時だけ完全一致で照合する。
	// トークンエンドポイントで空値を省略に正規化してから、この事前検証に渡す。
	if (redirectUri !== undefined && codeRecord.redirectUri !== redirectUri) {
		logger.warn("認可コード検証: redirect_uriが一致しない", {
			clientId,
		});
		return null;
	}

	// 4. [SECURITY] PKCE検証
	if (
		!verifyCodeChallenge(codeVerifier, codeRecord.codeChallenge, codeRecord.codeChallengeMethod)
	) {
		logger.warn("認可コード検証: PKCE検証に失敗", { clientId });
		return null;
	}

	return { codeRecord };
}
// #@range_end(verify-authorization-code)
