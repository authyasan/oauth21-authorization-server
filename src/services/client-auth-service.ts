import { findClientById } from "../repositories/client-repository.js";
import type { ClientConfig } from "../types/client.js";
import { constantTimeEqual, sha256 } from "../utils/crypto.js";
import { decodeFormComponent } from "../utils/form-encoding.js";
import { logger } from "../utils/logger.js";

/**
 * クライアント認証サービス。
 *
 * client_secret_post（MUST）+ client_secret_basic に対応。
 *   OAuth 2.1ではclient_secret_postが必須。client_secret_basicも広く使われるため対応。
 *
 * 複数の認証方式が同時に送られた場合はinvalid_request。
 *   RFC 6749 Section 5.2のinvalid_requestの定義に「utilizes more than one mechanism
 *   for authenticating the client」が明記されている。
 *
 * client_secretの比較は定数時間比較。
 *   [SECURITY] タイミング攻撃対策。
 *
 * パブリッククライアントが認証情報を送信した場合はinvalid_request。
 *   クライアントの設定ミス（シークレットの埋め込み等）を早期に検出するため、
 *   認証失敗とは区別したエラーで開発者に気づかせる。
 */

export type ClientAuthResult =
	| {
			type: "success";
			client: ClientConfig;
			authMethod: "client_secret_post" | "client_secret_basic" | "none";
	  }
	| {
			type: "failure";
			errorCode: "invalid_request" | "invalid_client";
			errorDescription: string;
	  };

// 純粋な認証失敗（不明なclient_id、client_secret不一致など）に共通で使う失敗結果。
// 認証失敗の内訳は区別せず固定文言とする。
// [SECURITY] どの段階で失敗したかを応答から区別できないよう、文言は固定する。
// 内訳を区別して返すと、応答の違いから登録済みクライアントIDを列挙できてしまう。
// 詳細な失敗理由はログにのみ記録する。
const AUTH_FAILURE: ClientAuthResult = {
	type: "failure",
	errorCode: "invalid_client",
	errorDescription: "Client authentication failed",
};

/**
 * トークンリクエストのクライアント認証を行う。
 *
 * @param authorizationHeader Authorizationヘッダーの値（client_secret_basic用）
 * @param bodyClientId リクエストボディのclient_id
 * @param bodyClientSecret リクエストボディのclient_secret
 * @returns 判別可能な認証結果（success / failure）
 */
export function authenticateClient(
	authorizationHeader: string | undefined,
	bodyClientId: string | undefined,
	bodyClientSecret: string | undefined,
): ClientAuthResult {
	// #@range_begin(client-auth-method-selection) ※書籍掲載用の範囲マーカー
	// 認証方式の検出
	// RFC 9110 §11.1 / §11.4: 大小を区別せず、区切りのASCII SPだけを消費する。
	// 空のBasicやタブ区切りも検出し、不正な認証試行を認証なしへ落とさない。
	const basicPrefix = authorizationHeader?.match(/^Basic(?=[ \t]|$) */i);
	const hasBasicAuth = basicPrefix != null;
	const hasPostAuth = bodyClientSecret !== undefined && bodyClientSecret !== "";

	// 複数の認証方式が同時に送られた場合はinvalid_request
	// （RFC 6749 Section 5.2がこのケースをinvalid_requestとして名指ししている）
	if (hasBasicAuth && hasPostAuth) {
		logger.warn("クライアント認証: 複数の認証方式が同時に送信された");
		return {
			type: "failure",
			errorCode: "invalid_request",
			errorDescription: "Multiple client authentication methods are not allowed",
		};
	}
	// #@range_end(client-auth-method-selection)

	// client_secret_basic
	if (basicPrefix) {
		return authenticateBasic(authorizationHeader?.slice(basicPrefix[0].length) ?? "");
	}

	// client_secret_post
	if (hasPostAuth) {
		return authenticatePost(bodyClientId, bodyClientSecret);
	}

	// 認証情報なし → パブリッククライアント
	if (!bodyClientId) {
		logger.warn("クライアント認証: client_idが指定されていない");
		return AUTH_FAILURE;
	}

	const client = findClientById(bodyClientId);
	if (!client) {
		logger.warn("クライアント認証: 不明なclient_id", { clientId: bodyClientId });
		return AUTH_FAILURE;
	}

	// コンフィデンシャルクライアントが認証情報なしでリクエストした場合はエラー
	// （RFC 6749 Section 5.2: 「no client authentication included」はinvalid_client）
	if (client.clientType === "confidential") {
		logger.warn("クライアント認証: コンフィデンシャルクライアントに認証情報がない", {
			clientId: bodyClientId,
		});
		return AUTH_FAILURE;
	}

	return { type: "success", client, authMethod: "none" };
}

/**
 * client_secret_basic認証。
 *
 * RFC 6749 §2.3.1 のフォーム符号化を戻す。
 * Authorization: Basic base64(formEncode(client_id):formEncode(client_secret))
 */
function authenticateBasic(encoded: string): ClientAuthResult {
	// [SECURITY] RFC 9110 §11.2: token68内の空白をBase64デコーダに無視させない。
	if (!/^[A-Za-z0-9._~+/-]+=*$/.test(encoded) || /[\r\n]/.test(encoded)) {
		logger.warn("クライアント認証: Basic認証のtoken68が不正");
		return AUTH_FAILURE;
	}
	let decoded: string;
	try {
		decoded = Buffer.from(encoded, "base64").toString("utf-8");
	} catch {
		logger.warn("クライアント認証: Basic認証のBase64デコードに失敗");
		return AUTH_FAILURE;
	}

	const colonIndex = decoded.indexOf(":");
	if (colonIndex === -1) {
		logger.warn("クライアント認証: Basic認証の形式が不正（コロンがない）");
		return AUTH_FAILURE;
	}

	// RFC 6749 §2.3.1: フォーム符号化（付録B）を戻す。「+」は空白になる。
	const clientId = decodeFormComponent(decoded.slice(0, colonIndex));
	const clientSecret = decodeFormComponent(decoded.slice(colonIndex + 1));
	// [SECURITY] 不正なパーセントエンコードは例外にせず、認証失敗（401）として返す。
	if (clientId === null || clientSecret === null) {
		logger.warn("クライアント認証: Basic認証のパーセントエンコードが不正");
		return AUTH_FAILURE;
	}

	return verifyClientSecret(clientId, clientSecret, "client_secret_basic");
}

/**
 * client_secret_post認証。
 */
function authenticatePost(
	clientId: string | undefined,
	clientSecret: string | undefined,
): ClientAuthResult {
	if (!clientId || !clientSecret) {
		logger.warn("クライアント認証: client_secret_postにclient_idまたはclient_secretがない");
		return AUTH_FAILURE;
	}

	return verifyClientSecret(clientId, clientSecret, "client_secret_post");
}

/**
 * client_secretの検証。
 *
 * [SECURITY] 定数時間比較でclient_secretを検証する。
 * 通常の文字列比較(===)はタイミング攻撃に脆弱。
 */
function verifyClientSecret(
	clientId: string,
	clientSecret: string,
	method: "client_secret_post" | "client_secret_basic",
): ClientAuthResult {
	const client = findClientById(clientId);
	if (!client) {
		logger.warn("クライアント認証: 不明なclient_id", { clientId, method });
		return AUTH_FAILURE;
	}

	// パブリッククライアントが認証情報を送信した場合はinvalid_request
	// （クライアントの設定ミスの兆候。暗黙に無視せず明確なエラーで開発者に気づかせる）
	if (client.clientType === "public") {
		logger.warn("クライアント認証: パブリッククライアントが認証情報を送信した", {
			clientId,
			method,
		});
		return {
			type: "failure",
			errorCode: "invalid_request",
			errorDescription: "Public clients must not send client credentials",
		};
	}

	if (!client.clientSecretHash) {
		logger.error("クライアント認証: コンフィデンシャルクライアントにclientSecretHashが未設定", {
			clientId,
		});
		return AUTH_FAILURE;
	}

	// [SECURITY] 定数時間比較: client_secretのSHA-256ハッシュを比較
	// タイミング攻撃を防ぐために、constantTimeEqualを使用する
	// #@range_begin(client-secret-hash-comparison) ※書籍掲載用の範囲マーカー
	const providedHash = sha256(clientSecret);
	if (!constantTimeEqual(providedHash, client.clientSecretHash)) {
		logger.warn("クライアント認証: client_secretが不一致", { clientId, method });
		return AUTH_FAILURE;
	}
	// #@range_end(client-secret-hash-comparison)

	return { type: "success", client, authMethod: method };
}
