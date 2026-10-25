import { MIMEType } from "node:util";
import type { Context } from "hono";
import { Hono } from "hono";
import type { ContentfulStatusCode } from "hono/utils/http-status";
import {
	invalidClient,
	invalidGrant,
	invalidRequest,
	invalidScope,
	type OAuthError,
	unsupportedGrantType,
} from "../errors/oauth-error.js";
import { verifyAuthorizationCode } from "../services/authorization-code-verifier.js";
import { authenticateClient } from "../services/client-auth-service.js";
import { isValidPkceCodeVerifier } from "../services/pkce-service.js";
import { rotateRefreshToken, verifyRefreshToken } from "../services/refresh-token-service.js";
import { exchangeAuthorizationCode } from "../services/token-service.js";
import type { ClientConfig } from "../types/client.js";
import { logger } from "../utils/logger.js";

// 未対応の拡張パラメータは無視する。拡張を実装するときは、その多値の規定も確認する。
const TOKEN_REQUEST_PARAMETERS = [
	"grant_type",
	"client_id",
	"client_secret",
	"code",
	"redirect_uri",
	"code_verifier",
	"refresh_token",
	"scope",
] as const;

type TokenRequest = Partial<Record<(typeof TOKEN_REQUEST_PARAMETERS)[number], string>>;

/**
 * トークンエンドポイント。
 * POST /token: 認可コードをアクセストークンに交換する。
 *
 * grant_typeはauthorization_codeとrefresh_tokenのみ対応。
 * エラーレスポンスにはerror_descriptionを含める（invalid_grantは汎用メッセージ）。
 *
 * セキュリティ要件:
 * - Cache-Control: no-store（OAuth 2.1 draft-16 §3.2.3。成功・エラーとも）
 * - Content-Type: application/json
 *
 * Pragma: no-cache は付けない。RFC 6749 §5.1 は求めていたが、draft-16 §3.2.3 が求めるのは
 * Cache-Control: no-store だけで、RFC 9111 §5.4 は Pragma を非推奨とし、応答での意味は
 * 定められていないとする。HTTP/1.0 キャッシュとの互換は要件にしない。
 */
export function createTokenEndpoint() {
	const app = new Hono();

	app.post("/token", async (c) => {
		// [SECURITY] OAuth 2.1 draft-16 §3.2.2 / 付録C.2: UTF-8のフォームだけを受け付ける。
		// 本文解析・クライアント認証・トークンの状態変更より前に拒否する。
		if (!isFormContentType(c.req.header("Content-Type"))) {
			const error = invalidRequest(
				"Content-Type must be application/x-www-form-urlencoded with UTF-8 encoding",
			);
			return tokenErrorResponse(c, error);
		}

		// parseBodyの生ヘッダー前方一致を使わず、大文字小文字を問わずフォームを読む。
		// #@range_begin(token-request-parameters) ※書籍掲載用の範囲マーカー
		const rawBody = await c.req.formData();

		// [SECURITY] 空値の除去・クライアント認証・状態変更より先に重複を拒否する。
		// OAuth 2.1 draft-16 §3.2 / §3.2.4。同じ値や空値を含む重複も対象とする。
		for (const name of TOKEN_REQUEST_PARAMETERS) {
			if (rawBody.getAll(name).length > 1) {
				return tokenErrorResponse(c, invalidRequest(`Duplicate ${name} parameter`));
			}
		}

		const body: TokenRequest = {};
		for (const name of TOKEN_REQUEST_PARAMETERS) {
			const value = rawBody.get(name);
			// §3.2: 空値は省略として扱う。空白を含む非空文字列は変更しない。
			if (value === null || value === "") continue;
			// multipartはContent-Typeで拒否するため通常は文字列のみ。型を絞り込むため防御的に確認する。
			if (typeof value !== "string") {
				return tokenErrorResponse(c, invalidRequest(`Invalid ${name} parameter`));
			}
			body[name] = value;
		}
		// #@range_end(token-request-parameters)

		const grantType = body.grant_type;

		// grant_type必須チェック
		if (!grantType) {
			return tokenErrorResponse(c, invalidRequest("Missing grant_type parameter"));
		}

		// authorization_codeとrefresh_tokenのみ対応
		if (grantType !== "authorization_code" && grantType !== "refresh_token") {
			return tokenErrorResponse(c, unsupportedGrantType(`Unsupported grant_type: ${grantType}`));
		}

		// --- 共通: クライアント認証 ---
		const authResult = authenticateClient(
			c.req.header("Authorization"),
			body.client_id,
			body.client_secret,
		);

		if (authResult.type === "failure") {
			// 認証情報の組み立てがおかしいケースは400 invalid_request、
			// 純粋な認証失敗は401 invalid_client を返す
			const error =
				authResult.errorCode === "invalid_request"
					? invalidRequest(authResult.errorDescription)
					: invalidClient(authResult.errorDescription);
			return tokenErrorResponse(c, error);
		}

		const { client } = authResult;

		// --- authorization_code グラント ---
		if (grantType === "authorization_code") {
			return handleAuthorizationCodeGrant(c, body, client);
		}

		// --- refresh_token グラント ---
		return handleRefreshTokenGrant(c, body, client);
	});

	return app;
}

/**
 * Content-Typeの構文とフォームの文字コードを確認する。
 */
function isFormContentType(contentType: string | undefined): boolean {
	if (!contentType) return false;

	try {
		const mediaType = new MIMEType(contentType);
		if (mediaType.essence !== "application/x-www-form-urlencoded") return false;

		const parameterStart = contentType.indexOf(";");
		if (parameterStart === -1) return true;

		// MIMETypeは不正なパラメータを補正・無視するため、RFC 9110 §5.6.2 / §5.6.4 /
		// §5.6.6の構文も確認する。空のセミコロン要素、quoted-pair、OWSは許可する。
		const parameterPattern =
			/;[ \t]*(?:([!#$%&'*+.^_`|~0-9A-Za-z-]+)=(?:[!#$%&'*+.^_`|~0-9A-Za-z-]+|"(?:[\t\x20\x21\x23-\x5b\x5d-\x7e\x80-\xff]|\\[\t\x20-\x7e\x80-\xff])*"))?[ \t]*/y;
		parameterPattern.lastIndex = parameterStart;
		while (parameterPattern.lastIndex < contentType.length) {
			const parameter = parameterPattern.exec(contentType);
			if (!parameter) return false;
			if (parameter[1]?.toLowerCase() === "charset") {
				// MIMETypeは同名パラメータの先頭だけを保持する。後続の非UTF-8も拒否する。
				const { params } = new MIMEType(`${mediaType.essence}${parameter[0]}`);
				if (params.get("charset")?.toLowerCase() !== "utf-8") return false;
			}
		}
		return true;
	} catch {
		return false;
	}
}

/**
 * authorization_codeグラントの処理。
 */
async function handleAuthorizationCodeGrant(c: Context, body: TokenRequest, client: ClientConfig) {
	const code = body.code;
	const redirectUri = body.redirect_uri;
	const codeVerifier = body.code_verifier;

	if (!code) {
		return tokenErrorResponse(c, invalidRequest("Missing code parameter"));
	}

	// [SECURITY] 必須値の欠落はinvalid_request。空値も正規化済みなので同じ扱い。
	// OAuth 2.1 draft-16 §4.1.3の必須条件と§3.2.4のエラー定義に従う。
	if (!codeVerifier) {
		logger.warn("トークンリクエスト: code_verifierが未指定", {
			clientId: client.clientId,
		});
		return tokenErrorResponse(c, invalidRequest("Missing code_verifier parameter"));
	}

	// [SECURITY] 長さ・文字種の違反は不正な形式のトークンリクエストとして拒否する。
	// 認可コードの検索・消費・再利用による無効化より前に検証する。
	if (!isValidPkceCodeVerifier(codeVerifier)) {
		logger.warn("トークンリクエスト: code_verifierの構文が不正", {
			clientId: client.clientId,
		});
		return tokenErrorResponse(c, invalidRequest("Invalid code_verifier parameter"));
	}

	// 認可コードの事前検証（読み取り専用: 存在・client_id・指定時のredirect_uri・PKCE）
	// レスポンスにはinvalid_grantのみ返す
	const verified = await verifyAuthorizationCode({
		code,
		clientId: client.clientId,
		redirectUri,
		codeVerifier,
	});

	if (!verified) {
		// invalid_grantは汎用メッセージ（詳細はログに記録済み）
		// ここで弾かれた不正パラメータでは、消費も grant 失効も行わない。認可コードだけを盗んだ攻撃者が
		// 不正なリクエストで正規の利用者のトークンを巻き添えで失効させる DoS を防ぐため
		return tokenErrorResponse(c, invalidGrant("The authorization code is invalid"));
	}

	const { codeRecord } = verified;

	// [SECURITY] 認可コードの原子的消費とトークン発行を同一トランザクションで行う。
	// 使用済み・期限切れ・並行交換での敗北はここで invalid_grant になり、再利用なら grant を失効。
	const result = await exchangeAuthorizationCode({ codeRecord, client });

	if (result.type === "invalid_grant") {
		return tokenErrorResponse(c, invalidGrant("The authorization code is invalid"));
	}

	const { token } = result;

	logger.info("トークン発行: 認可コードグラント", {
		clientId: client.clientId,
		userId: codeRecord.userId,
		scope: codeRecord.scope,
	});

	// scopeは常に返す
	// expires_inは実際の有効期限と一致させる
	const responseBody: Record<string, unknown> = {
		access_token: token.accessToken,
		token_type: "Bearer",
		expires_in: token.expiresIn,
		scope: token.scope,
	};

	// リフレッシュトークンはクライアント種別によらず発行する
	responseBody.refresh_token = token.refreshToken;

	return tokenSuccessResponse(c, responseBody);
}

/**
 * refresh_tokenグラントの処理。
 *
 * クライアント種別によらずリフレッシュトークンを扱う。
 * 更新のたびにローテーションし、新しいリフレッシュトークンを返す。
 */
async function handleRefreshTokenGrant(c: Context, body: TokenRequest, client: ClientConfig) {
	const refreshToken = body.refresh_token;

	if (!refreshToken) {
		return tokenErrorResponse(c, invalidRequest("Missing refresh_token parameter"));
	}

	// [SECURITY] 提示されたトークンの持ち主を確認する。使用済み・失効済み・期限切れの
	// 判定はここでは行わない（判定は rotateRefreshToken が grant ロックの内側で行う）
	const verified = await verifyRefreshToken({
		refreshToken,
		clientId: client.clientId,
	});

	if (!verified) {
		return tokenErrorResponse(c, invalidGrant("The refresh token is invalid"));
	}

	const { tokenRecord } = verified;

	const requestedScope = body.scope;

	// 新しいアクセストークンを発行
	// scope が省略されたときの既定値は grant 行から取るため、
	// ここでは確定しない。ログに出すのは要求されたスコープそのものである。
	logger.info("トークン発行: リフレッシュトークングラント", {
		clientId: client.clientId,
		userId: tokenRecord.userId,
		requestedScope,
	});

	// #@range_begin(refresh-token-grant) ※書籍掲載用の範囲マーカー
	// [SECURITY] リフレッシュトークンを消費し、
	// 新しいアクセストークンとリフレッシュトークンを発行する。消費できなかった場合は
	// 猶予窓・再利用・期限切れに分類され、再利用なら grant 全体が失効する。
	// 発行する新しいトークンは元のリフレッシュトークンと同じ grant に属する。
	// 失敗の理由は応答に含めず、一律 invalid_grant で返す。
	// 攻撃者に「そのトークンは以前有効だった」と教えないため。
	//
	// [SECURITY] 要求スコープの検証もこの中で行う。ここで先に検証して
	// 返してしまうと、範囲外のスコープを添えるだけで再利用検知をすり抜けられる。
	const result = await rotateRefreshToken({ tokenRecord, client, requestedScope });

	if (result.type === "invalid_grant") {
		return tokenErrorResponse(c, invalidGrant("The refresh token is invalid"));
	}

	// 元の認可範囲を超えるスコープの要求は invalid_scope
	// （定義がこのケースを直接指す。検証済み RT ＋クライアント認証通過後にのみ
	// 到達するため情報漏えいの懸念もない）
	if (result.type === "invalid_scope") {
		return tokenErrorResponse(c, invalidScope("The requested scope exceeds the original grant"));
	}
	// #@range_end(refresh-token-grant)

	// ローテーションした新しいリフレッシュトークンを返す。
	// クライアントは古いほうを破棄する（draft-16 §4.3.2）。
	return tokenSuccessResponse(c, {
		access_token: result.token.accessToken,
		token_type: "Bearer",
		expires_in: result.token.expiresIn,
		scope: result.token.scope,
		refresh_token: result.token.refreshToken,
	});
}

/**
 * トークンエンドポイントの成功レスポンス（OAuth 2.1 draft-16 §3.2.3）。
 */
function tokenSuccessResponse(c: Context, body: Record<string, unknown>) {
	// [SECURITY] トークンを含む応答をキャッシュに残さない（draft-16 §3.2.3 の MUST）。
	return c.json(body, 200, { "Cache-Control": "no-store" });
}

/**
 * トークンエンドポイントのエラーレスポンス（OAuth 2.1 draft-16 §3.2.4）。
 */
function tokenErrorResponse(c: Context, error: OAuthError) {
	// [SECURITY] OAuth 2.1 draft-16 §3.2.4 / RFC 9110 §15.5.2: 401にはチャレンジが必須。
	// post認証・認証情報なしでも既存の401方針を維持し、対応するBasic認証を示す。
	if (error.statusCode === 401) {
		c.header("WWW-Authenticate", 'Basic realm="token"');
	}
	return c.json(error.toJSON(), error.statusCode as ContentfulStatusCode, {
		"Cache-Control": "no-store",
	});
}
