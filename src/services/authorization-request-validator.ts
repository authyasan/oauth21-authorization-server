import { findClientById } from "../repositories/client-repository.js";
import { isValidPkceCodeChallenge } from "../services/pkce-service.js";
import type { ClientConfig } from "../types/client.js";
import type { AuthorizationRequest, OAuthErrorCode } from "../types/oauth.js";
import {
	getUnknownScopes,
	isAllowedRedirectUriScheme,
	isValidScopeSyntax,
	validateRedirectUriWithLoopback,
} from "../utils/validation.js";

/**
 * client_id/redirect_uri検証前のエラー。
 * redirect_uriにリダイレクトできないため、エラー画面を表示する必要がある。
 */
export interface ClientValidationError {
	type: "client_error";
	errorDescription: string;
}

/**
 * redirect_uri検証後のエラー。
 * redirect_uriにリダイレクトしてエラーを返せる。
 */
export interface RedirectableError {
	type: "redirect_error";
	redirectUri: string;
	errorCode: OAuthErrorCode;
	errorDescription: string;
	state?: string;
}

/**
 * バリデーション成功時の結果。
 */
export interface ValidationSuccess {
	type: "success";
	client: ClientConfig;
	authorizationRequest: AuthorizationRequest;
}

export type ValidationResult = ClientValidationError | RedirectableError | ValidationSuccess;

/**
 * 認可リクエストのバリデーション。
 *
 * 段階的検証を行う。
 *   1. client_id → 存在しないならエラー画面
 *   2. redirect_uri → 不一致ならエラー画面
 *   3. その他のパラメータ → redirect_uriにリダイレクトでエラーを返す
 *
 * [SECURITY] client_idとredirect_uriの正当性が確認できるまで、
 * エラーをリダイレクトで返してはならない。不正なリダイレクト先に
 * 情報を送るリスクがある。
 */
export function validateAuthorizationRequest(params: URLSearchParams): ValidationResult {
	// #@range_begin(authorize-client-validation) ※書籍掲載用の範囲マーカー
	// === フェーズ1: client_id検証（エラー時はエラー画面） ===

	// [SECURITY] 空値を除去したり、一つの値を選んだりする前に重複を拒否する。
	if (params.getAll("client_id").length > 1) {
		return { type: "client_error", errorDescription: "Duplicate client_id parameter" };
	}
	const clientId = params.get("client_id");
	if (!clientId) {
		return {
			type: "client_error",
			errorDescription: "Missing client_id parameter",
		};
	}

	const client = findClientById(clientId);
	if (!client) {
		return {
			type: "client_error",
			errorDescription: "Unknown client_id",
		};
	}

	// #@range_end(authorize-client-validation)
	// #@range_begin(authorize-redirect-validation) ※書籍掲載用の範囲マーカー
	// === フェーズ2: redirect_uri検証（エラー時はエラー画面） ===

	if (params.getAll("redirect_uri").length > 1) {
		return { type: "client_error", errorDescription: "Duplicate redirect_uri parameter" };
	}
	// 空値は省略として扱い、登録が1件のときだけ補う。
	const redirectUri =
		params.get("redirect_uri") ||
		(client.redirectUris.length === 1 ? client.redirectUris[0] : undefined);
	if (!redirectUri) {
		return {
			type: "client_error",
			errorDescription: "Missing redirect_uri parameter",
		};
	}
	// #@range_end(authorize-redirect-validation)

	// [SECURITY] redirect_uriのスキーム検証
	// カスタムURLスキームは逆ドメイン名形式のみ許可
	// HTTPはループバックアドレスのみ許可
	if (!isAllowedRedirectUriScheme(redirectUri)) {
		return {
			type: "client_error",
			errorDescription: "The redirect_uri scheme is not allowed",
		};
	}

	// [SECURITY] redirect_uriの完全一致検証（ループバックはポート除外）
	// OAuth 2.1ではredirect_uriの完全一致が必須。
	// この検証がないと、オープンリダイレクト攻撃が成立する。
	if (!validateRedirectUriWithLoopback(redirectUri, client.redirectUris)) {
		return {
			type: "client_error",
			errorDescription: "The redirect_uri does not match a registered URI",
		};
	}

	// #@range_begin(authorize-other-duplicates) ※書籍掲載用の範囲マーカー
	// === フェーズ3: その他のパラメータ検証（エラー時はリダイレクト） ===
	// ここからはredirect_uriが信頼できるため、リダイレクトでエラーを返せる

	// stateは任意。重複した値から一つを選ばず、空値は省略として扱う。
	const stateValues = params.getAll("state");
	const state = stateValues.length === 1 ? stateValues[0] || undefined : undefined;
	const redirectError = (
		errorCode: OAuthErrorCode,
		errorDescription: string,
	): RedirectableError => ({
		type: "redirect_error",
		redirectUri,
		errorCode,
		errorDescription,
		state,
	});

	// [SECURITY] 未知のパラメータは無視し、認識するパラメータの重複を拒否する。
	for (const name of [
		"response_type",
		"scope",
		"state",
		"code_challenge",
		"code_challenge_method",
	]) {
		if (params.getAll(name).length > 1) {
			return redirectError("invalid_request", `Duplicate ${name} parameter`);
		}
	}
	// #@range_end(authorize-other-duplicates)

	// response_type検証
	const responseType = params.get("response_type");
	if (!responseType) {
		return redirectError("invalid_request", "Missing response_type parameter");
	}
	if (responseType !== "code") {
		return redirectError(
			"unsupported_response_type",
			`Unsupported response_type '${responseType}'; use 'code'`,
		);
	}

	// scopeが未指定の場合はエラー
	const scopeString = params.get("scope");
	if (!scopeString) {
		return redirectError("invalid_scope", "Missing scope parameter");
	}

	// scopeに未登録値が含まれる場合は全体エラー
	// [SECURITY] draft-16 §1.4.1のscope構文を、空白の正規化より前に検証する。
	if (!isValidScopeSyntax(scopeString)) {
		return redirectError("invalid_scope", "Invalid scope syntax");
	}

	const unknownScopes = getUnknownScopes(scopeString.split(" "), client.allowedScopes);
	if (unknownScopes.length > 0) {
		return redirectError("invalid_scope", `Unknown scopes: ${unknownScopes.join(", ")}`);
	}

	// [SECURITY] PKCE必須検証（OAuth 2.1）
	// PKCEがないと、認可コード横取り攻撃が成立する。
	const codeChallenge = params.get("code_challenge");
	if (!codeChallenge) {
		return redirectError("invalid_request", "Missing code_challenge parameter");
	}

	// [SECURITY] draft-16 §4.1.1: 方式の指定は必須で、plainは禁止されている。
	// 本書はS256のみを実装し、未対応の方式も拒否する。
	const codeChallengeMethod = params.get("code_challenge_method");
	if (!codeChallengeMethod) {
		return redirectError("invalid_request", "Missing code_challenge_method parameter");
	}
	if (codeChallengeMethod !== "S256") {
		return redirectError(
			"invalid_request",
			`Unsupported code_challenge_method '${codeChallengeMethod}'; use 'S256'`,
		);
	}

	// [SECURITY] S256のchallengeは43文字・パディングなしBase64url。
	// 認可サーバーは PKCE の当事者として、保存前に challenge の構文を検証する。
	if (!isValidPkceCodeChallenge(codeChallenge)) {
		return redirectError(
			"invalid_request",
			"Invalid code_challenge; expected 43 unpadded Base64url characters",
		);
	}

	// 未知のパラメータは無視する

	return {
		type: "success",
		client,
		authorizationRequest: {
			responseType,
			clientId,
			redirectUri,
			scope: scopeString,
			state,
			codeChallenge,
			codeChallengeMethod,
		},
	};
}
