import type { OAuthErrorCode } from "../types/oauth.js";

export function sanitizeErrorDescription(description: string): string {
	// [SECURITY] RFC 6749: 復号後も%x20-21 / %x23-5B / %x5D-7Eだけを返す。
	// 動的な値に含まれる非ASCII・制御文字・二重引用符・バックスラッシュを置換する。
	return description.replace(/[^\x20-\x21\x23-\x5B\x5D-\x7E]/gu, "?");
}

/**
 * OAuthエラーを表すカスタムエラークラス。
 * RFC 6749 Section 4.1.2.1（認可エンドポイント）および Section 5.2（トークンエンドポイント）に準拠。
 *
 * error_descriptionは常に含める。
 *   攻撃者に情報を与えるリスクはあるが、開発者のデバッグ効率を優先する。
 *   本番環境で制限したい場合は環境変数での切り替えを検討する余地がある。
 *
 * error_uriは提供しない。
 *   ドキュメントページの整備・維持コストに対してメリットが小さい。
 *
 * 2種類のエラーレスポンス方法がある:
 * - redirect: redirect_uriが信頼できる場合、クエリパラメータでエラーを返す
 * - json: トークンエンドポイントなど、JSONレスポンスでエラーを返す
 */
export class OAuthError extends Error {
	readonly code: OAuthErrorCode;
	readonly description: string;
	readonly statusCode: number;
	readonly state?: string;

	constructor(code: OAuthErrorCode, description: string, statusCode: number = 400, state?: string) {
		super(`${code}: ${description}`);
		this.name = "OAuthError";
		this.code = code;
		this.description = description;
		this.statusCode = statusCode;
		this.state = state;
	}

	/**
	 * JSONレスポンス用のボディを生成する。
	 * トークンエンドポイント (RFC 6749 Section 5.2) 等で使用。
	 * stateは含めない（stateはリダイレクトエラー専用）。
	 */
	toJSON(): Record<string, string> {
		return {
			error: this.code,
			error_description: sanitizeErrorDescription(this.description),
		};
	}

	/**
	 * リダイレクト用のクエリパラメータを生成する。
	 * 認可エンドポイント (RFC 6749 Section 4.1.2.1) で使用。
	 */
	toRedirectParams(): URLSearchParams {
		const params = new URLSearchParams();
		params.set("error", this.code);
		params.set("error_description", sanitizeErrorDescription(this.description));
		if (this.state) {
			params.set("state", this.state);
		}
		return params;
	}

	/**
	 * redirect_uriにエラーパラメータを付与したURLを生成する。
	 */
	toRedirectUrl(redirectUri: string): string {
		const url = new URL(redirectUri);
		const params = this.toRedirectParams();
		for (const [key, value] of params) {
			url.searchParams.set(key, value);
		}
		return url.toString();
	}
}

// よく使うエラーのファクトリ関数

export function invalidRequest(description: string, state?: string): OAuthError {
	return new OAuthError("invalid_request", description, 400, state);
}

export function invalidGrant(description: string): OAuthError {
	return new OAuthError("invalid_grant", description, 400);
}

export function invalidClient(description: string): OAuthError {
	return new OAuthError("invalid_client", description, 401);
}

export function unsupportedGrantType(description: string): OAuthError {
	return new OAuthError("unsupported_grant_type", description, 400);
}

export function invalidScope(description: string, state?: string): OAuthError {
	return new OAuthError("invalid_scope", description, 400, state);
}
