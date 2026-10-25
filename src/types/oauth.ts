// 認可リクエストのパラメータ
// redirect_uriは省略時に唯一の登録値で補った値、scopeは常に必須
// stateは任意（OAuth 2.1 §4.1.1でOPTIONAL）
export interface AuthorizationRequest {
	responseType: string;
	clientId: string;
	redirectUri: string;
	scope: string;
	state?: string;
	codeChallenge: string;
	codeChallengeMethod: string;
}

// OAuthエラーコード (RFC 6749 Section 4.1.2.1, 5.2)
export type OAuthErrorCode =
	| "invalid_request"
	| "unauthorized_client"
	| "access_denied"
	| "unsupported_response_type"
	| "invalid_scope"
	| "server_error"
	| "temporarily_unavailable"
	| "invalid_grant"
	| "invalid_client"
	| "unsupported_grant_type"
	| "unsupported_token_type";
