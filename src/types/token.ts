// JWTアクセストークンのペイロード (RFC 9068準拠)
export interface AccessTokenPayload {
	jti: string; // トークン識別子（イントロスペクション用）
	iss: string; // 認可サーバーのURL
	sub: string; // ユーザー識別子
	aud: string | string[]; // リソースサーバーのID（複数の場合は配列）
	client_id: string; // クライアント識別子
	scope: string; // 許可されたスコープ
	iat: number; // 発行時刻 (Unix timestamp)
	exp: number; // 有効期限 (Unix timestamp)
}

// イントロスペクションレスポンス (RFC 7662)
export interface IntrospectionResponse {
	active: boolean;
	scope?: string;
	client_id?: string;
	username?: string;
	token_type?: string;
	exp?: number;
	iat?: number;
	sub?: string;
	aud?: string | string[];
	iss?: string;
	jti?: string;
}
