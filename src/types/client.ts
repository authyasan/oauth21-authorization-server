// クライアントタイプ
export type ClientType = "public" | "confidential";

// クライアント定義
export interface ClientConfig {
	clientId: string;
	clientName: string;
	// クライアントを登録した開発者・組織の名前。同意画面に表示する（OAuth 2.1 draft-16 §7.9）。
	organizationName: string;
	clientType: ClientType;
	// コンフィデンシャルクライアントのみ。SHA-256ハッシュ済みの値を設定ファイルに保持。
	clientSecretHash?: string;
	redirectUris: string[];
	allowedScopes: string[];
}
