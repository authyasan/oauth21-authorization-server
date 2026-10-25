/**
 * リソースサーバー定義。
 *
 * OAuthにおいてリソースサーバーはクライアントとは異なる役割を持つ：
 * - クライアント: ユーザーの認可を受けてリソースにアクセスする側
 * - リソースサーバー: 保護されたリソースを提供し、トークンを検証する側
 *
 * イントロスペクションエンドポイントはリソースサーバーが利用する。
 */
export interface ResourceServerConfig {
	/** リソースサーバー識別子 */
	resourceServerId: string;
	/** リソースサーバー名 */
	resourceServerName: string;
	/** 認証用シークレットのSHA-256ハッシュ */
	secretHash: string;
	/** このリソースサーバーが保護するスコープ */
	protectedScopes: string[];
}
