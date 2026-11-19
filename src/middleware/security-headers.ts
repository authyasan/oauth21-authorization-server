import type { MiddlewareHandler } from "hono";

/**
 * セキュリティ関連のHTTPヘッダーを設定するミドルウェア。
 *
 * OAuth 2.1 draft-16 §3.2.3: トークンなど機密情報を含む応答には Cache-Control: no-store が必須。
 * ここでは全レスポンスに対して防御的にセキュリティヘッダーを付与する。
 * Pragma: no-cache は付けない。RFC 9111 §5.4 は Pragma を非推奨とし、応答での意味は
 * 定められていないとする。HTTP/1.0 キャッシュとの互換は要件にしない。
 */
export const securityHeaders: MiddlewareHandler = async (c, next) => {
	await next();

	// [SECURITY] トークンや認可コードがキャッシュに残ることを防ぐ
	// ただし、JWKSやメタデータなど公開情報のエンドポイントが明示的にCache-Controlを設定している場合はスキップ
	if (!c.res.headers.get("Cache-Control")) {
		c.header("Cache-Control", "no-store");
	}

	// [SECURITY] クリックジャッキング防止（レガシーブラウザ向けフォールバック）。
	// 主対策はCSPのframe-ancestors。このヘッダはCSP未対応の旧ブラウザを守る
	c.header("X-Frame-Options", "DENY");

	// MIMEスニッフィング防止
	c.header("X-Content-Type-Options", "nosniff");

	// [SECURITY] URLクエリで運ぶtxnIdがRefererヘッダ経由で外部に漏れることを防ぐ
	c.header("Referrer-Policy", "no-referrer");

	// CSP: インラインスクリプトを禁止し、同一オリジンのみ許可
	// X-XSS-Protection は付けない。非標準で非推奨のヘッダーで、XSS対策はこのCSPが担う。
	// [SECURITY] frame-ancestors 'none' で画面の埋め込みを拒否し、クリックジャッキングを防ぐ。
	c.header(
		"Content-Security-Policy",
		"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
	);
};
