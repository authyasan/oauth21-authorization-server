import { Hono } from "hono";
import { serverConfig } from "../config/server.js";

/**
 * OAuth 2.0 Authorization Server Metadataエンドポイント。
 * GET /.well-known/oauth-authorization-server: サーバーのメタデータを返す。
 *
 * RFC 8414準拠。
 * リソースサーバーやクライアントがサーバーの機能を自動検出するために使用する。
 */
export function createMetadataEndpoint() {
	const app = new Hono();

	app.get("/.well-known/oauth-authorization-server", (c) => {
		const issuer = serverConfig.issuer;

		// #@range_begin(metadata-fields) ※書籍掲載用の範囲マーカー
		const metadata = {
			issuer,
			authorization_endpoint: `${issuer}/authorize`,
			token_endpoint: `${issuer}/token`,
			revocation_endpoint: `${issuer}/revoke`,
			introspection_endpoint: `${issuer}/introspect`,
			jwks_uri: `${issuer}/.well-known/jwks.json`,
			response_types_supported: ["code"],
			grant_types_supported: ["authorization_code", "refresh_token"],
			code_challenge_methods_supported: ["S256"],
			token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
			revocation_endpoint_auth_methods_supported: [
				"client_secret_basic",
				"client_secret_post",
				"none",
			],
			introspection_endpoint_auth_methods_supported: ["client_secret_basic"],
			// [SECURITY] RFC 9207 §2.3: 認可レスポンスに iss を付与することを宣言する。
			// クライアントはこのフラグを見て、ミックスアップ攻撃対策の検証を有効化できる。
			authorization_response_iss_parameter_supported: true,
		};
		// #@range_end(metadata-fields)

		// #@range_begin(metadata-cache) ※書籍掲載用の範囲マーカー
		return c.json(metadata, 200, {
			"Cache-Control": "public, max-age=3600",
		});
		// #@range_end(metadata-cache)
	});

	return app;
}
