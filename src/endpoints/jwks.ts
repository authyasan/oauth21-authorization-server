import { Hono } from "hono";
import { getJwks } from "../config/keys.js";

/**
 * JWKSエンドポイント。
 * GET /.well-known/jwks.json: リソースサーバーがJWT検証用の公開鍵を取得する。
 *
 * 公開鍵は頻繁に変わらないため、Cache-Controlヘッダーでキャッシュを許可する。
 */
export function createJwksEndpoint() {
	const app = new Hono();

	// #@range_begin(jwks-endpoint) ※書籍掲載用の範囲マーカー
	app.get("/.well-known/jwks.json", (c) => {
		const jwks = getJwks();
		return c.json(jwks, 200, {
			"Cache-Control": "public, max-age=3600",
		});
	});
	// #@range_end(jwks-endpoint)

	return app;
}
