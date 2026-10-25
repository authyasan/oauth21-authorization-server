import { Hono } from "hono";
import { jwtVerify } from "jose";
import { getPublicKey } from "../config/keys.js";
import { invalidClient, invalidRequest } from "../errors/oauth-error.js";
import { introspectToken } from "../services/introspection-service.js";
import { authenticateResourceServer } from "../services/resource-server-auth-service.js";
import { logger } from "../utils/logger.js";

/**
 * イントロスペクションエンドポイント。
 * POST /introspect: トークンの有効性を検証する。
 *
 * RFC 7662準拠。
 *
 * リソースサーバーのみアクセス可能（クライアントからのアクセスは拒否）。
 * アクセストークンのみ対応。
 * Cache-Control: no-store を付ける。
 * 照会元RSがトークンのaudに含まれない場合、active: false を返す。
 */
export function createIntrospectionEndpoint() {
	const app = new Hono();

	app.post("/introspect", async (c) => {
		const body = await c.req.parseBody();

		// --- リソースサーバー認証（必須） ---
		// リソースサーバー以外のアクセスを拒否
		const authResult = authenticateResourceServer(c.req.header("Authorization"));

		if (!authResult) {
			const error = invalidClient("Resource server authentication failed");
			return c.json(error.toJSON(), 401, {
				"Cache-Control": "no-store",
			});
		}

		// #@range_begin(introspect-verify-jti) ※書籍掲載用の範囲マーカー
		// --- tokenパラメータ必須チェック ---
		const token = body.token as string | undefined;
		if (!token) {
			const error = invalidRequest("Missing token parameter");
			return c.json(error.toJSON(), 400, {
				"Cache-Control": "no-store",
			});
		}

		// --- JWTからjtiを取得 ---
		// [SECURITY] 署名検証を行い、改ざんされたJWTを排除する
		// jwtVerifyはデフォルトで有効期限もチェックするが、ここではjtiの取り出しが目的なのでスキップする。
		// 有効期限・リボーク状態の判定はintrospectToken内で行う。
		let jti: string;
		try {
			const publicKey = await getPublicKey();
			const { payload } = await jwtVerify(token, publicKey, {
				currentDate: new Date(0),
				// [SECURITY] アルゴリズムを RS256 に固定（多層防御）
				algorithms: ["RS256"],
			});

			if (!payload.jti) {
				logger.warn("イントロスペクション: JWTにjtiがない");
				return c.json({ active: false }, 200, {
					"Cache-Control": "no-store",
				});
			}
			jti = payload.jti;
		} catch {
			// JWT署名検証に失敗 → 無効なトークン
			return c.json({ active: false }, 200, {
				"Cache-Control": "no-store",
			});
		}
		// #@range_end(introspect-verify-jti)

		// --- イントロスペクション実行 ---
		// 照会元RS（Basic認証で特定済み）をintrospectTokenに渡し、audとの突き合わせを行う。
		const result = await introspectToken(jti, authResult.resourceServer.resourceServerId);

		return c.json(result, 200, {
			"Cache-Control": "no-store",
		});
	});

	return app;
}
