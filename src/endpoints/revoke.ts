import { Hono } from "hono";
import { invalidClient, invalidRequest } from "../errors/oauth-error.js";
import { authenticateClient } from "../services/client-auth-service.js";
import { revokeToken } from "../services/revocation-service.js";

/**
 * トークンリボケーションエンドポイント。
 * POST /revoke: トークンを無効化する。
 *
 * RFC 7009準拠。
 *
 * パブリッククライアントにも許可（client_idのみで識別）。
 *
 * セキュリティ要件:
 * - 無効なトークンでも200を返す（クライアントにトークンの有効性を推測させない）
 * - Cache-Control: no-store
 */
export function createRevocationEndpoint() {
	const app = new Hono();

	app.post("/revoke", async (c) => {
		const body = await c.req.parseBody();

		// --- クライアント認証/識別 ---
		const authResult = authenticateClient(
			c.req.header("Authorization"),
			body.client_id as string | undefined,
			body.client_secret as string | undefined,
		);

		if (authResult.type === "failure") {
			// 認証情報の組み立てがおかしいケースは400 invalid_request、
			// 純粋な認証失敗は401 invalid_client を返す
			if (authResult.errorCode === "invalid_request") {
				const error = invalidRequest(authResult.errorDescription);
				return c.json(error.toJSON(), 400, {
					"Cache-Control": "no-store",
				});
			}
			const error = invalidClient(authResult.errorDescription);
			return c.json(error.toJSON(), 401, {
				"Cache-Control": "no-store",
			});
		}

		const { client } = authResult;

		// --- tokenパラメータ必須チェック ---
		const token = body.token as string | undefined;
		if (!token) {
			const error = invalidRequest("Missing token parameter");
			return c.json(error.toJSON(), 400, {
				"Cache-Control": "no-store",
			});
		}

		const tokenTypeHint = body.token_type_hint as string | undefined;

		// --- リボケーション実行 ---
		// RFC 7009: トークンが無効・存在しない・すでにリボーク済みでも200を返す
		await revokeToken({
			token,
			tokenTypeHint,
			clientId: client.clientId,
		});

		// RFC 7009 Section 2.2: 成功時は200を返す
		return c.body(null, 200, {
			"Cache-Control": "no-store",
		});
	});

	return app;
}
