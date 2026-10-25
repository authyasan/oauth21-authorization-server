import type { Context } from "hono";
import { logger } from "../utils/logger.js";

/**
 * Honoのグローバルエラーハンドラ。
 * 予期しない例外を500のserver_errorとして返す。
 *
 * OAuthのエラー応答は、各エンドポイントが OAuthError から直接組み立てる
 * （トークンエンドポイントはJSON、認可エンドポイントはredirect_uriへのリダイレクト）。
 * OAuthError を throw してここで変換する経路は持たない。
 */
export function errorHandler(err: Error, c: Context): Response {
	logger.error("予期しないエラー", {
		message: err.message,
		stack: err.stack,
	});

	return c.json(
		{
			error: "server_error",
			error_description: "An internal server error occurred",
		},
		500,
	);
}
