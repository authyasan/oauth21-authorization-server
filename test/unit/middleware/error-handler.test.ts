import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { errorHandler } from "../../../src/middleware/error-handler.js";

// テスト用のHonoアプリ
function createTestApp() {
	const app = new Hono();
	app.onError(errorHandler);

	// 一般的なエラーをスローするルート
	app.get("/generic-error", () => {
		throw new Error("予期しないエラー");
	});

	return app;
}

describe("エラーハンドラ", () => {
	const app = createTestApp();

	it("一般的なエラーは500のserver_errorに変換する", async () => {
		const res = await app.request("/generic-error");
		expect(res.status).toBe(500);

		const body = await res.json();
		expect(body.error).toBe("server_error");
		expect(body.error_description).toBe("An internal server error occurred");
	});

	it("一般エラーのレスポンスに内部情報を含めない", async () => {
		const res = await app.request("/generic-error");
		const body = await res.json();
		// 内部エラーメッセージ「予期しないエラー」が漏れていないこと
		expect(body.error_description).not.toContain("予期しないエラー");
	});
});
