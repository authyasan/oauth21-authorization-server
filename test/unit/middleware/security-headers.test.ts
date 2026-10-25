import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import app from "../../../src/app.js";
import { errorHandler } from "../../../src/middleware/error-handler.js";
import { securityHeaders } from "../../../src/middleware/security-headers.js";

describe("セキュリティヘッダーミドルウェア", () => {
	it("Cache-Control: no-store が設定される", async () => {
		const res = await app.request("/health");
		expect(res.headers.get("Cache-Control")).toBe("no-store");
	});

	it("非推奨の Pragma は付けない（RFC 9111 §5.4）", async () => {
		const res = await app.request("/health");
		expect(res.headers.get("Pragma")).toBeNull();
	});

	it.each(["/.well-known/jwks.json", "/.well-known/oauth-authorization-server"])(
		"%s は明示的なキャッシュ設定を保ち、no-store や Pragma を足さない",
		async (path) => {
			const res = await app.request(path);
			expect(res.status).toBe(200);
			expect(res.headers.get("Cache-Control")).toBe("public, max-age=3600");
			expect(res.headers.get("Pragma")).toBeNull();
		},
	);

	it("想定外の例外による500応答も no-store で、Pragma は付けない", async () => {
		// app.ts と同じ組み合わせ（全体のミドルウェアとエラーハンドラ）で、例外を投げる経路を再現する
		const failing = new Hono();
		failing.use("*", securityHeaders);
		failing.onError(errorHandler);
		failing.post("/token", () => {
			throw new Error("想定外の失敗");
		});
		const res = await failing.request("/token", { method: "POST" });
		expect(res.status).toBe(500);
		expect(await res.json()).toEqual({
			error: "server_error",
			error_description: "An internal server error occurred",
		});
		expect(res.headers.get("Cache-Control")).toBe("no-store");
		expect(res.headers.get("Pragma")).toBeNull();
	});

	it("X-Frame-Options: DENY が設定される", async () => {
		const res = await app.request("/health");
		expect(res.headers.get("X-Frame-Options")).toBe("DENY");
	});

	it("X-Content-Type-Options: nosniff が設定される", async () => {
		const res = await app.request("/health");
		expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
	});

	it("Content-Security-Policy が設定される", async () => {
		const res = await app.request("/health");
		const csp = res.headers.get("Content-Security-Policy");
		expect(csp).toContain("default-src 'self'");
	});

	it("非標準で非推奨の X-XSS-Protection は付けない（XSS対策はCSPが担う）", async () => {
		const res = await app.request("/health");
		expect(res.headers.get("X-XSS-Protection")).toBeNull();
	});

	it("Referrer-Policy: no-referrer が設定される（URLで運ぶtxnIdのReferer漏洩防止）", async () => {
		const res = await app.request("/health");
		expect(res.headers.get("Referrer-Policy")).toBe("no-referrer");
	});

	it("CSP に frame-ancestors 'none' が含まれる（クリックジャッキング防止の主対策）", async () => {
		const res = await app.request("/health");
		const csp = res.headers.get("Content-Security-Policy");
		expect(csp).toContain("frame-ancestors 'none'");
	});
});
