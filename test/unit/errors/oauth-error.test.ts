import { describe, expect, it } from "vitest";
import {
	invalidClient,
	invalidGrant,
	invalidRequest,
	OAuthError,
	sanitizeErrorDescription,
	unsupportedGrantType,
} from "../../../src/errors/oauth-error.js";

describe("OAuthError", () => {
	it("ASCIIの全128文字について許可範囲を検証する", () => {
		for (let code = 0; code < 128; code++) {
			const char = String.fromCharCode(code);
			const allowed = code >= 32 && code <= 126 && code !== 34 && code !== 92;
			expect(sanitizeErrorDescription(char)).toBe(allowed ? char : "?");
		}
		expect(sanitizeErrorDescription("日本語😀")).toBe("????");
	});
	it("禁止文字を含む説明もJSONと復号後のクエリで許可文字だけにする", () => {
		const raw = 'invalid "value" \\ 日本語\r\n\t\u0000\u007f';
		const err = new OAuthError("invalid_request", raw, 400, "日本語-state");
		const json = JSON.parse(JSON.stringify(err.toJSON()));
		const params = new URL(err.toRedirectUrl("https://client.example/callback")).searchParams;
		expect(json.error_description).toBe(sanitizeErrorDescription(raw));
		expect(params.get("error_description")).toBe(json.error_description);
		expect(json.error_description).toMatch(/^[\x20-\x21\x23-\x5B\x5D-\x7E]*$/);
		expect(params.get("state")).toBe("日本語-state");
	});
	it("基本プロパティが正しく設定される", () => {
		const err = new OAuthError("invalid_request", "client_idが必要です", 400, "abc123");
		expect(err.code).toBe("invalid_request");
		expect(err.description).toBe("client_idが必要です");
		expect(err.statusCode).toBe(400);
		expect(err.state).toBe("abc123");
		expect(err.message).toBe("invalid_request: client_idが必要です");
		expect(err.name).toBe("OAuthError");
	});

	it("Errorクラスを継承している", () => {
		const err = new OAuthError("invalid_request", "test");
		expect(err).toBeInstanceOf(Error);
		expect(err).toBeInstanceOf(OAuthError);
	});

	describe("toJSON", () => {
		it("error_descriptionを含むJSONを返す", () => {
			const err = new OAuthError("invalid_request", "Missing parameter");
			const json = err.toJSON();
			expect(json).toEqual({
				error: "invalid_request",
				error_description: "Missing parameter",
			});
		});

		it("stateはJSONに含まない（stateはリダイレクトエラー専用）", () => {
			const err = new OAuthError("invalid_request", "テスト", 400, "state123");
			const json = err.toJSON();
			expect(json).not.toHaveProperty("state");
		});

		it("error_uriは含まない", () => {
			const err = new OAuthError("invalid_request", "テスト");
			const json = err.toJSON();
			expect(json).not.toHaveProperty("error_uri");
		});
	});

	describe("toRedirectParams", () => {
		it("リダイレクト用のクエリパラメータを生成する", () => {
			const err = new OAuthError("access_denied", "The user denied access", 403, "xyz");
			const params = err.toRedirectParams();
			expect(params.get("error")).toBe("access_denied");
			expect(params.get("error_description")).toBe("The user denied access");
			expect(params.get("state")).toBe("xyz");
		});

		it("stateが未設定の場合はパラメータに含まない", () => {
			const err = new OAuthError("invalid_request", "テスト");
			const params = err.toRedirectParams();
			expect(params.has("state")).toBe(false);
		});
	});

	describe("toRedirectUrl", () => {
		it("redirect_uriにエラーパラメータを付与する", () => {
			const err = new OAuthError("invalid_scope", "Unsupported scope", 400, "s1");
			const url = err.toRedirectUrl("http://localhost:8080/callback");
			const parsed = new URL(url);
			expect(parsed.origin).toBe("http://localhost:8080");
			expect(parsed.pathname).toBe("/callback");
			expect(parsed.searchParams.get("error")).toBe("invalid_scope");
			expect(parsed.searchParams.get("error_description")).toBe("Unsupported scope");
			expect(parsed.searchParams.get("state")).toBe("s1");
		});
	});
});

describe("ファクトリ関数", () => {
	it("invalidRequest: 400", () => {
		const err = invalidRequest("テスト");
		expect(err.code).toBe("invalid_request");
		expect(err.statusCode).toBe(400);
	});

	it("invalidGrant: 400", () => {
		const err = invalidGrant("認可コードが無効");
		expect(err.code).toBe("invalid_grant");
		expect(err.statusCode).toBe(400);
	});

	it("invalidClient: 401", () => {
		const err = invalidClient("クライアント認証失敗");
		expect(err.code).toBe("invalid_client");
		expect(err.statusCode).toBe(401);
	});

	it("unsupportedGrantType: 400", () => {
		const err = unsupportedGrantType("未対応");
		expect(err.code).toBe("unsupported_grant_type");
		expect(err.statusCode).toBe(400);
	});
});
