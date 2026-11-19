import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanupDatabase, closeDatabase, createTestUser, extractCsrfToken } from "./helpers.js";

// SESSION_COOKIE_NAME はモジュールの読み込み時に決まるので、環境変数を先に設定してから読み込む。
vi.stubEnv("NODE_ENV", "production");
// 本番では ISSUER に https を要求する（RFC 8414 §2）。
vi.stubEnv("ISSUER", "https://as.example.test");
const { default: app } = await import("../../src/app.js");
const { clearAllSessions } = await import("../../src/services/session-service.js");

beforeAll(async () => {
	await cleanupDatabase();
	await createTestUser();
});

beforeEach(() => {
	clearAllSessions();
});

afterAll(async () => {
	vi.unstubAllEnvs();
	await cleanupDatabase();
	await closeDatabase();
});

function hostCookieFrom(response: Response): string {
	const value = response.headers.get("Set-Cookie")?.match(/^__Host-sid=([^;]+)/)?.[1];
	if (!value) throw new Error("__Host-sid が発行されていません");
	return `__Host-sid=${value}`;
}

function loginBody(csrfToken: string, username = "testuser", password = "password123") {
	return new URLSearchParams({ username, password, csrfToken });
}

async function loginForm(cookie?: string) {
	const response = await app.request("/login", {
		headers: cookie ? { Cookie: cookie } : undefined,
	});
	expect(response.status).toBe(200);
	return { response, csrfToken: extractCsrfToken(await response.text()) };
}

describe("本番環境のセッションCookie名", () => {
	it("__Host-sid を Secure・Path=/・Domainなしで発行する", async () => {
		const { response } = await loginForm();
		const setCookie = response.headers.get("Set-Cookie") ?? "";
		expect(setCookie).toMatch(/^__Host-sid=/);
		expect(setCookie).toContain("Secure");
		expect(setCookie).toContain("Path=/");
		expect(setCookie).toContain("HttpOnly");
		expect(setCookie).toContain("SameSite=Lax");
		expect(setCookie).not.toMatch(/Domain=/i);
	});

	it("__Host-sid で直接ログインでき、ログイン後も __Host-sid を発行する", async () => {
		const form = await loginForm();
		const cookie = hostCookieFrom(form.response);
		const response = await app.request("/login", {
			method: "POST",
			headers: { Cookie: cookie },
			body: loginBody(form.csrfToken),
		});
		expect(response.status).toBe(303);
		const next = hostCookieFrom(response);
		expect(next).not.toBe(cookie);
		expect(response.headers.get("Set-Cookie")).toContain("Secure");
	});

	it("接頭辞のない sid は読まない（注入されたセッションでログインさせない）", async () => {
		// 攻撃者のセッション識別子をsidというCookie名で注入し、攻撃者のCSRFトークンとともに送る。
		const attacker = await loginForm();
		const attackerSid = hostCookieFrom(attacker.response).slice("__Host-sid=".length);
		const injected = `sid=${attackerSid}`;

		const response = await app.request("/login", {
			method: "POST",
			headers: { Cookie: injected },
			body: loginBody(attacker.csrfToken),
		});
		expect(response.status).toBe(403);
		expect(response.headers.get("Set-Cookie")).toBeNull();

		// GETでも注入されたセッションを使わず、新しい __Host-sid を発行する。
		const form = await loginForm(injected);
		expect(form.csrfToken).not.toBe(attacker.csrfToken);
		expect(hostCookieFrom(form.response)).not.toBe(`__Host-sid=${attackerSid}`);
	});
});
