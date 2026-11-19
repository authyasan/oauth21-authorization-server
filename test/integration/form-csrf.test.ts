import assert from "node:assert/strict";
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import app from "../../src/app.js";
import { authorizationCodes, consents, grants } from "../../src/db/schema.js";
import {
	clearAuthorizationRequests,
	getAuthorizationRequest,
} from "../../src/services/authorization-request-store.js";
import { clearAllSessions, getSession } from "../../src/services/session-service.js";
import {
	buildAuthorizeUrl,
	cleanupDatabase,
	closeDatabase,
	createTestUser,
	extractCsrfToken,
	extractTxnIdFromLocation,
	generatePkce,
	getRedirectParams,
	TEST_PUBLIC_CLIENT,
	testDb,
} from "./helpers.js";

let userId: string;

beforeEach(async () => {
	await cleanupDatabase();
	clearAllSessions();
	clearAuthorizationRequests();
	userId = (await createTestUser()).id;
});

afterEach(() => {
	vi.useRealTimers();
	clearAllSessions();
	clearAuthorizationRequests();
});

afterAll(async () => {
	await cleanupDatabase();
	await closeDatabase();
});

function cookieFrom(response: Response): string {
	const sid = response.headers.get("Set-Cookie")?.match(/sid=([^;]+)/)?.[1];
	assert(sid);
	return `sid=${sid}`;
}

function sidFrom(cookie: string): string {
	return cookie.slice("sid=".length);
}

function post(path: string, body: URLSearchParams | FormData, cookie?: string) {
	return app.request(path, {
		method: "POST",
		headers: cookie ? { Cookie: cookie } : undefined,
		body,
	});
}

function loginBody(csrfToken: string) {
	return new URLSearchParams({ username: "testuser", password: "password123", csrfToken });
}

async function loginForm(cookie?: string) {
	const response = await app.request("/login", {
		headers: cookie ? { Cookie: cookie } : undefined,
	});
	expect(response.status).toBe(200);
	const sessionCookie = response.headers.has("Set-Cookie") ? cookieFrom(response) : cookie;
	assert(sessionCookie);
	return {
		cookie: sessionCookie,
		csrfToken: extractCsrfToken(await response.text()),
	};
}

async function startAuthorization(cookie?: string) {
	const response = await app.request(
		buildAuthorizeUrl({ ...TEST_PUBLIC_CLIENT, ...generatePkce() }),
		{
			headers: cookie ? { Cookie: cookie } : undefined,
		},
	);
	expect(response.status).toBe(302);
	const txnId = extractTxnIdFromLocation(response);
	const sessionCookie = cookie ?? cookieFrom(response);
	const form = await app.request(`/login?txnId=${txnId}`, { headers: { Cookie: sessionCookie } });
	expect(form.status).toBe(200);
	return { cookie: sessionCookie, txnId, csrfToken: extractCsrfToken(await form.text()) };
}

async function consentForm() {
	const start = await startAuthorization();
	const body = loginBody(start.csrfToken);
	body.set("txnId", start.txnId);
	const loggedIn = await post("/login", body, start.cookie);
	expect(loggedIn.status).toBe(303);
	const cookie = cookieFrom(loggedIn);
	const response = await app.request(`/authorize?txnId=${start.txnId}`, {
		headers: { Cookie: cookie },
	});
	expect(response.status).toBe(200);
	const html = await response.text();
	expect(html.match(/name="csrfToken"/g)).toHaveLength(2);
	return {
		...start,
		oldCookie: start.cookie,
		oldToken: start.csrfToken,
		cookie,
		csrfToken: extractCsrfToken(html),
	};
}

async function expectNoAuthorization() {
	expect(await testDb.select().from(consents)).toHaveLength(0);
	expect(await testDb.select().from(grants)).toHaveLength(0);
	expect(await testDb.select().from(authorizationCodes)).toHaveLength(0);
}

function malformedTokenBody(kind: string, token: string): URLSearchParams | FormData {
	const body = new URLSearchParams({ csrfToken: token });
	switch (kind) {
		case "欠落":
			body.delete("csrfToken");
			break;
		case "空":
			body.set("csrfToken", "");
			break;
		case "不一致":
			body.set("csrfToken", "x".repeat(43));
			break;
		case "重複":
			body.append("csrfToken", token);
			break;
		case "配列名":
			body.delete("csrfToken");
			body.set("csrfToken[]", token);
			break;
		case "非ASCII":
			body.set("csrfToken", "あ".repeat(43));
			break;
		case "File": {
			const form = new FormData();
			form.set("csrfToken", new File([token], "token.txt"));
			return form;
		}
		default:
			throw new Error(`未定義のケース: ${kind}`);
	}
	return body;
}

const invalidTokenCases = ["欠落", "空", "不一致", "重複", "配列名", "非ASCII", "File"];

describe("ログインフォームのCSRF対策", () => {
	it("直接GETでセッションを用意し、SIDではなく独立したCSRFトークンをフォームに渡す", async () => {
		const response = await app.request("/login");
		const cookie = cookieFrom(response);
		const html = await response.text();
		const token = extractCsrfToken(html);
		expect(html).not.toContain(sidFrom(cookie));
		expect(getSession(sidFrom(cookie))?.csrfToken).toBe(token);
		expect(response.headers.get("Set-Cookie")).toContain("HttpOnly");
		expect(response.headers.get("Set-Cookie")).toContain("SameSite=Lax");
		expect(response.headers.get("Cache-Control")).toBe("no-store");
		const second = await loginForm(cookie);
		expect(second.csrfToken).toBe(token);
	});

	it("期限切れCookieによる直接GETでは新しいセッションを用意する", async () => {
		const form = await loginForm();
		vi.useFakeTimers({ toFake: ["Date"] });
		vi.advanceTimersByTime(31 * 60 * 1000);
		const renewed = await loginForm(form.cookie);
		expect(renewed.cookie).not.toBe(form.cookie);
		expect(renewed.csrfToken).not.toBe(form.csrfToken);
	});

	it("Cookieなしの攻撃者認証情報POSTは、攻撃者自身のCSRFトークンがあっても拒否する", async () => {
		const attacker = await loginForm();
		const response = await post("/login", loginBody(attacker.csrfToken));
		expect(response.status).toBe(403);
		expect(response.headers.get("Set-Cookie")).toBeNull();
		expect(getSession(sidFrom(attacker.cookie))?.userId).toBeUndefined();
		await expectNoAuthorization();
	});

	it.each(invalidTokenCases)("トークン%sならログインせず、セッションを変更しない", async (kind) => {
		const start = await startAuthorization();
		const body = malformedTokenBody(kind, start.csrfToken);
		body.set("username", "testuser");
		body.set("password", "password123");
		body.set("txnId", start.txnId);
		const response = await post("/login", body, start.cookie);
		expect(response.status).toBe(403);
		expect(response.headers.get("Set-Cookie")).toBeNull();
		expect(getSession(sidFrom(start.cookie))).toEqual({ csrfToken: start.csrfToken });
		expect(getAuthorizationRequest(start.txnId, sidFrom(start.cookie))).not.toBeNull();
		await expectNoAuthorization();
	});

	it("別セッションのCSRFトークンではログインできない", async () => {
		const victim = await loginForm();
		const attacker = await loginForm();
		expect((await post("/login", loginBody(attacker.csrfToken), victim.cookie)).status).toBe(403);
		expect(getSession(sidFrom(victim.cookie))?.userId).toBeUndefined();
	});

	it("有効期限切れのセッションでは正しいCSRFトークンでもログインできない", async () => {
		const form = await loginForm();
		vi.useFakeTimers({ toFake: ["Date"] });
		vi.advanceTimersByTime(31 * 60 * 1000);
		expect((await post("/login", loginBody(form.csrfToken), form.cookie)).status).toBe(403);
	});

	it("直接ログインが成功し、SIDとCSRFトークンが再生成される", async () => {
		const form = await loginForm();
		const response = await post("/login", loginBody(form.csrfToken), form.cookie);
		expect(response.status).toBe(303);
		expect(response.headers.get("Location")).toBe("/");
		const cookie = cookieFrom(response);
		expect(cookie).not.toBe(form.cookie);
		expect(getSession(sidFrom(form.cookie))).toBeNull();
		expect(getSession(sidFrom(cookie))?.userId).toBe(userId);
		expect(getSession(sidFrom(cookie))?.csrfToken).not.toBe(form.csrfToken);
		expect((await post("/login", loginBody(form.csrfToken), form.cookie)).status).toBe(403);
		expect((await post("/login", loginBody(form.csrfToken), cookie)).status).toBe(403);
	});

	it("同じフォームから並行してログインすると、パスワード検証後の再照合で1本を拒否する", async () => {
		const form = await loginForm();
		// 2本ともパスワード検証（await）の前に初回の照合を通る。先に完了した側がセッションを作り直すので、
		// 後から再開した側は旧セッションが消えていることを再照合で検出する。
		const responses = await Promise.all([
			post("/login", loginBody(form.csrfToken), form.cookie),
			post("/login", loginBody(form.csrfToken), form.cookie),
		]);
		expect(responses.map((r) => r.status).sort()).toEqual([303, 403]);
		const rejected = responses.find((r) => r.status === 403);
		const succeeded = responses.find((r) => r.status === 303);
		assert(rejected && succeeded);
		expect(rejected.headers.get("Set-Cookie")).toBeNull();
		expect(getSession(sidFrom(form.cookie))).toBeNull();
		expect(getSession(sidFrom(cookieFrom(succeeded)))?.userId).toBe(userId);
	});

	it.each([
		["", "password123", 400],
		["testuser", "wrong", 401],
		["unknown", "password123", 401],
	] as const)(
		"入力不備や認証失敗後も同じCSRFトークンで再送できる: %s",
		async (username, password, status) => {
			const start = await startAuthorization();
			const body = new URLSearchParams({
				username,
				password,
				txnId: start.txnId,
				csrfToken: start.csrfToken,
			});
			const failed = await post("/login", body, start.cookie);
			expect(failed.status).toBe(status);
			const html = await failed.text();
			expect(extractCsrfToken(html)).toBe(start.csrfToken);
			expect(html).toContain(`name="txnId" value="${start.txnId}"`);
			expect(failed.headers.get("Set-Cookie")).toBeNull();
			body.set("username", "testuser");
			body.set("password", "password123");
			expect((await post("/login", body, start.cookie)).status).toBe(303);
		},
	);

	it("存在しないユーザーとパスワード不一致で、同じレスポンスを返す", async () => {
		const start = await startAuthorization();
		const attempt = async (username: string, password: string) => {
			const body = new URLSearchParams({
				username,
				password,
				txnId: start.txnId,
				csrfToken: start.csrfToken,
			});
			const response = await post("/login", body, start.cookie);
			return { status: response.status, html: await response.text() };
		};
		const unknownUser = await attempt("unknown", "password123");
		const wrongPassword = await attempt("testuser", "wrong");
		expect(unknownUser.status).toBe(401);
		expect(unknownUser).toEqual(wrongPassword);
	});

	it.each(["別セッション", "期限切れ"])("txnIdが%sならGETとPOSTを拒否する", async (kind) => {
		const start = await startAuthorization();
		const form = kind === "別セッション" ? await loginForm() : start;
		if (kind === "期限切れ") {
			vi.useFakeTimers({ toFake: ["Date"] });
			vi.advanceTimersByTime(11 * 60 * 1000);
		}
		const get = await app.request(`/login?txnId=${start.txnId}`, {
			headers: { Cookie: form.cookie },
		});
		expect(get.status).toBe(400);
		const body = loginBody(form.csrfToken);
		body.set("txnId", start.txnId);
		expect((await post("/login", body, form.cookie)).status).toBe(400);
		expect(getSession(sidFrom(form.cookie))?.userId).toBeUndefined();
	});
});

describe.each(["approve", "deny"])("同意フォームのCSRF対策: %s", (decision) => {
	it.each(invalidTokenCases)(
		"CSRFトークン%sの同意リクエストを拒否しても、認可リクエストは残り再送できる",
		async (kind) => {
			const form = await consentForm();
			const body = malformedTokenBody(kind, form.csrfToken);
			body.set("txnId", form.txnId);
			body.set("decision", decision);
			const response = await post("/authorize", body, form.cookie);
			expect(response.status).toBe(403);
			expect(response.headers.get("Set-Cookie")).toBeNull();
			expect(getAuthorizationRequest(form.txnId, sidFrom(form.cookie))).not.toBeNull();
			expect(getSession(sidFrom(form.cookie))?.csrfToken).toBe(form.csrfToken);
			await expectNoAuthorization();

			const valid = await post(
				"/authorize",
				new URLSearchParams({ txnId: form.txnId, decision, csrfToken: form.csrfToken }),
				form.cookie,
			);
			expect(valid.status).toBe(303);
			expect(getAuthorizationRequest(form.txnId, sidFrom(form.cookie))).toBeNull();
			if (decision === "approve") {
				expect(getRedirectParams(valid).get("code")).toBeTruthy();
				expect(await testDb.select().from(authorizationCodes)).toHaveLength(1);
			} else {
				expect(getRedirectParams(valid).get("error")).toBe("access_denied");
				expect(getRedirectParams(valid).get("error_description")).toBe("The user denied access");
				await expectNoAuthorization();
			}
		},
	);

	it("ログイン前・他セッションのCSRFトークンとCookieなしのPOSTを拒否する", async () => {
		const form = await consentForm();
		const other = await loginForm();
		for (const token of [form.oldToken, other.csrfToken]) {
			const body = new URLSearchParams({ txnId: form.txnId, decision, csrfToken: token });
			expect((await post("/authorize", body, form.cookie)).status).toBe(403);
		}
		const body = new URLSearchParams({ txnId: form.txnId, decision, csrfToken: form.csrfToken });
		expect((await post("/authorize", body)).status).toBe(403);
		expect(getAuthorizationRequest(form.txnId, sidFrom(form.cookie))).not.toBeNull();
		await expectNoAuthorization();
	});
});

it("複数タブの認可リクエストを引き継ぎ、同意POSTではCSRFトークンを消費しない", async () => {
	const first = await startAuthorization();
	const second = await startAuthorization(first.cookie);
	expect(second.csrfToken).toBe(first.csrfToken);
	const body = loginBody(first.csrfToken);
	body.set("txnId", first.txnId);
	const loggedIn = await post("/login", body, first.cookie);
	const cookie = cookieFrom(loggedIn);
	// 別タブに残ったログインフォームは、新しいCookieで送っても拒否する。
	body.set("txnId", second.txnId);
	expect((await post("/login", body, cookie)).status).toBe(403);
	let previousToken: string | undefined;
	for (const txnId of [first.txnId, second.txnId]) {
		const page = await app.request(`/authorize?txnId=${txnId}`, { headers: { Cookie: cookie } });
		expect(page.status).toBe(200);
		const csrfToken = extractCsrfToken(await page.text());
		if (previousToken) expect(csrfToken).toBe(previousToken);
		previousToken = csrfToken;
		expect(
			(
				await post(
					"/authorize",
					new URLSearchParams({ txnId, csrfToken, decision: "approve" }),
					cookie,
				)
			).status,
		).toBe(303);
	}
	expect(await testDb.select().from(authorizationCodes)).toHaveLength(2);
});
