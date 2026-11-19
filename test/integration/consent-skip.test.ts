import assert from "node:assert/strict";
import { and, eq } from "drizzle-orm";
import { afterAll, afterEach, beforeEach, describe, expect, it } from "vitest";
import app from "../../src/app.js";
import { getClient } from "../../src/config/clients.js";
import { authorizationCodes, consents } from "../../src/db/schema.js";
import { clearAuthorizationRequests } from "../../src/services/authorization-request-store.js";
import { recordConsent } from "../../src/services/consent-service.js";
import {
	clearAllSessions,
	createSession,
	updateSession,
} from "../../src/services/session-service.js";
import {
	buildAuthorizeUrl,
	cleanupDatabase,
	closeDatabase,
	createTestUser,
	extractCsrfToken,
	extractTxnIdFromLocation,
	generatePkce,
	getFormCsrfToken,
	getRedirectParams,
	TEST_CONFIDENTIAL_CLIENT,
	TEST_PUBLIC_CLIENT,
	testDb,
} from "./helpers.js";

const HTTPS_URI = "https://client.example/callback";
const registeredUris = [
	HTTPS_URI,
	"http://127.0.0.1:8080/callback",
	"http://[::1]:8080/callback",
	"https://127.0.0.1:8443/callback",
	"https://[::1]:8443/callback",
	"com.example.native://callback",
	"com.example.native:/oauth2redirect",
];
const fixtures = [TEST_PUBLIC_CLIENT, TEST_CONFIDENTIAL_CLIENT].map(({ clientId }) => {
	const client = getClient(clientId);
	assert(client);
	return { client, originalUris: [...client.redirectUris] };
});
let userId: string;

beforeEach(async () => {
	await cleanupDatabase();
	clearAllSessions();
	clearAuthorizationRequests();
	userId = (await createTestUser()).id;
	for (const { client } of fixtures) client.redirectUris = [...registeredUris];
});

afterEach(() => {
	for (const { client, originalUris } of fixtures) client.redirectUris = [...originalUris];
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

async function authorize(
	clientId: string,
	redirectUri: string,
	afterLogin: boolean,
	scope = "read",
	omitRedirectUri = false,
) {
	const url = new URL(
		buildAuthorizeUrl({ clientId, redirectUri, scope, ...generatePkce() }),
		"http://localhost",
	);
	if (omitRedirectUri) url.searchParams.delete("redirect_uri");
	const path = url.pathname + url.search;
	if (!afterLogin) {
		const sid = createSession();
		updateSession(sid, { userId });
		const cookie = `sid=${sid}`;
		return { response: await app.request(path, { headers: { Cookie: cookie } }), cookie };
	}

	const start = await app.request(path);
	expect(start.status).toBe(302);
	expect(start.headers.get("Location")).toMatch(/^\/login\?txnId=/);
	const txnId = extractTxnIdFromLocation(start);
	const login = await app.request("/login", {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: cookieFrom(start) },
		body: new URLSearchParams({
			username: "testuser",
			password: "password123",
			txnId,
			csrfToken: await getFormCsrfToken(app, `/login?txnId=${txnId}`, cookieFrom(start)),
		}),
	});
	expect(login.status).toBe(303);
	const cookie = cookieFrom(login);
	const returnTo = login.headers.get("Location");
	assert(returnTo);
	return { response: await app.request(returnTo, { headers: { Cookie: cookie } }), cookie };
}

describe.each([TEST_PUBLIC_CLIENT, TEST_CONFIDENTIAL_CLIENT])(
	"同意省略: $clientId",
	({ clientId }) => {
		describe.each([false, true])("ログイン後の復帰=%s", (afterLogin) => {
			it("同意を省略して狭いscopeの認可コードを発行しても、同意記録を変更しない", async () => {
				await recordConsent(userId, clientId, "read write");
				// 時刻も更新されないことを、テストの実行速度によらず確かめる。
				await testDb
					.update(consents)
					.set({ createdAt: new Date("2026-01-01T00:00:00Z") })
					.where(and(eq(consents.userId, userId), eq(consents.clientId, clientId)));
				const before = await testDb.select().from(consents);
				expect(before).toHaveLength(1);
				expect(before[0].scope).toBe("read write");

				const { response } = await authorize(clientId, HTTPS_URI, afterLogin, "read");
				expect(response.status).toBe(302);
				expect(getRedirectParams(response).get("code")).toBeTruthy();
				const codes = await testDb.select().from(authorizationCodes);
				expect(codes).toHaveLength(1);
				expect(codes[0]).toMatchObject({ userId, clientId, scope: "read" });
				expect(await testDb.select().from(consents)).toEqual(before);
			});

			it.each([
				[HTTPS_URI, true],
				["http://127.0.0.1:54321/callback", false],
				["http://[::1]:54321/callback", false],
				["https://127.0.0.1:54321/callback", false],
				["https://[::1]:54321/callback", false],
				["com.example.native://callback", false],
				["com.example.native:/oauth2redirect", false],
			])(
				"今回のリダイレクトURIに基づいて同意画面を省略するか決める: %s",
				async (uri, shouldSkip) => {
					await recordConsent(userId, clientId, "read write");
					const { response, cookie } = await authorize(clientId, uri, afterLogin);
					let issued = response;
					if (shouldSkip) {
						expect(response.status).toBe(302);
					} else {
						expect(response.status).toBe(200);
						expect(response.headers.get("Location")).toBeNull();
						expect(await testDb.select().from(authorizationCodes)).toHaveLength(0);
						const html = await response.text();
						expect(html).toContain("approve");
						// OAuth 2.1 draft-16 §7.9: クライアント名と登録した組織を表示する
						expect(html).toContain(getClient(clientId)?.clientName);
						expect(html).toContain(`提供元: ${getClient(clientId)?.organizationName}`);
						const txnId = html.match(/name="txnId" value="([^"]+)"/)?.[1];
						assert(txnId);
						issued = await app.request("/authorize", {
							method: "POST",
							headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: cookie },
							body: new URLSearchParams({
								decision: "approve",
								txnId,
								csrfToken: extractCsrfToken(html),
							}),
						});
					}
					expect(issued.status).toBe(shouldSkip ? 302 : 303);
					expect(getRedirectParams(issued).get("code")).toBeTruthy();
					const codes = await testDb.select().from(authorizationCodes);
					expect(codes).toHaveLength(1);
					expect(codes[0]).toMatchObject({ clientId, userId, redirectUri: uri, scope: "read" });
				},
			);

			it.each([undefined, "read"])(
				"HTTPSのリダイレクトURIでも要求scopeに未同意の範囲があれば同意画面を表示する（同意済みscope=%s）",
				async (consentedScope) => {
					if (consentedScope) await recordConsent(userId, clientId, consentedScope);
					const { response } = await authorize(clientId, HTTPS_URI, afterLogin, "read write");
					expect(response.status).toBe(200);
					expect(await response.text()).toContain("approve");
					expect(await testDb.select().from(authorizationCodes)).toHaveLength(0);
				},
			);

			it.each([
				[HTTPS_URI, 302],
				["http://127.0.0.1:8080/callback", 200],
			])(
				"redirect_uri省略時も採用した登録URIに基づいて同意画面を省略するか決める: %s",
				async (uri, status) => {
					const client = getClient(clientId);
					assert(client);
					client.redirectUris = [uri];
					await recordConsent(userId, clientId, "read write");
					const { response } = await authorize(clientId, uri, afterLogin, "read", true);
					expect(response.status).toBe(status);
					if (status === 302) expect(getRedirectParams(response).get("code")).toBeTruthy();
					else expect(await testDb.select().from(authorizationCodes)).toHaveLength(0);
				},
			);
		});
	},
);

describe("同意の保存", () => {
	it("同じユーザーとクライアントの同意を更新すると、既存の1レコードを上書きする", async () => {
		await recordConsent(userId, TEST_PUBLIC_CLIENT.clientId, "read write");
		await recordConsent(userId, TEST_PUBLIC_CLIENT.clientId, "read");
		const rows = await testDb.select().from(consents);
		expect(rows).toHaveLength(1);
		expect(rows[0].scope).toBe("read");
	});

	it("同じユーザーとクライアントの同意を並行して保存しても、レコードは重複しない", async () => {
		await recordConsent(userId, TEST_PUBLIC_CLIENT.clientId, "read");
		const scopes = ["read", "read write", "write", "read", "write"];
		await Promise.all(
			scopes.map((scope) => recordConsent(userId, TEST_PUBLIC_CLIENT.clientId, scope)),
		);
		const rows = await testDb.select().from(consents);
		expect(rows).toHaveLength(1);
		expect(scopes).toContain(rows[0].scope);
	});

	it("クライアントが異なる同意は別のレコードに保存する", async () => {
		await recordConsent(userId, TEST_PUBLIC_CLIENT.clientId, "read");
		await recordConsent(userId, TEST_CONFIDENTIAL_CLIENT.clientId, "write");
		expect(await testDb.select().from(consents)).toHaveLength(2);
	});
});
