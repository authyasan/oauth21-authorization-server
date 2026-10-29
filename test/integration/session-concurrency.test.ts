import assert from "node:assert/strict";
import { eq } from "drizzle-orm";
import postgres from "postgres";
import { afterAll, afterEach, beforeEach, describe, expect, it } from "vitest";
import app from "../../src/app.js";
import { authorizationCodes, grants } from "../../src/db/schema.js";
import {
	clearAuthorizationRequests,
	getAuthorizationRequest,
} from "../../src/services/authorization-request-store.js";
import { clearAllSessions, getSession } from "../../src/services/session-service.js";
import { sha256 } from "../../src/utils/crypto.js";
import {
	buildAuthorizeUrl,
	cleanupDatabase,
	closeDatabase,
	createTestUser,
	extractTxnIdFromLocation,
	generatePkce,
	getFormCsrfToken,
	getRedirectParams,
	TEST_CONFIDENTIAL_CLIENT,
	testDb,
} from "./helpers.js";

function sessionCookie(response: Response): string {
	const cookie = response.headers.get("Set-Cookie")?.match(/(?:^|;\s*)sid=([^;]+)/)?.[0];
	assert(cookie, "セッションCookieが返ること");
	return cookie;
}

function sid(cookie: string): string {
	return cookie.slice("sid=".length);
}

function post(path: string, cookie: string, body: Record<string, string>) {
	return app.request(path, {
		method: "POST",
		headers: { Cookie: cookie, "Content-Type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams(body).toString(),
	});
}

async function startAuthorization(scope: string, state: string, cookie?: string) {
	const response = await app.request(
		buildAuthorizeUrl({
			...TEST_CONFIDENTIAL_CLIENT,
			scope,
			state,
			codeChallenge: generatePkce().codeChallenge,
		}),
		{ headers: cookie ? { Cookie: cookie } : {} },
	);
	expect(response.status).toBe(302);
	return { txnId: extractTxnIdFromLocation(response), response, scope, state };
}

type Flow = Awaited<ReturnType<typeof startAuthorization>>;

async function approveAndCheck(flow: Flow, cookie: string, userId: string) {
	const csrfToken = await getFormCsrfToken(app, `/authorize?txnId=${flow.txnId}`, cookie);
	const response = await post("/authorize", cookie, {
		txnId: flow.txnId,
		decision: "approve",
		csrfToken,
	});
	expect(response.status).toBe(303);
	const params = getRedirectParams(response);
	expect(params.get("state")).toBe(flow.state);
	const code = params.get("code");
	assert(code);
	const [row] = await testDb
		.select()
		.from(authorizationCodes)
		.where(eq(authorizationCodes.codeHash, sha256(code)));
	expect(row).toMatchObject({
		userId,
		clientId: TEST_CONFIDENTIAL_CLIENT.clientId,
		redirectUri: TEST_CONFIDENTIAL_CLIENT.redirectUri,
		scope: flow.scope,
		codeChallenge: generatePkce().codeChallenge,
	});
	const [grant] = await testDb.select().from(grants).where(eq(grants.id, row.grantId));
	expect(grant).toMatchObject({ userId, scope: flow.scope });
	expect(getAuthorizationRequest(flow.txnId, sid(cookie))).toBeNull();
	return code;
}

// ユーザー検索を実DBのロックで待たせ、2要求とも初回のセッション検証を
// 通過したことを確認してから解放する。単なる旧フォームの逐次送信とは区別する。
async function overlapLogins(start: () => Promise<Response>[]): Promise<Response[]> {
	assert(process.env.DATABASE_URL);
	const control = postgres(process.env.DATABASE_URL, { max: 2 });
	const lock = await control.reserve();
	let pending: Promise<Response>[] = [];
	try {
		await lock`BEGIN`;
		await lock`LOCK TABLE users IN ACCESS EXCLUSIVE MODE`;
		pending = start();
		await expect
			.poll(
				async () => {
					const [row] = await control`
				SELECT count(*)::int AS count FROM pg_locks
				WHERE relation = 'users'::regclass AND NOT granted
				AND mode = 'AccessShareLock'
				AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
			`;
					return row.count;
				},
				{ timeout: 5000 },
			)
			.toBe(2);
	} finally {
		await lock`ROLLBACK`;
		lock.release();
		await Promise.allSettled(pending);
		await control.end();
	}
	return Promise.all(pending);
}

describe("セッション作成・再生成の競合", () => {
	beforeEach(async () => {
		await cleanupDatabase();
		clearAllSessions();
		clearAuthorizationRequests();
	});
	afterEach(() => {
		clearAllSessions();
		clearAuthorizationRequests();
	});
	afterAll(async () => {
		await cleanupDatabase();
		await closeDatabase();
	});

	it.each([0, 1])(
		"初回Cookieのうち%d番を保持しても、別セッションのtxnは拒否される",
		async (selected) => {
			const user = await createTestUser();
			const flows = await Promise.all([
				startAuthorization("read", "initial-read-state-123456789012345678"),
				startAuthorization("write", "initial-write-state-12345678901234567"),
			]);
			const cookies = flows.map((flow) => sessionCookie(flow.response));
			expect(cookies[0]).not.toBe(cookies[1]);
			const own = flows[selected];
			const other = flows[1 - selected];
			const cookie = cookies[selected];
			for (const path of ["/login", "/authorize"]) {
				const response = await app.request(`${path}?txnId=${other.txnId}`, {
					headers: { Cookie: cookie },
				});
				expect(response.status).toBe(400);
				expect(response.headers.get("Set-Cookie")).toBeNull();
			}
			const csrfToken = await getFormCsrfToken(app, `/login?txnId=${own.txnId}`, cookie);
			const rejected = await post("/login", cookie, {
				username: user.username,
				password: "password123",
				csrfToken,
				txnId: other.txnId,
			});
			expect(rejected.status).toBe(400);
			expect(rejected.headers.get("Set-Cookie")).toBeNull();
			const unchangedSession = getSession(sid(cookie));
			assert(unchangedSession, "拒否後も元の未ログインセッションが存在すること");
			expect(unchangedSession.userId).toBeUndefined();
			expect(await testDb.select().from(authorizationCodes)).toHaveLength(0);
			const login = await post("/login", cookie, {
				username: user.username,
				password: "password123",
				csrfToken,
				txnId: own.txnId,
			});
			expect(login.status).toBe(303);
			const newCookie = sessionCookie(login);
			expect(getAuthorizationRequest(other.txnId, sid(newCookie))).toBeNull();
			expect(getAuthorizationRequest(other.txnId, sid(cookies[1 - selected]))).not.toBeNull();
			await approveAndCheck(own, newCookie, user.id);
			expect(await testDb.select().from(authorizationCodes)).toHaveLength(1);
		},
	);

	it.each([false, true])(
		"同じ旧セッションで並行ログイン（別ユーザー=%s）しても成功は1件だけ",
		async (differentUser) => {
			const firstUser = await createTestUser();
			const secondUser = differentUser
				? await createTestUser({ username: "other-user" })
				: firstUser;
			const users = [firstUser, secondUser];
			const first = await startAuthorization("read", "parallel-read-state-12345678901234567");
			const cookie = sessionCookie(first.response);
			const second = await startAuthorization(
				"write",
				"parallel-write-state-1234567890123456",
				cookie,
			);
			const flows = [first, second];
			const csrfToken = await getFormCsrfToken(app, `/login?txnId=${first.txnId}`, cookie);
			const responses = await overlapLogins(() =>
				flows.map((flow, index) =>
					post("/login", cookie, {
						username: users[index].username,
						password: "password123",
						csrfToken,
						txnId: flow.txnId,
					}),
				),
			);
			expect(responses.map((response) => response.status).sort()).toEqual([303, 403]);
			const winner = responses.findIndex((response) => response.status === 303);
			const newCookie = sessionCookie(responses[winner]);
			expect(responses[1 - winner].headers.get("Set-Cookie")).toBeNull();
			expect(getSession(sid(cookie))).toBeNull();
			expect(getSession(sid(newCookie))?.userId).toBe(users[winner].id);
			expect(await testDb.select().from(authorizationCodes)).toHaveLength(0);
			const codes: string[] = [];
			for (const flow of flows) {
				expect(getAuthorizationRequest(flow.txnId, sid(cookie))).toBeNull();
				expect(getAuthorizationRequest(flow.txnId, sid(newCookie))?.scope).toBe(flow.scope);
				const stale = await app.request(`/authorize?txnId=${flow.txnId}`, {
					headers: { Cookie: cookie },
				});
				expect(stale.status).toBe(400);
				// 敗者のタブも再読込後は勝者のセッションになる。新しい同意を経て発行する。
				codes.push(await approveAndCheck(flow, newCookie, users[winner].id));
			}
			expect(new Set(codes).size).toBe(2);
			expect(await testDb.select().from(authorizationCodes)).toHaveLength(2);
		},
	);
});
