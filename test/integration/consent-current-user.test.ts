import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import app from "../../src/app.js";
import { clearAuthorizationRequests } from "../../src/services/authorization-request-store.js";
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
	generatePkce,
	TEST_CONFIDENTIAL_CLIENT,
} from "./helpers.js";

describe("同意画面のログイン中ユーザー表示", () => {
	beforeEach(async () => {
		await cleanupDatabase();
		clearAllSessions();
		clearAuthorizationRequests();
	});
	afterAll(async () => {
		await cleanupDatabase();
		clearAllSessions();
		clearAuthorizationRequests();
		await closeDatabase();
	});

	it.each(["testuser", '<script>alert("user")</script>'])(
		"新規受付・復帰ともセッションのユーザー名を安全に表示する: %s",
		async (username) => {
			const user = await createTestUser({ username });
			const sessionId = createSession();
			updateSession(sessionId, { userId: user.id, authenticatedAt: new Date() });
			const url = buildAuthorizeUrl({
				...TEST_CONFIDENTIAL_CLIENT,
				codeChallenge: generatePkce().codeChallenge,
			});
			const response = await app.request(`${url}&username=forged-user`, {
				headers: { Cookie: `sid=${sessionId}` },
			});
			expect(response.status).toBe(200);
			const html = await response.text();
			const expected =
				username === "testuser" ? username : "&lt;script&gt;alert(&quot;user&quot;)&lt;/script&gt;";
			expect(html).toContain(`ログイン中のユーザー: ${expected}`);
			expect(html).not.toContain("forged-user");
			expect(html).not.toContain("<script>");
			const txnId = html.match(/name="txnId" value="([^"]+)"/)?.[1];
			assert(txnId);
			const resumed = await app.request(`/authorize?txnId=${txnId}`, {
				headers: { Cookie: `sid=${sessionId}` },
			});
			expect(resumed.status).toBe(200);
			expect(await resumed.text()).toContain(`ログイン中のユーザー: ${expected}`);
		},
	);

	it("セッションのユーザーが存在しなければ同意フォームを表示しない", async () => {
		const sessionId = createSession();
		updateSession(sessionId, { userId: randomUUID(), authenticatedAt: new Date() });
		const url = buildAuthorizeUrl({
			...TEST_CONFIDENTIAL_CLIENT,
			codeChallenge: generatePkce().codeChallenge,
		});
		const response = await app.request(url, { headers: { Cookie: `sid=${sessionId}` } });
		expect(response.status).toBe(400);
		expect(await response.text()).not.toContain('class="approve"');
	});
});
