import { afterEach, describe, expect, it, vi } from "vitest";
import {
	clearAllSessions,
	createSession,
	deleteSession,
	getSession,
	updateSession,
	validateCsrfToken,
} from "../../../src/services/session-service.js";

describe("セッション管理サービス", () => {
	afterEach(() => {
		clearAllSessions();
		vi.restoreAllMocks();
	});

	describe("createSession", () => {
		it("セッションIDを返す", () => {
			const sessionId = createSession();
			expect(sessionId).toBeDefined();
			expect(typeof sessionId).toBe("string");
			expect(sessionId.length).toBeGreaterThan(0);
		});

		it("毎回異なるセッションIDが生成される", () => {
			const id1 = createSession();
			const id2 = createSession();
			expect(id1).not.toBe(id2);
		});

		it("作成したセッションが取得できる", () => {
			const sessionId = createSession();
			const session = getSession(sessionId);
			expect(session).not.toBeNull();
			expect(session?.csrfToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
			expect(session?.csrfToken).not.toBe(sessionId);
			expect(session?.userId).toBeUndefined();
		});
	});

	describe("validateCsrfToken", () => {
		it("同じセッションのトークンだけを受け入れ、検証では消費しない", () => {
			const session = getSession(createSession());
			const other = getSession(createSession());
			expect(validateCsrfToken(session, session?.csrfToken)).toBe(true);
			expect(validateCsrfToken(session, session?.csrfToken)).toBe(true);
			expect(validateCsrfToken(session, other?.csrfToken)).toBe(false);
		});

		it.each([undefined, null, "", "a".repeat(42), "あ".repeat(43), [], {}, 123])(
			"欠落・形式不正を例外なしで拒否する: %j",
			(token) => {
				expect(validateCsrfToken(getSession(createSession()), token)).toBe(false);
			},
		);

		it("セッションがなければ正しい形式のトークンでも拒否する", () => {
			expect(validateCsrfToken(null, "a".repeat(43))).toBe(false);
		});

		it("ユーザー情報を更新してもCSRFトークンを保持する", () => {
			const sid = createSession();
			const token = getSession(sid)?.csrfToken;
			updateSession(sid, { userId: "user-123" });
			expect(getSession(sid)?.csrfToken).toBe(token);
		});
	});

	describe("getSession", () => {
		it("存在しないセッションIDでnullを返す", () => {
			const session = getSession("nonexistent");
			expect(session).toBeNull();
		});

		it("有効期限切れのセッションはnullを返す", () => {
			const sessionId = createSession();

			// 31分後に時間を進める
			vi.useFakeTimers();
			vi.advanceTimersByTime(31 * 60 * 1000);

			const session = getSession(sessionId);
			expect(session).toBeNull();

			vi.useRealTimers();
		});

		it("有効期限内のセッションは取得できる", () => {
			vi.useFakeTimers();
			const sessionId = createSession();

			// 29分後（有効期限内）
			vi.advanceTimersByTime(29 * 60 * 1000);

			const session = getSession(sessionId);
			expect(session).not.toBeNull();

			vi.useRealTimers();
		});
	});

	describe("updateSession", () => {
		it("セッションデータを更新できる", () => {
			const sessionId = createSession();
			const result = updateSession(sessionId, { userId: "user-123" });
			expect(result).toBe(true);

			const session = getSession(sessionId);
			expect(session?.userId).toBe("user-123");
		});

		it("既存データとマージされる", () => {
			const authenticatedAt = new Date();
			const sessionId = createSession();
			updateSession(sessionId, { userId: "user-123" });
			updateSession(sessionId, { authenticatedAt });

			const session = getSession(sessionId);
			expect(session?.userId).toBe("user-123");
			expect(session?.authenticatedAt).toBe(authenticatedAt);
		});

		it("存在しないセッションの更新はfalseを返す", () => {
			const result = updateSession("nonexistent", { userId: "user-123" });
			expect(result).toBe(false);
		});

		it("有効期限切れのセッションの更新はfalseを返す", () => {
			const sessionId = createSession();

			vi.useFakeTimers();
			vi.advanceTimersByTime(31 * 60 * 1000);

			const result = updateSession(sessionId, { userId: "user-123" });
			expect(result).toBe(false);

			vi.useRealTimers();
		});
	});

	describe("deleteSession", () => {
		it("セッションを削除できる", () => {
			const sessionId = createSession();
			deleteSession(sessionId);

			const session = getSession(sessionId);
			expect(session).toBeNull();
		});

		it("存在しないセッションの削除はエラーにならない", () => {
			expect(() => deleteSession("nonexistent")).not.toThrow();
		});
	});
});
