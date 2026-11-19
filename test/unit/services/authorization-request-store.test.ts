import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	clearAuthorizationRequests,
	consumeAuthorizationRequest,
	getAuthorizationRequest,
	rebindAuthorizationRequests,
	saveAuthorizationRequest,
} from "../../../src/services/authorization-request-store.js";
import type { AuthorizationRequest } from "../../../src/types/oauth.js";

const sampleAuthorizationRequest: AuthorizationRequest = {
	responseType: "code",
	clientId: "public-spa-client",
	redirectUri: "http://127.0.0.1:8080/callback",
	scope: "read",
	state: "test-state",
	codeChallenge: "test-challenge",
	codeChallengeMethod: "S256",
};

beforeEach(() => {
	clearAuthorizationRequests();
});

afterEach(() => {
	vi.useRealTimers();
});

describe("authorization-request-store", () => {
	describe("saveAuthorizationRequest / getAuthorizationRequest", () => {
		it("保存した認可リクエストは同一セッション識別子 で取得できる", () => {
			const sid = "sid-1";
			const txnId = saveAuthorizationRequest(sampleAuthorizationRequest, sid);
			const got = getAuthorizationRequest(txnId, sid);
			expect(got).toEqual(sampleAuthorizationRequest);
		});

		it("txnIdは22文字以上のBase64URL文字列である", () => {
			const txnId = saveAuthorizationRequest(sampleAuthorizationRequest, "sid-1");
			expect(txnId.length).toBeGreaterThanOrEqual(22);
			expect(txnId).toMatch(/^[A-Za-z0-9_-]+$/);
		});

		it("同じ入力でも毎回別の txnId が生成される", () => {
			const a = saveAuthorizationRequest(sampleAuthorizationRequest, "sid-1");
			const b = saveAuthorizationRequest(sampleAuthorizationRequest, "sid-1");
			expect(a).not.toBe(b);
		});
	});

	describe("getAuthorizationRequest: 失敗ケース", () => {
		it("存在しない txnId に対しては null を返す", () => {
			expect(getAuthorizationRequest("nonexistent", "sid-1")).toBeNull();
		});

		it("保存した認可リクエストの有効期限を過ぎるとnullを返す", () => {
			vi.useFakeTimers();
			const sid = "sid-1";
			const txnId = saveAuthorizationRequest(sampleAuthorizationRequest, sid);
			// TTL は 10 分
			vi.advanceTimersByTime(11 * 60 * 1000);
			expect(getAuthorizationRequest(txnId, sid)).toBeNull();
		});

		it("保存時とは異なるセッション識別子で取得するとnullを返す", () => {
			const txnId = saveAuthorizationRequest(sampleAuthorizationRequest, "sid-original");
			expect(getAuthorizationRequest(txnId, "sid-attacker")).toBeNull();
		});

		it("boundSid 不一致時はエントリを削除しない（正規ユーザーは再試行可能）", () => {
			const sid = "sid-original";
			const txnId = saveAuthorizationRequest(sampleAuthorizationRequest, sid);
			// 別セッションからの取得を拒否しても、紐付け先のセッションからは取得できる。
			expect(getAuthorizationRequest(txnId, "sid-attacker")).toBeNull();
			expect(getAuthorizationRequest(txnId, sid)).toEqual(sampleAuthorizationRequest);
		});
	});

	describe("consumeAuthorizationRequest", () => {
		it("成功時は取得して削除する（2 回目は null）", () => {
			const sid = "sid-1";
			const txnId = saveAuthorizationRequest(sampleAuthorizationRequest, sid);
			expect(consumeAuthorizationRequest(txnId, sid)).toEqual(sampleAuthorizationRequest);
			expect(getAuthorizationRequest(txnId, sid)).toBeNull();
		});

		it("boundSid 不一致時は削除せず null を返す", () => {
			const sid = "sid-original";
			const txnId = saveAuthorizationRequest(sampleAuthorizationRequest, sid);
			expect(consumeAuthorizationRequest(txnId, "sid-attacker")).toBeNull();
			// 紐付け先のセッションからは、保存した認可リクエストを引き続き取得できる。
			expect(getAuthorizationRequest(txnId, sid)).toEqual(sampleAuthorizationRequest);
		});

		it("存在しない txnId は null を返す", () => {
			expect(consumeAuthorizationRequest("nonexistent", "sid-1")).toBeNull();
		});
	});

	describe("rebindAuthorizationRequests", () => {
		it("保存した認可リクエストを旧セッションから新セッションへ紐付け直す", () => {
			const oldSid = "sid-old";
			const newSid = "sid-new";
			const txnId = saveAuthorizationRequest(sampleAuthorizationRequest, oldSid);

			rebindAuthorizationRequests(oldSid, newSid);

			// 更新前のセッション識別子では取得できない。
			expect(getAuthorizationRequest(txnId, oldSid)).toBeNull();
			// 更新後のセッション識別子では取得できる。
			expect(getAuthorizationRequest(txnId, newSid)).toEqual(sampleAuthorizationRequest);
		});

		it("同じセッションの複数件を更新し、別セッションの保存データは変更しない", () => {
			const first = saveAuthorizationRequest(sampleAuthorizationRequest, "sid-old");
			const secondRequest = { ...sampleAuthorizationRequest, state: "second-state" };
			const second = saveAuthorizationRequest(secondRequest, "sid-old");
			const unrelated = saveAuthorizationRequest(sampleAuthorizationRequest, "sid-other");

			rebindAuthorizationRequests("sid-old", "sid-new");

			expect(getAuthorizationRequest(first, "sid-old")).toBeNull();
			expect(getAuthorizationRequest(second, "sid-old")).toBeNull();
			expect(getAuthorizationRequest(first, "sid-new")).toEqual(sampleAuthorizationRequest);
			expect(getAuthorizationRequest(second, "sid-new")).toEqual(secondRequest);
			expect(getAuthorizationRequest(unrelated, "sid-new")).toBeNull();
			expect(getAuthorizationRequest(unrelated, "sid-other")).toEqual(sampleAuthorizationRequest);
		});

		it("セッションを更新しても、保存時に設定した有効期限を延長しない", () => {
			vi.useFakeTimers();
			const txnId = saveAuthorizationRequest(sampleAuthorizationRequest, "sid-old");
			vi.advanceTimersByTime(9 * 60 * 1000);
			rebindAuthorizationRequests("sid-old", "sid-new");
			expect(getAuthorizationRequest(txnId, "sid-new")).toEqual(sampleAuthorizationRequest);

			vi.advanceTimersByTime(2 * 60 * 1000);
			expect(getAuthorizationRequest(txnId, "sid-new")).toBeNull();
		});
	});
});
