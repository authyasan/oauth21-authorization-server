import assert from "node:assert/strict";
import { afterEach, describe, expect, it } from "vitest";
import { createClientMap, getClient } from "../../src/config/clients.js";
import { serverConfig } from "../../src/config/server.js";
import { createAuthorizeEndpoint } from "../../src/endpoints/authorize.js";
import { SESSION_COOKIE_NAME } from "../../src/middleware/auth.js";
import {
	clearAuthorizationRequests,
	getAuthorizationRequest,
} from "../../src/services/authorization-request-store.js";
import { clearAllSessions } from "../../src/services/session-service.js";

// 未ログインの受付とエラー応答を実HTTPハンドラで確認する。DBアクセス・モックは不要。
const app = createAuthorizeEndpoint();
const client = getClient("public-spa-client");
assert(client);
const clientId = client.clientId;
const originalUris = [...client.redirectUris];

function redirectLocation(response: Response): URL {
	const location = response.headers.get("Location");
	assert(location);
	return new URL(location, "http://localhost");
}

function query(overrides: Record<string, string> = {}) {
	return new URLSearchParams({
		client_id: clientId,
		redirect_uri: originalUris[0],
		response_type: "code",
		scope: "read",
		state: "original-state",
		code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		code_challenge_method: "S256",
		...overrides,
	});
}

afterEach(() => {
	client.redirectUris = [...originalUris];
	clearAuthorizationRequests();
	clearAllSessions();
});

describe("認可リクエスト検証のHTTP応答", () => {
	describe.each(["HTTP://127.0.0.1", "HtTp://[::1]", "HTTPS://127.0.0.1", "HtTpS://[::1]"])(
		"大文字を含むスキームの登録URI: %s",
		(origin) => {
			it.each(["exact", "different-port", "omitted"])(
				"登録で受理したURIを認可受付でも受理し、元の表記で保存する: %s",
				async (mode) => {
					const registered = `${origin}:8080/callback?q=%2F`;
					const config = createClientMap([{ ...client, redirectUris: [registered] }]).get(
						client.clientId,
					);
					assert(config);
					client.redirectUris = config.redirectUris;
					const requested =
						mode === "different-port" ? `${origin}:54321/callback?q=%2F` : registered;
					const params = query({ redirect_uri: requested });
					if (mode === "omitted") params.delete("redirect_uri");
					const response = await app.request(`/authorize?${params}`);
					expect(response.status).toBe(302);
					const location = redirectLocation(response);
					expect(location.pathname).toBe("/login");
					const sid = response.headers
						.get("Set-Cookie")
						?.match(new RegExp(`${SESSION_COOKIE_NAME}=([^;]+)`))?.[1];
					const txnId = location.searchParams.get("txnId");
					assert(sid);
					assert(txnId);
					expect(getAuthorizationRequest(txnId, sid)?.redirectUri).toBe(requested);
				},
			);
		},
	);

	it.each([
		["client_id", "unregistered-client"],
		["redirect_uri", "https://unregistered.example/callback"],
	])("不正な%sは詳細を含まない共通エラー画面を返す", async (name, value) => {
		const response = await app.request(`/authorize?${query({ [name]: value })}`);
		expect(response.status).toBe(400);
		expect(response.headers.get("Location")).toBeNull();
		expect(response.headers.get("Content-Type")).toContain("text/html");
		const html = await response.text();
		expect(html).toContain("不正なリクエストです。");
		expect(html).not.toContain(value);
	});

	it.each([
		"http://127.0.0.1:54321/a/../callback",
		"http://127.1:54321/callback",
		"http://user:pass@127.0.0.1:54321/callback",
		"http://127.0.0.1:54321/callback#",
		"http://127.0.0.1:54321/callback#x",
	])("不正なredirect_uriは400で、Locationを返さない: %s", async (redirectUri) => {
		const params = query({ redirect_uri: redirectUri });
		const response = await app.request(`/authorize?${params}`);
		expect(response.status).toBe(400);
		expect(response.headers.get("Location")).toBeNull();
	});

	it.each(["client_id", "redirect_uri"])("%sの重複は400で、Locationを返さない", async (name) => {
		const params = query();
		params.append(name, params.get(name) ?? "");
		const response = await app.request(`/authorize?${params}`);
		expect(response.status).toBe(400);
		expect(response.headers.get("Location")).toBeNull();
	});

	it("scope重複は登録URIへinvalid_request、state、issを返す", async () => {
		const params = query();
		params.append("scope", "write");
		const response = await app.request(`/authorize?${params}`);
		expect(response.status).toBe(302);
		const location = redirectLocation(response);
		expect(location.origin + location.pathname).toBe(originalUris[0]);
		expect(location.searchParams.get("error")).toBe("invalid_request");
		expect(location.searchParams.get("state")).toBe("original-state");
		expect(location.searchParams.get("iss")).toBe(serverConfig.issuer);
	});

	it("state重複時はいずれの値も選ばずinvalid_requestを返す", async () => {
		const params = query();
		params.append("state", "other-state");
		const response = await app.request(`/authorize?${params}`);
		expect(response.status).toBe(302);
		const location = redirectLocation(response);
		expect(location.searchParams.get("error")).toBe("invalid_request");
		expect(location.searchParams.has("state")).toBe(false);
	});

	it("scope重複があっても未登録URIにはリダイレクトしない", async () => {
		const params = query({ redirect_uri: "https://attacker.example/callback" });
		params.append("scope", "write");
		const response = await app.request(`/authorize?${params}`);
		expect(response.status).toBe(400);
		expect(response.headers.get("Location")).toBeNull();
	});

	it("percent-encodingされた名前の重複も検出する", async () => {
		const response = await app.request(`/authorize?${query()}&%63lient_id=other`);
		expect(response.status).toBe(400);
		expect(response.headers.get("Location")).toBeNull();
	});

	it.each(["", "read\twrite", "read  write", "read\n"])(
		"不正なscopeはinvalid_scope: %j",
		async (scope) => {
			const response = await app.request(`/authorize?${query({ scope })}`);
			expect(response.status).toBe(302);
			expect(redirectLocation(response).searchParams.get("error")).toBe("invalid_scope");
		},
	);

	it.each(["omitted", "empty"])(
		"redirect_uriの省略を補い、ログイン後のために保存する: %s",
		async (mode) => {
			const params = query({ redirect_uri: "" });
			if (mode === "omitted") params.delete("redirect_uri");
			params.append("unknown", "one");
			params.append("unknown", "two");
			const response = await app.request(`/authorize?${params}`);
			expect(response.status).toBe(302);
			const location = redirectLocation(response);
			expect(location.pathname).toBe("/login");
			const sid = response.headers
				.get("Set-Cookie")
				?.match(new RegExp(`${SESSION_COOKIE_NAME}=([^;]+)`))?.[1];
			const txnId = location.searchParams.get("txnId");
			assert(sid);
			assert(txnId);
			const stored = getAuthorizationRequest(txnId, sid);
			expect(stored).toBeDefined();
			expect(stored?.redirectUri).toBe(originalUris[0]);
		},
	);

	it("OAuthパラメータとともに届いたtxnIdは無視し、新規の認可リクエストとして扱う", async () => {
		// draft-16 §3.1: 認識しないパラメータは無視する。txnIdはクライアントから見て未知の名前
		const params = query();
		params.append("txnId", "client-defined-value");
		const response = await app.request(`/authorize?${params}`);
		expect(response.status).toBe(302);
		const location = redirectLocation(response);
		expect(location.pathname).toBe("/login");
		expect(location.searchParams.get("txnId")).not.toBe("client-defined-value");
	});

	it("txnIdだけのリクエストはログイン後の復帰として扱う", async () => {
		// 保存データがないので、復帰として処理されればエラー画面になる
		const response = await app.request("/authorize?txnId=unknown", {
			headers: { Cookie: `${SESSION_COOKIE_NAME}=unknown-session` },
		});
		expect(response.status).toBe(400);
		expect(response.headers.get("Location")).toBeNull();
	});

	it("省略時のエラー応答でも登録URIの既存クエリを保持する", async () => {
		client.redirectUris = ["https://client.example/callback?action=oauth"];
		const params = query({ redirect_uri: "", scope: "unknown" });
		const response = await app.request(`/authorize?${params}`);
		expect(response.status).toBe(302);
		const location = redirectLocation(response);
		expect(location.origin + location.pathname).toBe("https://client.example/callback");
		expect(location.searchParams.get("action")).toBe("oauth");
		expect(location.searchParams.get("error")).toBe("invalid_scope");
	});
});
