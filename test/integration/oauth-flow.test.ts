import assert from "node:assert/strict";
import { and, eq, isNull, sql } from "drizzle-orm";
import { createLocalJWKSet, decodeJwt, type JSONWebKeySet, jwtVerify } from "jose";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import app from "../../src/app.js";
import { getClient } from "../../src/config/clients.js";
import { getResourceServer } from "../../src/config/resource-server.js";
import { serverConfig } from "../../src/config/server.js";
import { accessTokens, authorizationCodes, grants, refreshTokens } from "../../src/db/schema.js";
import { clearAuthorizationRequests } from "../../src/services/authorization-request-store.js";
import { clearAllSessions } from "../../src/services/session-service.js";
import { sha256, sha256Base64url } from "../../src/utils/crypto.js";
import {
	basicAuthHeader,
	buildAuthorizeUrl,
	cleanupDatabase,
	cleanupTokenSaveFailureInjection,
	closeDatabase,
	createTestUser,
	extractCsrfToken,
	extractTxnIdFromLocation,
	generatePkce,
	getFormCsrfToken,
	getRedirectParams,
	TEST_CONFIDENTIAL_CLIENT,
	TEST_PUBLIC_CLIENT,
	TEST_RESOURCE_SERVER,
	TEST_RESOURCE_SERVER_2,
	testDb,
} from "./helpers.js";

const HTTPS_REDIRECT_URI = "https://client.example/callback";
const BASIC_AUTH_CASES = ["Basic", "bAsIc", "basic", "BASIC"].flatMap((scheme) =>
	[1, 2, 5].map((spaces) => ({ scheme, spaces })),
);
const confidentialClient = getClient(TEST_CONFIDENTIAL_CLIENT.clientId);
assert(confidentialClient);
const originalConfidentialUris = [...confidentialClient.redirectUris];

// テスト用ヘルパー: appにHTTPリクエストを送信
function request(path: string, init?: RequestInit): Promise<Response> {
	return app.request(path, init);
}

// テスト用ヘルパー: フォームボディを構築
function formBody(params: Record<string, string>): string {
	return new URLSearchParams(params).toString();
}

describe("OAuth 2.1 結合テスト", () => {
	let testUserId: string;

	beforeAll(async () => {
		// テスト用DBをクリーンアップしてユーザーを作成
		await cleanupDatabase();
	});

	afterAll(async () => {
		await cleanupDatabase();
		await closeDatabase();
	});

	beforeEach(async () => {
		// 各テスト前にデータとセッション、認可リクエストの保存先をクリア
		await cleanupDatabase();
		clearAllSessions();
		clearAuthorizationRequests();
		const user = await createTestUser();
		testUserId = user.id;
	});

	afterEach(() => {
		confidentialClient.redirectUris = [...originalConfidentialUris];
		vi.useRealTimers();
		clearAllSessions();
		clearAuthorizationRequests();
	});

	// ============================================================
	// トークン認証チャレンジ
	// ============================================================

	describe("共通クライアント認証のスキーム名", () => {
		it.each(["/token", "/revoke"])("%sで不正Basicを認証なしへ落とさない", async (path) => {
			const credentials = basicAuthHeader(
				TEST_CONFIDENTIAL_CLIENT.clientId,
				TEST_CONFIDENTIAL_CLIENT.clientSecret,
			).slice(6);
			for (const authorization of [
				"basic",
				`basic\t${credentials}`,
				`basic \t${credentials}`,
				`basic   ${credentials.slice(0, 8)} ${credentials.slice(8)}`,
				`basic   ${credentials.slice(0, 8)}\t${credentials.slice(8)}`,
				// 不正なパーセントエンコードも500にせず認証失敗にする
				`Basic ${Buffer.from("unknown:%E0%A4%A").toString("base64")}`,
				`Basic ${Buffer.from("%:x").toString("base64")}`,
			]) {
				const res = await request(path, {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
						Authorization: authorization,
					},
					body: formBody({
						grant_type: "authorization_code",
						token: "unknown-token",
						client_id: TEST_PUBLIC_CLIENT.clientId,
					}),
				});
				expect(res.status).toBe(401);
				expect(await res.json()).toMatchObject({ error: "invalid_client" });
				if (path === "/token") {
					expect(res.headers.get("WWW-Authenticate")).toBe('Basic realm="token"');
				}
			}
		});
		it.each(BASIC_AUTH_CASES)(
			"/revokeで$scheme・$spaces SPの認証を受け付ける",
			async ({ scheme, spaces }) => {
				const credentials = basicAuthHeader(
					TEST_CONFIDENTIAL_CLIENT.clientId,
					TEST_CONFIDENTIAL_CLIENT.clientSecret,
				).slice(6);
				const res = await request("/revoke", {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
						Authorization: `${scheme}${" ".repeat(spaces)}${credentials}`,
					},
					body: formBody({ token: "unknown-token" }),
				});
				expect(res.status).toBe(200);
			},
		);

		it.each(["/token", "/revoke"])(
			"%sで小文字basic・複数SPとpostの同時使用を拒否する",
			async (path) => {
				const credentials = basicAuthHeader(
					TEST_CONFIDENTIAL_CLIENT.clientId,
					TEST_CONFIDENTIAL_CLIENT.clientSecret,
				).slice(6);
				const res = await request(path, {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
						Authorization: `basic   ${credentials}`,
					},
					body: formBody({
						grant_type: "authorization_code",
						token: "unknown-token",
						client_id: TEST_CONFIDENTIAL_CLIENT.clientId,
						client_secret: TEST_CONFIDENTIAL_CLIENT.clientSecret,
					}),
				});
				expect(res.status).toBe(400);
				expect(res.headers.get("WWW-Authenticate")).toBeNull();
				expect(await res.json()).toEqual({
					error: "invalid_request",
					error_description: "Multiple client authentication methods are not allowed",
				});
			},
		);
	});

	describe.each(["authorization_code", "refresh_token"])(
		"トークン認証チャレンジ（%s）",
		(grantType) => {
			it.each([
				...BASIC_AUTH_CASES.flatMap(({ scheme, spaces }) => [
					{
						name: `${scheme}・${spaces} SPのシークレット不一致`,
						authorization: `${scheme}${" ".repeat(spaces)}${basicAuthHeader(TEST_CONFIDENTIAL_CLIENT.clientId, "wrong-secret").slice(6)}`,
						params: {},
					},
					{
						name: `${scheme}・${spaces} SPの未知クライアント`,
						authorization: `${scheme}${" ".repeat(spaces)}${basicAuthHeader("unknown-client", "some-secret").slice(6)}`,
						params: {},
					},
				]),
				{
					name: "Basicのコロン欠落",
					authorization: `Basic ${Buffer.from("no-colon").toString("base64")}`,
					params: {},
				},
				{
					name: "postのシークレット不一致",
					params: {
						client_id: TEST_CONFIDENTIAL_CLIENT.clientId,
						client_secret: "wrong-secret",
					},
				},
				{
					name: "postの未知クライアント",
					params: { client_id: "unknown-client", client_secret: "some-secret" },
				},
				{
					name: "コンフィデンシャルの認証情報なし",
					params: { client_id: TEST_CONFIDENTIAL_CLIENT.clientId },
				},
				{ name: "認証情報もclient_idもなし", params: {} },
			])("$nameは401と固定のBasicチャレンジを返す", async (testCase) => {
				const headers: Record<string, string> = {
					"Content-Type": "application/x-www-form-urlencoded",
				};
				if (testCase.authorization) headers.Authorization = testCase.authorization;
				const params: Record<string, string> = { grant_type: grantType };
				for (const [name, value] of Object.entries(testCase.params)) {
					if (value !== undefined) params[name] = value;
				}
				const res = await request("/token", {
					method: "POST",
					headers,
					body: formBody(params),
				});
				expect(res.status).toBe(401);
				expect(res.headers.get("WWW-Authenticate")).toBe('Basic realm="token"');
				expect(res.headers.get("Cache-Control")).toBe("no-store");
				expect(res.headers.get("Pragma")).toBeNull();
				expect(res.headers.get("Content-Type")).toContain("application/json");
				expect(await res.json()).toEqual({
					error: "invalid_client",
					error_description: "Client authentication failed",
				});
			});

			it.each([
				{
					name: "Basicとpostの同時使用",
					clientId: TEST_CONFIDENTIAL_CLIENT.clientId,
					params: {
						client_id: TEST_CONFIDENTIAL_CLIENT.clientId,
						client_secret: TEST_CONFIDENTIAL_CLIENT.clientSecret,
					},
				},
				{
					name: "パブリッククライアントのBasic認証",
					clientId: TEST_PUBLIC_CLIENT.clientId,
					params: {},
				},
				{
					name: "認証成功後のグラント必須パラメータ欠落",
					clientId: TEST_CONFIDENTIAL_CLIENT.clientId,
					params: {},
				},
			])("$nameは400のままでチャレンジを返さない", async (testCase) => {
				const params: Record<string, string> = { grant_type: grantType };
				for (const [name, value] of Object.entries(testCase.params)) {
					if (value !== undefined) params[name] = value;
				}
				const res = await request("/token", {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
						Authorization: basicAuthHeader(
							testCase.clientId,
							TEST_CONFIDENTIAL_CLIENT.clientSecret,
						),
					},
					body: formBody(params),
				});
				expect(res.status).toBe(400);
				expect(res.headers.get("WWW-Authenticate")).toBeNull();
				expect(await res.json()).toMatchObject({ error: "invalid_request" });
			});
		},
	);

	// ============================================================
	// ヘルスチェック・メタデータ・JWKS
	// ============================================================

	describe("基本エンドポイント", () => {
		it("GET /health が正常に応答する", async () => {
			const res = await request("/health");
			expect(res.status).toBe(200);
			const body = await res.json();
			expect(body).toEqual({ status: "ok" });
		});

		it("GET /.well-known/jwks.json がJWKSを返す", async () => {
			const res = await request("/.well-known/jwks.json");
			expect(res.status).toBe(200);
			const body = await res.json();
			expect(body.keys).toBeDefined();
			expect(body.keys.length).toBeGreaterThan(0);
			expect(body.keys[0].kty).toBe("RSA");
			expect(body.keys[0].alg).toBe("RS256");
			// 公開情報は明示的なキャッシュ設定を保つ。no-store の既定値や Pragma は付けない
			expect(res.headers.get("Cache-Control")).toBe("public, max-age=3600");
			expect(res.headers.get("Pragma")).toBeNull();
		});

		it("GET /.well-known/oauth-authorization-server がメタデータを返す", async () => {
			const res = await request("/.well-known/oauth-authorization-server");
			expect(res.status).toBe(200);
			const body = await res.json();
			expect(body.issuer).toBeDefined();
			expect(body.authorization_endpoint).toContain("/authorize");
			expect(body.token_endpoint).toContain("/token");
			expect(body.revocation_endpoint).toContain("/revoke");
			expect(body.introspection_endpoint).toContain("/introspect");
			expect(body.jwks_uri).toContain("/.well-known/jwks.json");
			expect(body.response_types_supported).toContain("code");
			expect(body.grant_types_supported).toContain("authorization_code");
			expect(body.code_challenge_methods_supported).toContain("S256");
			expect(res.headers.get("Cache-Control")).toBe("public, max-age=3600");
			expect(res.headers.get("Pragma")).toBeNull();
		});
	});

	// ============================================================
	// 認可コードフロー（コンフィデンシャルクライアント）
	// ============================================================

	describe.each(BASIC_AUTH_CASES)(
		"認可コードフロー（$scheme・$spaces SP）",
		({ scheme, spaces }) => {
			it.each([false, true])(
				"認可リクエスト → ログイン → 同意 → トークン交換の全フロー（redirect_uri省略: %s）",
				async (omitRedirectUri) => {
					const { codeVerifier, codeChallenge } = generatePkce();

					// Step 1: 認可リクエスト（未ログイン → ログイン画面へリダイレクト）
					const authorizeUrl = buildAuthorizeUrl({
						clientId: TEST_CONFIDENTIAL_CLIENT.clientId,
						redirectUri: TEST_CONFIDENTIAL_CLIENT.redirectUri,
						scope: "read write",
						codeChallenge,
					});

					const requestUrl = new URL(authorizeUrl, "http://localhost");
					if (omitRedirectUri) requestUrl.searchParams.delete("redirect_uri");
					const authRes = await request(requestUrl.pathname + requestUrl.search);
					expect(authRes.status).toBe(302);
					expect(authRes.headers.get("Location")).toMatch(/^\/login\?txnId=/);
					const txnId = extractTxnIdFromLocation(authRes);

					// セッションCookieを取得
					const setCookieHeader = authRes.headers.get("Set-Cookie");
					expect(setCookieHeader).toBeTruthy();
					const sidMatch = setCookieHeader!.match(/sid=([^;]+)/);
					expect(sidMatch).toBeTruthy();
					const sessionCookie = `sid=${sidMatch![1]}`;

					const loginLocation = authRes.headers.get("Location");
					assert(loginLocation);
					expect(getRedirectParams(authRes).has("txn")).toBe(false);
					const loginPage = await request(loginLocation, { headers: { Cookie: sessionCookie } });
					const loginHtml = await loginPage.text();
					expect(loginHtml).toContain(`name="txnId" value="${txnId}"`);
					expect(loginHtml).not.toContain('name="txn"');

					// Step 2: ログイン（hidden form field の txnId を渡す）
					const loginRes = await request("/login", {
						method: "POST",
						headers: {
							"Content-Type": "application/x-www-form-urlencoded",
							Cookie: sessionCookie,
						},
						body: formBody({
							username: "testuser",
							password: "password123",
							txnId,
							csrfToken: extractCsrfToken(loginHtml),
						}),
					});
					expect(loginRes.status).toBe(303);
					expect(loginRes.headers.get("Location")).toBe(
						`/authorize?txnId=${encodeURIComponent(txnId)}`,
					);

					// ログイン後のセッションCookieを更新
					const loginSetCookie = loginRes.headers.get("Set-Cookie");
					const loginSidMatch = loginSetCookie?.match(/sid=([^;]+)/);
					const loggedInCookie = loginSidMatch ? `sid=${loginSidMatch[1]}` : sessionCookie;

					// Step 3: 認可エンドポイントへ復帰（ログイン済み → 同意画面表示）
					const authRes2 = await request(`/authorize?txnId=${encodeURIComponent(txnId)}`, {
						headers: { Cookie: loggedInCookie },
					});
					expect(authRes2.status).toBe(200);
					// 同意画面のHTMLが返る
					const html = await authRes2.text();
					expect(html).toContain("approve");
					expect(html).toContain(`name="txnId" value="${txnId}"`);
					expect(html).not.toContain('name="txn"');

					// Step 4: 同意承認
					const consentRes = await request("/authorize", {
						method: "POST",
						headers: {
							"Content-Type": "application/x-www-form-urlencoded",
							Cookie: loggedInCookie,
						},
						body: formBody({ decision: "approve", txnId, csrfToken: extractCsrfToken(html) }),
					});
					expect(consentRes.status).toBe(303);

					// リダイレクト先から認可コードを取得
					const redirectParams = getRedirectParams(consentRes);
					const code = redirectParams.get("code");
					const state = redirectParams.get("state");
					expect(code).toBeTruthy();
					expect(state).toBe("test-state-12345678901234567890ab");

					// Step 5: トークン交換
					const authorization = `${scheme}${" ".repeat(spaces)}${basicAuthHeader(
						TEST_CONFIDENTIAL_CLIENT.clientId,
						TEST_CONFIDENTIAL_CLIENT.clientSecret,
					).slice(6)}`;
					const tokenRes = await request("/token", {
						method: "POST",
						headers: {
							"Content-Type": "application/x-www-form-urlencoded",
							Authorization: authorization,
						},
						body: formBody({
							grant_type: "authorization_code",
							code: code!,
							redirect_uri: TEST_CONFIDENTIAL_CLIENT.redirectUri,
							code_verifier: codeVerifier,
						}),
					});
					expect(tokenRes.status).toBe(200);

					const tokenBody = await tokenRes.json();
					expect(tokenBody.access_token).toBeTruthy();
					expect(tokenBody.token_type).toBe("Bearer");
					expect(tokenBody.expires_in).toBe(1800); // 30分
					expect(tokenBody.scope).toBe("read write");
					// コンフィデンシャルクライアントにはリフレッシュトークンが発行される
					expect(tokenBody.refresh_token).toBeTruthy();

					// セキュリティヘッダーの確認（draft-16 §3.2.3: no-store のみ。非推奨の Pragma は付けない）
					expect(tokenRes.headers.get("Cache-Control")).toBe("no-store");
					expect(tokenRes.headers.get("Pragma")).toBeNull();
				},
			);
		},
	);

	// ============================================================
	// 認可コードフロー（パブリッククライアント）
	// ============================================================

	describe("認可コードフロー（パブリッククライアント）", () => {
		// リフレッシュトークンはクライアント種別によらず発行する。
		// アクセストークンの寿命もクライアント種別によらず一律30分。
		it("パブリッククライアントにもリフレッシュトークンが発行される", async () => {
			const { codeVerifier, codeChallenge } = generatePkce();

			// 認可リクエスト → ログイン → 同意 → コード取得（ヘルパーで一括）
			const code = await performAuthorizationFlow({
				clientId: TEST_PUBLIC_CLIENT.clientId,
				redirectUri: TEST_PUBLIC_CLIENT.redirectUri,
				scope: "read",
				codeChallenge,
				codeVerifier,
			});

			// トークン交換（パブリッククライアント: client_secret不要）
			const tokenRes = await request("/token", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: formBody({
					grant_type: "authorization_code",
					code,
					redirect_uri: TEST_PUBLIC_CLIENT.redirectUri,
					code_verifier: codeVerifier,
					client_id: TEST_PUBLIC_CLIENT.clientId,
				}),
			});
			expect(tokenRes.status).toBe(200);

			const tokenBody = await tokenRes.json();
			expect(tokenBody.access_token).toBeTruthy();
			expect(tokenBody.expires_in).toBe(1800); // 30分
			expect(tokenBody.refresh_token).toBeTruthy();
		});
	});

	// ============================================================
	// リフレッシュトークンによるトークン更新
	// ============================================================

	describe("リフレッシュトークンによるトークン更新", () => {
		it("リフレッシュトークンで新しいアクセストークンを取得できる", async () => {
			const { codeVerifier, codeChallenge } = generatePkce();

			const code = await performAuthorizationFlow({
				clientId: TEST_CONFIDENTIAL_CLIENT.clientId,
				redirectUri: TEST_CONFIDENTIAL_CLIENT.redirectUri,
				scope: "read write",
				codeChallenge,
				codeVerifier,
			});

			// トークン交換
			const tokenRes = await request("/token", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_CONFIDENTIAL_CLIENT.clientId,
						TEST_CONFIDENTIAL_CLIENT.clientSecret,
					),
				},
				body: formBody({
					grant_type: "authorization_code",
					code,
					redirect_uri: TEST_CONFIDENTIAL_CLIENT.redirectUri,
					code_verifier: codeVerifier,
				}),
			});
			const tokenBody = await tokenRes.json();
			const refreshToken = tokenBody.refresh_token;
			expect(refreshToken).toBeTruthy();

			// リフレッシュトークンでトークン更新
			const refreshRes = await request("/token", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_CONFIDENTIAL_CLIENT.clientId,
						TEST_CONFIDENTIAL_CLIENT.clientSecret,
					),
				},
				body: formBody({
					grant_type: "refresh_token",
					refresh_token: refreshToken,
				}),
			});
			expect(refreshRes.status).toBe(200);
			expect(refreshRes.headers.get("Cache-Control")).toBe("no-store");
			expect(refreshRes.headers.get("Pragma")).toBeNull();

			const refreshBody = await refreshRes.json();
			expect(refreshBody.access_token).toBeTruthy();
			expect(refreshBody.token_type).toBe("Bearer");
			expect(refreshBody.scope).toBe("read write");
			// 新しいアクセストークンが元のとは異なること
			expect(refreshBody.access_token).not.toBe(tokenBody.access_token);
		});

		it("リフレッシュ時にスコープのサブセットを要求できる", async () => {
			const { codeVerifier, codeChallenge } = generatePkce();

			const code = await performAuthorizationFlow({
				clientId: TEST_CONFIDENTIAL_CLIENT.clientId,
				redirectUri: TEST_CONFIDENTIAL_CLIENT.redirectUri,
				scope: "read write",
				codeChallenge,
				codeVerifier,
			});

			const tokenRes = await request("/token", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_CONFIDENTIAL_CLIENT.clientId,
						TEST_CONFIDENTIAL_CLIENT.clientSecret,
					),
				},
				body: formBody({
					grant_type: "authorization_code",
					code,
					redirect_uri: TEST_CONFIDENTIAL_CLIENT.redirectUri,
					code_verifier: codeVerifier,
				}),
			});
			const tokenBody = await tokenRes.json();

			// スコープのサブセットでリフレッシュ
			const refreshRes = await request("/token", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_CONFIDENTIAL_CLIENT.clientId,
						TEST_CONFIDENTIAL_CLIENT.clientSecret,
					),
				},
				body: formBody({
					grant_type: "refresh_token",
					refresh_token: tokenBody.refresh_token,
					scope: "read",
				}),
			});
			expect(refreshRes.status).toBe(200);

			const refreshBody = await refreshRes.json();
			expect(refreshBody.scope).toBe("read");
		});
	});

	// ============================================================
	// リフレッシュトークンのローテーション
	// ============================================================

	describe("リフレッシュトークンのローテーション", () => {
		// [SECURITY]
		// 更新のたびにリフレッシュトークンをローテーションし、無効になったトークンの提示を
		// 漏洩の兆候として grant 単位で失効させる。応答の喪失に備えて消費から60秒の
		// 猶予窓を設ける。ここで確認する不変条件は「1つの grant に生きたリフレッシュトークンは
		// 高々1本」であり、これが破れると再利用検知が永久に発火しなくなる。

		/** コンフィデンシャルクライアントでリフレッシュ要求を送る */
		function refresh(refreshToken: string, params?: Record<string, string>) {
			return request("/token", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_CONFIDENTIAL_CLIENT.clientId,
						TEST_CONFIDENTIAL_CLIENT.clientSecret,
					),
				},
				body: formBody({
					grant_type: "refresh_token",
					refresh_token: refreshToken,
					...params,
				}),
			});
		}

		/** 平文のリフレッシュトークンから DB 行を引く */
		async function findRefreshToken(token: string) {
			const rows = await testDb
				.select()
				.from(refreshTokens)
				.where(eq(refreshTokens.tokenHash, sha256(token)))
				.limit(1);
			return rows[0];
		}

		/** grant 配下の生きた（未使用かつ未失効の）リフレッシュトークン */
		async function liveRefreshTokens(grantId: string) {
			return testDb
				.select()
				.from(refreshTokens)
				.where(
					and(
						eq(refreshTokens.grantId, grantId),
						isNull(refreshTokens.usedAt),
						isNull(refreshTokens.revokedAt),
					),
				);
		}

		/** grant 行を引く */
		async function findGrant(grantId: string) {
			const rows = await testDb.select().from(grants).where(eq(grants.id, grantId)).limit(1);
			return rows[0];
		}

		it("更新のたびに新しいリフレッシュトークンが返り、旧トークンは消費済みになる", async () => {
			const { refreshToken: rt0 } = await obtainTokens();
			const row0 = await findRefreshToken(rt0);

			const res = await refresh(rt0);
			expect(res.status).toBe(200);

			const body = await res.json();
			const rt1 = body.refresh_token as string;
			expect(rt1).toBeTruthy();
			expect(rt1).not.toBe(rt0);

			// 旧トークンは消費済みになり、後継への前向きポインタが張られる
			const consumed = await findRefreshToken(rt0);
			expect(consumed.usedAt).not.toBeNull();
			const row1 = await findRefreshToken(rt1);
			expect(consumed.replacedBy).toBe(row1.id);

			// 生きたリフレッシュトークンは新しいほうの1本だけ
			const live = await liveRefreshTokens(row0.grantId);
			expect(live).toHaveLength(1);
			expect(live[0].id).toBe(row1.id);
		});

		it("猶予窓内の再送は後継RTを失効させるが、既存ATとgrantは無効化しない", async () => {
			const { refreshToken: rt0 } = await obtainTokens();
			const row0 = await findRefreshToken(rt0);

			const first = await refresh(rt0);
			expect(first.status).toBe(200);
			const firstBody = await first.json();
			const rt1 = firstBody.refresh_token as string;
			const at1Jti = decodeJwt(firstBody.access_token).jti;
			assert(at1Jti);
			const beforeAccessTokens = await testDb
				.select()
				.from(accessTokens)
				.where(eq(accessTokens.grantId, row0.grantId))
				.orderBy(accessTokens.jti);
			expect(beforeAccessTokens).toHaveLength(2);
			expect(beforeAccessTokens.some((row) => row.jti === at1Jti)).toBe(true);
			expect(beforeAccessTokens.every((row) => row.revokedAt === null)).toBe(true);
			const beforeGrant = await findGrant(row0.grantId);
			const consumed = await findRefreshToken(rt0);
			const previousSuccessor = await findRefreshToken(rt1);
			expect(consumed.revokedAt).toBeNull();
			expect(previousSuccessor.revokedAt).toBeNull();

			// 応答を受け取れなかったクライアントが同じトークンをもう一度出す
			const retry = await refresh(rt0);
			expect(retry.status).toBe(200);
			const retryBody = await retry.json();
			const rt2 = retryBody.refresh_token as string;
			const at2Jti = decodeJwt(retryBody.access_token).jti;
			assert(at2Jti);
			expect(rt2).not.toBe(rt1);
			expect(beforeAccessTokens.map((row) => row.jti)).not.toContain(at2Jti);

			const afterAccessTokens = await testDb
				.select()
				.from(accessTokens)
				.where(eq(accessTokens.grantId, row0.grantId))
				.orderBy(accessTokens.jti);
			expect(afterAccessTokens).toHaveLength(3);
			expect(afterAccessTokens.filter((row) => row.jti !== at2Jti)).toEqual(beforeAccessTokens);
			expect(afterAccessTokens.find((row) => row.jti === at2Jti)).toMatchObject({
				revokedAt: null,
			});
			expect(beforeGrant.revokedAt).toBeNull();
			expect(await findGrant(row0.grantId)).toEqual(beforeGrant);

			const row2 = await findRefreshToken(rt2);
			// 旧RTは後継への参照だけを更新し、使用時刻や無効化状態は変更しない。
			expect(await findRefreshToken(rt0)).toEqual({ ...consumed, replacedBy: row2.id });
			// 直前の後継RTは無効化日時だけが変わる。
			const row1 = await findRefreshToken(rt1);
			expect(row1).toEqual({ ...previousSuccessor, revokedAt: expect.any(Date) });
			expect(row2).toMatchObject({
				grantId: row0.grantId,
				usedAt: null,
				revokedAt: null,
				replacedBy: null,
			});

			const live = await liveRefreshTokens(row0.grantId);
			expect(live).toHaveLength(1);
			expect(live[0].id).toBe(row2.id);
		});

		it("連鎖が2世代進んだあとの猶予窓でも、生きたトークンは1本に保たれる", async () => {
			const { refreshToken: rt0 } = await obtainTokens();
			const row0 = await findRefreshToken(rt0);

			const rt1 = (await (await refresh(rt0)).json()).refresh_token as string;
			const rt2 = (await (await refresh(rt1)).json()).refresh_token as string;

			// [SECURITY] 直後の後継（rt1）だけを失効させる実装だと rt2 が生き残り、
			// 有効なトークンが2本並んで再利用検知が発火しなくなる
			const retry = await refresh(rt0);
			expect(retry.status).toBe(200);
			const rt3 = (await retry.json()).refresh_token as string;

			expect((await findRefreshToken(rt2)).revokedAt).not.toBeNull();

			const live = await liveRefreshTokens(row0.grantId);
			expect(live).toHaveLength(1);
			expect(live[0].id).toBe((await findRefreshToken(rt3)).id);
		});

		it("猶予窓のやり直しで失効させたトークンの提示は再利用として grant を失効させる", async () => {
			const { accessToken, refreshToken: rt0 } = await obtainTokens();
			const row0 = await findRefreshToken(rt0);

			const rt1 = (await (await refresh(rt0)).json()).refresh_token as string;
			await refresh(rt0); // やり直しで rt1 が失効する

			// [SECURITY] 失効させられたトークンの提示も再利用として扱う。
			// 攻撃者が猶予窓を使った場合、失効するのは正規のクライアントが持つトークンになる。
			const res = await refresh(rt1);
			expect(res.status).toBe(400);
			expect((await res.json()).error).toBe("invalid_grant");

			expect((await findGrant(row0.grantId)).revokedAt).not.toBeNull();
			expect(await liveRefreshTokens(row0.grantId)).toHaveLength(0);

			// カスケード失効で発行済みのアクセストークンも巻き込まれる
			const ats = await testDb
				.select()
				.from(accessTokens)
				.where(eq(accessTokens.grantId, row0.grantId));
			expect(ats.length).toBeGreaterThan(0);
			expect(ats.every((at) => at.revokedAt !== null)).toBe(true);
			expect(accessToken).toBeTruthy();
		});

		it("猶予窓を過ぎた使用済みトークンの提示は再利用として grant を失効させる", async () => {
			const { refreshToken: rt0 } = await obtainTokens();
			const row0 = await findRefreshToken(rt0);

			const rt1 = (await (await refresh(rt0)).json()).refresh_token as string;

			// 消費時刻を60秒より前に巻き戻し、猶予窓の外にする
			await testDb
				.update(refreshTokens)
				.set({ usedAt: sql`now() - interval '120 seconds'` })
				.where(eq(refreshTokens.id, row0.id));

			const res = await refresh(rt0);
			expect(res.status).toBe(400);
			expect((await res.json()).error).toBe("invalid_grant");

			expect((await findGrant(row0.grantId)).revokedAt).not.toBeNull();
			expect((await findRefreshToken(rt1)).revokedAt).not.toBeNull();
		});

		it("同一トークンの並行提示でも、生きたトークンは1本に収束する", async () => {
			const { refreshToken: rt0 } = await obtainTokens();
			const row0 = await findRefreshToken(rt0);

			// [SECURITY] grant 行ロックで直列化され、敗者は消費に失敗して猶予窓の処理に回る
			const [resA, resB] = await Promise.all([refresh(rt0), refresh(rt0)]);
			expect(resA.status).toBe(200);
			expect(resB.status).toBe(200);

			const live = await liveRefreshTokens(row0.grantId);
			expect(live).toHaveLength(1);
			expect((await findGrant(row0.grantId)).revokedAt).toBeNull();
		});

		it("使用済みの旧トークンを /revoke に渡すと 200 を返し grant が失効する", async () => {
			const { refreshToken: rt0 } = await obtainTokens();
			const row0 = await findRefreshToken(rt0);
			await refresh(rt0);

			// トークン自体が死んでいても、消せと言われたら消す（期限切れのトークンもリボークできるのと同じ考え方）
			const res = await request("/revoke", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_CONFIDENTIAL_CLIENT.clientId,
						TEST_CONFIDENTIAL_CLIENT.clientSecret,
					),
				},
				body: formBody({ token: rt0, token_type_hint: "refresh_token" }),
			});
			expect(res.status).toBe(200);

			expect((await findGrant(row0.grantId)).revokedAt).not.toBeNull();
			expect(await liveRefreshTokens(row0.grantId)).toHaveLength(0);
		});

		it("一度も使われないまま期限切れになったトークンでは grant を失効させない", async () => {
			const { refreshToken: rt0 } = await obtainTokens();
			const row0 = await findRefreshToken(rt0);

			await testDb
				.update(refreshTokens)
				.set({ expiresAt: sql`now() - interval '1 second'` })
				.where(eq(refreshTokens.id, row0.id));

			const res = await refresh(rt0);
			expect(res.status).toBe(400);
			expect((await res.json()).error).toBe("invalid_grant");

			// 期限切れのトークン1つで正規の利用者を追い出さない
			expect((await findGrant(row0.grantId)).revokedAt).toBeNull();
		});

		it("失効させられたトークンは、期限を過ぎてから提示されても grant を失効させる", async () => {
			const { refreshToken: rt0 } = await obtainTokens();
			const row0 = await findRefreshToken(rt0);

			// [SECURITY] 期限を来歴より先に見る実装だと、この提示が期限切れとして
			// 素通りし、サーバー側に残っている再利用の証拠を捨てることになる
			await testDb
				.update(refreshTokens)
				.set({
					revokedAt: sql`now() - interval '2 seconds'`,
					expiresAt: sql`now() - interval '1 second'`,
				})
				.where(eq(refreshTokens.id, row0.id));

			const res = await refresh(rt0);
			expect(res.status).toBe(400);
			expect((await res.json()).error).toBe("invalid_grant");
			expect((await findGrant(row0.grantId)).revokedAt).not.toBeNull();
		});

		it("使用済みのトークンは、猶予窓と期限の両方を過ぎてから提示されても grant を失効させる", async () => {
			const { refreshToken: rt0 } = await obtainTokens();
			const row0 = await findRefreshToken(rt0);
			await refresh(rt0);

			await testDb
				.update(refreshTokens)
				.set({
					usedAt: sql`now() - interval '120 seconds'`,
					expiresAt: sql`now() - interval '1 second'`,
				})
				.where(eq(refreshTokens.id, row0.id));

			const res = await refresh(rt0);
			expect(res.status).toBe(400);
			expect((await res.json()).error).toBe("invalid_grant");
			expect((await findGrant(row0.grantId)).revokedAt).not.toBeNull();
		});

		it("後継トークンの有効期限は grant 誕生からの絶対上限で頭打ちになる", async () => {
			const { refreshToken: rt0 } = await obtainTokens();
			const row0 = await findRefreshToken(rt0);

			// grant の誕生を179日前に巻き戻す。絶対上限180日まで残り1日なので、
			// 無操作30日ではなく絶対上限のほうが効く
			await testDb
				.update(grants)
				.set({ createdAt: sql`now() - interval '179 days'` })
				.where(eq(grants.id, row0.grantId));

			const rt1 = (await (await refresh(rt0)).json()).refresh_token as string;
			const row1 = await findRefreshToken(rt1);

			const remainingDays = (row1.expiresAt.getTime() - Date.now()) / (24 * 60 * 60 * 1000);
			expect(remainingDays).toBeLessThan(2);
			expect(remainingDays).toBeGreaterThan(0);
		});

		it("猶予窓の内側でも、grant の絶対上限を過ぎていれば更新できない", async () => {
			const { refreshToken: rt0 } = await obtainTokens();
			const row0 = await findRefreshToken(rt0);

			const rt1 = (await (await refresh(rt0)).json()).refresh_token as string;

			// [SECURITY] 猶予窓のやり直しは消費の期限判定を通らない。絶対上限を見ないと
			// min(無操作期限, 絶対上限) が過去になり、受け取った瞬間に期限切れの
			// リフレッシュトークンを 200 で返してしまう
			await testDb
				.update(grants)
				.set({ createdAt: sql`now() - interval '181 days'` })
				.where(eq(grants.id, row0.grantId));

			const res = await refresh(rt0);
			expect(res.status).toBe(400);
			expect((await res.json()).error).toBe("invalid_grant");

			// 上限に達しただけなので grant は失効させない（再利用ではない）
			expect((await findGrant(row0.grantId)).revokedAt).toBeNull();

			// やり直しに入っていないので、直前の後継はそのまま生きている
			const live = await liveRefreshTokens(row0.grantId);
			expect(live).toHaveLength(1);
			expect(live[0].id).toBe((await findRefreshToken(rt1)).id);
		});

		it("範囲外のスコープを要求しても、リフレッシュトークンは消費されない", async () => {
			const { refreshToken: rt0 } = await obtainTokens({ scope: "read" });
			const row0 = await findRefreshToken(rt0);

			const res = await refresh(rt0, { scope: "read write" });
			expect(res.status).toBe(400);
			expect((await res.json()).error).toBe("invalid_scope");

			// スコープの検証は消費のあとに行うため、失敗時はトランザクションごと
			// 巻き戻す。クライアントの誤りで正規のトークンを殺さないため
			expect((await findRefreshToken(rt0)).usedAt).toBeNull();
			expect(await liveRefreshTokens(row0.grantId)).toHaveLength(1);

			// 同じトークンでそのまま更新できる
			expect((await refresh(rt0)).status).toBe(200);
		});

		it("使用済みトークンに範囲外のスコープを添えても再利用検知が働く", async () => {
			const { refreshToken: rt0 } = await obtainTokens({ scope: "read" });
			const row0 = await findRefreshToken(rt0);
			await refresh(rt0);

			await testDb
				.update(refreshTokens)
				.set({ usedAt: sql`now() - interval '120 seconds'` })
				.where(eq(refreshTokens.id, row0.id));

			// [SECURITY] スコープの検証を状態の確認より先に置くと、範囲外のスコープを
			// 添えるだけで invalid_scope に逃げ、再利用検知をすり抜けられる
			const res = await refresh(rt0, { scope: "read write" });
			expect(res.status).toBe(400);
			expect((await res.json()).error).toBe("invalid_grant");

			expect((await findGrant(row0.grantId)).revokedAt).not.toBeNull();
		});

		it("猶予窓の判定には grant 行ロックの待ち時間が含まれる", async () => {
			const { refreshToken: rt0 } = await obtainTokens();
			const row0 = await findRefreshToken(rt0);
			await refresh(rt0);

			// 猶予窓（60秒）の終わり際まで巻き戻す。残りは1秒
			await testDb
				.update(refreshTokens)
				.set({ usedAt: sql`clock_timestamp() - interval '59 seconds'` })
				.where(eq(refreshTokens.id, row0.id));

			// 別の接続で grant 行をロックし、リフレッシュをロック待ちにする
			let releaseLock = (): void => {};
			const lockHeld = new Promise<void>((resolve) => {
				releaseLock = resolve;
			});
			const holding = testDb.transaction(async (tx) => {
				await tx
					.select({ id: grants.id })
					.from(grants)
					.where(eq(grants.id, row0.grantId))
					.for("update");
				await lockHeld;
			});

			await new Promise((resolve) => setTimeout(resolve, 100));
			const pending = refresh(rt0);

			// 窓が閉じてからロックを解放する
			await new Promise((resolve) => setTimeout(resolve, 2000));
			releaseLock();
			await holding;

			// [SECURITY] 窓の判定を now()（トランザクション開始時刻）で行うと、
			// ロックを待つあいだに窓が閉じても内側と見なされ、猶予窓が実質的に延びる。
			// clock_timestamp() で判定すれば待ち時間が反映され、再利用として検知される
			const res = await pending;
			expect(res.status).toBe(400);
			expect((await res.json()).error).toBe("invalid_grant");
			expect((await findGrant(row0.grantId)).revokedAt).not.toBeNull();
		});

		it("パブリッククライアントでもローテーションが働く", async () => {
			const { codeVerifier, codeChallenge } = generatePkce();

			const code = await performAuthorizationFlow({
				clientId: TEST_PUBLIC_CLIENT.clientId,
				redirectUri: TEST_PUBLIC_CLIENT.redirectUri,
				scope: "read",
				codeChallenge,
				codeVerifier,
			});

			const tokenBody = await (
				await request("/token", {
					method: "POST",
					headers: { "Content-Type": "application/x-www-form-urlencoded" },
					body: formBody({
						grant_type: "authorization_code",
						code,
						redirect_uri: TEST_PUBLIC_CLIENT.redirectUri,
						code_verifier: codeVerifier,
						client_id: TEST_PUBLIC_CLIENT.clientId,
					}),
				})
			).json();
			const rt0 = tokenBody.refresh_token as string;
			expect(rt0).toBeTruthy();

			const res = await request("/token", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: formBody({
					grant_type: "refresh_token",
					refresh_token: rt0,
					client_id: TEST_PUBLIC_CLIENT.clientId,
				}),
			});
			expect(res.status).toBe(200);

			const body = await res.json();
			expect(body.refresh_token).toBeTruthy();
			expect(body.refresh_token).not.toBe(rt0);
			expect(body.expires_in).toBe(1800);
		});

		it("スコープを縮めて更新しても、以後の更新の上限は変わらない", async () => {
			const { refreshToken: rt0 } = await obtainTokens({ scope: "read write" });

			// 縮小はそのとき発行するアクセストークンにだけ効く
			// （draft-15 §4.3.3: 後継の scope はリクエストに含まれたトークンと一致させる）
			const body = await (await refresh(rt0, { scope: "read" })).json();
			expect(body.scope).toBe("read");

			// 上限は grant 行にあり、後継のリフレッシュトークンは
			// スコープを持たない。scope を省略した次の更新が元の範囲に戻ることで確かめる。
			const again = await refresh(body.refresh_token as string);
			expect((await again.json()).scope).toBe("read write");
		});
	});

	// ============================================================
	// トークンリボケーション
	// ============================================================

	describe("トークンリボケーション", () => {
		it("アクセストークンをリボークできる", async () => {
			const { accessToken } = await obtainTokens();

			// リボーク
			const revokeRes = await request("/revoke", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_CONFIDENTIAL_CLIENT.clientId,
						TEST_CONFIDENTIAL_CLIENT.clientSecret,
					),
				},
				body: formBody({
					token: accessToken,
					token_type_hint: "access_token",
				}),
			});
			expect(revokeRes.status).toBe(200);

			// イントロスペクションで無効を確認
			const introRes = await request("/introspect", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_RESOURCE_SERVER.resourceServerId,
						TEST_RESOURCE_SERVER.secret,
					),
				},
				body: formBody({ token: accessToken }),
			});
			expect(introRes.status).toBe(200);
			const introBody = await introRes.json();
			expect(introBody.active).toBe(false);
		});

		it("リフレッシュトークンリボーク時に関連アクセストークンもカスケードリボークされる", async () => {
			const { accessToken, refreshToken } = await obtainTokens();

			// リフレッシュトークンをリボーク
			const revokeRes = await request("/revoke", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_CONFIDENTIAL_CLIENT.clientId,
						TEST_CONFIDENTIAL_CLIENT.clientSecret,
					),
				},
				body: formBody({
					token: refreshToken,
					token_type_hint: "refresh_token",
				}),
			});
			expect(revokeRes.status).toBe(200);

			// アクセストークンもカスケードリボークされていることを確認
			const introRes = await request("/introspect", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_RESOURCE_SERVER.resourceServerId,
						TEST_RESOURCE_SERVER.secret,
					),
				},
				body: formBody({ token: accessToken }),
			});
			const introBody = await introRes.json();
			expect(introBody.active).toBe(false);
		});

		it("未登録のクライアントは401を返す", async () => {
			const res = await request("/revoke", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: formBody({
					token: "some-token",
					client_id: "unknown-client",
				}),
			});
			expect(res.status).toBe(401);
			const body = await res.json();
			expect(body.error).toBe("invalid_client");
		});

		it("client_id が指定されていない場合は401", async () => {
			const res = await request("/revoke", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: formBody({ token: "some-token" }),
			});
			expect(res.status).toBe(401);
		});

		it("コンフィデンシャルクライアントが client_secret_post で認証できる", async () => {
			const res = await request("/revoke", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: formBody({
					token: "some-token",
					client_id: TEST_CONFIDENTIAL_CLIENT.clientId,
					client_secret: TEST_CONFIDENTIAL_CLIENT.clientSecret,
				}),
			});
			expect(res.status).toBe(200);
		});

		it("パブリッククライアントは client_id のみでリボークできる", async () => {
			const res = await request("/revoke", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: formBody({
					token: "some-token",
					client_id: TEST_PUBLIC_CLIENT.clientId,
				}),
			});
			expect(res.status).toBe(200);
		});

		it("token パラメータが欠けている場合は400", async () => {
			const res = await request("/revoke", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: formBody({ client_id: TEST_PUBLIC_CLIENT.clientId }),
			});
			expect(res.status).toBe(400);
			const body = await res.json();
			expect(body.error).toBe("invalid_request");
		});

		it("未知の token_type_hint でもエラーにならない", async () => {
			const res = await request("/revoke", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: formBody({
					token: "some-token",
					token_type_hint: "unknown_type",
					client_id: TEST_PUBLIC_CLIENT.clientId,
				}),
			});
			expect(res.status).toBe(200);
			expect(res.headers.get("Cache-Control")).toBe("no-store");
			expect(res.headers.get("Pragma")).toBeNull();
		});

		it("エラー時にも Cache-Control: no-store が設定される", async () => {
			const res = await request("/revoke", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: formBody({ client_id: TEST_PUBLIC_CLIENT.clientId }),
			});
			expect(res.status).toBe(400);
			expect(res.headers.get("Cache-Control")).toBe("no-store");
			expect(res.headers.get("Pragma")).toBeNull();
		});

		// RFC 7009 §2.1: token_type_hint は "hint" であり、フォールバック検索が必要
		it("ヒントが access_token でも実態が refresh_token ならフォールバックでリボークされる", async () => {
			const { refreshToken } = await obtainTokens();

			const res = await request("/revoke", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_CONFIDENTIAL_CLIENT.clientId,
						TEST_CONFIDENTIAL_CLIENT.clientSecret,
					),
				},
				body: formBody({
					token: refreshToken,
					token_type_hint: "access_token", // 嘘のヒント
				}),
			});
			expect(res.status).toBe(200);

			// リフレッシュトークンを使おうとして失敗することで実際にリボークされたと確認
			const refreshRes = await request("/token", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_CONFIDENTIAL_CLIENT.clientId,
						TEST_CONFIDENTIAL_CLIENT.clientSecret,
					),
				},
				body: formBody({
					grant_type: "refresh_token",
					refresh_token: refreshToken,
				}),
			});
			expect(refreshRes.status).toBe(400);
		});

		it("ヒントが refresh_token でも実態が access_token ならフォールバックでリボークされる", async () => {
			const { accessToken } = await obtainTokens();

			const res = await request("/revoke", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_CONFIDENTIAL_CLIENT.clientId,
						TEST_CONFIDENTIAL_CLIENT.clientSecret,
					),
				},
				body: formBody({
					token: accessToken,
					token_type_hint: "refresh_token", // 嘘のヒント
				}),
			});
			expect(res.status).toBe(200);

			// イントロスペクションで無効を確認
			const introRes = await request("/introspect", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_RESOURCE_SERVER.resourceServerId,
						TEST_RESOURCE_SERVER.secret,
					),
				},
				body: formBody({ token: accessToken }),
			});
			const introBody = await introRes.json();
			expect(introBody.active).toBe(false);
		});

		// [SECURITY] client_id 不一致のトークンはリボークできない
		it("別クライアントが発行したアクセストークンはリボークできない", async () => {
			const { accessToken } = await obtainTokens(); // confidential が発行

			// 別クライアント（public）が同じトークンをリボーク試行
			const res = await request("/revoke", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: formBody({
					token: accessToken,
					token_type_hint: "access_token",
					client_id: TEST_PUBLIC_CLIENT.clientId,
				}),
			});
			// RFC 7009: エラー扱いされない（呼出側は知らない token として扱われる）
			expect(res.status).toBe(200);

			// 元のトークンは依然として有効
			const introRes = await request("/introspect", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_RESOURCE_SERVER.resourceServerId,
						TEST_RESOURCE_SERVER.secret,
					),
				},
				body: formBody({ token: accessToken }),
			});
			const introBody = await introRes.json();
			expect(introBody.active).toBe(true);
		});

		it("別クライアントが発行したリフレッシュトークンはリボークできない", async () => {
			const { accessToken, refreshToken } = await obtainTokens(); // confidential

			const res = await request("/revoke", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: formBody({
					token: refreshToken,
					token_type_hint: "refresh_token",
					client_id: TEST_PUBLIC_CLIENT.clientId,
				}),
			});
			expect(res.status).toBe(200);

			// access はカスケードされていない（refresh が削除されていないため）
			const introRes = await request("/introspect", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_RESOURCE_SERVER.resourceServerId,
						TEST_RESOURCE_SERVER.secret,
					),
				},
				body: formBody({ token: accessToken }),
			});
			const introBody = await introRes.json();
			expect(introBody.active).toBe(true);
		});

		// 補足: アクセストークンの単独リボークは refresh をカスケード破棄しない
		it("アクセストークンリボーク時にはリフレッシュトークンはカスケードリボークされない", async () => {
			const { accessToken, refreshToken } = await obtainTokens();

			// アクセストークンのみリボーク
			const revokeRes = await request("/revoke", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_CONFIDENTIAL_CLIENT.clientId,
						TEST_CONFIDENTIAL_CLIENT.clientSecret,
					),
				},
				body: formBody({
					token: accessToken,
					token_type_hint: "access_token",
				}),
			});
			expect(revokeRes.status).toBe(200);

			// リフレッシュトークンはまだ有効 → 新アクセストークンが取得できる
			const refreshRes = await request("/token", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_CONFIDENTIAL_CLIENT.clientId,
						TEST_CONFIDENTIAL_CLIENT.clientSecret,
					),
				},
				body: formBody({
					grant_type: "refresh_token",
					refresh_token: refreshToken,
				}),
			});
			expect(refreshRes.status).toBe(200);
			const refreshBody = await refreshRes.json();
			expect(refreshBody.access_token).toBeTruthy();
		});
	});

	// ============================================================
	// イントロスペクション
	// ============================================================

	describe("イントロスペクション", () => {
		it("有効なトークンのイントロスペクション", async () => {
			const { accessToken } = await obtainTokens();

			const res = await request("/introspect", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_RESOURCE_SERVER.resourceServerId,
						TEST_RESOURCE_SERVER.secret,
					),
				},
				body: formBody({ token: accessToken }),
			});
			expect(res.status).toBe(200);

			const body = await res.json();
			expect(body.active).toBe(true);
			expect(body.scope).toBe("read write");
			expect(body.client_id).toBe(TEST_CONFIDENTIAL_CLIENT.clientId);
			expect(body.sub).toBe(testUserId);
			expect(body.token_type).toBe("Bearer");
			expect(body.exp).toBeDefined();
			expect(body.iat).toBeDefined();
			expect(body.jti).toBeDefined();
			// iss は認可サーバーの issuer
			expect(body.iss).toBe("http://localhost:3000");
			// aud は scope に対応するリソースサーバーID（resource-server-1 が read/write を担当）
			expect(body.aud).toBe(TEST_RESOURCE_SERVER.resourceServerId);
			expect(res.headers.get("Cache-Control")).toBe("no-store");
			expect(res.headers.get("Pragma")).toBeNull();
		});

		// 照会元RSがトークンのaudに含まれない場合はactive:falseを返す
		it("照会元RSがaudに含まれない場合はactive=falseを返す", async () => {
			// scope=read write のトークンのaudはresource-server-1のみ。
			// resource-server-2（admin専用）は照会元としてaudに含まれない。
			const { accessToken } = await obtainTokens();

			const res = await request("/introspect", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_RESOURCE_SERVER_2.resourceServerId,
						TEST_RESOURCE_SERVER_2.secret,
					),
				},
				body: formBody({ token: accessToken }),
			});
			expect(res.status).toBe(200);

			const body = await res.json();
			expect(body).toEqual({ active: false });
		});

		it("照会元RSがaudに含まれる場合はactive=trueを返す", async () => {
			// scope=admin のトークンのaudはresource-server-2のみ。
			const { accessToken } = await obtainTokens({ scope: "admin" });

			const res = await request("/introspect", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_RESOURCE_SERVER_2.resourceServerId,
						TEST_RESOURCE_SERVER_2.secret,
					),
				},
				body: formBody({ token: accessToken }),
			});
			expect(res.status).toBe(200);

			const body = await res.json();
			expect(body.active).toBe(true);
			expect(body.aud).toBe(TEST_RESOURCE_SERVER_2.resourceServerId);
		});

		it("不正なトークンの場合はactive=falseを返す", async () => {
			const res = await request("/introspect", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_RESOURCE_SERVER.resourceServerId,
						TEST_RESOURCE_SERVER.secret,
					),
				},
				body: formBody({ token: "invalid-token" }),
			});
			expect(res.status).toBe(200);

			const body = await res.json();
			expect(body.active).toBe(false);
		});

		it("リソースサーバー認証なしではエラーを返す", async () => {
			const { accessToken } = await obtainTokens();

			const res = await request("/introspect", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: formBody({ token: accessToken }),
			});
			expect(res.status).toBe(401);
		});

		describe("発行時のaudの保存と照会", () => {
			const RESOURCE_SERVERS = [TEST_RESOURCE_SERVER, TEST_RESOURCE_SERVER_2];

			async function introspectAs(
				resourceServer: (typeof RESOURCE_SERVERS)[number],
				token: string,
			): Promise<Record<string, unknown>> {
				const res = await request("/introspect", {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
						Authorization: basicAuthHeader(resourceServer.resourceServerId, resourceServer.secret),
					},
					body: formBody({ token }),
				});
				expect(res.status).toBe(200);
				return res.json();
			}

			async function refreshAccessToken(refreshToken: string): Promise<string> {
				const res = await request("/token", {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
						Authorization: basicAuthHeader(
							TEST_CONFIDENTIAL_CLIENT.clientId,
							TEST_CONFIDENTIAL_CLIENT.clientSecret,
						),
					},
					body: formBody({ grant_type: "refresh_token", refresh_token: refreshToken }),
				});
				expect(res.status).toBe(200);
				return (await res.json()).access_token;
			}

			async function storedAudience(accessToken: string): Promise<string[]> {
				const { jti } = decodeJwt(accessToken);
				assert(typeof jti === "string");
				const rows = await testDb.select().from(accessTokens).where(eq(accessTokens.jti, jti));
				expect(rows).toHaveLength(1);
				return rows[0].audience;
			}

			describe.each([
				{ label: "単一aud", scope: "read", audience: [TEST_RESOURCE_SERVER.resourceServerId] },
				{
					label: "複数aud",
					scope: "read admin",
					audience: [
						TEST_RESOURCE_SERVER.resourceServerId,
						TEST_RESOURCE_SERVER_2.resourceServerId,
					],
				},
			])("$label", ({ scope, audience }) => {
				const expectedAud = audience.length === 1 ? audience[0] : audience;

				it.each(["authorization_code", "refresh_token"])(
					"%s で発行したATのJWT・DB・照会結果のaudが一致する",
					async (grantType) => {
						const issued = await obtainTokens({ scope });
						const accessToken =
							grantType === "authorization_code"
								? issued.accessToken
								: await refreshAccessToken(issued.refreshToken);

						expect(decodeJwt(accessToken).aud).toEqual(expectedAud);
						expect(await storedAudience(accessToken)).toEqual(audience);

						for (const rs of RESOURCE_SERVERS) {
							const body = await introspectAs(rs, accessToken);
							if (audience.includes(rs.resourceServerId)) {
								expect(body).toMatchObject({ active: true, aud: expectedAud, scope });
							} else {
								// 対象外のRSには、有効性以外の情報を返さない
								expect(body).toEqual({ active: false });
							}
						}
					},
				);
			});

			it("発行後にscope→RSの設定が変わっても、照会は発行時に保存したaudを使う", async () => {
				// 発行時の設定: read → resource-server-1
				const { accessToken, refreshToken } = await obtainTokens({ scope: "read" });
				const rs1 = getResourceServer(TEST_RESOURCE_SERVER.resourceServerId);
				const rs2 = getResourceServer(TEST_RESOURCE_SERVER_2.resourceServerId);
				assert(rs1 && rs2);
				const original = { rs1: [...rs1.protectedScopes], rs2: [...rs2.protectedScopes] };
				try {
					// 設定変更を再現する: read の担当を resource-server-1 から resource-server-2 へ移す。
					// 設定ファイルは書き換えず、読み込み済みの設定だけをこのテストの間変更する。
					rs1.protectedScopes = original.rs1.filter((s) => s !== "read");
					rs2.protectedScopes = [...original.rs2, "read"];

					// 対照: 変更後に発行したATは、新しい設定どおり resource-server-2 宛になる
					const reissued = await refreshAccessToken(refreshToken);
					expect(decodeJwt(reissued).aud).toBe(TEST_RESOURCE_SERVER_2.resourceServerId);
					expect(await storedAudience(reissued)).toEqual([TEST_RESOURCE_SERVER_2.resourceServerId]);

					// 変更前に発行したATは、JWTのaudのとおり resource-server-1 宛のまま照会される
					expect(decodeJwt(accessToken).aud).toBe(TEST_RESOURCE_SERVER.resourceServerId);
					expect(await introspectAs(TEST_RESOURCE_SERVER, accessToken)).toMatchObject({
						active: true,
						aud: TEST_RESOURCE_SERVER.resourceServerId,
					});
					// 現在の設定では read を担当する resource-server-2 でも、発行時のaudに含まれないので照会できない
					expect(await introspectAs(TEST_RESOURCE_SERVER_2, accessToken)).toEqual({
						active: false,
					});
				} finally {
					rs1.protectedScopes = original.rs1;
					rs2.protectedScopes = original.rs2;
				}
			});
		});

		it("未登録のリソースサーバーIDでは401", async () => {
			const res = await request("/introspect", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader("unknown-server", "some-secret"),
				},
				body: formBody({ token: "some-token" }),
			});
			expect(res.status).toBe(401);
			const body = await res.json();
			expect(body.error).toBe("invalid_client");
		});

		it("OAuthクライアントのIDではイントロスペクションできない", async () => {
			const res = await request("/introspect", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_CONFIDENTIAL_CLIENT.clientId,
						TEST_CONFIDENTIAL_CLIENT.clientSecret,
					),
				},
				body: formBody({ token: "some-token" }),
			});
			expect(res.status).toBe(401);
			const body = await res.json();
			expect(body.error).toBe("invalid_client");
		});

		it("リソースサーバーのシークレットが不一致なら401", async () => {
			const res = await request("/introspect", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(TEST_RESOURCE_SERVER.resourceServerId, "wrong-secret"),
				},
				body: formBody({ token: "some-token" }),
			});
			expect(res.status).toBe(401);
			const body = await res.json();
			expect(body.error).toBe("invalid_client");
		});

		it("tokenパラメータがない場合は400", async () => {
			const res = await request("/introspect", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_RESOURCE_SERVER.resourceServerId,
						TEST_RESOURCE_SERVER.secret,
					),
				},
				body: "",
			});
			expect(res.status).toBe(400);
			const body = await res.json();
			expect(body.error).toBe("invalid_request");
		});

		it("エラー時にも Cache-Control: no-store が設定される", async () => {
			const res = await request("/introspect", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader("unknown-server", "wrong-secret"),
				},
				body: formBody({ token: "some-token" }),
			});
			expect(res.status).toBe(401);
			expect(res.headers.get("Cache-Control")).toBe("no-store");
			expect(res.headers.get("Pragma")).toBeNull();
		});

		it("有効期限切れトークンは active: false を返す", async () => {
			const { accessToken } = await obtainTokens();

			// 31 分後に時刻を進める（コンフィデンシャルのトークンは 30 分有効）
			const now = Date.now();
			vi.useFakeTimers({ now: now + 31 * 60 * 1000, shouldAdvanceTime: true });

			const res = await request("/introspect", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_RESOURCE_SERVER.resourceServerId,
						TEST_RESOURCE_SERVER.secret,
					),
				},
				body: formBody({ token: accessToken }),
			});

			vi.useRealTimers();

			expect(res.status).toBe(200);
			const body = await res.json();
			expect(body.active).toBe(false);
		});
	});

	// ============================================================
	// 認可コード再利用検知
	// ============================================================

	describe("認可コード再利用検知", () => {
		it("使用済み認可コードの再利用で関連トークンが全て無効化される", async () => {
			const { codeVerifier, codeChallenge } = generatePkce();

			const code = await performAuthorizationFlow({
				clientId: TEST_CONFIDENTIAL_CLIENT.clientId,
				redirectUri: TEST_CONFIDENTIAL_CLIENT.redirectUri,
				scope: "read write",
				codeChallenge,
				codeVerifier,
			});

			// 1回目のトークン交換（成功）
			const tokenRes = await request("/token", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_CONFIDENTIAL_CLIENT.clientId,
						TEST_CONFIDENTIAL_CLIENT.clientSecret,
					),
				},
				body: formBody({
					grant_type: "authorization_code",
					code,
					redirect_uri: TEST_CONFIDENTIAL_CLIENT.redirectUri,
					code_verifier: codeVerifier,
				}),
			});
			expect(tokenRes.status).toBe(200);
			const tokenBody = await tokenRes.json();
			const accessToken = tokenBody.access_token;

			// 2回目のトークン交換（同じ認可コード → 失敗、かつ全トークン無効化）
			const tokenRes2 = await request("/token", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_CONFIDENTIAL_CLIENT.clientId,
						TEST_CONFIDENTIAL_CLIENT.clientSecret,
					),
				},
				body: formBody({
					grant_type: "authorization_code",
					code,
					redirect_uri: TEST_CONFIDENTIAL_CLIENT.redirectUri,
					code_verifier: codeVerifier,
				}),
			});
			expect(tokenRes2.status).toBe(400);

			// 1回目で発行されたアクセストークンも無効化されている
			const introRes = await request("/introspect", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_RESOURCE_SERVER.resourceServerId,
						TEST_RESOURCE_SERVER.secret,
					),
				},
				body: formBody({ token: accessToken }),
			});
			const introBody = await introRes.json();
			expect(introBody.active).toBe(false);
		});

		// 不正パラメータでの再使用試行ではトークンを無効化しない
		// （OAuth 2.1 §7.5.2 後半の DoS 対策）
		it("使用済み認可コードを不正なcode_verifierで再使用しても既発行トークンは無効化されない", async () => {
			const { codeVerifier, codeChallenge } = generatePkce();

			const code = await performAuthorizationFlow({
				clientId: TEST_CONFIDENTIAL_CLIENT.clientId,
				redirectUri: TEST_CONFIDENTIAL_CLIENT.redirectUri,
				scope: "read write",
				codeChallenge,
				codeVerifier,
			});

			// 1回目のトークン交換（成功）
			const tokenRes = await request("/token", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_CONFIDENTIAL_CLIENT.clientId,
						TEST_CONFIDENTIAL_CLIENT.clientSecret,
					),
				},
				body: formBody({
					grant_type: "authorization_code",
					code,
					redirect_uri: TEST_CONFIDENTIAL_CLIENT.redirectUri,
					code_verifier: codeVerifier,
				}),
			});
			expect(tokenRes.status).toBe(200);
			const tokenBody = await tokenRes.json();
			const accessToken = tokenBody.access_token;

			// 2回目: コードだけ知っている攻撃者が、デタラメなcode_verifierで再送
			// → invalid_grantで拒否されるが、トークンは無効化されない
			const tokenRes2 = await request("/token", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_CONFIDENTIAL_CLIENT.clientId,
						TEST_CONFIDENTIAL_CLIENT.clientSecret,
					),
				},
				body: formBody({
					grant_type: "authorization_code",
					code,
					redirect_uri: TEST_CONFIDENTIAL_CLIENT.redirectUri,
					code_verifier: "x".repeat(43),
				}),
			});
			expect(tokenRes2.status).toBe(400);
			expect(await tokenRes2.json()).toMatchObject({ error: "invalid_grant" });

			// 1回目で発行されたアクセストークンは依然として有効
			const introRes = await request("/introspect", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_RESOURCE_SERVER.resourceServerId,
						TEST_RESOURCE_SERVER.secret,
					),
				},
				body: formBody({ token: accessToken }),
			});
			const introBody = await introRes.json();
			expect(introBody.active).toBe(true);
		});
	});

	// ============================================================
	// 認可コードの並行交換（競合状態）
	// ============================================================

	describe("認可コードの並行交換", () => {
		// [SECURITY] 同一認可コードを並行交換しても、成功は最大1件に
		// 限られ、再利用検知で grant ごと失効する（勝者が発行したトークンも含めて）。
		// 消費とトークン発行を同一トランザクションに置く修正がないと、敗者の grant 失効が
		// 勝者のトークン挿入より先に走り、勝者トークンが失効対象から漏れて生き残る。
		// この回帰は実DBの並行実行でしか再現しない。
		it("同一コードの並行交換は1件だけ成功し、再利用検知で勝者トークンも失効する", async () => {
			const { codeVerifier, codeChallenge } = generatePkce();

			const code = await performAuthorizationFlow({
				clientId: TEST_CONFIDENTIAL_CLIENT.clientId,
				redirectUri: TEST_CONFIDENTIAL_CLIENT.redirectUri,
				scope: "read write",
				codeChallenge,
				codeVerifier,
			});

			// 同一の認可コード交換リクエストを生成する
			const exchange = () =>
				request("/token", {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
						Authorization: basicAuthHeader(
							TEST_CONFIDENTIAL_CLIENT.clientId,
							TEST_CONFIDENTIAL_CLIENT.clientSecret,
						),
					},
					body: formBody({
						grant_type: "authorization_code",
						code,
						redirect_uri: TEST_CONFIDENTIAL_CLIENT.redirectUri,
						code_verifier: codeVerifier,
					}),
				});

			// 同一コードで2本同時にトークン交換する
			const [resA, resB] = await Promise.all([exchange(), exchange()]);
			const statuses = [resA.status, resB.status].sort();

			// 成功はちょうど1件、もう1件は invalid_grant（400）
			expect(statuses).toEqual([200, 400]);

			// 勝者（200）のレスポンスからトークンを取り出す
			const successRes = resA.status === 200 ? resA : resB;
			const successBody = await successRes.json();
			const accessToken = successBody.access_token as string;
			const refreshToken = successBody.refresh_token as string;
			expect(accessToken).toBeTruthy();
			expect(refreshToken).toBeTruthy();

			// [SECURITY] 並行交換は再利用として扱われ、勝者の AT も失効している
			const introRes = await request("/introspect", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_RESOURCE_SERVER.resourceServerId,
						TEST_RESOURCE_SERVER.secret,
					),
				},
				body: formBody({ token: accessToken }),
			});
			const introBody = await introRes.json();
			expect(introBody.active).toBe(false);

			// [SECURITY] 勝者の RT も失効しており、リフレッシュは invalid_grant になる
			const refreshRes = await request("/token", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_CONFIDENTIAL_CLIENT.clientId,
						TEST_CONFIDENTIAL_CLIENT.clientSecret,
					),
				},
				body: formBody({
					grant_type: "refresh_token",
					refresh_token: refreshToken,
				}),
			});
			expect(refreshRes.status).toBe(400);
		});
	});

	describe("リフレッシュと失効の競合", () => {
		// [SECURITY] リフレッシュによる AT 発行と revokeGrant を
		// grant 行ロック（lockActiveGrant / FOR UPDATE）で直列化する。この直列化がないと、
		// 失効コミットの直後に発行された新 AT が失効対象から漏れ、grant 失効後も生き残る。
		// 実DBの並行実行でのみ再現する不変条件を確認する。
		it("リフレッシュとリフレッシュトークンリボークを並行実行しても孤児アクセストークンが残らない", async () => {
			const { refreshToken } = await obtainTokens();
			expect(refreshToken).toBeTruthy();

			const refresh = () =>
				request("/token", {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
						Authorization: basicAuthHeader(
							TEST_CONFIDENTIAL_CLIENT.clientId,
							TEST_CONFIDENTIAL_CLIENT.clientSecret,
						),
					},
					body: formBody({
						grant_type: "refresh_token",
						refresh_token: refreshToken,
					}),
				});

			const revoke = () =>
				request("/revoke", {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
						Authorization: basicAuthHeader(
							TEST_CONFIDENTIAL_CLIENT.clientId,
							TEST_CONFIDENTIAL_CLIENT.clientSecret,
						),
					},
					body: formBody({
						token: refreshToken,
						token_type_hint: "refresh_token",
					}),
				});

			// リフレッシュと grant 失効を同時に実行する
			const [refreshRes, revokeRes] = await Promise.all([refresh(), revoke()]);

			// リボークは常に成功する（RFC 7009: 無効トークンでも200）
			expect(revokeRes.status).toBe(200);

			if (refreshRes.status === 200) {
				// リフレッシュが先行した場合、新 AT も grant 失効に巻き込まれていなければならない。
				// [SECURITY] 孤児 AT が残ると introspection で active:true になり、この検証が破れる。
				const body = await refreshRes.json();
				const newAccessToken = body.access_token as string;
				expect(newAccessToken).toBeTruthy();

				const introRes = await request("/introspect", {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
						Authorization: basicAuthHeader(
							TEST_RESOURCE_SERVER.resourceServerId,
							TEST_RESOURCE_SERVER.secret,
						),
					},
					body: formBody({ token: newAccessToken }),
				});
				const introBody = await introRes.json();
				expect(introBody.active).toBe(false);
			} else {
				// 失効が先行した場合、リフレッシュはロック取得時に失効を観測して invalid_grant で中断する。
				expect(refreshRes.status).toBe(400);
				const body = await refreshRes.json();
				expect(body.error).toBe("invalid_grant");
			}
		});
	});

	// ============================================================
	// PKCE検証
	// ============================================================

	describe("PKCE検証", () => {
		it("不正なcode_verifierでトークン交換が拒否される", async () => {
			const { codeChallenge } = generatePkce();

			const code = await performAuthorizationFlow({
				clientId: TEST_CONFIDENTIAL_CLIENT.clientId,
				redirectUri: TEST_CONFIDENTIAL_CLIENT.redirectUri,
				scope: "read",
				codeChallenge,
				codeVerifier: "dummy", // performAuthorizationFlowでは使わない
			});

			// 不正なcode_verifierでトークン交換
			const tokenRes = await request("/token", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_CONFIDENTIAL_CLIENT.clientId,
						TEST_CONFIDENTIAL_CLIENT.clientSecret,
					),
				},
				body: formBody({
					grant_type: "authorization_code",
					code,
					redirect_uri: TEST_CONFIDENTIAL_CLIENT.redirectUri,
					code_verifier: "wrong-verifier-that-does-not-match-the-challenge",
				}),
			});
			expect(tokenRes.status).toBe(400);

			const body = await tokenRes.json();
			expect(body.error).toBe("invalid_grant");
		});
	});

	// ============================================================
	// 認可エンドポイントのリクエストパターン
	// DB が必要なパターンを結合テストでカバーする。
	// ============================================================

	describe("認可エンドポイント: リクエストパターン", () => {
		// クエリ完全, ログイン済み, 未同意 → 同意画面表示
		it("ログイン済み・未同意で同意画面が表示される", async () => {
			const { codeChallenge } = generatePkce();
			const sessionCookie = await loginAndGetCookie();

			const authorizeUrl = buildAuthorizeUrl({
				clientId: TEST_CONFIDENTIAL_CLIENT.clientId,
				redirectUri: TEST_CONFIDENTIAL_CLIENT.redirectUri,
				scope: "read",
				codeChallenge,
			});

			const res = await request(authorizeUrl, {
				headers: { Cookie: sessionCookie },
			});
			expect(res.status).toBe(200);
			const html = await res.text();
			expect(html).toContain("approve");
		});

		// クエリ完全, ログイン済み, 同意済み → 認可コード発行（txnId 不作成）
		it("ログイン済み・同意済みで認可コードが発行される（同意スキップ）", async () => {
			confidentialClient.redirectUris.push(HTTPS_REDIRECT_URI);
			const { codeVerifier, codeChallenge } = generatePkce();

			// 1回目: 同意を含む完全なフロー
			await performAuthorizationFlow({
				clientId: TEST_CONFIDENTIAL_CLIENT.clientId,
				redirectUri: HTTPS_REDIRECT_URI,
				scope: "read",
				codeChallenge,
				codeVerifier,
			});

			// 2回目: 同じスコープで再認可（同意スキップ）
			const pkce2 = generatePkce();
			const authorizeUrl = buildAuthorizeUrl({
				clientId: TEST_CONFIDENTIAL_CLIENT.clientId,
				redirectUri: HTTPS_REDIRECT_URI,
				scope: "read",
				codeChallenge: pkce2.codeChallenge,
			});

			const sessionCookie = await loginAndGetCookie();

			const authRes = await request(authorizeUrl, {
				headers: { Cookie: sessionCookie },
			});

			expect(authRes.status).toBe(302);
			const params = getRedirectParams(authRes);
			expect(params.get("code")).toBeTruthy();
		});

		// state は任意（OAuth 2.1 §4.1.1 で OPTIONAL）
		it("state なしの認可リクエストが受け付けられ、レスポンスに state が付かない", async () => {
			confidentialClient.redirectUris.push(HTTPS_REDIRECT_URI);
			const { codeVerifier, codeChallenge } = generatePkce();

			// 1回目: 同意を含む完全なフロー（state あり）
			await performAuthorizationFlow({
				clientId: TEST_CONFIDENTIAL_CLIENT.clientId,
				redirectUri: HTTPS_REDIRECT_URI,
				scope: "read",
				codeChallenge,
				codeVerifier,
			});

			// 2回目: state なしで再認可（同意スキップ → 即認可コード発行）
			const pkce2 = generatePkce();
			const params = new URLSearchParams({
				response_type: "code",
				client_id: TEST_CONFIDENTIAL_CLIENT.clientId,
				redirect_uri: HTTPS_REDIRECT_URI,
				scope: "read",
				code_challenge: pkce2.codeChallenge,
				code_challenge_method: "S256",
			});

			const sessionCookie = await loginAndGetCookie();
			const authRes = await request(`/authorize?${params.toString()}`, {
				headers: { Cookie: sessionCookie },
			});

			expect(authRes.status).toBe(302);
			const redirectParams = getRedirectParams(authRes);
			expect(redirectParams.get("code")).toBeTruthy();
			// RFC 6749 §4.1.2: state はリクエストにあった場合のみ返す
			expect(redirectParams.has("state")).toBe(false);
		});

		// ログイン済みで既存の txnId があり、新しい認可リクエストを送るケースは、
		// 新しい認可リクエストとして扱われ、上の2件と挙動が同じなので省いている。

		// ?txnId=... 付き, ログイン済み, 有効 txnId, 未同意 → 同意画面表示
		it("ログイン後の復帰（未同意） → 同意画面表示", async () => {
			const { codeChallenge } = generatePkce();

			// Step 1: 認可リクエスト（未ログイン → /login?txnId=... へ）
			const authorizeUrl = buildAuthorizeUrl({
				clientId: TEST_CONFIDENTIAL_CLIENT.clientId,
				redirectUri: TEST_CONFIDENTIAL_CLIENT.redirectUri,
				scope: "read",
				codeChallenge,
			});

			const authRes = await request(authorizeUrl);
			expect(authRes.status).toBe(302);
			const txnId = extractTxnIdFromLocation(authRes);
			const setCookieHeader = authRes.headers.get("Set-Cookie");
			const sidMatch = setCookieHeader!.match(/sid=([^;]+)/);
			let sessionCookie = `sid=${sidMatch![1]}`;

			// Step 2: ログイン
			const loginRes = await request("/login", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Cookie: sessionCookie,
				},
				body: formBody({
					username: "testuser",
					password: "password123",
					txnId,
					csrfToken: await getFormCsrfToken(app, `/login?txnId=${txnId}`, sessionCookie),
				}),
			});
			expect(loginRes.status).toBe(303);
			expect(loginRes.headers.get("Location")).toBe(
				`/authorize?txnId=${encodeURIComponent(txnId)}`,
			);

			// ログイン後のセッションCookieを更新
			const loginSetCookie = loginRes.headers.get("Set-Cookie");
			const loginSidMatch = loginSetCookie?.match(/sid=([^;]+)/);
			if (loginSidMatch) {
				sessionCookie = `sid=${loginSidMatch[1]}`;
			}

			// Step 3: /authorize?txnId=... へ復帰（同意画面表示）
			const authRes2 = await request(`/authorize?txnId=${encodeURIComponent(txnId)}`, {
				headers: { Cookie: sessionCookie },
			});
			expect(authRes2.status).toBe(200);
			const html = await authRes2.text();
			expect(html).toContain("approve");
		});

		// ========================================================
		// GET /authorize 復帰パス（?txnId=... 付き）の異常系
		// 認可リクエストの保存先の分岐自体は authorization-request-store の unit テストで
		// 網羅。ここではエンドポイントが store の null をどう扱うかの代表確認。
		// ========================================================

		it("セッションなしで ?txnId=... → 400 エラー画面", async () => {
			const res = await request("/authorize?txnId=any-txnId-id");
			expect(res.status).toBe(400);
			expect(res.headers.get("content-type")).toContain("text/html");
		});

		it("store が null を返す（不正/期限切れ/boundSid不一致）→ 400", async () => {
			// セッションは作るが txnId は別セッション ID で作成（boundSid 不一致）
			// 代表として他セッションで作った txnId を踏むケースを使用。
			// 「存在しない」「期限切れ」も同じく store が null を返すので
			// エンドポイント側のハンドリングは共通。
			const { codeChallenge } = generatePkce();
			const setupRes = await request(
				buildAuthorizeUrl({
					clientId: TEST_PUBLIC_CLIENT.clientId,
					redirectUri: TEST_PUBLIC_CLIENT.redirectUri,
					scope: "read",
					codeChallenge,
				}),
			);
			const txnId = extractTxnIdFromLocation(setupRes);

			// 別セッション Cookie を作って同じ txnId を踏む
			const otherRes = await request(
				buildAuthorizeUrl({
					clientId: TEST_PUBLIC_CLIENT.clientId,
					redirectUri: TEST_PUBLIC_CLIENT.redirectUri,
					scope: "read",
					codeChallenge,
				}),
			);
			const otherSidMatch = otherRes.headers.get("Set-Cookie")?.match(/sid=([^;]+)/);
			const otherCookie = `sid=${otherSidMatch?.[1]}`;

			const res = await request(`/authorize?txnId=${encodeURIComponent(txnId)}`, {
				headers: { Cookie: otherCookie },
			});
			expect(res.status).toBe(400);
		});

		it("有効な txnId で未ログイン → /login?txnId=... へ再リダイレクト", async () => {
			const { codeChallenge } = generatePkce();
			const initRes = await request(
				buildAuthorizeUrl({
					clientId: TEST_PUBLIC_CLIENT.clientId,
					redirectUri: TEST_PUBLIC_CLIENT.redirectUri,
					scope: "read",
					codeChallenge,
				}),
			);
			const txnId = extractTxnIdFromLocation(initRes);
			const sidMatch = initRes.headers.get("Set-Cookie")?.match(/sid=([^;]+)/);
			const sessionCookie = `sid=${sidMatch?.[1]}`;

			// ログインせずに同じ txnId で /authorize?txnId=... を踏み直す
			const res = await request(`/authorize?txnId=${encodeURIComponent(txnId)}`, {
				headers: { Cookie: sessionCookie },
			});
			expect(res.status).toBe(302);
			const location = res.headers.get("location") ?? "";
			expect(location).toMatch(/^\/login\?txnId=/);
			const txnIdInLocation = new URL(location, "http://test").searchParams.get("txnId");
			expect(txnIdInLocation).toBe(txnId);
		});

		// ========================================================
		// GET /authorize 新規パス（?txnId=... なし）
		// ========================================================

		it("クエリ完全 + セッションなし → Set-Cookie 付き /login?txnId=...", async () => {
			const { codeChallenge } = generatePkce();
			const res = await request(
				buildAuthorizeUrl({
					clientId: TEST_PUBLIC_CLIENT.clientId,
					redirectUri: TEST_PUBLIC_CLIENT.redirectUri,
					scope: "read",
					codeChallenge,
				}),
			);
			expect(res.status).toBe(302);
			expect(res.headers.get("location")).toMatch(/^\/login\?txnId=/);
			const setCookie = res.headers.get("set-cookie") ?? "";
			expect(setCookie).toContain("sid=");
			expect(setCookie).toContain("HttpOnly");
		});

		it("クエリ完全 + 既存セッション → Set-Cookie なし、新しい txnId が発行される", async () => {
			const { codeChallenge } = generatePkce();
			// 1 回目: セッション作成 + txnId 発行
			const firstRes = await request(
				buildAuthorizeUrl({
					clientId: TEST_PUBLIC_CLIENT.clientId,
					redirectUri: TEST_PUBLIC_CLIENT.redirectUri,
					scope: "read",
					codeChallenge,
				}),
			);
			const firstTxnId = extractTxnIdFromLocation(firstRes);
			const sidMatch = firstRes.headers.get("Set-Cookie")?.match(/sid=([^;]+)/);
			const sessionCookie = `sid=${sidMatch?.[1]}`;

			// 2 回目: 同じセッションで別の認可リクエストを開始
			const pkce2 = generatePkce();
			const secondRes = await request(
				buildAuthorizeUrl({
					clientId: TEST_PUBLIC_CLIENT.clientId,
					redirectUri: TEST_PUBLIC_CLIENT.redirectUri,
					scope: "read",
					codeChallenge: pkce2.codeChallenge,
				}),
				{ headers: { Cookie: sessionCookie } },
			);
			expect(secondRes.status).toBe(302);
			// 既存セッションを使い回すので Set-Cookie は付かない
			expect(secondRes.headers.get("set-cookie")).toBeNull();
			// 新規 txnId が発行される（既存とは別 ID）
			const secondTxnId = extractTxnIdFromLocation(secondRes);
			expect(secondTxnId).not.toBe(firstTxnId);
		});

		it("response_type なし → redirect_uri に invalid_request リダイレクト", async () => {
			// validator の redirect_error をエンドポイントが redirect_uri 付きで
			// リダイレクトするかの代表確認。他のエラー種別は validator unit でカバー。
			const { codeChallenge } = generatePkce();
			const params = new URLSearchParams({
				client_id: TEST_PUBLIC_CLIENT.clientId,
				redirect_uri: TEST_PUBLIC_CLIENT.redirectUri,
				state: "test-state-12345678901234567890ab",
				scope: "read",
				code_challenge: codeChallenge,
				code_challenge_method: "S256",
			});
			const res = await request(`/authorize?${params.toString()}`);
			expect(res.status).toBe(302);
			const location = res.headers.get("location") ?? "";
			expect(location).toContain("error=invalid_request");
			expect(location).toContain("state=test-state-12345678901234567890ab");
		});

		it("クエリも txnId もなしで GET → 400 エラー画面", async () => {
			const res = await request("/authorize");
			expect(res.status).toBe(400);
			expect(res.headers.get("content-type")).toContain("text/html");
		});

		// ========================================================
		// POST /authorize
		// ========================================================

		it("POST に txnId が含まれない → 400", async () => {
			const sessionCookie = await loginAndGetCookie();
			const res = await request("/authorize", {
				method: "POST",
				headers: {
					Cookie: sessionCookie,
					"Content-Type": "application/x-www-form-urlencoded",
				},
				body: formBody({
					decision: "approve",
					csrfToken: await getFormCsrfToken(
						app,
						buildAuthorizeUrl({
							clientId: TEST_PUBLIC_CLIENT.clientId,
							redirectUri: TEST_PUBLIC_CLIENT.redirectUri,
							...generatePkce(),
						}),
						sessionCookie,
					),
				}),
			});
			expect(res.status).toBe(400);
		});

		it("POST にセッション Cookie なし → 403", async () => {
			const res = await request("/authorize", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: formBody({ decision: "approve", txnId: "anything" }),
			});
			expect(res.status).toBe(403);
			expect(res.headers.get("content-type")).toContain("text/html");
		});

		it("POST 未ログインセッション → 400", async () => {
			const { codeChallenge } = generatePkce();
			const initRes = await request(
				buildAuthorizeUrl({
					clientId: TEST_PUBLIC_CLIENT.clientId,
					redirectUri: TEST_PUBLIC_CLIENT.redirectUri,
					scope: "read",
					codeChallenge,
				}),
			);
			const txnId = extractTxnIdFromLocation(initRes);
			const sidMatch = initRes.headers.get("Set-Cookie")?.match(/sid=([^;]+)/);
			const sessionCookie = `sid=${sidMatch?.[1]}`;

			// ログインせずに POST
			const res = await request("/authorize", {
				method: "POST",
				headers: {
					Cookie: sessionCookie,
					"Content-Type": "application/x-www-form-urlencoded",
				},
				body: formBody({
					decision: "approve",
					txnId,
					csrfToken: await getFormCsrfToken(app, `/login?txnId=${txnId}`, sessionCookie),
				}),
			});
			expect(res.status).toBe(400);
		});

		it("POST decision=deny → access_denied リダイレクト", async () => {
			const { codeChallenge } = generatePkce();
			// セッション準備 + ログイン + txnId 取得
			const authorizeUrl = buildAuthorizeUrl({
				clientId: TEST_PUBLIC_CLIENT.clientId,
				redirectUri: TEST_PUBLIC_CLIENT.redirectUri,
				scope: "read",
				codeChallenge,
			});
			const authRes = await request(authorizeUrl);
			const txnId = extractTxnIdFromLocation(authRes);
			const sidMatch = authRes.headers.get("Set-Cookie")?.match(/sid=([^;]+)/);
			let sessionCookie = `sid=${sidMatch?.[1]}`;

			const loginRes = await request("/login", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Cookie: sessionCookie,
				},
				body: formBody({
					username: "testuser",
					password: "password123",
					txnId,
					csrfToken: await getFormCsrfToken(app, `/login?txnId=${txnId}`, sessionCookie),
				}),
			});
			const loginSidMatch = loginRes.headers.get("Set-Cookie")?.match(/sid=([^;]+)/);
			if (loginSidMatch) {
				sessionCookie = `sid=${loginSidMatch[1]}`;
			}

			const res = await request("/authorize", {
				method: "POST",
				headers: {
					Cookie: sessionCookie,
					"Content-Type": "application/x-www-form-urlencoded",
				},
				body: formBody({
					decision: "deny",
					txnId,
					csrfToken: await getFormCsrfToken(app, `/authorize?txnId=${txnId}`, sessionCookie),
				}),
			});
			expect(res.status).toBe(303);
			const params = getRedirectParams(res);
			expect(params.get("error")).toBe("access_denied");
			expect(params.get("state")).toBe("test-state-12345678901234567890ab");
			// RFC 9207: iss が含まれる
			expect(params.get("iss")).toBe("http://localhost:3000");
		});

		it("POST decision に不正値 → 400", async () => {
			const { codeChallenge } = generatePkce();
			const authorizeUrl = buildAuthorizeUrl({
				clientId: TEST_PUBLIC_CLIENT.clientId,
				redirectUri: TEST_PUBLIC_CLIENT.redirectUri,
				scope: "read",
				codeChallenge,
			});
			const authRes = await request(authorizeUrl);
			const txnId = extractTxnIdFromLocation(authRes);
			const sidMatch = authRes.headers.get("Set-Cookie")?.match(/sid=([^;]+)/);
			let sessionCookie = `sid=${sidMatch?.[1]}`;

			const loginRes = await request("/login", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Cookie: sessionCookie,
				},
				body: formBody({
					username: "testuser",
					password: "password123",
					txnId,
					csrfToken: await getFormCsrfToken(app, `/login?txnId=${txnId}`, sessionCookie),
				}),
			});
			const loginSidMatch = loginRes.headers.get("Set-Cookie")?.match(/sid=([^;]+)/);
			if (loginSidMatch) {
				sessionCookie = `sid=${loginSidMatch[1]}`;
			}

			const res = await request("/authorize", {
				method: "POST",
				headers: {
					Cookie: sessionCookie,
					"Content-Type": "application/x-www-form-urlencoded",
				},
				body: formBody({
					decision: "garbage",
					txnId,
					csrfToken: await getFormCsrfToken(app, `/authorize?txnId=${txnId}`, sessionCookie),
				}),
			});
			expect(res.status).toBe(400);
		});

		// ========================================================
		// RFC 9207: Authorization Server Issuer Identification
		// 認可コード発行成功時の iss は、同意済みでの発行・認可コード再利用検知・主フロー
		// などで間接的にカバーされる。ここではリダイレクト型エラーで明示確認。
		// ========================================================

		it("RFC 9207: リダイレクト型エラーレスポンスに iss が含まれる", async () => {
			const { codeChallenge } = generatePkce();
			const params = new URLSearchParams({
				client_id: TEST_PUBLIC_CLIENT.clientId,
				redirect_uri: TEST_PUBLIC_CLIENT.redirectUri,
				state: "test-state-12345678901234567890ab",
				scope: "read",
				code_challenge: codeChallenge,
				code_challenge_method: "S256",
			});
			const res = await request(`/authorize?${params.toString()}`);
			expect(res.status).toBe(302);
			const location = new URL(res.headers.get("location") ?? "");
			expect(location.searchParams.get("error")).toBe("invalid_request");
			expect(location.searchParams.get("iss")).toBe("http://localhost:3000");
		});

		// ?txnId=... 付き, ログイン済み, 有効 txnId, 同意済み → 認可コード発行
		it("ログイン後の復帰（同意済み） → 認可コード発行", async () => {
			confidentialClient.redirectUris.push(HTTPS_REDIRECT_URI);
			const { codeVerifier, codeChallenge } = generatePkce();

			// 事前に同意を記録するために1回目のフローを完了
			await performAuthorizationFlow({
				clientId: TEST_CONFIDENTIAL_CLIENT.clientId,
				redirectUri: HTTPS_REDIRECT_URI,
				scope: "read",
				codeChallenge,
				codeVerifier,
			});

			// 2回目: 認可リクエスト（未ログイン → ログイン画面へ）
			const pkce2 = generatePkce();
			const authorizeUrl = buildAuthorizeUrl({
				clientId: TEST_CONFIDENTIAL_CLIENT.clientId,
				redirectUri: HTTPS_REDIRECT_URI,
				scope: "read",
				codeChallenge: pkce2.codeChallenge,
			});

			const authRes = await request(authorizeUrl);
			const txnId = extractTxnIdFromLocation(authRes);
			const setCookieHeader = authRes.headers.get("Set-Cookie");
			const sidMatch = setCookieHeader!.match(/sid=([^;]+)/);
			let sessionCookie = `sid=${sidMatch![1]}`;

			// ログイン
			const loginRes = await request("/login", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Cookie: sessionCookie,
				},
				body: formBody({
					username: "testuser",
					password: "password123",
					txnId,
					csrfToken: await getFormCsrfToken(app, `/login?txnId=${txnId}`, sessionCookie),
				}),
			});
			expect(loginRes.status).toBe(303);
			expect(loginRes.headers.get("Location")).toBe(
				`/authorize?txnId=${encodeURIComponent(txnId)}`,
			);

			const loginSetCookie = loginRes.headers.get("Set-Cookie");
			const loginSidMatch = loginSetCookie?.match(/sid=([^;]+)/);
			if (loginSidMatch) {
				sessionCookie = `sid=${loginSidMatch[1]}`;
			}

			// /authorize?txnId=... へ復帰（同意済み → 認可コード発行）
			const authRes2 = await request(`/authorize?txnId=${encodeURIComponent(txnId)}`, {
				headers: { Cookie: sessionCookie },
			});
			expect(authRes2.status).toBe(302);
			const params = getRedirectParams(authRes2);
			expect(params.get("code")).toBeTruthy();
		});
	});

	// ============================================================
	// エラーケース
	// ============================================================

	// ============================================================
	// セキュリティテスト
	// ============================================================

	describe("セキュリティ", () => {
		it("ログイン成功時にセッションIDが再生成される（セッション固定攻撃対策）", async () => {
			const { codeChallenge } = generatePkce();
			const authorizeUrl = buildAuthorizeUrl({
				clientId: TEST_CONFIDENTIAL_CLIENT.clientId,
				redirectUri: TEST_CONFIDENTIAL_CLIENT.redirectUri,
				scope: "read",
				codeChallenge,
			});

			// 認可リクエスト → セッション作成
			const authRes = await request(authorizeUrl);
			const setCookie = authRes.headers.get("Set-Cookie");
			const sidMatch = setCookie?.match(/sid=([^;]+)/);
			const preLoginSessionId = sidMatch?.[1];
			expect(preLoginSessionId).toBeTruthy();

			// ログイン
			const loginRes = await request("/login", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Cookie: `sid=${preLoginSessionId}`,
				},
				body: formBody({
					username: "testuser",
					password: "password123",
					csrfToken: await getFormCsrfToken(app, "/login", `sid=${preLoginSessionId}`),
				}),
			});

			// ログイン後のセッションIDが変わっていることを検証
			const loginSetCookie = loginRes.headers.get("Set-Cookie");
			const loginSidMatch = loginSetCookie?.match(/sid=([^;]+)/);
			const postLoginSessionId = loginSidMatch?.[1];
			expect(postLoginSessionId).toBeTruthy();
			expect(postLoginSessionId).not.toBe(preLoginSessionId);
		});

		it("セッションID再生成後も txnId は新 sid に rebind され、認可フローを継続できる", async () => {
			const { codeChallenge } = generatePkce();
			const authorizeUrl = buildAuthorizeUrl({
				clientId: TEST_CONFIDENTIAL_CLIENT.clientId,
				redirectUri: TEST_CONFIDENTIAL_CLIENT.redirectUri,
				scope: "read",
				codeChallenge,
			});

			// 認可リクエスト → ログイン → 新セッションで認可フロー継続
			const authRes = await request(authorizeUrl);
			const txnId = extractTxnIdFromLocation(authRes);
			const setCookie = authRes.headers.get("Set-Cookie");
			const sidMatch = setCookie?.match(/sid=([^;]+)/);
			let sessionCookie = sidMatch ? `sid=${sidMatch[1]}` : "";

			const loginRes = await request("/login", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Cookie: sessionCookie,
				},
				body: formBody({
					username: "testuser",
					password: "password123",
					txnId,
					csrfToken: await getFormCsrfToken(app, `/login?txnId=${txnId}`, sessionCookie),
				}),
			});

			// 新しいセッションIDを取得
			const loginSetCookie = loginRes.headers.get("Set-Cookie");
			const loginSidMatch = loginSetCookie?.match(/sid=([^;]+)/);
			if (loginSidMatch) {
				sessionCookie = `sid=${loginSidMatch[1]}`;
			}

			// 新セッションで /authorize?txnId=... → rebind されているため引ける
			const restoreRes = await request(`/authorize?txnId=${encodeURIComponent(txnId)}`, {
				headers: { Cookie: sessionCookie },
			});

			// 同意画面が表示される（保存データの boundSid が新 sid に張り替えられた）
			expect(restoreRes.status).toBe(200);
			const html = await restoreRes.text();
			expect(html).toContain("認可");
		});

		it("ログイン前の古いセッションIDで txnId を引こうとしても boundSid 不一致で拒否される", async () => {
			const { codeChallenge } = generatePkce();
			const authorizeUrl = buildAuthorizeUrl({
				clientId: TEST_CONFIDENTIAL_CLIENT.clientId,
				redirectUri: TEST_CONFIDENTIAL_CLIENT.redirectUri,
				scope: "read",
				codeChallenge,
			});

			// 認可リクエスト → セッション・txnId 取得
			const authRes = await request(authorizeUrl);
			const txnId = extractTxnIdFromLocation(authRes);
			const setCookie = authRes.headers.get("Set-Cookie");
			const sidMatch = setCookie?.match(/sid=([^;]+)/);
			const oldSessionCookie = `sid=${sidMatch?.[1]}`;

			// ログイン（セッションID再生成 + txnId rebind）
			await request("/login", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Cookie: oldSessionCookie,
				},
				body: formBody({
					username: "testuser",
					password: "password123",
					txnId,
					csrfToken: await getFormCsrfToken(app, `/login?txnId=${txnId}`, oldSessionCookie),
				}),
			});

			// 古いセッションIDで /authorize?txnId=... → 旧 sid と boundSid が一致せず 400
			const res = await request(`/authorize?txnId=${encodeURIComponent(txnId)}`, {
				headers: { Cookie: oldSessionCookie },
			});

			expect(res.status).toBe(400);
		});
	});

	describe("エラーケース", () => {
		it("不正なclient_idでエラー画面が表示される", async () => {
			const { codeChallenge } = generatePkce();
			const url = buildAuthorizeUrl({
				clientId: "unknown-client",
				redirectUri: "http://evil.example.com/callback",
				codeChallenge,
			});

			const res = await request(url);
			expect(res.status).toBe(400);
			// エラー画面が返る（リダイレクトしない）
			const html = await res.text();
			expect(html).toBeTruthy();
		});

		it("grant_typeが未指定でエラーが返る", async () => {
			const res = await request("/token", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: formBody({ client_id: TEST_PUBLIC_CLIENT.clientId }),
			});
			expect(res.status).toBe(400);
			const body = await res.json();
			expect(body.error).toBe("invalid_request");
		});

		it("サポートされていないgrant_typeでエラーが返る", async () => {
			const res = await request("/token", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: formBody({
					grant_type: "implicit",
					client_id: TEST_PUBLIC_CLIENT.clientId,
				}),
			});
			expect(res.status).toBe(400);
			const body = await res.json();
			expect(body.error).toBe("unsupported_grant_type");
		});

		it("有効期限切れの認可コードでトークン交換するとエラーになる（B-7）", async () => {
			const { codeVerifier, codeChallenge } = generatePkce();

			// 認可フローで認可コードを取得
			const code = await performAuthorizationFlow({
				clientId: TEST_CONFIDENTIAL_CLIENT.clientId,
				redirectUri: TEST_CONFIDENTIAL_CLIENT.redirectUri,
				scope: "read write",
				codeChallenge,
				codeVerifier,
			});

			// 認可コードを期限切れにする。
			// 期限切れ判定は原子的 UPDATE 内で DB 時計（now()）と
			// 比較する。アプリ時計（vi.useFakeTimers）を進めても DB 時計には影響しないため、
			// ここでは expires_at を直接過去に書き換えて期限切れ状態を再現する。
			const codeHash = sha256(code);
			await testDb
				.update(authorizationCodes)
				.set({ expiresAt: new Date(Date.now() - 60 * 1000) })
				.where(eq(authorizationCodes.codeHash, codeHash));

			const tokenRes = await request("/token", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_CONFIDENTIAL_CLIENT.clientId,
						TEST_CONFIDENTIAL_CLIENT.clientSecret,
					),
				},
				body: formBody({
					grant_type: "authorization_code",
					code,
					redirect_uri: TEST_CONFIDENTIAL_CLIENT.redirectUri,
					code_verifier: codeVerifier,
				}),
			});

			expect(tokenRes.status).toBe(400);
			const body = await tokenRes.json();
			expect(body.error).toBe("invalid_grant");
		});

		it("リボケーションは無効なトークンでも200を返す", async () => {
			const res = await request("/revoke", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
				},
				body: formBody({
					token: "nonexistent-token",
					client_id: TEST_PUBLIC_CLIENT.clientId,
				}),
			});
			expect(res.status).toBe(200);
		});
	});

	// ============================================================
	// トークンエンドポイント: パラメータ・認証検証
	// ============================================================

	describe.each([TEST_PUBLIC_CLIENT, TEST_CONFIDENTIAL_CLIENT])(
		"トークン交換のredirect_uri省略: $clientId",
		(client) => {
			const { codeVerifier } = generatePkce();
			const otherClient =
				client.clientId === TEST_PUBLIC_CLIENT.clientId
					? TEST_CONFIDENTIAL_CLIENT
					: TEST_PUBLIC_CLIENT;

			async function createCode(verifier = codeVerifier) {
				return performAuthorizationFlow({
					clientId: client.clientId,
					redirectUri: client.redirectUri,
					scope: "read",
					codeVerifier: verifier,
					codeChallenge: sha256Base64url(verifier),
				});
			}

			function exchange(code: string, overrides: Record<string, string | undefined> = {}) {
				const params: Record<string, string> = {
					grant_type: "authorization_code",
					client_id: client.clientId,
					code,
					code_verifier: codeVerifier,
				};
				if ("clientSecret" in client) params.client_secret = client.clientSecret;
				for (const [key, value] of Object.entries(overrides)) {
					if (value === undefined) delete params[key];
					else params[key] = value;
				}
				return request("/token", {
					method: "POST",
					headers: { "Content-Type": "application/x-www-form-urlencoded" },
					body: formBody(params),
				});
			}

			it.each([undefined, "", client.redirectUri])(
				"省略・空値・保存値との一致なら交換でき、認可時の保存値は維持される（%s）",
				async (redirectUri) => {
					const code = await createCode();
					const response = await exchange(code, { redirect_uri: redirectUri });
					expect(response.status).toBe(200);
					expect(await response.json()).toMatchObject({
						access_token: expect.any(String),
						refresh_token: expect.any(String),
						token_type: "Bearer",
					});
					const record = await testDb.query.authorizationCodes.findFirst({
						where: eq(authorizationCodes.codeHash, sha256(code)),
					});
					expect(record?.redirectUri).toBe(client.redirectUri);
					expect(record?.usedAt).toBeInstanceOf(Date);
				},
			);

			it.each([
				" ",
				"https://other.example/callback",
				"http://127.0.0.1:9999/callback",
				client.redirectUri.replace("/callback", "/%63allback"),
			])("明示指定の不一致は正規化せず拒否する（%s）", async (redirectUri) => {
				const code = await createCode();
				const response = await exchange(code, { redirect_uri: redirectUri });
				expect(response.status).toBe(400);
				expect(await response.json()).toEqual({
					error: "invalid_grant",
					error_description: "The authorization code is invalid",
				});
				expect((await exchange(code)).status).toBe(200);
			});

			const verifierFailures = [
				{ label: "欠落", verifier: undefined, error: "invalid_request" },
				{ label: "空値", verifier: "", error: "invalid_request" },
				{ label: "42文字", verifier: "x".repeat(42), error: "invalid_request" },
				{ label: "129文字", verifier: "x".repeat(129), error: "invalid_request" },
				{ label: "空白", verifier: " ".repeat(43), error: "invalid_request" },
				{ label: "予約文字", verifier: `${"x".repeat(42)}+`, error: "invalid_request" },
				{ label: "非ASCII文字", verifier: `${"x".repeat(42)}あ`, error: "invalid_request" },
				{ label: "末尾改行", verifier: `${"x".repeat(43)}\n`, error: "invalid_request" },
				{ label: "照合不一致", verifier: "x".repeat(43), error: "invalid_grant" },
			];

			async function snapshotTokenState() {
				return Promise.all([
					testDb.select().from(authorizationCodes).orderBy(authorizationCodes.id),
					testDb.select().from(grants).orderBy(grants.id),
					testDb.select().from(accessTokens).orderBy(accessTokens.jti),
					testDb.select().from(refreshTokens).orderBy(refreshTokens.id),
				]);
			}

			it.each(verifierFailures)(
				"PKCEの$labelを拒否し、未使用の認可コードを消費しない",
				async ({ verifier, error }) => {
					const code = await createCode();
					const before = await snapshotTokenState();
					const response = await exchange(code, { code_verifier: verifier });
					expect(response.status).toBe(400);
					expect(response.headers.get("Cache-Control")).toBe("no-store");
					expect(response.headers.get("Pragma")).toBeNull();
					expect(response.headers.get("Content-Type")).toContain("application/json");
					expect(await response.json()).toEqual({
						error,
						error_description:
							error === "invalid_grant"
								? "The authorization code is invalid"
								: verifier
									? "Invalid code_verifier parameter"
									: "Missing code_verifier parameter",
					});
					expect(await snapshotTokenState()).toEqual(before);
					expect((await exchange(code)).status).toBe(200);
				},
			);

			it.each(verifierFailures)(
				"使用済み認可コードでもPKCEの$labelで既発行トークンを無効化しない",
				async ({ verifier, error }) => {
					const code = await createCode();
					expect((await exchange(code)).status).toBe(200);
					const before = await snapshotTokenState();
					const response = await exchange(code, { code_verifier: verifier });
					expect(response.status).toBe(400);
					expect(await response.json()).toMatchObject({ error });
					expect(await snapshotTokenState()).toEqual(before);
				},
			);

			it.each(["x".repeat(42), "x".repeat(129), `${"x".repeat(42)}+`, `${"x".repeat(43)}\n`])(
				"ハッシュが一致しても構文不正なverifierを拒否する（%s）",
				async (verifier) => {
					const code = await createCode(verifier);
					const before = await snapshotTokenState();
					const response = await exchange(code, { code_verifier: verifier });
					expect(response.status).toBe(400);
					expect(await response.json()).toMatchObject({ error: "invalid_request" });
					expect(await snapshotTokenState()).toEqual(before);
				},
			);

			it.each(["x".repeat(43), `${"x".repeat(124)}-._~`])(
				"構文境界を満たすverifierで交換できる（%s）",
				async (verifier) => {
					const code = await createCode(verifier);
					expect((await exchange(code, { code_verifier: verifier })).status).toBe(200);
				},
			);

			it("省略しても認可コードの発行先と異なるクライアントを拒否する", async () => {
				const code = await createCode();
				const response = await exchange(code, {
					client_id: otherClient.clientId,
					client_secret: "clientSecret" in otherClient ? otherClient.clientSecret : undefined,
				});
				expect(response.status).toBe(400);
				expect(await response.json()).toMatchObject({ error: "invalid_grant" });
				expect((await exchange(code)).status).toBe(200);
			});

			it("省略しても期限切れの認可コードを拒否する", async () => {
				const code = await createCode();
				await testDb
					.update(authorizationCodes)
					.set({ expiresAt: new Date(Date.now() - 60_000) })
					.where(eq(authorizationCodes.codeHash, sha256(code)));
				const response = await exchange(code);
				expect(response.status).toBe(400);
				expect(await response.json()).toMatchObject({ error: "invalid_grant" });
			});

			it("省略時も正当な再使用だけがgrantと関連トークンを失効させる", async () => {
				const code = await createCode();
				expect((await exchange(code)).status).toBe(200);
				const record = await testDb.query.authorizationCodes.findFirst({
					where: eq(authorizationCodes.codeHash, sha256(code)),
				});
				assert(record);
				const grantId = record.grantId;

				async function expectRevoked(revoked: boolean) {
					const grant = await testDb.query.grants.findFirst({
						where: eq(grants.id, grantId),
					});
					assert(grant);
					const access = await testDb.query.accessTokens.findMany({
						where: eq(accessTokens.grantId, grant.id),
					});
					const refresh = await testDb.query.refreshTokens.findMany({
						where: eq(refreshTokens.grantId, grant.id),
					});
					expect(access).toHaveLength(1);
					expect(refresh).toHaveLength(1);
					for (const item of [grant, ...access, ...refresh]) {
						expect(item.revokedAt !== null).toBe(revoked);
					}
				}

				const invalidRequests: Record<string, string | undefined>[] = [
					{ code_verifier: "x".repeat(43) },
					{
						client_id: otherClient.clientId,
						client_secret: "clientSecret" in otherClient ? otherClient.clientSecret : undefined,
					},
					{ redirect_uri: " " },
					{ redirect_uri: "https://other.example/callback" },
				];
				for (const params of invalidRequests) {
					const response = await exchange(code, params);
					expect(response.status).toBe(400);
					expect(await response.json()).toMatchObject({ error: "invalid_grant" });
					await expectRevoked(false);
				}

				const replay = await exchange(code);
				expect(replay.status).toBe(400);
				expect(await replay.json()).toMatchObject({ error: "invalid_grant" });
				await expectRevoked(true);
			});
		},
	);

	describe.each([TEST_PUBLIC_CLIENT, TEST_CONFIDENTIAL_CLIENT])(
		"トークンリクエストの共通パラメータ: $clientId",
		(client) => {
			const { codeVerifier, codeChallenge } = generatePkce();

			function postToken(
				params: URLSearchParams,
				authorization?: string,
				contentType = "application/x-www-form-urlencoded",
			) {
				return request("/token", {
					method: "POST",
					headers: {
						"Content-Type": contentType,
						...(authorization ? { Authorization: authorization } : {}),
					},
					body: params.toString(),
				});
			}

			async function snapshotTokenState() {
				return Promise.all([
					testDb.select().from(authorizationCodes).orderBy(authorizationCodes.id),
					testDb.select().from(grants).orderBy(grants.id),
					testDb.select().from(accessTokens).orderBy(accessTokens.jti),
					testDb.select().from(refreshTokens).orderBy(refreshTokens.id),
				]);
			}

			describe.each(["authorization_code", "refresh_token"] as const)("%s", (grantType) => {
				async function prepareRequest() {
					const code = await performAuthorizationFlow({
						clientId: client.clientId,
						redirectUri: client.redirectUri,
						scope: "read",
						codeVerifier,
						codeChallenge,
					});
					const params = new URLSearchParams({
						grant_type: "authorization_code",
						client_id: client.clientId,
						code,
						code_verifier: codeVerifier,
					});
					if ("clientSecret" in client) params.set("client_secret", client.clientSecret);
					if (grantType === "refresh_token") {
						const response = await postToken(params);
						expect(response.status).toBe(200);
						const token = await response.json();
						params.set("grant_type", "refresh_token");
						params.set("refresh_token", token.refresh_token);
						params.delete("code");
						params.delete("code_verifier");
					}
					return params;
				}

				it.each([
					"application/x-www-form-urlencoded",
					"Application/X-WWW-Form-Urlencoded",
					"application/x-www-form-urlencoded; charset=UTF-8",
					'application/x-www-form-urlencoded; CHARSET="uTf-8"',
					'application/x-www-form-urlencoded; charset="UTF\\-8"',
					'application/x-www-form-urlencoded; extension=token; note="a;b=1"; charset=UTF-8',
					'application/x-www-form-urlencoded; note="a\\"b\\\\c"; charset=UTF-8',
					'application/x-www-form-urlencoded\t; ; charset="UTF-8"; note="";\t;',
					"application/x-www-form-urlencoded; charset=UTF-8; CHARSET=utf-8",
				])("Content-Typeの有効な表記でトークンを発行できる（%s）", async (contentType) => {
					const params = await prepareRequest();
					const response = await postToken(params, undefined, contentType);
					expect(response.status).toBe(200);
					expect(await response.json()).toMatchObject({
						access_token: expect.any(String),
						refresh_token: expect.any(String),
						token_type: "Bearer",
						scope: "read",
					});
				});

				it("Content-Typeの欠落・不正形式・非UTF-8を本文解析前に拒否し、状態を変えない", async () => {
					const params = await prepareRequest();
					const before = await snapshotTokenState();
					for (const contentType of [
						null,
						"",
						"application/json",
						"multipart/form-data",
						"text/plain",
						"application/x-www-form-urlencoded-extra",
						"application/x-www-form-urlencoded/json",
						"application /x-www-form-urlencoded",
						"application/ x-www-form-urlencoded",
						"application/x-www-form-urlencoded, application/json",
						"application/x-www-form-urlencoded; charset",
						"application/x-www-form-urlencoded; charset=",
						"application/x-www-form-urlencoded; charset =UTF-8",
						"application/x-www-form-urlencoded; charset= UTF-8",
						'application/x-www-form-urlencoded; charset="UTF-8',
						'application/x-www-form-urlencoded; charset="UTF-8"junk',
						'application/x-www-form-urlencoded; charset=""',
						"application/x-www-form-urlencoded; charset=ISO-8859-1",
						'application/x-www-form-urlencoded; charset="Shift_JIS"',
						"application/x-www-form-urlencoded; charset=UTF-8; CHARSET=ISO-8859-1",
						"application/x-www-form-urlencoded; charset=ISO-8859-1; CHARSET=UTF-8",
						"application/x-www-form-urlencoded; charset=UTF-8, application/json",
						"application/x-www-form-urlencoded; extension",
						"application/x-www-form-urlencoded; extension=",
						'application/x-www-form-urlencoded; extension="unterminated',
						'application/x-www-form-urlencoded; extension="x"junk',
						'application/x-www-form-urlencoded; extension="x\u0001y"',
					]) {
						const incoming = new Request("http://localhost/token", {
							method: "POST",
							headers: contentType === null ? {} : { "Content-Type": contentType },
							// 文字列ボディによるContent-Typeの自動補完を避け、欠落も検証する。
							body: new TextEncoder().encode(params.toString()),
						});
						const response = await app.request(incoming);
						expect(response.status, String(contentType)).toBe(400);
						expect(await response.json()).toEqual({
							error: "invalid_request",
							error_description:
								"Content-Type must be application/x-www-form-urlencoded with UTF-8 encoding",
						});
						expect(response.headers.get("Cache-Control")).toBe("no-store");
						expect(response.headers.get("Pragma")).toBeNull();
						expect(incoming.bodyUsed).toBe(false);
						expect(await snapshotTokenState()).toEqual(before);
					}
					expect((await postToken(params)).status).toBe(200);
				});

				it.each(["JSON", "multipart"])(
					"%s形式の有効な資格情報でも拒否し、状態を変えない",
					async (format) => {
						const params = await prepareRequest();
						const form = new FormData();
						for (const [name, value] of params) form.append(name, value);
						const before = await snapshotTokenState();
						const incoming = new Request("http://localhost/token", {
							method: "POST",
							headers: format === "JSON" ? { "Content-Type": "application/json" } : {},
							body: format === "JSON" ? JSON.stringify(Object.fromEntries(params)) : form,
						});
						const response = await app.request(incoming);
						expect(response.status).toBe(400);
						expect(await response.json()).toMatchObject({ error: "invalid_request" });
						expect(incoming.bodyUsed).toBe(false);
						expect(await snapshotTokenState()).toEqual(before);
						expect((await postToken(params)).status).toBe(200);
					},
				);

				it("Content-Typeの拒否はクライアント認証失敗より先に行う", async () => {
					const params = await prepareRequest();
					params.set("client_id", "unknown-client");
					const before = await snapshotTokenState();
					const response = await postToken(
						params,
						undefined,
						"application/x-www-form-urlencoded; charset=Shift_JIS",
					);
					expect(response.status).toBe(400);
					expect(await response.json()).toMatchObject({
						error: "invalid_request",
						error_description:
							"Content-Type must be application/x-www-form-urlencoded with UTF-8 encoding",
					});
					const retry = await postToken(params);
					expect(retry.status).toBe(401);
					expect(await retry.json()).toMatchObject({ error: "invalid_client" });
					expect(await snapshotTokenState()).toEqual(before);
				});

				it("使用済みの認可コードやRTでもContent-Typeの拒否はgrantを失効させない", async () => {
					const params = await prepareRequest();
					expect((await postToken(params)).status).toBe(200);
					if (grantType === "refresh_token") {
						const refreshToken = params.get("refresh_token");
						assert(refreshToken);
						await testDb
							.update(refreshTokens)
							.set({ usedAt: new Date(Date.now() - 120_000) })
							.where(eq(refreshTokens.tokenHash, sha256(refreshToken)));
					}
					const before = await snapshotTokenState();
					const response = await postToken(
						params,
						undefined,
						"application/x-www-form-urlencoded; charset=ISO-8859-1",
					);
					expect(response.status).toBe(400);
					expect(await response.json()).toMatchObject({ error: "invalid_request" });
					expect(await snapshotTokenState()).toEqual(before);
				});

				it.each(["同値", "異値", "空値が先", "空値が後", "両方空値"])(
					"既知パラメータの重複は認証・状態変更前に拒否する（%s）",
					async (pattern) => {
						const params = await prepareRequest();
						const before = await snapshotTokenState();
						for (const name of [
							"grant_type",
							"client_id",
							"client_secret",
							"code",
							"redirect_uri",
							"code_verifier",
							"refresh_token",
							"scope",
						]) {
							const value = params.get(name) ?? "unused-value";
							const first = pattern === "空値が先" || pattern === "両方空値" ? "" : value;
							const second =
								pattern === "空値が後" || pattern === "両方空値"
									? ""
									: pattern === "異値"
										? "different-value"
										: value;
							const duplicate = new URLSearchParams(params);
							duplicate.set(name, first);
							duplicate.append(name, second);
							const response = await postToken(duplicate);
							expect(response.status).toBe(400);
							expect(await response.json()).toEqual({
								error: "invalid_request",
								error_description: `Duplicate ${name} parameter`,
							});
							expect(await snapshotTokenState()).toEqual(before);
						}
						expect((await postToken(params)).status).toBe(200);
					},
				);

				it("重複拒否はクライアント認証失敗より先に行う", async () => {
					const params = await prepareRequest();
					const before = await snapshotTokenState();
					params.set("client_id", "unknown-client");
					params.append("scope", "");
					params.append("scope", "");
					const response = await postToken(params);
					expect(response.status).toBe(400);
					expect(await response.json()).toMatchObject({
						error: "invalid_request",
						error_description: "Duplicate scope parameter",
					});
					expect(await snapshotTokenState()).toEqual(before);
				});

				it("使用済みの認可コードやRTでも重複拒否はgrantを失効させない", async () => {
					const params = await prepareRequest();
					expect((await postToken(params)).status).toBe(200);
					if (grantType === "refresh_token") {
						// 再利用として検知される猶予期間外の状態で、入口の拒否を確かめる。
						const refreshToken = params.get("refresh_token");
						assert(refreshToken);
						await testDb
							.update(refreshTokens)
							.set({ usedAt: new Date(Date.now() - 120_000) })
							.where(eq(refreshTokens.tokenHash, sha256(refreshToken)));
					}
					const before = await snapshotTokenState();
					params.append("scope", "read");
					params.append("scope", "read");
					const response = await postToken(params);
					expect(response.status).toBe(400);
					expect(await response.json()).toMatchObject({ error: "invalid_request" });
					expect(await snapshotTokenState()).toEqual(before);
				});

				const requiredParameters = [
					{ name: "grant_type", status: 400, error: "invalid_request" },
					{ name: "client_id", status: 401, error: "invalid_client" },
					...(grantType === "authorization_code"
						? [
								{ name: "code", status: 400, error: "invalid_request" },
								{ name: "code_verifier", status: 400, error: "invalid_request" },
							]
						: [{ name: "refresh_token", status: 400, error: "invalid_request" }]),
					...("clientSecret" in client
						? [{ name: "client_secret", status: 401, error: "invalid_client" }]
						: []),
				];
				it.each(requiredParameters)(
					"必須の$nameの空値は省略と同じ検証で拒否され、状態を変えない",
					async ({ name, status, error }) => {
						const params = await prepareRequest();
						const before = await snapshotTokenState();
						const empty = new URLSearchParams(params);
						empty.set(name, "");
						const emptyResponse = await postToken(empty);
						expect(emptyResponse.status).toBe(status);
						const emptyBody = await emptyResponse.json();
						expect(emptyBody.error).toBe(error);
						expect(await snapshotTokenState()).toEqual(before);
						empty.delete(name);
						const omittedResponse = await postToken(empty);
						expect(omittedResponse.status).toBe(status);
						expect(await omittedResponse.json()).toEqual(emptyBody);
						expect(await snapshotTokenState()).toEqual(before);
						expect((await postToken(params)).status).toBe(200);
					},
				);

				it("任意パラメータの空値は省略として扱い、scopeは元の認可範囲になる", async () => {
					const params = await prepareRequest();
					params.set("redirect_uri", "");
					params.set("scope", "");
					if (!("clientSecret" in client)) params.set("client_secret", "");
					const response = await postToken(params);
					expect(response.status).toBe(200);
					expect(await response.json()).toMatchObject({
						scope: "read",
						access_token: expect.any(String),
						refresh_token: expect.any(String),
					});
				});

				it("未知パラメータと未対応の拡張は重複・空値を含めて無視する", async () => {
					const params = await prepareRequest();
					for (const name of ["unknown", "resource", "code[]", "__proto__"]) {
						params.append(name, "");
						params.append(name, "https://resource.example/one");
						params.append(name, "https://resource.example/two");
					}
					expect((await postToken(params)).status).toBe(200);
				});

				if ("clientSecret" in client) {
					it("Basic認証では空のボディ認証情報を省略として扱う", async () => {
						const params = await prepareRequest();
						params.set("client_id", "");
						params.set("client_secret", "");
						const response = await postToken(
							params,
							basicAuthHeader(client.clientId, client.clientSecret),
						);
						expect(response.status).toBe(200);
					});
				}
			});
		},
	);

	describe("トークンエンドポイント: パラメータ・認証", () => {
		it("Fileを含むmultipartのトークンリクエストはContent-Typeで拒否し、保存状態を変えない", async () => {
			const existingTokens = await obtainTokens();
			expect(existingTokens.accessToken).toBeTruthy();
			expect(existingTokens.refreshToken).toBeTruthy();
			const { codeVerifier, codeChallenge } = generatePkce();
			const code = await performAuthorizationFlow({
				clientId: TEST_CONFIDENTIAL_CLIENT.clientId,
				redirectUri: TEST_CONFIDENTIAL_CLIENT.redirectUri,
				scope: "read",
				codeVerifier,
				codeChallenge,
			});
			const params = {
				grant_type: "authorization_code",
				client_id: TEST_CONFIDENTIAL_CLIENT.clientId,
				client_secret: TEST_CONFIDENTIAL_CLIENT.clientSecret,
				code,
				code_verifier: codeVerifier,
			};
			const form = new FormData();
			for (const [name, value] of Object.entries(params)) form.set(name, value);
			form.set("code", new File([code], "code.txt"));

			async function snapshotTokenState() {
				return Promise.all([
					testDb.select().from(authorizationCodes).orderBy(authorizationCodes.id),
					testDb.select().from(grants).orderBy(grants.id),
					testDb.select().from(accessTokens).orderBy(accessTokens.jti),
					testDb.select().from(refreshTokens).orderBy(refreshTokens.id),
				]);
			}

			const before = await snapshotTokenState();
			const response = await request("/token", { method: "POST", body: form });
			expect(response.status).toBe(400);
			expect(await response.json()).toEqual({
				error: "invalid_request",
				error_description:
					"Content-Type must be application/x-www-form-urlencoded with UTF-8 encoding",
			});
			expect(await snapshotTokenState()).toEqual(before);

			const retry = await request("/token", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: formBody(params),
			});
			expect(retry.status).toBe(200);
		});

		it("refresh_token グラントでクライアント認証なしは invalid_client", async () => {
			const res = await request("/token", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: formBody({ grant_type: "refresh_token" }),
			});
			expect(res.status).toBe(401);
			const body = await res.json();
			expect(body.error).toBe("invalid_client");
		});

		it("不明な client_id で 401 invalid_client", async () => {
			const res = await request("/token", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: formBody({
					grant_type: "authorization_code",
					client_id: "unknown-client",
					code: "test-code",
					redirect_uri: "http://127.0.0.1:8080/callback",
					code_verifier: "test-verifier",
				}),
			});
			expect(res.status).toBe(401);
			const body = await res.json();
			expect(body.error).toBe("invalid_client");
		});

		it("コンフィデンシャルクライアントが認証情報なしなら 401", async () => {
			const res = await request("/token", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: formBody({
					grant_type: "authorization_code",
					client_id: TEST_CONFIDENTIAL_CLIENT.clientId,
					code: "test-code",
					redirect_uri: TEST_CONFIDENTIAL_CLIENT.redirectUri,
					code_verifier: "test-verifier",
				}),
			});
			expect(res.status).toBe(401);
		});

		it("BasicとPostの認証方式を同時に使うと 400 invalid_request", async () => {
			const res = await request("/token", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_CONFIDENTIAL_CLIENT.clientId,
						TEST_CONFIDENTIAL_CLIENT.clientSecret,
					),
				},
				body: formBody({
					grant_type: "authorization_code",
					client_id: TEST_CONFIDENTIAL_CLIENT.clientId,
					client_secret: TEST_CONFIDENTIAL_CLIENT.clientSecret,
					code: "test-code",
					redirect_uri: TEST_CONFIDENTIAL_CLIENT.redirectUri,
					code_verifier: "test-verifier",
				}),
			});
			expect(res.status).toBe(400);
			const body = await res.json();
			expect(body.error).toBe("invalid_request");
		});

		it("パブリッククライアントがclient_secretを送ると 400 invalid_request", async () => {
			const res = await request("/token", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: formBody({
					grant_type: "authorization_code",
					client_id: TEST_PUBLIC_CLIENT.clientId,
					client_secret: "accidentally-embedded-secret",
					code: "test-code",
					redirect_uri: TEST_PUBLIC_CLIENT.redirectUri,
					code_verifier: "test-verifier",
				}),
			});
			expect(res.status).toBe(400);
			const body = await res.json();
			expect(body.error).toBe("invalid_request");
		});

		it("code が未指定なら invalid_request", async () => {
			const res = await request("/token", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: formBody({
					grant_type: "authorization_code",
					client_id: TEST_PUBLIC_CLIENT.clientId,
					redirect_uri: TEST_PUBLIC_CLIENT.redirectUri,
					code_verifier: "test-verifier",
				}),
			});
			expect(res.status).toBe(400);
			const body = await res.json();
			expect(body.error).toBe("invalid_request");
			expect(body.error_description).toContain("code");
		});

		it("redirect_uriを省略しても存在しない認可コードはinvalid_grant", async () => {
			const res = await request("/token", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: formBody({
					grant_type: "authorization_code",
					client_id: TEST_PUBLIC_CLIENT.clientId,
					code: "test-code",
					code_verifier: generatePkce().codeVerifier,
				}),
			});
			expect(res.status).toBe(400);
			const body = await res.json();
			expect(body.error).toBe("invalid_grant");
			expect(body.error_description).toBe("The authorization code is invalid");
		});

		// draft-16 §4.1.3の必須条件と§3.2.4の必須パラメーター不足に対応する。
		it("code_verifier が未指定なら invalid_request", async () => {
			const res = await request("/token", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: formBody({
					grant_type: "authorization_code",
					client_id: TEST_PUBLIC_CLIENT.clientId,
					code: "test-code",
					redirect_uri: TEST_PUBLIC_CLIENT.redirectUri,
				}),
			});
			expect(res.status).toBe(400);
			const body = await res.json();
			expect(body.error).toBe("invalid_request");
			expect(body.error_description).toBe("Missing code_verifier parameter");
		});

		it("client_secret_post で認証してトークン交換できる", async () => {
			const { codeVerifier, codeChallenge } = generatePkce();
			const code = await performAuthorizationFlow({
				clientId: TEST_CONFIDENTIAL_CLIENT.clientId,
				redirectUri: TEST_CONFIDENTIAL_CLIENT.redirectUri,
				scope: "read",
				codeChallenge,
				codeVerifier,
			});

			const res = await request("/token", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: formBody({
					grant_type: "authorization_code",
					client_id: TEST_CONFIDENTIAL_CLIENT.clientId,
					client_secret: TEST_CONFIDENTIAL_CLIENT.clientSecret,
					code,
					redirect_uri: TEST_CONFIDENTIAL_CLIENT.redirectUri,
					code_verifier: codeVerifier,
				}),
			});
			expect(res.status).toBe(200);
			const body = await res.json();
			expect(body.access_token).toBeTruthy();
		});

		it("refresh_token が未指定なら invalid_request", async () => {
			const res = await request("/token", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_CONFIDENTIAL_CLIENT.clientId,
						TEST_CONFIDENTIAL_CLIENT.clientSecret,
					),
				},
				body: formBody({ grant_type: "refresh_token" }),
			});
			expect(res.status).toBe(400);
			const body = await res.json();
			expect(body.error).toBe("invalid_request");
		});

		it("無効な refresh_token なら invalid_grant", async () => {
			const res = await request("/token", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_CONFIDENTIAL_CLIENT.clientId,
						TEST_CONFIDENTIAL_CLIENT.clientSecret,
					),
				},
				body: formBody({
					grant_type: "refresh_token",
					refresh_token: "invalid-token",
				}),
			});
			expect(res.status).toBe(400);
			const body = await res.json();
			expect(body.error).toBe("invalid_grant");
		});

		it("リフレッシュで元のスコープを超えると invalid_scope", async () => {
			const { codeVerifier, codeChallenge } = generatePkce();
			const code = await performAuthorizationFlow({
				clientId: TEST_CONFIDENTIAL_CLIENT.clientId,
				redirectUri: TEST_CONFIDENTIAL_CLIENT.redirectUri,
				scope: "read",
				codeChallenge,
				codeVerifier,
			});

			const tokenRes = await request("/token", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_CONFIDENTIAL_CLIENT.clientId,
						TEST_CONFIDENTIAL_CLIENT.clientSecret,
					),
				},
				body: formBody({
					grant_type: "authorization_code",
					code,
					redirect_uri: TEST_CONFIDENTIAL_CLIENT.redirectUri,
					code_verifier: codeVerifier,
				}),
			});
			const tokenBody = await tokenRes.json();

			// 元 scope=read で発行されたリフレッシュトークンで read write を要求
			const refreshRes = await request("/token", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: basicAuthHeader(
						TEST_CONFIDENTIAL_CLIENT.clientId,
						TEST_CONFIDENTIAL_CLIENT.clientSecret,
					),
				},
				body: formBody({
					grant_type: "refresh_token",
					refresh_token: tokenBody.refresh_token,
					scope: "read write",
				}),
			});
			expect(refreshRes.status).toBe(400);
			const refreshBody = await refreshRes.json();
			// スコープ超過はinvalid_scope（invalid_grantではない）
			expect(refreshBody.error).toBe("invalid_scope");
		});

		it("エラー時にも Cache-Control: no-store が設定される", async () => {
			const res = await request("/token", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: formBody({}),
			});
			expect(res.status).toBe(400);
			expect(res.headers.get("Cache-Control")).toBe("no-store");
		});
	});

	// ============================================================
	// 発行結果と保存失敗時の状態
	// ============================================================

	describe("発行したJWTのヘッダー・クレーム・有効期限", () => {
		describe.each([TEST_PUBLIC_CLIENT, TEST_CONFIDENTIAL_CLIENT])("$clientId", (client) => {
			it.each(["authorization_code", "refresh_token"])(
				"%sで発行したJWTを公開鍵で検証する",
				async (grantType) => {
					const { codeVerifier, codeChallenge } = generatePkce();
					const code = await performAuthorizationFlow({
						clientId: client.clientId,
						redirectUri: client.redirectUri,
						scope: "read write",
						codeVerifier,
						codeChallenge,
					});
					let before = Math.floor(Date.now() / 1000);
					let response = await tokenRequest(
						{
							grant_type: "authorization_code",
							code,
							code_verifier: codeVerifier,
						},
						client,
					);
					expect(response.status).toBe(200);
					let body = await response.json();
					const scope = grantType === "refresh_token" ? "read" : "read write";
					if (grantType === "refresh_token") {
						before = Math.floor(Date.now() / 1000);
						response = await tokenRequest(
							{ grant_type: grantType, refresh_token: body.refresh_token, scope },
							client,
						);
						expect(response.status).toBe(200);
						body = await response.json();
					}
					const after = Math.floor(Date.now() / 1000);
					expect(body).toMatchObject({ token_type: "Bearer", expires_in: 1800, scope });

					const jwksResponse = await request("/.well-known/jwks.json");
					expect(jwksResponse.status).toBe(200);
					const jwks = (await jwksResponse.json()) as JSONWebKeySet;
					const { payload, protectedHeader } = await jwtVerify(
						body.access_token,
						createLocalJWKSet(jwks),
						{
							algorithms: ["RS256"],
							typ: "at+jwt",
							issuer: serverConfig.issuer,
							audience: TEST_RESOURCE_SERVER.resourceServerId,
						},
					);
					expect(protectedHeader).toMatchObject({ alg: "RS256", typ: "at+jwt" });
					assert(typeof protectedHeader.kid === "string" && protectedHeader.kid.length > 0);
					expect(jwks.keys.some((key) => key.kid === protectedHeader.kid)).toBe(true);
					expect(payload).toMatchObject({
						iss: serverConfig.issuer,
						sub: testUserId,
						aud: TEST_RESOURCE_SERVER.resourceServerId,
						client_id: client.clientId,
						scope,
					});
					assert(typeof payload.iat === "number" && typeof payload.exp === "number");
					expect(Number.isInteger(payload.iat)).toBe(true);
					expect(payload.iat).toBeGreaterThanOrEqual(before);
					expect(payload.iat).toBeLessThanOrEqual(after);
					expect(payload.exp - payload.iat).toBe(1800);
					assert(payload.jti);
					expect(payload.jti).toMatch(/^[A-Za-z0-9_-]{22}$/);
					expect(Buffer.from(payload.jti, "base64url")).toHaveLength(16);

					const rows = await testDb
						.select()
						.from(accessTokens)
						.where(eq(accessTokens.jti, payload.jti));
					expect(rows).toHaveLength(1);
					expect(rows[0]).toMatchObject({
						clientId: client.clientId,
						userId: testUserId,
						scope,
						audience: [TEST_RESOURCE_SERVER.resourceServerId],
						expiresAt: new Date(payload.exp * 1000),
						revokedAt: null,
					});
				},
			);
		});
	});

	describe("トークン保存失敗の巻き戻し", () => {
		async function snapshot() {
			return {
				codes: await testDb.select().from(authorizationCodes).orderBy(authorizationCodes.id),
				grants: await testDb.select().from(grants).orderBy(grants.id),
				accessTokens: await testDb.select().from(accessTokens).orderBy(accessTokens.jti),
				refreshTokens: await testDb.select().from(refreshTokens).orderBy(refreshTokens.id),
			};
		}

		async function withRefreshTokenInsertFailure(run: () => Promise<void>) {
			await cleanupTokenSaveFailureInjection();
			// シーケンスはロールバックされないため、失敗直前のAT保存を外側から確認できる。
			await testDb.execute(sql`CREATE SEQUENCE test_rt_insert_at_count MINVALUE 0 START 0`);
			try {
				await testDb.execute(sql`
					CREATE FUNCTION test_fail_rt_insert() RETURNS trigger LANGUAGE plpgsql AS $$
					BEGIN
						PERFORM setval('test_rt_insert_at_count',
							(SELECT count(*) FROM access_tokens WHERE grant_id = NEW.grant_id), true);
						RAISE EXCEPTION 'テスト用のRT保存失敗';
					END;
					$$
				`);
				await testDb.execute(sql`
					CREATE TRIGGER test_fail_rt_insert BEFORE INSERT ON refresh_tokens
					FOR EACH ROW EXECUTE FUNCTION test_fail_rt_insert()
				`);
				await run();
			} finally {
				await cleanupTokenSaveFailureInjection();
			}
		}

		it("残った障害注入を通常のDB初期化で除去し、トークンを発行できる", async () => {
			await withRefreshTokenInsertFailure(async () => {
				// finallyが走らずに残った状態を、次回のテスト開始時の初期化で回復する。
				await cleanupDatabase();
				const [remaining] = await testDb.execute(sql`
					SELECT to_regclass('test_rt_insert_at_count') AS sequence,
						to_regprocedure('test_fail_rt_insert()') AS function,
						(SELECT count(*)::int FROM pg_trigger WHERE tgname = 'test_fail_rt_insert') AS triggers
				`);
				expect(remaining).toEqual({ sequence: null, function: null, triggers: 0 });
				testUserId = (await createTestUser()).id;
				const tokens = await obtainTokens();
				expect(tokens.accessToken).toBeTruthy();
				expect(tokens.refreshToken).toBeTruthy();
			});
		});

		it.each(["認可コード交換", "RTの初回使用", "猶予期間内の再送"])(
			"%s: AT保存後にRT保存が失敗したら状態を巻き戻し、再試行できる",
			async (scenario) => {
				// 別grantのATが存在しても、障害注入の到達確認は対象grantの件数だけで行う。
				const unrelated = await obtainTokens();
				expect(unrelated.accessToken).toBeTruthy();
				let params: Record<string, string>;
				if (scenario === "認可コード交換") {
					const { codeVerifier, codeChallenge } = generatePkce();
					const code = await performAuthorizationFlow({
						clientId: TEST_CONFIDENTIAL_CLIENT.clientId,
						redirectUri: TEST_CONFIDENTIAL_CLIENT.redirectUri,
						scope: "read write",
						codeVerifier,
						codeChallenge,
					});
					params = { grant_type: "authorization_code", code, code_verifier: codeVerifier };
				} else {
					const { refreshToken } = await obtainTokens();
					params = { grant_type: "refresh_token", refresh_token: refreshToken };
					if (scenario === "猶予期間内の再送") {
						expect((await tokenRequest(params)).status).toBe(200);
					}
				}

				const before = await snapshot();
				const target =
					params.grant_type === "authorization_code"
						? before.codes.find((row) => row.codeHash === sha256(params.code))
						: before.refreshTokens.find((row) => row.tokenHash === sha256(params.refresh_token));
				assert(target);
				const targetAccessTokenCount = before.accessTokens.filter(
					(row) => row.grantId === target.grantId,
				).length;
				expect(before.accessTokens.length).toBeGreaterThan(targetAccessTokenCount);
				await withRefreshTokenInsertFailure(async () => {
					const response = await tokenRequest(params);
					expect(response.status).toBe(500);
					expect(response.headers.get("Cache-Control")).toBe("no-store");
					expect(response.headers.get("Pragma")).toBeNull();
					const body = await response.json();
					expect(body.error).toBe("server_error");
					expect(body).not.toHaveProperty("access_token");
					expect(body).not.toHaveProperty("refresh_token");
					const [observed] = await testDb.execute(sql`
					SELECT last_value::int AS at_count, is_called FROM test_rt_insert_at_count
				`);
					// 単なる早期エラーではなく、新しいATの保存まで進んだことを確認する。
					expect(observed).toEqual({ at_count: targetAccessTokenCount + 1, is_called: true });
					expect(await snapshot()).toEqual(before);
				});

				// 障害を取り除けば、同じ認可コードまたはRTで発行をやり直せる。
				const retry = await tokenRequest(params);
				expect(retry.status).toBe(200);
				const body = await retry.json();
				expect(body.access_token).toBeTruthy();
				expect(body.refresh_token).toBeTruthy();
				const after = await snapshot();
				expect(after.accessTokens).toHaveLength(before.accessTokens.length + 1);
				expect(after.refreshTokens).toHaveLength(before.refreshTokens.length + 1);
				expect(after.grants).toEqual(before.grants);
			},
		);
	});

	// ============================================================
	// ヘルパー関数
	// ============================================================

	function tokenRequest(
		params: Record<string, string>,
		client: typeof TEST_PUBLIC_CLIENT | typeof TEST_CONFIDENTIAL_CLIENT = TEST_CONFIDENTIAL_CLIENT,
	) {
		const headers: Record<string, string> = { "Content-Type": "application/x-www-form-urlencoded" };
		if ("clientSecret" in client) {
			headers.Authorization = basicAuthHeader(client.clientId, client.clientSecret);
		} else {
			params = { ...params, client_id: client.clientId };
		}
		return request("/token", { method: "POST", headers, body: formBody(params) });
	}

	/**
	 * 認可フロー全体を実行して認可コードを取得するヘルパー。
	 */
	async function performAuthorizationFlow(params: {
		clientId: string;
		redirectUri: string;
		scope: string;
		codeChallenge: string;
		codeVerifier: string;
	}): Promise<string> {
		const authorizeUrl = buildAuthorizeUrl({
			clientId: params.clientId,
			redirectUri: params.redirectUri,
			scope: params.scope,
			codeChallenge: params.codeChallenge,
		});

		// 認可リクエスト → ログインリダイレクト（?txnId=... 付き）
		const authRes = await request(authorizeUrl);
		const setCookie = authRes.headers.get("Set-Cookie");
		const sidMatch = setCookie?.match(/sid=([^;]+)/);
		let sessionCookie = sidMatch ? `sid=${sidMatch[1]}` : "";
		const txnId = extractTxnIdFromLocation(authRes);

		// ログイン（hidden form field の txnId を渡す）
		const loginRes = await request("/login", {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
				Cookie: sessionCookie,
			},
			body: formBody({
				username: "testuser",
				password: "password123",
				txnId,
				csrfToken: await getFormCsrfToken(app, `/login?txnId=${txnId}`, sessionCookie),
			}),
		});
		const loginSetCookie = loginRes.headers.get("Set-Cookie");
		const loginSidMatch = loginSetCookie?.match(/sid=([^;]+)/);
		if (loginSidMatch) {
			sessionCookie = `sid=${loginSidMatch[1]}`;
		}

		// 認可エンドポイントへ復帰（同意画面表示 or 同意済みなら直接リダイレクト）
		const authRes2 = await request(`/authorize?txnId=${encodeURIComponent(txnId)}`, {
			headers: { Cookie: sessionCookie },
		});

		// 同意済みの場合は直接リダイレクト
		if (authRes2.status === 302) {
			const params = getRedirectParams(authRes2);
			return params.get("code")!;
		}

		// 同意承認（hidden form field の txnId を渡す）
		const consentRes = await request("/authorize", {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
				Cookie: sessionCookie,
			},
			body: formBody({
				decision: "approve",
				txnId,
				csrfToken: extractCsrfToken(await authRes2.text()),
			}),
		});

		const redirectParams = getRedirectParams(consentRes);
		return redirectParams.get("code")!;
	}

	/**
	 * トークンを取得するヘルパー（コンフィデンシャルクライアント）。
	 */
	async function obtainTokens(params?: { scope?: string }): Promise<{
		accessToken: string;
		refreshToken: string;
	}> {
		const { codeVerifier, codeChallenge } = generatePkce();

		const code = await performAuthorizationFlow({
			clientId: TEST_CONFIDENTIAL_CLIENT.clientId,
			redirectUri: TEST_CONFIDENTIAL_CLIENT.redirectUri,
			scope: params?.scope ?? "read write",
			codeChallenge,
			codeVerifier,
		});

		const tokenRes = await request("/token", {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
				Authorization: basicAuthHeader(
					TEST_CONFIDENTIAL_CLIENT.clientId,
					TEST_CONFIDENTIAL_CLIENT.clientSecret,
				),
			},
			body: formBody({
				grant_type: "authorization_code",
				code,
				redirect_uri: TEST_CONFIDENTIAL_CLIENT.redirectUri,
				code_verifier: codeVerifier,
			}),
		});

		const body = await tokenRes.json();
		return {
			accessToken: body.access_token,
			refreshToken: body.refresh_token,
		};
	}

	/**
	 * ログインしてセッションCookieを取得するヘルパー。
	 */
	async function loginAndGetCookie(): Promise<string> {
		// ダミー認可リクエストでセッション作成
		const { codeChallenge } = generatePkce();
		const authorizeUrl = buildAuthorizeUrl({
			clientId: TEST_CONFIDENTIAL_CLIENT.clientId,
			redirectUri: TEST_CONFIDENTIAL_CLIENT.redirectUri,
			scope: "read",
			codeChallenge,
		});

		const authRes = await request(authorizeUrl);
		const setCookie = authRes.headers.get("Set-Cookie");
		const sidMatch = setCookie?.match(/sid=([^;]+)/);
		let sessionCookie = sidMatch ? `sid=${sidMatch[1]}` : "";

		const loginRes = await request("/login", {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
				Cookie: sessionCookie,
			},
			body: formBody({
				username: "testuser",
				password: "password123",
				csrfToken: await getFormCsrfToken(app, "/login", sessionCookie),
			}),
		});

		const loginSetCookie = loginRes.headers.get("Set-Cookie");
		const loginSidMatch = loginSetCookie?.match(/sid=([^;]+)/);
		if (loginSidMatch) {
			sessionCookie = `sid=${loginSidMatch[1]}`;
		}

		return sessionCookie;
	}
});
