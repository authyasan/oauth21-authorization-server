import { sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/postgres-js";
import type { Hono } from "hono";
import postgres from "postgres";
import * as schema from "../../src/db/schema.js";
import { sha256Base64url } from "../../src/utils/crypto.js";
import { assertTestCleanupDatabaseName, DEFAULT_INTEGRATION_DATABASE_URL } from "./db-guard.js";

// テスト用DB接続
const TEST_DATABASE_URL = process.env.DATABASE_URL || DEFAULT_INTEGRATION_DATABASE_URL;

const testClient = postgres(TEST_DATABASE_URL);
export const testDb = drizzle(testClient, { schema });

/** 初期化失敗後の後片付けでも誤削除しないよう、削除直前の実DB名を確認する。 */
async function assertCleanupDatabase(): Promise<void> {
	// E2Eの/resetでも共用するため、E2E専用DBも許可する。
	const rows = await testDb.execute<{ name: string }>(sql`select current_database() as name`);
	assertTestCleanupDatabaseName(rows[0]?.name ?? "");
}

/** テスト用の障害注入だけを除去する。途中でCREATEが失敗した場合も再実行できる。 */
export async function cleanupTokenSaveFailureInjection(): Promise<void> {
	await assertCleanupDatabase();
	await testDb.execute(sql`DROP TRIGGER IF EXISTS test_fail_rt_insert ON refresh_tokens`);
	await testDb.execute(sql`DROP FUNCTION IF EXISTS test_fail_rt_insert()`);
	await testDb.execute(sql`DROP SEQUENCE IF EXISTS test_rt_insert_at_count`);
}

/**
 * テスト用: 以下の対象テーブルのデータを削除する。
 * 外部キー制約を考慮した順序で削除する。
 */
export async function cleanupDatabase(): Promise<void> {
	await assertCleanupDatabase();
	// 異常終了で残ったトリガーが、次回の別テストのRT発行を妨げないよう先に除去する。
	await cleanupTokenSaveFailureInjection();
	// 外部キー順: トークン・認可コード（grants を参照）→ grants → consents → users
	await testDb.delete(schema.accessTokens);
	await testDb.delete(schema.refreshTokens);
	await testDb.delete(schema.authorizationCodes);
	await testDb.delete(schema.grants);
	await testDb.delete(schema.consents);
	await testDb.delete(schema.users);
}

/**
 * テスト用DB接続を閉じる。
 */
export async function closeDatabase(): Promise<void> {
	await testClient.end();
}

/**
 * テスト用ユーザーを作成する。
 * 指定されたパスワード（省略時はpassword123）をハッシュ化して保存する。
 */
export async function createTestUser(params?: {
	username?: string;
	password?: string;
}): Promise<{ id: string; username: string }> {
	const username = params?.username ?? "testuser";
	const { hashPassword } = await import("../../src/utils/password.js");
	const passwordHash = await hashPassword(params?.password ?? "password123");

	const result = await testDb
		.insert(schema.users)
		.values({ username, passwordHash })
		.returning({ id: schema.users.id });

	return { id: result[0].id, username };
}

// テスト用クライアント設定（clients.jsonと同じ値）
export const TEST_PUBLIC_CLIENT = {
	clientId: "public-spa-client",
	redirectUri: "http://127.0.0.1:8080/callback",
};

export const TEST_CONFIDENTIAL_CLIENT = {
	clientId: "confidential-backend-client",
	clientSecret: "test-client-secret",
	redirectUri: "http://127.0.0.1:8081/callback",
};

// テスト用リソースサーバー設定（resource-server.jsonと同じ値）
// resource-server.jsonのsecretHashはtest-client-secretのSHA-256
export const TEST_RESOURCE_SERVER = {
	resourceServerId: "resource-server-1",
	secret: "test-client-secret",
};

// テスト用リソースサーバー設定その2（admin scopeのみ担当）
// 照会元のリソースサーバーとaudの突き合わせのテスト用: resource-server-1 のaudに含まれないRSとして使う
export const TEST_RESOURCE_SERVER_2 = {
	resourceServerId: "resource-server-2",
	secret: "test-resource-server-2-secret",
};

/**
 * PKCE用のcode_verifierとcode_challengeを生成する。
 */
export function generatePkce(): {
	codeVerifier: string;
	codeChallenge: string;
} {
	// テスト用の固定値（本番ではCSPRNGで生成する）
	const codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
	const codeChallenge = sha256Base64url(codeVerifier);
	return { codeVerifier, codeChallenge };
}

/**
 * テスト用のBasic認証ヘッダーを生成する。
 * 入力はフォームエンコードせず、そのままコロンで連結してBase64化する。
 */
export function basicAuthHeader(username: string, password: string): string {
	const encoded = Buffer.from(`${username}:${password}`).toString("base64");
	return `Basic ${encoded}`;
}

/**
 * 認可リクエストのパスとクエリを返す。localhostはURL編集用で、戻り値には含めない。
 */
export function buildAuthorizeUrl(params: {
	clientId: string;
	redirectUri: string;
	scope?: string;
	state?: string;
	codeChallenge: string;
	codeChallengeMethod?: string;
}): string {
	const url = new URL("http://localhost/authorize");
	url.searchParams.set("response_type", "code");
	url.searchParams.set("client_id", params.clientId);
	url.searchParams.set("redirect_uri", params.redirectUri);
	url.searchParams.set("scope", params.scope ?? "read");
	url.searchParams.set("state", params.state ?? "test-state-12345678901234567890ab");
	url.searchParams.set("code_challenge", params.codeChallenge);
	url.searchParams.set("code_challenge_method", params.codeChallengeMethod ?? "S256");
	return url.pathname + url.search;
}

/**
 * レスポンスのリダイレクト先URLからクエリパラメータを取得する。
 */
export function getRedirectParams(response: Response): URLSearchParams {
	const location = response.headers.get("Location");
	if (!location) {
		throw new Error("Locationヘッダーがありません");
	}
	const url = new URL(location, "http://localhost");
	return url.searchParams;
}

/**
 * レスポンスのLocationヘッダーから、保存済みの認可リクエストを参照するtxnIdを取得する。
 */
export function extractTxnIdFromLocation(response: Response): string {
	const params = getRedirectParams(response);
	const txnId = params.get("txnId");
	if (!txnId) {
		throw new Error("Location に txnId パラメータがありません");
	}
	return txnId;
}

/** テスト対象が生成したフォームから、送信用のCSRFトークンを取得する。 */
export function extractCsrfToken(html: string): string {
	const token = html.match(/name="csrfToken" value="([A-Za-z0-9_-]{43})"/)?.[1];
	if (!token) throw new Error("フォームにCSRFトークンがありません");
	return token;
}

export async function getFormCsrfToken(app: Hono, path: string, cookie: string): Promise<string> {
	const response = await app.request(path, { headers: { Cookie: cookie } });
	if (response.status !== 200) throw new Error(`フォーム取得失敗: ${response.status}`);
	return extractCsrfToken(await response.text());
}
