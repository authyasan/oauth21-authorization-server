import { createHash, randomBytes } from "node:crypto";
import { type APIRequestContext, type BrowserContext, expect, type Page } from "@playwright/test";
import {
	AS_ORIGIN,
	CLIENT_ID,
	CONTROL_ORIGIN,
	HOSTS,
	HTTPS_PORT,
	PASSWORD,
	REDIRECT_URI,
	USERNAME,
} from "./config.js";

export type CallbackRecord = { query: Record<string, string>; referer: string | null };

/** DB・メモリ上のセッション・認可リクエスト・callbackの記録を初期化し、テストユーザーを作る。 */
export async function resetServer(request: APIRequestContext): Promise<void> {
	const res = await request.post(`${CONTROL_ORIGIN}/reset`);
	expect(res.ok()).toBe(true);
}

export async function callbacks(request: APIRequestContext): Promise<CallbackRecord[]> {
	return (await request.get(`${CONTROL_ORIGIN}/callbacks`)).json();
}

export function pkce(): { verifier: string; challenge: string } {
	const verifier = randomBytes(32).toString("base64url");
	const challenge = createHash("sha256").update(verifier).digest("base64url");
	return { verifier, challenge };
}

export function authorizeUrl(params: {
	scope?: string;
	state?: string;
	challenge: string;
}): string {
	const url = new URL("/authorize", AS_ORIGIN);
	url.searchParams.set("response_type", "code");
	url.searchParams.set("client_id", CLIENT_ID);
	url.searchParams.set("redirect_uri", REDIRECT_URI);
	url.searchParams.set("scope", params.scope ?? "read");
	url.searchParams.set("state", params.state ?? "state-e2e");
	url.searchParams.set("code_challenge", params.challenge);
	url.searchParams.set("code_challenge_method", "S256");
	return url.toString();
}

/** ログイン画面に入力して送信する。 */
export async function submitLogin(
	page: Page,
	username = USERNAME,
	password = PASSWORD,
): Promise<void> {
	await expect(page.locator('form[action="/login"]')).toBeVisible();
	await page.fill("#username", username);
	await page.fill("#password", password);
	await page.click('form[action="/login"] button[type="submit"]');
}

export async function sessionCookie(context: BrowserContext) {
	const cookies = await context.cookies(AS_ORIGIN);
	return cookies.find((c) => c.name === "__Host-sid");
}

/** 同意画面のhiddenに埋め込まれたCSRFトークンを読む（テストの対照を作るために使う）。 */
export async function formCsrfToken(page: Page): Promise<string> {
	const token = await page.locator('input[name="csrfToken"]').first().getAttribute("value");
	if (!token) throw new Error("csrfToken が見つかりません");
	return token;
}

/** callbackに届いたクエリを、最新の記録から返す。 */
export async function lastCallback(request: APIRequestContext): Promise<CallbackRecord> {
	const all = await callbacks(request);
	const last = all.at(-1);
	if (!last) throw new Error("callbackに到達していません");
	return last;
}

/** 認可コードをトークンに交換する（クライアントのバックチャネルに相当。Nodeから直接送る）。 */
export async function exchangeCode(request: APIRequestContext, code: string, verifier: string) {
	return request.post(`https://127.0.0.1:${HTTPS_PORT}/token`, {
		form: {
			grant_type: "authorization_code",
			code,
			redirect_uri: REDIRECT_URI,
			client_id: CLIENT_ID,
			code_verifier: verifier,
		},
		ignoreHTTPSErrors: true,
	});
}

/** 攻撃者・対照のページに置いたフォームのURL。 */
export function formPageUrl(host: string, action: string, fields: Record<string, string>): string {
	const url = new URL(`https://${host}:${HTTPS_PORT}/form`);
	url.searchParams.set("action", action);
	url.searchParams.set("fields", new URLSearchParams(fields).toString());
	return url.toString();
}

export const origin = (host: string) => `https://${host}:${HTTPS_PORT}`;
export { HOSTS };
