/**
 * 実ブラウザでの認可フロー。
 * APIの異常系は主に結合テスト（test/integration）で確認する。
 * ここではブラウザの画面遷移・Cookie・フォームに関わる経路を確認する。
 */
import { expect, test } from "@playwright/test";
import { AS_ORIGIN, REDIRECT_URI } from "./config.js";
import {
	authorizeUrl,
	callbacks,
	exchangeCode,
	lastCallback,
	pkce,
	resetServer,
	sessionCookie,
	submitLogin,
} from "./helpers.js";

test.beforeEach(async ({ request }) => {
	await resetServer(request);
});

test("ログイン→同意→callback→トークン交換まで通り、ログイン時にセッションCookieが入れ替わる", async ({
	page,
	context,
	request,
}) => {
	const { verifier, challenge } = pkce();
	await page.goto(authorizeUrl({ challenge }));
	await expect(page).toHaveURL(/\/login\?txnId=/);

	// ログイン前のセッション。本番相当の設定なので __Host- 付き・Secure・Domainなし。
	const before = await sessionCookie(context);
	expect(before).toMatchObject({ secure: true, httpOnly: true, sameSite: "Lax", path: "/" });
	expect(before?.domain).toBe(new URL(AS_ORIGIN).hostname);

	await submitLogin(page);
	await expect(page.locator("button.approve")).toBeVisible();
	await expect(page.locator(".current-user")).toHaveText("ログイン中のユーザー: testuser");

	// ログインでセッションIDが作り直され、新しいセッションで認可フローが続いている。
	const after = await sessionCookie(context);
	expect(after?.value).toBeTruthy();
	expect(after?.value).not.toBe(before?.value);

	// フォームPOST後のリダイレクトは303（draft-16 §7.5.4）。ブラウザはGETでcallbackへ進む。
	const approved = page.waitForResponse(
		(r) => r.url() === `${AS_ORIGIN}/authorize` && r.request().method() === "POST",
	);
	await page.click("button.approve");
	expect((await approved).status()).toBe(303);
	await expect(page.locator("#callback")).toBeVisible();
	expect(page.url().startsWith(REDIRECT_URI)).toBe(true);

	const cb = await lastCallback(request);
	expect(cb.query.state).toBe("state-e2e");
	expect(cb.query.iss).toBe(AS_ORIGIN);
	expect(cb.query.code).toBeTruthy();

	const token = await exchangeCode(request, cb.query.code, verifier);
	expect(token.status()).toBe(200);
	const body = await token.json();
	expect(body.token_type).toBe("Bearer");
	expect(body.access_token).toBeTruthy();
	expect(body.scope).toBe("read");
});

test("別タブで別ユーザーがログインすると古い同意は拒否され、再読込後に現在のユーザー名が表示される", async ({
	page,
	context,
	request,
}) => {
	await page.goto(authorizeUrl({ challenge: pkce().challenge }));
	await submitLogin(page);
	await expect(page.locator(".current-user")).toHaveText("ログイン中のユーザー: testuser");
	const consentUrl = page.url();
	const other = await context.newPage();
	// ログイン済みのGET /loginはフォームを表示しないため、現在のセッションのCSRFトークンでPOSTする。
	const csrfToken = await page.locator('input[name="csrfToken"]').first().inputValue();
	await other.goto(consentUrl);
	const login = other.waitForResponse(
		(r) => r.url() === `${AS_ORIGIN}/login` && r.request().method() === "POST",
	);
	await other.evaluate((csrfToken) => {
		const form = document.createElement("form");
		form.method = "post";
		form.action = "/login";
		for (const [name, value] of Object.entries({
			username: "other-user",
			password: "password123",
			csrfToken,
		})) {
			const input = document.createElement("input");
			input.name = name;
			input.value = value;
			form.append(input);
		}
		document.body.append(form);
		form.submit();
	}, csrfToken);
	expect((await login).status()).toBe(303);
	await other.waitForURL(`${AS_ORIGIN}/`);
	await other.goto(consentUrl);
	await expect(other.locator(".current-user")).toHaveText("ログイン中のユーザー: other-user");
	const rejected = page.waitForResponse(
		(r) => r.url() === `${AS_ORIGIN}/authorize` && r.request().method() === "POST",
	);
	await page.click("button.approve");
	expect((await rejected).status()).toBe(403);
	expect(await callbacks(request)).toHaveLength(0);
	await page.goto(consentUrl);
	await expect(page.locator(".current-user")).toHaveText("ログイン中のユーザー: other-user");
	await page.click("button.approve");
	await expect(page.locator("#callback")).toBeVisible();
	expect(await callbacks(request)).toHaveLength(1);
});

test("同意画面で拒否すると access_denied が callback に届く", async ({ page, request }) => {
	await page.goto(authorizeUrl({ challenge: pkce().challenge }));
	await submitLogin(page);
	await page.click("button.deny");
	await expect(page.locator("#callback")).toBeVisible();
	const cb = await lastCallback(request);
	expect(cb.query.error).toBe("access_denied");
	expect(cb.query.code).toBeUndefined();
	expect(cb.query.iss).toBe(AS_ORIGIN);
});

test("同意済みの範囲なら2回目は同意画面を省略し、scopeを追加すると再び同意を求める", async ({
	page,
	request,
}) => {
	// 1回目: read に同意
	await page.goto(authorizeUrl({ challenge: pkce().challenge, scope: "read" }));
	await submitLogin(page);
	await page.click("button.approve");
	await expect(page.locator("#callback")).toBeVisible();

	// 2回目: 同じ read。ログイン済みのセッションのまま、同意画面を出さずにcallbackへ進む。
	// GET /authorize からのリダイレクトは302のまま。
	const skipped = page.waitForResponse(
		(r) => r.url().startsWith(`${AS_ORIGIN}/authorize?`) && r.request().method() === "GET",
	);
	await page.goto(authorizeUrl({ challenge: pkce().challenge, scope: "read" }));
	expect((await skipped).status()).toBe(302);
	await expect(page.locator("#callback")).toBeVisible();
	expect((await lastCallback(request)).query.code).toBeTruthy();
	expect(await callbacks(request)).toHaveLength(2);

	// 3回目: write を追加。同意済みの範囲を超えるので、同意画面を表示する。
	await page.goto(authorizeUrl({ challenge: pkce().challenge, scope: "read write" }));
	await expect(page.locator("button.approve")).toBeVisible();
	await expect(page.getByText("write")).toBeVisible();
	expect(await callbacks(request)).toHaveLength(2);
});

test("パスワードを誤ったあと、同じ画面から再入力してログインできる", async ({ page, context }) => {
	await page.goto(authorizeUrl({ challenge: pkce().challenge }));
	const before = await sessionCookie(context);

	await submitLogin(page, undefined, "wrong-password");
	await expect(page.locator(".error")).toBeVisible();
	// パスワードの不一致ではセッションを作り直さず、同じフォームとCSRFトークンで再試行できる。
	expect((await sessionCookie(context))?.value).toBe(before?.value);

	await submitLogin(page);
	await expect(page.locator("button.approve")).toBeVisible();
	expect((await sessionCookie(context))?.value).not.toBe(before?.value);
});

test("認可フローを経ない直接ログインでも、フォームを表示してログインできる", async ({
	page,
	context,
}) => {
	await page.goto("/login");
	const before = await sessionCookie(context);
	expect(before).toBeTruthy();

	const response = page.waitForResponse(
		(r) => r.url() === `${AS_ORIGIN}/login` && r.request().method() === "POST",
	);
	await submitLogin(page);
	expect((await response).status()).toBe(303);
	await expect(page).toHaveURL(`${AS_ORIGIN}/`);
	const after = await sessionCookie(context);
	expect(after?.value).not.toBe(before?.value);

	// ログイン済みのまま /login を開くとトップへ戻る（ログイン済みとして扱われている）。
	await page.goto("/login");
	await expect(page).toHaveURL(`${AS_ORIGIN}/`);
});

test("複数タブ: 一方でログインすると、他方の古いログインフォームは拒否され、読み直せば認可を続けられる", async ({
	context,
	request,
}) => {
	const tabA = await context.newPage();
	const tabB = await context.newPage();
	await tabA.goto(authorizeUrl({ challenge: pkce().challenge, state: "tab-a" }));
	await tabB.goto(authorizeUrl({ challenge: pkce().challenge, state: "tab-b" }));
	await expect(tabB).toHaveURL(/\/login\?txnId=/);

	await submitLogin(tabA);
	await expect(tabA.locator("button.approve")).toBeVisible();

	// タブBのフォームに残る古いCSRFトークンは、ログイン後のCookieが示すセッションと一致せず403になる。
	const rejected = tabB.waitForResponse(
		(r) => r.url() === `${AS_ORIGIN}/login` && r.request().method() === "POST",
	);
	await submitLogin(tabB);
	expect((await rejected).status()).toBe(403);

	// タブBを読み直すと、ログイン済みとして同意画面へ進める（認可リクエストは新しいセッションへ引き継がれている）。
	await tabB.goBack();
	await tabB.reload();
	await expect(tabB.locator("button.approve")).toBeVisible();

	// CSRFトークンは同意POSTで消費しないため、両タブから同じセッションのCSRFトークンで同意を送れる。
	await tabA.click("button.approve");
	await expect(tabA.locator("#callback")).toBeVisible();
	await tabB.click("button.approve");
	await expect(tabB.locator("#callback")).toBeVisible();
	const states = (await callbacks(request)).map((c) => c.query.state).sort();
	expect(states).toEqual(["tab-a", "tab-b"]);
});
