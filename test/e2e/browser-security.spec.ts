/**
 * ブラウザの仕組み（Cookieの送信条件・__Host-接頭辞・埋め込み・Referer）が関わる防御。
 * 各拒否ケースには、同じ手順で成功する対照を置き、拒否の理由が意図したものであることを確かめる。
 */
import {
	type Browser,
	type BrowserContext,
	expect,
	type Page,
	type Request,
	test,
} from "@playwright/test";
import { AS_ORIGIN, HOSTS, PASSWORD, REDIRECT_URI, USERNAME } from "./config.js";
import {
	authorizeUrl,
	callbacks,
	formCsrfToken,
	formPageUrl,
	lastCallback,
	origin,
	pkce,
	resetServer,
	sessionCookie,
	submitLogin,
} from "./helpers.js";

test.beforeEach(async ({ request }) => {
	await resetServer(request);
});

/** 攻撃者などのページに置いたフォームを送信し、認可サーバーへのPOSTとその応答を返す。 */
async function submitFrom(
	page: Page,
	host: string,
	action: string,
	fields: Record<string, string>,
) {
	await page.goto(formPageUrl(host, `${AS_ORIGIN}${action}`, fields));
	const [request] = await Promise.all([
		page.waitForRequest((r) => r.url() === `${AS_ORIGIN}${action}` && r.method() === "POST"),
		page.click("button"),
	]);
	const response = await request.response();
	if (!response) throw new Error("応答がありません");
	return { request, status: response.status() };
}

async function sentSessionCookie(request: Request): Promise<boolean> {
	const cookie = (await request.allHeaders()).cookie ?? "";
	return /(^|;\s*)__Host-sid=/.test(cookie);
}

/** ログイン前のセッションとCSRFトークンを用意する（被害者がログイン画面を開いている状態）。 */
async function openLoginForm(page: Page): Promise<string> {
	await page.goto("/login");
	return formCsrfToken(page);
}

/** ログインして同意画面まで進んだ状態を用意する。 */
async function openConsent(page: Page): Promise<{ txnId: string; csrfToken: string }> {
	await page.goto(authorizeUrl({ challenge: pkce().challenge }));
	await submitLogin(page);
	await expect(page.locator("button.approve")).toBeVisible();
	const txnId = await page.locator('input[name="txnId"]').first().getAttribute("value");
	if (!txnId) throw new Error("txnId が見つかりません");
	return { txnId, csrfToken: await formCsrfToken(page) };
}

test.describe("別サイトからのPOST（SameSite=Lax）", () => {
	test("ログイン: 別サイトからはCookieが送られず403。同じトークンでも同一サイトからなら通る（対照）", async ({
		page,
		context,
	}) => {
		const csrfToken = await openLoginForm(page);
		const before = await sessionCookie(context);
		// 拒否の理由をCookieの有無に絞るため、あえて正しいトークンを載せる。
		const fields = { username: USERNAME, password: PASSWORD, csrfToken };

		const cross = await submitFrom(page, HOSTS.evil, "/login", fields);
		expect(await sentSessionCookie(cross.request)).toBe(false);
		expect(cross.status).toBe(403);
		expect((await sessionCookie(context))?.value).toBe(before?.value);

		const same = await submitFrom(page, HOSTS.other, "/login", fields);
		expect(await sentSessionCookie(same.request)).toBe(true);
		expect(same.status).toBe(303);
	});

	test("同意: 別サイトからはCookieが送られず403で、認可リクエストも消費されない", async ({
		page,
		request,
	}) => {
		const { txnId, csrfToken } = await openConsent(page);
		const fields = { txnId, csrfToken, decision: "approve" };

		const cross = await submitFrom(page, HOSTS.evil, "/authorize", fields);
		expect(await sentSessionCookie(cross.request)).toBe(false);
		expect(cross.status).toBe(403);
		expect(await callbacks(request)).toHaveLength(0);

		// 対照: 同じ値を同一サイトから送ると承認まで進む（認可リクエストが残っていたことの確認でもある）。
		const same = await submitFrom(page, HOSTS.other, "/authorize", fields);
		expect(await sentSessionCookie(same.request)).toBe(true);
		expect(same.status).toBe(303);
		await expect(page.locator("#callback")).toBeVisible();
		expect((await lastCallback(request)).query.code).toBeTruthy();
	});
});

test.describe("同一サイトの別オリジンからのPOST（Cookieは送られる）", () => {
	for (const kind of ["不一致", "欠落"] as const) {
		test(`ログイン: Cookieが送られても、トークン${kind}なら403`, async ({ page, context }) => {
			const csrfToken = await openLoginForm(page);
			const before = await sessionCookie(context);
			const fields: Record<string, string> = { username: USERNAME, password: PASSWORD };
			if (kind === "不一致") fields.csrfToken = "A".repeat(43);

			const bad = await submitFrom(page, HOSTS.other, "/login", fields);
			expect(await sentSessionCookie(bad.request)).toBe(true);
			expect(bad.status).toBe(403);
			expect((await sessionCookie(context))?.value).toBe(before?.value);

			const good = await submitFrom(page, HOSTS.other, "/login", { ...fields, csrfToken });
			expect(good.status).toBe(303);
		});

		test(`同意: Cookieが送られても、トークン${kind}なら403で、認可リクエストは残る`, async ({
			page,
			request,
		}) => {
			const { txnId, csrfToken } = await openConsent(page);
			const fields: Record<string, string> = { txnId, decision: "approve" };
			if (kind === "不一致") fields.csrfToken = "A".repeat(43);

			const bad = await submitFrom(page, HOSTS.other, "/authorize", fields);
			expect(await sentSessionCookie(bad.request)).toBe(true);
			expect(bad.status).toBe(403);
			expect(await callbacks(request)).toHaveLength(0);

			const good = await submitFrom(page, HOSTS.other, "/authorize", { ...fields, csrfToken });
			expect(good.status).toBe(303);
			expect((await lastCallback(request)).query.code).toBeTruthy();
		});
	}
});

test.describe("Cookie tossing（__Host-接頭辞）", () => {
	async function attackerSession(
		browser: Browser,
	): Promise<{ ctx: BrowserContext; sid: string; token: string }> {
		const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
		const page = await ctx.newPage();
		const token = await openLoginForm(page);
		const sid = (await sessionCookie(ctx))?.value;
		if (!sid) throw new Error("攻撃者のセッションがありません");
		return { ctx, sid, token };
	}

	test("兄弟サブドメインからDomain付きの __Host-sid は設定できず、被害者のセッションは変わらない", async ({
		page,
		context,
		browser,
	}) => {
		const victimToken = await openLoginForm(page);
		const victim = await sessionCookie(context);
		const attacker = await attackerSession(browser);

		await page.goto(`${origin(HOSTS.sub)}/toss?sid=${attacker.sid}`);
		await expect(page.locator("#tossed")).toBeVisible();
		const cookies = await context.cookies();

		// 対照: 同じ応答の接頭辞なしのDomain Cookieは受け入れられている（Set-Cookie自体は届いている）。
		expect(cookies.find((c) => c.name === "toss-control")?.domain).toBe(`.${HOSTS.site}`);
		expect(cookies.find((c) => c.name === "sid")?.domain).toBe(`.${HOSTS.site}`);
		// __Host-sid はDomain付きでは受け入れられない。認可サーバーの __Host-sid は被害者のまま。
		const hostSids = cookies.filter((c) => c.name === "__Host-sid");
		expect(hostSids).toHaveLength(1);
		expect(hostSids[0]).toMatchObject({ domain: HOSTS.as, value: victim?.value });

		// 注入された sid=攻撃者 は送られるが、サーバーは読まない。攻撃者のトークンは被害者のセッションに合わず403。
		const attack = await submitFrom(page, HOSTS.other, "/login", {
			username: USERNAME,
			password: PASSWORD,
			csrfToken: attacker.token,
		});
		expect((await attack.request.allHeaders()).cookie).toContain(`sid=${attacker.sid}`);
		expect(attack.status).toBe(403);

		// 対照: 被害者自身のトークンなら通る（被害者のセッションが生きている）。
		const own = await submitFrom(page, HOSTS.other, "/login", {
			username: USERNAME,
			password: PASSWORD,
			csrfToken: victimToken,
		});
		expect(own.status).toBe(303);
		await attacker.ctx.close();
	});
});

test.describe("埋め込みの拒否（CSP frame-ancestors / X-Frame-Options）", () => {
	for (const host of [HOSTS.evil, HOSTS.other]) {
		test(`${host} のiframeにログイン画面を表示できない（埋め込み可能なページは表示できる: 対照）`, async ({
			page,
		}) => {
			const loginResponse = page.waitForResponse(`${AS_ORIGIN}/login`);
			await page.goto(`${origin(host)}/frame?src=${encodeURIComponent(`${AS_ORIGIN}/login`)}`);
			const headers = (await loginResponse).headers();
			expect(headers["content-security-policy"]).toContain("frame-ancestors 'none'");
			expect(headers["x-frame-options"]).toBe("DENY");
			await page.waitForLoadState("load");
			const frame = page.frames().find((f) => f !== page.mainFrame());
			expect(frame).toBeTruthy();
			expect(await frame?.locator('form[action="/login"]').count()).toBe(0);
			expect(frame?.url()).not.toBe(`${AS_ORIGIN}/login`);

			await page.goto(
				`${origin(host)}/frame?src=${encodeURIComponent(`${origin(host)}/embeddable`)}`,
			);
			await expect(page.frameLocator("#target").locator("#embeddable")).toBeVisible();
		});
	}
});

test.describe("同意画面の埋め込みの拒否（クリックジャッキング）", () => {
	test("ログイン済みセッションの同意画面を、同一サイト別オリジンのiframeには表示できない（トップレベルでは表示できる: 対照）", async ({
		page,
		request,
	}) => {
		// 被害者がログインし、同意画面が出る状態（有効なセッションと、同意待ちのtxnId）を作る。
		await page.goto(authorizeUrl({ challenge: pkce().challenge }));
		await submitLogin(page);
		await expect(page.locator("button.approve")).toBeVisible();
		const txnId = await page.locator('input[name="txnId"]').first().getAttribute("value");
		if (!txnId) throw new Error("txnId が見つかりません");
		const consentUrl = `${AS_ORIGIN}/authorize?txnId=${encodeURIComponent(txnId)}`;

		// 同一サイトの別オリジンに置いたページが、同意画面をiframeに読み込もうとする。
		// 描画を拒否されたフレームの応答本文はブラウザに残らないので、ブラウザが送ったリクエストを
		// そのまま転送し、応答を手を加えずに返す中継を挟んで本文を記録する（ヘッダ・本文とも変更しない）。
		let framed:
			| { cookie: string; status: number; body: string; headers: Record<string, string> }
			| undefined;
		await page.route(consentUrl, async (route) => {
			// Node側からの転送はブラウザの名前解決を使わないので、127.0.0.1へ送りHostヘッダで振り分ける。
			const target = new URL(route.request().url());
			const upstream = await route.fetch({
				url: `https://127.0.0.1:${target.port}${target.pathname}${target.search}`,
				headers: { ...(await route.request().allHeaders()), host: target.host },
			});
			framed = {
				cookie: (await route.request().allHeaders()).cookie ?? "",
				status: upstream.status(),
				body: await upstream.text(),
				headers: upstream.headers(),
			};
			await route.fulfill({ response: upstream });
		});
		await page.goto(`${origin(HOSTS.other)}/frame?src=${encodeURIComponent(consentUrl)}`);
		await page.waitForLoadState("load");
		await page.unroute(consentUrl);
		if (!framed) throw new Error("iframeから同意画面へのリクエストが送られていません");

		// 拒否の理由を埋め込み禁止に絞る: Cookieは送られ、サーバーは正規の同意画面を200で返している。
		expect(framed.cookie).toMatch(/(^|;\s*)__Host-sid=/);
		expect(framed.status).toBe(200);
		expect(framed.body).toContain('value="approve"');
		expect(framed.body).toContain(`name="txnId" value="${txnId}"`);
		expect(framed.headers["content-security-policy"]).toContain("frame-ancestors 'none'");
		expect(framed.headers["x-frame-options"]).toBe("DENY");

		// それでもブラウザはiframe内に同意画面を描画しない。
		const frame = page.frames().find((f) => f !== page.mainFrame());
		expect(frame).toBeTruthy();
		expect(await frame?.locator("button.approve").count()).toBe(0);
		expect(frame?.url()).not.toBe(consentUrl);

		// 対照: 同じURLをトップレベルで開けば同意画面が表示され、承認できる（txnIdもセッションも有効なまま）。
		await page.goto(consentUrl);
		await expect(page.locator("button.approve")).toBeVisible();
		await page.click("button.approve");
		await expect(page.locator("#callback")).toBeVisible();
		expect((await lastCallback(request)).query.code).toBeTruthy();
	});
});

test.describe("Refererによる漏えい", () => {
	test("callbackへの遷移にRefererが付かず、txnIdが外部へ出ない（既定のページからは付く: 対照）", async ({
		page,
		request,
	}) => {
		await page.goto(authorizeUrl({ challenge: pkce().challenge }));
		await expect(page).toHaveURL(/txnId=/);
		await submitLogin(page);
		await page.click("button.approve");
		await expect(page.locator("#callback")).toBeVisible();
		expect((await lastCallback(request)).referer).toBeNull();

		// 同意省略の経路（ログイン済みでGET /authorize から直接callbackへ）でも付かない。
		await page.goto(authorizeUrl({ challenge: pkce().challenge }));
		await expect(page.locator("#callback")).toBeVisible();
		expect((await lastCallback(request)).referer).toBeNull();

		// 対照: 既定のReferrer-Policyのページからのリンクでは、callbackがRefererを受け取れている。
		await page.goto(`${origin(HOSTS.evil)}/link?to=${encodeURIComponent(REDIRECT_URI)}`);
		await page.click("#go");
		await expect(page.locator("#callback")).toBeVisible();
		expect((await lastCallback(request)).referer).toBe(`${origin(HOSTS.evil)}/`);
	});

	test("ログイン画面・同意画面は Referrer-Policy: no-referrer を返す", async ({ page }) => {
		const loginRes = page.waitForResponse((r) => r.url().startsWith(`${AS_ORIGIN}/login?txnId=`));
		await page.goto(authorizeUrl({ challenge: pkce().challenge }));
		expect((await loginRes).headers()["referrer-policy"]).toBe("no-referrer");
		const consentRes = page.waitForResponse((r) =>
			r.url().startsWith(`${AS_ORIGIN}/authorize?txnId=`),
		);
		await submitLogin(page);
		expect((await consentRes).headers()["referrer-policy"]).toBe("no-referrer");
	});
});
